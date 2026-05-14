package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultDetectionManifestURL = "https://api.github.com/repos/turenlabs/spice-detections/contents/manifest.json?ref=main"
	trustedDetectionOwner       = "turenlabs"
	trustedDetectionRepo        = "spice-detections"
	trustedDetectionRef         = "main"
	detectionTrustPolicy        = "HTTPS GitHub content pinned to turenlabs/spice-detections main"
)

type RemoteDetectionBundle struct {
	Packs       []*RemoteDetectionPack
	Fingerprint string
	Source      string
	UsedCache   bool
	UsedRemote  bool
}

type RemoteDetectionPack struct {
	ID                          string
	Campaign                    string
	AffectedVersions            map[string]map[string]bool
	AffectedVersionsByEcosystem map[string]map[string]map[string]bool
	IOCs                        []RemoteIOC
	CompositeIOCs               []RemoteCompositeIOC
	SuspiciousFilenames         []string
	KnownSHA256                 map[string]string
	KnownSHA1                   map[string]string
}

type RemoteIOC struct {
	Label    string `json:"label"`
	Pattern  string `json:"pattern"`
	Severity string `json:"severity,omitempty"`
}

type RemoteCompositeIOC struct {
	Label      string      `json:"label"`
	Severity   string      `json:"severity,omitempty"`
	MinMatches int         `json:"minMatches,omitempty"`
	Signals    []RemoteIOC `json:"signals"`
}

type remoteManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	UpdatedAt     string          `json:"updatedAt"`
	Packs         []remotePackRef `json:"packs"`
}

type remotePackRef struct {
	ID                  string `json:"id"`
	Campaign            string `json:"campaign"`
	URL                 string `json:"url"`
	AffectedPackagesURL string `json:"affectedPackagesUrl"`
}

type remotePackFile struct {
	SchemaVersion       int                  `json:"schemaVersion"`
	ID                  string               `json:"id"`
	Campaign            string               `json:"campaign"`
	IOCs                []RemoteIOC          `json:"iocs"`
	CompositeIOCs       []RemoteCompositeIOC `json:"compositeIocs"`
	SuspiciousFilenames []string             `json:"suspiciousFilenames"`
	KnownSHA256         map[string]string    `json:"knownSha256"`
	KnownSHA1           map[string]string    `json:"knownSha1"`
}

func LoadRemoteDetectionBundle(ctx context.Context) (*RemoteDetectionBundle, error) {
	client := newDetectionHTTPClient()
	fingerprint := sha256.New()
	manifestURL, err := resolveDetectionURL(defaultDetectionManifestURL, "manifest.json")
	if err != nil {
		return nil, err
	}

	rawManifest, err := fetchDetectionBytes(ctx, client, defaultDetectionManifestURL)
	manifestFromCache := false
	if err != nil {
		rawManifest, err = readCachedDetectionFile("manifest.json")
		if err != nil {
			return nil, err
		}
		manifestFromCache = true
	} else {
		_ = writeCachedDetectionFile("manifest.json", rawManifest)
	}
	_, _ = fingerprint.Write(rawManifest)

	var manifest remoteManifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return nil, err
	}
	if manifest.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported detection manifest schema %d", manifest.SchemaVersion)
	}

	bundle := &RemoteDetectionBundle{}
	recordDetectionSource(bundle, manifestFromCache)
	for _, ref := range manifest.Packs {
		packURL, err := resolveDetectionURL(manifestURL, ref.URL)
		if err != nil {
			continue
		}
		cacheName, err := detectionPackCacheName(packURL)
		if err != nil {
			continue
		}
		rawPack, err := fetchDetectionBytes(ctx, client, packURL)
		packFromCache := false
		if err != nil {
			rawPack, err = readCachedDetectionFile(cacheName)
			if err != nil {
				continue
			}
			packFromCache = true
		} else {
			_ = writeCachedDetectionFile(cacheName, rawPack)
		}
		recordDetectionSource(bundle, packFromCache)
		_, _ = fingerprint.Write([]byte(ref.URL))
		_, _ = fingerprint.Write(rawPack)

		var file remotePackFile
		if err := json.Unmarshal(rawPack, &file); err != nil || file.SchemaVersion != 1 {
			continue
		}
		pack := &RemoteDetectionPack{
			ID:                          firstNonEmpty(file.ID, ref.ID),
			Campaign:                    firstNonEmpty(file.Campaign, ref.Campaign),
			IOCs:                        file.IOCs,
			CompositeIOCs:               file.CompositeIOCs,
			SuspiciousFilenames:         file.SuspiciousFilenames,
			KnownSHA256:                 file.KnownSHA256,
			KnownSHA1:                   file.KnownSHA1,
			AffectedVersions:            map[string]map[string]bool{},
			AffectedVersionsByEcosystem: map[string]map[string]map[string]bool{},
		}

		if ref.AffectedPackagesURL != "" {
			csvURL, err := resolveDetectionURL(manifestURL, ref.AffectedPackagesURL)
			if err != nil {
				bundle.Packs = append(bundle.Packs, pack)
				continue
			}
			csvCacheName, err := detectionPackCacheName(csvURL)
			if err != nil {
				bundle.Packs = append(bundle.Packs, pack)
				continue
			}
			rawCSV, err := fetchDetectionBytes(ctx, client, csvURL)
			csvFromCache := false
			if err != nil {
				rawCSV, err = readCachedDetectionFile(csvCacheName)
				csvFromCache = err == nil
			} else {
				_ = writeCachedDetectionFile(csvCacheName, rawCSV)
			}
			if err == nil {
				recordDetectionSource(bundle, csvFromCache)
				_, _ = fingerprint.Write([]byte(ref.AffectedPackagesURL))
				_, _ = fingerprint.Write(rawCSV)
				parsed := parsePackageCSVWithEcosystems(string(rawCSV))
				pack.AffectedVersions = parsed.Versions
				pack.AffectedVersionsByEcosystem = parsed.EcosystemVersions
			}
		}
		bundle.Packs = append(bundle.Packs, pack)
	}
	if len(bundle.Packs) == 0 {
		return nil, fmt.Errorf("no usable remote detection packs")
	}
	bundle.Fingerprint = fmt.Sprintf("%x", fingerprint.Sum(nil))
	bundle.Source = detectionBundleSource(bundle)
	return bundle, nil
}

func fetchDetectionBytes(ctx context.Context, client *http.Client, location string) ([]byte, error) {
	if err := validateTrustedDetectionURL(location); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return nil, err
	}
	if isGitHubContentAPI(location) {
		req.Header.Set("Accept", "application/vnd.github+json")
	}
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil {
		if err := validateTrustedDetectionURL(resp.Request.URL.String()); err != nil {
			return nil, err
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("fetch %s: %s", location, resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if isGitHubContentAPI(location) {
		var content struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if err := json.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		if content.Encoding != "base64" {
			return nil, fmt.Errorf("unsupported github content encoding %q", content.Encoding)
		}
		return base64.StdEncoding.DecodeString(strings.ReplaceAll(content.Content, "\n", ""))
	}
	return data, nil
}

func newDetectionHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req == nil || req.URL == nil {
				return fmt.Errorf("empty detection redirect URL")
			}
			if err := validateTrustedDetectionURL(req.URL.String()); err != nil {
				return err
			}
			if len(via) >= 5 {
				return fmt.Errorf("too many detection redirects")
			}
			return nil
		},
	}
}

func resolveDetectionURL(baseLocation, relative string) (string, error) {
	relative = strings.TrimSpace(relative)
	if relative == "" {
		return "", fmt.Errorf("empty detection URL")
	}
	if strings.HasPrefix(relative, "http://") || strings.HasPrefix(relative, "https://") {
		if err := validateTrustedDetectionURL(relative); err != nil {
			return "", err
		}
		return relative, nil
	}
	if strings.HasPrefix(relative, "//") {
		return "", fmt.Errorf("protocol-relative detection URL rejected: %s", relative)
	}
	if strings.Contains(relative, "\\") {
		return "", fmt.Errorf("backslash detection path rejected: %s", relative)
	}

	parsed, err := url.Parse(baseLocation)
	if err != nil {
		return "", err
	}
	if err := validateTrustedDetectionURL(parsed.String()); err != nil {
		return "", err
	}
	ref, err := url.Parse(relative)
	if err != nil {
		return "", err
	}
	if ref.IsAbs() || ref.Host != "" {
		return "", fmt.Errorf("untrusted detection URL rejected: %s", relative)
	}
	if ref.Fragment != "" {
		return "", fmt.Errorf("detection URL fragments are rejected: %s", relative)
	}
	if path.IsAbs(ref.Path) {
		return "", fmt.Errorf("absolute detection path rejected: %s", relative)
	}
	if err := validateRelativeDetectionPath(ref.Path); err != nil {
		return "", err
	}

	if isGitHubContentAPI(parsed.String()) {
		basePath := strings.TrimPrefix(parsed.EscapedPath(), githubAPIDetectionPrefix())
		basePath, err = url.PathUnescape(basePath)
		if err != nil {
			return "", err
		}
		parsed.Path = githubAPIDetectionPrefix() + path.Join(path.Dir(basePath), ref.Path)
		parsed.RawQuery = mergeDetectionRefQuery(parsed.RawQuery, ref.RawQuery)
		if err := validateTrustedDetectionURL(parsed.String()); err != nil {
			return "", err
		}
		return parsed.String(), nil
	}

	rawPath := strings.TrimPrefix(parsed.EscapedPath(), githubRawDetectionPrefix())
	rawPath, err = url.PathUnescape(rawPath)
	if err != nil {
		return "", err
	}
	parsed.Path = githubRawDetectionPrefix() + path.Join(path.Dir(rawPath), ref.Path)
	parsed.RawQuery = ref.RawQuery
	if err := validateTrustedDetectionURL(parsed.String()); err != nil {
		return "", err
	}
	return parsed.String(), nil
}

func validateTrustedDetectionURL(location string) error {
	parsed, err := url.Parse(location)
	if err != nil {
		return err
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("detection URL must use HTTPS: %s", location)
	}
	if parsed.User != nil {
		return fmt.Errorf("detection URL userinfo rejected: %s", location)
	}
	switch parsed.Host {
	case "api.github.com":
		return validateGitHubAPIDetectionURL(parsed)
	case "raw.githubusercontent.com":
		return validateGitHubRawDetectionURL(parsed)
	default:
		return fmt.Errorf("untrusted detection host rejected: %s", parsed.Host)
	}
}

func validateGitHubAPIDetectionURL(parsed *url.URL) error {
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return err
	}
	prefix := githubAPIDetectionPrefix()
	if !strings.HasPrefix(decodedPath, prefix) {
		return fmt.Errorf("untrusted GitHub content path rejected: %s", decodedPath)
	}
	resource := strings.TrimPrefix(decodedPath, prefix)
	if err := validateRelativeDetectionPath(resource); err != nil {
		return err
	}
	ref := parsed.Query().Get("ref")
	if ref != "" && ref != trustedDetectionRef {
		return fmt.Errorf("untrusted detection ref rejected: %s", ref)
	}
	for key := range parsed.Query() {
		if key != "ref" {
			return fmt.Errorf("unsupported detection query parameter rejected: %s", key)
		}
	}
	return nil
}

func validateGitHubRawDetectionURL(parsed *url.URL) error {
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return err
	}
	prefix := githubRawDetectionPrefix()
	if !strings.HasPrefix(decodedPath, prefix) {
		return fmt.Errorf("untrusted GitHub raw path rejected: %s", decodedPath)
	}
	resource := strings.TrimPrefix(decodedPath, prefix)
	parts := strings.Split(resource, "/")
	if len(parts) < 2 || parts[0] != trustedDetectionRef {
		return fmt.Errorf("untrusted detection ref rejected: %s", resource)
	}
	if parsed.RawQuery != "" {
		return fmt.Errorf("unsupported raw detection query rejected")
	}
	return validateRelativeDetectionPath(strings.Join(parts[1:], "/"))
}

func validateRelativeDetectionPath(resource string) error {
	if resource == "" {
		return fmt.Errorf("empty detection path rejected")
	}
	decoded, err := url.PathUnescape(resource)
	if err != nil {
		return err
	}
	if strings.Contains(decoded, "\\") {
		return fmt.Errorf("backslash detection path rejected: %s", resource)
	}
	if path.IsAbs(decoded) {
		return fmt.Errorf("absolute detection path rejected: %s", resource)
	}
	for _, part := range strings.Split(decoded, "/") {
		if part == "" || part == "." || part == ".." {
			return fmt.Errorf("unsafe detection path rejected: %s", resource)
		}
	}
	return nil
}

func mergeDetectionRefQuery(baseRawQuery, relativeRawQuery string) string {
	if relativeRawQuery == "" {
		return baseRawQuery
	}
	return relativeRawQuery
}

func isGitHubContentAPI(location string) bool {
	parsed, err := url.Parse(location)
	return err == nil && parsed.Host == "api.github.com" && strings.HasPrefix(parsed.EscapedPath(), githubAPIDetectionPrefix())
}

func githubAPIDetectionPrefix() string {
	return "/repos/" + trustedDetectionOwner + "/" + trustedDetectionRepo + "/contents/"
}

func githubRawDetectionPrefix() string {
	return "/" + trustedDetectionOwner + "/" + trustedDetectionRepo + "/"
}

func detectionPackCacheName(location string) (string, error) {
	name, err := detectionResourceBase(location)
	if err != nil {
		return "", err
	}
	return filepath.Join("packs", name), nil
}

func detectionResourceBase(location string) (string, error) {
	parsed, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	if err := validateTrustedDetectionURL(location); err != nil {
		return "", err
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		return "", err
	}
	var resource string
	if parsed.Host == "api.github.com" {
		resource = strings.TrimPrefix(decodedPath, githubAPIDetectionPrefix())
	} else {
		resource = strings.TrimPrefix(decodedPath, githubRawDetectionPrefix())
		parts := strings.Split(resource, "/")
		if len(parts) < 2 {
			return "", fmt.Errorf("empty detection resource: %s", location)
		}
		resource = strings.Join(parts[1:], "/")
	}
	return path.Base(resource), nil
}

func recordDetectionSource(bundle *RemoteDetectionBundle, fromCache bool) {
	if fromCache {
		bundle.UsedCache = true
		return
	}
	bundle.UsedRemote = true
}

func detectionBundleSource(bundle *RemoteDetectionBundle) string {
	switch {
	case bundle.UsedCache && bundle.UsedRemote:
		return "mixed"
	case bundle.UsedCache:
		return "cache"
	case bundle.UsedRemote:
		return "remote"
	default:
		return "none"
	}
}

func detectionCacheDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Spice", "detections"), nil
}

func readCachedDetectionFile(name string) ([]byte, error) {
	path, err := detectionCachePath(name)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func writeCachedDetectionFile(name string, data []byte) error {
	path, err := detectionCachePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func detectionCachePath(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("absolute detection cache path rejected: %s", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("relative detection cache path rejected: %s", name)
	}
	dir, err := detectionCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, clean), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
