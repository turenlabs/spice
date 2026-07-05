package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha1" // batou:ignore BATOU-AST-005 -- matches published SHA-1 malware-hash IOCs, not a security primitive
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

const miniShaiHuludID = "mini-shai-hulud-2026-05"
const miniShaiHuludCampaign = "Mini Shai-Hulud May 2026"

const (
	maxArchiveMemberBytes   int64 = 8 * 1024 * 1024
	maxArchiveExpandedBytes int64 = 64 * 1024 * 1024
	maxArchiveMembers             = 4096
)

type MiniShaiHuludDetection struct {
	id                  string
	campaign            string
	affected            map[string]map[string]bool
	affectedByEcosystem map[string]map[string]map[string]bool
	iocs                []iocPattern
	compositeIOCs       []compositeIOCPattern
	suspiciousFilename  map[string]bool
	knownSHA256         map[string]string
	knownSHA1           map[string]string
}

type iocPattern struct {
	label    string
	re       *regexp.Regexp
	severity string
}

type compositeIOCPattern struct {
	label      string
	severity   string
	minMatches int
	signals    []iocPattern
}

func NewMiniShaiHuludDetection() *MiniShaiHuludDetection {
	return &MiniShaiHuludDetection{
		id:                  miniShaiHuludID,
		campaign:            miniShaiHuludCampaign,
		affected:            map[string]map[string]bool{},
		affectedByEcosystem: map[string]map[string]map[string]bool{},
		suspiciousFilename:  map[string]bool{},
		knownSHA256:         map[string]string{},
		knownSHA1:           map[string]string{},
	}
}

func NewMiniShaiHuludDetectionWithRemote(pack *RemoteDetectionPack) *MiniShaiHuludDetection {
	detection := NewMiniShaiHuludDetection()
	if pack == nil {
		return detection
	}
	if pack.ID != "" {
		detection.id = pack.ID
	}
	if pack.Campaign != "" {
		detection.campaign = pack.Campaign
	}
	if len(pack.AffectedVersions) > 0 {
		detection.affected = mergeVersionMaps(map[string]map[string]bool{}, pack.AffectedVersions)
	}
	if len(pack.AffectedVersionsByEcosystem) > 0 {
		detection.affectedByEcosystem = mergeEcosystemVersionMaps(map[string]map[string]map[string]bool{}, pack.AffectedVersionsByEcosystem)
	}
	for _, remoteIOC := range pack.IOCs {
		if remoteIOC.Label == "" || remoteIOC.Pattern == "" {
			continue
		}
		if isDeadMansSwitchIOC(remoteIOC.Label) {
			continue
		}
		re, err := regexp.Compile(remoteIOC.Pattern)
		if err == nil {
			detection.iocs = append(detection.iocs, iocPattern{label: remoteIOC.Label, re: re, severity: normalizeSeverity(remoteIOC.Severity, "high")})
		}
	}
	for _, remoteComposite := range pack.CompositeIOCs {
		compiled := compileRemoteCompositeIOC(remoteComposite)
		if len(compiled.signals) > 0 {
			detection.compositeIOCs = append(detection.compositeIOCs, compiled)
		}
	}
	for _, name := range pack.SuspiciousFilenames {
		detection.suspiciousFilename[strings.ToLower(name)] = true
	}
	for hash, label := range pack.KnownSHA256 {
		detection.knownSHA256[strings.ToLower(hash)] = label
	}
	for hash, label := range pack.KnownSHA1 {
		detection.knownSHA1[strings.ToLower(hash)] = label
	}
	return detection
}

func (d *MiniShaiHuludDetection) ID() string {
	return d.id
}

func (d *MiniShaiHuludDetection) Campaign() string {
	return d.campaign
}

func (d *MiniShaiHuludDetection) ScanGlobal(emit EmitFinding) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	for _, path := range []string{
		filepath.Join(home, "Library/LaunchAgents/com.user.gh-token-monitor.plist"),
		filepath.Join(home, ".config/systemd/user/gh-token-monitor.service"),
		filepath.Join(home, ".local/bin/gh-token-monitor.sh"),
	} {
		if _, err := os.Stat(path); err == nil {
			d.emit(emit, "critical", "persistence", path, "gh-token-monitor persistence artifact exists", "Remove this persistence before revoking GitHub tokens, then rotate credentials and inspect the host.")
		}
	}
}

func (d *MiniShaiHuludDetection) ScanFile(file FileContext, emit EmitFinding) {
	base := strings.ToLower(file.Base)
	switch base {
	case "package.json":
		d.scanPackageJSON(file, emit)
	case "package-lock.json":
		d.scanPackageLock(file, emit)
	case "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pyproject.toml", "npm-shrinkwrap.json", "pipfile.lock", "uv.lock", "pdm.lock", "composer.json", "composer.lock", "go.mod", "cargo.toml", "cargo.lock":
		d.scanTextManifest(file, emit)
	case "metadata":
		d.scanPythonMetadata(file, emit)
	default:
		if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			d.scanRequirements(file, emit)
		}
	}
	d.scanCompositeArtifacts(file, emit)
	d.scanKnownHash(file, emit)
	d.scanArchive(file, emit)
	d.scanIOCStrings(file, emit)
}

func (d *MiniShaiHuludDetection) WatchEvent(event fsnotify.Event) []WatchEvent {
	if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove|fsnotify.Chmod) == 0 {
		return nil
	}
	path := event.Name
	lower := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	now := time.Now().Format(time.RFC3339)
	alerts := []WatchEvent{}

	add := func(sev, kind, detail string) {
		alerts = append(alerts, WatchEvent{
			Time:     now,
			Severity: sev,
			Kind:     kind,
			Path:     path,
			Op:       event.Op.String(),
			Detail:   detail,
		})
	}

	if base == "package.json" && hasSuspiciousInstallHook(path) {
		add("high", "suspicious-install-hook", "package.json contains a suspicious install lifecycle script")
	}
	if isSensitiveCredentialBasename(base) && isSensitiveCredentialPath(lower) {
		add("high", "credential-path-change", "credential/config path changed while watcher was active")
	}
	if strings.Contains(lower, "launchagents/com.user.gh-token-monitor.plist") ||
		strings.Contains(lower, ".config/systemd/user/gh-token-monitor.service") ||
		strings.Contains(lower, ".local/bin/gh-token-monitor.sh") {
		add("critical", "persistence", "gh-token-monitor persistence path changed; remove persistence before revoking GitHub tokens")
	}
	return alerts
}

func (d *MiniShaiHuludDetection) scanPackageJSON(file FileContext, emit EmitFinding) {
	var data map[string]any
	if !file.ReadJSON(&data) {
		return
	}
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		deps, ok := data[section].(map[string]any)
		if !ok {
			continue
		}
		for pkg, raw := range deps {
			version := normalizeVersion(fmt.Sprint(raw))
			if d.isAffected("npm", pkg, version) {
				d.addAffected(emit, file.Path, pkg, version, section)
			}
		}
	}
	if scripts, ok := data["scripts"].(map[string]any); ok {
		for _, hook := range []string{"preinstall", "postinstall", "prepare", "install"} {
			if val, ok := scripts[hook]; ok {
				if sev, reason, ok := d.classifyInstallHook(hook, fmt.Sprint(val)); ok {
					d.emit(emit, sev, "suspicious-install-hook", file.Path, fmt.Sprintf("%s script: %s (%s)", hook, val, reason), "Review this lifecycle script before running package manager commands. Treat as higher risk if it appeared unexpectedly or came from an installed package.")
				}
			}
		}
	}
}

func (d *MiniShaiHuludDetection) scanPackageLock(file FileContext, emit EmitFinding) {
	var data map[string]any
	if !file.ReadJSON(&data) {
		return
	}
	if packages, ok := data["packages"].(map[string]any); ok {
		for location, rawMeta := range packages {
			meta, ok := rawMeta.(map[string]any)
			if !ok {
				continue
			}
			pkg := fmt.Sprint(meta["name"])
			if pkg == "" || pkg == "<nil>" {
				pkg = packageFromNodeModulesPath(location)
			}
			version := fmt.Sprint(meta["version"])
			if d.isAffected("npm", pkg, version) {
				d.addAffected(emit, file.Path, pkg, version, "package-lock packages")
			}
		}
	}
	if deps, ok := data["dependencies"].(map[string]any); ok {
		for pkg, rawMeta := range deps {
			meta, ok := rawMeta.(map[string]any)
			if !ok {
				continue
			}
			version := fmt.Sprint(meta["version"])
			if d.isAffected("npm", pkg, version) {
				d.addAffected(emit, file.Path, pkg, version, "package-lock dependencies")
			}
		}
	}
}

func (d *MiniShaiHuludDetection) scanRequirements(file FileContext, emit EmitFinding) {
	var scanner *bufio.Scanner
	if file.Data != nil {
		scanner = bufio.NewScanner(bytes.NewReader(file.Data))
	} else {
		handle, err := os.Open(file.Path)
		if err != nil {
			return
		}
		defer handle.Close()
		scanner = bufio.NewScanner(handle)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.SplitN(line, "#", 2)[0]
		line = strings.SplitN(line, ";", 2)[0]
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		pkg := normalizePythonName(strings.TrimSpace(parts[0]))
		version := strings.TrimSpace(parts[1])
		if d.isAffected("pypi", pkg, version) {
			d.addAffected(emit, file.Path, pkg, version, "requirements")
		}
	}
}

func (d *MiniShaiHuludDetection) scanPythonMetadata(file FileContext, emit EmitFinding) {
	for _, pkg := range extractPythonMetadataPackage(file.Path, file.Data) {
		if d.isAffected("pypi", pkg.Name, pkg.Version) {
			d.addAffected(emit, file.Path, pkg.Name, pkg.Version, "installed Python metadata")
		}
	}
}

func (d *MiniShaiHuludDetection) scanTextManifest(file FileContext, emit EmitFinding) {
	data, ok := file.ReadAll(16 * 1024 * 1024)
	if !ok {
		return
	}
	text := string(data)
	for pkg, versions := range d.affectedVersionsFor(manifestEcosystem(file)) {
		quotedPkg := regexp.QuoteMeta(pkg)
		for version := range versions {
			quotedVersion := regexp.QuoteMeta(version)
			patterns := []*regexp.Regexp{
				regexp.MustCompile(`(?m)(^|["'\s/@])` + quotedPkg + `@` + quotedVersion + `([:",\s()_]|$)`),
				regexp.MustCompile(`(?m)^\s*(?:require\s+)?` + quotedPkg + `\s+` + quotedVersion + `(?:\s|$)`),
				regexp.MustCompile(`(?m)["']?` + quotedPkg + `["']?\s*[:=]\s*["']?[\^~]?` + quotedVersion + `["']?`),
				regexp.MustCompile(`(?ms)` + quotedPkg + `@[^:\n]+:\s*.{0,300}version:\s*["']?` + quotedVersion + `["']?`),
				regexp.MustCompile(`(?ms)name\s*=\s*["']` + quotedPkg + `["'].{0,250}version\s*=\s*["']` + quotedVersion + `["']`),
				regexp.MustCompile(`(?ms)"name"\s*:\s*"` + quotedPkg + `".{0,350}"version"\s*:\s*"` + quotedVersion + `"`),
			}
			for _, pattern := range patterns {
				if pattern.MatchString(text) {
					d.addAffected(emit, file.Path, pkg, version, "text manifest/lockfile")
					break
				}
			}
		}
	}
}

func (d *MiniShaiHuludDetection) isAffected(ecosystem, pkg, version string) bool {
	if d.affected[pkg][version] {
		return true
	}
	for _, alias := range ecosystemAliases(ecosystem) {
		if d.affectedByEcosystem[alias][pkg][version] {
			return true
		}
	}
	return false
}

func (d *MiniShaiHuludDetection) affectedVersionsFor(ecosystem string) map[string]map[string]bool {
	affected := mergeVersionMaps(map[string]map[string]bool{}, d.affected)
	aliases := ecosystemAliases(ecosystem)
	if len(aliases) == 0 {
		for _, versionsByPackage := range d.affectedByEcosystem {
			affected = mergeVersionMaps(affected, versionsByPackage)
		}
		return affected
	}
	for _, alias := range aliases {
		affected = mergeVersionMaps(affected, d.affectedByEcosystem[alias])
	}
	return affected
}

func (d *MiniShaiHuludDetection) scanCompositeArtifacts(file FileContext, emit EmitFinding) {
	base := strings.ToLower(file.Base)
	if !d.suspiciousFilename[base] {
		return
	}
	evidence := []string{}
	score := 0

	if base == "setup_bun.js" && siblingExists(file.Path, "bun_environment.js") {
		evidence = append(evidence, "setup_bun.js paired with bun_environment.js")
		score += 3
	}
	if base == "bun_environment.js" && siblingExists(file.Path, "setup_bun.js") {
		evidence = append(evidence, "bun_environment.js paired with setup_bun.js")
		score += 3
	}
	if packageJSONReferencesAnyScript(file.Path, base) {
		evidence = append(evidence, "referenced by package.json lifecycle script")
		score += 2
	}

	text := ""
	if textCandidate(file.Path) {
		if data, ok := file.ReadAll(8 * 1024 * 1024); ok {
			text = string(data)
		}
	}
	if text != "" {
		if labels := matchedIOCs(d.iocs, text); len(labels) > 0 {
			evidence = append(evidence, "matched IOC: "+strings.Join(labels, ", "))
			score += 3
		}
		if hasShaiHuludLoaderBehavior(text) {
			evidence = append(evidence, "loader behavior: credential/runtime access plus process execution or download")
			score += 2
		}
		if base == "router_init.js" && looksLikeLargeObfuscatedPayload(file.Path, text) {
			evidence = append(evidence, "large obfuscated router payload")
			score += 2
		}
	}

	if score < 3 {
		return
	}
	sev := "high"
	if score >= 5 || strings.Contains(file.Slash, ".claude/") || strings.Contains(file.Slash, ".vscode/") {
		sev = "critical"
	}
	d.emit(emit, sev, "campaign-artifact", file.Path, fmt.Sprintf("composite artifact match: %s (%s)", file.Base, strings.Join(evidence, "; ")), "Quarantine or remove after preserving forensic evidence. Rotate credentials if this artifact was installed or executed.")
}

func (d *MiniShaiHuludDetection) scanKnownHash(file FileContext, emit EmitFinding) {
	if !d.hashCandidate(file.Base) {
		return
	}
	if isPackageArchiveBase(strings.ToLower(file.Base)) && fileContextSize(file) > maxPackageArchiveScanBytes {
		return
	}

	sha256Hash := sha256.New()
	sha1Hash := sha1.New()
	if file.Data != nil {
		_, _ = io.Copy(io.MultiWriter(sha256Hash, sha1Hash), bytes.NewReader(file.Data))
	} else {
		handle, err := os.Open(file.Path)
		if err != nil {
			return
		}
		defer handle.Close()
		if _, err := io.Copy(io.MultiWriter(sha256Hash, sha1Hash), handle); err != nil {
			return
		}
	}
	sha256Hex := hex.EncodeToString(sha256Hash.Sum(nil))
	sha1Hex := hex.EncodeToString(sha1Hash.Sum(nil))
	if label, ok := d.knownSHA256[sha256Hex]; ok {
		d.emit(emit, "critical", "known-malware-hash", file.Path, fmt.Sprintf("sha256=%s (%s)", sha256Hex, label), "Assume compromise for environments where this file was present during install or runtime. Remove persistence before revoking GitHub tokens, then rotate credentials.")
	}
	if label, ok := d.knownSHA1[sha1Hex]; ok {
		d.emit(emit, "critical", "known-malware-hash", file.Path, fmt.Sprintf("sha1=%s (%s)", sha1Hex, label), "Assume compromise for environments where this file was present during install or runtime. Remove persistence before revoking GitHub tokens, then rotate credentials.")
	}
}

func (d *MiniShaiHuludDetection) scanArchive(file FileContext, emit EmitFinding) {
	base := strings.ToLower(file.Base)
	if fileContextSize(file) > maxPackageArchiveScanBytes {
		return
	}
	switch {
	case strings.HasSuffix(base, ".zip"), strings.HasSuffix(base, ".whl"), strings.HasSuffix(base, ".pyz"):
		d.scanZipArchive(file, emit)
	case strings.HasSuffix(base, ".tgz"), strings.HasSuffix(base, ".tar.gz"):
		d.scanTarGzArchive(file, emit)
	case strings.HasSuffix(base, ".tar"):
		d.scanTarArchive(file, emit)
	}
}

func fileContextSize(file FileContext) int64 {
	if file.Data != nil {
		return int64(len(file.Data))
	}
	info, err := os.Stat(file.Path)
	if err != nil {
		return -1
	}
	return info.Size()
}

func (d *MiniShaiHuludDetection) scanZipArchive(file FileContext, emit EmitFinding) {
	reader, closeFn, err := openZipReader(file)
	if err != nil {
		return
	}
	defer closeFn()
	var expanded int64
	for _, member := range reader.File {
		if len(reader.File) > maxArchiveMembers {
			return
		}
		if member.FileInfo().IsDir() {
			continue
		}
		if member.UncompressedSize64 > uint64(maxArchiveMemberBytes) {
			continue
		}
		expanded += int64(member.UncompressedSize64)
		if expanded > maxArchiveExpandedBytes {
			return
		}
		handle, err := member.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(handle, maxArchiveMemberBytes+1))
		_ = handle.Close()
		if err != nil || int64(len(data)) > maxArchiveMemberBytes {
			continue
		}
		d.scanArchiveMember(file.Path, member.Name, data, emit)
	}
}

func openZipReader(file FileContext) (*zip.Reader, func(), error) {
	if file.Data != nil {
		reader, err := zip.NewReader(bytes.NewReader(file.Data), int64(len(file.Data)))
		return reader, func() {}, err
	}
	handle, err := os.Open(file.Path)
	if err != nil {
		return nil, func() {}, err
	}
	info, err := handle.Stat()
	if err != nil {
		_ = handle.Close()
		return nil, func() {}, err
	}
	reader, err := zip.NewReader(handle, info.Size())
	if err != nil {
		_ = handle.Close()
		return nil, func() {}, err
	}
	return reader, func() { _ = handle.Close() }, nil
}

func (d *MiniShaiHuludDetection) scanTarGzArchive(file FileContext, emit EmitFinding) {
	reader := io.Reader(nil)
	var closeFn func()
	if file.Data != nil {
		reader = bytes.NewReader(file.Data)
		closeFn = func() {}
	} else {
		handle, err := os.Open(file.Path)
		if err != nil {
			return
		}
		reader = handle
		closeFn = func() { _ = handle.Close() }
	}
	defer closeFn()
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return
	}
	defer gzipReader.Close()
	d.scanTarReader(file.Path, tar.NewReader(gzipReader), emit)
}

func (d *MiniShaiHuludDetection) scanTarArchive(file FileContext, emit EmitFinding) {
	reader := io.Reader(nil)
	var closeFn func()
	if file.Data != nil {
		reader = bytes.NewReader(file.Data)
		closeFn = func() {}
	} else {
		handle, err := os.Open(file.Path)
		if err != nil {
			return
		}
		reader = handle
		closeFn = func() { _ = handle.Close() }
	}
	defer closeFn()
	d.scanTarReader(file.Path, tar.NewReader(reader), emit)
}

func (d *MiniShaiHuludDetection) scanTarReader(archivePath string, reader *tar.Reader, emit EmitFinding) {
	var members int
	var expanded int64
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return
		}
		if err != nil {
			return
		}
		members++
		if members > maxArchiveMembers {
			return
		}
		if header.Size > 0 {
			expanded += header.Size
			if expanded > maxArchiveExpandedBytes {
				return
			}
		}
		if header.Typeflag != tar.TypeReg || header.Size > maxArchiveMemberBytes {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxArchiveMemberBytes+1))
		if err != nil || int64(len(data)) > maxArchiveMemberBytes {
			continue
		}
		d.scanArchiveMember(archivePath, header.Name, data, emit)
	}
}

func (d *MiniShaiHuludDetection) scanArchiveMember(archivePath, memberName string, data []byte, emit EmitFinding) {
	memberName = filepath.ToSlash(memberName)
	base := filepath.Base(memberName)
	virtualPath := archivePath + "!" + memberName
	member := FileContext{Path: virtualPath, Base: base, Slash: filepath.ToSlash(virtualPath), Data: data}
	if d.suspiciousFilename[strings.ToLower(base)] {
		d.emit(emit, "high", "archive-artifact", virtualPath, fmt.Sprintf("suspicious package archive member: %s", memberName), "Treat this archive as hostile if it came from a package registry or install cache. Remove the package and rotate credentials if it may have run.")
	}
	switch strings.ToLower(base) {
	case "package.json":
		d.scanPackageJSON(member, emit)
	case "metadata":
		d.scanPythonMetadata(member, emit)
	case "composer.json", "composer.lock", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "pyproject.toml", "pipfile.lock", "uv.lock", "pdm.lock", "cargo.toml", "cargo.lock":
		d.scanTextManifest(member, emit)
	default:
		lowerBase := strings.ToLower(base)
		if strings.HasPrefix(lowerBase, "requirements") && strings.HasSuffix(lowerBase, ".txt") {
			d.scanRequirements(member, emit)
		}
	}
	d.scanCompositeArtifacts(member, emit)
	d.scanKnownHash(member, emit)
	d.scanIOCStrings(member, emit)
}

func (d *MiniShaiHuludDetection) scanIOCStrings(file FileContext, emit EmitFinding) {
	if !textCandidate(file.Path) {
		return
	}
	data, ok := file.ReadAll(8 * 1024 * 1024)
	if !ok {
		return
	}
	text := string(data)
	d.scanCompositeIOCs(text, file, emit)
	for _, ioc := range d.iocs {
		if ioc.re.MatchString(text) {
			d.emit(emit, normalizeSeverity(ioc.severity, "high"), "ioc-string", file.Path, ioc.label, "Confirm whether this is benign threat-intel text. If found in dependency files, logs, package contents, or scripts, inspect execution history and rotate exposed credentials.")
		}
	}
}

func (d *MiniShaiHuludDetection) scanCompositeIOCs(text string, file FileContext, emit EmitFinding) {
	for _, composite := range d.compositeIOCs {
		matched := []string{}
		for _, signal := range composite.signals {
			if signal.re.MatchString(text) {
				matched = append(matched, signal.label)
			}
		}
		minMatches := composite.minMatches
		if minMatches <= 0 {
			minMatches = len(composite.signals)
		}
		if len(matched) < minMatches {
			continue
		}
		confidence := int(float64(len(matched)) / float64(len(composite.signals)) * 100)
		d.emit(emit, normalizeSeverity(composite.severity, "high"), "ioc-string", file.Path, fmt.Sprintf("%s: %d%% match (%s)", composite.label, confidence, strings.Join(matched, ", ")), "Confirm whether this is benign threat-intel text. If found in dependency files, logs, package contents, or scripts, inspect execution history and rotate exposed credentials.")
	}
}

func (d *MiniShaiHuludDetection) addAffected(emit EmitFinding, path, pkg, version, source string) {
	d.emit(emit, "critical", "affected-package", path, fmt.Sprintf("%s@%s in %s", pkg, version, source), "Remove the affected version, reinstall from a known-good registry state, and rotate exposed package, CI, cloud, and source-control credentials if install scripts may have run.")
}

func (d *MiniShaiHuludDetection) emit(emit EmitFinding, severity, kind, path, evidence, remediation string) {
	emit(Finding{
		DetectionID: d.ID(),
		Campaign:    d.Campaign(),
		Severity:    severity,
		Kind:        kind,
		Path:        path,
		Evidence:    evidence,
		Remediation: remediation,
	})
}

func matchedIOCs(iocs []iocPattern, text string) []string {
	var labels []string
	for _, ioc := range iocs {
		if ioc.re.MatchString(text) {
			labels = append(labels, ioc.label)
		}
	}
	if len(labels) > 3 {
		return labels[:3]
	}
	return labels
}

func normalizeSeverity(value, fallback string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return fallback
	}
}

func isDeadMansSwitchIOC(label string) bool {
	return strings.Contains(strings.ToLower(label), "dead man's switch")
}

func compileRemoteCompositeIOC(remote RemoteCompositeIOC) compositeIOCPattern {
	composite := compositeIOCPattern{
		label:      remote.Label,
		severity:   normalizeSeverity(remote.Severity, "high"),
		minMatches: remote.MinMatches,
	}
	for _, signal := range remote.Signals {
		if signal.Label == "" || signal.Pattern == "" {
			continue
		}
		re, err := regexp.Compile(signal.Pattern)
		if err != nil {
			continue
		}
		composite.signals = append(composite.signals, iocPattern{
			label:    signal.Label,
			re:       re,
			severity: normalizeSeverity(signal.Severity, composite.severity),
		})
	}
	if composite.minMatches <= 0 || composite.minMatches > len(composite.signals) {
		composite.minMatches = len(composite.signals)
	}
	return composite
}

func hasShaiHuludLoaderBehavior(text string) bool {
	normalized := strings.ToLower(text)
	credentialAccess := strings.Contains(normalized, "actions_id_token_request_token") ||
		strings.Contains(normalized, "github_token") ||
		strings.Contains(normalized, "npm_token") ||
		strings.Contains(normalized, ".npmrc") ||
		strings.Contains(normalized, ".config/gh") ||
		strings.Contains(normalized, "metadata.google.internal") ||
		strings.Contains(normalized, "169.254.169.254")
	processOrNetwork := strings.Contains(normalized, "child_process") ||
		strings.Contains(normalized, ".exec(") ||
		strings.Contains(normalized, ".spawn(") ||
		strings.Contains(normalized, "fetch(") ||
		strings.Contains(normalized, "https.request") ||
		strings.Contains(normalized, "http.request") ||
		strings.Contains(normalized, "curl ") ||
		strings.Contains(normalized, "wget ")
	return credentialAccess && processOrNetwork
}

func looksLikeLargeObfuscatedPayload(path string, text string) bool {
	info, err := os.Stat(path)
	if err != nil || info.Size() < 512*1024 {
		return false
	}
	return strings.Count(text, "\n") < 250 || strings.Contains(text, "eval(") || strings.Contains(text, "Function(")
}

func siblingExists(path, sibling string) bool {
	_, err := os.Stat(filepath.Join(filepath.Dir(path), sibling))
	return err == nil
}

func packageJSONReferencesAnyScript(path, scriptName string) bool {
	packagePath := filepath.Join(filepath.Dir(path), "package.json")
	var data map[string]any
	file := FileContext{Path: packagePath}
	if !file.ReadJSON(&data) {
		return false
	}
	scripts, ok := data["scripts"].(map[string]any)
	if !ok {
		return false
	}
	scriptName = strings.ToLower(scriptName)
	for _, hook := range []string{"preinstall", "postinstall", "prepare", "install"} {
		if val, ok := scripts[hook]; ok && strings.Contains(strings.ToLower(fmt.Sprint(val)), scriptName) {
			return true
		}
	}
	return false
}

func cloneBoolMap(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeVersionMaps(base, overlay map[string]map[string]bool) map[string]map[string]bool {
	merged := map[string]map[string]bool{}
	for pkg, versions := range base {
		merged[pkg] = map[string]bool{}
		for version := range versions {
			merged[pkg][version] = true
		}
	}
	for pkg, versions := range overlay {
		if merged[pkg] == nil {
			merged[pkg] = map[string]bool{}
		}
		for version := range versions {
			merged[pkg][version] = true
		}
	}
	return merged
}

func mergeEcosystemVersionMaps(base, overlay map[string]map[string]map[string]bool) map[string]map[string]map[string]bool {
	merged := map[string]map[string]map[string]bool{}
	for ecosystem, versionsByPackage := range base {
		merged[ecosystem] = mergeVersionMaps(map[string]map[string]bool{}, versionsByPackage)
	}
	for ecosystem, versionsByPackage := range overlay {
		merged[ecosystem] = mergeVersionMaps(merged[ecosystem], versionsByPackage)
	}
	return merged
}

func manifestEcosystem(file FileContext) string {
	base := strings.ToLower(file.Base)
	switch base {
	case "package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock":
		return "npm"
	case "pyproject.toml", "poetry.lock", "pipfile.lock", "uv.lock", "pdm.lock", "metadata":
		return "pypi"
	case "composer.json", "composer.lock":
		return "composer"
	case "go.mod":
		return "go"
	case "cargo.toml", "cargo.lock":
		return "crates"
	default:
		if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			return "pypi"
		}
		return ""
	}
}

func ecosystemAliases(ecosystem string) []string {
	switch normalizePackageEcosystem(ecosystem) {
	case "":
		return nil
	case "composer":
		return []string{"composer", "packagist"}
	default:
		return []string{normalizePackageEcosystem(ecosystem)}
	}
}

func (d *MiniShaiHuludDetection) hashCandidate(base string) bool {
	base = strings.ToLower(base)
	return d.suspiciousFilename[base] ||
		base == "_index.js" ||
		base == "bundle.js" ||
		base == "composer.json" ||
		base == "composer.lock" ||
		strings.HasSuffix(base, ".pth") ||
		strings.HasSuffix(base, ".tgz") ||
		strings.HasSuffix(base, ".tar") ||
		strings.HasSuffix(base, ".tar.gz") ||
		strings.HasSuffix(base, ".zip") ||
		strings.HasSuffix(base, ".whl") ||
		strings.HasSuffix(base, ".pyz")
}

func (d *MiniShaiHuludDetection) classifyInstallHook(hook string, command string) (string, string, bool) {
	sev, reason, ok := classifyInstallHook(hook, command)
	if !ok {
		return "", "", false
	}
	if d.id == miniShaiHuludID {
		return sev, reason, true
	}
	lowerCommand := strings.ToLower(command)
	for name := range d.suspiciousFilename {
		if name != "" && strings.Contains(lowerCommand, name) {
			return sev, reason, true
		}
	}
	for _, ioc := range d.iocs {
		if ioc.re.MatchString(command) {
			return normalizeSeverity(ioc.severity, sev), reason, true
		}
	}
	return "", "", false
}

func hasSuspiciousInstallHook(path string) bool {
	var data map[string]any
	file := FileContext{Path: path}
	if !file.ReadJSON(&data) {
		return false
	}
	scripts, ok := data["scripts"].(map[string]any)
	if !ok {
		return false
	}
	for _, hook := range []string{"preinstall", "postinstall", "prepare", "install"} {
		if val, ok := scripts[hook]; ok {
			if _, _, suspicious := classifyInstallHook(hook, fmt.Sprint(val)); suspicious {
				return true
			}
		}
	}
	return false
}

func classifyInstallHook(hook string, command string) (string, string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(command))
	if normalized == "" {
		return "", "", false
	}
	if hook == "prepare" && isCommonBenignPrepare(normalized) {
		return "", "", false
	}
	switch {
	case strings.Contains(normalized, "setup.mjs"):
		return "high", "known campaign setup.mjs pattern", true
	case strings.Contains(normalized, "curl ") || strings.Contains(normalized, "wget "):
		return "high", "network download in install lifecycle", true
	case strings.Contains(normalized, "bash -c") || strings.Contains(normalized, " sh -c") || strings.Contains(normalized, "node -e"):
		return "medium", "inline shell or node execution", true
	case strings.Contains(normalized, "bun ") || strings.Contains(normalized, "npx "):
		return "medium", "package/runtime execution during install", true
	default:
		return "", "", false
	}
}

func isCommonBenignPrepare(command string) bool {
	benign := []string{
		"svelte-kit sync",
		"husky install",
		"husky",
		"tsc",
		"tsc -p",
		"npm run build",
		"pnpm build",
		"vite build",
	}
	for _, prefix := range benign {
		if command == prefix || strings.HasPrefix(command, prefix+" ") || strings.HasPrefix(command, prefix+" ||") {
			return true
		}
	}
	return false
}

func isSensitiveCredentialBasename(base string) bool {
	switch base {
	case ".env", ".env.local", ".npmrc", ".pypirc", ".yarnrc.yml", ".netrc", "credentials", "config", "hosts.yml", "kubeconfig":
		return true
	default:
		return false
	}
}

func isSensitiveCredentialPath(path string) bool {
	return strings.Contains(path, "/.aws/") ||
		strings.Contains(path, "/.config/gh/") ||
		strings.Contains(path, "/.kube/") ||
		strings.Contains(path, "/.npmrc") ||
		strings.Contains(path, "/.pypirc") ||
		strings.Contains(path, "/.docker/config.json") ||
		strings.Contains(path, "/.azure/") ||
		strings.Contains(path, "/.config/gcloud/") ||
		strings.Contains(path, "/.config/systemd/user/") ||
		strings.Contains(path, "/.ssh/")
}

func normalizePythonName(name string) string {
	if idx := strings.Index(name, "["); idx >= 0 {
		name = name[:idx]
	}
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(name), "_", "-"))
}
