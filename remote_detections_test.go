package main

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestResolveDetectionURLAllowsTrustedGitHubContent(t *testing.T) {
	tests := []struct {
		name     string
		base     string
		relative string
		want     string
	}{
		{
			name:     "api relative pack",
			base:     defaultDetectionManifestURL,
			relative: "packs/shai-hulud.json",
			want:     "https://api.github.com/repos/turenlabs/spice-detections/contents/packs/shai-hulud.json?ref=main",
		},
		{
			name:     "trusted api absolute",
			base:     defaultDetectionManifestURL,
			relative: "https://api.github.com/repos/turenlabs/spice-detections/contents/packs/affected.csv?ref=main",
			want:     "https://api.github.com/repos/turenlabs/spice-detections/contents/packs/affected.csv?ref=main",
		},
		{
			name:     "raw relative pack",
			base:     "https://raw.githubusercontent.com/turenlabs/spice-detections/main/manifest.json",
			relative: "packs/shai-hulud.json",
			want:     "https://raw.githubusercontent.com/turenlabs/spice-detections/main/packs/shai-hulud.json",
		},
		{
			name:     "trusted raw absolute",
			base:     defaultDetectionManifestURL,
			relative: "https://raw.githubusercontent.com/turenlabs/spice-detections/main/packs/shai-hulud.json",
			want:     "https://raw.githubusercontent.com/turenlabs/spice-detections/main/packs/shai-hulud.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveDetectionURL(test.base, test.relative)
			if err != nil {
				t.Fatalf("resolveDetectionURL() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("resolveDetectionURL() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveDetectionURLRejectsTraversalAndUntrustedEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		relative string
	}{
		{name: "parent traversal", relative: "../manifest.json"},
		{name: "nested parent traversal", relative: "packs/../../manifest.json"},
		{name: "encoded parent traversal", relative: "packs/%2e%2e/manifest.json"},
		{name: "absolute path", relative: "/repos/turenlabs/spice-detections/contents/packs/rules.json"},
		{name: "backslash path", relative: `packs\evil.json`},
		{name: "protocol relative", relative: "//raw.githubusercontent.com/turenlabs/spice-detections/main/packs/rules.json"},
		{name: "http scheme", relative: "http://api.github.com/repos/turenlabs/spice-detections/contents/packs/rules.json?ref=main"},
		{name: "github web host", relative: "https://github.com/turenlabs/spice-detections/raw/main/packs/rules.json"},
		{name: "wrong api owner", relative: "https://api.github.com/repos/other/spice-detections/contents/packs/rules.json?ref=main"},
		{name: "wrong raw repo", relative: "https://raw.githubusercontent.com/turenlabs/other/main/packs/rules.json"},
		{name: "wrong api ref", relative: "https://api.github.com/repos/turenlabs/spice-detections/contents/packs/rules.json?ref=dev"},
		{name: "wrong raw ref", relative: "https://raw.githubusercontent.com/turenlabs/spice-detections/dev/packs/rules.json"},
		{name: "extra api query", relative: "https://api.github.com/repos/turenlabs/spice-detections/contents/packs/rules.json?ref=main&download=1"},
		{name: "raw query", relative: "https://raw.githubusercontent.com/turenlabs/spice-detections/main/packs/rules.json?token=1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got, err := resolveDetectionURL(defaultDetectionManifestURL, test.relative); err == nil {
				t.Fatalf("resolveDetectionURL() = %q, want error", got)
			}
		})
	}
}

func TestFetchDetectionBytesRejectsUntrustedURLBeforeRequest(t *testing.T) {
	called := false
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}

	_, err := fetchDetectionBytes(context.Background(), client, "https://example.com/turenlabs/spice-detections/manifest.json")
	if err == nil {
		t.Fatal("fetchDetectionBytes() expected error for untrusted URL")
	}
	if called {
		t.Fatal("fetchDetectionBytes() made an HTTP request for an untrusted URL")
	}
}

func TestValidateTrustedDetectionURLRejectsEscapedTraversal(t *testing.T) {
	urls := []string{
		"https://api.github.com/repos/turenlabs/spice-detections/contents/packs/%2e%2e/manifest.json?ref=main",
		"https://raw.githubusercontent.com/turenlabs/spice-detections/main/packs/%2e%2e/manifest.json",
	}
	for _, location := range urls {
		t.Run(location, func(t *testing.T) {
			err := validateTrustedDetectionURL(location)
			if err == nil {
				t.Fatal("validateTrustedDetectionURL() expected escaped traversal rejection")
			}
			if !strings.Contains(err.Error(), "unsafe detection path") {
				t.Fatalf("validateTrustedDetectionURL() error = %q", err)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
