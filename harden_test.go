package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHardenPresetFromValues(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]string
		want   string
	}{
		{
			name: "recommended",
			values: map[string]string{
				"min-release-age": "7",
				"save-exact":      "true",
				"allow-git":       "none",
				"ignore-scripts":  "false",
			},
			want: "recommended",
		},
		{
			name: "strict",
			values: map[string]string{
				"min-release-age": "14",
				"save-exact":      "true",
				"allow-git":       "none",
				"ignore-scripts":  "true",
			},
			want: "strict",
		},
		{
			name: "defaults",
			values: map[string]string{
				"min-release-age": "null",
				"save-exact":      "false",
				"allow-git":       "all",
				"ignore-scripts":  "false",
			},
			want: "defaults",
		},
		{
			name: "custom",
			values: map[string]string{
				"min-release-age": "3",
				"save-exact":      "true",
				"allow-git":       "none",
				"ignore-scripts":  "false",
			},
			want: "custom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hardenPresetFromValues(tt.values); got != tt.want {
				t.Fatalf("hardenPresetFromValues() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSettingStatusNullAliases(t *testing.T) {
	for _, value := range []string{"", "null", "undefined"} {
		if got := settingStatus(value, "null"); got != "ok" {
			t.Fatalf("settingStatus(%q, null) = %q, want ok", value, got)
		}
	}
	if got := settingStatus("7", "null"); got != "warn" {
		t.Fatalf("settingStatus(7, null) = %q, want warn", got)
	}
}

func TestGuardrailStatusForKey(t *testing.T) {
	tests := []struct {
		key   string
		value string
		want  string
	}{
		{key: "min-release-age", value: "7", want: "ok"},
		{key: "min-release-age", value: "14", want: "ok"},
		{key: "min-release-age", value: "null", want: "warn"},
		{key: "save-exact", value: "true", want: "ok"},
		{key: "allow-git", value: "none", want: "ok"},
		{key: "ignore-scripts", value: "true", want: "ok"},
		{key: "ignore-scripts", value: "false", want: "ok"},
	}
	for _, tt := range tests {
		t.Run(tt.key+"="+tt.value, func(t *testing.T) {
			if got := guardrailStatusForKey(tt.key, tt.value); got != tt.want {
				t.Fatalf("guardrailStatusForKey(%q, %q) = %q, want %q", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

func TestParseNPMConfigValue(t *testing.T) {
	contents := `
; comment
save-exact=true
min-release-age=7
save-prefix=""
`
	if got, ok := parseNPMConfigValue(contents, "min-release-age"); !ok || got != "7" {
		t.Fatalf("parseNPMConfigValue(min-release-age) = %q, %v; want 7, true", got, ok)
	}
	if got, ok := parseNPMConfigValue(contents, "save-prefix"); !ok || got != "null" {
		t.Fatalf("parseNPMConfigValue(save-prefix) = %q, %v; want null, true", got, ok)
	}
	if got, ok := parseNPMConfigValue(contents, "missing"); ok || got != "" {
		t.Fatalf("parseNPMConfigValue(missing) = %q, %v; want empty, false", got, ok)
	}
}

func TestCommandEnvWithPackageManagerPath(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")

	env := commandEnvWithPackageManagerPath("/opt/homebrew/bin/npm")
	path := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			path = strings.TrimPrefix(entry, "PATH=")
			break
		}
	}
	if path == "" {
		t.Fatal("PATH was not set")
	}
	parts := filepath.SplitList(path)
	if len(parts) == 0 || parts[0] != "/opt/homebrew/bin" {
		t.Fatalf("PATH first entry = %q; want /opt/homebrew/bin", parts)
	}
	if strings.Count(path, "/opt/homebrew/bin") != 1 {
		t.Fatalf("PATH should not duplicate /opt/homebrew/bin: %q", path)
	}
}
