package main

import (
	"fmt"
	"os"
	"runtime/debug"
	"strings"
)

var (
	buildVersion string
	buildCommit  string
)

func cliVersionString() string {
	version, commit := buildMetadata()
	return fmt.Sprintf("spice %s (%s)", version, commit)
}

func buildMetadata() (string, string) {
	version := strings.TrimSpace(buildVersion)
	if version == "" {
		version = versionFromFile()
	}
	if version == "" {
		version = "dev"
	}

	commit := strings.TrimSpace(buildCommit)
	if commit == "" {
		commit = commitFromBuildInfo()
	}
	if commit == "" {
		commit = "unknown"
	}

	return version, commit
}

func versionFromFile() string {
	raw, err := os.ReadFile("VERSION")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func commitFromBuildInfo() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return shortCommit(setting.Value)
		}
	}
	return ""
}

func shortCommit(commit string) string {
	commit = strings.TrimSpace(commit)
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}
