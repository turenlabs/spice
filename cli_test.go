package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIVersionUsesBuildMetadata(t *testing.T) {
	withBuildMetadata(t, "1.2.3", "abc1234")

	output, code := captureStdout(t, func() int {
		return runCLI([]string{"version"})
	})

	if code != 0 {
		t.Fatalf("runCLI(version) exit code = %d, want 0", code)
	}
	if output != "spice 1.2.3 (abc1234)\n" {
		t.Fatalf("runCLI(version) output = %q", output)
	}
}

func TestCLIVersionFallsBackToVersionFile(t *testing.T) {
	withBuildMetadata(t, "", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("9.8.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("restore working directory: %v", err)
		}
	})

	output, code := captureStdout(t, func() int {
		return runCLI([]string{"version"})
	})

	if code != 0 {
		t.Fatalf("runCLI(version) exit code = %d, want 0", code)
	}
	if !strings.HasPrefix(output, "spice 9.8.7 (") {
		t.Fatalf("runCLI(version) output = %q", output)
	}
	if strings.TrimSpace(output) == "spice dev" {
		t.Fatalf("runCLI(version) output still uses dev placeholder: %q", output)
	}
}

func TestParseScanArgsAcceptsStartupProfile(t *testing.T) {
	_, _, profile, roots, err := parseScanArgs([]string{"--profile", "startup"})
	if err != nil {
		t.Fatal(err)
	}
	if profile != ScanProfileStartup {
		t.Fatalf("profile = %q, want %q", profile, ScanProfileStartup)
	}
	if len(roots) != 0 {
		t.Fatalf("parseScanArgs should not inject roots, got %#v", roots)
	}
}

func withBuildMetadata(t *testing.T, version, commit string) {
	t.Helper()
	previousVersion := buildVersion
	previousCommit := buildCommit
	buildVersion = version
	buildCommit = commit
	t.Cleanup(func() {
		buildVersion = previousVersion
		buildCommit = previousCommit
	})
}

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	previousStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	t.Cleanup(func() {
		os.Stdout = previousStdout
	})

	code := fn()

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output), code
}
