package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

type countingDetection struct {
	calls int
}

func (d *countingDetection) ID() string {
	return "test-business-logic"
}

func (d *countingDetection) Campaign() string {
	return "test"
}

func (d *countingDetection) ScanGlobal(emit EmitFinding) {}

func (d *countingDetection) ScanFile(file FileContext, emit EmitFinding) {
	d.calls++
	emit(Finding{
		DetectionID: d.ID(),
		Campaign:    d.Campaign(),
		Severity:    "medium",
		Kind:        "test-scan",
		Path:        file.Path,
		Evidence:    "scanner business logic exercised",
		Remediation: "test only",
	})
}

func (d *countingDetection) WatchEvent(event fsnotify.Event) []WatchEvent {
	return nil
}

func TestScannerCacheReusesSameProfileAndSeparatesProfileVersions(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"cache-profile-test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	detection := &countingDetection{}
	projectScanner := NewScannerWithOptions(index, nil)
	projectScanner.detections = []Detection{detection}
	firstFindings, err := projectScanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if detection.calls != 1 || len(firstFindings) != 1 {
		t.Fatalf("expected first project scan to call detector once and return one finding, calls=%d findings=%#v", detection.calls, firstFindings)
	}

	secondProjectScanner := NewScannerWithOptions(index, nil)
	secondProjectScanner.detections = []Detection{detection}
	secondFindings, err := secondProjectScanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if detection.calls != 1 {
		t.Fatalf("expected same-profile scan to reuse cached finding without detector call, got %d calls", detection.calls)
	}
	if len(secondFindings) != 1 || secondFindings[0].Path != manifest {
		t.Fatalf("expected cached finding for manifest, got %#v", secondFindings)
	}

	deepScanner := NewScannerWithOptions(index, nil)
	deepScanner.SetProfile(ScanProfileDeep)
	deepScanner.detections = []Detection{detection}
	deepFindings, err := deepScanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if detection.calls != 2 {
		t.Fatalf("expected different profile cache version to rescan content, got %d calls", detection.calls)
	}
	if len(deepFindings) != 1 || deepFindings[0].Path != manifest {
		t.Fatalf("expected deep scan finding for manifest, got %#v", deepFindings)
	}
}

func TestPreCanceledScanStopsBeforeIndexWrites(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"cancel-test"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var progress []ScanProgress
	findings, err := NewScannerWithOptions(index, func(item ScanProgress) {
		progress = append(progress, item)
	}).ScanContext(ctx, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected canceled scan to return no findings, got %#v", findings)
	}
	if len(progress) == 0 || !progress[len(progress)-1].Done || progress[len(progress)-1].Status != "stopped" {
		t.Fatalf("expected stopped final progress, got %#v", progress)
	}
	if got := countRows(t, index, "file_index"); got != 0 {
		t.Fatalf("expected no index writes after pre-canceled scan, got %d", got)
	}
}

func TestCanceledAppScanDoesNotReplaceLastCompletedScanHistory(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("HOME", configHome)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(configHome, ".config"))

	root := filepath.Join(t.TempDir(), "project")
	manifest := filepath.Join(root, "package.json")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte(`{"name":"history-cancel-test"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenFileIndex()
	if err != nil {
		t.Fatal(err)
	}
	previous := ScanResult{
		StartedAt:  "2026-05-12T10:00:00Z",
		FinishedAt: "2026-05-12T10:00:02Z",
		Roots:      []string{root},
		Findings: []Finding{{
			DetectionID: "previous",
			Campaign:    "test",
			Severity:    "high",
			Kind:        "test-history",
			Path:        manifest,
			Evidence:    "completed scan finding",
		}},
		Indexed: true,
		Status:  "completed",
	}
	if err := index.SaveScanRun(previous); err != nil {
		t.Fatal(err)
	}
	if err := index.Close(); err != nil {
		t.Fatal(err)
	}

	app := NewApp()
	type scanResponse struct {
		result ScanResult
		err    error
	}
	done := make(chan scanResponse, 1)
	go func() {
		result, err := app.Scan(ScanRequest{Paths: []string{root}})
		done <- scanResponse{result: result, err: err}
	}()

	deadline := time.After(2 * time.Second)
	for {
		app.scanCancelMu.Lock()
		ready := app.scanCancel != nil
		app.scanCancelMu.Unlock()
		if ready {
			break
		}
		select {
		case <-deadline:
			t.Fatal("scan did not install cancellation handler")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	app.StopScan()
	app.markDetectionReady()

	select {
	case response := <-done:
		if response.err != nil {
			t.Fatal(response.err)
		}
		if response.result.Status != "canceled" {
			t.Fatalf("expected canceled scan result, got %#v", response.result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled scan did not return")
	}

	got, err := app.LastScan()
	if err != nil {
		t.Fatal(err)
	}
	if got.FinishedAt != previous.FinishedAt || got.Status != "completed" || len(got.Findings) != 1 || got.Findings[0].Evidence != previous.Findings[0].Evidence {
		t.Fatalf("expected last completed scan history to remain unchanged, got %#v", got)
	}
}

func TestExcludedDirsRespectPathBoundariesAndChangedPathScans(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "cache")
	excludedManifest := filepath.Join(excluded, "package.json")
	siblingManifest := filepath.Join(dir, "cache-other", "package.json")
	if err := os.MkdirAll(filepath.Dir(excludedManifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(siblingManifest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(excludedManifest, []byte(`{"name":"excluded"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(siblingManifest, []byte(`{"name":"included"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	detection := &countingDetection{}
	scanner := NewScannerWithOptions(nil, nil)
	scanner.detections = []Detection{detection}
	scanner.SetExcludedDirs([]string{excluded})

	if !scanner.shouldExcludePath(excludedManifest) {
		t.Fatal("expected nested excluded manifest to be excluded")
	}
	if scanner.shouldExcludePath(siblingManifest) {
		t.Fatal("expected similarly-prefixed sibling path not to be excluded")
	}
	if findings := scanner.ScanChangedPath(excludedManifest); len(findings) != 0 {
		t.Fatalf("expected changed-path scan to skip excluded file, got %#v", findings)
	}
	findings := scanner.ScanChangedPath(siblingManifest)
	if len(findings) != 1 || findings[0].Path != siblingManifest {
		t.Fatalf("expected changed-path scan to include sibling file, got %#v", findings)
	}
}

func TestClearLocalDataPreservesSettingsAndClearsScanArtifacts(t *testing.T) {
	dir := t.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	excluded := filepath.Join(dir, "excluded")
	if err := index.SaveSettings(AppSettings{ExcludedDirs: []string{excluded}}); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(dir, "package.json")
	entry := scanFileEntry{path: sourcePath, size: 2, mtimeUnixNano: time.Now().UnixNano()}
	if err := index.UpsertBatch([]indexWrite{{
		entry:  entry,
		digest: HashBytes([]byte("{}")),
		findings: []Finding{{
			DetectionID: "test",
			Campaign:    "test",
			Severity:    "medium",
			Kind:        "test-finding",
			Path:        sourcePath,
			Evidence:    "stored finding",
		}},
		packages: []PackageRef{{
			Ecosystem:  "npm",
			Name:       "left-pad",
			Version:    "1.3.0",
			SourceKind: "dependencies",
		}},
	}}, "test-engine"); err != nil {
		t.Fatal(err)
	}
	if err := index.SaveScanRun(ScanResult{
		StartedAt:  time.Now().Add(-time.Second).Format(time.RFC3339),
		FinishedAt: time.Now().Format(time.RFC3339),
		Roots:      []string{dir},
	}); err != nil {
		t.Fatal(err)
	}

	if err := index.ClearLocalData(); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"file_findings", "file_index", "package_inventory", "scan_runs"} {
		if got := countRows(t, index, table); got != 0 {
			t.Fatalf("expected %s to be cleared, got %d rows", table, got)
		}
	}
	settings, err := index.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.ExcludedDirs) != 1 || settings.ExcludedDirs[0] != excluded {
		t.Fatalf("expected settings to survive clear-local-data, got %#v", settings)
	}
}

func TestInventoryDeduplicatesBySourceDigestAndAppliesFilters(t *testing.T) {
	dir := t.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	sameDigest := HashBytes([]byte("same lock content"))
	differentDigest := HashBytes([]byte("different lock content"))
	writes := []indexWrite{
		inventoryWrite(filepath.Join(dir, "a", "package.json"), sameDigest, PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SourceKind: "dependencies"}),
		inventoryWrite(filepath.Join(dir, "b", "package.json"), sameDigest, PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SourceKind: "dependencies"}),
		inventoryWrite(filepath.Join(dir, "c", "package.json"), differentDigest, PackageRef{Ecosystem: "npm", Name: "left-pad", Version: "1.3.0", SourceKind: "dependencies"}),
		inventoryWrite(filepath.Join(dir, "requirements.txt"), HashBytes([]byte("requests==2.32.0")), PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0", SourceKind: "requirements"}),
	}
	if err := index.UpsertBatch(writes, "test-engine"); err != nil {
		t.Fatal(err)
	}

	all, err := index.ListPackageInventory(InventoryRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 3 || len(all.Packages) != 3 {
		t.Fatalf("expected inventory to dedupe same package from same source digest, got total=%d packages=%#v", all.Total, all.Packages)
	}

	filtered, err := index.ListPackageInventory(InventoryRequest{
		Limit:      10,
		Query:      "LEFT",
		Ecosystem:  "npm",
		SourceKind: "dependencies",
	})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 2 || len(filtered.Packages) != 2 {
		t.Fatalf("expected filtered npm inventory to include two source digests, got total=%d packages=%#v", filtered.Total, filtered.Packages)
	}
	for _, pkg := range filtered.Packages {
		if pkg.Ecosystem != "npm" || pkg.Name != "left-pad" || !strings.HasSuffix(pkg.SourcePath, "package.json") {
			t.Fatalf("unexpected filtered package: %#v", pkg)
		}
	}
	assertInventoryBin(t, all.EcosystemCounts, "npm", 2)
	assertInventoryBin(t, all.EcosystemCounts, "pypi", 1)
	assertInventoryBin(t, all.SourceKindCounts, "dependencies", 2)
	assertInventoryBin(t, all.SourceKindCounts, "requirements", 1)
}

func inventoryWrite(path string, digest string, pkg PackageRef) indexWrite {
	return indexWrite{
		entry: scanFileEntry{
			path:          path,
			size:          int64(len(digest)),
			mtimeUnixNano: time.Now().UnixNano(),
		},
		digest:   digest,
		packages: []PackageRef{pkg},
	}
}

func countRows(t *testing.T, index *ScanIndex, table string) int {
	t.Helper()

	query := ""
	switch table {
	case "file_findings":
		query = `SELECT COUNT(*) FROM file_findings`
	case "file_index":
		query = `SELECT COUNT(*) FROM file_index`
	case "package_inventory":
		query = `SELECT COUNT(*) FROM package_inventory`
	case "scan_runs":
		query = `SELECT COUNT(*) FROM scan_runs`
	default:
		t.Fatalf("unsupported table %q", table)
	}

	var count int
	if err := index.db.QueryRow(query).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func assertInventoryBin(t *testing.T, bins []InventoryBin, value string, count int) {
	t.Helper()

	for _, bin := range bins {
		if bin.Value == value {
			if bin.Count != count {
				t.Fatalf("expected inventory bin %q count %d, got %d in %#v", value, count, bin.Count, bins)
			}
			return
		}
	}
	t.Fatalf("missing inventory bin %q in %#v", value, bins)
}
