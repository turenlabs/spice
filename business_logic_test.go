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
	calls    int
	severity string
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
	severity := d.severity
	if severity == "" {
		severity = "medium"
	}
	emit(Finding{
		DetectionID: d.ID(),
		Campaign:    d.Campaign(),
		Severity:    severity,
		Kind:        "test-scan",
		Path:        file.Path,
		Evidence:    "scanner business logic exercised",
		Remediation: "test only",
	})
}

func (d *countingDetection) WatchEvent(event fsnotify.Event) []WatchEvent {
	return nil
}

func TestReferencePathFindingsAreDemotedByDefault(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{
		filepath.Join("testdata", "package.json"),
		filepath.Join("fixtures", "package.json"),
	} {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"name":"reference-fixture"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	detection := &countingDetection{severity: "critical"}
	scanner := NewScannerWithOptions(nil, nil)
	scanner.detections = []Detection{detection}
	findings, err := scanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected fixture findings to remain visible but demoted, got %#v", findings)
	}
	for _, finding := range findings {
		if finding.Severity != "low" || finding.Confidence != "reference" || finding.Context != "reference or test fixture" {
			t.Fatalf("expected demoted reference finding, got %#v", finding)
		}
		if !strings.Contains(finding.Remediation, "reference or fixture") {
			t.Fatalf("expected reference remediation guidance, got %#v", finding)
		}
	}
}

func TestReferencePathDemotionCoversArchiveMemberPaths(t *testing.T) {
	finding := enrichFinding(Finding{
		DetectionID: "test",
		Campaign:    "test",
		Severity:    "high",
		Kind:        "ioc-string",
		Path:        "/tmp/package.tgz!fixtures/setup.mjs",
		Evidence:    "scanner business logic exercised",
		Remediation: "test only",
	})
	if finding.Severity != "low" || finding.Confidence != "reference" || finding.Context != "reference or test fixture" {
		t.Fatalf("expected archive fixture member to be demoted, got %#v", finding)
	}
}

func TestDefaultSuppressionSkipsSystemVolumesDataDuplicatePath(t *testing.T) {
	if !shouldSuppressDefaultPath("/System/Volumes/Data/Users/alice/project/package.json") {
		t.Fatal("expected macOS Data volume duplicate path to be suppressed")
	}
	if shouldSuppressDefaultPath("/Users/alice/project/package.json") {
		t.Fatal("expected normal user path not to be suppressed")
	}
}

func TestStartupProfileDefaultRootsCoverUserAndSystemStartupItems(t *testing.T) {
	roots := defaultRootsForProfile(ScanProfileStartup)
	joined := strings.Join(roots, "\n")
	for _, want := range []string{
		"~/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"~/.config/systemd/user",
		"/etc/systemd/system",
		"~/.config/autostart",
		"~/.zshrc",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected startup roots to include %q, got %#v", want, roots)
		}
	}
}

func TestDeepProfileDefaultRootsIncludeSystemStartupItems(t *testing.T) {
	roots := defaultRootsForProfile(ScanProfileDeep)
	joined := strings.Join(roots, "\n")
	for _, want := range []string{"~", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/etc/systemd/system"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected deep roots to include %q, got %#v", want, roots)
		}
	}
}

func TestStartupProfileScansStartupPathsOnly(t *testing.T) {
	dir := t.TempDir()
	startupFile := filepath.Join(dir, "Library", "LaunchDaemons", "com.example.test.plist")
	ordinaryFile := filepath.Join(dir, "notes.txt")
	if err := os.MkdirAll(filepath.Dir(startupFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(startupFile, []byte(`<plist></plist>`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinaryFile, []byte(`ordinary text`), 0o644); err != nil {
		t.Fatal(err)
	}

	detection := &countingDetection{}
	scanner := NewScannerWithOptions(nil, nil)
	scanner.SetProfile(ScanProfileStartup)
	scanner.detections = []Detection{detection}
	findings, err := scanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if detection.calls != 1 {
		t.Fatalf("expected startup profile to scan only startup path, got %d detector calls", detection.calls)
	}
	if len(findings) != 1 || findings[0].Path != startupFile {
		t.Fatalf("expected only startup finding, got %#v", findings)
	}
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

func TestScanSkipsOversizedGenericPackageArchives(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "training-data.tar.gz")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxPackageArchiveScanBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer index.Close()

	detection := &countingDetection{}
	scanner := NewScannerWithOptions(index, nil)
	scanner.SetProfile(ScanProfileShaiHulud)
	scanner.detections = []Detection{detection}
	findings, err := scanner.Scan([]string{dir})
	if err != nil {
		t.Fatal(err)
	}
	if detection.calls != 0 || len(findings) != 0 {
		t.Fatalf("expected oversized generic archive to stay metadata-only, calls=%d findings=%#v", detection.calls, findings)
	}

	var indexed int
	if err := index.db.QueryRow(`SELECT COUNT(*) FROM file_index WHERE path = ?`, archive).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != 0 {
		t.Fatalf("expected oversized metadata-only archive not to be stored as a scanned file, got %d rows", indexed)
	}
}

func TestFindingEnrichmentDemotesReferencePathsAndCanonicalizesDataVolume(t *testing.T) {
	finding := enrichFinding(Finding{
		DetectionID: "mini-shai-hulud-2026-05",
		Campaign:    "Mini Shai-Hulud May 2026",
		Severity:    "critical",
		Kind:        "affected-package",
		Path:        "/System/Volumes/Data/Users/tom/project/testdata/package-lock.json",
		Evidence:    "axios@1.14.1 in package-lock",
		Remediation: "Remove the affected version.",
	})

	if finding.Path != "/Users/tom/project/testdata/package-lock.json" {
		t.Fatalf("expected data volume path to be canonicalized, got %q", finding.Path)
	}
	if finding.Severity != "low" || finding.Confidence != "reference" || finding.Context != "reference or test fixture" {
		t.Fatalf("expected reference path to be demoted, got severity=%q confidence=%q context=%q", finding.Severity, finding.Confidence, finding.Context)
	}
	if !strings.Contains(finding.Remediation, "reference or fixture") {
		t.Fatalf("expected remediation to mention reference context, got %q", finding.Remediation)
	}
}

func TestFindingEnrichmentKeepsConfirmedHashCriticalInFixtures(t *testing.T) {
	finding := enrichFinding(Finding{
		DetectionID: "mini-shai-hulud-2026-05",
		Campaign:    "Mini Shai-Hulud May 2026",
		Severity:    "critical",
		Kind:        "known-malware-hash",
		Path:        "/Users/tom/project/fixtures/payload.js",
		Evidence:    "sha256=abc",
	})

	if finding.Severity != "critical" || finding.Confidence != "confirmed" {
		t.Fatalf("expected confirmed hash to remain critical, got severity=%q confidence=%q", finding.Severity, finding.Confidence)
	}
	if finding.Context != "reference or test fixture" {
		t.Fatalf("expected context to still mark fixture path, got %q", finding.Context)
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
		inventoryWrite(filepath.Join(dir, "project", "node_modules", "react", "package.json"), HashBytes([]byte("react lock content")), PackageRef{Ecosystem: "npm", Name: "react", Version: "19.0.0", SourceKind: "dependencies"}),
		inventoryWrite(filepath.Join(dir, "requirements.txt"), HashBytes([]byte("requests==2.32.0")), PackageRef{Ecosystem: "pypi", Name: "requests", Version: "2.32.0", SourceKind: "requirements"}),
	}
	if err := index.UpsertBatch(writes, "test-engine"); err != nil {
		t.Fatal(err)
	}

	all, err := index.ListPackageInventory(InventoryRequest{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if all.Total != 4 || len(all.Packages) != 4 {
		t.Fatalf("expected inventory to dedupe same package from same source digest, got total=%d packages=%#v", all.Total, all.Packages)
	}

	filtered, err := index.ListPackageInventory(InventoryRequest{
		Limit:      10,
		Query:      "left",
		Ecosystem:  "npm",
		SourceKind: "dependencies",
	})
	if err != nil {
		t.Fatal(err)
	}
	if filtered.Total != 2 || len(filtered.Packages) != 2 {
		t.Fatalf("expected filtered npm inventory to include two source digests, got total=%d packages=%#v", filtered.Total, filtered.Packages)
	}
	hyphenated, err := index.ListPackageInventory(InventoryRequest{Limit: 10, Query: "left-pad"})
	if err != nil {
		t.Fatal(err)
	}
	if hyphenated.Total != 2 || len(hyphenated.Packages) != 2 {
		t.Fatalf("expected hyphenated free-text inventory query to use FTS tokens, got total=%d packages=%#v", hyphenated.Total, hyphenated.Packages)
	}
	var duplicateSource PackageRef
	for _, pkg := range filtered.Packages {
		if pkg.Ecosystem != "npm" || pkg.Name != "left-pad" || !strings.HasSuffix(pkg.SourcePath, "package.json") {
			t.Fatalf("unexpected filtered package: %#v", pkg)
		}
		if pkg.SourceCount == 2 {
			duplicateSource = pkg
		}
		if pkg.SourceID == "" {
			t.Fatalf("expected inventory row to include source ID: %#v", pkg)
		}
	}
	if duplicateSource.Name == "" {
		t.Fatalf("expected deduped row to report two source locations: %#v", filtered.Packages)
	}
	locations, err := index.ListPackageLocations(InventoryLocationsRequest{
		Ecosystem:  duplicateSource.Ecosystem,
		Name:       duplicateSource.Name,
		Version:    duplicateSource.Version,
		SourceKind: duplicateSource.SourceKind,
		SourceID:   duplicateSource.SourceID,
		Limit:      10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if locations.Total != 2 || len(locations.Locations) != 2 {
		t.Fatalf("expected two locations for deduped source digest, got %#v", locations)
	}
	for _, location := range locations.Locations {
		if location.SourceSHA256 != duplicateSource.SourceID {
			t.Fatalf("expected location source digest %q, got %#v", duplicateSource.SourceID, location)
		}
	}
	assertInventoryBin(t, all.EcosystemCounts, "npm", 3)
	assertInventoryBin(t, all.EcosystemCounts, "pypi", 1)
	assertInventoryBin(t, all.SourceKindCounts, "dependencies", 3)
	assertInventoryBin(t, all.SourceKindCounts, "requirements", 1)

	withoutFacets, err := index.ListPackageInventory(InventoryRequest{Limit: 10, SkipFacets: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutFacets.EcosystemCounts) != 0 || len(withoutFacets.SourceKindCounts) != 0 {
		t.Fatalf("expected skip facets request to omit count bins, got %#v", withoutFacets)
	}

	structured, err := index.ListPackageInventory(InventoryRequest{
		Limit: 10,
		Query: `ecosystem:npm name:left source:dependencies path:/a/`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if structured.Total != 1 || len(structured.Packages) != 1 || !strings.Contains(structured.Packages[0].SourcePath, string(filepath.Separator)+"a"+string(filepath.Separator)) {
		t.Fatalf("expected structured inventory query to filter by ecosystem/name/source/path, got total=%d packages=%#v", structured.Total, structured.Packages)
	}

	pathFTS, err := index.ListPackageInventory(InventoryRequest{
		Limit: 10,
		Query: `path:node_modules`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pathFTS.Total != 1 || len(pathFTS.Packages) != 1 || pathFTS.Packages[0].Name != "react" {
		t.Fatalf("expected path:node_modules to use path-scoped indexed search, got total=%d packages=%#v", pathFTS.Total, pathFTS.Packages)
	}

	quoted, err := index.ListPackageInventory(InventoryRequest{
		Limit: 10,
		Query: `"left banana"`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if quoted.Total != 0 {
		t.Fatalf("expected quoted unmatched free text to return no rows, got %#v", quoted)
	}
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
