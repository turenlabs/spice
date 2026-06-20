package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
)

type Detection interface {
	ID() string
	Campaign() string
	ScanGlobal(emit EmitFinding)
	ScanFile(file FileContext, emit EmitFinding)
	WatchEvent(event fsnotify.Event) []WatchEvent
}

type EmitFinding func(Finding)

type FileContext struct {
	Path  string
	Base  string
	Slash string
	Data  []byte
}

func (f FileContext) ReadAll(maxBytes int64) ([]byte, bool) {
	if f.Data != nil {
		if int64(len(f.Data)) > maxBytes {
			return nil, false
		}
		return f.Data, true
	}
	info, err := os.Stat(f.Path)
	if err != nil || info.Size() > maxBytes {
		return nil, false
	}
	data, err := os.ReadFile(f.Path)
	return data, err == nil
}

func (f FileContext) ReadJSON(dest any) bool {
	if f.Data != nil {
		return json.Unmarshal(f.Data, dest) == nil
	}
	file, err := os.Open(f.Path)
	if err != nil {
		return false
	}
	defer file.Close()
	return json.NewDecoder(file).Decode(dest) == nil
}

type Scanner struct {
	detections          []Detection
	index               *FileIndex
	progress            ScanProgressFunc
	finding             ScanFindingFunc
	ctx                 context.Context
	deep                bool
	profile             ScanProfile
	suspiciousFilenames map[string]bool
	ruleCacheVersion    string
	excludedDirs        []string
}

func NewScanner() *Scanner {
	return NewScannerWithOptions(nil, nil)
}

type ScanProfile string

const (
	ScanProfileProject   ScanProfile = "project"
	ScanProfileShaiHulud ScanProfile = "shai-hulud"
	ScanProfileStartup   ScanProfile = "startup"
	ScanProfileDeep      ScanProfile = "deep"
)

type ScanProgressFunc func(ScanProgress)
type ScanFindingFunc func(Finding)

type ScanProgress struct {
	ScanID      string `json:"scanId"`
	Seq         int64  `json:"seq"`
	Status      string `json:"status"`
	Phase       string `json:"phase"`
	CurrentPath string `json:"currentPath"`
	Total       int    `json:"total"`
	Processed   int    `json:"processed"`
	Scanned     int    `json:"scanned"`
	Skipped     int    `json:"skipped"`
	Findings    int    `json:"findings"`
	Percent     int    `json:"percent"`
	Done        bool   `json:"done"`
}

type scanFileEntry struct {
	path          string
	size          int64
	mtimeUnixNano int64
}

type scanFileResult struct {
	entry    scanFileEntry
	findings []Finding
	packages []PackageRef
	digest   string
	cached   bool
	scanned  bool
	err      error
}

type scanDecision int

const (
	scanMetadataOnly scanDecision = iota
	scanContent
)

const (
	maxInMemoryScanBytes       int64 = 16 * 1024 * 1024
	maxPackageArchiveScanBytes int64 = 128 * 1024 * 1024
)

func NewScannerWithOptions(index *FileIndex, progress ScanProgressFunc) *Scanner {
	return &Scanner{
		index:               index,
		progress:            progress,
		profile:             ScanProfileProject,
		suspiciousFilenames: map[string]bool{},
		ruleCacheVersion:    scanEngineVersion + ":no-rules",
	}
}

func (s *Scanner) UseRemoteDetectionBundle(bundle *RemoteDetectionBundle) {
	if bundle == nil {
		return
	}
	var detections []Detection
	suspicious := map[string]bool{}
	for _, pack := range bundle.Packs {
		if remotePackHasRules(pack) {
			detections = append(detections, NewMiniShaiHuludDetectionWithRemote(pack))
		}
		for _, name := range pack.SuspiciousFilenames {
			suspicious[strings.ToLower(name)] = true
		}
	}
	if len(detections) > 0 {
		s.detections = detections
		s.suspiciousFilenames = suspicious
		if bundle.Fingerprint != "" {
			s.ruleCacheVersion = scanEngineVersion + ":" + bundle.Fingerprint
		} else {
			s.ruleCacheVersion = scanEngineVersion + ":remote"
		}
	}
}

func remotePackHasRules(pack *RemoteDetectionPack) bool {
	return pack != nil &&
		(pack.ID != "" || pack.Campaign != "") &&
		(len(pack.AffectedVersions) > 0 ||
			len(pack.AffectedVersionsByEcosystem) > 0 ||
			len(pack.IOCs) > 0 ||
			len(pack.CompositeIOCs) > 0 ||
			len(pack.SuspiciousFilenames) > 0 ||
			len(pack.KnownSHA256) > 0 ||
			len(pack.KnownSHA1) > 0)
}

func (s *Scanner) cacheVersion() string {
	if s == nil || s.ruleCacheVersion == "" {
		return scanEngineVersion + ":profile=project:no-rules"
	}
	return scanEngineVersion + ":profile=" + string(s.profile) + ":" + strings.TrimPrefix(s.ruleCacheVersion, scanEngineVersion+":")
}

func (s *Scanner) Scan(roots []string) ([]Finding, error) {
	return s.ScanContext(context.Background(), roots)
}

func (s *Scanner) ScanContext(ctx context.Context, roots []string) ([]Finding, error) {
	s.ctx = ctx
	pipeline := newScanPipeline(s)
	return pipeline.Run(roots)
}

func (s *Scanner) SetProfile(profile ScanProfile) {
	if s == nil {
		return
	}
	switch profile {
	case ScanProfileShaiHulud, ScanProfileStartup, ScanProfileDeep:
		s.profile = profile
	default:
		s.profile = ScanProfileProject
	}
}

func (s *Scanner) SetExcludedDirs(paths []string) {
	if s == nil {
		return
	}
	seen := map[string]bool{}
	var excluded []string
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		abs, err := filepath.Abs(expandHome(path))
		if err != nil {
			abs = filepath.Clean(path)
		}
		abs = filepath.Clean(abs)
		if seen[abs] {
			continue
		}
		seen[abs] = true
		excluded = append(excluded, abs)
	}
	sort.Strings(excluded)
	s.excludedDirs = excluded
}

func (s *Scanner) shouldExcludePath(path string) bool {
	if s == nil || len(s.excludedDirs) == 0 {
		return false
	}
	abs, err := filepath.Abs(expandHome(path))
	if err != nil {
		abs = filepath.Clean(path)
	}
	abs = filepath.Clean(abs)
	for _, excluded := range s.excludedDirs {
		if abs == excluded {
			return true
		}
		rel, err := filepath.Rel(excluded, abs)
		if err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func shouldSuppressDefaultPath(path string) bool {
	slash := strings.ToLower(filepath.ToSlash(filepath.Clean(path)))
	return slash == "/system/volumes/data" || strings.HasPrefix(slash, "/system/volumes/data/")
}

func (s *Scanner) scanGlobals(emit EmitFinding) {
	for _, detection := range s.detections {
		detection.ScanGlobal(emit)
	}
}

func (s *Scanner) scanFileEntry(entry scanFileEntry) scanFileResult {
	return s.scanFileEntryContext(s.ctx, entry)
}

func (s *Scanner) scanFileEntryContext(ctx context.Context, entry scanFileEntry) scanFileResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return scanFileResult{entry: entry, err: err}
	}
	decision := s.classifyScanFile(entry.path, entry.size)
	if decision == scanMetadataOnly {
		return scanFileResult{entry: entry}
	}
	if s.index != nil {
		cached, ok, err := s.index.GetUnchangedContext(ctx, entry.path, entry.size, entry.mtimeUnixNano, s.cacheVersion())
		if err != nil {
			return scanFileResult{entry: entry, err: err}
		}
		if ok {
			var packages []PackageRef
			if cached.PackageCount < 0 {
				packages = ExtractPackages(entry.path)
			}
			return scanFileResult{
				entry:    entry,
				findings: cached.Findings,
				packages: packages,
				digest:   cached.SHA256,
				cached:   true,
				scanned:  true,
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return scanFileResult{entry: entry, err: err}
	}
	var findings []Finding
	var data []byte
	if entry.size <= maxInMemoryScanBytes {
		data, _ = os.ReadFile(entry.path)
	}
	if err := ctx.Err(); err != nil {
		return scanFileResult{entry: entry, err: err}
	}
	s.scanOneFileWithData(entry.path, data, func(finding Finding) {
		findings = append(findings, finding)
	})
	if err := ctx.Err(); err != nil {
		return scanFileResult{entry: entry, err: err}
	}
	digest := ""
	if data != nil {
		digest = HashBytes(data)
	} else {
		var err error
		digest, err = HashFile(entry.path)
		if err != nil {
			return scanFileResult{entry: entry, findings: findings}
		}
	}
	return scanFileResult{
		entry:    entry,
		findings: dedupeFindings(findings),
		packages: ExtractPackagesFromBytes(entry.path, data),
		digest:   digest,
		scanned:  true,
	}
}

func (s *Scanner) classifyScanFile(path string, size int64) scanDecision {
	if s != nil && (s.deep || s.profile == ScanProfileDeep) {
		if shouldSkipDeepContent(path, size) {
			return scanMetadataOnly
		}
		return scanContent
	}
	if s != nil && s.profile == ScanProfileStartup {
		base := strings.ToLower(filepath.Base(path))
		slash := strings.ToLower(filepath.ToSlash(path))
		if isStartupOrTokenPath(slash) || isShaiHuludArtifactBase(base) || s.suspiciousFilenames[base] {
			return scanContent
		}
		return scanMetadataOnly
	}
	if s != nil && s.profile == ScanProfileShaiHulud && classifyShaiHuludVectorFile(path, size, s.suspiciousFilenames) == scanContent {
		return scanContent
	}
	return classifyScanFile(path, size, s.suspiciousFilenames)
}

func classifyScanFile(path string, size int64, suspicious map[string]bool) scanDecision {
	base := strings.ToLower(filepath.Base(path))
	slash := strings.ToLower(filepath.ToSlash(path))
	if isAlwaysScanBase(base) || suspicious[base] || isStartupOrTokenPath(slash) {
		return scanContent
	}
	if isRepoOpenExecutionPath(slash) && textCandidate(path) {
		return scanContent
	}
	if isCIWorkflowPath(slash) && textCandidate(path) {
		return scanContent
	}
	if isPackageArchiveBase(base) {
		if shouldScanPackageArchive(size) {
			return scanContent
		}
		return scanMetadataOnly
	}
	if size > 8*1024*1024 {
		return scanMetadataOnly
	}
	if strings.Contains(slash, "/node_modules/") || strings.Contains(slash, "/.npm/") ||
		strings.Contains(slash, "/.pnpm-store/") || strings.Contains(slash, "/.yarn/") ||
		strings.Contains(slash, "/site-packages/") || strings.Contains(slash, "/dist-packages/") {
		switch {
		case isDependencyLoaderCandidate(base):
			return scanContent
		}
	}
	return scanMetadataOnly
}

func classifyShaiHuludVectorFile(path string, size int64, suspicious map[string]bool) scanDecision {
	base := strings.ToLower(filepath.Base(path))
	slash := strings.ToLower(filepath.ToSlash(path))
	if isAlwaysScanBase(base) || suspicious[base] || isStartupOrTokenPath(slash) || isShaiHuludArtifactBase(base) {
		return scanContent
	}
	if isPackageArchiveBase(base) {
		if shouldScanPackageArchive(size) {
			return scanContent
		}
		return scanMetadataOnly
	}
	if size > 16*1024*1024 {
		return scanMetadataOnly
	}
	if isShaiHuludWorkspacePath(slash) && textCandidate(path) {
		return scanContent
	}
	if isCIWorkflowPath(slash) && textCandidate(path) {
		return scanContent
	}
	if isPackageCachePath(slash) {
		switch {
		case textCandidate(path):
			return scanContent
		case strings.Contains(base, "install") || strings.Contains(base, "setup") || strings.Contains(base, "runtime"):
			return scanContent
		case strings.Contains(base, "router") || strings.Contains(base, "tanstack") || strings.Contains(base, "token"):
			return scanContent
		}
	}
	return scanMetadataOnly
}

func isShaiHuludArtifactBase(base string) bool {
	switch base {
	case "router_init.js", "opensearch_init.js", "router_runtime.js", "tanstack_runner.js", "setup.mjs", "setup_bun.js", "bun_environment.js", "setup-intercom.sh", "composerplugin.php", "package-updated.tgz", "transformers.pyz":
		return true
	case "com.user.gh-token-monitor.plist", "gh-token-monitor.service", "gh-token-monitor.sh":
		return true
	default:
		return false
	}
}

func isShaiHuludWorkspacePath(slash string) bool {
	return strings.Contains(withLeadingSlash(slash), "/.claude/") ||
		strings.Contains(withLeadingSlash(slash), "/.gemini/") ||
		strings.Contains(withLeadingSlash(slash), "/.cursor/rules/") ||
		strings.Contains(withLeadingSlash(slash), "/.vscode/") ||
		isRepoOpenPayloadPath(slash)
}

func isRepoOpenExecutionPath(slash string) bool {
	slash = withLeadingSlash(slash)
	return strings.HasSuffix(slash, "/.claude/settings.json") ||
		strings.HasSuffix(slash, "/.gemini/settings.json") ||
		strings.Contains(slash, "/.cursor/rules/") ||
		strings.HasSuffix(slash, "/.vscode/tasks.json") ||
		isRepoOpenPayloadPath(slash)
}

func isRepoOpenPayloadPath(slash string) bool {
	slash = withLeadingSlash(slash)
	return strings.HasSuffix(slash, "/.github/setup.js") ||
		strings.HasSuffix(slash, "/.github/setup.mjs")
}

func withLeadingSlash(slash string) string {
	if strings.HasPrefix(slash, "/") {
		return slash
	}
	return "/" + slash
}

// isCIWorkflowPath reports whether slash is a GitHub Actions workflow file.
// Workflow YAML is a recurring supply-chain payload host: the Shai-Hulud family
// (and the Miasma variant) plant a malicious release/discussion workflow that
// publishes via OIDC, so these files are content-scanned in every profile rather
// than only deep scans. A workflow file is not suspicious by presence; malicious
// ones are gated by composite IOCs.
func isCIWorkflowPath(slash string) bool {
	return strings.Contains(slash, ".github/workflows/")
}

func isPackageCachePath(slash string) bool {
	return strings.Contains(slash, "/node_modules/") ||
		strings.Contains(slash, "/.npm/") ||
		strings.Contains(slash, "/.pnpm-store/") ||
		strings.Contains(slash, "/.yarn/") ||
		strings.Contains(slash, "/.cache/") ||
		strings.Contains(slash, "/site-packages/") ||
		strings.Contains(slash, "/dist-packages/")
}

func isDependencyLoaderCandidate(base string) bool {
	if base == "_index.js" || base == "binding.gyp" || strings.HasSuffix(base, ".pth") {
		return true
	}
	return strings.Contains(base, "install") ||
		strings.Contains(base, "setup") ||
		strings.Contains(base, "runtime") ||
		strings.Contains(base, "router") ||
		strings.Contains(base, "tanstack") ||
		strings.Contains(base, "token")
}

func shouldSkipDeepContent(path string, size int64) bool {
	if size < 0 {
		return true
	}
	if isPackageArchiveBase(strings.ToLower(filepath.Base(path))) {
		return !shouldScanPackageArchive(size)
	}
	return size > 64*1024*1024
}

func shouldScanPackageArchive(size int64) bool {
	return size >= 0 && size <= maxPackageArchiveScanBytes
}

func isAlwaysScanBase(base string) bool {
	switch {
	case base == "package.json", base == "package-lock.json", base == "npm-shrinkwrap.json":
		return true
	case base == "pnpm-lock.yaml", base == "yarn.lock", base == "bun.lock", base == "bun.lockb":
		return true
	case base == "pyproject.toml", base == "poetry.lock", base == "pipfile", base == "pipfile.lock":
		return true
	case base == "uv.lock", base == "pdm.lock", base == "composer.json", base == "composer.lock":
		return true
	case base == "go.mod", base == "cargo.toml", base == "cargo.lock", base == "build.rs":
		return true
	case base == "metadata":
		return true
	case isAIAgentConfigBase(base):
		return true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."):
		return true
	default:
		return false
	}
}

func isPackageArchiveBase(base string) bool {
	return strings.HasSuffix(base, ".tgz") ||
		strings.HasSuffix(base, ".tar") ||
		strings.HasSuffix(base, ".tar.gz") ||
		strings.HasSuffix(base, ".zip") ||
		strings.HasSuffix(base, ".whl") ||
		strings.HasSuffix(base, ".pyz")
}

func isStartupOrTokenPath(slash string) bool {
	return strings.Contains(slash, "/launchagents/") ||
		strings.Contains(slash, "/launchdaemons/") ||
		strings.Contains(slash, "/.config/systemd/user/") ||
		strings.Contains(slash, "/etc/systemd/user/") ||
		strings.Contains(slash, "/etc/systemd/system/") ||
		strings.Contains(slash, "/.config/autostart/") ||
		strings.Contains(slash, "/etc/xdg/autostart/") ||
		strings.Contains(slash, "/.local/bin/gh-token-monitor.sh") ||
		strings.HasSuffix(slash, "/.npmrc") ||
		strings.HasSuffix(slash, "/.pypirc") ||
		strings.HasSuffix(slash, "/.yarnrc") ||
		strings.Contains(slash, "/.config/gh/") ||
		strings.HasSuffix(slash, "/.zshrc") ||
		strings.HasSuffix(slash, "/.zprofile") ||
		strings.HasSuffix(slash, "/.bashrc") ||
		strings.HasSuffix(slash, "/.bash_profile") ||
		strings.HasSuffix(slash, "/.profile") ||
		strings.HasSuffix(slash, "/.config/fish/config.fish")
}

func (s *Scanner) scanPriority(path string) int {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case base == "package.json", base == "package-lock.json", base == "pnpm-lock.yaml", base == "yarn.lock":
		return 0
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return 1
	case base == "dockerfile" || strings.HasPrefix(base, "dockerfile."):
		return 2
	case s != nil && s.suspiciousFilenames[base]:
		return 3
	case s != nil && s.profile == ScanProfileShaiHulud && isShaiHuludArtifactBase(base):
		return 3
	case s != nil && s.profile == ScanProfileShaiHulud && isShaiHuludWorkspacePath(strings.ToLower(filepath.ToSlash(path))):
		return 4
	case isPackageArchiveBase(base):
		return 5
	case isStartupOrTokenPath(strings.ToLower(filepath.ToSlash(path))):
		return 6
	default:
		return 9
	}
}

func shouldSkipFile(name string) bool {
	switch name {
	case "scan-index.sqlite", "spice.db", "spice.db-shm", "spice.db-wal", "scan-index.sqlite-shm", "scan-index.sqlite-wal":
		return true
	default:
		return false
	}
}

func indexingPercent(processed int, total int) int {
	if total <= 0 {
		return 0
	}
	return int(float64(processed) / float64(total) * 10)
}

func scanPercent(processed int, total int) int {
	if total <= 0 {
		return 10
	}
	percent := 10 + int(float64(processed)/float64(total)*90)
	if processed < total && percent >= 100 {
		return 99
	}
	return percent
}

func (s *Scanner) ScanChangedPath(path string) []Finding {
	var findings []Finding
	emit := func(finding Finding) {
		findings = append(findings, finding)
	}
	if shouldSuppressDefaultPath(path) {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if s.shouldExcludePath(path) {
		return nil
	}
	if !info.IsDir() {
		s.scanOneFile(path, emit)
		return dedupeFindings(findings)
	}
	_ = filepath.WalkDir(path, func(child string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if shouldSuppressDefaultPath(child) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if s.shouldExcludePath(child) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		s.scanOneFile(child, emit)
		return nil
	})
	return dedupeFindings(findings)
}

func (s *Scanner) WatchEvent(event fsnotify.Event) []WatchEvent {
	alerts := []WatchEvent{}
	for _, detection := range s.detections {
		alerts = append(alerts, detection.WatchEvent(event)...)
	}
	return alerts
}

func (s *Scanner) scanOneFile(path string, emit EmitFinding) {
	s.scanOneFileWithData(path, nil, emit)
}

func (s *Scanner) scanOneFileWithData(path string, data []byte, emit EmitFinding) {
	file := FileContext{
		Path:  path,
		Base:  filepath.Base(path),
		Slash: filepath.ToSlash(path),
		Data:  data,
	}
	for _, detection := range s.detections {
		detection.ScanFile(file, emit)
	}
}

func (s *Scanner) emitProgress(progress ScanProgress) {
	if s.progress != nil {
		s.progress(progress)
	}
}

func (s *Scanner) emitFinding(finding Finding) {
	if s.finding != nil {
		s.finding(enrichFinding(finding))
	}
}

func shouldSkipDir(name string) bool {
	switch name {
	case ".git", ".hg", ".svn", ".cache", ".next", ".nuxt", "dist", "build", "coverage":
		return true
	default:
		return false
	}
}

func normalizeVersion(version string) string {
	return strings.TrimLeft(strings.TrimSpace(version), "^~=> <")
}

func packageFromNodeModulesPath(location string) string {
	marker := "node_modules/"
	idx := strings.LastIndex(location, marker)
	if idx == -1 {
		return ""
	}
	pkg := location[idx+len(marker):]
	parts := strings.Split(pkg, "/")
	if strings.HasPrefix(pkg, "@") && len(parts) >= 2 {
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

func textCandidate(path string) bool {
	lower := strings.ToLower(path)
	for _, suffix := range []string{".json", ".lock", ".yaml", ".yml", ".txt", ".log", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".rs", ".toml", ".ini", ".cfg", ".conf", ".plist", ".service", ".pth", ".gyp", ".md", ".mdc"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	base := filepath.Base(lower)
	return base == "package-lock.json" || base == "pnpm-lock.yaml" || base == "yarn.lock" || base == "metadata" || isAIAgentConfigBase(base) || strings.HasPrefix(base, "requirements")
}

// isAIAgentConfigBase reports whether base is an AI-agent instruction/config file.
// Campaigns inject hidden instructions into these to coerce assistants into running
// payloads, so their contents must be IOC-scanned even without a normal text extension.
func isAIAgentConfigBase(base string) bool {
	switch base {
	case ".cursorrules", "claude.md", "agents.md":
		return true
	default:
		return false
	}
}

func dedupeFindings(findings []Finding) []Finding {
	seen := map[string]bool{}
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		finding = enrichFinding(finding)
		key := finding.DetectionID + "\x00" + finding.Severity + "\x00" + finding.Confidence + "\x00" + finding.Kind + "\x00" + finding.Path + "\x00" + finding.Evidence
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, finding)
	}
	return out
}

func sortFindings(findings []Finding) {
	for i := range findings {
		findings[i] = enrichFinding(findings[i])
	}
	weight := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	confidenceWeight := map[string]int{"confirmed": 0, "likely": 1, "exposure": 2, "possible": 3, "reference": 4}
	sort.SliceStable(findings, func(i, j int) bool {
		left := weight[findings[i].Severity]
		right := weight[findings[j].Severity]
		if left != right {
			return left < right
		}
		leftConfidence := confidenceWeight[findings[i].Confidence]
		rightConfidence := confidenceWeight[findings[j].Confidence]
		if leftConfidence != rightConfidence {
			return leftConfidence < rightConfidence
		}
		if findings[i].Path != findings[j].Path {
			return findings[i].Path < findings[j].Path
		}
		return findings[i].Evidence < findings[j].Evidence
	})
}

func enrichFinding(finding Finding) Finding {
	finding.Path = canonicalDisplayPath(finding.Path)
	if finding.Confidence == "" {
		finding.Confidence = defaultFindingConfidence(finding)
	}
	if isReferencePath(finding.Path) {
		finding.Context = "reference or test fixture"
		if finding.Kind != "known-malware-hash" && finding.Kind != "persistence" {
			finding.Confidence = "reference"
			finding.Severity = "low"
			if finding.Remediation != "" && !strings.Contains(finding.Remediation, "reference or fixture") {
				finding.Remediation = "This looks like a reference or fixture path. Confirm whether it is executable project code before treating it as exposure. " + finding.Remediation
			}
		}
	}
	return finding
}

func defaultFindingConfidence(finding Finding) string {
	switch finding.Kind {
	case "known-malware-hash", "persistence":
		return "confirmed"
	case "campaign-artifact":
		return "likely"
	case "affected-package":
		return "exposure"
	case "suspicious-install-hook":
		return "possible"
	case "ioc-string", "archive-artifact":
		if strings.Contains(finding.Evidence, "100% match") {
			return "likely"
		}
		return "possible"
	default:
		return "possible"
	}
}

func canonicalDisplayPath(path string) string {
	const dataPrefix = "/System/Volumes/Data"
	if strings.HasPrefix(path, dataPrefix+"/Users/") {
		return strings.TrimPrefix(path, dataPrefix)
	}
	return path
}

func isReferencePath(path string) bool {
	slash := strings.ToLower(filepath.ToSlash(path))
	parts := strings.FieldsFunc(slash, func(r rune) bool {
		return r == '/' || r == '!'
	})
	for _, part := range parts {
		switch part {
		case "testdata", "fixture", "fixtures", "__fixtures__", "__tests__", "sample", "samples", "example", "examples", "mock", "mocks":
			return true
		}
	}
	referenceSegments := []string{
		"/testdata/",
		"/fixtures/",
		"/fixture/",
		"/test/fixtures/",
		"/tests/fixtures/",
		"/__tests__/",
		"/spec/fixtures/",
		"/sample/",
		"/samples/",
		"/example/",
		"/examples/",
		"/mock/",
		"/mocks/",
	}
	for _, segment := range referenceSegments {
		if strings.Contains(slash, segment) {
			return true
		}
	}
	return strings.Contains(slash, "/node_modules/") && (strings.Contains(slash, "/test/") || strings.Contains(slash, "/tests/"))
}
