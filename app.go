package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx context.Context

	scanMu       sync.Mutex
	scanSeq      atomic.Int64
	scanCancelMu sync.Mutex
	scanCancel   context.CancelFunc

	detectionMu     sync.RWMutex
	detectionBundle *RemoteDetectionBundle
	detectionStatus DetectionStatus
	detectionCancel context.CancelFunc
	detectionReady  chan struct{}
	detectionOnce   sync.Once

	watcherMu sync.Mutex
	watcher   *fsnotify.Watcher
	watchDone chan struct{}
	watching  bool
	events    []WatchEvent
}

type ScanRequest struct {
	Paths        []string `json:"paths"`
	Deep         bool     `json:"deep"`
	ExcludedDirs []string `json:"excludedDirs"`
	Profile      string   `json:"profile"`
}

type ScanResult struct {
	StartedAt  string    `json:"startedAt"`
	FinishedAt string    `json:"finishedAt"`
	Roots      []string  `json:"roots"`
	Findings   []Finding `json:"findings"`
	Indexed    bool      `json:"indexed"`
	Status     string    `json:"status"`
}

type ScanFindingEvent struct {
	ScanID  string  `json:"scanId"`
	Seq     int64   `json:"seq"`
	Finding Finding `json:"finding"`
}

type Finding struct {
	DetectionID string `json:"detectionId"`
	Campaign    string `json:"campaign"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence,omitempty"`
	Context     string `json:"context,omitempty"`
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

type FilePreviewRequest struct {
	Path string `json:"path"`
}

type FilePreview struct {
	Path      string `json:"path"`
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Mode      string `json:"mode"`
	Modified  string `json:"modified"`
	Content   string `json:"content"`
	Encoding  string `json:"encoding"`
	Truncated bool   `json:"truncated"`
}

type DeletePathRequest struct {
	Path string `json:"path"`
}

type DeletePathResult struct {
	Path      string `json:"path"`
	DeletedAt string `json:"deletedAt"`
}

type InventoryRequest struct {
	Limit      int    `json:"limit"`
	Offset     int    `json:"offset"`
	Query      string `json:"query"`
	Ecosystem  string `json:"ecosystem"`
	SourceKind string `json:"sourceKind"`
}

type InventoryResult struct {
	Packages         []PackageRef   `json:"packages"`
	Total            int            `json:"total"`
	Limit            int            `json:"limit"`
	Offset           int            `json:"offset"`
	EcosystemCounts  []InventoryBin `json:"ecosystemCounts"`
	SourceKindCounts []InventoryBin `json:"sourceKindCounts"`
}

type DetectionStatus struct {
	RemoteURL     string `json:"remoteUrl"`
	Source        string `json:"source"`
	TrustPolicy   string `json:"trustPolicy"`
	UsedCache     bool   `json:"usedCache"`
	UsedRemote    bool   `json:"usedRemote"`
	LastAttemptAt string `json:"lastAttemptAt"`
	LastSuccessAt string `json:"lastSuccessAt"`
	Error         string `json:"error,omitempty"`
	PackCount     int    `json:"packCount"`
}

type AppSettings struct {
	ExcludedDirs []string `json:"excludedDirs"`
}

type WatchRequest struct {
	Paths []string `json:"paths"`
}

type WatchStatus struct {
	Running bool         `json:"running"`
	Roots   []string     `json:"roots"`
	Events  []WatchEvent `json:"events"`
	Error   string       `json:"error,omitempty"`
}

type WatchEvent struct {
	Time     string `json:"time"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"`
	Path     string `json:"path"`
	Op       string `json:"op"`
	Detail   string `json:"detail"`
}

func NewApp() *App {
	return &App{
		detectionReady: make(chan struct{}),
		detectionStatus: DetectionStatus{
			RemoteURL:   defaultDetectionManifestURL,
			Source:      "none",
			TrustPolicy: detectionTrustPolicy,
		},
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	detectionCtx, cancel := context.WithCancel(context.Background())
	a.detectionCancel = cancel
	go func() {
		a.refreshDetectionBundle(detectionCtx, "startup")
		a.markDetectionReady()
		a.detectionRefreshLoop(detectionCtx)
	}()
}

func (a *App) shutdown(_ context.Context) {
	if a.detectionCancel != nil {
		a.detectionCancel()
	}
	_ = a.StopWatcher()
}

func (a *App) Scan(req ScanRequest) (ScanResult, error) {
	a.scanMu.Lock()
	defer a.scanMu.Unlock()

	started := time.Now()
	roots := normalizeRoots(req.Paths)
	scanID := started.Format("20060102T150405.000000000")
	parentCtx := context.Background()
	if a.ctx != nil {
		parentCtx = a.ctx
	}
	scanCtx, cancel := context.WithCancel(parentCtx)
	a.scanCancelMu.Lock()
	a.scanCancel = cancel
	a.scanCancelMu.Unlock()
	defer func() {
		a.scanCancelMu.Lock()
		a.scanCancel = nil
		a.scanCancelMu.Unlock()
		cancel()
	}()
	index, err := OpenFileIndex()
	if err != nil {
		return ScanResult{}, err
	}
	defer index.Close()

	a.waitForStartupDetections(2 * time.Second)
	scanner := NewScannerWithOptions(index, func(progress ScanProgress) {
		if a.ctx != nil {
			progress.ScanID = scanID
			progress.Seq = a.scanSeq.Add(1)
			runtime.EventsEmit(a.ctx, "scan:progress", progress)
		}
	})
	scanner.deep = req.Deep
	scanner.SetProfile(ScanProfile(req.Profile))
	scanner.SetExcludedDirs(normalizePathList(req.ExcludedDirs, false))
	if bundle := a.currentDetectionBundle(); bundle != nil {
		scanner.UseRemoteDetectionBundle(bundle)
	}
	go a.refreshDetectionBundle(context.Background(), "scan-background")
	scanner.finding = func(finding Finding) {
		if a.ctx != nil {
			runtime.EventsEmit(a.ctx, "scan:finding", ScanFindingEvent{
				ScanID:  scanID,
				Seq:     a.scanSeq.Add(1),
				Finding: finding,
			})
		}
	}
	findings, err := scanner.ScanContext(scanCtx, roots)
	if err != nil {
		return ScanResult{}, err
	}
	status := "completed"
	if scanCtx.Err() != nil {
		status = "canceled"
	}
	sortFindings(findings)
	result := ScanResult{
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: time.Now().Format(time.RFC3339),
		Roots:      roots,
		Findings:   findings,
		Indexed:    true,
		Status:     status,
	}
	if status == "completed" {
		_ = index.SaveScanRun(result)
	}
	return result, nil
}

func (a *App) StopScan() {
	a.scanCancelMu.Lock()
	defer a.scanCancelMu.Unlock()
	if a.scanCancel != nil {
		a.scanCancel()
	}
}

func (a *App) LastScan() (ScanResult, error) {
	index, err := OpenFileIndex()
	if err != nil {
		return ScanResult{}, err
	}
	defer index.Close()
	result, ok, err := index.LastScanRun()
	if err != nil || !ok {
		return ScanResult{}, err
	}
	sortFindings(result.Findings)
	return result, nil
}

func (a *App) Settings() (AppSettings, error) {
	index, err := OpenFileIndex()
	if err != nil {
		return AppSettings{}, err
	}
	defer index.Close()
	return index.LoadSettings()
}

func (a *App) SaveSettings(settings AppSettings) (AppSettings, error) {
	normalized := AppSettings{ExcludedDirs: normalizePathList(settings.ExcludedDirs, false)}
	index, err := OpenFileIndex()
	if err != nil {
		return AppSettings{}, err
	}
	defer index.Close()
	if err := index.SaveSettings(normalized); err != nil {
		return AppSettings{}, err
	}
	return normalized, nil
}

func (a *App) ClearLocalData() error {
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	index, err := OpenFileIndex()
	if err != nil {
		return err
	}
	defer index.Close()
	return index.ClearLocalData()
}

func (a *App) Inventory(req InventoryRequest) (InventoryResult, error) {
	index, err := OpenFileIndex()
	if err != nil {
		return InventoryResult{}, err
	}
	defer index.Close()
	result, err := index.ListPackageInventory(req)
	if err != nil {
		return InventoryResult{}, err
	}
	return result, nil
}

func (a *App) DetectionStatus() DetectionStatus {
	a.detectionMu.RLock()
	defer a.detectionMu.RUnlock()
	return a.detectionStatus
}

func (a *App) RefreshDetections() DetectionStatus {
	a.refreshDetectionBundle(context.Background(), "manual")
	return a.DetectionStatus()
}

func (a *App) PreviewFile(req FilePreviewRequest) (FilePreview, error) {
	cleanPath, err := normalizeUserPath(req.Path)
	if err != nil {
		return FilePreview{}, err
	}
	info, err := os.Stat(cleanPath)
	if err != nil {
		return FilePreview{}, err
	}
	if info.IsDir() {
		return FilePreview{}, fmt.Errorf("cannot preview directory: %s", cleanPath)
	}

	const maxPreviewBytes int64 = 256 * 1024
	handle, err := os.Open(cleanPath)
	if err != nil {
		return FilePreview{}, err
	}
	defer handle.Close()

	limit := int64(maxPreviewBytes)
	if info.Size() < limit {
		limit = info.Size()
	}
	truncated := info.Size() > maxPreviewBytes
	data := make([]byte, int(limit))
	n, err := handle.Read(data)
	if err != nil && n == 0 {
		return FilePreview{}, err
	}
	data = data[:n]
	encoding := "text"
	content := string(data)
	if isLikelyBinary(data) {
		encoding = "base64"
		content = base64.StdEncoding.EncodeToString(data)
	}
	return FilePreview{
		Path:      cleanPath,
		Name:      filepath.Base(cleanPath),
		Size:      info.Size(),
		Mode:      info.Mode().String(),
		Modified:  info.ModTime().Format(time.RFC3339),
		Content:   content,
		Encoding:  encoding,
		Truncated: truncated,
	}, nil
}

func (a *App) DeletePath(req DeletePathRequest) (DeletePathResult, error) {
	cleanPath, err := normalizeUserPath(req.Path)
	if err != nil {
		return DeletePathResult{}, err
	}
	info, err := os.Stat(cleanPath)
	if err != nil {
		return DeletePathResult{}, err
	}
	if info.IsDir() {
		return DeletePathResult{}, fmt.Errorf("refusing to delete directory: %s", cleanPath)
	}
	if err := os.Remove(cleanPath); err != nil {
		return DeletePathResult{}, err
	}
	return DeletePathResult{
		Path:      cleanPath,
		DeletedAt: time.Now().Format(time.RFC3339),
	}, nil
}

func (a *App) StartWatcher(req WatchRequest) (WatchStatus, error) {
	a.watcherMu.Lock()
	defer a.watcherMu.Unlock()

	if a.watcher != nil {
		return a.watchStatusLocked(""), nil
	}

	roots := normalizeRoots(req.Paths)
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return WatchStatus{}, err
	}

	a.watcher = watcher
	a.watchDone = make(chan struct{})
	a.watching = true
	a.events = nil

	for _, root := range roots {
		if err := addWatchTree(watcher, root); err != nil {
			a.appendEventLocked(WatchEvent{
				Time:     time.Now().Format(time.RFC3339),
				Severity: "medium",
				Kind:     "watch-error",
				Path:     root,
				Detail:   err.Error(),
			})
		}
	}

	go a.watchLoop()
	return a.watchStatusLocked(""), nil
}

func (a *App) StopWatcher() error {
	a.watcherMu.Lock()
	defer a.watcherMu.Unlock()

	if a.watcher == nil {
		a.watching = false
		return nil
	}

	close(a.watchDone)
	err := a.watcher.Close()
	a.watcher = nil
	a.watchDone = nil
	a.watching = false
	return err
}

func (a *App) WatchStatus() WatchStatus {
	a.watcherMu.Lock()
	defer a.watcherMu.Unlock()
	return a.watchStatusLocked("")
}

func (a *App) PickDirectory() (string, error) {
	return runtime.OpenDirectoryDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Choose a project directory to scan or watch",
	})
}

func (a *App) watchLoop() {
	scanner := NewScanner()
	if bundle := a.currentDetectionBundle(); bundle != nil {
		scanner.UseRemoteDetectionBundle(bundle)
	}
	for {
		a.watcherMu.Lock()
		watcher := a.watcher
		done := a.watchDone
		a.watcherMu.Unlock()

		if watcher == nil || done == nil {
			return
		}

		select {
		case <-done:
			return
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			a.recordWatchEvent(WatchEvent{
				Time:     time.Now().Format(time.RFC3339),
				Severity: "medium",
				Kind:     "watch-error",
				Detail:   err.Error(),
			})
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Create|fsnotify.Rename) != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = addWatchTree(watcher, event.Name)
				}
			}
			for _, alert := range scanner.WatchEvent(event) {
				a.recordWatchEvent(alert)
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) != 0 {
				for _, finding := range scanner.ScanChangedPath(event.Name) {
					a.recordWatchEvent(findingToWatchEvent(event, finding))
				}
			}
		}
	}
}

func findingToWatchEvent(event fsnotify.Event, finding Finding) WatchEvent {
	return WatchEvent{
		Time:     time.Now().Format(time.RFC3339),
		Severity: finding.Severity,
		Kind:     "scan-" + finding.Kind,
		Path:     finding.Path,
		Op:       event.Op.String(),
		Detail:   finding.Evidence,
	}
}

func (a *App) detectionRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refreshDetectionBundle(ctx, "background")
		}
	}
}

func (a *App) markDetectionReady() {
	a.detectionOnce.Do(func() {
		close(a.detectionReady)
	})
}

func (a *App) waitForStartupDetections(timeout time.Duration) {
	if a.detectionReady == nil {
		return
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-a.detectionReady:
	case <-timer.C:
	}
}

func (a *App) refreshDetectionBundle(parent context.Context, _ string) {
	a.detectionMu.Lock()
	a.detectionStatus.LastAttemptAt = time.Now().Format(time.RFC3339)
	a.detectionStatus.TrustPolicy = detectionTrustPolicy
	if a.detectionBundle == nil {
		a.detectionStatus.Source = "refreshing"
	}
	a.detectionMu.Unlock()

	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	bundle, err := LoadRemoteDetectionBundle(ctx)

	a.detectionMu.Lock()
	defer a.detectionMu.Unlock()
	if err != nil {
		a.detectionStatus.Error = err.Error()
		if a.detectionBundle == nil {
			a.detectionStatus.Source = "none"
			a.detectionStatus.PackCount = 0
			a.detectionStatus.UsedCache = false
			a.detectionStatus.UsedRemote = false
		}
		a.emitDetectionStatusLocked()
		return
	}
	a.detectionBundle = bundle
	a.detectionStatus.Source = bundle.Source
	a.detectionStatus.Error = ""
	a.detectionStatus.LastSuccessAt = time.Now().Format(time.RFC3339)
	a.detectionStatus.PackCount = len(bundle.Packs)
	a.detectionStatus.UsedCache = bundle.UsedCache
	a.detectionStatus.UsedRemote = bundle.UsedRemote
	a.emitDetectionStatusLocked()
}

func (a *App) emitDetectionStatusLocked() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "detections:status", a.detectionStatus)
	}
}

func (a *App) currentDetectionBundle() *RemoteDetectionBundle {
	a.detectionMu.RLock()
	defer a.detectionMu.RUnlock()
	return a.detectionBundle
}

func (a *App) recordWatchEvent(event WatchEvent) {
	a.watcherMu.Lock()
	defer a.watcherMu.Unlock()
	a.appendEventLocked(event)
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "watch:event", event)
	}
}

func (a *App) appendEventLocked(event WatchEvent) {
	if event.Time == "" {
		event.Time = time.Now().Format(time.RFC3339)
	}
	a.events = append([]WatchEvent{event}, a.events...)
	if len(a.events) > 250 {
		a.events = a.events[:250]
	}
}

func (a *App) watchStatusLocked(errMsg string) WatchStatus {
	roots := []string{}
	if a.watcher != nil {
		roots = append(roots, a.watcher.WatchList()...)
		sort.Strings(roots)
	}
	events := append([]WatchEvent(nil), a.events...)
	if events == nil {
		events = []WatchEvent{}
	}
	return WatchStatus{Running: a.watching, Roots: roots, Events: events, Error: errMsg}
}

func normalizeRoots(paths []string) []string {
	return normalizePathList(paths, true)
}

func normalizePathList(paths []string, defaultToCurrent bool) []string {
	if len(paths) == 0 && defaultToCurrent {
		paths = []string{"."}
	}
	roots := make([]string, 0, len(paths))
	seen := map[string]bool{}
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		expanded := expandHome(raw)
		abs, err := filepath.Abs(expanded)
		if err != nil {
			if !seen[expanded] {
				roots = append(roots, expanded)
				seen[expanded] = true
			}
			continue
		}
		clean := filepath.Clean(abs)
		if seen[clean] {
			continue
		}
		seen[clean] = true
		roots = append(roots, clean)
	}
	if len(roots) == 0 && defaultToCurrent {
		roots = []string{"."}
	}
	return roots
}

func expandHome(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func normalizeUserPath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("path is required")
	}
	return filepath.Abs(expandHome(raw))
}

func isLikelyBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	for _, b := range data {
		if b == 0 {
			return true
		}
	}
	return false
}

func addWatchTree(watcher *fsnotify.Watcher, root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return watcher.Add(root)
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		if shouldSkipDir(d.Name()) {
			return filepath.SkipDir
		}
		if err := watcher.Add(path); err != nil {
			return nil
		}
		return nil
	})
}
