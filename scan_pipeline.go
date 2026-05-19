package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"
)

const indexBatchSize = 512
const indexCacheBatchSize = 131072
const indexBatchMaxDelay = 250 * time.Millisecond
const scanResultQueueSize = 512
const indexWriteQueueSize = indexBatchSize * 2

type scanPipeline struct {
	scanner     *Scanner
	cachedScans map[string]CachedFileScan
}

type indexResult struct {
	candidates []scanFileEntry
	indexed    int
}

type indexWrite struct {
	entry    scanFileEntry
	findings []Finding
	packages []PackageRef
	digest   string
}

func newScanPipeline(scanner *Scanner) *scanPipeline {
	return &scanPipeline{scanner: scanner}
}

func (p *scanPipeline) Run(roots []string) ([]Finding, error) {
	ctx := p.scanner.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	var findings []Finding
	p.scanner.scanGlobals(func(finding Finding) {
		findings = append(findings, finding)
	})

	writes := make(chan indexWrite, indexWriteQueueSize)
	writeDone := p.startIndexWriter(ctx, writes)
	writesOpen := true
	enqueueWrite := func(write indexWrite) {
		select {
		case writes <- write:
		case <-ctx.Done():
		}
	}
	defer func() {
		if writesOpen {
			close(writes)
			_ = <-writeDone
		}
	}()

	indexed, findings, err := p.indexFiles(ctx, roots, findings, writes)
	if err != nil {
		return nil, err
	}

	stopping := false
	var runErr error

	progress := ScanProgress{
		Status:   "Scanning indexed files",
		Phase:    "scanning",
		Total:    len(indexed.candidates),
		Percent:  0,
		Findings: len(findings),
	}
	p.scanner.emitProgress(progress)

	if len(indexed.candidates) > 0 {
		results := p.scanFiles(ctx, indexed.candidates)
		for result := range results {
			progress.Processed++
			progress.CurrentPath = result.entry.path
			progress.Percent = scanPercent(progress.Processed, progress.Total)
			progress.Phase = "scanning"
			if result.err != nil {
				progress.Status = "Scan error"
				p.scanner.emitProgress(progress)
				continue
			}
			if result.cached {
				progress.Status = "Using cached result"
				progress.Skipped++
				if len(result.packages) > 0 {
					enqueueWrite(indexWrite{
						entry:    result.entry,
						findings: dedupeFindings(result.findings),
						packages: result.packages,
						digest:   result.digest,
					})
				}
			} else if result.scanned {
				progress.Status = "Scanning file"
				progress.Scanned++
				enqueueWrite(indexWrite{
					entry:    result.entry,
					findings: dedupeFindings(result.findings),
					packages: result.packages,
					digest:   result.digest,
				})
			} else {
				progress.Status = "Indexing metadata"
				progress.Skipped++
				enqueueWrite(indexWrite{entry: result.entry})
			}
			findings = append(findings, result.findings...)
			for _, finding := range result.findings {
				p.scanner.emitFinding(finding)
			}
			progress.Findings = len(findings)
			if shouldEmitScanProgress(progress, result) {
				p.scanner.emitProgress(progress)
			}
			if ctx.Err() != nil && !stopping {
				stopping = true
				progress.Status = "Scan stopping"
				progress.Phase = "scanning"
				progress.Done = false
				p.scanner.emitProgress(progress)
			}
		}
	}

	close(writes)
	if err := <-writeDone; err != nil && runErr == nil {
		runErr = err
	}
	writesOpen = false
	if ctx.Err() != nil {
		progress.Status = "stopped"
	} else {
		progress.Status = "done"
		progress.Percent = 100
		progress.CurrentPath = ""
	}
	progress.Phase = "done"
	progress.Findings = len(findings)
	progress.Done = true
	p.scanner.emitProgress(progress)
	if runErr != nil {
		return dedupeFindings(findings), runErr
	}
	return dedupeFindings(findings), nil
}

func shouldEmitScanProgress(progress ScanProgress, result scanFileResult) bool {
	return progress.Processed == 1 ||
		progress.Processed == progress.Total ||
		progress.Processed%512 == 0 ||
		len(result.findings) > 0 ||
		result.err != nil
}

func (p *scanPipeline) indexFiles(ctx context.Context, roots []string, findings []Finding, writes chan<- indexWrite) (indexResult, []Finding, error) {
	result := indexResult{}
	p.cachedScans = make(map[string]CachedFileScan)
	progress := ScanProgress{
		Status:   "Indexing file tree",
		Phase:    "indexing",
		Total:    len(roots),
		Findings: len(findings),
	}
	p.scanner.emitProgress(progress)
	for rootIndex, root := range roots {
		if ctx.Err() != nil {
			progress.Status = "Indexing stopped"
			progress.Phase = "done"
			progress.Done = true
			p.scanner.emitProgress(progress)
			return result, findings, nil
		}
		progress.CurrentPath = root
		progress.Processed = rootIndex
		progress.Percent = indexingPercent(rootIndex, len(roots))
		p.scanner.emitProgress(progress)
		if _, err := os.Stat(root); err != nil {
			continue
		}
		rootResult, err := p.indexRootFiles(ctx, root, writes, func(path string, total int) {
			if total == 1 || total%512 == 0 {
				progress.CurrentPath = path
				progress.Total = result.indexed + total
				progress.Status = "Indexing file tree"
				progress.Phase = "indexing"
				progress.Percent = indexingPercent(rootIndex, len(roots))
				p.scanner.emitProgress(progress)
			}
		})
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return result, findings, nil
			}
			return indexResult{}, findings, err
		}
		result.indexed += rootResult.indexed
		result.candidates = append(result.candidates, rootResult.candidates...)
		progress.Processed = rootIndex + 1
		progress.Total = result.indexed
		progress.Percent = indexingPercent(rootIndex+1, len(roots))
		p.scanner.emitProgress(progress)
	}
	sort.SliceStable(result.candidates, func(i, j int) bool {
		left := p.scanner.scanPriority(result.candidates[i].path)
		right := p.scanner.scanPriority(result.candidates[j].path)
		if left != right {
			return left < right
		}
		return result.candidates[i].path < result.candidates[j].path
	})
	return result, findings, nil
}

func (p *scanPipeline) indexRootFiles(ctx context.Context, root string, writes chan<- indexWrite, emit func(path string, total int)) (indexResult, error) {
	if shouldSuppressDefaultPath(root) {
		return indexResult{}, nil
	}
	if p.scanner.shouldExcludePath(root) {
		return indexResult{}, nil
	}
	info, err := os.Lstat(root)
	if err != nil {
		return indexResult{}, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return indexResult{}, nil
	}
	if !info.IsDir() {
		result := indexResult{}
		entry := scanFileEntry{path: root, size: info.Size(), mtimeUnixNano: info.ModTime().UnixNano()}
		if emit != nil {
			emit(root, 1)
		}
		if err := p.processIndexedBatch(ctx, []scanFileEntry{entry}, writes, &result); err != nil {
			return result, err
		}
		if ctx.Err() != nil {
			return result, context.Canceled
		}
		return result, nil
	}
	workerCount := min(runtime.NumCPU()*2, 64)
	if workerCount < 4 {
		workerCount = 4
	}
	dirs := make(chan string, workerCount*4)
	results := make(chan scanFileEntry, 4096)
	var dirWG sync.WaitGroup
	var workerWG sync.WaitGroup
	var processDir func(string)

	processDir = func(dir string) {
		if ctx.Err() != nil {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}
			name := entry.Name()
			path := filepath.Join(dir, name)
			if shouldSuppressDefaultPath(path) {
				continue
			}
			if entry.IsDir() {
				if shouldSkipDir(name) || p.scanner.shouldExcludePath(path) {
					continue
				}
				dirWG.Add(1)
				select {
				case dirs <- path:
				default:
					dirWG.Done()
					processDir(path)
				}
				continue
			}
			if shouldSkipFile(name) {
				continue
			}
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			if p.scanner.shouldExcludePath(path) {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				continue
			}
			select {
			case results <- scanFileEntry{path: path, size: info.Size(), mtimeUnixNano: info.ModTime().UnixNano()}:
			case <-ctx.Done():
				return
			}
		}
	}

	dirWG.Add(1)
	dirs <- root

	for i := 0; i < workerCount; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			for dir := range dirs {
				processDir(dir)
				dirWG.Done()
			}
		}()
	}

	go func() {
		dirWG.Wait()
		close(dirs)
		workerWG.Wait()
		close(results)
	}()

	result := indexResult{}
	batch := make([]scanFileEntry, 0, indexCacheBatchSize)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := p.processIndexedBatch(ctx, batch, writes, &result); err != nil {
			return err
		}
		batch = batch[:0]
		return nil
	}
	for entry := range results {
		batch = append(batch, entry)
		if emit != nil {
			emit(entry.path, result.indexed+len(batch))
		}
		if len(batch) >= cap(batch) {
			if err := flush(); err != nil {
				return result, err
			}
		}
	}
	if err := flush(); err != nil {
		return result, err
	}
	if ctx.Err() != nil {
		return result, context.Canceled
	}
	return result, nil
}

func (p *scanPipeline) processIndexedBatch(ctx context.Context, entries []scanFileEntry, writes chan<- indexWrite, result *indexResult) error {
	if len(entries) == 0 {
		return nil
	}
	contentEntries := make([]scanFileEntry, 0, len(entries)/8)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		result.indexed++
		decision := p.scanner.classifyScanFile(entry.path, entry.size)
		if decision == scanContent {
			contentEntries = append(contentEntries, entry)
		}
	}
	if len(contentEntries) == 0 {
		return ctx.Err()
	}
	cached := map[string]CachedFileScan{}
	if p.scanner.index != nil {
		var err error
		cached, err = p.scanner.index.LoadCachedScansContext(ctx, contentEntries, p.scanner.cacheVersion())
		if err != nil {
			return err
		}
	}
	for _, entry := range contentEntries {
		result.candidates = append(result.candidates, entry)
		if item, ok := cached[entry.path]; ok {
			p.cachedScans[entry.path] = item
		}
	}
	return ctx.Err()
}

func (p *scanPipeline) scanFiles(ctx context.Context, files []scanFileEntry) <-chan scanFileResult {
	jobs := make(chan scanFileEntry)
	results := make(chan scanFileResult, scanResultQueueSize)
	workerCount := min(runtime.NumCPU(), len(files))
	if workerCount < 1 {
		workerCount = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case entry, ok := <-jobs:
					if !ok {
						return
					}
					if ctx.Err() != nil {
						return
					}
					result := p.scanFileEntry(ctx, entry)
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		for _, entry := range files {
			select {
			case jobs <- entry:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				close(results)
				return
			}
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	return results
}

func (p *scanPipeline) scanFileEntry(ctx context.Context, entry scanFileEntry) scanFileResult {
	decision := p.scanner.classifyScanFile(entry.path, entry.size)
	if decision == scanMetadataOnly {
		if cached, ok := p.cachedScans[entry.path]; ok && cached.Indexed {
			return scanFileResult{entry: entry, cached: true}
		}
		return scanFileResult{entry: entry}
	}
	if cached, ok := p.cachedScans[entry.path]; ok {
		if cached.SHA256 == "" {
			return p.scanner.scanFileEntryContext(ctx, entry)
		}
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
	return p.scanner.scanFileEntryContext(ctx, entry)
}

func (p *scanPipeline) startIndexWriter(ctx context.Context, writes <-chan indexWrite) chan error {
	done := make(chan error, 1)
	go func() {
		if p.scanner.index == nil {
			for range writes {
			}
			done <- nil
			return
		}
		batch := make([]indexWrite, 0, indexBatchSize)
		timer := time.NewTimer(indexBatchMaxDelay)
		defer timer.Stop()
		var writeErr error
		flush := func() {
			if len(batch) == 0 {
				return
			}
			if writeErr == nil {
				writeErr = p.scanner.index.UpsertBatchContext(ctx, batch, p.scanner.cacheVersion())
				if errors.Is(writeErr, context.Canceled) {
					writeErr = nil
				}
			}
			batch = batch[:0]
		}
		for {
			select {
			case write, ok := <-writes:
				if !ok {
					flush()
					done <- writeErr
					return
				}
				batch = append(batch, write)
				if len(batch) >= indexBatchSize {
					flush()
				}
			case <-ctx.Done():
				batch = batch[:0]
				for range writes {
				}
				done <- writeErr
				return
			case <-timer.C:
				flush()
				timer.Reset(indexBatchMaxDelay)
			}
		}
	}()
	return done
}
