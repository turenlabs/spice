package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkScanMetadataOnlyFiles(b *testing.B) {
	dir := b.TempDir()
	makeBenchFiles(b, dir, 10000, "src/file-%05d.txt", []byte("plain source text\n"))
	index, err := OpenScanIndex(filepath.Join(b.TempDir(), "scan-index.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	defer index.Close()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewScannerWithOptions(index, nil).Scan([]string{dir}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIndexMetadataOnlyFiles(b *testing.B) {
	dir := b.TempDir()
	makeBenchFiles(b, dir, 10000, "src/file-%05d.txt", []byte("plain source text\n"))
	pipeline := newScanPipeline(NewScannerWithOptions(nil, nil))
	writes := make(chan indexWrite)
	go func() {
		for range writes {
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, findings, err := pipeline.indexFiles(b.Context(), []string{dir}, nil, writes)
		if err != nil {
			b.Fatal(err)
		}
		if len(findings) != 0 || result.indexed != 10000 || len(result.candidates) != 0 {
			b.Fatalf("unexpected index result: indexed=%d candidates=%d findings=%d", result.indexed, len(result.candidates), len(findings))
		}
	}
	b.StopTimer()
	close(writes)
}

func BenchmarkScanPackageManifestsCold(b *testing.B) {
	dir := b.TempDir()
	makeBenchFiles(b, dir, 2000, "pkg-%05d/package.json", []byte(`{"dependencies":{"left-pad":"1.3.0","@tanstack/react-router":"1.169.5"},"devDependencies":{"vite":"7.3.3"}}`))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		index, err := OpenScanIndex(filepath.Join(b.TempDir(), "scan-index.sqlite"))
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		_, scanErr := NewScannerWithOptions(index, nil).Scan([]string{dir})
		b.StopTimer()
		_ = index.Close()
		if scanErr != nil {
			b.Fatal(scanErr)
		}
	}
}

func BenchmarkScanPackageManifestsWarmCache(b *testing.B) {
	dir := b.TempDir()
	makeBenchFiles(b, dir, 2000, "pkg-%05d/package.json", []byte(`{"dependencies":{"left-pad":"1.3.0","@tanstack/react-router":"1.169.5"},"devDependencies":{"vite":"7.3.3"}}`))
	index, err := OpenScanIndex(filepath.Join(b.TempDir(), "scan-index.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	defer index.Close()
	if _, err := NewScannerWithOptions(index, nil).Scan([]string{dir}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := NewScannerWithOptions(index, nil).Scan([]string{dir}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInventoryPageQuery(b *testing.B) {
	dir := b.TempDir()
	index, err := OpenScanIndex(filepath.Join(dir, "scan-index.sqlite"))
	if err != nil {
		b.Fatal(err)
	}
	defer index.Close()
	writes := make([]indexWrite, 0, 10000)
	for i := 0; i < 10000; i++ {
		path := filepath.Join(dir, fmt.Sprintf("pkg-%05d/package.json", i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			b.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			b.Fatal(err)
		}
		writes = append(writes, indexWrite{
			entry:  scanFileEntry{path: path, size: info.Size(), mtimeUnixNano: info.ModTime().UnixNano()},
			digest: fmt.Sprintf("%064d", i),
			packages: []PackageRef{{
				Ecosystem:  "npm",
				Name:       fmt.Sprintf("package-%05d", i),
				Version:    "1.0.0",
				SourcePath: path,
				SourceKind: "dependencies",
			}},
		})
	}
	for start := 0; start < len(writes); start += indexBatchSize {
		end := min(start+indexBatchSize, len(writes))
		if err := index.UpsertBatch(writes[start:end], scanEngineVersion+":benchmark"); err != nil {
			b.Fatal(err)
		}
	}

	req := InventoryRequest{Limit: 100, Offset: 5000, Query: "package", Ecosystem: "npm", SourceKind: "dependencies"}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := index.ListPackageInventory(req); err != nil {
			b.Fatal(err)
		}
	}
}

func makeBenchFiles(b *testing.B, root string, count int, pattern string, data []byte) {
	b.Helper()
	for i := 0; i < count; i++ {
		path := filepath.Join(root, fmt.Sprintf(pattern, i))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
}
