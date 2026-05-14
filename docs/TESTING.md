# Testing

Run the normal suite before handing work back:

```bash
go test ./...
npm run build
```

For release changes:

```bash
make release-check
make release
shasum -a 256 -c dist/SHA256SUMS
```

For local desktop install:

```bash
make install
```

## Test Layers

Business logic tests:

- scanner cache behavior
- profile cache isolation
- cancellation semantics
- excluded directory behavior
- local data clearing
- inventory dedupe/filtering
- scan history behavior

Detection tests:

- parser behavior
- archive inspection behavior
- composite IOC matching behavior
- false-positive regressions

Remote detection tests:

- URL resolution
- path traversal rejection
- untrusted host/repo/ref rejection
- redirect validation
- cache path safety

Frontend build:

- run `npm run build` after type, model, or component changes
- run Wails generation/build when Go Wails models change

## Benchmarks

Existing benchmarks:

```bash
go test -bench 'Benchmark(IndexMetadataOnlyFiles|ScanMetadataOnlyFiles|ScanPackageManifestsCold|ScanPackageManifestsWarmCache|InventoryPageQuery)' -benchmem -run '^$' ./...
```

Important baseline:

- `BenchmarkScanPackageManifestsWarmCache` should stay near the current warm-cache performance, around tens of milliseconds for 2k manifests on Apple Silicon.

Benchmark after changes to:

- `scan_pipeline.go`
- `engine.go` classification
- package extraction in `scan_index.go`
- `LoadCachedScans`
- `UpsertBatch`
- inventory query SQL

## Test Design

Prefer behavior tests over implementation tests.

Good tests say:

- "same-profile cache reuse avoids detector call"
- "different profile rescans"
- "canceled scan does not replace last completed scan"
- "excluded sibling path is not excluded by prefix accident"

Avoid tests that only assert line-by-line implementation details unless protecting a subtle bug.

## Fixtures

Keep fixtures small and redacted. Never commit real credentials, private source, or customer package names.

When adding malware-like fixtures:

- use inert snippets
- preserve the matching shape only
- add comments in tests explaining why the fixture exists

