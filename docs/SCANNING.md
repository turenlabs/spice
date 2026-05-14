# Scanning System

Spice has three scan profiles:

- `project`: fast default for manifests, lockfiles, package archives, known suspicious names, startup/token paths, and dependency loader candidates.
- `shai-hulud`: targeted host/package-cache scan for incident vectors, IDE residue, persistence paths, token config paths, and package caches. The internal value is kept for compatibility; the UI labels this profile "Incident sweep".
- `deep`: broad content scan for selected paths, bounded by size filters.

## Pipeline Phases

1. Global checks.
2. Index selected roots.
3. Build content candidate list.
4. Load cached results for unchanged candidates.
5. Scan candidates with workers.
6. Emit live findings and progress.
7. Write scan cache, findings, and package inventory.
8. Return completed or canceled result.

## Indexing

Indexing walks selected roots concurrently. Symlinks are skipped. Missing roots are silently ignored.

Each file is classified:

- `scanMetadataOnly`: count for progress but do not persist or read content.
- `scanContent`: cache lookup and scan if needed.

Metadata-only files should not be written to SQLite. This keeps large source trees fast and avoids stale inventory rows for irrelevant files.

## Candidate Selection

Candidate selection lives in `engine.go`.

Always scan:

- package manifests and lockfiles
- package archives
- Python `METADATA`
- Dockerfiles
- startup/token-sensitive paths
- remote incident filenames

Project profile scans only dependency files likely to be loaders, such as setup/install/runtime/router/token filenames. Arbitrary dependency source files stay metadata-only unless deep scan is selected.

## Cache Semantics

Scan cache keys include:

- path
- size
- mtime
- engine version
- scan profile
- remote detection bundle fingerprint

Cached results include findings, digest, and package inventory state. If package inventory rows are missing or incomplete, the pipeline reparses the manifest and backfills inventory without rerunning detectors.

## Cancellation

Scan cancellation is context-driven.

Expected behavior:

- stop accepting queued work when possible
- stop DB cache and write work when context is canceled
- return partial live findings if already emitted
- mark final result `status: "canceled"`
- do not save canceled scans as completed scan history

Do not reintroduce tests or behavior that require flushing every pending DB write after cancellation. Stop should prioritize responsiveness over perfect partial cache persistence.

## Progress Events

Progress has two user-visible phases:

- `indexing`: building the file tree and content candidate set
- `scanning`: scanning or using cached candidate results

The UI should not show a stopped scan as 100% complete. Completed scans report 100%; canceled scans keep the last observed percent and show stopped/canceled language.

## Performance Notes

Known hot paths:

- per-file stat calls during tree walking
- manifest parsing on warm cache
- SQLite inventory dedup/group queries
- path allocation and lowercasing during classification

Current warm-cache manifest scans should stay near the `BenchmarkScanPackageManifestsWarmCache` baseline. Run the benchmark after cache or inventory changes.
