# Architecture

Spice has four main layers:

1. Wails app/API layer.
2. Scan engine and pipeline.
3. SQLite-backed local storage.
4. React frontend.

The CLI uses the same scan engine and storage as the desktop app.

## Backend Boundaries

`app.go` owns user-facing operations:

- scan requests and cancellation
- detection refresh lifecycle
- settings
- inventory queries
- file preview and delete actions
- Wails event emission

`engine.go` owns scan decisions that do not require global pipeline state:

- scan profile selection
- candidate classification
- one-file scan execution
- detector invocation
- changed-path watcher scanning

`scan_pipeline.go` owns multi-file orchestration:

- root indexing
- candidate ordering
- cache lookup batching
- worker pools
- progress events
- DB write queue
- cancellation propagation

`scan_index.go` owns persistence:

- schema migration
- file scan cache
- findings
- package inventory
- settings
- scan history
- local data clearing

`remote_detections.go` owns remote detection pack loading:

- manifest and pack fetches
- cache fallback
- trusted URL validation
- bundle fingerprinting
- remote/cache provenance

## Frontend Boundaries

`frontend/src/main.tsx` owns app-level state and Wails API calls. Components in `frontend/src/components/` should stay mostly presentational and receive callbacks/data by props.

UI state that must persist across reloads can use local storage only when it is UI preference/workflow state. Scanner state, package inventory, findings, scan history, settings, and remote detections belong in backend storage.

## Data Flow

Manual scan:

1. UI calls `App.Scan`.
2. `App.Scan` opens storage, waits briefly for startup detections, builds a `Scanner`, and starts scan context.
3. `scanPipeline` indexes roots and classifies files into metadata-only or content candidates.
4. Pipeline loads cached scan results by path, size, mtime, engine version, profile, and remote bundle fingerprint.
5. Workers scan uncached candidates through detector implementations.
6. Findings are emitted live over Wails events.
7. Scan results and package inventory are written to SQLite unless canceled.
8. UI receives final `ScanResult` and refreshes inventory.

Detection update:

1. App startup and manual refresh call `LoadRemoteDetectionBundle`.
2. Manifest, pack JSON, and affected package CSV are fetched from pinned trusted GitHub endpoints.
3. Cached files are used when remote fetch fails.
4. Bundle fingerprint becomes part of the scan cache key.

## Design Invariants

- Scanned file contents are never uploaded by detection update code.
- Remote detection data is data, not executable code.
- The scanner must be useful offline using cached detection packs.
- Canceled scans must not replace the last completed scan history.
- Missing scan roots are silently skipped and must not become findings.
- Metadata-only files should not be persisted in the scan index.
- Findings should be emitted live during scanning, not only at the end.
- Public release builds must include checksums.

## Known Architecture Debt

- SQLite is still opened per Wails method. A future storage service should open/migrate once at startup and serialize destructive maintenance.
- Some DB methods still use background contexts for non-scan operations. Scan hot paths are context-aware; broader app storage should follow.
- Deep scans collect and sort all candidates in memory. For very large trees, move toward bounded streaming priority queues.
- Detection pack authenticity currently relies on HTTPS and pinned GitHub owner/repo/ref. Cryptographic signing is a future release hardening item.

