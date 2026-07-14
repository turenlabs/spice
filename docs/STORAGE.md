# Storage

Spice stores local scan state in SQLite.

Default paths:

- macOS: `~/Library/Application Support/Spice/scan-index.sqlite`
- Linux: `~/.config/Spice/scan-index.sqlite`

Remote detections are cached in:

- macOS: `~/Library/Application Support/Spice/detections/`
- Linux: `~/.config/Spice/detections/`

## Tables

`file_index`

- one row per content-scanned file
- path, size, mtime, SHA-256, engine/cache version, package count, last scanned timestamp

`file_findings`

- findings for a file path
- replaced on each content scan write

`package_inventory`

- package references extracted from manifests, lockfiles, archives, and metadata
- NuGet inventory includes package references from project/props XML, `packages.config`, `packages.lock.json`, `project.assets.json`, and `.nuspec` metadata; declared minimums and ranges remain visible even when they are not exact resolved versions
- deduped in queries by package identity and source digest/path

`scan_runs`

- completed scan history
- canceled scans must not be saved as completed runs

`app_settings`

- persisted settings such as excluded directories

## Cache Version

Cache version is composed from:

- `scanEngineVersion`
- scan profile
- remote detection bundle fingerprint or `no-rules`

Any change that affects detection behavior should update either the engine version or remote bundle fingerprint. Profile-specific behavior must not share cached results across profiles.

## Package Inventory Cache

`file_index.package_count` records how many package rows were extracted for the current file cache row.

Meaning:

- `>= 0`: inventory extraction completed and this many package rows were expected
- `< 0`: unknown inventory state; reparse for inventory backfill when cache is reused

If inventory rows are deleted but the file cache row remains, warm scans should reparse the manifest and restore inventory without rerunning full detection logic.

## Clear Local Data

Clear local data deletes:

- `file_findings`
- `file_index`
- `package_inventory`
- `scan_runs`

It keeps:

- `app_settings`
- remote detection cache files

This lets users clear scan data without losing offline detection capability or scan excludes.

## Prepared Statements

Use parameterized SQL for values. Dynamic SQL should be limited to internal fixed strings. Do not concatenate user-controlled values into SQL statements.

Tests that need table-specific helpers should use explicit switch allowlists for table names.

## Current Storage Debt

- Wails methods open storage independently. A future `StorageService` should open/migrate once at app startup and own context-aware methods.
- PRAGMAs are set during migration; if connection pooling remains, ensure connection-scoped settings are applied consistently.
- Inventory queries still perform dedup grouping at read time. A generated or persisted source key may improve large inventories.
