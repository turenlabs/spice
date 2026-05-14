# Spice Agent Documentation Index

This file is the starting point for agents working in this repository. Read the relevant docs before changing code. Keep durable guidance in `docs/`; keep `AGENTS.md` as the index.

## Core Docs

- [Architecture](docs/ARCHITECTURE.md): application layers, main packages, data flow, and ownership boundaries.
- [Scanning System](docs/SCANNING.md): scan profiles, indexing, candidate selection, caching, cancellation, and progress events.
- [Detections](docs/DETECTIONS.md): remote pack model, trust guardrails, detector interfaces, IOC quality, and false-positive handling.
- [Storage](docs/STORAGE.md): SQLite schema, local data paths, inventory model, cache semantics, and cleanup behavior.
- [Code Quality](docs/CODE_QUALITY.md): Go, TypeScript, UI, security, and performance standards for changes.
- [Testing](docs/TESTING.md): test layers, required checks, benchmark usage, and what to test for each change type.
- [Frontend](docs/FRONTEND.md): Wails/React architecture, UI principles, event handling, and state ownership.
- [Release](docs/RELEASE.md): release checklist, artifacts, checksums, and detection-pack release notes.

## Quick Orientation

Spice is a Wails desktop app and CLI for local supply-chain scanning. The engine scans local files, stores scan/index data in SQLite, loads remote detection packs from `turenlabs/spice-detections`, and surfaces findings, package inventory, and scan status in the UI.

Main backend files:

- `app.go`: Wails API, scan orchestration, detection refresh status, file preview/delete, settings, inventory.
- `engine.go`: scanner interface, scan profiles, file classification, one-file scan execution.
- `scan_pipeline.go`: directory indexing, candidate queue, cache use, scan workers, progress, write queue.
- `scan_index.go`: SQLite schema, settings, scan history, inventory, cache lookup/write paths.
- `detections_shaihulud.go`: built-in detector implementation backed by remote detection-pack data.
- `remote_detections.go`: remote detection manifest/pack loading, cache fallback, trust validation.
- `cli.go`: CLI entry points for scan/update/version.

Frontend files:

- `frontend/src/main.tsx`: top-level app state, Wails API calls, scan lifecycle, event subscriptions.
- `frontend/src/components/`: focused UI components for scan, findings, inventory, settings, preview, and sidebar.
- `frontend/src/types.ts`: frontend view of Wails models.

## Before Changing Code

1. Identify the subsystem in the docs above.
2. Read the owning doc and the relevant source files.
3. Keep changes scoped to that subsystem unless the docs call out a cross-boundary contract.
4. Add or update business-logic tests for behavior changes.
5. Run the checks listed in [Testing](docs/TESTING.md).

## Documentation Rules

- Put durable technical guidance in `docs/`.
- Update docs in the same change when behavior, architecture, release flow, or detection-pack semantics change.
- Prefer concrete file names, invariants, and commands over broad prose.
- Do not duplicate long content from `README.md`; link to the detailed doc instead.

