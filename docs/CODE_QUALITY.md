# Code Quality

This project should stay small, direct, and easy to audit.

## Go Standards

- Keep scanner behavior deterministic.
- Prefer explicit structs and small helpers over broad abstractions.
- Use context-aware APIs on scan hot paths.
- Use prepared SQL statements for all values.
- Return errors with enough context for developers, but do not surface expected missing files as findings.
- Avoid global mutable state outside app lifecycle/status holders.
- Keep comments sparse and useful.

## TypeScript Standards

- Keep Wails API types in `frontend/src/types.ts` aligned with Go models.
- Keep `main.tsx` responsible for app-level state and API calls.
- Keep components focused on rendering and user interaction.
- Do not store backend-owned scan data in local storage.
- Use local storage only for UI workflow state such as finding actions.

## Security Standards

- Do not upload scan contents, findings, inventory, previews, or paths.
- Treat local paths and package names as sensitive in logs and docs.
- Validate any path used for cache writes.
- Validate remote detection URLs before fetch and after redirects.
- Deletion must be explicit and user-confirmed.
- Avoid following symlinks during broad scans unless a future feature explicitly models that risk.

## Performance Standards

- Indexing should avoid content reads unless a file is a content candidate.
- Metadata-only files should not be persisted.
- Warm-cache scans should avoid reparsing manifests unless inventory backfill is needed.
- Benchmarks should be run after changes to indexing, cache lookup, package extraction, or inventory queries.
- Deep scan changes must be tested against large trees for memory growth.

## UI Standards

- Optimize for developers who want direct answers, not security jargon.
- Explain findings as "what matched" and "what to do next."
- Do not show scan errors as findings.
- Do not show canceled scans as completed.
- Keep scan profiles clear: Project scan, Incident sweep, Startup items, Deep disk scan.
- Settings should hold lower-frequency configuration and maintenance actions.

## Documentation Standards

- Update docs when behavior changes.
- Put subsystem details in `docs/`.
- Keep `AGENTS.md` as an index, not a full manual.
- Keep release-facing user docs in `README.md`, `SECURITY.md`, and `docs/RELEASE.md`.
