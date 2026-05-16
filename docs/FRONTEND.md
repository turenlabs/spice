# Frontend

The frontend is a React app served through Wails.

## Main State

`frontend/src/main.tsx` owns:

- active page/mode
- selected scan profile and paths
- scan progress
- live findings
- last scan result
- detection status
- inventory query state
- settings
- preview pane state
- finding actions

Wails events:

- `scan:progress`
- `scan:finding`
- `detections:status`

## Components

Components in `frontend/src/components/` should stay focused:

- `ScanStrip`: scan profile/path/progress flow
- `FindingsTable`: findings review and actions
- `InventoryPanel`: local package inventory
- `SettingsPanel`: detection status, excludes, local data, ignored findings
- `PreviewPane`: file preview sandbox pane
- `Sidebar`: navigation

Do not move backend API calls deep into leaf components unless a component fully owns that workflow.

## Scan UX

The scan page should read like a simple wizard:

1. choose scan type
2. choose paths
3. index
4. scan
5. review results

Canceled scans should show stopped language, not completion language. Findings should appear as they are found.

## Settings UX

Settings is for lower-frequency controls:

- detection refresh/status
- trust guardrails
- local data clearing
- scan excludes
- ignored findings

Do not put the detection pack summary in the main left nav.

## Developer-Friendly Language

Prefer:

- "What matched"
- "Where"
- "What to do next"
- "Triage evidence"
- "Exposure signal"
- "Checks loaded from remote/cache"

Avoid unexplained security jargon in primary UI labels. Detailed technical evidence can still be present in findings and settings.

Frame findings as evidence for review, not proof that a system is compromised. Use the existing finding kind, severity, evidence, and remediation fields to explain confidence and meaning without implying certainty.

## Type Sync

When Go Wails model structs change:

1. run Wails build or generation so `frontend/wailsjs/go/models.ts` updates
2. update `frontend/src/types.ts`
3. run `npm run build`
