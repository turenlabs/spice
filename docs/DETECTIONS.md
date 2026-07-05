# Detections

Spice separates scanner code from detection data.

The app contains detector logic and rule evaluators. Incident-pack data lives in the remote `spice-detections` repository:

- affected package versions
- IOC regexes
- composite IOC signals
- incident filenames
- known SHA-256 and SHA-1 hashes

## Detector Interface

Detector implementations satisfy:

```go
type Detection interface {
    ID() string
    Campaign() string
    ScanGlobal(emit EmitFinding)
    ScanFile(file FileContext, emit EmitFinding)
    WatchEvent(event fsnotify.Event) []WatchEvent
}
```

`ScanFile` should be deterministic and side-effect free. It receives a file context and emits findings. It must not perform network access.

## Remote Pack Loading

Remote pack loading lives in `remote_detections.go`.

Trust guardrails:

- HTTPS only.
- GitHub API or raw content hosts only.
- Owner/repo pinned to `turenlabs/spice-detections`.
- Ref pinned to `main`.
- Relative paths must stay inside the trusted repo content tree.
- URL fragments, userinfo, protocol-relative URLs, unsupported query parameters, backslashes, and path traversal are rejected.
- Redirect targets are revalidated.

Cached packs are used when remote fetch fails. Detection status reports whether data came from remote, cache, mixed remote/cache, or none.

## Rule Quality

Prefer high-signal rules:

- exact affected package name and version
- exact known incident file hashes
- incident-specific URLs, commit strings, repo descriptions, service names, or payload filenames
- composite rules requiring multiple independent signals

Avoid weak rules:

- generic filenames alone, such as `setup.mjs`
- generic lifecycle scripts alone, such as normal `prepare` build commands
- broad credential-looking regexes without campaign context
- common cloud metadata strings without loader or exfil context

If a file is threat-intel text or documentation, it can contain real IOCs. Composite detections should require enough context to avoid flagging benign reports.

## Findings

Findings should include:

- `DetectionID`
- `Campaign`
- `Severity`
- `Kind`
- `Path`
- concise evidence
- actionable remediation

Developer-facing evidence should explain what matched and why it matters. Avoid vague labels such as "suspicious" without the concrete match.

Product and developer copy should describe findings as exposure or triage evidence. Even high-confidence rules indicate a match against loaded detection data; operators still need project context before declaring compromise or deleting files.

## Adding Campaign Coverage

Use the remote detection pack when possible. Change engine code only when a detection requires new parsing, archive handling, package inventory support, or composite behavior that cannot be expressed as data.

Pack IOC regexes only run against files the engine content-scans. Covered ecosystems include npm, PyPI, Composer, Go modules (`go.mod`), and crates (`Cargo.toml`/`Cargo.lock` map to the `crates` ecosystem). Crates build scripts (`build.rs`), AI-agent instruction/config files (`.cursorrules`, `.windsurfrules`, `CLAUDE.md`, `AGENTS.md`, `mcp.json`, `.aider.conf.yml`), repo-open AI/editor execution config (`.claude/settings.json`, `.gemini/settings.json`, `.cursor/rules/*`, `.vscode/tasks.json`, `.github/setup.js`/`.mjs`, `.github/copilot-instructions.md`), npm package-cache native-build configs (`binding.gyp`), and GitHub Actions workflow files (`.github/workflows/*.yml`/`.yaml`) are content-scanned so payload, prompt-injection, install-time execution, and malicious-publish-workflow IOCs can match. Adding a new ecosystem or file class requires an engine change (`manifestEcosystem`, `normalizePackageEcosystem`, `textCandidate`, `isAlwaysScanBase`, `isRepoOpenExecutionPath`, `isCIWorkflowPath`).

Add tests in the engine repo for parser/engine behavior. Add pack-specific fixtures/tests in the detection pack repo when the scanner already supports the needed rule type.

## False Positives

False-positive fixes should tighten evidence, add composite requirements, or add benign exclusions. Do not simply remove coverage for an attack vector unless the rule type is fundamentally unsalvageable.

See `SECURITY.md` for the reporting template.
