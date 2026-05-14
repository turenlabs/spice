# Spice

Small Wails desktop app for local supply-chain checks on macOS and Linux.

## Disclaimer

Spice is a best-effort local detection tool. It can help find known indicators, affected package versions, and suspicious artifacts covered by its current detection pack, but it does not guarantee that every compromise, variant, or future Shai-Hulud-style attack will be found. Treat a clean scan as a useful signal, not proof that a system or project is safe.

## What it does

- Static scan of package manifests, lockfiles, remote campaign artifact names, IOC strings, malware hashes, and persistence paths.
- fsnotify watcher that flags suspicious package install hook changes, known campaign artifacts, credential path changes, and `gh-token-monitor` persistence writes.
- Detection engine abstraction so new campaigns can be shipped as remote detection packs.

The watcher is filesystem-based. It detects file creation/modification/removal events; it does not claim to inspect process memory or syscall-level reads.

## Run

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd frontend && npm install && npm run build
cd ..
wails dev
```

## CLI

Build the local CLI:

```bash
make build-cli
build/bin/spice scan --profile project .
```

Useful commands:

```bash
spice scan [--json] [--no-remote] [--profile project|shai-hulud|deep] [path ...]
spice update
spice version
```

`--no-remote` runs with only built-in checks. Without it, Spice attempts to load the remote detection pack and falls back to the cached pack when offline.

## Detection Engine

Spice loads rules from the remote `spice-detections` repository. The local engine provides scanners and rule evaluators; package rows, IOCs, hashes, suspicious filenames, and composite IOCs live in the remote pack.

The engine interface is in [engine.go](./engine.go):

```go
type Detection interface {
	ID() string
	Campaign() string
	ScanGlobal(emit EmitFinding)
	ScanFile(file FileContext, emit EmitFinding)
	WatchEvent(event fsnotify.Event) []WatchEvent
}
```

Current remote pack: `mini-shai-hulud-2026-05`.

## Local Data And Privacy

Spice is designed to scan local files on your workstation. Scan roots, findings, package inventory rows, file hashes, ignored findings, and app settings are stored locally in a SQLite index under the operating system user config directory:

- macOS: `~/Library/Application Support/Spice/scan-index.sqlite`
- Linux: `~/.config/Spice/scan-index.sqlite`

Remote detection packs are cached separately:

- macOS: `~/Library/Application Support/Spice/detections/`
- Linux: `~/.config/Spice/detections/`

The desktop app's "Clear local data" action clears scan history, cached findings, file index rows, and package inventory. Detection packs and settings, including scan excludes, are kept so the app can continue to work offline with the last downloaded rules.

Remote detection updates are outbound HTTPS GET requests to GitHub for `turenlabs/spice-detections`. Spice does not upload scanned files, package inventory, findings, file previews, or local paths as part of detection updates. Treat findings and previews as sensitive anyway: they can contain local paths, package names, matched strings, and occasionally snippets that look like credentials.

## False Positives

Report false positives with enough context to reproduce the rule match, but do not include secrets or private source files. Useful details include:

- Spice version and platform.
- Detection ID, campaign, severity, and kind.
- Detection pack status or pack ID if shown in the app.
- Package name/version or a redacted file path.
- The matched evidence with tokens, hostnames, credentials, and customer names removed.
- Whether the result came from `spice scan`, the desktop scan, or the watcher.

Security-sensitive reports should follow [SECURITY.md](./SECURITY.md). Detection-only corrections can be contributed through the remote detection pack workflow described there.

## License

Spice is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Releases

Release metadata lives in [VERSION](./VERSION) and must match `wails.json` `info.productVersion`.

Common release checks:

```bash
make release-check
make test
make release
```

`make release` builds CLI archives in `dist/`, builds and packages the macOS app bundle on macOS, and writes `dist/SHA256SUMS`. See [docs/RELEASE.md](./docs/RELEASE.md) for the full checklist.
