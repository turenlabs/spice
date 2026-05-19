# Spice

Spice is a local Shai-Hulud exposure checker for developers. It scans your workstation and projects for known package versions, files, hashes, and incident-specific indicators from public detection packs.

<img width="1178" height="794" alt="spice-img" src="https://github.com/user-attachments/assets/b18023e2-eadc-406f-9aa1-0068b96cc779" />

## Install

Install the signed macOS desktop app and the CLI:

```bash
brew tap turenlabs/tap
brew install --cask turenlabs/tap/spice
spice version
```

Install only the CLI:

```bash
brew tap turenlabs/tap
brew install turenlabs/tap/spice
spice version
```

You can also download the signed macOS app from the [latest GitHub release](https://github.com/turenlabs/spice/releases/latest).

## What Spice Checks

Spice is focused on known Shai-Hulud and Mini Shai-Hulud supply-chain attacks. It does not try to be a general antivirus or generic malware scanner.

It checks local files for:

- Affected package names and versions in manifests, lockfiles, Python metadata, Composer metadata, package archives, and package cache folders.
- Known campaign artifacts such as incident-specific payload filenames, runtime files, persistence files, and repository marker strings.
- Known SHA-256 and SHA-1 hashes for published malicious files and tarballs.
- Network and payload indicators from loaded packs, including campaign domains, payload URLs, exfil endpoints, and composite IOC patterns.
- Startup and persistence locations such as macOS LaunchAgents, Linux systemd units, shell startup files, and known token-monitor service paths.
- Package install or prepare hook context when it matches high-signal incident evidence, not just because a package has a normal lifecycle script.
- A local package inventory so you can search what Spice saw by package name, version, ecosystem, path, source file, and digest.

Detection data lives in the public [turenlabs/spice-detections](https://github.com/turenlabs/spice-detections) repository. The Spice app is the scanning engine; the detection repo is where package rows, IOCs, hashes, filenames, and remediation text are updated.

## Use The App

Open Spice from `/Applications/Spice.app`.

Use the desktop app when you want to:

- Run a guided scan.
- See findings as they are discovered.
- Review findings with file previews.
- Ignore or restore findings during triage.
- Browse the local package inventory.
- Exclude noisy directories from future scans.
- Clear local scan data from settings.

Recommended first scan:

1. Choose **Incident sweep**.
2. Keep the default paths.
3. Run the scan.
4. Review anything in **Findings**.
5. Open **Inventory** if you want to inspect packages Spice discovered.

Use **Deep disk scan** only when you want a broader pass over selected paths. It reads more files and takes longer.

## Use The CLI

Scan the current project:

```bash
spice scan .
```

Run the targeted Shai-Hulud incident sweep:

```bash
spice scan --profile shai-hulud
```

Scan startup and persistence locations:

```bash
spice scan --profile startup
```

Run a broader deep scan over selected paths:

```bash
spice scan --profile deep ~/code ~/Downloads
```

Write JSON for automation:

```bash
spice scan --json --profile shai-hulud > spice-findings.json
```

Refresh remote detection packs:

```bash
spice update
```

CLI reference:

```bash
spice scan [--json] [--no-remote] [--profile project|shai-hulud|startup|deep] [path ...]
spice update
spice version
```

Exit codes:

- `0`: scan completed and found no issues.
- `1`: scan or update failed.
- `2`: invalid CLI usage.
- `3`: scan completed and found one or more findings.

`--no-remote` disables fetching remote packs for that run. Normal scans load [spice-detections](https://github.com/turenlabs/spice-detections) from GitHub and fall back to cached packs when offline.

## Scan Profiles

`project` is the default. It is meant for a repository or working directory. It prioritizes package manifests, lockfiles, package metadata, Dockerfiles, package archives, known suspicious names, and likely loader files.

`shai-hulud` is the incident sweep. It checks default host paths and package caches that matter for Shai-Hulud style attacks, including IDE residue, package caches, token config paths, known payload names, and persistence paths.

`startup` focuses on persistence. It checks startup items, LaunchAgents, LaunchDaemons, systemd units, Linux autostart entries, shell startup files, and known token-monitor locations.

`deep` scans more content under the paths you choose. Use it when you are willing to trade speed for broader coverage.

## Reading Findings

A Spice finding means "this matched loaded detection evidence." It is triage evidence, not proof by itself that your machine or project is compromised.

When Spice finds something:

1. Read **what matched** and **where**.
2. Check whether the file is an installed dependency, a lockfile, a package cache entry, or documentation containing copied IOCs.
3. Follow the finding's **what now** guidance from the detection pack.
4. If a malicious package version is present, remove or upgrade it and regenerate the lockfile.
5. If persistence or credential theft evidence is present, treat the host as potentially exposed and rotate relevant credentials after removing any persistence.

False positives are possible, especially when security notes or threat-intel files contain real IOC text. Report detection issues with the finding ID, package/version, redacted path, and matched evidence.

## Local Data And Privacy

Spice scans local files on your workstation. It stores scan state locally in SQLite:

- macOS: `~/Library/Application Support/Spice/scan-index.sqlite`
- Linux: `~/.config/Spice/scan-index.sqlite`

Remote detection packs are cached separately:

- macOS: `~/Library/Application Support/Spice/detections/`
- Linux: `~/.config/Spice/detections/`

Spice makes outbound HTTPS GET requests to GitHub to load [turenlabs/spice-detections](https://github.com/turenlabs/spice-detections). It does not upload scanned files, package inventory, findings, previews, or local paths as part of detection updates.

Treat findings and previews as sensitive anyway. They can contain local paths, package names, matched strings, and occasionally snippets that look like credentials.

## Detection Packs

Detection packs are remote data, not executable code. Spice pins detection loading to HTTPS GitHub content from `turenlabs/spice-detections` on `main`, validates pack URLs, and uses cached packs when remote loading fails.

Add or review detections here:

- [spice-detections repository](https://github.com/turenlabs/spice-detections)
- [Detection architecture notes](./docs/DETECTIONS.md)

Engine changes belong in this repo only when the scanner needs a new parser, archive handler, inventory source, or composite rule capability.

## Build From Source

Run the desktop app from source:

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest
cd frontend && npm install && npm run build
cd ..
wails dev
```

Build the CLI:

```bash
make build-cli
build/bin/spice scan --profile project .
```

Run checks:

```bash
make release-check
make test
```

## Disclaimer

Spice is a best-effort local detection tool for known Shai-Hulud indicators covered by loaded detection packs. It does not guarantee that every compromise, variant, or future supply-chain attack will be found. A clean scan is a useful signal, not proof that a system or project is safe.

## License

Spice is licensed under the Apache License 2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Releases

Release metadata lives in [VERSION](./VERSION) and must match `wails.json` `info.productVersion`.

`make release` builds CLI archives in `dist/`, builds and packages the macOS app bundle on macOS, and writes `dist/SHA256SUMS`. See [docs/RELEASE.md](./docs/RELEASE.md) for the full checklist.
