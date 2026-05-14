# Security Policy

## Reporting Security Issues

Please report suspected vulnerabilities privately before opening a public issue. Send a concise report to the project maintainers with:

- Affected version or commit.
- Operating system and install method.
- Impact and expected attacker capabilities.
- Reproduction steps, proof of concept, or logs.
- Whether any secret, package, or repository data may have been exposed.

Do not include live credentials, private source files, or unredacted customer data. If a report needs sensitive artifacts to reproduce, first share filenames, hashes, and redacted snippets so maintainers can decide what is necessary.

## Scope

In scope:

- Local privilege escalation or unsafe file handling in the desktop app or CLI.
- Unintended network transmission of scan data, local paths, findings, previews, or package inventory.
- Remote detection update integrity problems, cache poisoning, or path traversal.
- Unsafe deletion, preview, or watcher behavior.
- Release packaging issues that could mislead users about artifact provenance.

Out of scope:

- Reports that only state that Spice detects known malware or suspicious package behavior.
- False positives without a security impact. Use the detection contribution process below.
- Vulnerabilities in third-party package managers, package registries, or malware samples unless Spice mishandles them.

## Detection Contributions

Spice separates scanner logic from detection data. Package rows, IOCs, suspicious filenames, known hashes, and composite IOC data are shipped through the remote `spice-detections` pack. Prefer detection-pack changes for new campaign indicators unless the scanner cannot express the detection.

Detection contributions should include:

- Campaign name and detection intent.
- Source links or provenance for each indicator.
- Indicator type: affected package version, IOC regex, composite IOC, suspicious filename, SHA-256, or SHA-1.
- Suggested severity and remediation text when applicable.
- Test fixtures or representative redacted examples.
- False-positive analysis, including common legitimate matches to avoid.

Keep indicators narrow. Avoid patterns that match generic package scripts, common filenames, normal cloud metadata references, or broad credential-looking strings without campaign-specific context.

## False Positive Corrections

For a false positive, include the detection ID, campaign, kind, matched evidence, platform, Spice version, and whether remote detections were loaded. Redact local usernames, tokens, hostnames, private package names, and source content that is not needed to understand the match.

Maintainers may ask for a minimized fixture that reproduces the finding. A good fixture preserves the package name/version, file type, and matching line shape while replacing private values with placeholders.

## Local Data And Privacy Expectations

Spice stores scan data locally in the user config directory. On macOS this is usually `~/Library/Application Support/Spice/`; on Linux this is usually `~/.config/Spice/`.

The scan index stores file metadata, content hashes, findings, package inventory, recent scan roots, and settings. Remote detection packs are cached under the same `Spice` config directory in `detections/`. Detection updates are fetched from GitHub over HTTPS; scanned files and findings are not uploaded by the update path.

When sharing diagnostics, assume findings, previews, paths, and package inventory may be sensitive.
