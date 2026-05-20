# Release Checklist

## Version

Release version is tracked in two places:

- `VERSION`
- `wails.json` at `info.productVersion`

They must match. Check this before building:

```bash
make release-check
make version
```

## Verify

Run the normal verification before creating artifacts:

```bash
make test
```

This runs the frontend production build and Go tests.

## GitHub Actions

The release workflow lives at `.github/workflows/release.yml` and is intended for the public `turenlabs/spice` repository.

It runs on:

- pushes to `v*` branches
- pushes to `release/v*` branches
- pushes to `v*` tags
- manual `workflow_dispatch`

Branch builds compile and upload artifacts for validation. Tag builds also create a draft GitHub Release with the same artifacts attached.

Use a tag for public release publishing:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Build Artifacts

Build CLI archives and checksums:

```bash
make release
```

The release target writes artifacts under `dist/`:

- `spice_<version>_darwin_amd64.tar.gz`
- `spice_<version>_darwin_arm64.tar.gz`
- `spice_<version>_linux_amd64.tar.gz`
- `spice_<version>_linux_arm64.tar.gz`
- `SHA256SUMS`

On macOS, `make release` also builds the Wails app and writes `spice_<version>_macos_app.zip`.

To build only the desktop app bundle:

```bash
make build
```

## Signed macOS Releases

Tag builds require Apple signing and notarization secrets. Branch builds can still produce unsigned validation artifacts when those secrets are not configured.

Required repository secrets:

- `APPLE_CERTIFICATE_P12_BASE64`: base64-encoded Developer ID Application `.p12`
- `APPLE_CERTIFICATE_PASSWORD`: password used when exporting the `.p12`
- `APPLE_CODESIGN_IDENTITY`: exact Developer ID Application signing identity

For notarization, use either the App Store Connect API key secrets:

- `APPLE_NOTARY_KEY_P8_BASE64`: base64-encoded App Store Connect API key `.p8`
- `APPLE_NOTARY_KEY_ID`: App Store Connect API key ID
- `APPLE_NOTARY_ISSUER_ID`: App Store Connect API issuer ID

Or the Apple ID/app-specific-password secrets used by the Turen Agent release flow:

- `APPLE_ID`: Apple ID with access to the Turen Labs developer team
- `APPLE_ID_PASSWORD`: app-specific password for that Apple ID
- `APPLE_TEAM_ID`: Apple Developer Team ID

The release workflow creates a temporary keychain, imports the `.p12`, signs the Darwin CLI binaries in the release tarballs, signs the Wails app with hardened runtime, submits the app zip to Apple notarization, staples the ticket, verifies with `codesign`, `stapler`, and `spctl`, then writes the final macOS app zip under `dist/`.

Local helper commands for secret material:

```bash
openssl pkcs12 -export \
  -inkey ~/.spice-signing/TurenLabsInc_DeveloperID_G2.key \
  -in ~/.spice-signing/developerID_application.pem \
  -name "$APPLE_CODESIGN_IDENTITY" \
  -out ~/.spice-signing/TurenLabsInc_DeveloperID_G2.p12

base64 -i ~/.spice-signing/TurenLabsInc_DeveloperID_G2.p12 | tr -d '\n'
base64 -i ~/Downloads/AuthKey_XXXXXXXXXX.p8 | tr -d '\n'
```

Never commit certificate exports, private keys, App Store Connect API keys, or printed base64 secrets.

## Checksums

`make checksums` computes SHA-256 sums for all files in `dist/` except `SHA256SUMS` itself:

```bash
make checksums
shasum -a 256 -c dist/SHA256SUMS
```

Publish `SHA256SUMS` next to the release artifacts.

## Detection Pack State

Document the remote detection pack state in release notes:

- Detection manifest URL: `https://api.github.com/repos/turenlabs/spice-detections/contents/manifest.json?ref=main`
- Current campaign pack named in the README.
- Any detection-only updates shipped since the previous app release.

Detection data can change independently from app releases. If a release fixes scanner behavior, note whether users also need to refresh detections with `spice update` or the desktop refresh action.

## Privacy Note For Release Notes

Include a short reminder that Spice stores scan history, findings, package inventory, settings, and detection caches locally under the user config directory. Detection updates fetch data from GitHub and do not upload scan results.
