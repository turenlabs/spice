#!/usr/bin/env bash
set -euo pipefail

APP_NAME="${APP_NAME:-spice}"
VERSION="${VERSION:-$(tr -d '[:space:]' < VERSION)}"
APP_BUNDLE="${APP_BUNDLE:-build/bin/${APP_NAME}.app}"
DIST_DIR="${DIST_DIR:-dist}"
ARCHIVE_NAME="${ARCHIVE_NAME:-${APP_NAME}_${VERSION}_macos_app.zip}"

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    printf "Missing required release credential.\n" >&2
    exit 1
  fi
}

for name in \
  APPLE_CERTIFICATE_P12_BASE64 \
  APPLE_CERTIFICATE_PASSWORD \
  APPLE_CODESIGN_IDENTITY; do
  require_env "$name"
done

if [[ -n "${APPLE_NOTARY_KEY_P8_BASE64:-}" || -n "${APPLE_NOTARY_KEY_ID:-}" || -n "${APPLE_NOTARY_ISSUER_ID:-}" ]]; then
  for name in \
    APPLE_NOTARY_KEY_P8_BASE64 \
    APPLE_NOTARY_KEY_ID \
    APPLE_NOTARY_ISSUER_ID; do
    require_env "$name"
  done
  notary_auth="api-key"
elif [[ -n "${APPLE_ID:-}" || -n "${APPLE_ID_PASSWORD:-}" || -n "${APPLE_TEAM_ID:-}" ]]; then
  for name in \
    APPLE_ID \
    APPLE_ID_PASSWORD \
    APPLE_TEAM_ID; do
    require_env "$name"
  done
  notary_auth="apple-id"
else
  printf "Missing required notarization credentials.\n" >&2
  exit 1
fi

if [[ ! -d "$APP_BUNDLE" ]]; then
  printf "App bundle not found: %s\n" "$APP_BUNDLE" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
keychain="$tmpdir/signing.keychain-db"
keychain_password="$(openssl rand -hex 24)"
p12="$tmpdir/certificate.p12"
notary_key="$tmpdir/notary-key.p8"
notary_zip="$tmpdir/notary.zip"

cleanup() {
  security delete-keychain "$keychain" >/dev/null 2>&1 || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT

printf "%s" "$APPLE_CERTIFICATE_P12_BASE64" | /usr/bin/base64 -D > "$p12"
if [[ "$notary_auth" == "api-key" ]]; then
  printf "%s" "$APPLE_NOTARY_KEY_P8_BASE64" | /usr/bin/base64 -D > "$notary_key"
  chmod 600 "$notary_key"
fi
chmod 600 "$p12"

security create-keychain -p "$keychain_password" "$keychain"
security set-keychain-settings -lut 21600 "$keychain"
security unlock-keychain -p "$keychain_password" "$keychain"

existing_keychains=()
while IFS= read -r item; do
  item="${item//\"/}"
  [[ -n "$item" ]] && existing_keychains+=("$item")
done < <(security list-keychains -d user)
security list-keychains -d user -s "$keychain" "${existing_keychains[@]}"

security import "$p12" \
  -k "$keychain" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security \
  -T /usr/bin/productsign

security set-key-partition-list \
  -S apple-tool:,apple:,codesign: \
  -s \
  -k "$keychain_password" \
  "$keychain"

sign_darwin_cli_archives() {
  local archive binary workdir inner

  shopt -s nullglob
  for archive in "$DIST_DIR/${APP_NAME}_${VERSION}_darwin_"*.tar.gz; do
    printf "Signing macOS CLI archive %s\n" "$archive"
    workdir="$(mktemp -d "$tmpdir/cli.XXXXXX")"
    tar -C "$workdir" -xzf "$archive"
    binary="$(find "$workdir" -type f -path "*/${APP_NAME}" -perm -111 | head -n 1)"
    if [[ -z "$binary" ]]; then
      printf "CLI binary not found in %s\n" "$archive" >&2
      exit 1
    fi

    codesign --force --options runtime --timestamp \
      --sign "$APPLE_CODESIGN_IDENTITY" \
      "$binary"
    codesign --verify --strict --verbose=2 "$binary"

    inner="$(find "$workdir" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
    if [[ -z "$inner" ]]; then
      printf "CLI archive root not found in %s\n" "$archive" >&2
      exit 1
    fi
    rm -f "$archive"
    tar -C "$workdir" -czf "$archive" "$(basename "$inner")"
  done
  shopt -u nullglob
}

sign_darwin_cli_archives

printf "Signing macOS app bundle\n"
codesign --force --deep --options runtime --timestamp \
  --sign "$APPLE_CODESIGN_IDENTITY" \
  "$APP_BUNDLE"

codesign --verify --deep --strict "$APP_BUNDLE"

printf "Creating notarization archive\n"
ditto -c -k --keepParent "$APP_BUNDLE" "$notary_zip"

printf "Submitting notarization request\n"
if [[ "$notary_auth" == "api-key" ]]; then
  xcrun notarytool submit "$notary_zip" \
    --key "$notary_key" \
    --key-id "$APPLE_NOTARY_KEY_ID" \
    --issuer "$APPLE_NOTARY_ISSUER_ID" \
    --wait
else
  xcrun notarytool submit "$notary_zip" \
    --apple-id "$APPLE_ID" \
    --password "$APPLE_ID_PASSWORD" \
    --team-id "$APPLE_TEAM_ID" \
    --wait
fi

printf "Stapling notarization ticket\n"
xcrun stapler staple "$APP_BUNDLE"
xcrun stapler validate "$APP_BUNDLE"

spctl --assess --type execute "$APP_BUNDLE"

mkdir -p "$DIST_DIR"
rm -f "$DIST_DIR/$ARCHIVE_NAME"
printf "Writing signed archive %s\n" "$DIST_DIR/$ARCHIVE_NAME"
ditto -c -k --keepParent "$APP_BUNDLE" "$DIST_DIR/$ARCHIVE_NAME"
