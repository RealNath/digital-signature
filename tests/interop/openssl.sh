#!/usr/bin/env bash
# Signature perlu verifikasi dalam OpenSSL, dan signature OpenSSL
# harus verifikasi dalam minisign. Dan sebaliknya, ketiga profil.
#
#   bash tests/interop/openssl.sh
#
# Butuh openssl 3.0+ (utk Ed25519 -rawin) dan CLI Python

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
OUT_DIR=${OUT_DIR:-$ROOT_DIR/out/interop}
HELPERS="$SCRIPT_DIR/helpers.py"
PACKAGE=interop-app
VERSION=1.0.0

cd "$ROOT_DIR"
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

minisign() {
  python3 -m src.minisign "$@"
}

# Extract signed manifest dan signature dari bundle
extract_bundle() {
  python3 "$HELPERS" extract "$1/bundle.json" "$1/manifest.bin" "$1/signature.bin"
}

# OpenSSL verifikasi signature yang dibuat minisign
openssl_verifies_minisign() {
  local profile=$1 dir=$2
  case "$profile" in
    rsa-pss-sha256)
      openssl dgst -sha256 -verify "$dir/key.pub.pem" \
        -signature "$dir/signature.bin" \
        -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        "$dir/manifest.bin"
      ;;
    ecdsa-p256-sha256)
      python3 "$HELPERS" raw-to-der "$dir/signature.bin" "$dir/signature.der"
      openssl dgst -sha256 -verify "$dir/key.pub.pem" \
        -signature "$dir/signature.der" "$dir/manifest.bin"
      ;;
    ed25519)
      openssl pkeyutl -verify -pubin -inkey "$dir/key.pub.pem" \
        -rawin -in "$dir/manifest.bin" -sigfile "$dir/signature.bin"
      ;;
  esac
}

# OpenSSL buat signature terhadap manifest bytes yang sama.
openssl_signs() {
  local profile=$1 dir=$2
  case "$profile" in
    rsa-pss-sha256)
      openssl dgst -sha256 -sign "$dir/key.key.pem" \
        -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
        -out "$dir/openssl-signature.bin" "$dir/manifest.bin"
      ;;
    ecdsa-p256-sha256)
      openssl dgst -sha256 -sign "$dir/key.key.pem" \
        -out "$dir/openssl-signature.der" "$dir/manifest.bin"
      python3 "$HELPERS" der-to-raw \
        "$dir/openssl-signature.der" "$dir/openssl-signature.bin"
      ;;
    ed25519)
      openssl pkeyutl -sign -inkey "$dir/key.key.pem" \
        -rawin -in "$dir/manifest.bin" -out "$dir/openssl-signature.bin"
      ;;
  esac
}

# Verifikasi, assert exit code-nya dan status, print status yang diamati.
verify_expect() {
  local expected_exit=$1 expected_status=$2 dir=$3
  set +e
  minisign verify --file "$dir/artifact.bin" --bundle "$dir/openssl-bundle.json" \
    --trust-store "$dir/trust.json" --package "$PACKAGE" --version "$VERSION" \
    --json >"$dir/verify.json" 2>"$dir/verify.err"
  local actual=$?
  set -e
  local observed
  observed=$(python3 - "$dir/verify.json" <<'PY' 2>/dev/null
import json, sys
print(json.load(open(sys.argv[1]))["status"])
PY
) || observed="<unparsable>"
  if [ "$actual" -ne "$expected_exit" ] || [ "$observed" != "$expected_status" ]; then
    echo "expected exit $expected_exit with status $expected_status, got exit $actual with status $observed" >&2
    cat "$dir/verify.json" "$dir/verify.err" >&2
    return 1
  fi
  printf '%s\n' "$observed"
}

SUMMARY="$OUT_DIR/summary.txt"
: >"$SUMMARY"

for profile in rsa-pss-sha256 ecdsa-p256-sha256 ed25519; do
  dir="$OUT_DIR/$profile"
  mkdir -p "$dir"
  printf 'interop artifact for %s\n' "$profile" >"$dir/artifact.bin"

  keyid=$(minisign keygen --algorithm "$profile" --out "$dir/key")
  minisign sign --file "$dir/artifact.bin" --package "$PACKAGE" --version "$VERSION" \
    --key "$dir/key.key.pem" --out "$dir/bundle.json" >/dev/null
  minisign trust add --key "$dir/key.pub.pem" --package "$PACKAGE" \
    --store "$dir/trust.json" >/dev/null

  extract_bundle "$dir"

  # keyid adalah SHA-256 DER SPKI. Hitung ulang dengan OpenSSL
  # daripada percaya dengan kode sendiri untuk definisi identifier-nya sendiri
  openssl_keyid=$(openssl pkey -pubin -in "$dir/key.pub.pem" -outform DER \
    | sha256sum | cut -d' ' -f1)
  if [ "$openssl_keyid" != "$keyid" ]; then
    echo "$profile: keyid mismatch: tool=$keyid openssl=$openssl_keyid" >&2
    exit 1
  fi

  if ! openssl_out=$(openssl_verifies_minisign "$profile" "$dir"); then
    echo "$profile: openssl rejected minisign signature: $openssl_out" >&2
    exit 1
  fi

  openssl_status=$(grep -oE "Verified OK|Signature Verified Successfully" <<<"$openssl_out" | head -1)
  if [ -z "$openssl_status" ]; then
    echo "$profile: openssl did not confirm minisign signature: $openssl_out" >&2
    exit 1
  fi
  echo "$profile: openssl verified minisign signature ($openssl_status)" >&2

  openssl_signs "$profile" "$dir"
  python3 "$HELPERS" replace-signature "$dir/bundle.json" \
    "$dir/openssl-signature.bin" "$dir/openssl-bundle.json"
  minisign_status=$(verify_expect 0 OK "$dir")
  echo "$profile: minisign verified openssl's signature (status=$minisign_status)" >&2

  # Coba flip 1 bit pada signature OpenSSL, cek penolakan
  python3 - "$dir/openssl-signature.bin" <<'PY'
import sys
path = sys.argv[1]
data = bytearray(open(path, "rb").read())
data[0] ^= 0x01
open(path, "wb").write(bytes(data))
PY
  python3 "$HELPERS" replace-signature "$dir/bundle.json" \
    "$dir/openssl-signature.bin" "$dir/openssl-bundle.json"
  tampered_status=$(verify_expect 1 INVALID_SIGNATURE "$dir")
  echo "$profile: tampered openssl signature rejected (status=$tampered_status)" >&2

  size=$(wc -c <"$dir/signature.bin")
  printf '%s keyid=%s signature_bytes=%s openssl_verifies_minisign="%s" minisign_verifies_openssl=%s tampered=%s\n' \
    "$profile" "$keyid" "$size" "$openssl_status" "$minisign_status" "$tampered_status" >>"$SUMMARY"
done

echo
cat "$SUMMARY"
