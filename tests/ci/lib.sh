#!/usr/bin/env bash
# Required: IMAGE, PACKAGE, VERSION
# Optional: KEY_FILE (signing key), TRUST_STORE, OUT_DIR, DIST_DIR
# 
# IMAGE=ghcr.io/...@sha256:... PACKAGE=demo-app VERSION=1.0.0 \
# KEY_FILE=$PWD/keys/publisher.key.pem bash tests/ci/c01.sh
# Skenario bisa dijalankan lokal

set -euo pipefail

: "${IMAGE:?IMAGE must be the pinned image reference}"
: "${PACKAGE:?PACKAGE must be set}"
: "${VERSION:?VERSION must be set}"
: "${SCENARIO:?each scenario must set SCENARIO before sourcing lib.sh}"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)
DIST_DIR=${DIST_DIR:-$ROOT_DIR/dist/$SCENARIO}
OUT_DIR=${OUT_DIR:-$ROOT_DIR/out/$SCENARIO}
TRUST_STORE=${TRUST_STORE:-$ROOT_DIR/ci/trust.json}

docker_cmd() {
  docker run --rm --network none --user "$(id -u):$(id -g)" "$@"
}

clean_output() {
  rm -rf "$OUT_DIR" "$DIST_DIR"
  mkdir -p "$OUT_DIR"
}

prepare_artifact() {
  mkdir -p "$DIST_DIR"
  printf 'demo release %s\n' "$VERSION" > "$DIST_DIR/app.txt"
  tar -czf "$DIST_DIR/$PACKAGE.tar.gz" -C "$DIST_DIR" app.txt
  rm -f "$DIST_DIR/app.txt"
}

sign_release() {
  : "${KEY_FILE:?KEY_FILE must point at the signing key}"
  docker_cmd \
    -v "$DIST_DIR:/input:ro" \
    -v "$OUT_DIR:/output" \
    -v "$KEY_FILE:/run/signing.key.pem:ro" \
    "$IMAGE" sign --file "/input/$PACKAGE.tar.gz" \
    --package "$PACKAGE" --version "$VERSION" \
    --key /run/signing.key.pem --out /output/bundle.json
}

verify_release() {
  local artifact=${1:-$PACKAGE.tar.gz}
  docker_cmd \
    -v "$DIST_DIR:/input:ro" \
    -v "$OUT_DIR:/output:ro" \
    -v "$TRUST_STORE:/trust.json:ro" \
    "$IMAGE" verify --file "/input/$artifact" \
    --bundle /output/bundle.json --trust-store /trust.json \
    --package "$PACKAGE" --version "$VERSION" --json
}

expect_status() {
  local expected=$1 json=$2
  if ! grep -q "\"status\":\"$expected\"" "$json"; then
    echo "expected status $expected, got:" >&2
    cat "$json" >&2
    return 1
  fi
}
# Cek exit code expected vs yang sebenarnya, cek juga statusnya
verify_expect() {
  local expected_exit=$1 expected_status=$2 artifact=${3:-$PACKAGE.tar.gz}
  local json="$OUT_DIR/verification.json"
  set +e
  verify_release "$artifact" >"$json" 2>"$OUT_DIR/verify.err"
  local actual=$?
  set -e
  if [ "$actual" -ne "$expected_exit" ]; then
    echo "expected exit $expected_exit, got $actual" >&2
    cat "$json" "$OUT_DIR/verify.err" >&2
    return 1
  fi
  expect_status "$expected_status" "$json"
}
