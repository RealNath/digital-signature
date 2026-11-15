#!/usr/bin/env bash
# C01: Ambil image rilis dari registry, lalu jalankan sign dan verify terhadap artefak sah.
# Simulasikan publikasi atau deployment dengan berkas penanda.
# Jangan memasang program dari kode sumber.

set -euo pipefail
SCENARIO=c01
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output
prepare_artifact
sign_release

verify_release >"$OUT_DIR/verification.json"
expect_status OK "$OUT_DIR/verification.json"

echo "$PACKAGE $VERSION verified" >"$OUT_DIR/deployed.marker"
cat "$OUT_DIR/deployed.marker"
