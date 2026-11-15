#!/usr/bin/env bash
# C03: Verifikasi artefak menggunakan trust store kosong atau kunci yang tidak diizinkan untuk paket tersebut.

set -euo pipefail
SCENARIO=c03
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

clean_output
prepare_artifact
sign_release

printf '{"schema":"minisign-trust/v1","keys":[]}\n' >"$OUT_DIR/empty-trust.json"

TRUST_STORE="$OUT_DIR/empty-trust.json" verify_expect 1 KEY_NOT_TRUSTED

test ! -e "$OUT_DIR/deployed.marker"
echo "rejected as expected: KEY_NOT_TRUSTED"
