#!/usr/bin/env python3
# Cek bahwa OpenSSL (bukan library sendiri) membuat/validasi signature.

from __future__ import annotations

import base64
import json
import sys

SCALAR_BYTES = 32

def _read_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    return tag, data[offset : offset + length], offset + length

def der_to_raw(source: str, target: str) -> None:
    der = open(source, "rb").read()
    tag, body, end = _read_tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise SystemExit(f"{source}: not a DER SEQUENCE")

    tag, r, offset = _read_tlv(body, 0)
    if tag != 0x02:
        raise SystemExit(f"{source}: first element is not an INTEGER")
    tag, s, offset = _read_tlv(body, offset)
    if tag != 0x02 or offset != len(body):
        raise SystemExit(f"{source}: malformed INTEGER sequence")

    raw = _pad(r) + _pad(s)
    open(target, "wb").write(raw)

def _pad(value: bytes) -> bytes:
    value = value.lstrip(b"\x00")
    if len(value) > SCALAR_BYTES:
        raise SystemExit("scalar does not fit in 32 bytes")
    return value.rjust(SCALAR_BYTES, b"\x00")

def _der_integer(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + _der_length(len(value)) + value

def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body

def raw_to_der(source: str, target: str) -> None:
    raw = open(source, "rb").read()
    if len(raw) != 2 * SCALAR_BYTES:
        raise SystemExit(f"{source}: expected 64 raw bytes, got {len(raw)}")
    body = _der_integer(raw[:SCALAR_BYTES]) + _der_integer(raw[SCALAR_BYTES:])
    open(target, "wb").write(b"\x30" + _der_length(len(body)) + body)

def extract(bundle: str, manifest_out: str, signature_out: str) -> None:
    payload = json.load(open(bundle, encoding="utf-8"))
    open(manifest_out, "wb").write(base64.b64decode(payload["manifest_b64"]))
    open(signature_out, "wb").write(base64.b64decode(payload["signature_b64"]))

def replace_signature(bundle: str, signature: str, target: str) -> None:
    payload = json.load(open(bundle, encoding="utf-8"))
    payload["signature_b64"] = base64.b64encode(open(signature, "rb").read()).decode("ascii")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, separators=(",", ":"))

COMMANDS = {
    "der-to-raw": der_to_raw,
    "raw-to-der": raw_to_der,
    "extract": extract,
    "replace-signature": replace_signature,
}

def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in COMMANDS:
        raise SystemExit(f"usage: {argv[0]} <{'|'.join(COMMANDS)}> ...")
    COMMANDS[argv[1]](*argv[2:])
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
