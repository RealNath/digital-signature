from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from support import PROFILES, keygen

def _generate(directory: Path, prefix_name: str, profile: str) -> dict[str, Any]:
    prefix = directory / prefix_name
    keyid = keygen(prefix, profile)
    return {
        "key": Path(f"{prefix}.key.pem"),
        "pub": Path(f"{prefix}.pub.pem"),
        "keyid": keyid,
    }

@pytest.fixture(scope="session")
def keyring(tmp_path_factory) -> dict[str, dict[str, Any]]:
    directory = tmp_path_factory.mktemp("keys")
    return {profile: _generate(directory, profile, profile) for profile in PROFILES}

@pytest.fixture(scope="session")
def other_key(tmp_path_factory) -> dict[str, Any]:
    directory = tmp_path_factory.mktemp("other-key")
    return _generate(directory, "other", "ed25519")