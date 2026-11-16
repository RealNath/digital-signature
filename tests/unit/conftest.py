"""Fixtures and reporting for the U01-U14 suite.

Besides the session keyring, this module attaches the size of the artifact each
test produced to its report, so the terminal summary shows the evidence a
report needs (16 B, 1024 B, 0 B, ...) without re-running anything by hand.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from support import PROFILES, keygen

# Files a test writes next to the artifact: bundle, trust store, key material.
_NOT_ARTIFACTS = {".json", ".pem", ".err"}


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


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return
    directory = item.funcargs.get("tmp_path")
    if directory is None:
        return
    found = [
        f"{path.name} ({path.stat().st_size} B)"
        for path in sorted(Path(directory).iterdir())
        if path.is_file() and path.suffix not in _NOT_ARTIFACTS
    ]
    if found:
        report.user_properties.append(("artifacts", ", ".join(found)))


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    rows = []
    for reports in terminalreporter.stats.values():
        for report in reports:
            if getattr(report, "when", None) != "call":
                continue
            artifacts = dict(getattr(report, "user_properties", ()) or ()).get("artifacts")
            if artifacts:
                rows.append((report.nodeid.split("::")[-1], artifacts))
    if not rows:
        return
    terminalreporter.section("artifact sizes")
    width = max(len(name) for name, _ in rows)
    for name, artifacts in sorted(rows):
        terminalreporter.write_line(f"{name:<{width}}  {artifacts}")
