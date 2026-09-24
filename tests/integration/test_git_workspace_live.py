# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Clone a real public repository through the actual CLI (#861).

The unit suite clones over ``file://``; this is the one place the hardened
HTTPS path meets a real server. Skips when GitHub is unreachable or
``GAIA_SKIP_NETWORK_TESTS`` is set.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.network,
    pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH"),
]

REPO_ROOT = Path(__file__).resolve().parents[2]
#: GitHub's own tiny demo repository: one file, three commits, never changes.
REPO = "octocat/Hello-World"


@pytest.fixture(scope="module", autouse=True)
def _github_reachable():
    if os.environ.get("GAIA_SKIP_NETWORK_TESTS"):
        pytest.skip("GAIA_SKIP_NETWORK_TESTS is set")
    try:
        socket.create_connection(("github.com", 443), timeout=10).close()
    except OSError as e:
        pytest.skip(f"github.com unreachable: {e}")


def _gaia(home: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "GAIA_HOME": str(home)}
    return subprocess.run(
        [sys.executable, "-m", "gaia.cli", "git", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )


def test_clone_analyze_list_clean_round_trip(tmp_path: Path):
    home = tmp_path / "gaia-home"

    cloned = _gaia(home, "clone", REPO, "--depth", "0", "--json")
    assert cloned.returncode == 0, cloned.stderr
    record = json.loads(cloned.stdout)
    assert record["name"] == "github.com/octocat/Hello-World"
    assert record["shallow"] is False
    assert Path(record["path"]).is_relative_to(home / "workspaces")

    analyzed = _gaia(home, "analyze", REPO, "--json")
    assert analyzed.returncode == 0, analyzed.stderr
    assert "README" in json.loads(analyzed.stdout)["key_files"]

    listed = _gaia(home, "list", "--json")
    assert [w["name"] for w in json.loads(listed.stdout)] == [record["name"]]

    cleaned = _gaia(home, "clean", "--all")
    assert cleaned.returncode == 0, cleaned.stderr
    assert json.loads(_gaia(home, "list", "--json").stdout) == []


def test_missing_repository_fails_loudly(tmp_path: Path):
    result = _gaia(tmp_path, "clone", "octocat/this-repo-does-not-exist-861")
    assert result.returncode == 1
    assert "does not exist or is private" in result.stderr
