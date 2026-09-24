# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Sandboxed git workspaces and the tools on top of them (#861).

Clones run for real against a local fixture repository: ``_remote_url`` and the
single allowed protocol are the only seams swapped, so every other hardening
flag reaches a real ``git`` binary. No test touches the network or ``~/.gaia``.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import gaia.git.workspace as ws
from gaia.git.analyzer import analyze_repository
from gaia.git.workspace import (
    READ_ONLY_GIT_SUBCOMMANDS,
    GitWorkspaceError,
    WorkspaceManager,
    parse_repo_url,
    validate_ref,
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not on PATH")

REPO_ROOT = Path(__file__).resolve().parents[2]


def _git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Ada",
        "GIT_AUTHOR_EMAIL": "ada@example.com",
        "GIT_COMMITTER_NAME": "Ada",
        "GIT_COMMITTER_EMAIL": "ada@example.com",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout


@pytest.fixture
def source_repo(tmp_path: Path) -> Path:
    """A two-commit Python repo with a tag on the first commit."""
    src = tmp_path / "source"
    (src / "demo").mkdir(parents=True)
    (src / "tests").mkdir()
    _git(src, "init", "-q", "-b", "main")
    (src / "pyproject.toml").write_text(
        '[project]\nname = "demo"\ndependencies = ["fastapi>=0.100", "pydantic"]\n'
        '[project.scripts]\ndemo = "demo.cli:main"\n'
    )
    (src / "README.md").write_text("# Demo\n\nA demo service.\n")
    (src / "LICENSE").write_text("MIT License\n\nCopyright (c) Ada\n")
    (src / "demo" / "cli.py").write_text("def main():\n    return 1\n")
    (src / "tests" / "test_cli.py").write_text("def test_main():\n    pass\n")
    _git(src, "add", "-A")
    _git(src, "commit", "-qm", "feat: initial import")
    _git(src, "tag", "v1.0")
    (src / "demo" / "cli.py").write_text("def main():\n    return 2\n")
    _git(src, "commit", "-qam", "fix(cli): return the right code")
    return src


@pytest.fixture
def local_transport(monkeypatch, source_repo: Path):
    """Point clones at the fixture repo over file:// instead of https://."""
    monkeypatch.setattr(ws, "_remote_url", lambda ref: source_repo.as_uri())
    monkeypatch.setattr(ws, "_ALLOWED_PROTOCOL", "file")
    return source_repo


@pytest.fixture
def manager(tmp_path: Path, local_transport) -> WorkspaceManager:
    return WorkspaceManager(root=tmp_path / "workspaces", check_host=False)


# ── URL validation ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spec, slug",
    [
        ("amd/gaia", "github.com/amd/gaia"),
        ("https://github.com/amd/gaia", "github.com/amd/gaia"),
        ("https://github.com/amd/gaia.git", "github.com/amd/gaia"),
        ("https://GitLab.com/group/project/", "gitlab.com/group/project"),
        ("https://codeberg.org:443/forgejo/forgejo", "codeberg.org/forgejo/forgejo"),
    ],
)
def test_parse_repo_url_accepts_public_https(spec, slug):
    assert parse_repo_url(spec).slug == slug


@pytest.mark.parametrize(
    "spec, fragment",
    [
        ("git@github.com:amd/gaia.git", "SSH"),
        ("ssh://git@github.com/amd/gaia", "https://"),
        ("http://github.com/amd/gaia", "https://"),
        ("file:///etc/passwd", "https://"),
        ("ext::sh -c touch% /tmp/pwned", "whitespace"),
        ("https://user:token@github.com/amd/gaia", "credentials"),
        ("https://github.com:8443/amd/gaia", "port"),
        ("https://github.com/amd/gaia?x=1", "query"),
        ("https://github.com/group/sub/project", "Nested groups"),
        ("https://localhost/amd/gaia", "hostname"),
        ("amd/..", "Invalid repository"),
        ("-oProxyCommand=x/gaia", "Invalid owner"),
        ("amd", "owner/repo"),
        ("", "No repository"),
    ],
)
def test_parse_repo_url_refuses_everything_else(spec, fragment):
    with pytest.raises(GitWorkspaceError, match=fragment):
        parse_repo_url(spec)


def test_private_host_is_refused(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443))
        ],
    )
    with pytest.raises(GitWorkspaceError, match="private or reserved"):
        ws.assert_public_host("git.internal.example")


def test_public_host_is_allowed(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.112.3", 443))
        ],
    )
    ws.assert_public_host("github.com")


@pytest.mark.parametrize("ref", ["-p", "--output=/tmp/x", "a..b", "HEAD; rm", ""])
def test_validate_ref_refuses_option_shaped_or_odd_revisions(ref):
    with pytest.raises(GitWorkspaceError):
        validate_ref(ref)


@pytest.mark.parametrize("ref", ["HEAD", "HEAD~3", "v1.2.0", "origin/main", "abc123"])
def test_validate_ref_accepts_real_revisions(ref):
    assert validate_ref(ref) == ref


def test_git_env_drops_the_users_git_variables(monkeypatch):
    monkeypatch.setenv("GIT_SSH_COMMAND", "evil")
    monkeypatch.setenv("GIT_DIR", "/elsewhere")
    env = ws._git_env(Path(os.devnull))
    assert "GIT_SSH_COMMAND" not in env and "GIT_DIR" not in env
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_hardening_allows_only_https_and_disables_credentials_and_redirects():
    flags = ws._hardening()
    pairs = {flags[i + 1] for i in range(0, len(flags), 2)}
    assert {
        "protocol.allow=never",
        "protocol.https.allow=always",
        "credential.helper=",
        "http.followRedirects=false",
        "core.symlinks=false",
    } <= pairs


# ── clone ──────────────────────────────────────────────────────────────


def test_clone_lands_in_the_sandbox_with_metadata(manager: WorkspaceManager):
    record = manager.clone("octo/demo")

    assert record["name"] == "github.com/octo/demo"
    assert record["already_present"] is False
    assert record["shallow"] is True
    path = Path(record["path"])
    assert path == manager.root / "github.com" / "octo" / "demo"
    meta = json.loads((path / ".git" / ws.METADATA_FILE).read_text())
    assert meta["url"] == "https://github.com/octo/demo.git"
    assert not (manager.root / ".staging").exists() or not any(
        (manager.root / ".staging").iterdir()
    )


def test_clone_does_not_persist_credentials_or_hooks(manager: WorkspaceManager):
    path = Path(manager.clone("octo/demo")["path"])
    config = (path / ".git" / "config").read_text()

    assert "credential" not in config
    assert "symlinks = false" in config
    hooks = path / ".git" / "hooks"
    assert not hooks.exists() or not any(hooks.iterdir())


@pytest.mark.skipif(sys.platform == "win32", reason="symlink creation needs privileges")
def test_checked_in_symlink_cannot_point_out_of_the_sandbox(
    tmp_path: Path, source_repo: Path, manager: WorkspaceManager
):
    (source_repo / "leak").symlink_to("/etc/passwd")
    _git(source_repo, "add", "leak")
    _git(source_repo, "commit", "-qm", "add link")

    path = Path(manager.clone("octo/demo")["path"])

    assert not (path / "leak").is_symlink()
    assert (path / "leak").read_text() == "/etc/passwd"


def test_existing_workspace_is_returned_not_recloned(manager: WorkspaceManager):
    first = manager.clone("octo/demo")
    second = manager.clone("https://github.com/octo/demo.git")

    assert second["already_present"] is True
    assert second["head"] == first["head"]


def test_clone_over_the_size_cap_is_aborted_and_removed(tmp_path, local_transport):
    big = local_transport / "blob.bin"
    big.write_bytes(os.urandom(2 * 1024 * 1024))
    _git(local_transport, "add", "blob.bin")
    _git(local_transport, "commit", "-qm", "blob")
    manager = WorkspaceManager(root=tmp_path / "ws", max_clone_mb=1, check_host=False)

    with pytest.raises(GitWorkspaceError, match="exceeds the 1 MB"):
        manager.clone("octo/demo")

    assert not (manager.root / "github.com" / "octo" / "demo").exists()
    assert not any((manager.root / ".staging").iterdir())


def test_missing_repository_reports_a_clear_error(
    tmp_path, monkeypatch, local_transport
):
    monkeypatch.setattr(ws, "_remote_url", lambda ref: (tmp_path / "nope").as_uri())
    manager = WorkspaceManager(root=tmp_path / "ws", check_host=False)

    with pytest.raises(GitWorkspaceError, match="git clone of .* failed"):
        manager.clone("octo/demo")
    assert not (manager.root / "github.com").exists()


@pytest.mark.parametrize(
    "kwargs, fragment",
    [
        ({"depth": -1}, "depth"),
        ({"depth": 10**6}, "depth"),
        ({"branch": "--upload-pack=x"}, "branch"),
    ],
)
def test_clone_refuses_bad_depth_or_branch(manager: WorkspaceManager, kwargs, fragment):
    with pytest.raises(GitWorkspaceError, match=fragment):
        manager.clone("octo/demo", **kwargs)


def test_clone_vets_the_host_before_running_git(tmp_path, monkeypatch):
    def _blocked(host):
        raise GitWorkspaceError(f"blocked {host}")

    monkeypatch.setattr(ws, "_assert_git_can_pin", lambda: None)
    monkeypatch.setattr(ws, "assert_public_host", _blocked)
    monkeypatch.setattr(ws.subprocess, "Popen", lambda *a, **k: pytest.fail("git ran"))

    with pytest.raises(GitWorkspaceError, match="blocked github.com"):
        WorkspaceManager(root=tmp_path / "ws").clone("amd/gaia")


# ── read-only enforcement ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "subcommand",
    [
        "push",
        "commit",
        "merge",
        "rebase",
        "checkout",
        "clone",
        "fetch",
        "config",
        "reset",
    ],
)
def test_write_git_operations_are_refused(manager: WorkspaceManager, subcommand):
    path = Path(manager.clone("octo/demo")["path"])
    with pytest.raises(GitWorkspaceError, match="read-only"):
        manager.run_git(path, [subcommand])


def test_read_only_allowlist_has_no_writers():
    assert not READ_ONLY_GIT_SUBCOMMANDS & {
        "push",
        "commit",
        "merge",
        "rebase",
        "checkout",
        "clone",
        "fetch",
        "pull",
        "config",
        "reset",
        "am",
        "apply",
    }


def test_shell_mixin_still_cannot_clone():
    from gaia.agents.tools.shell_tools import SAFE_GIT_COMMANDS

    assert "clone" not in SAFE_GIT_COMMANDS


# ── lookup and cleanup ─────────────────────────────────────────────────


def test_resolve_accepts_short_and_full_names(manager: WorkspaceManager):
    path = Path(manager.clone("octo/demo")["path"]).resolve()

    assert manager.resolve("octo/demo") == path
    assert manager.resolve("github.com/octo/demo") == path
    assert manager.resolve("https://github.com/octo/demo") == path


@pytest.mark.parametrize(
    "name", ["../../etc", "octo/../../x", "/etc/passwd", "a/b/c/d", "octo/missing"]
)
def test_resolve_refuses_traversal_and_unknown_names(manager: WorkspaceManager, name):
    manager.clone("octo/demo")
    with pytest.raises(GitWorkspaceError):
        manager.resolve(name)


def test_resolve_refuses_an_ambiguous_short_name(manager: WorkspaceManager):
    manager.clone("octo/demo")
    manager.clone("https://gitlab.com/octo/demo")
    with pytest.raises(GitWorkspaceError, match="several workspaces"):
        manager.resolve("octo/demo")


def _age(manager: WorkspaceManager, name: str, days: int) -> None:
    path = manager.resolve(name)
    meta_path = path / ".git" / ws.METADATA_FILE
    meta = json.loads(meta_path.read_text())
    meta["last_used_at"] = (
        datetime.now(timezone.utc) - timedelta(days=days)
    ).isoformat()
    meta_path.write_text(json.dumps(meta))


def test_clean_removes_only_stale_workspaces(manager: WorkspaceManager):
    manager.clone("octo/demo")
    manager.clone("https://gitlab.com/octo/other")
    _age(manager, "github.com/octo/demo", days=30)

    listed = {w["name"]: w["stale"] for w in manager.list()}
    assert listed == {"github.com/octo/demo": True, "gitlab.com/octo/other": False}

    assert manager.clean(dry_run=True) == ["github.com/octo/demo"]
    assert len(manager.list()) == 2

    assert manager.clean() == ["github.com/octo/demo"]
    assert [w["name"] for w in manager.list()] == ["gitlab.com/octo/other"]
    assert not (manager.root / "github.com").exists()


def test_clean_zero_days_removes_everything(manager: WorkspaceManager):
    manager.clone("octo/demo")
    assert manager.clean(older_than_days=0) == ["github.com/octo/demo"]
    assert manager.list() == []


def test_touch_keeps_a_workspace_fresh(manager: WorkspaceManager):
    manager.clone("octo/demo")
    _age(manager, "octo/demo", days=30)
    manager.touch(manager.resolve("octo/demo"))
    assert manager.clean() == []


# ── analyzer ───────────────────────────────────────────────────────────


def _write_tree(root: Path, files: dict) -> list:
    for rel, body in files.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)
    return list(files)


def test_analyze_python_repo(tmp_path: Path):
    files = _write_tree(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname="x"\ndependencies=["django>=4", "numpy"]\n'
            '[project.scripts]\nx = "x.cli:main"\n',
            "README.md": "# X\n",
            "LICENSE": "Apache License\nVersion 2.0\n",
            "x/__init__.py": "",
            "x/cli.py": "",
            "tests/test_cli.py": "",
            ".github/workflows/ci.yml": "",
        },
    )
    profile = analyze_repository(tmp_path, files)

    assert profile["primary_language"] == "Python"
    assert profile["frameworks"] == ["Django", "NumPy"]
    assert profile["ecosystems"] == ["Python"]
    assert profile["license"] == "Apache-2.0"
    assert "console script `x` -> x.cli:main" in profile["entry_points"]
    assert profile["tests"]["test_files"] == 1
    assert profile["ci"]["github_workflows"] == 1
    assert profile["readme_excerpt"].startswith("# X")


def test_analyze_node_repo(tmp_path: Path):
    pkg = {
        "name": "web",
        "main": "dist/index.js",
        "scripts": {"dev": "next dev", "test": "jest"},
        "dependencies": {"next": "14", "react": "18"},
        "devDependencies": {"typescript": "5", "jest": "29"},
    }
    files = _write_tree(
        tmp_path,
        {
            "package.json": json.dumps(pkg),
            "src/index.ts": "",
            "src/app.tsx": "",
            "src/app.test.tsx": "",
            "README.md": "# Web\n",
        },
    )
    profile = analyze_repository(tmp_path, files)

    assert profile["primary_language"] == "TypeScript"
    assert profile["frameworks"] == ["Jest", "Next.js", "React", "TypeScript"]
    assert profile["ecosystems"] == ["Node.js"]
    assert "package main: dist/index.js" in profile["entry_points"]
    assert "npm run dev" in profile["entry_points"]
    assert profile["tests"]["test_files"] == 1


def test_analyze_rust_repo(tmp_path: Path):
    files = _write_tree(
        tmp_path,
        {
            "Cargo.toml": '[package]\nname="svc"\n[dependencies]\ntokio = "1"\naxum = "0.7"\n',
            "src/main.rs": "fn main() {}",
            "src/lib.rs": "",
            "LICENSE-MIT": "MIT License\n",
        },
    )
    profile = analyze_repository(tmp_path, files)

    assert profile["primary_language"] == "Rust"
    assert profile["frameworks"] == ["Axum", "Tokio"]
    assert "src/main.rs" in profile["entry_points"]


def test_analyze_reports_a_broken_manifest_instead_of_hiding_it(tmp_path: Path):
    files = _write_tree(tmp_path, {"package.json": "{not json", "index.js": ""})
    profile = analyze_repository(tmp_path, files)

    assert profile["frameworks"] == []
    assert profile["manifest_errors"] and profile["manifest_errors"][0].startswith(
        "package.json"
    )


# ── tools ──────────────────────────────────────────────────────────────


@pytest.fixture
def tools(manager: WorkspaceManager):
    from gaia.agents.base.tools import _TOOL_REGISTRY
    from gaia.agents.tools.git_tools import GIT_TOOL_NAMES, GitToolsMixin

    class _Agent(GitToolsMixin):
        pass

    agent = _Agent()
    agent._git_workspaces = manager
    before = dict(_TOOL_REGISTRY)
    agent.register_git_tools()
    registered = {name: _TOOL_REGISTRY[name]["function"] for name in GIT_TOOL_NAMES}
    _TOOL_REGISTRY.clear()
    _TOOL_REGISTRY.update(before)
    return registered


def test_known_tools_exposes_the_git_mixin():
    from gaia.agents.registry import KNOWN_TOOLS

    assert KNOWN_TOOLS["git"] == ("gaia.agents.tools.git_tools", "GitToolsMixin")


def test_clone_then_analyze(tools):
    cloned = tools["clone_repo"]("octo/demo")
    assert cloned["status"] == "success"
    assert "analyze_repo" in cloned["next_step"]

    profile = tools["analyze_repo"](cloned["name"])
    assert profile["status"] == "success"
    assert profile["frameworks"] == ["FastAPI", "Pydantic"]
    assert profile["license"] == "MIT"


def test_clone_repo_returns_refusals_as_errors(tools):
    result = tools["clone_repo"]("git@github.com:amd/gaia.git")
    assert result["status"] == "error"
    assert "SSH" in result["error"]


def test_git_history(tools):
    tools["clone_repo"]("octo/demo", depth=0)
    history = tools["git_history"]("octo/demo")

    assert history["status"] == "success"
    assert history["commit_count"] == 2
    assert history["commits"][0]["subject"] == "fix(cli): return the right code"
    assert history["top_contributors"] == [{"author": "Ada", "commits": 2}]
    assert history["commit_types"] == {"feat": 1, "fix": 1}
    assert "note" not in history


def test_git_history_filters_by_author_as_a_literal(tools):
    tools["clone_repo"]("octo/demo")
    assert tools["git_history"]("octo/demo", author="Nobody")["commit_count"] == 0
    assert tools["git_history"]("octo/demo", author="Ad.")["commit_count"] == 0


def test_git_history_rejects_out_of_range_limits(tools):
    assert tools["git_history"]("octo/demo", max_commits=0)["status"] == "error"


def test_review_diff_between_tag_and_head(tools):
    tools["clone_repo"]("octo/demo", depth=0)
    diff = tools["review_diff"]("octo/demo", base="v1.0")

    assert diff["status"] == "success"
    assert diff["commits"] == [diff["commits"][0]]
    assert diff["commits"][0].endswith("fix(cli): return the right code")
    assert diff["files"] == [
        {"file": "demo/cli.py", "added": 1, "removed": 1, "binary": False}
    ]
    assert "-    return 1" in diff["patch"] and diff["truncated"] is False


def test_review_diff_truncates_the_patch(tools):
    tools["clone_repo"]("octo/demo", depth=0)
    diff = tools["review_diff"]("octo/demo", base="v1.0", max_patch_chars=1000)
    assert len(diff["patch"]) <= 1000


def test_review_diff_reports_a_missing_revision(tools):
    tools["clone_repo"]("octo/demo")
    result = tools["review_diff"]("octo/demo", base="v9.9")
    assert result["status"] == "error"
    assert "'v9.9' is not in" in result["error"]
    assert "shallow clone" in result["error"]


def test_review_diff_refuses_option_shaped_refs(tools):
    tools["clone_repo"]("octo/demo")
    result = tools["review_diff"]("octo/demo", base="--output=/tmp/pwned")
    assert result["status"] == "error"
    assert not Path("/tmp/pwned").exists()


def test_list_workspaces(tools):
    assert tools["list_workspaces"]()["count"] == 0
    tools["clone_repo"]("octo/demo")
    listed = tools["list_workspaces"]()
    assert listed["count"] == 1
    assert listed["workspaces"][0]["name"] == "github.com/octo/demo"


def test_tools_on_an_unknown_workspace_return_errors(tools):
    for name in ("analyze_repo", "git_history"):
        result = tools[name]("octo/missing")
        assert result["status"] == "error"
        assert "No workspace named" in result["error"]


# ── CLI ────────────────────────────────────────────────────────────────


def _gaia(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "GAIA_HOME": str(tmp_path / "gaia-home"),
        "HOME": str(tmp_path),
    }
    return subprocess.run(
        [sys.executable, "-m", "gaia.cli", "git", *args],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_cli_list_on_an_empty_sandbox(tmp_path: Path):
    result = _gaia(tmp_path, "list")
    assert result.returncode == 0, result.stderr
    assert "No workspaces under" in result.stdout


def test_cli_clone_refuses_ssh_with_exit_1(tmp_path: Path):
    result = _gaia(tmp_path, "clone", "git@github.com:amd/gaia.git")
    assert result.returncode == 1
    assert "Only public HTTPS clones" in result.stderr


def test_cli_analyze_unknown_workspace(tmp_path: Path):
    result = _gaia(tmp_path, "analyze", "octo/missing")
    assert result.returncode == 1
    assert "No workspace named" in result.stderr


def test_cli_clean_on_an_empty_sandbox(tmp_path: Path):
    result = _gaia(tmp_path, "clean", "--all")
    assert result.returncode == 0, result.stderr
    assert "Nothing to clean." in result.stdout


def test_cli_without_subcommand_is_a_usage_error(tmp_path: Path):
    assert _gaia(tmp_path).returncode == 2


# ── review follow-ups ──────────────────────────────────────────────────


def test_empty_repository_is_refused_and_leaves_nothing_behind(
    tmp_path, monkeypatch, local_transport
):
    empty = tmp_path / "empty"
    empty.mkdir()
    _git(empty, "init", "-q", "-b", "main")
    monkeypatch.setattr(ws, "_remote_url", lambda ref: empty.as_uri())
    manager = WorkspaceManager(root=tmp_path / "ws", check_host=False)

    with pytest.raises(GitWorkspaceError, match="is empty"):
        manager.clone("octo/empty")

    assert manager.list() == []
    assert not any((manager.root / ".staging").iterdir())


def test_relative_root_is_resolved(tmp_path, monkeypatch, local_transport):
    monkeypatch.chdir(tmp_path)
    manager = WorkspaceManager(root=Path("rel-ws"), check_host=False)

    record = manager.clone("octo/demo")

    assert Path(record["path"]) == tmp_path / "rel-ws" / "github.com" / "octo" / "demo"


def test_git_runs_with_an_isolated_home_so_netrc_is_never_read(manager, monkeypatch):
    monkeypatch.setenv("NETRC", "/home/user/.netrc")
    env = ws._git_env(manager._isolated_home())

    assert env["HOME"] == str(manager.root / ".git-home")
    assert env["USERPROFILE"] == env["HOME"]
    assert "NETRC" not in env
    assert not any(Path(env["HOME"]).iterdir())


def test_clone_pins_the_vetted_address(tmp_path, monkeypatch):
    monkeypatch.setattr(ws, "_assert_git_can_pin", lambda: None)
    monkeypatch.setattr(ws, "assert_public_host", lambda host: "140.82.112.3")
    seen = {}

    def _capture(argv, *a, **k):
        seen["argv"] = argv
        raise GitWorkspaceError("stop after argv")

    monkeypatch.setattr(ws.subprocess, "Popen", _capture)
    with pytest.raises(GitWorkspaceError, match="stop after argv"):
        WorkspaceManager(root=tmp_path / "ws").clone("amd/gaia")

    assert "http.curloptResolve=github.com:443:140.82.112.3" in seen["argv"]


def test_ipv6_address_is_bracketed_for_pinning(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *a, **k: [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:50c0::1", 443, 0, 0))
        ],
    )
    assert ws.assert_public_host("example.com") == "[2606:50c0::1]"


def test_old_git_is_refused_rather_than_cloning_unpinned(monkeypatch):
    monkeypatch.setattr(
        ws.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(
            a, 0, stdout="git version 2.30.1\n"
        ),
    )
    with pytest.raises(GitWorkspaceError, match="too old"):
        ws._assert_git_can_pin()
