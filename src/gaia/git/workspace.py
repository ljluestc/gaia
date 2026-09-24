# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Clone public repositories into a sandbox and run read-only git against them.

Security model, in the order a clone meets it:

* **HTTPS only, public hosts only.** :func:`parse_repo_url` refuses every other
  scheme and any URL carrying credentials; :func:`assert_public_host` refuses a
  host that resolves to a private, loopback or link-local address (the same
  block list :class:`gaia.web.client.WebClient` applies). Redirects are off, so
  a public URL cannot bounce the clone to an internal one.
* **Nothing from the user's git setup.** System and global config are nulled,
  every inherited ``GIT_*`` variable is dropped, prompts and credential helpers
  are disabled — so no stored credential is sent and none is saved.
* **Nothing the repository can execute.** No hook templates, no submodules, and
  ``core.symlinks=false`` so a checked-in symlink becomes a plain file instead
  of a pointer out of the sandbox.
* **Bounded.** Shallow by default, a wall-clock timeout, and a size cap enforced
  while the clone runs, not after it finishes.
* **Read-only afterwards.** :meth:`WorkspaceManager.run_git` refuses any
  subcommand outside :data:`READ_ONLY_GIT_SUBCOMMANDS`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from gaia.logger import get_logger

logger = get_logger(__name__)

DEFAULT_DEPTH = 1
MAX_DEPTH = 10_000
DEFAULT_MAX_CLONE_MB = 500
STALE_AFTER_DAYS = 7
CLONE_TIMEOUT_SECONDS = 600
GIT_READ_TIMEOUT_SECONDS = 60

#: Written inside ``.git/`` so it never shows up in the working tree or status.
METADATA_FILE = "gaia-workspace.json"

#: The only subcommands :meth:`WorkspaceManager.run_git` will run. ``clone`` is
#: deliberately absent: it has its own hardened path in
#: :meth:`WorkspaceManager.clone`.
READ_ONLY_GIT_SUBCOMMANDS = frozenset(
    {
        "log",
        "diff",
        "show",
        "shortlog",
        "rev-parse",
        "rev-list",
        "ls-files",
        "cat-file",
        "for-each-ref",
    }
)

_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_HOST_RE = re.compile(
    r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
_DEFAULT_HOST = "github.com"


class GitWorkspaceError(Exception):
    """A clone or workspace operation was refused or failed.

    The message is written for the end user: what failed and what to do next.
    """


@dataclass(frozen=True)
class RepoRef:
    """A validated ``https://<host>/<owner>/<repo>`` reference."""

    host: str
    owner: str
    repo: str

    @property
    def url(self) -> str:
        return f"https://{self.host}/{self.owner}/{self.repo}.git"

    @property
    def slug(self) -> str:
        """The workspace name, which is also its path under the root."""
        return f"{self.host}/{self.owner}/{self.repo}"


def parse_repo_url(spec: str) -> RepoRef:
    """Validate a repository reference and normalize it.

    Accepts ``owner/repo`` (GitHub shorthand) or
    ``https://<host>/<owner>/<repo>[.git]``.

    Raises:
        GitWorkspaceError: for any other shape, naming the accepted ones.
    """
    raw = (spec or "").strip()
    if not raw:
        raise GitWorkspaceError(
            "No repository given. Pass owner/repo or an https:// URL."
        )
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise GitWorkspaceError(
            f"Repository reference {raw!r} contains whitespace or control characters."
        )

    if "://" not in raw:
        if raw.startswith("git@") or ":" in raw:
            raise GitWorkspaceError(
                f"{raw!r} looks like an SSH address. Only public HTTPS clones are "
                "supported; use https://<host>/<owner>/<repo>."
            )
        parts = raw.split("/")
        if len(parts) != 2:
            raise GitWorkspaceError(
                f"{raw!r} is not owner/repo. Pass owner/repo for GitHub, or a full "
                "https://<host>/<owner>/<repo> URL."
            )
        return _build_ref(_DEFAULT_HOST, parts[0], parts[1], raw)

    parsed = urlparse(raw)
    if parsed.scheme.lower() != "https":
        raise GitWorkspaceError(
            f"{raw!r} uses {parsed.scheme}://. Only https:// clones are supported, "
            "so nothing is fetched over an unauthenticated or local transport."
        )
    if parsed.username or parsed.password:
        raise GitWorkspaceError(
            "The URL carries credentials. Workspaces only clone public repositories "
            "and never store credentials — remove the user:password@ part."
        )
    if parsed.query or parsed.fragment or parsed.params:
        raise GitWorkspaceError(
            f"{raw!r} has a query or fragment. Pass the plain repository URL."
        )
    try:
        port = parsed.port
    except ValueError as e:
        raise GitWorkspaceError(f"{raw!r} has an invalid port: {e}") from e
    if port not in (None, 443):
        raise GitWorkspaceError(
            f"{raw!r} uses port {port}. Only the default HTTPS port is supported."
        )

    host = (parsed.hostname or "").lower()
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2:
        raise GitWorkspaceError(
            f"{raw!r} does not name a repository as <host>/<owner>/<repo>. "
            "Nested groups (GitLab subgroups) are not supported yet."
        )
    return _build_ref(host, parts[0], parts[1], raw)


def _build_ref(host: str, owner: str, repo: str, raw: str) -> RepoRef:
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not _HOST_RE.match(host):
        raise GitWorkspaceError(f"{raw!r} does not have a valid public hostname.")
    for label, value in (("owner", owner), ("repository", repo)):
        if not _SEGMENT_RE.match(value) or ".." in value:
            raise GitWorkspaceError(
                f"Invalid {label} name {value!r} in {raw!r}. Names may contain "
                "letters, digits, '.', '_' and '-'."
            )
    return RepoRef(host=host, owner=owner, repo=repo)


def assert_public_host(host: str) -> str:
    """Refuse a host that resolves to a private, loopback or reserved address.

    Returns:
        The vetted address, which the clone pins so git cannot re-resolve the
        host to something else (DNS rebinding).

    Raises:
        GitWorkspaceError: when the host does not resolve or any address is blocked.
    """
    from gaia.web.client import _is_blocked_ip, _loopback_allowed_hosts

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise GitWorkspaceError(
            f"Cannot resolve {host}: {e}. Check the hostname and your network connection."
        ) from e
    allow_loopback = host in _loopback_allowed_hosts()
    vetted = []
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        if not (allow_loopback and ip.is_loopback) and _is_blocked_ip(ip):
            raise GitWorkspaceError(
                f"Refused: {host} resolves to the private or reserved address {ip}. "
                "Workspaces only clone from public hosts."
            )
        vetted.append(ip)
    if not vetted:
        raise GitWorkspaceError(f"Cannot resolve {host}: no addresses returned.")
    ip = vetted[0]
    return f"[{ip}]" if ip.version == 6 else str(ip)


def validate_ref(ref: str, *, label: str = "ref") -> str:
    """Return *ref* if it is a plausible revision, else raise.

    Refs are passed to git after ``--end-of-options`` too; this check exists so
    a malformed value produces a clear message instead of a git usage error.
    """
    value = (ref or "").strip()
    if not value:
        raise GitWorkspaceError(f"{label} is empty.")
    if value.startswith("-") or len(value) > 200 or ".." in value:
        raise GitWorkspaceError(f"{label} {value!r} is not a valid git revision.")
    if not re.match(r"^[A-Za-z0-9._/@^~{}-]+$", value):
        raise GitWorkspaceError(
            f"{label} {value!r} contains characters git revisions do not use."
        )
    return value


def _git_env(home: Path) -> Dict[str, str]:
    """An environment that ignores the user's git config, credentials and prompts.

    *home* must be an empty directory: git's HTTP layer reads ``~/.netrc`` on
    its own, so the real home would leak stored credentials into a clone.
    """
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.upper().startswith("GIT_") and k.upper() not in ("NETRC", "CURL_HOME")
    }
    env.update(
        {
            "HOME": str(home),
            "USERPROFILE": str(home),
            "XDG_CONFIG_HOME": str(home),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "",
            "SSH_ASKPASS": "",
            "GCM_INTERACTIVE": "never",
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_PAGER": "cat",
            "PAGER": "cat",
            "LC_ALL": "C",
        }
    )
    return env


#: The one transport clones may use. Tests swap it for ``file`` alongside
#: :func:`_remote_url`; nothing else should.
_ALLOWED_PROTOCOL = "https"


def _hardening() -> List[str]:
    """``-c`` options applied to every git invocation, read or clone."""
    return [
        "-c",
        "credential.helper=",
        "-c",
        "core.symlinks=false",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "protocol.allow=never",
        "-c",
        f"protocol.{_ALLOWED_PROTOCOL}.allow=always",
        "-c",
        "http.followRedirects=false",
    ]


def _remote_url(ref: RepoRef) -> str:
    """The URL actually cloned. A seam for tests, which point it at a local repo."""
    return ref.url


def _git_binary() -> str:
    path = shutil.which("git")
    if not path:
        raise GitWorkspaceError(
            "git is not installed or not on PATH. Install it from "
            "https://git-scm.com/downloads, then retry."
        )
    return path


#: ``http.curloptResolve``, which pins the vetted address, arrived in git 2.37.
_MIN_GIT_FOR_PINNING = (2, 37)


def _assert_git_can_pin() -> None:
    """Refuse to clone on a git that would silently ignore the address pin."""
    out = subprocess.run(
        [_git_binary(), "--version"], capture_output=True, text=True, check=True
    ).stdout
    match = re.search(r"(\d+)\.(\d+)", out)
    if not match or tuple(map(int, match.groups())) < _MIN_GIT_FOR_PINNING:
        raise GitWorkspaceError(
            f"{out.strip() or 'git'} is too old to clone safely: git "
            f"{'.'.join(map(str, _MIN_GIT_FOR_PINNING))} or newer is required to pin "
            "the vetted host address. Update git from https://git-scm.com/downloads."
        )


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except FileNotFoundError:
                continue
    return total


def _rmtree(path: Path) -> None:
    """Delete a tree, clearing the read-only bit git sets on pack files (Windows)."""

    def _on_error(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=_on_error)
    else:
        shutil.rmtree(path, onerror=_on_error)  # pylint: disable=deprecated-argument


def _rmtree_if_exists(path: Path) -> None:
    if path.exists():
        _rmtree(path)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _default_root() -> Path:
    from gaia.llm.lemonade_embedded import gaia_home

    return gaia_home() / "workspaces"


class WorkspaceManager:
    """Owns ``~/.gaia/workspaces``: clone into it, list, resolve, clean.

    Args:
        root: Override the workspace root (tests). Defaults to
            ``$GAIA_HOME/workspaces``.
        max_clone_mb: Size cap applied while a clone runs.
        check_host: Resolve and vet the host before cloning. Only tests that
            clone from a local fixture turn this off.
    """

    def __init__(
        self,
        root: Optional[Path] = None,
        *,
        max_clone_mb: int = DEFAULT_MAX_CLONE_MB,
        check_host: bool = True,
    ):
        if max_clone_mb < 1:
            raise ValueError(f"max_clone_mb must be at least 1, got {max_clone_mb}")
        self.root = (Path(root) if root is not None else _default_root()).resolve()
        self.max_clone_bytes = max_clone_mb * 1024 * 1024
        self.check_host = check_host

    # ── clone ──────────────────────────────────────────────────────────

    def clone(
        self, spec: str, *, depth: int = DEFAULT_DEPTH, branch: str = ""
    ) -> Dict[str, Any]:
        """Clone *spec* into the sandbox and return its workspace record.

        ``depth=0`` fetches full history. An existing workspace for the same
        repository is returned as-is with ``already_present: True`` — re-cloning
        would silently discard its history depth and branch.
        """
        ref = parse_repo_url(spec)
        if not isinstance(depth, int) or depth < 0 or depth > MAX_DEPTH:
            raise GitWorkspaceError(
                f"depth must be 0 (full history) or 1-{MAX_DEPTH}, got {depth!r}."
            )
        branch = (branch or "").strip()
        if branch and (
            not _BRANCH_RE.match(branch) or ".." in branch or branch.endswith(".lock")
        ):
            raise GitWorkspaceError(f"{branch!r} is not a valid branch or tag name.")

        dest = self.root / ref.host / ref.owner / ref.repo
        if (dest / ".git").is_dir():
            record = self.describe(dest)
            record["already_present"] = True
            return record
        if dest.exists():
            raise GitWorkspaceError(
                f"{dest} exists but is not a git checkout. Remove it with "
                f"`gaia git clean --name {ref.slug}` and retry."
            )

        pin: List[str] = []
        if self.check_host:
            _assert_git_can_pin()
            address = assert_public_host(ref.host)
            pin = ["-c", f"http.curloptResolve={ref.host}:443:{address}"]

        staging = self.root / ".staging" / uuid.uuid4().hex
        try:
            staging.parent.mkdir(parents=True, exist_ok=True)
            self._isolated_home()
        except OSError as e:
            raise GitWorkspaceError(f"Cannot create {staging.parent}: {e}") from e
        argv = [
            _git_binary(),
            *_hardening(),
            *pin,
            "clone",
            "--template=",
            "--no-recurse-submodules",
            "--config",
            "core.symlinks=false",
        ]
        if depth:
            argv += ["--depth", str(depth)]
        if branch:
            argv += ["--branch", branch]
        argv += ["--", _remote_url(ref), str(staging)]

        now = _now().isoformat()
        try:
            self._run_clone(argv, staging, ref)
            if _dir_size(staging) > self.max_clone_bytes:
                raise self._too_large(ref)
            has_head = self.run_git(
                staging, ["rev-parse", "--verify", "--quiet", "HEAD"], ok_codes=(0, 1)
            ).strip()
            if not has_head:
                raise GitWorkspaceError(
                    f"{ref.url} is empty — it has no commits to explore."
                )
            self._write_metadata(
                staging,
                {
                    "url": ref.url,
                    "host": ref.host,
                    "owner": ref.owner,
                    "repo": ref.repo,
                    "requested_branch": branch or None,
                    "depth": depth,
                    "cloned_at": now,
                    "last_used_at": now,
                },
            )
            dest.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging, dest)
        except OSError as e:
            _rmtree_if_exists(staging)
            raise GitWorkspaceError(
                f"Could not move the clone of {ref.url} into {dest}: {e}. If another "
                "clone of the same repository is running, wait for it and retry."
            ) from e
        except BaseException:
            _rmtree_if_exists(staging)
            raise
        record = self.describe(dest)
        record["already_present"] = False
        return record

    def _run_clone(self, argv: Sequence[str], staging: Path, ref: RepoRef) -> None:
        """Run ``git clone``, killing it if it outgrows the cap or the timeout."""
        logger.debug("Cloning %s into %s", ref.url, staging)
        # stderr goes to a file, not a pipe: nothing drains a pipe while we poll,
        # so a chatty clone could fill it and deadlock.
        with tempfile.TemporaryFile() as err_file:
            proc = subprocess.Popen(  # pylint: disable=consider-using-with
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=err_file,
                env=_git_env(self._isolated_home()),
                cwd=str(self.root),
            )
            deadline = time.monotonic() + CLONE_TIMEOUT_SECONDS
            try:
                while proc.poll() is None:
                    if time.monotonic() > deadline:
                        raise GitWorkspaceError(
                            f"Cloning {ref.url} took longer than {CLONE_TIMEOUT_SECONDS}s "
                            "and was stopped. Try a shallower clone (depth=1) or a "
                            "smaller repository."
                        )
                    if staging.exists() and _dir_size(staging) > self.max_clone_bytes:
                        raise self._too_large(ref)
                    time.sleep(0.5)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            err_file.seek(0)
            err = err_file.read().decode("utf-8", "replace")

        if proc.returncode == 0:
            return
        if "could not read Username" in err or "Authentication failed" in err:
            raise GitWorkspaceError(
                f"{ref.url} does not exist or is private. Workspaces only clone public "
                "repositories; check the owner and name, and note that a renamed "
                "repository must be cloned by its new URL because redirects are not "
                "followed."
            )
        detail = " ".join(err.strip().splitlines()[-3:])
        raise GitWorkspaceError(
            f"git clone of {ref.url} failed: {detail or 'no output'}. Check the URL "
            "and your network connection."
        )

    def _too_large(self, ref: RepoRef) -> GitWorkspaceError:
        return GitWorkspaceError(
            f"{ref.url} exceeds the {self.max_clone_bytes // (1024 * 1024)} MB workspace "
            "limit and was removed. Clone shallower (depth=1), or raise the limit with "
            "`gaia git clone --max-size-mb`."
        )

    def _isolated_home(self) -> Path:
        """An always-empty HOME for git, so no ``.netrc`` or config is read."""
        home = self.root / ".git-home"
        home.mkdir(parents=True, exist_ok=True)
        if any(home.iterdir()):
            raise GitWorkspaceError(
                f"{home} must stay empty (it stands in for HOME when git runs). "
                "Remove whatever was put there and retry."
            )
        return home

    # ── lookup ─────────────────────────────────────────────────────────

    def resolve(self, name: str) -> Path:
        """Map a workspace name to its checkout directory.

        Accepts ``host/owner/repo``, ``owner/repo`` (when only one host has it),
        or a clone URL.

        Raises:
            GitWorkspaceError: unknown, ambiguous, or outside the sandbox.
        """
        value = (name or "").strip().rstrip("/")
        if "://" in value:
            value = parse_repo_url(value).slug
        parts = value.split("/")
        if len(parts) not in (2, 3) or not all(
            _SEGMENT_RE.match(p) and ".." not in p for p in parts
        ):
            raise GitWorkspaceError(
                f"{name!r} is not a workspace name. Use owner/repo or host/owner/repo "
                "as shown by list_workspaces."
            )
        if len(parts) == 3:
            candidates = [self.root / parts[0].lower() / parts[1] / parts[2]]
        else:
            candidates = sorted(
                p / parts[0] / parts[1]
                for p in self._host_dirs()
                if (p / parts[0] / parts[1] / ".git").is_dir()
            )
            if len(candidates) > 1:
                names = ", ".join(
                    str(c.relative_to(self.root)).replace(os.sep, "/")
                    for c in candidates
                )
                raise GitWorkspaceError(
                    f"{name!r} matches several workspaces: {names}. Pass host/owner/repo."
                )

        if not candidates or not (candidates[0] / ".git").is_dir():
            raise GitWorkspaceError(
                f"No workspace named {name!r}. Clone it first, or call list_workspaces "
                "to see what is available."
            )
        path = candidates[0].resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise GitWorkspaceError(
                f"{name!r} resolves outside the workspace sandbox and was refused."
            )
        return path

    def _host_dirs(self) -> List[Path]:
        if not self.root.is_dir():
            return []
        return [
            p for p in self.root.iterdir() if p.is_dir() and not p.name.startswith(".")
        ]

    def _checkouts(self) -> List[Path]:
        found: List[Path] = []
        for host in self._host_dirs():
            for owner in (p for p in host.iterdir() if p.is_dir()):
                found.extend(r for r in owner.iterdir() if (r / ".git").is_dir())
        return sorted(found)

    def name_of(self, path: Path) -> str:
        return str(path.resolve().relative_to(self.root.resolve())).replace(os.sep, "/")

    # ── metadata ───────────────────────────────────────────────────────

    def _read_metadata(self, path: Path) -> Dict[str, Any]:
        meta_path = path / ".git" / METADATA_FILE
        if not meta_path.is_file():
            return {}
        try:
            data: Dict[str, Any] = json.loads(meta_path.read_text(encoding="utf-8"))
            return data
        except (OSError, json.JSONDecodeError) as e:
            raise GitWorkspaceError(
                f"Workspace metadata at {meta_path} is unreadable ({e}). Remove the "
                f"workspace with `gaia git clean --name {self.name_of(path)}` and re-clone."
            ) from e

    def _write_metadata(self, path: Path, data: Dict[str, Any]) -> None:
        (path / ".git" / METADATA_FILE).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def touch(self, path: Path) -> None:
        """Record that a workspace was just used, so it is not cleaned as stale."""
        meta = self._read_metadata(path)
        meta["last_used_at"] = _now().isoformat()
        self._write_metadata(path, meta)

    def _last_used(self, path: Path, meta: Dict[str, Any]) -> datetime:
        stamp = meta.get("last_used_at") or meta.get("cloned_at")
        if stamp:
            return datetime.fromisoformat(stamp)
        return datetime.fromtimestamp((path / ".git").stat().st_mtime, tz=timezone.utc)

    def describe(self, path: Path) -> Dict[str, Any]:
        """The workspace record: name, path, HEAD, size, and staleness."""
        meta = self._read_metadata(path)
        last_used = self._last_used(path, meta)
        head = self.run_git(path, ["rev-parse", "HEAD"]).strip()
        branch = self.run_git(path, ["rev-parse", "--abbrev-ref", "HEAD"]).strip()
        shallow = (
            self.run_git(path, ["rev-parse", "--is-shallow-repository"]).strip()
            == "true"
        )
        return {
            "name": self.name_of(path),
            "path": str(path),
            "url": meta.get("url"),
            "branch": branch,
            "head": head,
            "shallow": shallow,
            "depth": meta.get("depth"),
            "size_mb": round(_dir_size(path) / (1024 * 1024), 2),
            "cloned_at": meta.get("cloned_at"),
            "last_used_at": last_used.isoformat(),
            "stale": _now() - last_used > timedelta(days=STALE_AFTER_DAYS),
        }

    def list(self) -> List[Dict[str, Any]]:
        return [self.describe(p) for p in self._checkouts()]

    # ── cleanup ────────────────────────────────────────────────────────

    def remove(self, name: str) -> str:
        path = self.resolve(name)
        workspace = self.name_of(path)
        _rmtree(path)
        self._prune_empty_parents(path.parent)
        return workspace

    def clean(
        self, *, older_than_days: int = STALE_AFTER_DAYS, dry_run: bool = False
    ) -> List[str]:
        """Remove workspaces unused for *older_than_days* (``0`` removes all)."""
        if older_than_days < 0:
            raise GitWorkspaceError(
                f"older_than_days must be 0 or more, got {older_than_days}."
            )
        cutoff = _now() - timedelta(days=older_than_days)
        removed = []
        for path in self._checkouts():
            if (
                older_than_days
                and self._last_used(path, self._read_metadata(path)) > cutoff
            ):
                continue
            removed.append(self.name_of(path))
            if not dry_run:
                _rmtree(path)
                self._prune_empty_parents(path.parent)
        staging = self.root / ".staging"
        if not dry_run and staging.is_dir():
            _rmtree(staging)
        return removed

    def _prune_empty_parents(self, path: Path) -> None:
        root = self.root.resolve()
        current = path.resolve()
        while (
            current != root
            and current.is_relative_to(root)
            and not any(current.iterdir())
        ):
            current.rmdir()
            current = current.parent

    # ── read-only git ──────────────────────────────────────────────────

    def run_git(
        self,
        path: Path,
        args: Sequence[str],
        *,
        timeout: int = GIT_READ_TIMEOUT_SECONDS,
        ok_codes: Sequence[int] = (0,),
    ) -> str:
        """Run one read-only git subcommand inside a workspace and return stdout.

        Raises:
            GitWorkspaceError: the subcommand is not read-only, or git failed.
        """
        if not args or args[0] not in READ_ONLY_GIT_SUBCOMMANDS:
            raise GitWorkspaceError(
                f"git {args[0] if args else ''} is not allowed in a workspace. Workspaces "
                f"are read-only after the clone; allowed: {', '.join(sorted(READ_ONLY_GIT_SUBCOMMANDS))}."
            )
        argv = [_git_binary(), *_hardening(), "-C", str(path), *args]
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                env=_git_env(self._isolated_home()),
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise GitWorkspaceError(
                f"git {args[0]} timed out after {timeout}s in {path}."
            ) from e
        if proc.returncode not in ok_codes:
            err = proc.stderr.decode("utf-8", "replace").strip()
            raise GitWorkspaceError(
                f"git {args[0]} failed in {self.name_of(path)}: {err or 'no output'}"
            )
        return proc.stdout.decode("utf-8", "replace")
