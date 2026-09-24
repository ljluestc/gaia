# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Clone a public repository into a sandbox, then explore it read-only (#861).

Five tools: ``clone_repo``, ``analyze_repo``, ``git_history``, ``review_diff``
and ``list_workspaces``. The only write is the clone itself, into
``~/.gaia/workspaces/``; every later git call goes through
:meth:`gaia.git.workspace.WorkspaceManager.run_git`, which refuses anything but
read-only subcommands. Reading the files themselves is left to the file tools
the agent already has — each result carries the absolute ``path`` for that.

``clone_repo`` is not added to the shell mixin's ``SAFE_GIT_COMMANDS``: the
general shell stays unable to clone, and this mixin's hardened clone path is
the only way in.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Optional

from gaia.logger import get_logger

logger = get_logger(__name__)

GIT_TOOL_NAMES = (
    "clone_repo",
    "analyze_repo",
    "git_history",
    "review_diff",
    "list_workspaces",
)

MAX_HISTORY_COMMITS = 200
DEFAULT_PATCH_CHARS = 20_000
MAX_PATCH_CHARS = 100_000

_FIELD_SEP = "\x1f"
_CONVENTIONAL_TYPES = (
    "feat",
    "fix",
    "docs",
    "refactor",
    "test",
    "chore",
    "ci",
    "perf",
    "build",
    "style",
    "revert",
)


def _error(message: str) -> Dict[str, Any]:
    return {"status": "error", "error": message}


class GitToolsMixin:
    """Adds the sandboxed repository-exploration tools.

    Call :meth:`register_git_tools` from ``_register_tools``. Set
    ``self._git_workspaces`` to a :class:`~gaia.git.workspace.WorkspaceManager`
    first to relocate the sandbox (tests do); otherwise one is built on first use.
    """

    _git_workspaces: Optional[Any] = None

    def _workspace_manager(self):
        if self._git_workspaces is None:
            from gaia.git.workspace import WorkspaceManager

            self._git_workspaces = WorkspaceManager()
        return self._git_workspaces

    def register_git_tools(self) -> None:
        """Register the git workspace tools onto this agent."""
        from gaia.agents.base.tools import tool
        from gaia.git.workspace import GitWorkspaceError, validate_ref

        agent = self

        @tool
        def clone_repo(url: str, depth: int = 1, branch: str = "") -> dict:
            """Clone a public repository into GAIA's sandbox so it can be explored.

            Use when the user asks what a repository does, to evaluate an
            open-source project, or to review its history or changes. Clones
            into ~/.gaia/workspaces/<host>/<owner>/<repo>/; nothing outside that
            folder is touched. HTTPS and public repositories only. A repository
            that is already cloned is returned as-is, not cloned again.

            Args:
                url: "owner/repo" for GitHub, or https://<host>/<owner>/<repo>.
                depth: Commits of history to fetch. 1 (default) is enough to
                    read the code; use 0 for full history when the user wants
                    history or a diff between releases.
                branch: Branch or tag to check out. Empty for the default branch.

            Returns:
                The workspace record: name (pass it to the other git tools),
                path (read files under it), branch, head, size_mb.
            """
            try:
                record: Dict[str, Any] = agent._workspace_manager().clone(
                    url, depth=depth, branch=branch
                )
            except GitWorkspaceError as e:
                return _error(str(e))
            record["status"] = "success"
            record["next_step"] = (
                f"Call analyze_repo('{record['name']}') for a profile, then read "
                f"files under {record['path']}."
            )
            return record

        @tool
        def analyze_repo(workspace: str) -> dict:
            """Profile a cloned repository: languages, stack, entry points, layout.

            Reads manifests and file names only; nothing in the repository is run.
            Start here after clone_repo to answer "what does this repo do".

            Args:
                workspace: Workspace name from clone_repo or list_workspaces,
                    e.g. "github.com/amd/gaia" or "amd/gaia".

            Returns:
                primary_language, languages, frameworks, manifests, entry_points,
                key_files, license, top_level folders, test and CI counts, and
                the start of the README.
            """
            from gaia.git.analyzer import analyze_repository

            manager = agent._workspace_manager()
            try:
                path = manager.resolve(workspace)
                files = manager.run_git(path, ["ls-files", "-z"]).split("\0")
                manager.touch(path)
            except GitWorkspaceError as e:
                return _error(str(e))
            profile = analyze_repository(path, files)
            profile.update(
                {
                    "status": "success",
                    "workspace": manager.name_of(path),
                    "path": str(path),
                }
            )
            return profile

        @tool
        def git_history(
            workspace: str, since: str = "", author: str = "", max_commits: int = 50
        ) -> dict:
            """Summarize a cloned repository's commit history.

            A depth-1 clone holds a single commit; clone with depth=0 first when
            the user wants real history.

            Args:
                workspace: Workspace name from clone_repo or list_workspaces.
                since: Only commits after this date, e.g. "2025-01-01" or
                    "3 months ago". Empty for no limit.
                author: Only commits whose author name or email contains this.
                max_commits: How many recent commits to return (1-200).

            Returns:
                commits (sha, author, date, subject), top contributors, the date
                range covered, conventional-commit type counts, and whether the
                clone is shallow.
            """
            if not 1 <= max_commits <= MAX_HISTORY_COMMITS:
                return _error(
                    f"max_commits must be 1-{MAX_HISTORY_COMMITS}, got {max_commits}."
                )
            args = [
                "log",
                "--no-color",
                "--date=short",
                f"--max-count={max_commits}",
                f"--pretty=format:%h{_FIELD_SEP}%an{_FIELD_SEP}%ad{_FIELD_SEP}%s",
            ]
            if since.strip():
                args.append(f"--since={since.strip()}")
            if author.strip():
                args += ["--fixed-strings", f"--author={author.strip()}"]
            manager = agent._workspace_manager()
            try:
                path = manager.resolve(workspace)
                raw = manager.run_git(path, args)
                shallow = (
                    manager.run_git(
                        path, ["rev-parse", "--is-shallow-repository"]
                    ).strip()
                    == "true"
                )
                manager.touch(path)
            except GitWorkspaceError as e:
                return _error(str(e))

            commits = []
            for line in raw.splitlines():
                parts = line.split(_FIELD_SEP)
                if len(parts) == 4:
                    commits.append(
                        {
                            "sha": parts[0],
                            "author": parts[1],
                            "date": parts[2],
                            "subject": parts[3],
                        }
                    )
            contributors = Counter(c["author"] for c in commits)
            types = Counter(
                c["subject"]
                .split(":", 1)[0]
                .split("(", 1)[0]
                .rstrip("!")
                .strip()
                .lower()
                for c in commits
            )
            result = {
                "status": "success",
                "workspace": manager.name_of(path),
                "shallow": shallow,
                "commit_count": len(commits),
                "date_range": (
                    {"newest": commits[0]["date"], "oldest": commits[-1]["date"]}
                    if commits
                    else None
                ),
                "top_contributors": [
                    {"author": a, "commits": n} for a, n in contributors.most_common(10)
                ],
                "commit_types": {t: types[t] for t in _CONVENTIONAL_TYPES if types[t]},
                "commits": commits,
            }
            if shallow:
                result["note"] = (
                    "This is a shallow clone, so older history is missing. Re-clone "
                    "with depth=0 after `gaia git clean --name "
                    f"{manager.name_of(path)}` for the full history."
                )
            return result

        @tool
        def review_diff(
            workspace: str,
            base: str,
            head: str = "HEAD",
            max_patch_chars: int = DEFAULT_PATCH_CHARS,
        ) -> dict:
            """Compare two revisions of a cloned repository and return the changes.

            Use to summarize what changed between releases, branches or commits.
            Both revisions must exist in the clone — a depth-1 clone only has
            HEAD, so clone with depth=0 first.

            Args:
                workspace: Workspace name from clone_repo or list_workspaces.
                base: The older revision: a tag, branch, or commit sha.
                head: The newer revision. Defaults to HEAD.
                max_patch_chars: Cap on the returned patch text (1000-100000).

            Returns:
                commits between the two, per-file added/removed line counts,
                totals, and the patch (truncated to max_patch_chars, with
                truncated=true when cut).
            """
            if not 1000 <= max_patch_chars <= MAX_PATCH_CHARS:
                return _error(
                    f"max_patch_chars must be 1000-{MAX_PATCH_CHARS}, got {max_patch_chars}."
                )
            manager = agent._workspace_manager()
            try:
                base_ref = validate_ref(base, label="base")
                head_ref = validate_ref(head, label="head")
                path = manager.resolve(workspace)
                for label, ref in (("base", base_ref), ("head", head_ref)):
                    found = manager.run_git(
                        path,
                        ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
                        ok_codes=(0, 1),
                    ).strip()
                    if not found:
                        shallow = (
                            manager.run_git(
                                path, ["rev-parse", "--is-shallow-repository"]
                            ).strip()
                            == "true"
                        )
                        hint = (
                            "This is a shallow clone, so older commits and tags are "
                            "missing; re-clone with depth=0 to compare them."
                            if shallow
                            else "Check the name with git_history, or pass a commit sha."
                        )
                        return _error(
                            f"{label} revision {ref!r} is not in {manager.name_of(path)}. {hint}"
                        )
                diff_opts = ["--no-color", "--no-ext-diff", "--no-textconv"]
                numstat = manager.run_git(
                    path,
                    [
                        "diff",
                        *diff_opts,
                        "--numstat",
                        "--end-of-options",
                        base_ref,
                        head_ref,
                    ],
                )
                log = manager.run_git(
                    path,
                    [
                        "log",
                        "--no-color",
                        "--max-count=100",
                        "--pretty=format:%h %s",
                        "--end-of-options",
                        f"{base_ref}..{head_ref}",
                    ],
                )
                patch = manager.run_git(
                    path, ["diff", *diff_opts, "--end-of-options", base_ref, head_ref]
                )
                manager.touch(path)
            except GitWorkspaceError as e:
                return _error(str(e))

            files = []
            for line in numstat.splitlines():
                added, removed, name = (line.split("\t", 2) + ["", ""])[:3]
                binary = added == "-"
                files.append(
                    {
                        "file": name,
                        "added": None if binary else int(added),
                        "removed": None if binary else int(removed),
                        "binary": binary,
                    }
                )
            return {
                "status": "success",
                "workspace": manager.name_of(path),
                "base": base_ref,
                "head": head_ref,
                "commits": log.splitlines(),
                "files_changed": len(files),
                "lines_added": sum(f["added"] or 0 for f in files),
                "lines_removed": sum(f["removed"] or 0 for f in files),
                "files": files,
                "patch": patch[:max_patch_chars],
                "truncated": len(patch) > max_patch_chars,
            }

        @tool
        def list_workspaces() -> dict:
            """List the repositories cloned into GAIA's sandbox.

            Returns:
                Each workspace's name, path, branch, size_mb, last_used_at, and
                stale (unused for 7+ days; `gaia git clean` removes those).
            """
            try:
                workspaces = agent._workspace_manager().list()
            except GitWorkspaceError as e:
                return _error(str(e))
            return {
                "status": "success",
                "count": len(workspaces),
                "workspaces": workspaces,
            }
