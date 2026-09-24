# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Sandboxed git workspaces: clone a public repository, then read it.

Every clone lands under ``~/.gaia/workspaces/<host>/<owner>/<repo>/``. After the
clone, only read-only git subcommands run against it — see
:data:`gaia.git.workspace.READ_ONLY_GIT_SUBCOMMANDS`.
"""

from gaia.git.workspace import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_CLONE_MB,
    STALE_AFTER_DAYS,
    GitWorkspaceError,
    RepoRef,
    WorkspaceManager,
    parse_repo_url,
)

__all__ = [
    "DEFAULT_DEPTH",
    "DEFAULT_MAX_CLONE_MB",
    "STALE_AFTER_DAYS",
    "GitWorkspaceError",
    "RepoRef",
    "WorkspaceManager",
    "parse_repo_url",
]
