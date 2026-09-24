# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""``gaia git`` — manage the sandboxed repository workspaces (#861)."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

from gaia.git.workspace import (
    DEFAULT_DEPTH,
    DEFAULT_MAX_CLONE_MB,
    STALE_AFTER_DAYS,
    GitWorkspaceError,
    WorkspaceManager,
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2


def add_subparser(subparsers: argparse._SubParsersAction) -> None:
    """Register ``gaia git`` and its subcommands."""
    p = subparsers.add_parser(
        "git",
        help="Clone public repositories into a sandbox and inspect them "
        "(clone|analyze|list|clean)",
        description=(
            "Manage GAIA's repository workspaces under ~/.gaia/workspaces/. "
            "Clones are HTTPS-only, public-only, and read-only afterwards."
        ),
    )
    sub = p.add_subparsers(dest="git_action", metavar="<subcommand>", help="Subcommand")

    p_clone = sub.add_parser("clone", help="Clone a public repository into a workspace")
    p_clone.add_argument(
        "url", help="owner/repo (GitHub) or https://<host>/<owner>/<repo>"
    )
    p_clone.add_argument(
        "--depth",
        type=int,
        default=DEFAULT_DEPTH,
        help=f"Commits of history to fetch; 0 for full history (default: {DEFAULT_DEPTH})",
    )
    p_clone.add_argument("--branch", default="", help="Branch or tag to check out")
    p_clone.add_argument(
        "--max-size-mb",
        type=int,
        default=DEFAULT_MAX_CLONE_MB,
        help=f"Abort the clone past this size (default: {DEFAULT_MAX_CLONE_MB})",
    )
    p_clone.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit JSON"
    )

    p_analyze = sub.add_parser("analyze", help="Profile a cloned repository")
    p_analyze.add_argument("name", help="Workspace name: owner/repo or host/owner/repo")
    p_analyze.add_argument(
        "--json", action="store_true", dest="as_json", help="Emit JSON"
    )

    p_list = sub.add_parser("list", help="List workspaces")
    p_list.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON")

    p_clean = sub.add_parser(
        "clean", help=f"Remove workspaces unused for {STALE_AFTER_DAYS}+ days"
    )
    target = p_clean.add_mutually_exclusive_group()
    target.add_argument(
        "--older-than-days",
        type=int,
        default=STALE_AFTER_DAYS,
        help=f"Staleness threshold in days (default: {STALE_AFTER_DAYS})",
    )
    target.add_argument("--all", action="store_true", help="Remove every workspace")
    target.add_argument("--name", help="Remove one workspace by name")
    p_clean.add_argument(
        "--dry-run", action="store_true", help="Show what would be removed"
    )

    p.set_defaults(action="git")


def _emit(data: Any, as_json: bool, text: str) -> None:
    print(json.dumps(data, indent=2) if as_json else text)


def _handle_clone(args: argparse.Namespace) -> int:
    manager = WorkspaceManager(max_clone_mb=args.max_size_mb)
    record = manager.clone(args.url, depth=args.depth, branch=args.branch)
    verb = "Already cloned" if record["already_present"] else "Cloned"
    _emit(
        record,
        args.as_json,
        f"{verb} {record['name']} ({record['branch']} @ {record['head'][:10]}, "
        f"{record['size_mb']} MB)\n  {record['path']}\n"
        f"Next: gaia git analyze {record['name']}",
    )
    return EXIT_OK


def _format_profile(name: str, profile: Dict[str, Any]) -> str:
    langs = ", ".join(
        f"{lang['language']} {lang['percent']}%" for lang in profile["languages"]
    )
    lines = [
        name,
        f"  files        : {profile['total_files']}",
        f"  languages    : {langs or '(none detected)'}",
        f"  ecosystems   : {', '.join(profile['ecosystems']) or '-'}",
        f"  frameworks   : {', '.join(profile['frameworks']) or '-'}",
        f"  license      : {profile['license'] or '-'}",
        f"  tests / CI   : {profile['tests']['test_files']} test files, "
        f"{profile['ci']['github_workflows']} GitHub workflows",
    ]
    if profile["entry_points"]:
        lines.append("  entry points :")
        lines.extend(f"    - {e}" for e in profile["entry_points"])
    lines.append(
        "  top level    : " + ", ".join(e["name"] for e in profile["top_level"][:15])
    )
    if profile["manifest_errors"]:
        lines.append("  manifest errors:")
        lines.extend(f"    - {e}" for e in profile["manifest_errors"])
    return "\n".join(lines)


def _handle_analyze(args: argparse.Namespace) -> int:
    from gaia.git.analyzer import analyze_repository

    manager = WorkspaceManager()
    path = manager.resolve(args.name)
    files = manager.run_git(path, ["ls-files", "-z"]).split("\0")
    manager.touch(path)
    profile = analyze_repository(path, files)
    name = manager.name_of(path)
    _emit({"workspace": name, **profile}, args.as_json, _format_profile(name, profile))
    return EXIT_OK


def _handle_list(args: argparse.Namespace) -> int:
    manager = WorkspaceManager()
    workspaces = manager.list()
    if args.as_json:
        _emit(workspaces, True, "")
        return EXIT_OK
    if not workspaces:
        print(f"No workspaces under {manager.root}.")
        return EXIT_OK
    for ws in workspaces:
        flag = "  [stale]" if ws["stale"] else ""
        print(
            f"{ws['name']:<50} {ws['branch']:<20} {ws['size_mb']:>8} MB  "
            f"last used {ws['last_used_at'][:10]}{flag}"
        )
    return EXIT_OK


def _handle_clean(args: argparse.Namespace) -> int:
    manager = WorkspaceManager()
    prefix = "Would remove" if args.dry_run else "Removed"
    if args.name:
        if args.dry_run:
            print(f"{prefix} {manager.name_of(manager.resolve(args.name))}")
        else:
            print(f"{prefix} {manager.remove(args.name)}")
        return EXIT_OK
    removed = manager.clean(
        older_than_days=0 if args.all else args.older_than_days, dry_run=args.dry_run
    )
    if not removed:
        print("Nothing to clean.")
    for name in removed:
        print(f"{prefix} {name}")
    return EXIT_OK


def handle(args: argparse.Namespace) -> int:
    """Dispatch a parsed ``gaia git ...`` command. Returns an exit code."""
    handlers = {
        "clone": _handle_clone,
        "analyze": _handle_analyze,
        "list": _handle_list,
        "clean": _handle_clean,
    }
    action = getattr(args, "git_action", None)
    if action not in handlers:
        sys.stderr.write("gaia git: missing subcommand. Try 'gaia git --help'.\n")
        return EXIT_USAGE
    try:
        return handlers[action](args)
    except GitWorkspaceError as e:
        sys.stderr.write(f"gaia git {action}: {e}\n")
        return EXIT_ERROR
