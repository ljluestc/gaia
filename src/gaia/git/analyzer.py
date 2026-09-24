# Copyright(C) 2025-2026 Advanced Micro Devices, Inc. All rights reserved.
# SPDX-License-Identifier: MIT
"""Profile a checked-out repository: languages, stack, layout, key files.

Pure file inspection over ``git ls-files`` — nothing in the repository is
imported or executed, so analyzing an untrusted clone is safe.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on 3.10 only
    import tomli as tomllib

README_EXCERPT_CHARS = 2000
_MAX_MANIFEST_BYTES = 512 * 1024

_LANGUAGES = {
    ".py": "Python",
    ".pyi": "Python",
    ".js": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".rs": "Rust",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".scala": "Scala",
    ".c": "C",
    ".h": "C/C++ header",
    ".cc": "C++",
    ".cpp": "C++",
    ".cxx": "C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".m": "Objective-C",
    ".dart": "Dart",
    ".lua": "Lua",
    ".r": "R",
    ".jl": "Julia",
    ".ex": "Elixir",
    ".exs": "Elixir",
    ".erl": "Erlang",
    ".hs": "Haskell",
    ".clj": "Clojure",
    ".zig": "Zig",
    ".sh": "Shell",
    ".ps1": "PowerShell",
    ".vue": "Vue",
    ".svelte": "Svelte",
    ".html": "HTML",
    ".css": "CSS",
    ".scss": "SCSS",
    ".sql": "SQL",
    ".ipynb": "Jupyter Notebook",
}

#: Root-level manifest → ecosystem it implies.
_MANIFESTS = {
    "pyproject.toml": "Python",
    "setup.py": "Python",
    "setup.cfg": "Python",
    "requirements.txt": "Python",
    "Pipfile": "Python",
    "package.json": "Node.js",
    "Cargo.toml": "Rust",
    "go.mod": "Go",
    "pom.xml": "Java (Maven)",
    "build.gradle": "JVM (Gradle)",
    "build.gradle.kts": "JVM (Gradle)",
    "Gemfile": "Ruby",
    "composer.json": "PHP",
    "CMakeLists.txt": "C/C++ (CMake)",
    "meson.build": "C/C++ (Meson)",
    "Package.swift": "Swift",
    "pubspec.yaml": "Dart/Flutter",
    "mix.exs": "Elixir",
    "Dockerfile": "Docker",
    "docker-compose.yml": "Docker Compose",
    "docker-compose.yaml": "Docker Compose",
    "Makefile": "Make",
}

#: Dependency name (lower-case) → framework or notable library it indicates.
_FRAMEWORKS = {
    # Python
    "django": "Django",
    "flask": "Flask",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "torch": "PyTorch",
    "tensorflow": "TensorFlow",
    "jax": "JAX",
    "transformers": "Hugging Face Transformers",
    "numpy": "NumPy",
    "pandas": "pandas",
    "scikit-learn": "scikit-learn",
    "langchain": "LangChain",
    "pytest": "pytest",
    "click": "Click",
    "typer": "Typer",
    "sqlalchemy": "SQLAlchemy",
    "pydantic": "Pydantic",
    # Node
    "react": "React",
    "next": "Next.js",
    "vue": "Vue",
    "nuxt": "Nuxt",
    "svelte": "Svelte",
    "@angular/core": "Angular",
    "express": "Express",
    "fastify": "Fastify",
    "@nestjs/core": "NestJS",
    "electron": "Electron",
    "vite": "Vite",
    "webpack": "webpack",
    "typescript": "TypeScript",
    "jest": "Jest",
    "vitest": "Vitest",
    "tailwindcss": "Tailwind CSS",
    # Rust
    "tokio": "Tokio",
    "actix-web": "Actix Web",
    "axum": "Axum",
    "serde": "Serde",
    "clap": "clap",
    "bevy": "Bevy",
    # Go
    "github.com/gin-gonic/gin": "Gin",
    "github.com/labstack/echo/v4": "Echo",
    "github.com/spf13/cobra": "Cobra",
    "google.golang.org/grpc": "gRPC",
    "k8s.io/client-go": "Kubernetes client-go",
}

_KEY_FILE_PATTERNS = (
    re.compile(r"^readme(\.[a-z]+)?$", re.I),
    re.compile(r"^license(\.[a-z]+)?$|^copying$", re.I),
    re.compile(r"^contributing(\.[a-z]+)?$", re.I),
    re.compile(
        r"^changelog(\.[a-z]+)?$|^changes(\.[a-z]+)?$|^history(\.[a-z]+)?$", re.I
    ),
    re.compile(r"^security(\.[a-z]+)?$", re.I),
    re.compile(r"^code_of_conduct(\.[a-z]+)?$", re.I),
    re.compile(r"^agents\.md$|^claude\.md$", re.I),
)

_TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|spec)(/|$)|(^|/)test_[^/]+\.py$|_test\.(py|go)$|\.(test|spec)\.[jt]sx?$"
)

_LICENSES = (
    ("MIT License", "MIT"),
    ("Apache License", "Apache-2.0"),
    ("GNU AFFERO GENERAL PUBLIC LICENSE", "AGPL-3.0"),
    ("GNU LESSER GENERAL PUBLIC LICENSE", "LGPL"),
    ("GNU GENERAL PUBLIC LICENSE", "GPL"),
    ("Mozilla Public License", "MPL-2.0"),
    ("BSD 3-Clause", "BSD-3-Clause"),
    ("Redistribution and use in source and binary forms", "BSD"),
    ("The Unlicense", "Unlicense"),
    ("This is free and unencumbered software", "Unlicense"),
)


def analyze_repository(root: Path, files: Iterable[str]) -> Dict[str, Any]:
    """Build a profile of the repository at *root*.

    Args:
        root: The checkout directory.
        files: Tracked paths relative to *root*, POSIX separators
            (``git ls-files`` output).
    """
    tracked = sorted({f for f in files if f})
    languages = _languages(tracked)
    root_files = {f for f in tracked if "/" not in f}
    manifests = sorted(f for f in root_files if f in _MANIFESTS)

    errors: List[str] = []
    deps = _dependencies(root, root_files, errors)
    entry_points = _entry_points(root, tracked, root_files, errors)
    frameworks = sorted({_FRAMEWORKS[d] for d in deps if d in _FRAMEWORKS})

    ecosystems = sorted({_MANIFESTS[m] for m in manifests})
    key_files = sorted(
        f for f in root_files if any(p.match(f) for p in _KEY_FILE_PATTERNS)
    )
    workflows = [
        f
        for f in tracked
        if f.startswith(".github/workflows/") and f.endswith((".yml", ".yaml"))
    ]
    test_files = [f for f in tracked if _TEST_PATH_RE.search(f)]

    return {
        "total_files": len(tracked),
        "primary_language": languages[0]["language"] if languages else None,
        "languages": languages,
        "ecosystems": ecosystems,
        "manifests": manifests,
        "frameworks": frameworks,
        "entry_points": entry_points,
        "key_files": key_files,
        "license": _license(root, key_files),
        "top_level": _top_level(tracked),
        "tests": {"test_files": len(test_files), "examples": test_files[:5]},
        "ci": {"github_workflows": len(workflows), "examples": workflows[:5]},
        "has_docs_dir": any(f.startswith(("docs/", "doc/")) for f in tracked),
        "readme_excerpt": _readme_excerpt(root, key_files),
        "manifest_errors": sorted(set(errors)),
    }


def _languages(tracked: List[str]) -> List[Dict[str, Any]]:
    counts = Counter(
        _LANGUAGES[PurePosixPath(f).suffix.lower()]
        for f in tracked
        if PurePosixPath(f).suffix.lower() in _LANGUAGES
    )
    total = sum(counts.values())
    return [
        {"language": lang, "files": n, "percent": round(100 * n / total, 1)}
        for lang, n in counts.most_common(8)
    ]


def _top_level(tracked: List[str]) -> List[Dict[str, Any]]:
    entries: Counter = Counter()
    for f in tracked:
        head = f.split("/", 1)[0]
        entries[head + ("/" if "/" in f else "")] += 1
    dirs = sorted(
        (e for e in entries if e.endswith("/")), key=lambda e: (-entries[e], e)
    )
    files = sorted(e for e in entries if not e.endswith("/"))
    return [{"name": d, "files": entries[d]} for d in dirs[:25]] + [
        {"name": f, "files": 1} for f in files[:25]
    ]


def _read_text(path: Path) -> Optional[str]:
    """Read a small regular file inside the checkout; ``None`` if absent or too big."""
    if (
        not path.is_file()
        or path.is_symlink()
        or path.stat().st_size > _MAX_MANIFEST_BYTES
    ):
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _read_toml(path: Path, errors: List[str]) -> Dict[str, Any]:
    """Parse a TOML manifest; a broken one is recorded in *errors*, not raised.

    A malformed manifest is a finding about the repository, reported in the
    profile's ``manifest_errors`` — not a reason to refuse the whole analysis.
    """
    text = _read_text(path)
    if text is None:
        return {}
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        errors.append(f"{path.name}: {e}")
        return {}


def _read_json(path: Path, errors: List[str]) -> Dict[str, Any]:
    text = _read_text(path)
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        errors.append(f"{path.name}: {e}")
        return {}
    return data if isinstance(data, dict) else {}


_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def _req_name(spec: str) -> Optional[str]:
    match = _REQ_NAME_RE.match(spec)
    return match.group(1).lower().replace("_", "-") if match else None


def _dependencies(root: Path, root_files: set, errors: List[str]) -> set:
    deps: set = set()
    if "pyproject.toml" in root_files:
        project = _read_toml(root / "pyproject.toml", errors)
        specs = list(project.get("project", {}).get("dependencies", []) or [])
        for group in (
            project.get("project", {}).get("optional-dependencies", {}) or {}
        ).values():
            specs.extend(group or [])
        deps.update(filter(None, (_req_name(s) for s in specs if isinstance(s, str))))
        poetry = project.get("tool", {}).get("poetry", {})
        for key in ("dependencies", "dev-dependencies"):
            deps.update(str(k).lower() for k in (poetry.get(key) or {}))
    if "requirements.txt" in root_files:
        text = _read_text(root / "requirements.txt") or ""
        deps.update(
            filter(
                None,
                (
                    _req_name(line)
                    for line in text.splitlines()
                    if not line.lstrip().startswith(("#", "-"))
                ),
            )
        )
    if "package.json" in root_files:
        pkg = _read_json(root / "package.json", errors)
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            section = pkg.get(key)
            if isinstance(section, dict):
                deps.update(str(k).lower() for k in section)
    if "Cargo.toml" in root_files:
        cargo = _read_toml(root / "Cargo.toml", errors)
        for key in ("dependencies", "dev-dependencies"):
            deps.update(str(k).lower() for k in (cargo.get(key) or {}))
        deps.update(
            str(k).lower()
            for k in (cargo.get("workspace", {}).get("dependencies") or {})
        )
    if "go.mod" in root_files:
        text = _read_text(root / "go.mod") or ""
        deps.update(
            m.group(1).lower()
            for m in re.finditer(
                r"^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+/\S+)\s+v", text, re.M
            )
        )
    return deps


def _entry_points(
    root: Path, tracked: List[str], root_files: set, errors: List[str]
) -> List[str]:
    found: List[str] = []
    if "pyproject.toml" in root_files:
        project = _read_toml(root / "pyproject.toml", errors)
        for name, target in (project.get("project", {}).get("scripts") or {}).items():
            found.append(f"console script `{name}` -> {target}")
    if "package.json" in root_files:
        pkg = _read_json(root / "package.json", errors)
        if isinstance(pkg.get("main"), str):
            found.append(f"package main: {pkg['main']}")
        bins = pkg.get("bin")
        if isinstance(bins, str):
            found.append(f"bin: {bins}")
        elif isinstance(bins, dict):
            found.extend(f"bin `{k}` -> {v}" for k, v in bins.items())
        scripts = pkg.get("scripts")
        if isinstance(scripts, dict):
            found.extend(f"npm run {k}" for k in list(scripts)[:8])
    conventional = (
        "main.py",
        "__main__.py",
        "app.py",
        "manage.py",
        "src/main.rs",
        "src/lib.rs",
        "main.go",
        "index.js",
        "src/index.ts",
        "src/main.ts",
    )
    found.extend(f for f in conventional if f in tracked)
    found.extend(
        sorted(
            {
                "/".join(f.split("/")[:2]) + "/"
                for f in tracked
                if f.startswith("cmd/") and f.endswith("/main.go")
            }
        )
    )
    return found[:20]


def _license(root: Path, key_files: List[str]) -> Optional[str]:
    for name in key_files:
        if re.match(r"^(license|copying)", name, re.I):
            head = (_read_text(root / name) or "")[:1500]
            for marker, spdx in _LICENSES:
                if marker.lower() in head.lower():
                    return spdx
            return f"unrecognized (see {name})"
    return None


def _readme_excerpt(root: Path, key_files: List[str]) -> str:
    for name in key_files:
        if name.lower().startswith("readme"):
            text = _read_text(root / name) or ""
            return text[:README_EXCERPT_CHARS]
    return ""
