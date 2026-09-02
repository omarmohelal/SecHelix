"""Building the target picture, offline.

Everything here reads the filesystem and nothing else. No network, no model, no
subprocess beyond ``git`` for identity. That is what lets ``sechelix audit .``
be useful with zero connectivity and what makes STATIC a real default rather
than a marketing word.

**This module observes; it does not conclude.** It reports that a manifest
exists, that a path looks like a route file, that a name matches a sink pattern.
It never says a sink is reachable or a route is unauthenticated -- those are
questions for a reasoner with evidence, and a filesystem walk that answered them
would be a keyword scanner wearing an audit's clothes.

Slices that cannot be established are simply absent, and their absence is what
the context builder turns into a recorded ``missing_required`` on the affected
node. A lane whose inputs do not exist is never routed into the graph, and the
run says so.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

#: How much of the tree to walk. Depth changes breadth of observation, never
#: the honesty of what is reported.
DEPTHS = {"quick": 400, "standard": 4000, "thorough": 40000}

_SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", ".nuxt", "target", "vendor", ".sechelix",
        ".mypy_cache", ".pytest_cache", ".tox", "coverage", ".idea", ".vscode",
    }
)

_MANIFESTS = {
    "package.json", "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
    "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "Gemfile", "composer.json", "mix.exs", "pubspec.yaml",
}
_LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
    "requirements.lock", "uv.lock",
}
_CONFIG_NAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml", ".env.example",
    "nginx.conf", "terraform.tf", "main.tf", "serverless.yml", "vercel.json",
    "netlify.toml", "wrangler.toml", "app.yaml", "web.config",
}
_NATIVE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".rs"}
_CLIENT_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".svelte", ".vue", ".html"}

#: Filename fragments that suggest a slice is present. Deliberately coarse: this
#: decides whether to *ask* a specialist, never what the answer is.
_HINTS: dict[str, tuple[str, ...]] = {
    "routes": ("route", "router", "urls", "endpoint", "controller", "handler", "api", "views"),
    "auth_middleware": ("auth", "middleware", "guard", "permission", "session", "login"),
    "identities": ("user", "account", "identity", "principal", "member", "tenant"),
    "roles": ("role", "permission", "policy", "rbac", "scope", "grant"),
    "ownership_model": ("model", "schema", "entity", "orm", "migration"),
    "state_machines": ("state", "status", "workflow", "saga", "transition", "order"),
    "mutating_routes": ("create", "update", "delete", "post", "put", "patch", "mutation"),
    "sinks": ("query", "exec", "eval", "render", "template", "shell", "command", "sql"),
    "sources": ("request", "input", "param", "body", "query", "form", "upload"),
    "parsers": ("parse", "decode", "deserial", "unmarshal", "xml", "yaml", "zip", "upload"),
    "ai_inventory": ("llm", "openai", "anthropic", "prompt", "agent", "mcp", "embedding"),
}


def describe_target(root: Path) -> dict[str, str]:
    """Stable identity for the audited tree.

    The commit is what binds coverage across runs, so a tree that is not a git
    repository gets ``UNKNOWN`` rather than a fabricated identifier.
    """
    def _git(*args: str) -> str | None:
        """Run a git query, returning None unless it genuinely succeeded.

        The return code is checked rather than just the output: outside a
        repository ``git rev-parse HEAD`` exits non-zero but echoes the literal
        string ``HEAD`` on stdout, and trusting stdout alone would record
        ``HEAD`` as this target's commit id.
        """
        try:
            out = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
        return out.stdout.strip() or None

    commit = _git("rev-parse", "HEAD") or "UNKNOWN"
    return {
        "root": str(root),
        "name": root.name,
        "commit": commit,
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD") or "UNKNOWN",
        "origin": _git("config", "--get", "remote.origin.url") or "UNKNOWN",
        "scope_id": f"SCOPE-{root.name.upper()}",
    }


def walk_files(root: Path, limit: int) -> list[str]:
    """Repository-relative paths, skipping vendored and generated trees."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".git"))
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            found.append(rel)
            if len(found) >= limit:
                return found
    return found


def _matching(files: list[str], hints: tuple[str, ...]) -> list[str]:
    lowered = [(f, f.lower()) for f in files]
    return [f for f, low in lowered if any(h in low for h in hints)]


def build_world(root: Path | str, *, depth: str = "standard") -> dict[str, Any]:
    """Assemble the observable world for a target.

    Only slices with actual evidence are included. An empty list would claim
    "looked and found none"; absence claims nothing, and the runner turns it
    into a routing decision instead of an answer.
    """
    root = Path(root)
    limit = DEPTHS.get(depth, DEPTHS["standard"])
    files = walk_files(root, limit)
    world: dict[str, Any] = {
        "target": describe_target(root),
        "file_index": files,
        "depth": depth,
        "file_count": len(files),
        "truncated": len(files) >= limit,
    }

    basenames = {f.rsplit("/", 1)[-1] for f in files}
    lower_basenames = {b.lower() for b in basenames}

    manifests = sorted(f for f in files if f.rsplit("/", 1)[-1] in _MANIFESTS)
    lockfiles = sorted(f for f in files if f.rsplit("/", 1)[-1] in _LOCKFILES)
    configs = sorted(f for f in files if f.rsplit("/", 1)[-1].lower() in _CONFIG_NAMES)
    if manifests:
        world["manifests"] = manifests
    if lockfiles:
        world["lockfiles"] = lockfiles
    if configs:
        world["config_files"] = configs

    for key, hints in _HINTS.items():
        matched = _matching(files, hints)
        if matched:
            world[key] = matched[:200]

    client = [f for f in files if Path(f).suffix.lower() in _CLIENT_SUFFIXES]
    if client:
        world["client_entrypoints"] = client[:200]

    native = [f for f in files if Path(f).suffix.lower() in _NATIVE_SUFFIXES]
    if native:
        world["native_sources"] = native[:200]

    # Slices no filesystem walk can establish. They are absent rather than
    # empty so a node that needs them is BLOCKED with the reason recorded,
    # instead of answering from nothing.
    #   candidates       - produced by specialist lanes during the run
    #   runtime_traces   - require a runtime observation that STATIC never makes
    #   verified_findings, patches - produced downstream
    world["findings"] = []
    world["node_records"] = []
    return world
