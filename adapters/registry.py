"""Adapter registry with stable CLI names."""

from __future__ import annotations

from typing import Any, Callable

from . import gitleaks, nuclei, osv, package_audit, playwright, semgrep, trivy, zap
from .base import AdapterError
from .sarif import parse_codeql, parse_sarif


Parser = Callable[[Any], list[dict[str, Any]]]

ADAPTERS: dict[str, Parser] = {
    "semgrep": semgrep.parse,
    "codeql": parse_codeql,
    "sarif": parse_sarif,
    "osv": osv.parse,
    "trivy": trivy.parse,
    "gitleaks": gitleaks.parse,
    "npm-audit": package_audit.parse_npm,
    "pnpm-audit": package_audit.parse_pnpm,
    "playwright": playwright.parse,
    "zap": zap.parse,
    "nuclei": nuclei.parse,
}


def parse(adapter: str, payload: Any) -> list[dict[str, Any]]:
    try:
        parser = ADAPTERS[adapter.casefold()]
    except KeyError as exc:
        supported = ", ".join(sorted(ADAPTERS))
        raise AdapterError(f"unknown adapter {adapter!r}; choose one of: {supported}") from exc
    return parser(payload)
