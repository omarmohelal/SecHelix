"""Fail-closed command builders for bounded local/staging dynamic scans."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .base import AdapterError


@dataclass(frozen=True)
class ScanContext:
    mode: str
    allowed_hosts: tuple[str, ...] = ()
    allowed_templates: tuple[str, ...] = ()


def _hostname(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise AdapterError("target must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise AdapterError("credentials must not be embedded in scan targets")
    return parsed.hostname.casefold().rstrip(".")


def _is_loopback(hostname: str) -> bool:
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def authorize_target(target: str, context: ScanContext) -> str:
    hostname = _hostname(target)
    mode = context.mode.casefold()
    if mode == "local":
        if not _is_loopback(hostname):
            raise AdapterError("local mode permits loopback targets only")
    elif mode == "staging":
        allowed = {host.casefold().rstrip(".") for host in context.allowed_hosts}
        if not allowed or hostname not in allowed:
            raise AdapterError("staging target is not explicitly allowlisted")
    else:
        raise AdapterError("only local and explicitly allowlisted staging modes are supported")
    return target


def zap_passive_command(target: str, report_path: str, context: ScanContext) -> list[str]:
    """Build a ZAP baseline (spider + passive rules) command; never an active scan."""
    authorize_target(target, context)
    if not report_path:
        raise AdapterError("a ZAP JSON report path is required")
    return [
        "zap-baseline.py",
        "-t",
        target,
        "-J",
        report_path,
    ]


def _authorized_templates(paths: Iterable[str], context: ScanContext) -> list[str]:
    allowlist = {str(Path(path).resolve()) for path in context.allowed_templates}
    selected: list[str] = []
    for raw_path in paths:
        if "://" in raw_path:
            raise AdapterError("remote Nuclei templates are not permitted")
        resolved = str(Path(raw_path).resolve())
        lowered = resolved.casefold()
        if resolved not in allowlist:
            raise AdapterError("Nuclei template is not explicitly allowlisted")
        if Path(resolved).suffix.casefold() not in {".yaml", ".yml"}:
            raise AdapterError("Nuclei templates must be explicit YAML files")
        if not Path(resolved).is_file():
            raise AdapterError("allowlisted Nuclei template does not exist")
        if any(token in lowered for token in ("dast", "fuzz", "headless", "code-protocol")):
            raise AdapterError("active or executable Nuclei template profiles are not permitted")
        selected.append(resolved)
    if not selected:
        raise AdapterError("at least one allowlisted Nuclei template is required")
    return selected


def nuclei_safe_command(
    target: str,
    templates: Iterable[str],
    report_path: str,
    context: ScanContext,
) -> list[str]:
    authorize_target(target, context)
    selected = _authorized_templates(templates, context)
    if not report_path:
        raise AdapterError("a Nuclei JSONL report path is required")
    command = [
        "nuclei",
        "-u",
        target,
        "-jsonl",
        "-o",
        report_path,
        "-rl",
        "5",
        "-c",
        "1",
        "-timeout",
        "5",
        "-retries",
        "0",
        "-disable-update-check",
    ]
    for template in selected:
        command.extend(["-t", template])
    return command
