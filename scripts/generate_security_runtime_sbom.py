#!/usr/bin/env python3
"""Generate a deterministic CycloneDX 1.5 SBOM for the V5 security runtime.

This inventory is derived only from repository-controlled provenance:
- the digest-pinned Python base image in runtime-lock.json;
- every exact Python package/version and SHA-256 artifact set in python-tools.lock;
- the SHA-256 pinned Gitleaks and Trivy release assets.

It does not query a registry, vulnerability database, or package index, and it
does not claim that an unpublished image has registry provenance or a signature.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
import uuid
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "containers" / "security-runtime"
DEFAULT_RUNTIME_LOCK = RUNTIME_DIR / "runtime-lock.json"
DEFAULT_PYTHON_LOCK = RUNTIME_DIR / "python-tools.lock"
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "security-runtime.sbom.sechelix.com")
REQ = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)\s*\\?$")
SHA_LINE = re.compile(r"--hash=sha256:([0-9a-f]{64})")


class RuntimeSbomError(ValueError):
    """The repository provenance inputs are malformed or contradictory."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _timestamp() -> str:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw and raw.isdigit():
        moment = dt.datetime.fromtimestamp(int(raw), tz=dt.timezone.utc)
    else:
        moment = dt.datetime.now(tz=dt.timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_python_lock(path: Path) -> list[dict[str, object]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    starts: list[tuple[int, str, str]] = []
    for index, raw in enumerate(lines):
        if not raw.strip() or raw.startswith((" ", "#")):
            continue
        match = REQ.fullmatch(raw.strip())
        if match is None:
            raise RuntimeSbomError(f"non-exact Python lock entry: {raw!r}")
        starts.append((index, _pypi_name(match.group(1)), match.group(2)))

    if not starts:
        raise RuntimeSbomError("Python lock contains no packages")

    components: list[dict[str, object]] = []
    for offset, (index, name, version) in enumerate(starts):
        stop = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        stanza = "\n".join(lines[index:stop])
        hashes = sorted(set(SHA_LINE.findall(stanza)))
        if not hashes:
            raise RuntimeSbomError(f"{name}=={version} has no SHA-256 artifact hashes")
        components.append(
            {
                "type": "library",
                "bom-ref": f"pkg:pypi/{name}@{version}",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name}@{version}",
                "scope": "required",
                "properties": [
                    {"name": "sechelix:pinning", "value": "sha256-python-lock"},
                    {
                        "name": "sechelix:artifactSha256Set",
                        "value": ",".join(hashes),
                    },
                ],
            }
        )
    return components


def _base_component(lock: dict[str, object]) -> dict[str, object]:
    base = lock.get("base_image")
    if not isinstance(base, dict):
        raise RuntimeSbomError("runtime lock is missing base_image")
    reference = str(base.get("reference") or "")
    digest = str(base.get("index_sha256") or "")
    if not reference or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise RuntimeSbomError("base image reference/digest is malformed")
    if f"@sha256:{digest}" not in reference:
        raise RuntimeSbomError("base image reference does not match index digest")
    return {
        "type": "container",
        "bom-ref": f"oci:base@sha256:{digest}",
        "name": "python-base-image",
        "version": reference.split("@", 1)[0],
        "scope": "required",
        "properties": [
            {"name": "sechelix:ociReference", "value": reference},
            {"name": "sechelix:indexSha256", "value": digest},
            {"name": "sechelix:pinning", "value": "oci-index-digest"},
        ],
    }


def _binary_components(lock: dict[str, object]) -> list[dict[str, object]]:
    binary = lock.get("binary_tools")
    if not isinstance(binary, dict):
        raise RuntimeSbomError("runtime lock is missing binary_tools")
    output: list[dict[str, object]] = []
    for name in sorted(binary):
        item = binary[name]
        if not isinstance(item, dict):
            raise RuntimeSbomError(f"binary tool {name!r} is malformed")
        version = str(item.get("version") or "")
        release = str(item.get("release") or "")
        assets = item.get("assets")
        if not version or not isinstance(assets, dict) or not assets:
            raise RuntimeSbomError(f"binary tool {name!r} lacks version/assets")
        properties = [{"name": "sechelix:pinning", "value": "sha256-release-asset"}]
        for arch in sorted(assets):
            asset = assets[arch]
            if not isinstance(asset, dict):
                raise RuntimeSbomError(f"{name}/{arch} asset is malformed")
            digest = str(asset.get("sha256") or "")
            filename = str(asset.get("filename") or "")
            if not filename or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise RuntimeSbomError(f"{name}/{arch} asset digest is malformed")
            properties.extend(
                [
                    {"name": f"sechelix:asset:{arch}:filename", "value": filename},
                    {"name": f"sechelix:asset:{arch}:sha256", "value": digest},
                ]
            )
        component: dict[str, object] = {
            "type": "application",
            "bom-ref": f"tool:{name}@{version}",
            "name": name,
            "version": version,
            "scope": "required",
            "properties": properties,
        }
        if release:
            component["externalReferences"] = [{"type": "distribution", "url": release}]
        output.append(component)
    return output


def build_bom(
    runtime_lock_path: Path = DEFAULT_RUNTIME_LOCK,
    python_lock_path: Path = DEFAULT_PYTHON_LOCK,
) -> dict[str, object]:
    try:
        lock = json.loads(runtime_lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeSbomError(f"cannot read runtime lock: {exc}") from exc
    if not isinstance(lock, dict):
        raise RuntimeSbomError("runtime lock must be a JSON object")

    python_components = parse_python_lock(python_lock_path)
    base = _base_component(lock)
    binaries = _binary_components(lock)
    components = [base, *python_components, *binaries]
    refs = [str(item["bom-ref"]) for item in components]

    input_digest = hashlib.sha256()
    for path in (runtime_lock_path, python_lock_path):
        input_digest.update(path.name.encode("utf-8"))
        input_digest.update(b"\0")
        input_digest.update(path.read_bytes())
        input_digest.update(b"\0")
    provenance_digest = input_digest.hexdigest()
    serial = uuid.uuid5(NAMESPACE, provenance_digest)
    root_ref = "sechelix:security-runtime:v5"

    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "generate_security_runtime_sbom.py",
                        "version": "1",
                    }
                ]
            },
            "component": {
                "type": "container",
                "bom-ref": root_ref,
                "name": "sechelix-security-runtime",
                "version": "v5",
                "properties": [
                    {
                        "name": "sechelix:runtimeLockSha256",
                        "value": _sha256(runtime_lock_path),
                    },
                    {
                        "name": "sechelix:pythonLockSha256",
                        "value": _sha256(python_lock_path),
                    },
                    {
                        "name": "sechelix:inventoryBasis",
                        "value": "repository-locks-not-registry-observation",
                    },
                    {
                        "name": "sechelix:publishedImageProvenance",
                        "value": "NOT_MEASURED",
                    },
                ],
            },
        },
        "components": components,
        "dependencies": [
            {"ref": root_ref, "dependsOn": sorted(refs)},
            *[{"ref": ref, "dependsOn": []} for ref in sorted(refs)],
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-lock", type=Path, default=DEFAULT_RUNTIME_LOCK)
    parser.add_argument("--python-lock", type=Path, default=DEFAULT_PYTHON_LOCK)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    try:
        bom = build_bom(args.runtime_lock, args.python_lock)
    except RuntimeSbomError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    payload = json.dumps(bom, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output is None:
        sys.stdout.write(payload)
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")

    if not args.quiet:
        print(
            f"OK: security-runtime CycloneDX 1.5 SBOM "
            f"({len(bom['components'])} components)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
