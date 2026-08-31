#!/usr/bin/env python3
"""Materialize the canonical explicit SecHelix catalog and frozen ID manifest."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.catalog import build_catalog, load_json, stable_json  # noqa: E402


CATALOG = ROOT / "catalog" / "checks.json"
MANIFEST = ROOT / "catalog" / "hypothesis-ids.txt"


def expected_outputs() -> tuple[str, str]:
    catalog = build_catalog(load_json(CATALOG))
    manifest = "\n".join(item["id"] for item in catalog["hypotheses"]) + "\n"
    return stable_json(catalog), manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if generated files are stale")
    args = parser.parse_args()
    catalog_text, manifest_text = expected_outputs()
    if args.check:
        stale = []
        if CATALOG.read_text(encoding="utf-8") != catalog_text:
            stale.append(str(CATALOG.relative_to(ROOT)))
        if not MANIFEST.exists() or MANIFEST.read_text(encoding="utf-8") != manifest_text:
            stale.append(str(MANIFEST.relative_to(ROOT)))
        if stale:
            print("Generated catalog artifacts are stale: " + ", ".join(stale))
            return 1
        print("OK: catalog and frozen 546-ID manifest are reproducible")
        return 0
    CATALOG.write_text(catalog_text, encoding="utf-8")
    MANIFEST.write_text(manifest_text, encoding="utf-8")
    print("Generated catalog/checks.json and catalog/hypothesis-ids.txt (546 hypotheses)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
