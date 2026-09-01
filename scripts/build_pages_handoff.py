#!/usr/bin/env python3
"""Build the source-free GitHub Pages handoff to the private SecHelix site."""

from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_ORIGIN = "https://sechelix.magnoumx.chatgpt.site"
ROUTES = ("", "docs", "contribute", "support")


def validate_origin(value: str) -> str:
    origin = value.rstrip("/")
    parsed = urlparse(origin)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("origin must be an HTTPS origin without a path, query, or fragment")
    return origin


def redirect_document(origin: str, route: str) -> str:
    path = f"/{route}" if route else "/"
    target = f"{origin}{path}"
    safe_target = html.escape(target, quote=True)
    target_json = json.dumps(target)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <meta http-equiv="refresh" content="0;url={safe_target}">
  <link rel="canonical" href="{safe_target}">
  <title>SecHelix — opening the official site</title>
  <style>
    :root {{ color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
    body {{ display:grid; min-height:100vh; margin:0; place-items:center; background:#050a0d; color:#9fb3bf; }}
    a {{ color:#62d9ff; }}
  </style>
  <script>window.location.replace({target_json} + window.location.search + window.location.hash);</script>
</head>
<body>
  <p>Opening the current SecHelix site… <a href="{safe_target}">Continue</a></p>
</body>
</html>
"""


def not_found_document(origin: str) -> str:
    origin_json = json.dumps(origin)
    routes_json = json.dumps(list(ROUTES))
    fallback = html.escape(origin, quote=True)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
  <title>SecHelix — opening the official site</title>
  <style>
    :root {{ color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }}
    body {{ display:grid; min-height:100vh; margin:0; place-items:center; background:#050a0d; color:#9fb3bf; }}
    a {{ color:#62d9ff; }}
  </style>
  <script>
    (() => {{
      const origin = {origin_json};
      const allowed = new Set({routes_json});
      const prefix = "/SecHelix";
      let raw = window.location.pathname.startsWith(prefix)
        ? window.location.pathname.slice(prefix.length)
        : window.location.pathname;
      raw = raw.endsWith(".html") ? raw.slice(0, -5) : raw;
      raw = raw.split("/").filter(Boolean).join("/");
      const route = allowed.has(raw) ? raw : "";
      window.location.replace(origin + (route ? "/" + route : "/") + window.location.search + window.location.hash);
    }})();
  </script>
</head>
<body>
  <p>Opening the current SecHelix site… <a href="{fallback}">Continue</a></p>
</body>
</html>
"""


def build(output: Path, origin: str) -> None:
    output.mkdir(parents=True, exist_ok=True)
    for route in ROUTES:
        document = redirect_document(origin, route)
        if route:
            (output / route).mkdir(parents=True, exist_ok=True)
            (output / route / "index.html").write_text(document, encoding="utf-8")
            (output / f"{route}.html").write_text(document, encoding="utf-8")
        else:
            (output / "index.html").write_text(document, encoding="utf-8")
    (output / "404.html").write_text(not_found_document(origin), encoding="utf-8")
    (output / ".nojekyll").write_text("", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.output, validate_origin(args.origin))
    print(f"Built GitHub Pages handoff for {validate_origin(args.origin)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
