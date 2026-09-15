# Web and input boundaries

Lane 3. Trace untrusted data from where it enters to where it is interpreted. Output candidates
only.

## Sources

Request parameters, headers, cookies, bodies, file names and contents, webhook payloads, queue
messages, and **stored** data that another user or system wrote. Second-order flows count: data
stored safely and later used unsafely is still injection.

## Sinks to trace

| Sink | Look for | Safe pattern |
|---|---|---|
| SQL / ORM / query filters | string-built queries, raw fragments, dynamic column or order names | parameters; allowlisted identifiers |
| Shell / process | `shell=True`, string commands, arguments starting with `-` | argument arrays; no shell; `--` separator |
| Templates / HTML / Markdown | unescaped output, `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, server-side template injection | context-aware auto-escaping; sanitizer for rich text |
| URLs and redirects | open redirect, `javascript:` links | allowlist of destinations or relative paths only |
| Deserialization | pickle, YAML full loaders, Java/.NET object streams on untrusted input | data-only formats with schema validation |
| Dynamic code | `eval`, `Function`, dynamic import/require from input | remove, or a fixed allowlist |
| Regex | attacker-controlled patterns or catastrophic backtracking | fixed patterns; linear-time engines; input limits |
| CI expressions | `${{ github.event.* }}` interpolated into `run:` | pass through environment variables |

A dangerous API is not a finding when every input reaching it is fixed or structurally
parameterized. Show the transformation chain and why encoding or parameterization does not hold.

## Web controls

- **CSRF:** state-changing requests authenticated by cookies need a token, `SameSite`, or origin
  check; confirm GET does not change state.
- **CORS:** a reflected `Origin` with credentials is a candidate; wildcard without credentials
  usually is not.
- **CSP and headers:** a weak CSP is hardening unless it enables a demonstrated XSS.
- **Clickjacking** matters only for sensitive one-click actions.

## SSRF and outbound requests

For any server-side fetch of a user-influenced URL:

- where is it validated, and is validation done **after** DNS resolution and on every redirect?
- are private, loopback, link-local and metadata ranges (IPv4 and IPv6) blocked?
- can alternate encodings, userinfo (`user@host`), or DNS rebinding bypass the check?
- does the response reach the attacker (full SSRF) or only timing and errors (blind)?

A URL parameter alone is not SSRF. Prove with a local mock endpoint. Never contact cloud metadata
services, internal production hosts or third-party systems.

## Files, paths and parsers

- **Path traversal:** normalize, then confirm the resolved path stays inside the intended root.
  Check symlinks and absolute-path joins.
- **Uploads:** content-type trust, extension checks, storage inside the web root, executable
  serving, missing size limits.
- **Archives:** zip-slip entry names, decompression size and file-count limits.
- **Parsers:** XML external entities, image and document libraries with known issues, parser
  subprocesses without time or memory limits.

Record sandboxing, size and time limits, and storage/execution separation as compensating
controls. Use inert fixture files only: no malware, decompression bombs or destructive payloads.

## Secrets and client exposure

- secrets committed to the repository, including history and example configs;
- server-only keys bundled into browser code or mobile apps;
- secrets written to logs, error messages, analytics or crash reports;
- environment flags that default to debug, permissive or fail-open in production.

Record the secret type and location, never its value. A committed secret remains exposed after
deletion until it is rotated.

## Dynamic proof

In `LOCAL` or authorized `STAGING` only: use minimal inert markers (a unique string, an inert DOM
attribute, a local callback server). No payload lists and no data extraction beyond
the marker.
