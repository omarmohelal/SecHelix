# Embedded engines

SecHelix keeps offensive engines behind explicit evidence and authorization
boundaries. Their source may live inside the SecHelix checkout for reproducible
installation, but their findings never become SecHelix verification verdicts.

## Strix

`engines/strix` is a pinned Git submodule of
`https://github.com/usestrix/strix`.

Pinned compatibility:

- package: `strix-agent`
- version: `1.6.2`
- upstream commit: `007ed1a94e7dbf7b096c81e5b0354533ce94e0db`
- license: Apache-2.0
- SecHelix contract: `strix-cli-v1`

The source is intentionally not copied and modified inline. The adapter in
`sechelix_runner/pentest/strix_adapter.py` remains the authority boundary so an
upstream update cannot silently change target scope, evidence semantics, or
verification status.

Use `git submodule update --init --recursive` or the full bootstrap script to
materialize the engine source.
