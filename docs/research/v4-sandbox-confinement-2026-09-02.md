# V4 sandbox: real confinement evidence — 2026-09-02

The sandbox policy existed before this; execution did not. This records the
first time a container was actually started under `SandboxSpec` and probed.

## Result: 7/7 behaved as specified

Image `python:3.12-slim`, spec defaults, one writable workspace mount.

| Probe | Expected | Observed |
|---|---|---|
| write to `/workspace` | allowed | **allowed** (rc=0, file present on the host afterwards) |
| TCP to `1.1.1.1:53` | denied | **denied** (rc=1) |
| DNS `example.com` | denied | **denied** (rc=1) |
| `os.listdir('/host')` | denied | **denied** (rc=1) |
| write `/etc/evil` | denied | **denied** (rc=1, read-only root) |
| write `/usr/local/evil` | denied | **denied** (rc=1) |
| write `/tmp/t` | allowed | **allowed** (tmpfs, `noexec,nosuid,size=64m`) |

A hanging command was also killed by the timeout rather than running forever.

## The command actually issued

```
docker run --rm --memory=2g --cpus=2.0 --pids-limit=256
  --security-opt=no-new-privileges --read-only --cap-drop=ALL --network=none
  --volume=<workspace>:/workspace:rw --workdir /workspace
  --tmpfs /tmp:rw,noexec,nosuid,size=64m --user 1000:1000
  python:3.12-slim <argv>
```

No Kali. No `sudo`. No privileged mode. Not root inside the container. The
network is `none` rather than an optional named network that defaults to full
egress when unset — which is what the competitive audit found in `usestrix/strix`
and the reason this posture is written the way it is.

An unsafe spec is refused **before** a container starts: `privileged=True`,
`no_new_privileges=False`, or an empty capability drop each raise
`SandboxRefused` from `build_command`.

## Reproducing it

```bash
python -m pytest tests/runner/test_sandbox_exec.py -q
```

Eight of those tests start real containers and **skip cleanly when no container
runtime is available** — `STATIC` mode never needs Docker, so CI must not fail
for lacking something the product does not require.

That skip path was exercised for real: partway through this session the local
Docker Desktop engine began returning `500 Internal Server Error`, and the suite
went from `15 passed` to `7 passed, 8 skipped` without a single failure. The
container evidence in the table above was captured while the daemon was healthy;
it is recorded here because it is not reproducible on demand from a machine whose
Docker is down.

## What this does not claim

A container is **not** a security boundary this project would stake a customer
on. It is defence in depth around code that is already only reading files. What
it is genuinely good at is making the default safe: no network, no capabilities,
no writes outside one workspace, bounded processes and memory, and a non-root
user.
