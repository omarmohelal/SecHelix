# SecHelix MCP adapter

A local, stdio MCP server that gives a compatible agent the SecHelix runner's
operations directly. Seven tools, no shell, no network, and every path argument
confined to a root you choose.

## Install

```bash
uvx sechelix mcp .
```

or, with the package installed:

```bash
pipx install sechelix
sechelix mcp .
```

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "sechelix": {
      "command": "uvx",
      "args": ["sechelix", "mcp", "/absolute/path/to/the/repository"]
    }
  }
}
```

**Set the root to the repository you want reviewed, not to your home
directory.** The root is the security boundary: every path any tool receives is
resolved and refused if it lands outside. A wider root is a wider blast radius.

### In a container

```bash
docker build -t sechelix .
docker run --rm -i --network none -v "$PWD:/workspace" sechelix
```

Runs as uid 10001, installs exactly one package, and the base image is pinned by
digest. Two things worth knowing before adding `:ro`: `sechelix_audit` writes a
run workspace under the root, so a read-only mount leaves you the six read-only
tools and a failing audit; and `:ro` is enforced by the host's bind-mount
implementation rather than by the image — on Docker Desktop for Windows 29.6.2 a
write to a `:ro` bind mount succeeded when this was tested. The enforced
boundary is still the configured root.

## Tools

| Tool | Reads | Writes |
|---|---|---|
| `sechelix_doctor` | which components are available | — |
| `sechelix_audit` | the target tree | a run workspace under the root |
| `sechelix_run_status` | node statuses and workspace integrity | — |
| `sechelix_findings` | findings, plus why an empty list is empty | — |
| `sechelix_report` | markdown, json, sarif or html | — |
| `sechelix_coverage` | what previous runs did **not** examine | — |
| `sechelix_verify` | safe verification plans for a finding | — |

`sechelix_audit` is the only tool that writes anything, and only a run workspace
under the configured root. Nothing edits a finding, a status or a coverage
record.

## Three limits, and why

**Read-only by default.** An MCP client is driven by a model reading untrusted
content. The blast radius of a confused model should be a directory listing, not
a mutated audit trail.

**No arbitrary shell.** There is no `run_command` tool and no argument that
reaches a shell. An agent gets the operations SecHelix defines, not a terminal
wearing an MCP costume. A test asserts the adapter's source imports no
`subprocess` and that no tool name reads as command execution.

**Paths are confined.** `../../.ssh` will eventually be passed as a path
argument, because a model reading a hostile repository will eventually be told
to pass it. Resolution happens first and comparison second, so an absolute path,
a symlink and `a/../../..` are all caught rather than only the obvious spelling.

`sechelix_verify` deliberately returns verification *plans* and does not execute
one. Executing a proof needs authority an MCP client cannot grant on the
operator's behalf; returning the plan and the authority it would require is
honest, and quietly doing less while calling it verification is not.

## What an empty result means

`sechelix_findings` always returns `unsatisfied_mandatory` alongside the
findings. If it is non-empty, lanes were blocked and nothing was examined — an
empty finding list is not a statement that no vulnerabilities exist. The tool
says so in its own response rather than leaving the agent to infer it.

## Registry

Published to the official MCP Registry as `io.github.omarmohelal/sechelix`,
which several MCP directories re-publish from. The entry is verified two ways:
the `io.github.omarmohelal` namespace comes from a GitHub OIDC claim in
`.github/workflows/publish-mcp.yml`, and PyPI package ownership is proven by the
`mcp-name` token in the published package description.
