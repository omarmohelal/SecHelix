# Getting help

Use the shortest path for what you need:

| You want to... | Go to |
|---|---|
| Install or run SecHelix | [README](README.md) |
| Copy a security-review workflow | [Command Cookbook](docs/COMMANDS.md) |
| Use the optional runtime | [V4 Runtime Quickstart](docs/v4-quickstart.md) |
| Check agent/client compatibility | [Compatibility](docs/reference/compatibility.md) |
| Report a false positive | [False-positive issue](https://github.com/omarmohelal/SecHelix/issues/new?template=false-positive.yml) |
| Report a normal bug | [Bug report](https://github.com/omarmohelal/SecHelix/issues/new?template=bug.yml) |
| Ask a question | [GitHub Discussions](https://github.com/omarmohelal/SecHelix/discussions) |
| Report a vulnerability in SecHelix | [SECURITY.md](SECURITY.md) |

## Before posting publicly

Do not paste credentials, private source code, customer data, internal hostnames, private evidence, or other sensitive material into an issue or Discussion.

If the problem is a vulnerability in a third-party system, use that project's responsible-disclosure process instead of opening a public SecHelix issue about it.

## Reporting a false positive

False positives are especially useful because SecHelix is designed to verify candidates before treating them as findings.

Please include:

- what SecHelix claimed;
- the smallest shareable reproduction;
- why the claim is wrong or unreachable;
- the compensating control, framework behavior, or missing attacker capability that refutes it;
- the related finding or hypothesis ID when available.

A synthetic/redacted example is usually better than real private code.

## Reporting a bug

Include:

- how you installed SecHelix;
- the agent/client or CLI command you used;
- the expected behavior;
- the actual behavior;
- a minimal reproduction when possible.

For CLI/runtime problems, `sechelix doctor --json` can provide useful environment information without requiring a full audit.

## Security terminology

The important status vocabularies and report contracts are defined in the repository schemas and reference docs. If a run lacks required evidence, SecHelix is designed to fail closed rather than silently turn uncertainty into a clean result.

## Response expectations

This is an open-source project maintained on a best-effort basis. There is no support SLA. Security reports sent through the process in [SECURITY.md](SECURITY.md) take priority.
