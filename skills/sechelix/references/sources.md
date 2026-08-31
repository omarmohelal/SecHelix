# Sources and standards

SecHelix should evolve from authoritative references and reproducible research rather than copied exploit lists.

## Agent Skills

- Agent Skills specification: https://agentskills.io/specification
- Agent Skills project: https://github.com/agentskills/agentskills
- Claude Code skills: https://code.claude.com/docs/en/slash-commands
- OpenAI skills overview: https://openai.com/academy/skills/
- OpenAI Skills API: https://developers.openai.com/api/reference/resources/skills
- Z.AI GLM Coding Plan / supported coding tools: https://docs.z.ai/devpack/quick-start

## Application security

Use current versions of:

- OWASP Top 10
- OWASP API Security Top 10
- OWASP ASVS
- OWASP Testing Guide
- OWASP Cheat Sheet Series
- CWE / CAPEC where useful for classification
- PortSwigger Web Security Academy for web vulnerability taxonomy and controlled lab methodology
- NIST Secure Software Development Framework (SSDF)
- supply-chain guidance such as SLSA and ecosystem-native provenance/signing documentation

## AI / agent security

Track evolving authoritative work on:

- MCP/tool authorization and trust boundaries;
- prompt/tool injection;
- untrusted tool output;
- agent identity and privilege;
- poisoned stored context;
- automatic side-effect controls;
- secret handling in agent runtimes.

Do not freeze SecHelix to a single model vendor's threat taxonomy.

## Source policy

When adding a new catalog family/lens or a new high-risk procedure:

1. cite the motivating standard/research/advisory;
2. translate it into a target-independent hypothesis;
3. define applicability and false-positive traps;
4. define safe evidence requirements;
5. add an eval/regression fixture when practical.

SecHelix is not a repository of copied exploit payloads. It is a verification methodology and structured hypothesis system.