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

Use current, versioned releases of:

- OWASP Top 10
- OWASP API Security Top 10
- OWASP ASVS
- OWASP Testing Guide
- OWASP Cheat Sheet Series
- CWE / CAPEC where useful for classification
- NIST SARD and OWASP Benchmark for rights-reviewed vulnerable/clean evaluation fixtures
- NIST Secure Software Development Framework (SSDF)
- supply-chain guidance such as SLSA and ecosystem-native provenance/signing documentation

Machine-readable authority, licensing, allowed-use, and refresh policy lives in
`knowledge/source-registry.json`. Do not duplicate that policy in prose.

## Current vulnerability intelligence

Prefer subject-vendor advisories and exact version evidence, then cross-check:

- NVD: https://nvd.nist.gov/developers/vulnerabilities
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- OSV: https://osv.dev/
- GitHub Advisory Database: https://github.com/github/advisory-database

An aggregator can normalize a lead but cannot prove local reachability or impact.

## Restricted curriculum sources

PortSwigger Web Security Academy, TryHackMe, and Hack The Box are human-reference
links only under the current registry policy. Their official terms restrict forms
of autonomous access and/or AI dataset, grounding, training, evaluation, or
benchmark use. Do not crawl, copy, embed, train on, or benchmark against their
content without separate written permission. Use rights-cleared public standards,
datasets, and purpose-built local labs for machine workflows.

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

For current or unfamiliar claims, also create a versioned research packet, use at
least two independent reputable sources, record dates and exact versions, and
return to code/runtime evidence before promotion.

SecHelix is not a repository of copied exploit payloads. It is a verification methodology and structured hypothesis system.
