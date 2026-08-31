# Getting started

## 1. Choose a target you are authorized to review

Start with a repository you own or a local demo application. SecHelix is designed for authorized AppSec, not third-party target scanning.

## 2. Install the skill

### Claude Code

```bash
mkdir -p .claude/skills/sechelix
cp -R /path/to/SecHelix/skills/sechelix/* .claude/skills/sechelix/
```

Or keep SecHelix in the target repository and use the included `.claude/skills/sechelix/` adapter.

### OpenAI / Codex

Use `skills/sechelix/` as the portable skill directory or package that folder as the skill bundle accepted by your OpenAI skills-capable workflow. The repository also includes `.codex/skills/sechelix/` as a local adapter.

### Z.AI / GLM

Z.AI documents GLM Coding Plan support through coding-agent hosts including Claude Code and other tools. If GLM is running through Claude Code, use the Claude installation path. For another host, use the portable bundle and that host's skill loader.

## 3. First audit prompt

```text
Run a SecHelix security audit on this authorized repository.
Mode: STATIC first; use LOCAL only if the local app/test fixtures are safe and available.
Map the architecture and trust boundaries before selecting checks.
Do not spray all hypotheses.
Independently verify every High/Critical candidate before reporting it.
For verified findings, propose the canonical root-cause fix and a regression test.
```

## 4. Expected output

A useful SecHelix audit should contain:

- scope and mode;
- architecture/trust-boundary map;
- role × object × action matrix where relevant;
- applicability summary;
- verified findings;
- rejected false positives;
- blocked/unknown evidence;
- recommended fixes;
- regression proof;
- release recommendation.

## 5. Use scanners as evidence sources

You can add Semgrep, CodeQL, dependency scanners, browser automation, database tests, and other tools. Their alerts remain hypotheses until verified.

## 6. Start small

For company adoption, review one service first and measure:

- verified findings;
- false-positive rejection rate;
- missed issues from human review;
- time to verification;
- model/tool cost;
- regression coverage added.

Then expand coverage and policy.