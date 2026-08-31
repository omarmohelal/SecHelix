# SecHelix launch / discovery playbook

The goal is discoverability without spam or fake credibility.

## Positioning

Primary one-liner:

> SecHelix is evidence-first multi-agent AppSec: 546 structured security hypotheses, independent verification, root-cause fixes, and release proof for AI coding agents.

Short tagline:

> Verify before you accuse.

## Search language

Use these phrases naturally in README/docs/site rather than keyword stuffing:

- Agent Skills security audit
- Claude Code security skill
- OpenAI Codex security skill
- AI AppSec workflow
- multi-agent security review
- business logic vulnerability review
- authorization BOLA BFLA testing
- race condition idempotency audit
- MCP agent security
- evidence-first security scanner orchestration
- application security release gate

## Suggested GitHub topics

`agent-skills`, `appsec`, `cybersecurity`, `security-audit`, `claude-code`, `codex`, `glm`, `owasp`, `devsecops`, `security-testing`, `ai-security`, `mcp`, `sast`, `business-logic`, `race-condition`

## Launch post — GitHub / Hacker News style

**Title:** SecHelix — an evidence-first security skill for AI coding agents

**Body:**

I built SecHelix around a problem I kept seeing with AI security review: finding more suspicious code is easy; producing findings engineers trust is much harder.

SecHelix uses a portable Agent Skills workflow with 21 security families × 26 verification lenses (546 structured hypothesis slots). It maps the system first, selects only applicable checks, can split review across specialist agents/models, and sends High/Critical candidates to an independent verifier before they are promoted.

Business logic, race conditions, exact-once behavior, payouts/refunds/inventory and AI/MCP tool boundaries are first-class rather than afterthoughts.

The project is Apache-2.0 and the methodology is open. I am especially looking for false-positive cases, eval fixtures, scanner adapters, and feedback from teams already using AI coding agents in security-sensitive repos.

## Launch post — X / short social

> Open-sourced SecHelix: evidence-first multi-agent AppSec for Claude Code, OpenAI/Codex and portable Agent Skills workflows. 546 structured hypotheses, business-logic/race coverage, independent verification, root-cause fixes, regression proof. No scanner alert is automatically a vulnerability. [repo]

## Launch post — Reddit / developer community

Do not lead with "AI hacker". Lead with the trust problem:

> I wanted an AI security workflow where the verifier is rewarded for rejecting bad findings, not generating more of them.

Then show a concrete owned/demo case study.

## Content roadmap

High-value posts:

1. Why two AI models agreeing is not independent verification.
2. A business-logic bug a normal SAST scanner cannot see.
3. How a green typecheck can still ship a broken browser security boundary.
4. Exact-once and idempotency as AppSec concerns.
5. Measuring false-positive rejection across Claude/Codex/GLM roles.
6. Building a role × object × action matrix automatically.
7. SecHelix vs scanner orchestration: what the skill does and does not replace.

## Credibility rules

Never buy stars, fake benchmarks, invent company adoption, or advertise a model as "best at hacking" without reproducible evals.

The strongest marketing asset will be public evidence:

- vulnerable fixture → verified finding;
- clean control → finding rejected;
- root-cause fix;
- regression proof;
- transparent model/tool cost and limitations.
