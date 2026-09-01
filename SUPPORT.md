# Getting help with SecHelix

Start here. Pick the row that matches what you need.

| I want to… | Go here |
|---|---|
| Install it and run a first audit | [Quickstart](docs/QUICKSTART.md) |
| Find the right prompt for a task | [Command cookbook](docs/COMMANDS.md) |
| Know whether my agent/host is supported | [COMPATIBILITY.md](COMPATIBILITY.md) |
| See what a real run looks like | [Case study](docs/case-studies/gamingops-store-2026-09-01.md) |
| Understand why there is no benchmark | [Evaluation protocol](docs/EVALUATION.md) · [`not-measured.json`](evals/results/not-measured.json) |
| Report a bug in the skill, adapters, docs, or scripts | [Bug report](https://github.com/omarmohelal/SecHelix/issues/new?template=bug.yml) |
| Report a **false positive** or a missed class | [False positive report](https://github.com/omarmohelal/SecHelix/issues/new?template=false-positive.yml) |
| Propose a new security check | [Hypothesis proposal](https://github.com/omarmohelal/SecHelix/issues/new?template=check-proposal.yml) |
| Propose an adapter, pack, reporter, or integration | [Extension proposal](https://github.com/omarmohelal/SecHelix/issues/new?template=extension.yml) |
| Share a public verified result | [Trophy-case submission](https://github.com/omarmohelal/SecHelix/issues/new?template=trophy-case.yml) |
| Report a **vulnerability in SecHelix itself** | [SECURITY.md](SECURITY.md) — private reporting, not a public issue |
| Contribute code or knowledge | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Talk about commercial use or services | [COMMERCIAL.md](COMMERCIAL.md) |

## Response expectations

SecHelix is maintained by one person. Issues are read, but there is no support
SLA and no guaranteed response time. Security reports are prioritized over
everything else — see [SECURITY.md](SECURITY.md) for the targets that do apply.

A well-formed issue gets answered faster than a vague one. For anything
behavioral, include the SecHelix version or commit, the agent host, your OS and
Python version, the exact instruction you gave the agent, and what it did
instead.

## Before you file

- **Search existing issues first.**
- **Do not paste secrets, credentials, customer data, or live exploit material**
  into an issue. Redact before posting.
- **A finding SecHelix produced about someone else's system is not a SecHelix
  issue.** Report it to that system's owner.
- If you are unsure whether something is a false positive or a bug, file it as a
  false positive — that is the more useful signal for this project either way.

## Supporting the project

Financial and non-financial support are documented separately:

- **Non-financial** — the highest-value early contribution is evidence: false
  positives, missed classes, eval fixtures, and reproducible case studies. See
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Financial** — see the support page on the official domain,
  **[sechelix.com/support](https://sechelix.com/support)**, and the maintainer
  notes in [docs/funding.md](docs/funding.md).

> [!WARNING]
> Donation details are published **only** on `sechelix.com` and in this
> repository. Verify the asset and network before sending anything, and treat a
> donation address advertised on any other domain as untrusted.

If donations ever become material, what they fund — hosting, domains, test
infrastructure, security research, model and API evaluation, maintainer time —
will be published.
