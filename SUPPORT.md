# Getting help

## Start here

| You want to | Go to |
|---|---|
| Install it | [README — Install](README.md#install-in-30-seconds) |
| Run your first audit | [Quickstart](docs/QUICKSTART.md) |
| Know whether your agent host is supported | [Compatibility](docs/reference/compatibility.md) |
| Understand a status word | [Report contract](schemas/report-v1.schema.json) and the vocabularies below |
| Report a **false positive** | [Open a false-positive issue](https://github.com/omarmohelal/SecHelix/issues/new?template=false-positive.yml) |
| Report a bug | [Open a bug](https://github.com/omarmohelal/SecHelix/issues/new?template=bug.yml) |
| Ask a question | [Discussions → Q&A](https://github.com/omarmohelal/SecHelix/discussions) |
| Report a vulnerability **in SecHelix** | [SECURITY.md](SECURITY.md) — **not** a public issue |

## Before you open anything

**Never paste credentials, private source, customer data, or internal hostnames into a public
thread.** Reports contain evidence, and evidence contains things you do not want indexed. Use the
redacted JSON output, and strip paths that reveal internal structure.

If the issue concerns a third party's system, complete responsible disclosure with them **first**.

## The most useful thing you can report

A **false positive**. This project's entire premise is that a finding is a claim that must survive
refutation, so a case where it accused something innocent is the most valuable bug report it can
receive.

What makes one actionable:

- the finding id and what it claimed;
- the smallest reproduction you can share — a redacted synthetic snippet is fine, and often better
  than real code;
- why it is wrong: the compensating control, the unreachable path, the framework behaviour that
  neutralises it;
- which catalog hypothesis produced it, if you can tell.

A confirmed false positive usually becomes a paired eval fixture — a vulnerable variant and a clean
one that looks alarming but is protected by the real control. That is how the suite gets harder.

## Status vocabularies

These are the words that carry meaning, and confusing them is the most common source of questions.

**Finding status** — `HYPOTHESIS`, `VERIFIED`, `LIKELY_BUT_UNPROVEN`, `FALSE_POSITIVE`,
`DUPLICATE_ROOT_CAUSE`, `BLOCKED_BY_ENVIRONMENT`.

**Applicability** — `APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`, `BLOCKED`. `UNKNOWN` and `BLOCKED`
are never converted into `NOT_APPLICABLE`: "we could not check" is not "this is fine".

**Release gate** — `PASS`, `PASS_WITH_KNOWN_RISK`, `BLOCKED`, `INCOMPLETE`. Missing required
evidence yields `INCOMPLETE` and a non-zero exit, never a silent pass.

**Compatibility** — `VERIFIED`, `DOCUMENTED`, `MODEL_COMPATIBLE`, `UNVERIFIED`, `NOT_SHIPPED`.
Nothing is upgraded to `VERIFIED` on the strength of vendor documentation alone.

## The benchmark question

It comes up first, so: **the public benchmark is `NOT_MEASURED`.**

There are 38 paired fixtures and a working scoring harness, plus a machine-readable blocker
(`CONTAMINATED_EVALUATOR`) recording why no number is published — the fixtures were authored by
assistant sessions working in this repository, so scoring one of them measures recall of authored
answers rather than review capability.

If you want to produce the first real number, the whole procedure is
[`evals/blind-packet/RUN.md`](evals/blind-packet/RUN.md). The result gets published whichever way it
comes out.

## What this project is not

It is not a scanner and does not replace one — it consumes scanner output as evidence and treats
every alert as a hypothesis. It is **alpha**: contracts and interfaces can still change.

## Response expectations

Single maintainer, best effort, no SLA. Security reports via `SECURITY.md` are read first.
