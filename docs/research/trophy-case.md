# SecHelix Trophy Case

SecHelix only lists findings that have **public, attributable evidence** and
permission to be referenced.

A large number of findings is not the goal. High-signal verified security
improvements are.

## Verified public results

_No entries yet._

That is intentional. SecHelix is new, and this file will not be filled with
unverifiable claims.

**What exists instead, today:**

- **[Case study: gamingops-store](../../docs/case-studies/gamingops-store-2026-09-01.md)** —
  a real end-to-end run with published artifacts: one MEDIUM clickjacking finding
  verified, fixed, and regression-proved, and one plausible high-severity XSS
  candidate refuted by verification. It is **not** a trophy entry, because the
  target repository is private and a reader cannot independently check it.
- **[Eval fixtures](../../evals/)** — 38 paired vulnerable/clean fixtures, 76 cases.
- **[Evaluation protocol](../../docs/EVALUATION.md)** and the
  **[`NOT_MEASURED` record](../../evals/results/not-measured.json)** — the metrics that
  will eventually be published, and the documented reason none of them are yet.

## Inclusion criteria

An entry is listed when all of these hold:

1. the target is a **public** project a reader can inspect;
2. a **public** advisory, issue, pull request, or commit shows the fix;
3. the fix is already public — **nothing embargoed or unpatched is ever listed**;
4. attribution is permitted by the project owner;
5. SecHelix evidence is described: which hypothesis was raised, what verification
   established it, and what regression proof was added;
6. no secrets, customer data, or weaponized exploit material appears anywhere in
   the submission.

Findings the maintainer made in their own projects are eligible only under the
same rules as anyone else's — public target, public fix, checkable by a reader.
The `gamingops-store` case study is the worked example of a result that
deliberately **fails** criterion 1 and is therefore published as a case study
rather than a trophy.

Duplicate reports of the same underlying issue are merged into one entry. An
entry is removed if the project owner later withdraws permission.

## Reporting a result

Open a **[trophy-case submission](https://github.com/omarmohelal/SecHelix/issues/new?template=trophy-case.yml)**.

Wait until the fix is public. A trophy entry is never worth exposing an unfixed
system.
