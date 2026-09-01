# Case study — gamingops-store storefront (authorized owner self-audit)

**Date:** 2026-09-01 · **Mode:** LOCAL and STATIC only · **Authorization:** repository owner
auditing their own private repository.

This is the first end-to-end SecHelix run recorded against a real application rather than a
synthetic fixture. It is published because the outcome is useful in both directions: one
finding was verified and fixed, and one plausible high-severity candidate was **refuted**.

> This case study is **not** a Trophy Case entry. `TROPHY_CASE.md` requires a public project
> and a public advisory, issue, or fix reference. The target repository is private, so the
> result does not meet that bar and no trophy entry was added.

---

## 1. Run record

| Field | Value |
| --- | --- |
| Target repository | `omarmohelal/gamingops-store` (private) |
| Target commit | `06ab8ca680d477b8005805d67ab44d11507e3321` |
| SecHelix commit | recorded in `artifacts/case-studies/gamingops-store-2026-09-01/run.json` |
| Execution mode | STATIC review + LOCAL runtime reproduction |
| Agent host | Claude Code |
| Scanners enabled | none — this run used code review plus local runtime observation |
| Tools | Next.js 16.2.7 production build, vitest 3.2.7, Chromium via Playwright, curl |
| Target size | ~600 lines of TypeScript/TSX across 19 source files |
| External systems contacted | none; a local mock stood in for the upstream config API |

The application is a display-only storefront. Purchase, account, and payment flows live in a
separate system that was explicitly **out of scope**.

## 2. What the workflow produced

| Stage | Result |
| --- | --- |
| Attack surface | 1 external data source (`WORK_API_BASE`), 3 public routes, 0 authenticated actions |
| Applicable hypotheses | 41 of 546 |
| Candidates raised | 3 |
| Verified findings | 1 |
| Refuted candidates | 2 |
| Fixed | 1 verified + 1 hardening |
| Regression tests added | 10 |
| Release decision | PASS after remediation |

## 3. Verified finding — `SHX-F-GOS-HEADERS-001` (MEDIUM)

**No response security headers were declared, so any origin could frame the storefront.**

`next.config.ts` contained only an `images` block. The production build emitted no
Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Strict-Transport-Security`, or `Permissions-Policy`, and advertised `X-Powered-By: Next.js`.

Evidence chain, all seven links established:

1. **Attacker control** — the attacker owns the page that embeds the storefront.
2. **Reachability** — every public route was served without a framing policy.
3. **Boundary failure** — no `frame-ancestors` and no `X-Frame-Options`; the browser default
   of permitting framing applied.
4. **Safe reproduction** — a local probe page on a separate origin embedded the storefront and
   the entire interface rendered, including the *Sign in* entry point. Nothing outside
   `127.0.0.1` was contacted.
5. **Impact** — UI redress. An overlay can bait clicks onto the sign-in and purchase calls to
   action. Honest severity is **MEDIUM**: the realistic outcome is phishing amplification and
   brand abuse, not direct account takeover, because this application performs no
   authenticated state-changing actions.
6. **Preconditions** — a victim visits the attacker page while the storefront is reachable.
7. **Root cause** — the application never declared a security header policy at all.

**Fix.** A catch-all `headers()` rule adding CSP with `frame-ancestors 'none'`,
`X-Frame-Options: DENY`, nosniff, referrer policy, Permissions-Policy, HSTS and COOP, plus
`poweredByHeader: false`.

**Retest.** After a clean rebuild the browser refused the frame itself:

```
Framing 'http://localhost:3009/' violates the following Content Security Policy
directive: "frame-ancestors 'none'". The request has been blocked.
```

## 4. Refuted candidate — `SHX-F-GOS-URLSCHEME-001`

**A high-severity XSS claim that did not survive verification.**

Remote store-configuration values (`hero.ctaHref`, `footerLinks[].href`, `socials.*`, and
listing `image`) flow into `href` and `src` attributes with only `.trim()` applied. This is
the shape a scanner or a confident reviewer reports as high-severity cross-site scripting.

The independent verification refuted it. A local mock configuration API served
`javascript:alert(document.domain)`; the rendered document contained

```
href="javascript:throw new Error('React has blocked a javascript: URL as a security precaution.')"
```

React 19 neutralizes `javascript:` URLs before they reach the document, so **no script
execution is achievable through this path**. Attacker control was independently not
established: the configuration source is the operator's own workspace API, not an
internet-reachable input.

Recorded outcome: `FALSE_POSITIVE`, with the refutation reason retained.

The scheme allowlist was still added at the trust boundary as **defense in depth**, because
depending on a renderer internal for URL safety is fragile. That is hardening, and the report
labels it as hardening rather than as a vulnerability fix.

A second candidate — a suspected PII leak in the buyer-name masking helper — was also rejected
after tracing every code path returned a masked value.

## 5. Regression proof

`tests/security.test.ts` in the target repository, 10 assertions:

- the catch-all header rule exists and carries all six required headers;
- `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` are both present;
- `poweredByHeader` is disabled;
- `javascript:`, `data:`, `vbscript:` and protocol-relative URLs are rejected at the boundary;
- relative paths, `https:` and `mailto:` survive;
- the config normalizer neutralizes hostile upstream values end to end.

Full target suite: **15/15 pass**, typecheck clean.

## 6. A finding about the process itself

The first retest appeared to fail: headers were still missing and the hostile URL still
appeared in the DOM. The cause was a **stale Next.js prerender cache** plus a still-running
server bound to the old port. Only a clean rebuild proved the fix.

This is recorded because it is the kind of detail that silently converts a real fix into a
false claim of remediation. It is also a direct instance of a SecHelix rule: *a green
typecheck is not proof that a built application is fixed.*

## 7. Limitations

- One small application (~600 LOC) with no authentication and no server-side state.
- No scanners were enabled; this was code review plus local runtime observation.
- Coverage numbers describe hypotheses considered applicable to this architecture; they are
  not a claim about the framework's accuracy.
- The severity assigned to the verified finding is a judgement, not a CVSS computation.
- This run measures nothing about SecHelix's performance in general. It is one audit.

## 8. Artifacts

`artifacts/case-studies/gamingops-store-2026-09-01/` — response headers before and after,
framing reproduction screenshots before and after, the refutation transcript, and the
regression output. Every artifact is referenced from the canonical report with a SHA-256
digest.

Canonical report: `examples/report.example.json` (validates against `report-v1`, and the
release gate returns PASS).
