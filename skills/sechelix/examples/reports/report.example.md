# SecHelix security report — gamingops-store (authorized owner self-audit)

- **Schema:** 1.0
- **Report ID:** REPORT-GOS-2026-09-01
- **Mode:** LOCAL
- **Generated at:** 2026-09-01T14:20:00Z
- **Release recommendation:** PASS

## Scope

- **Scope ID:** SCOPE-GOS-STOREFRONT
- **Project:** gamingops-store (authorized owner self-audit)
- **Execution mode:** LOCAL
- **Deployment state:** Not provided

## Coverage

| Catalog | Applicable | Not applicable | Unknown | Blocked | Total | Integrity-critical unknown |
|---|---:|---:|---:|---:|---:|---:|
| 2.2 | 41 | 496 | 8 | 1 | 546 | 0 |

## Tools and evidence sources

- next 16.2.7 — Production build under test
- vitest 3.2.7 — Regression proof execution
- chromium-devtools playwright-mcp — Local framing reproduction and CSP refusal capture
- curl 8.x — Response header observation

## Evidence

- EV-GOS-HEADERS-BASELINE [OBSERVATION/CONFIRMED] via curl: The baseline build returned no Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, or Permissions-Policy header, and advertised X-Powered-By: Next.js.
- EV-GOS-FRAME-REPRO [REPRODUCTION/CONFIRMED] via chromium-framing-probe: A third-party page on a different local origin embedded the storefront in an iframe and the full interface rendered, including the Sign in entry point.
- EV-GOS-ROOTCAUSE [CONTEXT/CONFIRMED] via next.config.ts: next.config.ts declared only an images block. The application defined no headers() policy, so no framing or content-security boundary was ever emitted.
- EV-GOS-REMEDIATION [REMEDIATION/CONFIRMED] via gamingops-store PR #2: next.config.ts now returns a catch-all header rule carrying CSP with frame-ancestors 'none', X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, HSTS, and COOP, and disables poweredByHeader.
- EV-GOS-REGRESSION [REGRESSION/CONFIRMED] via vitest: Ten regression assertions cover the header set, frame-ancestors, X-Frame-Options DENY, absence of X-Powered-By, and rejection of hostile URL schemes. Full suite 15/15 pass.
- EV-GOS-RETEST [VERIFICATION/CONFIRMED] via chromium-console: After a clean rebuild the browser refused the frame: "Framing 'http://localhost:3009/' violates the following Content Security Policy directive: \"frame-ancestors 'none'\". The request has been blocked."
- EV-GOS-URLSCHEME-REFUTATION [VERIFICATION/REJECTED] via mock-store-config-api: A hostile javascript: URL supplied through the remote store-config was rendered by React 19 as javascript:throw new Error('React has blocked a javascript: URL as a security precaution.'), so the suspected cross-site scripting path is not exploitable. Attacker control was also not established from the public internet.

## Findings

### SHX-F-GOS-HEADERS-001: Storefront declares no response security headers and can be framed by any origin

- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Status:** VERIFIED
- **Resolution:** FIXED
- **Catalog hypotheses:** SHX-WEB-L08
- **Affected surface:** All storefront routes served by the Next.js application
- **Mappings:** CWE-1021, OWASP-ASVS:V14
- **Evidence:** EV-GOS-HEADERS-BASELINE, EV-GOS-FRAME-REPRO, EV-GOS-ROOTCAUSE, EV-GOS-REMEDIATION, EV-GOS-REGRESSION, EV-GOS-RETEST
- **Attacker control:** [established] An attacker fully controls the third-party page that embeds the storefront. (evidence: EV-GOS-FRAME-REPRO)
- **Reachability:** [established] Every public route is served without a framing policy, so the embed reaches the real interface. (evidence: EV-GOS-HEADERS-BASELINE, EV-GOS-FRAME-REPRO)
- **Boundary failure:** [established] No frame-ancestors directive and no X-Frame-Options header were emitted, so the browser default of permitting framing applied. (evidence: EV-GOS-HEADERS-BASELINE)
- **Safe reproduction:** [established] The storefront rendered inside a cross-origin iframe on a local probe page. No external or production system was contacted. (evidence: EV-GOS-FRAME-REPRO)
- **Impact:** [established] UI redress: an overlay can bait clicks onto the Sign in and purchase calls to action. Realistic impact is phishing amplification and brand abuse rather than direct account takeover, because this application holds no authenticated state-changing actions. (evidence: EV-GOS-FRAME-REPRO)
- **Preconditions:** [established] A victim visits an attacker-controlled page while the storefront is publicly reachable. (evidence: EV-GOS-FRAME-REPRO)
- **Root cause:** [established] next.config.ts declared no headers() policy, so the application never expressed a framing or content-security boundary. (evidence: EV-GOS-ROOTCAUSE)
- **Independent verification:** VERIFIED (independent) by sechelix-independent-verifier; evidence: EV-GOS-FRAME-REPRO, EV-GOS-RETEST; refutation attempt: Attempted to refute by looking for a compensating framing control at the edge or in middleware. The application ships no middleware and no proxy configuration, and the production build emitted no framing header, so no compensating control exists in the reviewed deployment path.
- **Fix:** Declare a catch-all headers() rule in next.config.ts carrying CSP frame-ancestors 'none', X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, HSTS and COOP, and disable poweredByHeader. (evidence: EV-GOS-REMEDIATION)
- **Regression proof:** PASS — command: npx vitest run tests/security.test.ts; assertion: The catch-all header rule exists and carries every required header; X-Frame-Options is DENY; CSP contains frame-ancestors 'none'; poweredByHeader is false.; evidence: EV-GOS-REGRESSION, EV-GOS-RETEST
- **Residual risk:** The CSP retains 'unsafe-inline' for script-src and style-src because the application relies on framework-injected inline scripts and React inline styles. Moving to a nonce-based policy would remove that allowance.

### SHX-F-GOS-URLSCHEME-001: Remote store configuration reaches href and src sinks without scheme validation

- **Severity:** INFO
- **Confidence:** HIGH
- **Status:** FALSE_POSITIVE
- **Resolution:** FALSE_POSITIVE
- **Catalog hypotheses:** SHX-WEB-L18
- **Affected surface:** hero call to action rendered from remote store-config; footer links rendered from remote store-config; social links rendered from remote store-config; listing artwork src rendered from marketplace listings
- **Mappings:** CWE-79
- **Evidence:** EV-GOS-URLSCHEME-REFUTATION
- **Attacker control:** [not established] The configuration source is the operator's own workspace API. Injecting a hostile URL requires compromising that API or its administrative surface; it is not reachable by an anonymous internet attacker. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Reachability:** [established] Remote configuration values are rendered into href and src attributes on every page. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Boundary failure:** [not established] React 19 neutralizes javascript: URLs before they reach the document, so the rendering boundary held under a hostile payload. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Safe reproduction:** [established] A local mock configuration API served a javascript: payload; the rendered document contained React's blocked-URL placeholder rather than the payload. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Impact:** [not established] No script execution is achievable through this path in the reviewed framework version. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Preconditions:** [not established] Exploitation would require both upstream compromise and a renderer that does not block hostile URL schemes. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Root cause:** [established] The normalizer applied only whitespace trimming, so scheme safety depended entirely on a framework internal rather than on an application boundary. (evidence: EV-GOS-URLSCHEME-REFUTATION)
- **Independent verification:** FALSE_POSITIVE (independent) by sechelix-independent-verifier; evidence: EV-GOS-URLSCHEME-REFUTATION; refutation attempt: Reconstructed the suspected cross-site scripting claim from scratch by serving a hostile javascript: URL from a controlled configuration endpoint and observing the rendered document. The payload never reached the DOM, so the claim was rejected rather than promoted.
- **Fix:** A safeUrl() scheme allowlist was added at the normalization boundary as defense in depth so the application no longer depends on renderer behaviour for URL safety. This is hardening, not a vulnerability fix. (evidence: EV-GOS-REGRESSION)
- **Regression proof:** PASS — command: npx vitest run tests/security.test.ts; assertion: javascript:, data:, vbscript: and protocol-relative URLs are rejected at the trust boundary while relative paths, https and mailto survive.; evidence: EV-GOS-REGRESSION
- **Residual risk:** If the upstream configuration API is compromised, an attacker can still inject arbitrary http(s) destinations for outbound links. That is a link-injection and phishing risk, not script execution.

## Rejected candidates

- SHX-F-GOS-URLSCHEME-001: suspected javascript: cross-site scripting was refuted by local reproduction; React 19 blocks the scheme and no attacker-controlled path to the configuration API was established.
- Buyer-name masking in getRecentSales was reviewed for a privacy leak. Every code path returns a masked value, so no unmasked identifier reaches the page.

## Blocked checks

- SHX-CLOUD-L21

## Redaction summary

- No customer data, credentials, secrets, or live exploit material appears in this report.
- Reproduction used a local mock configuration API; no third-party or production system was contacted.

## Notes

- Authorized owner self-audit of a private repository.
- The storefront is a display-only front end; purchase and account flows live in a separate system that was out of scope.
