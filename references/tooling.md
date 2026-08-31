# Tooling adapters

SecHelix treats tools as **evidence producers**, not authorities.

## Recommended evidence lanes

### Static analysis

Useful sources include Semgrep, CodeQL, language-native linters/type systems, custom AST queries, and targeted repository search.

Use them to:

- enumerate dangerous sinks;
- trace candidate flows;
- detect repeated insecure patterns;
- perform variant analysis after a verified root cause.

Do not promote every static alert into the final report.

### Dependency and supply-chain analysis

Examples: OSV-Scanner, Trivy, package-manager audit commands, lockfile inspection, GitHub dependency/security information, Gitleaks-style secret scanning.

Separate:

- vulnerable dependency present;
- vulnerable code path reachable;
- exploit preconditions satisfied.

### Browser/runtime verification

Use a real browser or browser automation to prove issues static tooling cannot see:

- client/server bundle boundaries;
- cookie/origin/redirect behavior;
- CSP and DOM behavior;
- authorization navigation/direct URLs;
- race-sensitive UI/API transitions;
- mobile access to critical actions.

### API testing

Prefer schema-aware, bounded requests against local/staging fixtures. Test role/object/action differences, alternate endpoints, bulk routes, pagination/search/export, error paths, and retry behavior.

### DAST / proxy tools

OWASP ZAP, Burp Suite, and similar tools can provide useful signals in authorized environments. Use narrowly scoped targets and avoid uncontrolled active scanning against production.

### Nuclei-style templates

Treat signature/template matches as hypotheses. Safe local/staging templates can be useful for known exposure classes. Do not use SecHelix as a wrapper for indiscriminate internet scanning or rate-limit evasion.

## Model orchestration

Different models can be assigned different roles:

- long-context model → system map and cross-module reasoning;
- strong reasoning model → business logic, race conditions, abuse cases;
- fast model → inventories, repetitive applicability review, variant search;
- independent provider/model → verifier to reduce correlated mistakes.

The model name is not evidence. Track performance with reproducible eval fixtures.

## Output normalization

Future adapters should normalize tool output into a common record:

```json
{
  "source": "tool-or-model",
  "rule": "identifier",
  "location": "path:line",
  "claim": "what may be wrong",
  "evidence": [],
  "status": "HYPOTHESIS"
}
```

Only the SecHelix verification phase promotes a hypothesis into a verified finding.