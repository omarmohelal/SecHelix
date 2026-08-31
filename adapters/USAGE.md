# Evidence adapters

These standard-library-only adapters translate tool reports into one evidence envelope. They do not verify vulnerabilities. Every emitted record has `status: CANDIDATE` and `assessment`, `severity` and `verification` set to `UNASSESSED`. Original tool severity/confidence is retained only in `tool_signal.trusted_for_assessment: false`.

## Normalize a report

```console
python -m adapters.cli semgrep semgrep.json --pretty
python -m adapters.cli codeql codeql.sarif -o normalized.json
python -m adapters.cli sarif report.sarif
python -m adapters.cli osv osv.json
python -m adapters.cli trivy trivy.json
python -m adapters.cli gitleaks gitleaks.json
python -m adapters.cli npm-audit npm-audit.json
python -m adapters.cli pnpm-audit pnpm-audit.json
python -m adapters.cli playwright playwright.json
python -m adapters.cli zap zap.json
python -m adapters.cli nuclei nuclei.jsonl
```

The secret-oriented Trivy and Gitleaks paths omit captured values. The Nuclei adapter omits extracted results and request/response bodies. Keep the original reports protected according to their data classification.

## Bounded dynamic commands

`adapters.safety` constructs commands but never executes them. `ScanContext(mode="local")` accepts loopback HTTP(S) targets only. `mode="staging"` additionally requires an exact hostname allowlist. Production and uncontrolled modes fail closed.

`zap_passive_command` emits only a ZAP baseline command. `nuclei_safe_command` requires explicit, existing YAML template files on an operator-supplied allowlist and applies low concurrency/rate defaults. It rejects remote, directory-wide, DAST, fuzz, headless and code-protocol template profiles. Checked-in policy examples live in `adapters/profiles/`; they are constraints, not authorization.

Run the contract suite with:

```console
python -m unittest discover -s adapters/tests -v
```
