# SecHelix security report — demo-store

- **Schema:** 1.0.0
- **Mode:** LOCAL
- **Release recommendation:** PASS

## Scope

- **In scope:** ["demo-store repository", "local fixture database"]
- **Out of scope:** ["production providers"]
- **Restrictions:** ["non-destructive fixtures only"]

## Architecture and trust boundaries

A local multi-tenant store with API, worker, and fixture database boundaries.

## Trust boundaries

- buyer to API
- seller to tenant data
- API to worker

## Role × object × action matrix

| Role | Object | Actions |
|---|---|---|
| seller | own listing | ["read", "update"] |
| seller | other seller listing | [] |

## Coverage

| Applicable | Not applicable | Unknown | Blocked |
|---:|---:|---:|---:|
| 87 | 438 | 20 | 1 |

## Tools and evidence sources

- {"name": "targeted-source-review", "version": "repository-native"}
- {"name": "local-regression", "version": "fixture"}

## Findings

### SHX-AUTHZ-L02-DEMO: Missing seller identity previously widened a listing query

- **Severity:** HIGH
- **Confidence:** HIGH
- **Status:** VERIFIED
- **Resolution:** FIXED
- **Surface:** GET /seller/listings
- **Prerequisites:** ["authenticated seller", "missing seller lookup fixture"]
- **Attacker control:** The caller could reach the listing endpoint while the seller lookup returned no identity.
- **Reachability:** The route passed the missing identifier into the query builder.
- **Boundary failure:** Missing identity produced an unscoped query instead of failing closed.
- **Safe reproduction:** Use the local seller-without-profile fixture and assert the old handler returns cross-tenant rows.
- **Impact:** A seller could read listing metadata belonging to other tenants.
- **Root cause:** The canonical authorization helper treated a missing subject as an absent filter.
- **Independent verification:** {"evidence": ["local two-seller fixture reproduced the boundary failure"], "status": "VERIFIED", "verified_at": "2026-08-31T00:00:00Z", "verifier_id": "independent-verifier-demo"}
- **Fix:** Reject a missing seller subject before constructing the query.
- **Regression proof:** {"assertion": "missing seller identity returns 403 and no rows", "command": "python -m unittest tests.test_demo_authz", "result": "PASS"}
- **Residual risk:** Sibling background jobs require separate applicability review.
- **References:** ["CWE-862"]

### SHX-LOG-L20-DEMO: Verbose local diagnostics retain request identifiers

- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Status:** VERIFIED
- **Resolution:** OPEN
- **Surface:** local diagnostic log
- **Prerequisites:** Not provided
- **Attacker control:** Request identifiers are partially caller influenced.
- **Reachability:** Identifiers are written by the local diagnostic middleware.
- **Boundary failure:** The local log retention window exceeds the documented fixture requirement.
- **Safe reproduction:** Run one local request and inspect the isolated fixture log.
- **Impact:** Local-only correlation data persists longer than intended.
- **Root cause:** The fixture cleanup job uses the default retention period.
- **Independent verification:** {"evidence": [], "status": "NOT_REQUIRED"}
- **Fix:** Set an explicit fixture retention duration.
- **Regression proof:** Assert fixture logs expire after the configured duration.
- **Residual risk:** Production logging was out of scope.
- **References:** ["CWE-532"]

## Rejected candidates

- {"id": "SHX-SSRF-L04-DEMO", "reason": "The URL reaches a local allowlisted provider mock only.", "status": "FALSE_POSITIVE"}

## Blocked checks

- {"id": "SHX-CLOUD-L21-DEMO", "integrity_critical": false, "reason": "Cloud account was out of scope.", "status": "BLOCKED_BY_ENVIRONMENT"}
