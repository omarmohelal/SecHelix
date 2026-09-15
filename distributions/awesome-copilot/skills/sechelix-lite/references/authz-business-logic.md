# Authentication, authorization, business logic and races

Lanes 2 and 4. Output candidates only; the verifier decides.

## Authentication and sessions

Trace attacker-controlled input or state through each identity transition: login, logout,
enrollment, recovery, token refresh, federation callback, step-up.

Check:

- session fixation, and whether session IDs rotate on login and privilege change;
- token lifetime, rotation and revocation, including logout and password change;
- cookie `Secure`, `HttpOnly`, `SameSite`, domain and path scope;
- password reset tokens: entropy, single use, expiry, binding to the account;
- account enumeration through responses or timing;
- MFA and step-up enforced server-side on money, secret and permission changes;
- OAuth/OIDC/SAML: `state`/nonce, redirect URI matching, audience and issuer checks;
- JWT: algorithm pinning, signature verification, `kid` handling, expiry;
- missing or unparseable identity never falls through to an authenticated or unscoped path.

Do not brute force credentials, capture real tokens or trigger real recovery emails. A weak-looking
option without a reachable bypass is an evidence gap, not a finding.

## Authorization (BOLA / IDOR / BFLA / tenant isolation)

Work from the `role × object × action` matrix. For each protected object:

- list who may read, edit and delete it;
- check list endpoints and item endpoints separately;
- check direct URLs, search, exports, bulk actions, GraphQL resolvers and background jobs;
- confirm the server enforces the rule; hidden UI is not a control;
- confirm `null`, missing identity and lookup errors fail closed;
- check that mixed roles combine as intended (union vs intersection);
- check ownership over time: reassignment, historical windows, invited vs active members;
- check admin or bypass helpers are narrow, explicit and audited;
- check database policies (RLS, grants, RPC functions) agree with the API layer.

A candidate needs a reachable path and a specific failed or absent check, not just an identifier
in a request. Prove it with two test identities or tenants you control, never with real data.

Common root cause: the endpoint *does* check something, but the wrong thing, such as "is the user
logged in" or "does the object exist", instead of "does this tenant own this object".

## Business logic and state machines

For every money, entitlement, inventory, approval or fulfillment flow, list the transitions. For
each one record actor, preconditions, source of truth, side effects, terminal states and rollback.

Ask:

- Can the same action happen twice?
- Can a terminal state be reopened?
- Can partial success be recorded as full success?
- Can refund and delivery race?
- Can a client-supplied price, quantity, status or role override stored truth?
- Can a user replay a stale preview, quote or approval?
- Can `null` or unknown be coerced to zero, false or allowed?
- Can a failed second write follow a destructive first write (delete-then-insert)?
- Can an external timeout later succeed and double-apply?
- Can edits rewrite finalized financial or audit history?
- Does an admin UI show success when a second write failed?

A candidate names a producible invalid state and the business invariant it violates. Unusual is
not the same as vulnerable; show attacker control and impact.

## Races and idempotency

Look for integrity failures from concurrency, retries, duplicate delivery and crashes:

- check-then-act without a lock, constraint or conditional update (TOCTOU);
- webhooks and queue messages processed more than once;
- idempotency keys that are missing, client-chosen without scoping, or checked outside the
  transaction;
- balance, stock or quota decrements that are not atomic;
- retries that repeat a provider side effect;
- crash between two writes with no reconciliation;
- outcome-unknown provider calls treated as failures and retried.

Specify the competing operations, the interleaving, the shared state, the expected rule and the
observed invalid outcome. Prove on local fixtures with a small, bounded number of concurrent
requests, repeated enough to separate a race from a flaky test. No load testing.

Do not call a path racy only because it lacks a visible lock; a unique constraint or conditional
update may already serialize it.

## Typical root-cause fixes

- one central authorization check at the data-access boundary;
- ownership included in the query, not checked after fetching;
- atomic transaction or conditional update instead of read-modify-write;
- database uniqueness constraint as the idempotency backstop;
- an explicit state machine that rejects invalid transitions;
- unknown provider outcomes held for reconciliation, not retried blindly.
