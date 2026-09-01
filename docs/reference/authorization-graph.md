# Authorization graph

Authorization bugs are the most common serious finding class and the hardest to see by reading
code, because nobody writes the policy down in one place. It is spread across route decorators, a
middleware chain, a role table, a database rule, and a button that is hidden in the client. Each
fragment looks correct on its own. The gap appears only when they are laid side by side.

`sechelix_core/authz_graph.py` lays them side by side:

```text
Identity -> Role -> Permission -> Resource -> Action -> Policy
```

and then reports what no single file shows.

## What it detects

| Detection | What it means |
| --- | --- |
| `MISSING_POLICY` | A resource+action a role can reach, governed by no server-enforced policy. |
| `UNEXPECTED_GRANT` | A policy lets an identity reach a resource no role of theirs grants. |
| `CONFLICTING_POLICY` | Two policies decide one (identity, resource, action) in opposite directions. |
| `UI_ONLY_AUTHORIZATION` | The action is gated in the client, and nowhere else. |
| `CROSS_TENANT_PATH` | An identity in one tenant reaches another tenant's data, or a shared store with no subject-tenant predicate. |

`UI_ONLY_AUTHORIZATION` is the one worth reading first. A check that runs on the caller's machine
is not an authorization control: the caller can skip it by sending the request directly, so it
constrains nobody. The hypothesis says exactly that, and a client-side gate never closes a
`MISSING_POLICY` hypothesis — it is reported alongside one.

## The verdict vocabulary

Every cell of the matrix carries one verdict, and the difference between the last three is the
entire point of the module.

| Verdict | Meaning |
| --- | --- |
| `ALLOWED` | A server-enforced policy allows this, as declared. |
| `DENIED` | A server-enforced policy denies this. **The only verdict that means blocked.** |
| `CONFLICTED` | Server-enforced policies both allow and deny it; the declarations do not say which wins. |
| `UNGOVERNED` | A role grant reaches it and no server-enforced policy governs it. Not a denial. |
| `UNKNOWN` | The declarations do not decide it. Not a denial. |

An identity with no role at all gets `UNKNOWN`, never `DENIED`. Absence of a grant in a model is
not proof that the runtime refuses the request — it is proof that the model does not say. Collapsing
"we could not tell" into "it is blocked" turns a hole in the model into a clean bill of health,
which is the failure this module exists to prevent. `DENIAL_VERDICTS` holds exactly one member so
that any code treating `UNKNOWN` as a block is visible.

## What it will not do

| Refusal | Why |
| --- | --- |
| Report a finding | The graph is built from declarations. That an edge is reachable at runtime is exactly what has not been shown. |
| Turn missing information into `DENIED` | Silence is not a control. |
| Count a client-side check as authorization | It runs on the caller's machine. |
| Count a policy with an undeclared enforcement point | Where a policy runs decides whether it is a control at all, so it is never inferred. |
| Assign a severity | Severity belongs to a verified finding, and nothing here is verified. |
| Silently accept a broken model | Structural nonsense raises; an unreadable model analyzed as empty would produce no detections at all, which reads exactly like a clean result. |

References the declarations make but never define — an undeclared role, a permission on a resource
nobody declared, an inheritance cycle — are recorded in `declaration_gaps` rather than raised. Real
models are partial. Every hole is a reason a verdict is `UNKNOWN` rather than a fact, so the holes
have to be visible.

## Declaring a model

```python
declarations = {
    "identities": [{"id": "alice", "roles": ["support"], "tenant": "acme"}],
    "roles": [{"id": "support", "permissions": ["orders.read"], "inherits": ["viewer"]}],
    "permissions": [{"id": "orders.read", "resource": "orders", "action": "read"}],
    "resources": [{"id": "orders", "actions": ["read", "export"], "tenant": "acme"}],
    "policies": [{
        "id": "P-1",
        "effect": "ALLOW",                # ALLOW | DENY
        "subject": "role:support",        # "*" | "role:<id>" | "identity:<id>"
        "resource": "orders",             # id or "*"
        "action": "read",                 # verb or "*"
        "enforced_at": "SERVER",          # SERVER | DATABASE | GATEWAY | CLIENT | UNKNOWN
        "tenant_scoped": True,            # the policy carries a subject-tenant predicate
        "source": "app/policy.py:10",
    }],
}
```

`enforced_at` has no default. Where a policy runs is what decides whether it is an authorization
control, and inferring it is how a client check gets counted as one.

A resource whose `tenant` is `"*"` is a shared store holding several tenants' rows. Reaching it
without a `tenant_scoped` policy raises `CROSS_TENANT_PATH`. When either side's tenant is
undeclared, nothing is claimed: the pair is listed in `undetermined` instead, because not knowing
and knowing it is safe are different answers.

## Usage

```python
from sechelix_core.authz_graph import build_authorization_graph, render_mermaid

result = build_authorization_graph(declarations)

result.graph()            # nodes + edges, JSON-serializable
result.matrix()           # identity x resource-action, with the verdict in each cell
result.hypotheses         # what to check, each with the question that settles it
result.as_dict()          # all of the above, plus declaration_gaps and undetermined

print(render_mermaid(result.graph()))
```

Both exports are stable: node ids sort, edge ids are assigned after sorting, and hypothesis ids are
assigned after sorting, so the same model renders the same diagram and the same ids every time.

Wildcards stay wildcards in the graph. A policy with `subject: "*"` becomes an edge from a single
wildcard node rather than one edge per identity, because expanding it would hide the single most
important thing about that policy.

## Verifying a hypothesis

Each hypothesis carries `verification_question` — the thing to do against a running, authorized
instance — and `refuted_if`, the declaration or control that would make it go away. A hypothesis
becomes a finding only through the normal evidence path, and only then does it acquire a severity.

## Related

- [Patch mode](patch-mode.md) — what happens after a hypothesis is verified
- [PR review mode](pr-review-mode.md) — the same honesty rules applied to a pull request
- [Compatibility](compatibility.md)
- [`sechelix_core/authz_graph.py`](../../sechelix_core/authz_graph.py)
