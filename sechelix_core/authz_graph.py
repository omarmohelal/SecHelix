"""Authorization graph.

Authorization bugs are the most common serious finding class and the hardest to
see by reading code, because nobody writes the policy down in one place. It is
spread across route decorators, a middleware chain, a role table, a database
rule, and a button that is hidden in the client. Each fragment looks correct on
its own. The gap only appears when they are laid side by side.

This module lays them side by side:

    Identity -> Role -> Permission -> Resource -> Action -> Policy

and reports five things that are invisible in any single file:

* **missing edges** — a resource+action a role can reach, governed by no policy;
* **unexpected edges** — an identity reaching a resource no role grants it;
* **conflicting policies** — two policies deciding one cell in opposite directions;
* **UI-only authorization** — an action gated only in the client;
* **cross-tenant paths** — an identity in one tenant reaching another tenant's data.

What it refuses to do
---------------------

**It never reports a finding.** The graph is built from *declarations*. That a
declared edge is reachable at runtime is exactly what has not been shown, so
every detection is a ``HYPOTHESIS`` carrying the question that would settle it.

**It never turns silence into a denial.** A cell is ``DENIED`` only when a
server-enforced DENY policy matches it. "No policy grants this" is
``UNGOVERNED``; "the declarations do not decide this" is ``UNKNOWN``. Both are
*non-denials*, and collapsing either into ``DENIED`` would turn a hole in the
model into a clean bill of health — which is the failure this module exists to
prevent.

**It never counts a client-side check as authorization.** A check that runs on
the caller's machine is a usability feature. The caller can skip it by sending
the request directly, so it constrains nobody. A resource gated only in the
client is reported as ungoverned, and the hypothesis says so in those words.

**It assigns no severity.** Severity belongs to a verified finding, and nothing
here is verified.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping, Sequence

# --------------------------------------------------------------------------- #
# Vocabulary
# --------------------------------------------------------------------------- #

IDENTITY = "IDENTITY"
ROLE = "ROLE"
PERMISSION = "PERMISSION"
RESOURCE = "RESOURCE"
ACTION = "ACTION"
POLICY = "POLICY"

NODE_KINDS = (IDENTITY, ROLE, PERMISSION, RESOURCE, ACTION, POLICY)

ALLOW = "ALLOW"
DENY = "DENY"
EFFECTS = frozenset({ALLOW, DENY})

#: Where a policy is actually enforced. Only the server-side points are
#: authorization controls; CLIENT is listed so a client gate can be *declared*
#: and then explicitly refused the status of a control.
SERVER = "SERVER"
DATABASE = "DATABASE"
GATEWAY = "GATEWAY"
CLIENT = "CLIENT"
UNKNOWN_ENFORCEMENT = "UNKNOWN"
ENFORCEMENT_POINTS = frozenset({SERVER, DATABASE, GATEWAY, CLIENT, UNKNOWN_ENFORCEMENT})
SERVER_SIDE = frozenset({SERVER, DATABASE, GATEWAY})

ALLOWED = "ALLOWED"
DENIED = "DENIED"
CONFLICTED = "CONFLICTED"
UNGOVERNED = "UNGOVERNED"
UNKNOWN = "UNKNOWN"
VERDICTS = (ALLOWED, DENIED, CONFLICTED, UNGOVERNED, UNKNOWN)

#: The only verdict that means "this is blocked". Everything else is either an
#: allowance or an admission of ignorance. Code that treats UNKNOWN or
#: UNGOVERNED as a denial is the bug this constant exists to make obvious.
DENIAL_VERDICTS = frozenset({DENIED})

VERDICT_MEANINGS = {
    ALLOWED: "a server-enforced policy allows this, as declared",
    DENIED: "a server-enforced policy denies this; the only verdict that means blocked",
    CONFLICTED: "server-enforced policies both allow and deny this; the declarations do not say which wins",
    UNGOVERNED: "a grant path reaches this and no server-enforced policy governs it — not a denial",
    UNKNOWN: "the declarations do not determine this — not a denial",
}

MISSING_POLICY = "MISSING_POLICY"
UNEXPECTED_GRANT = "UNEXPECTED_GRANT"
CONFLICTING_POLICY = "CONFLICTING_POLICY"
UI_ONLY_AUTHORIZATION = "UI_ONLY_AUTHORIZATION"
CROSS_TENANT_PATH = "CROSS_TENANT_PATH"

HYPOTHESIS_KINDS = (
    MISSING_POLICY,
    UNEXPECTED_GRANT,
    CONFLICTING_POLICY,
    UI_ONLY_AUTHORIZATION,
    CROSS_TENANT_PATH,
)

#: Said once, quoted everywhere it applies. A client-side check is the single
#: most common thing mistaken for an authorization control.
CLIENT_CHECK_STATEMENT = (
    "A client-side check is not an authorization control: it runs on the caller's "
    "machine, and a caller who sends the request directly never executes it."
)

#: A resource whose declared tenant is "*" holds rows belonging to many tenants.
MULTI_TENANT = "*"
WILDCARD = "*"

SAME_TENANT = "SAME_TENANT"
FOREIGN_TENANT = "FOREIGN_TENANT"
SHARED_STORE = "SHARED_STORE"
UNDECLARED_IDENTITY_TENANT = "UNDECLARED_IDENTITY_TENANT"
UNDECLARED_RESOURCE_TENANT = "UNDECLARED_RESOURCE_TENANT"


class AuthorizationGraphError(ValueError):
    """The declarations cannot be read as an authorization model."""


# --------------------------------------------------------------------------- #
# Declarations
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Identity:
    id: str
    roles: tuple[str, ...] = ()
    tenant: str | None = None
    kind: str = "USER"


@dataclass(frozen=True)
class Role:
    id: str
    permissions: tuple[str, ...] = ()
    inherits: tuple[str, ...] = ()


@dataclass(frozen=True)
class Permission:
    id: str
    resource: str
    action: str


@dataclass(frozen=True)
class Resource:
    id: str
    actions: tuple[str, ...] = ()
    tenant: str | None = None


@dataclass(frozen=True)
class Policy:
    id: str
    effect: str
    subject: str
    resource: str
    action: str
    enforced_at: str
    tenant_scoped: bool = False
    source: str | None = None

    @property
    def server_side(self) -> bool:
        return self.enforced_at in SERVER_SIDE

    @property
    def client_side(self) -> bool:
        return self.enforced_at == CLIENT


@dataclass(frozen=True)
class AuthorizationModel:
    identities: dict[str, Identity]
    roles: dict[str, Role]
    permissions: dict[str, Permission]
    resources: dict[str, Resource]
    policies: tuple[Policy, ...]
    #: References the declarations make but do not define. Recorded rather than
    #: raised: real models are partial, and a partial model must still be
    #: readable — but the holes have to be visible, because every one of them is
    #: a reason a verdict is UNKNOWN rather than a fact.
    declaration_gaps: tuple[str, ...] = ()


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorizationGraphError(f"{label} must be an object, got {type(value).__name__}")
    return value


def _sequence(container: Mapping[str, Any], key: str) -> list[Any]:
    value = container.get(key, [])
    if value is None:
        return []
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise AuthorizationGraphError(f"{key} must be an array")
    return list(value)


def _identifier(entry: Mapping[str, Any], label: str) -> str:
    value = str(entry.get("id", "")).strip()
    if not value:
        raise AuthorizationGraphError(f"each {label} needs a non-empty id")
    return value


def _strings(entry: Mapping[str, Any], key: str) -> tuple[str, ...]:
    raw = entry.get(key, [])
    if raw is None:
        return ()
    if isinstance(raw, str):
        raise AuthorizationGraphError(f"{key} must be an array, not a string")
    if not isinstance(raw, Sequence):
        raise AuthorizationGraphError(f"{key} must be an array")
    return tuple(str(item).strip() for item in raw if str(item).strip())


def _unique(entries: Iterable[Any], label: str) -> None:
    seen: set[str] = set()
    for entry in entries:
        if entry in seen:
            raise AuthorizationGraphError(f"duplicate {label} id: {entry!r}")
        seen.add(entry)


def load_declarations(declarations: Mapping[str, Any]) -> AuthorizationModel:
    """Read declarations into a model, raising on shape and recording holes.

    Structural nonsense raises: an unreadable model would otherwise be analyzed
    as if it were empty, and an empty model produces no hypotheses at all, which
    reads exactly like a clean result.
    """
    declarations = _mapping(declarations, "declarations")

    # Ids are collected as they arrive: a duplicate would otherwise overwrite the
    # first declaration in the dict and disappear, which is precisely the kind of
    # silent loss this module exists to surface.
    seen_ids: list[str] = []

    identities: dict[str, Identity] = {}
    for entry in _sequence(declarations, "identities"):
        entry = _mapping(entry, "identity")
        ident = _identifier(entry, "identity")
        seen_ids.append(ident)
        tenant = entry.get("tenant")
        identities[ident] = Identity(
            ident,
            _strings(entry, "roles"),
            str(tenant).strip() if tenant not in (None, "") else None,
            str(entry.get("kind", "USER")).strip().upper() or "USER",
        )
    _unique(seen_ids, "identity")

    seen_ids = []
    roles: dict[str, Role] = {}
    for entry in _sequence(declarations, "roles"):
        entry = _mapping(entry, "role")
        ident = _identifier(entry, "role")
        seen_ids.append(ident)
        roles[ident] = Role(ident, _strings(entry, "permissions"), _strings(entry, "inherits"))
    _unique(seen_ids, "role")

    seen_ids = []
    permissions: dict[str, Permission] = {}
    for entry in _sequence(declarations, "permissions"):
        entry = _mapping(entry, "permission")
        ident = _identifier(entry, "permission")
        seen_ids.append(ident)
        resource = str(entry.get("resource", "")).strip()
        action = str(entry.get("action", "")).strip()
        if not resource or not action:
            raise AuthorizationGraphError(
                f"permission {ident!r} must declare both a resource and an action "
                f'(use "*" explicitly for a wildcard)'
            )
        permissions[ident] = Permission(ident, resource, action)
    _unique(seen_ids, "permission")

    seen_ids = []
    resources: dict[str, Resource] = {}
    for entry in _sequence(declarations, "resources"):
        entry = _mapping(entry, "resource")
        ident = _identifier(entry, "resource")
        seen_ids.append(ident)
        tenant = entry.get("tenant")
        resources[ident] = Resource(
            ident,
            _strings(entry, "actions"),
            str(tenant).strip() if tenant not in (None, "") else None,
        )
    _unique(seen_ids, "resource")

    policies: list[Policy] = []
    for entry in _sequence(declarations, "policies"):
        entry = _mapping(entry, "policy")
        ident = _identifier(entry, "policy")
        effect = str(entry.get("effect", "")).strip().upper()
        if effect not in EFFECTS:
            raise AuthorizationGraphError(
                f"policy {ident!r} has effect {effect or '<missing>'}; expected ALLOW or DENY"
            )
        enforced_at = str(entry.get("enforced_at", "")).strip().upper()
        if enforced_at not in ENFORCEMENT_POINTS:
            raise AuthorizationGraphError(
                f"policy {ident!r} declares enforced_at={enforced_at or '<missing>'}; expected one "
                f"of {sorted(ENFORCEMENT_POINTS)}. Where a policy runs decides whether it is a "
                f"control at all, so it is never inferred."
            )
        subject = str(entry.get("subject", "")).strip()
        if subject != WILDCARD and not (
            subject.startswith("role:") or subject.startswith("identity:")
        ):
            raise AuthorizationGraphError(
                f'policy {ident!r} has subject {subject!r}; expected "*", "role:<id>" or '
                f'"identity:<id>"'
            )
        resource = str(entry.get("resource", "")).strip()
        action = str(entry.get("action", "")).strip()
        if not resource or not action:
            raise AuthorizationGraphError(
                f"policy {ident!r} must declare both a resource and an action "
                f'(use "*" explicitly for a wildcard)'
            )
        tenant_scoped = entry.get("tenant_scoped", False)
        if not isinstance(tenant_scoped, bool):
            raise AuthorizationGraphError(f"policy {ident!r} tenant_scoped must be a boolean")
        source = entry.get("source")
        policies.append(Policy(
            ident, effect, subject, resource, action, enforced_at, tenant_scoped,
            str(source).strip() if source not in (None, "") else None,
        ))
    _unique([p.id for p in policies], "policy")

    gaps: list[str] = []
    for identity in identities.values():
        for role_id in identity.roles:
            if role_id not in roles:
                gaps.append(f"identity {identity.id} holds undeclared role {role_id}")
    for role in roles.values():
        for permission_id in role.permissions:
            if permission_id not in permissions:
                gaps.append(f"role {role.id} grants undeclared permission {permission_id}")
        for parent in role.inherits:
            if parent not in roles:
                gaps.append(f"role {role.id} inherits undeclared role {parent}")
    for permission in permissions.values():
        if permission.resource != WILDCARD and permission.resource not in resources:
            gaps.append(
                f"permission {permission.id} targets undeclared resource {permission.resource}"
            )
    for policy in policies:
        if policy.resource != WILDCARD and policy.resource not in resources:
            gaps.append(f"policy {policy.id} governs undeclared resource {policy.resource}")
        elif (policy.resource in resources and policy.action != WILDCARD
                and policy.action not in resources[policy.resource].actions):
            gaps.append(
                f"policy {policy.id} governs {policy.resource}:{policy.action}, an action "
                f"{policy.resource} does not declare"
            )
    for role_id in sorted(roles):
        if _inheritance_cycle(roles, role_id):
            gaps.append(f"role {role_id} inherits itself through a cycle")

    return AuthorizationModel(
        identities, roles, permissions, resources, tuple(policies), tuple(dict.fromkeys(gaps)),
    )


def _inheritance_cycle(roles: Mapping[str, Role], start: str) -> bool:
    """Whether ``start`` reaches itself. Cycles are declared by accident, not design."""
    seen: set[str] = set()
    queue = list(roles[start].inherits)
    while queue:
        current = queue.pop()
        if current == start:
            return True
        if current in seen:
            continue
        seen.add(current)
        role = roles.get(current)
        if role is not None:
            queue.extend(role.inherits)
    return False


# --------------------------------------------------------------------------- #
# Reachability
# --------------------------------------------------------------------------- #


def effective_roles(model: AuthorizationModel, identity: Identity) -> set[str]:
    """Every role an identity holds, directly or by inheritance. Cycle-safe."""
    seen: set[str] = set()
    queue = list(identity.roles)
    while queue:
        role_id = queue.pop()
        if role_id in seen:
            continue
        seen.add(role_id)
        role = model.roles.get(role_id)
        if role is not None:
            queue.extend(role.inherits)
    return seen


def _expand(model: AuthorizationModel, permission: Permission) -> set[tuple[str, str]]:
    targets = sorted(model.resources) if permission.resource == WILDCARD else [permission.resource]
    pairs: set[tuple[str, str]] = set()
    for resource_id in targets:
        if permission.action == WILDCARD:
            resource = model.resources.get(resource_id)
            for action in (resource.actions if resource else ()):
                pairs.add((resource_id, action))
        else:
            pairs.add((resource_id, permission.action))
    return pairs


def granted_pairs(model: AuthorizationModel, identity: Identity) -> set[tuple[str, str]]:
    """The (resource, action) pairs this identity's roles carry a permission for."""
    pairs: set[tuple[str, str]] = set()
    for role_id in sorted(effective_roles(model, identity)):
        role = model.roles.get(role_id)
        if role is None:
            continue
        for permission_id in role.permissions:
            permission = model.permissions.get(permission_id)
            if permission is not None:
                pairs |= _expand(model, permission)
    return pairs


def columns(model: AuthorizationModel) -> list[tuple[str, str]]:
    """Every concrete (resource, action) the declarations mention."""
    pairs: set[tuple[str, str]] = set()
    for resource in model.resources.values():
        for action in resource.actions:
            pairs.add((resource.id, action))
    for permission in model.permissions.values():
        if WILDCARD not in (permission.resource, permission.action):
            pairs.add((permission.resource, permission.action))
    for policy in model.policies:
        if WILDCARD not in (policy.resource, policy.action):
            pairs.add((policy.resource, policy.action))
    return sorted(pairs)


def _subject_matches(policy: Policy, identity: Identity, roles: set[str]) -> bool:
    if policy.subject == WILDCARD:
        return True
    if policy.subject.startswith("identity:"):
        return policy.subject[len("identity:"):] == identity.id
    return policy.subject[len("role:"):] in roles


def _governs(policy: Policy, resource_id: str, action: str) -> bool:
    return (policy.resource in (WILDCARD, resource_id)
            and policy.action in (WILDCARD, action))


def _tenancy(identity: Identity, resource: Resource | None) -> str:
    if identity.tenant is None:
        return UNDECLARED_IDENTITY_TENANT
    if resource is None or resource.tenant is None:
        return UNDECLARED_RESOURCE_TENANT
    if resource.tenant == MULTI_TENANT:
        return SHARED_STORE
    return SAME_TENANT if resource.tenant == identity.tenant else FOREIGN_TENANT


def _applies_across_tenants(policy: Policy, tenancy: str) -> bool:
    """Whether a policy still applies once tenancy is taken into account.

    ``tenant_scoped`` declares that the policy carries a subject-tenant
    predicate, so it cannot be what lets an identity reach another tenant's
    resource. When either side's tenant is undeclared, the policy is kept: not
    knowing is not the same as knowing it does not apply.
    """
    if not policy.tenant_scoped:
        return True
    return tenancy != FOREIGN_TENANT


# --------------------------------------------------------------------------- #
# Cells
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Cell:
    """One (identity, resource, action) in the matrix, with why it says so."""

    identity: str
    resource: str
    action: str
    verdict: str
    reason: str
    grant_path: bool
    policies: tuple[str, ...] = ()
    deciding_policies: tuple[str, ...] = ()
    client_policies: tuple[str, ...] = ()
    tenancy: str = UNDECLARED_IDENTITY_TENANT

    @property
    def is_denial(self) -> bool:
        """True only for DENIED. UNKNOWN and UNGOVERNED are not denials."""
        return self.verdict in DENIAL_VERDICTS

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "resource": self.resource,
            "action": self.action,
            "verdict": self.verdict,
            "reason": self.reason,
            "grant_path": self.grant_path,
            "policies": list(self.policies),
            "deciding_policies": list(self.deciding_policies),
            "client_policies": list(self.client_policies),
            "tenancy": self.tenancy,
            "claim_status": "DECLARED",
        }


def _cell(model: AuthorizationModel, identity: Identity, roles: set[str], resource_id: str,
          action: str, grants: set[tuple[str, str]]) -> Cell:
    resource = model.resources.get(resource_id)
    tenancy = _tenancy(identity, resource)

    matching = [
        policy for policy in model.policies
        if _governs(policy, resource_id, action)
        and _subject_matches(policy, identity, roles)
        and _applies_across_tenants(policy, tenancy)
    ]
    server = [p for p in matching if p.server_side]
    allows = [p for p in server if p.effect == ALLOW]
    denies = [p for p in server if p.effect == DENY]
    client = [p for p in matching if p.client_side]
    undeclared_point = [p for p in matching if p.enforced_at == UNKNOWN_ENFORCEMENT]
    grant_path = (resource_id, action) in grants

    common = {
        "identity": identity.id,
        "resource": resource_id,
        "action": action,
        "grant_path": grant_path,
        "policies": tuple(p.id for p in matching),
        "client_policies": tuple(p.id for p in client),
        "tenancy": tenancy,
    }

    if allows and denies:
        return Cell(
            verdict=CONFLICTED,
            reason=(f"{', '.join(p.id for p in allows)} allows and "
                    f"{', '.join(p.id for p in denies)} denies; the declarations do not say "
                    f"which wins"),
            deciding_policies=tuple(p.id for p in server),
            **common,
        )
    if denies:
        return Cell(
            verdict=DENIED,
            reason=f"server-enforced denial by {', '.join(p.id for p in denies)}",
            deciding_policies=tuple(p.id for p in denies),
            **common,
        )
    if allows:
        return Cell(
            verdict=ALLOWED,
            reason=f"server-enforced allowance by {', '.join(p.id for p in allows)}",
            deciding_policies=tuple(p.id for p in allows),
            **common,
        )

    notes = []
    if client:
        notes.append(
            f"the only declared gate is client-side ({', '.join(p.id for p in client)}); "
            + CLIENT_CHECK_STATEMENT
        )
    if undeclared_point:
        notes.append(
            f"{', '.join(p.id for p in undeclared_point)} matches but declares no enforcement "
            f"point, so it cannot be counted as a control"
        )

    if grant_path:
        reason = "a role grant reaches this and no server-enforced policy governs it"
        return Cell(
            verdict=UNGOVERNED,
            reason="; ".join([reason, *notes]),
            deciding_policies=(),
            **common,
        )

    reason = (
        "no declaration grants, allows or denies this; absence of a grant is not proof the "
        "runtime refuses it"
    )
    return Cell(verdict=UNKNOWN, reason="; ".join([reason, *notes]), deciding_policies=(), **common)


# --------------------------------------------------------------------------- #
# Hypotheses
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Hypothesis:
    """Something worth checking. Never a finding, never carrying a severity."""

    kind: str
    statement: str
    resource: str
    actions: tuple[str, ...]
    identities: tuple[str, ...]
    policies: tuple[str, ...]
    sources: tuple[str, ...]
    verification_question: str
    refuted_if: str
    detail: str | None = None
    hypothesis_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "kind": self.kind,
            "claim_status": "HYPOTHESIS",
            "statement": self.statement,
            "resource": self.resource,
            "actions": list(self.actions),
            "identities": list(self.identities),
            "policies": list(self.policies),
            "sources": list(self.sources),
            "verification_question": self.verification_question,
            "refuted_if": self.refuted_if,
            "detail": self.detail,
        }


def _sources(model: AuthorizationModel, policy_ids: Iterable[str]) -> tuple[str, ...]:
    wanted = set(policy_ids)
    return tuple(sorted(
        p.source for p in model.policies if p.id in wanted and p.source
    ))


def _listed(values: Iterable[str], limit: int = 6) -> str:
    values = list(values)
    head = ", ".join(values[:limit])
    return head if len(values) <= limit else f"{head} and {len(values) - limit} more"


def _missing_policy_hypotheses(model, cells_by_column) -> list[Hypothesis]:
    found = []
    for (resource_id, action), cells in sorted(cells_by_column.items()):
        reaching = sorted(c.identity for c in cells if c.grant_path)
        if not reaching:
            continue
        governing = [
            p for p in model.policies
            if p.server_side and _governs(p, resource_id, action)
        ]
        if governing:
            continue
        found.append(Hypothesis(
            MISSING_POLICY,
            f"{resource_id}:{action} is reachable through role grants held by "
            f"{_listed(reaching)}, and no server-enforced policy governs it.",
            resource_id,
            (action,),
            tuple(reaching),
            (),
            (),
            f"Call {action} on {resource_id} as each listed identity against a running "
            f"instance. If nothing refuses it, the missing policy is real.",
            "A server-side, gateway or database-enforced policy governs this resource+action "
            "but was not declared to this model.",
        ))
    return found


def _ui_only_hypotheses(model, cells_by_column) -> list[Hypothesis]:
    found = []
    for (resource_id, action), cells in sorted(cells_by_column.items()):
        client = [p for p in model.policies
                  if p.client_side and _governs(p, resource_id, action)]
        if not client:
            continue
        server = [p for p in model.policies
                  if p.server_side and _governs(p, resource_id, action)]
        server_denies = [p for p in server if p.effect == DENY]
        client_denies = [p for p in client if p.effect == DENY]

        if not server:
            detail = "NO_SERVER_SIDE_POLICY"
            statement = (
                f"{resource_id}:{action} is gated only in the client "
                f"({_listed(p.id for p in client)}). {CLIENT_CHECK_STATEMENT} "
                f"There is no server-enforced policy for this resource+action, so it is "
                f"ungoverned."
            )
        elif client_denies and not server_denies:
            detail = "SERVER_ALLOWS_WHAT_THE_CLIENT_HIDES"
            statement = (
                f"{resource_id}:{action} is hidden in the client "
                f"({_listed(p.id for p in client_denies)}) while the server-enforced policy "
                f"({_listed(p.id for p in server)}) still allows it. {CLIENT_CHECK_STATEMENT} "
                f"The restriction exists only in the interface."
            )
        else:
            continue

        exposed = sorted({c.identity for c in cells if not c.is_denial})
        found.append(Hypothesis(
            UI_ONLY_AUTHORIZATION, statement, resource_id, (action,), tuple(exposed),
            tuple(sorted(p.id for p in client + server)),
            _sources(model, [p.id for p in client + server]),
            f"Send the {action} request to {resource_id} directly, bypassing the interface. "
            f"If the server performs it, the client check was the only gate.",
            "A server-side, gateway or database-enforced policy refuses the same request when "
            "the client is bypassed.",
            detail,
        ))
    return found


def _unexpected_grant_hypotheses(model, cells) -> list[Hypothesis]:
    grouped: dict[tuple[str, str], list[Cell]] = {}
    for cell in cells:
        if cell.verdict == ALLOWED and not cell.grant_path:
            grouped.setdefault((cell.identity, cell.resource), []).append(cell)

    found = []
    for (identity_id, resource_id), group in sorted(grouped.items()):
        actions = tuple(sorted(c.action for c in group))
        policies = tuple(sorted({p for c in group for p in c.deciding_policies}))
        wildcard = [p.id for p in model.policies
                    if p.id in set(policies) and WILDCARD in (p.subject, p.resource, p.action)]
        note = (f" The allowance comes from wildcard policy {_listed(wildcard)}."
                if wildcard else "")
        found.append(Hypothesis(
            UNEXPECTED_GRANT,
            f"{_listed(policies)} allows {identity_id} to perform {_listed(actions)} on "
            f"{resource_id}, but no role held by {identity_id} carries a permission for it.{note}",
            resource_id, actions, (identity_id,), policies, _sources(model, policies),
            f"Is {identity_id} meant to reach {resource_id}? If the role model is the intended "
            f"authority, this policy grants more than the roles do.",
            "The role model is incomplete and the identity is intended to hold a permission "
            "for this resource.",
        ))
    return found


def _conflict_hypotheses(model, cells) -> list[Hypothesis]:
    found = []
    for cell in cells:
        if cell.verdict != CONFLICTED:
            continue
        deciding = set(cell.deciding_policies)
        allows = sorted(p.id for p in model.policies if p.id in deciding and p.effect == ALLOW)
        denies = sorted(p.id for p in model.policies if p.id in deciding and p.effect == DENY)
        found.append(Hypothesis(
            CONFLICTING_POLICY,
            f"For ({cell.identity}, {cell.resource}, {cell.action}) policy {_listed(allows)} "
            f"allows and {_listed(denies)} denies. Which one takes effect is not declared, so "
            f"the outcome depends on evaluation order rather than on intent.",
            cell.resource, (cell.action,), (cell.identity,),
            tuple(sorted(deciding)), _sources(model, deciding),
            f"Perform {cell.action} on {cell.resource} as {cell.identity}. The observed result "
            f"names the policy that actually wins.",
            "The enforcement layer defines a documented precedence rule that resolves this pair.",
        ))
    return found


def _cross_tenant_hypotheses(model, cells) -> tuple[list[Hypothesis], list[str]]:
    grouped: dict[tuple[str, str], list[Cell]] = {}
    undetermined: dict[tuple[str, str], str] = {}

    for cell in cells:
        reaches = cell.verdict in (ALLOWED, CONFLICTED) or cell.grant_path
        if not reaches:
            continue
        if cell.tenancy in (UNDECLARED_IDENTITY_TENANT, UNDECLARED_RESOURCE_TENANT):
            side = ("identity" if cell.tenancy == UNDECLARED_IDENTITY_TENANT else "resource")
            subject = cell.identity if side == "identity" else cell.resource
            undetermined.setdefault(
                (cell.identity, cell.resource),
                f"{cell.identity} -> {cell.resource}: cross-tenant reachability could not be "
                f"assessed because {side} {subject} declares no tenant",
            )
            continue
        if cell.tenancy in (SHARED_STORE, FOREIGN_TENANT):
            scoped = [p for p in model.policies
                      if p.id in set(cell.deciding_policies) and p.tenant_scoped]
            if scoped:
                continue
            grouped.setdefault((cell.identity, cell.resource), []).append(cell)

    found = []
    for (identity_id, resource_id), group in sorted(grouped.items()):
        identity = model.identities[identity_id]
        resource = model.resources.get(resource_id)
        actions = tuple(sorted(c.action for c in group))
        policies = tuple(sorted({p for c in group for p in c.deciding_policies}))
        if group[0].tenancy == SHARED_STORE:
            statement = (
                f"{identity_id} (tenant {identity.tenant}) reaches {resource_id} for "
                f"{_listed(actions)}. {resource_id} is declared as a shared multi-tenant store "
                f"and no governing policy carries a subject-tenant predicate, so nothing "
                f"declared keeps the read inside one tenant."
            )
        else:
            owner = resource.tenant if resource else "another tenant"
            statement = (
                f"{identity_id} (tenant {identity.tenant}) reaches {resource_id}, which is owned "
                f"by tenant {owner}, for {_listed(actions)}, and no governing policy carries a "
                f"subject-tenant predicate."
            )
        found.append(Hypothesis(
            CROSS_TENANT_PATH, statement, resource_id, actions, (identity_id,),
            policies, _sources(model, policies),
            f"As {identity_id}, request {resource_id} rows belonging to a different tenant. If "
            f"any are returned, the path is real.",
            "The query, the ORM scope or a row-level policy adds the tenant predicate at a layer "
            "these declarations do not describe.",
        ))
    return found, sorted(undetermined.values())


_KIND_ORDER = {kind: index for index, kind in enumerate(HYPOTHESIS_KINDS)}


def _assign_ids(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    ordered = sorted(
        hypotheses,
        key=lambda h: (_KIND_ORDER[h.kind], h.resource, h.actions, h.identities, h.policies),
    )
    return [replace(h, hypothesis_id=f"AUTHZ-H-{i:04d}") for i, h in enumerate(ordered, 1)]


# --------------------------------------------------------------------------- #
# Result
# --------------------------------------------------------------------------- #

NOTES = (
    "Every entry in hypotheses is a HYPOTHESIS derived from declarations. The graph reports what "
    "the declarations say; whether an edge is reachable at runtime is unproven.",
    "UNKNOWN and UNGOVERNED are not denials. A cell is DENIED only when a server-enforced DENY "
    "policy matches it; missing policy information is never read as a block.",
    CLIENT_CHECK_STATEMENT + " A client-side gate is never counted as authorization.",
    "No severity is assigned here. Severity belongs to a verified finding.",
)


@dataclass(frozen=True)
class AuthorizationGraph:
    model: AuthorizationModel
    cells: tuple[Cell, ...]
    hypotheses: tuple[Hypothesis, ...]
    undetermined: tuple[str, ...]

    # -- graph form -------------------------------------------------------- #

    def graph(self) -> dict[str, Any]:
        """Nodes and edges, JSON-serializable and stable, ready for Mermaid."""
        return build_graph_form(self.model)

    # -- matrix form ------------------------------------------------------- #

    def matrix(self) -> dict[str, Any]:
        """Identity x resource-action, with the verdict and its basis in each cell."""
        column_ids = sorted({f"{c.resource}:{c.action}" for c in self.cells})
        rows: dict[str, dict[str, Any]] = {}
        for cell in self.cells:
            rows.setdefault(cell.identity, {})[f"{cell.resource}:{cell.action}"] = cell.as_dict()
        counts = {verdict: 0 for verdict in VERDICTS}
        for cell in self.cells:
            counts[cell.verdict] += 1
        return {
            "columns": column_ids,
            "identities": sorted(rows),
            "rows": [{"identity": identity, "cells": rows[identity]} for identity in sorted(rows)],
            "verdict_counts": counts,
            "legend": dict(VERDICT_MEANINGS),
            "denial_verdicts": sorted(DENIAL_VERDICTS),
        }

    def cell(self, identity: str, resource: str, action: str) -> Cell | None:
        for candidate in self.cells:
            if (candidate.identity, candidate.resource, candidate.action) == (
                    identity, resource, action):
                return candidate
        return None

    def as_dict(self) -> dict[str, Any]:
        by_kind = {kind: 0 for kind in HYPOTHESIS_KINDS}
        for hypothesis in self.hypotheses:
            by_kind[hypothesis.kind] += 1
        return {
            "schema_version": "1.0",
            "graph": self.graph(),
            "matrix": self.matrix(),
            "hypotheses": [h.as_dict() for h in self.hypotheses],
            "hypothesis_counts": by_kind,
            "declaration_gaps": list(self.model.declaration_gaps),
            "undetermined": list(self.undetermined),
            "notes": list(NOTES),
        }


def build_authorization_graph(declarations: Mapping[str, Any]) -> AuthorizationGraph:
    """Build the graph, the matrix and the hypotheses from declarations."""
    model = load_declarations(declarations)

    grants = {ident: granted_pairs(model, identity)
              for ident, identity in model.identities.items()}
    roles = {ident: effective_roles(model, identity)
             for ident, identity in model.identities.items()}
    grid = columns(model)

    cells: list[Cell] = []
    cells_by_column: dict[tuple[str, str], list[Cell]] = {}
    for identity_id in sorted(model.identities):
        identity = model.identities[identity_id]
        for resource_id, action in grid:
            cell = _cell(model, identity, roles[identity_id], resource_id, action,
                         grants[identity_id])
            cells.append(cell)
            cells_by_column.setdefault((resource_id, action), []).append(cell)

    # A column no identity is declared to reach still has to be examined: a
    # resource nobody is declared to reach is not a resource nobody reaches.
    for resource_id, action in grid:
        cells_by_column.setdefault((resource_id, action), [])

    hypotheses: list[Hypothesis] = []
    hypotheses += _missing_policy_hypotheses(model, cells_by_column)
    hypotheses += _ui_only_hypotheses(model, cells_by_column)
    hypotheses += _unexpected_grant_hypotheses(model, cells)
    hypotheses += _conflict_hypotheses(model, cells)
    cross_tenant, undetermined = _cross_tenant_hypotheses(model, cells)
    hypotheses += cross_tenant

    return AuthorizationGraph(
        model, tuple(cells), tuple(_assign_ids(hypotheses)), tuple(undetermined),
    )


# --------------------------------------------------------------------------- #
# Graph form and rendering
# --------------------------------------------------------------------------- #


def _node(node_id: str, kind: str, label: str, **attributes: Any) -> dict[str, Any]:
    return {"id": node_id, "kind": kind, "label": label, "attributes": attributes}


def build_graph_form(model: AuthorizationModel) -> dict[str, Any]:
    """The declaration graph as nodes and edges.

    Wildcards are nodes of their own rather than being expanded, because
    ``subject: "*"`` on a policy is a fact about the policy — expanding it into
    one edge per identity would hide the single most important thing about it.
    """
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add(node_id: str, kind: str, label: str, **attributes: Any) -> str:
        nodes.setdefault(node_id, _node(node_id, kind, label, **attributes))
        return node_id

    def link(source: str, target: str, kind: str, label: str, **attributes: Any) -> None:
        edges.append({"from": source, "to": target, "kind": kind, "label": label,
                      "attributes": attributes})

    for identity in model.identities.values():
        add(f"identity:{identity.id}", IDENTITY, identity.id,
            tenant=identity.tenant, identity_kind=identity.kind)
    for role in model.roles.values():
        add(f"role:{role.id}", ROLE, role.id)
    for permission in model.permissions.values():
        add(f"permission:{permission.id}", PERMISSION, permission.id)
    for resource in model.resources.values():
        add(f"resource:{resource.id}", RESOURCE, resource.id, tenant=resource.tenant)
        for action in resource.actions:
            add(f"action:{action}", ACTION, action)
            link(f"resource:{resource.id}", f"action:{action}", "EXPOSES", "exposes")

    for identity in model.identities.values():
        for role_id in identity.roles:
            add(f"role:{role_id}", ROLE, role_id)
            link(f"identity:{identity.id}", f"role:{role_id}", "HOLDS_ROLE", "holds")
    for role in model.roles.values():
        for parent in role.inherits:
            add(f"role:{parent}", ROLE, parent)
            link(f"role:{role.id}", f"role:{parent}", "INHERITS", "inherits")
        for permission_id in role.permissions:
            add(f"permission:{permission_id}", PERMISSION, permission_id)
            link(f"role:{role.id}", f"permission:{permission_id}", "GRANTS", "grants")
    for permission in model.permissions.values():
        target = permission.resource
        add(f"resource:{target}", RESOURCE,
            "any resource (*)" if target == WILDCARD else target, wildcard=target == WILDCARD)
        link(f"permission:{permission.id}", f"resource:{target}", "TARGETS", "on")
        add(f"action:{permission.action}", ACTION,
            "any action (*)" if permission.action == WILDCARD else permission.action,
            wildcard=permission.action == WILDCARD)
        link(f"permission:{permission.id}", f"action:{permission.action}", "PERMITS", "permits")

    for policy in model.policies:
        add(f"policy:{policy.id}", POLICY, policy.id,
            effect=policy.effect, enforced_at=policy.enforced_at,
            tenant_scoped=policy.tenant_scoped, source=policy.source,
            is_authorization_control=policy.server_side)
        if policy.subject == WILDCARD:
            subject_node = add("identity:*", IDENTITY, "any subject (*)", wildcard=True)
        elif policy.subject.startswith("identity:"):
            subject_node = add(policy.subject, IDENTITY, policy.subject[len("identity:"):])
        else:
            role_id = policy.subject[len("role:"):]
            subject_node = add(f"role:{role_id}", ROLE, role_id)
        link(subject_node, f"policy:{policy.id}", "SUBJECT_OF", "subject of")
        resource_node = add(
            f"resource:{policy.resource}", RESOURCE,
            "any resource (*)" if policy.resource == WILDCARD else policy.resource,
            wildcard=policy.resource == WILDCARD,
        )
        link(f"policy:{policy.id}", resource_node, "GOVERNS",
             f"{policy.effect} {policy.action} @{policy.enforced_at}",
             effect=policy.effect, enforced_at=policy.enforced_at)
        action_node = add(
            f"action:{policy.action}", ACTION,
            "any action (*)" if policy.action == WILDCARD else policy.action,
            wildcard=policy.action == WILDCARD,
        )
        link(f"policy:{policy.id}", action_node, "GOVERNS_ACTION", policy.effect)

    ordered_edges = sorted(
        edges, key=lambda e: (e["kind"], e["from"], e["to"], e["label"])
    )
    for index, edge in enumerate(ordered_edges, 1):
        edge["id"] = f"e{index:04d}"
    return {
        "directed": True,
        "node_kinds": list(NODE_KINDS),
        "nodes": [nodes[node_id] for node_id in sorted(nodes)],
        "edges": ordered_edges,
    }


def _escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("|", "&#124;")
        .replace("\r", " ")
        .replace("\n", " ")
    )


_SHAPES = {
    IDENTITY: ('(["', '"])'),
    ROLE: ('[["', '"]]'),
    PERMISSION: ('["', '"]'),
    RESOURCE: ('[("', '")]'),
    ACTION: ('{{"', '"}}'),
    POLICY: ('{"', '"}'),
}


def render_mermaid(graph: Mapping[str, Any], direction: str = "LR") -> str:
    """Render the graph form as a Mermaid flowchart, deterministically."""
    if direction not in {"LR", "RL", "TB", "BT"}:
        raise AuthorizationGraphError("direction must be one of LR, RL, TB, BT")
    nodes = sorted(graph.get("nodes", []), key=lambda node: node["id"])
    aliases = {node["id"]: f"n{index:04d}" for index, node in enumerate(nodes, 1)}
    lines = [f"flowchart {direction}"]
    for node in nodes:
        opener, closer = _SHAPES.get(node.get("kind", ""), ('["', '"]'))
        lines.append(f'  {aliases[node["id"]]}{opener}{_escape(node["label"])}{closer}')
    for edge in graph.get("edges", []):
        source, target = aliases.get(edge["from"]), aliases.get(edge["to"])
        if source is None or target is None:
            continue
        lines.append(f'  {source} -->|"{_escape(edge["label"])}"| {target}')
    return "\n".join(lines) + "\n"
