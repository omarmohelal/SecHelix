"""Applicability-gated protocol review packs for the V4 runner.

These packs deepen existing stable SecHelix hypotheses; they do not mint new
catalog ids and they do not report vulnerabilities.  Detection only decides
which protocol-specific questions deserve a specialist lane.  Each question
names a bounded validation and an explicit false-positive/compensating-control
condition so "protocol present" can never become "protocol vulnerable".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable


class Protocol(StrEnum):
    GRAPHQL = "GRAPHQL"
    WEBSOCKET = "WEBSOCKET"
    GRPC = "GRPC"
    OAUTH_OIDC = "OAUTH_OIDC"
    SAML = "SAML"
    JWT_SESSION = "JWT_SESSION"
    WEBHOOK = "WEBHOOK"
    HTTP_DESYNC = "HTTP_DESYNC"
    CACHE_BOUNDARY = "CACHE_BOUNDARY"


@dataclass(frozen=True, slots=True)
class ProtocolCheck:
    check_id: str
    question: str
    safe_validation: str
    false_positive_filter: str

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "question": self.question,
            "safe_validation": self.safe_validation,
            "false_positive_filter": self.false_positive_filter,
        }


@dataclass(frozen=True, slots=True)
class ProtocolPack:
    protocol: Protocol
    markers: tuple[str, ...]
    catalog_hypothesis_ids: tuple[str, ...]
    threat_boundary: str
    checks: tuple[ProtocolCheck, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "sechelix-protocol-pack/v1",
            "protocol": self.protocol.value,
            "markers": list(self.markers),
            "catalog_hypothesis_ids": list(self.catalog_hypothesis_ids),
            "threat_boundary": self.threat_boundary,
            "checks": [check.to_dict() for check in self.checks],
        }


def _c(check_id: str, question: str, safe: str, fp: str) -> ProtocolCheck:
    return ProtocolCheck(check_id, question, safe, fp)


PACKS: dict[Protocol, ProtocolPack] = {
    Protocol.GRAPHQL: ProtocolPack(
        Protocol.GRAPHQL,
        ("graphql", "apollo", "urql", "relay", ".graphql", "graphene", "strawberry"),
        ("SHX-API-L01", "SHX-API-L04", "SHX-AUTHZ-L05"),
        "A query document can reach objects, fields and units of work beyond the first-party client's intended operation.",
        (
            _c("GQL-01", "Do generic node/entity resolvers apply the same viewer predicate as typed paths?", "With two synthetic identities, resolve one owned and one foreign object through typed and generic paths.", "Both entry points converge on the same viewer-scoped loader."),
            _c("GQL-02", "Can aliases, fragments, batching or recursive depth multiply expensive work without per-unit accounting?", "Use a small fixed query depth/alias count on LOCAL and compare server-enforced complexity accounting.", "Server-side depth/complexity/batch limits are evidenced and enforced before resolver work."),
            _c("GQL-03", "Do field resolvers inherit authorization from an expected parent instead of re-establishing object scope?", "Call the field through an alternate parent/generic path using a foreign synthetic subject.", "Resolver receives an already-authorized object from an enforcement layer that cannot be bypassed."),
            _c("GQL-04", "Do introspection, persisted-query fallbacks or debug schemas expose operations absent from the intended production surface?", "Inspect deployed schema/config and use one bounded LOCAL introspection/persisted-query request.", "Introspection/debug registration is disabled or intentionally public under a documented policy."),
        ),
    ),
    Protocol.WEBSOCKET: ProtocolPack(
        Protocol.WEBSOCKET,
        ("websocket", "socket.io", "sockjs", "ws://", "wss://", "websockets"),
        ("SHX-API-L01", "SHX-AUTHZ-L05", "SHX-SESS-L09"),
        "A long-lived connection can outlive or change the identity/object authorization established at handshake.",
        (
            _c("WS-01", "Is authorization re-evaluated per message/subscription when object scope changes?", "On LOCAL, authenticate once and request an owned then foreign synthetic channel/object.", "Topics are derived server-side from immutable connection identity and cannot be client-selected."),
            _c("WS-02", "What happens after session revocation, role change or tenant switch while the socket stays open?", "Revoke a synthetic session then send one benign follow-up message on the same connection.", "Server closes/re-authenticates the connection or checks current authorization on each message."),
            _c("WS-03", "Can origin/cross-site connection policy be bypassed where browser credentials attach automatically?", "Inspect Origin validation and make one LOCAL connection with a mismatched benign Origin.", "Non-browser bearer-token protocol is intentionally origin-independent and browser ambient credentials are not used."),
        ),
    ),
    Protocol.GRPC: ProtocolPack(
        Protocol.GRPC,
        ("grpc", ".proto", "protobuf", "grpcio", "tonic", "connectrpc"),
        ("SHX-API-L01", "SHX-AUTHZ-L05", "SHX-OPS-L09"),
        "RPC method identity, metadata and streaming lifetime can diverge from authorization applied at an HTTP gateway or initial handshake.",
        (
            _c("GRPC-01", "Does every RPC method enforce identity/role/object scope server-side rather than trusting a gateway?", "Invoke one method directly on LOCAL with owned and foreign fixture identities.", "The service interceptor/method guard is mandatory for direct and gateway calls."),
            _c("GRPC-02", "Are reflection/debug services exposed in the production registration set?", "Inspect registration and query reflection only on LOCAL.", "Reflection is intentionally enabled for authenticated operators and does not widen method authorization."),
            _c("GRPC-03", "Do streaming RPCs re-check authorization for messages or object changes after stream creation?", "Open a fixture stream, change/revoke its synthetic identity state, send one bounded message.", "Authorization state is bound immutably or revalidated per message."),
        ),
    ),
    Protocol.OAUTH_OIDC: ProtocolPack(
        Protocol.OAUTH_OIDC,
        ("oauth", "openid", "oidc", "pkce", "authorization_code", "jwks_uri"),
        ("SHX-AUTHN-L02", "SHX-SESS-L09", "SHX-CRYPTO-L03"),
        "Authorization response, client redirect, issuer/audience and token exchange must remain bound to the initiating client/session.",
        (
            _c("OIDC-01", "Are state, nonce and PKCE bound to the initiating browser/client and validated exactly once?", "Trace storage and compare one valid fixture callback with a mismatched state/nonce/verifier.", "Framework/library validation is evidenced at the callback before any session is created."),
            _c("OIDC-02", "Can redirect_uri or post-login return targets escape the registered/local allowlist?", "Use one benign alternate LOCAL URL and observe validation before redirect/token exchange.", "Exact registered redirect matching or a strict same-origin path allowlist is enforced."),
            _c("OIDC-03", "Are issuer, audience, signature algorithm and key source constrained before claims create local identity?", "Inspect verifier configuration and test a fixture token with wrong issuer/audience.", "Provider SDK pins these values and rejects the fixture before identity/session creation."),
            _c("OIDC-04", "Can account linking/login bind a provider identity to the wrong existing local account?", "Exercise synthetic duplicate-email/provider-subject cases without real external accounts.", "Linking requires an authenticated proof or immutable provider subject, not email coincidence alone."),
        ),
    ),
    Protocol.SAML: ProtocolPack(
        Protocol.SAML,
        ("saml", "saml2", "metadata.xml", "assertionconsumer", "acs"),
        ("SHX-AUTHN-L02", "SHX-CRYPTO-L03", "SHX-PARSER-L04"),
        "Signed assertion meaning depends on what element was signed, expected issuer/audience/destination and parser selection.",
        (
            _c("SAML-01", "Does the application consume the exact signed Assertion/Response rather than a sibling element selected after signature validation?", "Use a library-provided wrapping regression fixture or synthetic XML in LOCAL only.", "Library performs secure ID-based signed-element binding and duplicate IDs are rejected."),
            _c("SAML-02", "Are issuer, audience, recipient, destination and temporal conditions constrained to this SP?", "Validate a synthetic assertion with one mismatched condition at a time.", "SAML library enforces each condition before local session creation."),
            _c("SAML-03", "Are unsolicited responses or RelayState return URLs accepted outside the intended flow?", "Send a bounded fixture response with missing request binding / alternate local RelayState.", "IdP-initiated flow is intentionally supported with independent destination and return-target validation."),
        ),
    ),
    Protocol.JWT_SESSION: ProtocolPack(
        Protocol.JWT_SESSION,
        ("jwt", "jsonwebtoken", "jose", "pyjwt", "session", "refresh_token", "refresh-token"),
        ("SHX-SESS-L09", "SHX-AUTHN-L02", "SHX-CRYPTO-L03"),
        "Token signature is only one control; issuer/audience/lifetime/rotation/revocation and privilege freshness define session authority.",
        (
            _c("JWT-01", "Are accepted algorithms and key sources fixed independently of attacker-controlled token headers?", "Inspect verifier construction and test a fixture with an unapproved alg/kid.", "Mature library config fixes algorithm/key set and rejects unknown kid before claims use."),
            _c("JWT-02", "Are exp, nbf, issuer and audience validated before authorization claims are trusted?", "Use expired and wrong-audience fixture tokens locally.", "Central verifier requires all claims for every protected route."),
            _c("JWT-03", "Are refresh tokens rotated/replay-detected and are stolen/old tokens revoked after account or role changes?", "Replay one synthetic previous refresh token after a successful rotation.", "Token family rotation/revocation state rejects reuse and privilege changes invalidate relevant sessions."),
            _c("JWT-04", "Can client-controlled role/tenant claims remain authoritative after server-side membership changes?", "Change fixture membership then reuse the prior token for one protected action.", "Authorization re-derives mutable privilege server-side or uses short-lived/revocable authority with explicit policy."),
        ),
    ),
    Protocol.WEBHOOK: ProtocolPack(
        Protocol.WEBHOOK,
        ("webhook", "callback", "signature", "x-signature", "stripe-signature"),
        ("SHX-API-L05", "SHX-RACE-L04", "SHX-CRYPTO-L03"),
        "An unauthenticated inbound callback can mutate durable state unless authenticity, freshness and exactly-once semantics are established before effects.",
        (
            _c("WH-01", "Is the signature computed over the exact raw bytes and verified before JSON/body normalization or state change?", "LOCAL: compare valid, missing and wrong fixture signatures.", "Provider library validates exact raw payload and execution stops on failure."),
            _c("WH-02", "Are timestamp/freshness and replay/idempotency enforced independently?", "Replay one correctly signed synthetic event with the same event id.", "Duplicate delivery is accepted only as an idempotent no-op and stale timestamps are rejected."),
            _c("WH-03", "Does the callback trust price, owner, status or tenant fields that should be derived from server-side order/provider state?", "Alter one non-secret synthetic business field while keeping identity/event fixture valid.", "Handler resolves authoritative local/provider state by immutable event/order id before mutation."),
        ),
    ),
    Protocol.HTTP_DESYNC: ProtocolPack(
        Protocol.HTTP_DESYNC,
        ("nginx", "haproxy", "envoy", "traefik", "reverse_proxy", "proxy_pass", "http1"),
        ("SHX-HTTP-L05", "SHX-CONFIG-L03"),
        "Different HTTP parsers at adjacent hops may disagree on message boundaries, headers or normalized routing.",
        (
            _c("HTTP-01", "Do edge and origin disagree on Content-Length/Transfer-Encoding or HTTP/1 normalization?", "Prefer config/version analysis; any dynamic check must use a dedicated LOCAL proxy+origin fixture with one bounded ambiguous request.", "Stack is HTTP/2 end-to-end or front end normalizes/rejects ambiguous framing before reuse."),
            _c("HTTP-02", "Can duplicate Host/X-Forwarded-* or absolute-form targets influence security-sensitive routing differently at edge and app?", "Compare normalized request metadata across an owned LOCAL proxy/origin fixture.", "Only trusted proxy overwrites canonical forwarding headers and app trusts only that hop."),
            _c("HTTP-03", "Can path decoding/normalization differ between authorization/cache/proxy and application router?", "Use benign encoded path variants on LOCAL and compare route/security decisions.", "One canonical normalization occurs before every security/cache routing decision."),
        ),
    ),
    Protocol.CACHE_BOUNDARY: ProtocolPack(
        Protocol.CACHE_BOUNDARY,
        ("cache-control", "varnish", "cloudflare", "fastly", "cdn", "surrogate", "cache_key"),
        ("SHX-HTTP-L07", "SHX-PRIV-L05", "SHX-AUTHZ-L05"),
        "Cache keys and cacheability must include every request property that changes authorization or personalized response meaning.",
        (
            _c("CACHE-01", "Can an authenticated/personalized response become shared-cacheable?", "Inspect headers/config and use two fixture identities against an owned LOCAL cache if available.", "Private/no-store policy or cache partitioning is enforced before personalized content reaches a shared cache."),
            _c("CACHE-02", "Do unkeyed headers/query/path normalization influence the response and permit cache poisoning/deception?", "Vary one benign candidate input at a time and compare cache key/config, not production traffic volume.", "Input is ignored by origin or included/normalized in the cache key consistently."),
            _c("CACHE-03", "Can extension/path confusion make dynamic sensitive content look like a static cacheable asset?", "Use owned LOCAL route variants and inspect cacheability without storing real user data.", "Cache policy derives from resolved route/content class rather than attacker-controlled suffix alone."),
        ),
    ),
}


def _read_marker_text(root: Path, paths: Iterable[str], *, total_limit: int = 262_144) -> str:
    """Read small manifest/config files only; source content is not needed to route a pack."""
    chunks: list[str] = []
    used = 0
    for rel in paths:
        if used >= total_limit:
            break
        path = root / rel
        try:
            if path.stat().st_size > 128_000:
                continue
            data = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, ValueError):
            continue
        remaining = total_limit - used
        chunks.append(data[:remaining])
        used += min(len(data), remaining)
    return "\n".join(chunks).lower()


def detect_protocols(root: Path | str, world: dict[str, Any]) -> dict[Protocol, list[str]]:
    """Return protocols worth reviewing and the marker evidence that routed them.

    This function intentionally answers *presence*, not vulnerability.  A pack is
    routed when at least one marker occurs in file paths or small manifest/config
    content.  The returned marker strings are the provenance for that decision.
    """
    root = Path(root)
    files = [str(item) for item in world.get("file_index", [])]
    path_text = "\n".join(files).lower()
    detail_paths = list(world.get("manifests", [])) + list(world.get("config_files", []))
    manifest_text = _read_marker_text(root, detail_paths)
    haystack = path_text + "\n" + manifest_text

    detected: dict[Protocol, list[str]] = {}
    for protocol, pack in PACKS.items():
        hits = sorted({marker for marker in pack.markers if marker.lower() in haystack})
        if hits:
            detected[protocol] = hits
    return detected


def selected_packs(root: Path | str, world: dict[str, Any]) -> list[dict[str, Any]]:
    detected = detect_protocols(root, world)
    result: list[dict[str, Any]] = []
    for protocol in sorted(detected, key=lambda item: item.value):
        payload = PACKS[protocol].to_dict()
        payload["applicability"] = {
            "state": "APPLICABLE_FOR_REVIEW",
            "marker_evidence": detected[protocol],
            "note": "protocol presence routes questions; it is not vulnerability evidence",
        }
        result.append(payload)
    return result
