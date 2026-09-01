#!/usr/bin/env python3
"""Apply an organization policy to a canonical SecHelix JSON report.

Exit codes: 0 for PASS/PASS_WITH_KNOWN_RISK, 1 for BLOCKED, and 2 for
INCOMPLETE or malformed input.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sechelix_core.revision import assess_freshness  # noqa: E402

SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
FINDING_STATUSES = {
    "HYPOTHESIS", "VERIFIED", "LIKELY_BUT_UNPROVEN", "LIKELY_UNPROVEN",
    "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE", "BLOCKED",
    "BLOCKED_BY_ENVIRONMENT", "UNPROVEN",
}
RESOLUTIONS = {"OPEN", "FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE"}
UNPROVEN_STATES = {"LIKELY_BUT_UNPROVEN", "LIKELY_UNPROVEN", "BLOCKED", "BLOCKED_BY_ENVIRONMENT", "UNPROVEN"}
UNKNOWN_CHECK_STATES = {"UNKNOWN", "UNKNOWN_NEEDS_EVIDENCE", "BLOCKED", "BLOCKED_BY_ENVIRONMENT"}
CLOSED_RESOLUTIONS = {"FIXED", "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE"}
REQUIRED_REPORT_KEYS = (
    "schema_version", "report_id", "scope_id", "mode", "coverage",
    "findings", "blocked_checks", "release_recommendation",
)
COVERAGE_STATE_KEYS = ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED")
COVERAGE_KEYS = COVERAGE_STATE_KEYS + ("integrity_critical_unknown",)
EXECUTION_MODES = {"STATIC", "LOCAL", "STAGING", "PRODUCTION_SAFE"}
RELEASE_OUTCOMES = {"PASS", "PASS_WITH_KNOWN_RISK", "BLOCKED", "INCOMPLETE"}
REQUIRED_POLICY_KEYS = (
    "name",
    "blocking_severities",
    "require_independent_verification_for",
    "require_regression_for",
    "allow_accepted_risk",
    "accepted_risk_required_fields",
    "integrity_critical_unknown_outcome",
)


class GateInputError(ValueError):
    """The report or policy cannot support a trustworthy gate decision."""


@dataclass(frozen=True)
class GateDecision:
    outcome: str
    reasons: tuple[str, ...]
    blockers: tuple[str, ...] = ()
    incomplete: tuple[str, ...] = ()
    accepted_risks: tuple[str, ...] = ()

    @property
    def exit_code(self) -> int:
        if self.outcome == "BLOCKED":
            return 1
        if self.outcome == "INCOMPLETE":
            return 2
        return 0


def _uppercase_set(value: Any, field: str, allowed: set[str] | None = None) -> set[str]:
    if not isinstance(value, list) or not value:
        raise GateInputError(f"policy {field} must be a non-empty array")
    result = {str(item).upper() for item in value}
    if allowed is not None and not result <= allowed:
        raise GateInputError(f"policy {field} contains unsupported values: {sorted(result - allowed)}")
    return result


def validate_policy(policy: Mapping[str, Any]) -> None:
    if not isinstance(policy, Mapping):
        raise GateInputError("policy must be a JSON object")
    missing = [key for key in REQUIRED_POLICY_KEYS if key not in policy]
    if missing:
        raise GateInputError(f"policy missing required key(s): {', '.join(missing)}")
    _uppercase_set(policy["blocking_severities"], "blocking_severities", SEVERITIES)
    _uppercase_set(policy["require_independent_verification_for"], "require_independent_verification_for", SEVERITIES)
    _uppercase_set(policy["require_regression_for"], "require_regression_for", SEVERITIES)
    if not isinstance(policy["allow_accepted_risk"], bool):
        raise GateInputError("policy allow_accepted_risk must be boolean")
    if not isinstance(policy["accepted_risk_required_fields"], list):
        raise GateInputError("policy accepted_risk_required_fields must be an array")
    outcome = str(policy["integrity_critical_unknown_outcome"]).upper()
    if outcome not in {"BLOCKED", "INCOMPLETE"}:
        raise GateInputError("integrity_critical_unknown_outcome must be BLOCKED or INCOMPLETE")
    if "severity_overrides" in policy and not isinstance(policy["severity_overrides"], Mapping):
        raise GateInputError("policy severity_overrides must be an object")
    if "required_tools" in policy and not isinstance(policy["required_tools"], list):
        raise GateInputError("policy required_tools must be an array")
    if "forbidden_deployment_states" in policy and not isinstance(policy["forbidden_deployment_states"], list):
        raise GateInputError("policy forbidden_deployment_states must be an array")


def validate_report(report: Mapping[str, Any]) -> None:
    if not isinstance(report, Mapping):
        raise GateInputError("report must be a JSON object")
    missing = [key for key in REQUIRED_REPORT_KEYS if key not in report]
    if missing:
        raise GateInputError(f"report missing required key(s): {', '.join(missing)}")
    if str(report["mode"]).upper() not in EXECUTION_MODES:
        raise GateInputError(f"report mode must be one of {sorted(EXECUTION_MODES)}")
    if not isinstance(report["coverage"], Mapping):
        raise GateInputError("report coverage must be an object")
    missing_coverage = [key for key in COVERAGE_KEYS if key not in report["coverage"]]
    if missing_coverage:
        raise GateInputError(f"coverage missing required key(s): {', '.join(missing_coverage)}")
    coverage_values = [report["coverage"][key] for key in COVERAGE_KEYS]
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in coverage_values):
        raise GateInputError("coverage counts must be non-negative integers")
    if sum(report["coverage"][key] for key in COVERAGE_STATE_KEYS) == 0:
        raise GateInputError("coverage is empty; a release report must record applicability")
    if not isinstance(report["findings"], list):
        raise GateInputError("report findings must be an array")
    if not isinstance(report["blocked_checks"], list):
        raise GateInputError("report blocked_checks must be an array")
    finding_ids = []
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, Mapping):
            raise GateInputError(f"findings[{index}] must be an object")
        for key in ("finding_id", "title", "severity", "status"):
            if not str(finding.get(key, "")).strip():
                raise GateInputError(f"findings[{index}] missing {key}")
        if str(finding["severity"]).upper() not in SEVERITIES:
            raise GateInputError(f"findings[{index}] has unsupported severity {finding['severity']!r}")
        if str(finding["status"]).upper() not in FINDING_STATUSES:
            raise GateInputError(f"findings[{index}] has unsupported status {finding['status']!r}")
        if str(finding.get("resolution", "OPEN")).upper() not in RESOLUTIONS:
            raise GateInputError(f"findings[{index}] has unsupported resolution {finding.get('resolution')!r}")
        finding_ids.append(str(finding["finding_id"]))
    if len(finding_ids) != len(set(finding_ids)):
        raise GateInputError("finding IDs must be unique")
    if str(report["release_recommendation"]).upper() not in RELEASE_OUTCOMES:
        raise GateInputError(f"report release_recommendation must be one of {sorted(RELEASE_OUTCOMES)}")


def _verification_complete(finding: Mapping[str, Any]) -> bool:
    verification = finding.get("verification")
    return bool(
        isinstance(verification, Mapping)
        and verification.get("independent") is True
        and str(verification.get("outcome", "")).upper() == "VERIFIED"
        and str(verification.get("verifier", "")).strip()
        and verification.get("evidence_ids")
    )


def _parse_future_timestamp(value: Any, now: datetime) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed > now


def _regression_complete(finding: Mapping[str, Any]) -> bool:
    regression = finding.get("regression")
    return bool(
        isinstance(regression, Mapping)
        and str(regression.get("status", "")).upper() == "PASS"
        and (regression.get("assertion") or regression.get("evidence_ids"))
    )


def _accepted_risk_valid(finding: Mapping[str, Any], policy: Mapping[str, Any], now: datetime) -> tuple[bool, str]:
    if not policy["allow_accepted_risk"]:
        return False, "policy does not permit accepted risk"
    record = finding.get("accepted_risk")
    if not isinstance(record, Mapping):
        return False, "accepted_risk record is missing"
    for field in policy["accepted_risk_required_fields"]:
        if not str(record.get(str(field), "")).strip():
            return False, f"accepted_risk.{field} is required"
    if "expires_at" in policy["accepted_risk_required_fields"] and not _parse_future_timestamp(record.get("expires_at"), now):
        return False, "accepted_risk.expires_at must be a valid future timestamp"
    return True, "accepted risk is authorized by policy"


def _tool_names(report: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    for tool in report.get("tools", []):
        name = (tool.get("name") or tool.get("source")) if isinstance(tool, Mapping) else tool
        if name:
            names.add(str(name).lower())
    return names


def evaluate(
    report: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    now: datetime | None = None,
    enforce_contract: bool = True,
) -> GateDecision:
    """Evaluate a report without trusting its declared recommendation."""

    if enforce_contract:
        _assert_report_contract(report)
    validate_report(report)
    validate_policy(policy)
    now = now or datetime.now(timezone.utc)
    blocking_severities = _uppercase_set(policy["blocking_severities"], "blocking_severities", SEVERITIES)
    verification_severities = _uppercase_set(
        policy["require_independent_verification_for"], "require_independent_verification_for", SEVERITIES
    )
    regression_severities = _uppercase_set(policy["require_regression_for"], "require_regression_for", SEVERITIES)
    severity_overrides = {str(key): str(value).upper() for key, value in policy.get("severity_overrides", {}).items()}
    invalid_overrides = {value for value in severity_overrides.values() if value not in SEVERITIES}
    if invalid_overrides:
        raise GateInputError(f"policy severity_overrides contains unsupported severities: {sorted(invalid_overrides)}")

    blockers: list[str] = []
    incomplete: list[str] = []
    accepted_risks: list[str] = []

    deployment_state = str(report.get("deployment_state", "")).upper()
    forbidden_states = {str(item).upper() for item in policy.get("forbidden_deployment_states", [])}
    if deployment_state and deployment_state in forbidden_states:
        blockers.append(f"deployment state {deployment_state} is forbidden by policy")

    required_tools = {str(item).lower() for item in policy.get("required_tools", [])}
    missing_tools = sorted(required_tools - _tool_names(report))
    if missing_tools:
        incomplete.append(f"required evidence tool(s) not recorded: {', '.join(missing_tools)}")

    for finding in report["findings"]:
        finding_id = str(finding["finding_id"])
        severity = severity_overrides.get(finding_id, str(finding["severity"]).upper())
        status = str(finding["status"]).upper()
        resolution = str(finding.get("resolution", "OPEN")).upper()

        if severity in verification_severities and status == "VERIFIED" and not _verification_complete(finding):
            incomplete.append(f"{finding_id}: independent verification evidence is incomplete")
            continue
        if status in UNPROVEN_STATES and severity in blocking_severities:
            incomplete.append(f"{finding_id}: {severity} candidate remains {status}")
            continue
        if severity in regression_severities and status == "VERIFIED" and resolution == "FIXED" and not _regression_complete(finding):
            incomplete.append(f"{finding_id}: fixed {severity} finding lacks passing regression proof")
            continue
        if severity not in blocking_severities or status != "VERIFIED":
            continue
        if resolution in CLOSED_RESOLUTIONS:
            continue
        if resolution == "ACCEPTED_RISK":
            accepted, reason = _accepted_risk_valid(finding, policy, now)
            if accepted:
                accepted_risks.append(finding_id)
            else:
                blockers.append(f"{finding_id}: invalid accepted risk ({reason})")
            continue
        blockers.append(f"{finding_id}: unresolved verified {severity} finding")

    integrity_unknowns: list[str] = []
    for index, check in enumerate(report["blocked_checks"]):
        if isinstance(check, str):
            # report-v1 carries blocked checks as hypothesis IDs; the integrity signal
            # for those lives in coverage.integrity_critical_unknown.
            continue
        if not isinstance(check, Mapping):
            incomplete.append(f"blocked_checks[{index}] is not an object or hypothesis ID")
            continue
        status = str(check.get("status", "BLOCKED")).upper()
        if check.get("integrity_critical") is True and status in UNKNOWN_CHECK_STATES:
            integrity_unknowns.append(f"{check.get('id', f'blocked_checks[{index}]')}: integrity-critical evidence is {status}")
    coverage_unknown = report["coverage"].get("integrity_critical_unknown", 0)
    if isinstance(coverage_unknown, int) and coverage_unknown > 0:
        integrity_unknowns.append(f"coverage reports {coverage_unknown} integrity-critical unknown check(s)")
    if integrity_unknowns:
        if str(policy["integrity_critical_unknown_outcome"]).upper() == "BLOCKED":
            blockers.extend(integrity_unknowns)
        else:
            incomplete.extend(integrity_unknowns)

    if blockers:
        return GateDecision("BLOCKED", ("release-blocking policy conditions are unresolved",), tuple(blockers), tuple(incomplete), tuple(accepted_risks))
    if incomplete:
        return GateDecision("INCOMPLETE", ("required release evidence is unavailable or incomplete",), (), tuple(incomplete), tuple(accepted_risks))
    if accepted_risks:
        return GateDecision("PASS_WITH_KNOWN_RISK", ("all blockers are closed or explicitly accepted by policy",), (), (), tuple(accepted_risks))
    return GateDecision("PASS", ("no unresolved release-blocking conditions",))


def _load_json(path: Path, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateInputError(f"cannot read {label}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateInputError(f"invalid {label} JSON: {exc}") from exc
    if not isinstance(value, Mapping):
        raise GateInputError(f"{label} must contain a JSON object")
    return value


def _assert_report_contract(report: Mapping[str, Any]) -> None:
    """Refuse to gate a report that does not satisfy the canonical contract.

    A gate that scores a malformed report is fail-open: it can emit PASS for a
    document whose coverage, evidence, or finding semantics were never checked.
    """
    try:
        import sys

        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from sechelix_core.contracts import ContractValidationError, validate_contract
    except ImportError as exc:  # pragma: no cover - packaging failure
        raise GateInputError(f"cannot load the report contract validator: {exc}") from exc
    try:
        validate_contract("report", report)
    except ContractValidationError as exc:
        raise GateInputError(f"report does not satisfy the canonical report contract: {exc}") from exc


def _print_human(decision: GateDecision) -> None:
    print(f"{decision.outcome}: {decision.reasons[0]}")
    for item in decision.blockers:
        print(f"- BLOCKER: {item}")
    for item in decision.incomplete:
        print(f"- EVIDENCE GAP: {item}")
    for item in decision.accepted_risks:
        print(f"- ACCEPTED RISK: {item}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="canonical SecHelix JSON report")
    parser.add_argument("--policy", type=Path, default=ROOT / "policies/default.json", help="organization policy pack (JSON)")
    parser.add_argument("--json-output", action="store_true", help="emit the decision as JSON")
    parser.add_argument(
        "--current-commit",
        help="commit being released; the gate refuses a report bound to a different revision",
    )
    parser.add_argument(
        "--current-working-tree", choices=("CLEAN", "DIRTY"), default="CLEAN",
        help="whether the tree being released has uncommitted changes",
    )
    args = parser.parse_args(argv)
    try:
        report = _load_json(args.report, "report")
        if args.current_commit:
            # A report that describes another tree cannot gate this one.
            verdict = assess_freshness(
                report,
                current_commit=args.current_commit,
                current_working_tree=args.current_working_tree,
            )
            if not verdict.usable:
                raise GateInputError(f"report is not current for this release: {verdict.reason}")
        decision = evaluate(report, _load_json(args.policy, "policy"))
    except GateInputError as exc:
        decision = GateDecision("INCOMPLETE", (str(exc),), (), (str(exc),))
    if args.json_output:
        print(json.dumps(asdict(decision), indent=2, sort_keys=True))
    else:
        _print_human(decision)
    return decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
