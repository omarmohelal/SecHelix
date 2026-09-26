#!/usr/bin/env python3
"""Deterministic LOCAL benchmark for SecHelix dynamic proof primitives.

This is intentionally narrower than a full SecHelix workflow benchmark. It
measures whether bounded proof executors distinguish paired vulnerable and clean
LOCAL fixtures. It does not measure model reasoning, candidate generation,
independent verification, remediation, or release-gate accuracy.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Sequence

from sechelix_runner.proof import ProofClass, build_plan
from sechelix_runner.proof_exec import (
    LocalProofExecutor,
    MoneyFlowInvariantHttpSpec,
    PaymentInvariantHttpSpec,
    ProofBehavior,
    SettlementRefundSequenceHttpSpec,
    StateTransitionHttpSpec,
    WorkflowSequenceHttpSpec,
)
from sechelix_runner.sandbox import ExecutionMode, NetworkPolicy


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    family: str
    expected: ProofBehavior
    run: Callable[[str, LocalProofExecutor], object]


class _Handler(BaseHTTPRequestHandler):
    state_vulnerable = "cancelled"
    state_clean = "cancelled"
    payment_vulnerable = 10_000
    payment_clean = 10_000
    workflow_vulnerable = "created"
    workflow_clean = "created"
    money_flow_vulnerable = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    money_flow_clean = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    settlement_refund_vulnerable = {"customer": 10_000, "worker": 1_000, "platform": 500}
    settlement_refund_clean = {"customer": 10_000, "worker": 1_000, "platform": 500}
    settlement_refund_vulnerable_settle_count = 0
    settlement_refund_vulnerable_refund_count = 0
    settlement_refund_clean_settle_count = 0
    settlement_refund_clean_refund_count = 0

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)

        if self.path == "/state/vulnerable":
            type(self).state_vulnerable = "completed"
            self._send(200)
            return
        if self.path == "/state/clean":
            self._send(409)
            return

        if self.path == "/payment/vulnerable":
            type(self).payment_vulnerable -= 250
            self._send(200)
            return
        if self.path == "/payment/clean":
            if type(self).payment_clean == 10_000:
                type(self).payment_clean -= 250
            self._send(200)
            return

        if self.path == "/money-flow/vulnerable":
            state = type(self).money_flow_vulnerable
            state["buyer"] -= 1000
            state["seller"] += 900
            state["platform"] += 100
            self._send(200)
            return
        if self.path == "/money-flow/clean":
            state = type(self).money_flow_clean
            if state["buyer"] == 10_000:
                state["buyer"] -= 1000
                state["seller"] += 900
                state["platform"] += 100
            self._send(200)
            return

        if self.path == "/settlement-refund/vulnerable/settle":
            state = type(self).settlement_refund_vulnerable
            state["customer"] -= 1000
            state["worker"] += 800
            state["platform"] += 200
            type(self).settlement_refund_vulnerable_settle_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/vulnerable/refund":
            state = type(self).settlement_refund_vulnerable
            # Settlement is idempotent enough for the control path, but the
            # partial refund is incorrectly applied on every replay.
            if type(self).settlement_refund_vulnerable_refund_count >= 0:
                state["customer"] += 400
                state["worker"] -= 320
                state["platform"] -= 80
            type(self).settlement_refund_vulnerable_refund_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/clean/settle":
            state = type(self).settlement_refund_clean
            if type(self).settlement_refund_clean_settle_count == 0:
                state["customer"] -= 1000
                state["worker"] += 800
                state["platform"] += 200
            type(self).settlement_refund_clean_settle_count += 1
            self._send(200)
            return
        if self.path == "/settlement-refund/clean/refund":
            state = type(self).settlement_refund_clean
            if type(self).settlement_refund_clean_refund_count == 0:
                state["customer"] += 400
                state["worker"] -= 320
                state["platform"] -= 80
            type(self).settlement_refund_clean_refund_count += 1
            self._send(200)
            return

        if self.path == "/workflow/vulnerable/step1":
            if type(self).workflow_vulnerable != "created":
                self._send(409)
                return
            type(self).workflow_vulnerable = "approved"
            self._send(200)
            return
        if self.path == "/workflow/vulnerable/step2":
            type(self).workflow_vulnerable = "completed"
            self._send(200)
            return

        if self.path == "/workflow/clean/step1":
            if type(self).workflow_clean != "created":
                self._send(409)
                return
            type(self).workflow_clean = "approved"
            self._send(200)
            return
        if self.path == "/workflow/clean/step2":
            if type(self).workflow_clean != "approved":
                self._send(409)
                return
            type(self).workflow_clean = "completed"
            self._send(200)
            return

        self._send(404)

    def _send(self, status: int) -> None:
        body = b"ok"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *args: object) -> None:
        return


def _reset() -> None:
    _Handler.state_vulnerable = "cancelled"
    _Handler.state_clean = "cancelled"
    _Handler.payment_vulnerable = 10_000
    _Handler.payment_clean = 10_000
    _Handler.workflow_vulnerable = "created"
    _Handler.workflow_clean = "created"
    _Handler.money_flow_vulnerable = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    _Handler.money_flow_clean = {"buyer": 10_000, "seller": 2_000, "platform": 500}
    _Handler.settlement_refund_vulnerable = {"customer": 10_000, "worker": 1_000, "platform": 500}
    _Handler.settlement_refund_clean = {"customer": 10_000, "worker": 1_000, "platform": 500}
    _Handler.settlement_refund_vulnerable_settle_count = 0
    _Handler.settlement_refund_vulnerable_refund_count = 0
    _Handler.settlement_refund_clean_settle_count = 0
    _Handler.settlement_refund_clean_refund_count = 0


def _cases() -> tuple[BenchmarkCase, ...]:
    def state_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "BENCH-STATE-VULN",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        return executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=base + "/state/vulnerable",
                read_state=lambda: _Handler.state_vulnerable,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )

    def state_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.STATE_TRANSITION,
            "BENCH-STATE-CLEAN",
            available_authority={"fixture_write_access", "fixture_state_readback"},
        )
        return executor.execute(
            plan,
            StateTransitionHttpSpec(
                url=base + "/state/clean",
                read_state=lambda: _Handler.state_clean,
                expected_start_state="cancelled",
                expected_secure_state="cancelled",
                forbidden_state="completed",
            ),
        )

    def payment_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "BENCH-PAYMENT-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=base + "/payment/vulnerable",
                read_balance_minor=lambda: _Handler.payment_vulnerable,
                expected_single_delta_minor=-250,
            ),
        )

    def payment_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.PAYMENT_INVARIANT,
            "BENCH-PAYMENT-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            PaymentInvariantHttpSpec(
                url=base + "/payment/clean",
                read_balance_minor=lambda: _Handler.payment_clean,
                expected_single_delta_minor=-250,
            ),
        )

    def money_flow_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "BENCH-MONEY-FLOW-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=base + "/money-flow/vulnerable",
                read_balances_minor=lambda: dict(_Handler.money_flow_vulnerable),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )

    def money_flow_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.MONEY_FLOW_INVARIANT,
            "BENCH-MONEY-FLOW-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            MoneyFlowInvariantHttpSpec(
                url=base + "/money-flow/clean",
                read_balances_minor=lambda: dict(_Handler.money_flow_clean),
                expected_deltas_minor={"buyer": -1000, "seller": 900, "platform": 100},
            ),
        )

    def settlement_refund_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SETTLEMENT_REFUND_SEQUENCE,
            "BENCH-SETTLEMENT-REFUND-VULN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            SettlementRefundSequenceHttpSpec(
                settlement_url=base + "/settlement-refund/vulnerable/settle",
                refund_url=base + "/settlement-refund/vulnerable/refund",
                read_balances_minor=lambda: dict(_Handler.settlement_refund_vulnerable),
                expected_settlement_deltas_minor={
                    "customer": -1000,
                    "worker": 800,
                    "platform": 200,
                },
                expected_refund_deltas_minor={
                    "customer": 400,
                    "worker": -320,
                    "platform": -80,
                },
            ),
        )

    def settlement_refund_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.SETTLEMENT_REFUND_SEQUENCE,
            "BENCH-SETTLEMENT-REFUND-CLEAN",
            available_authority={"fixture_write_access", "fixture_financial_readback"},
        )
        return executor.execute(
            plan,
            SettlementRefundSequenceHttpSpec(
                settlement_url=base + "/settlement-refund/clean/settle",
                refund_url=base + "/settlement-refund/clean/refund",
                read_balances_minor=lambda: dict(_Handler.settlement_refund_clean),
                expected_settlement_deltas_minor={
                    "customer": -1000,
                    "worker": 800,
                    "platform": 200,
                },
                expected_refund_deltas_minor={
                    "customer": 400,
                    "worker": -320,
                    "platform": -80,
                },
            ),
        )

    def workflow_vulnerable(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "BENCH-WORKFLOW-VULN",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _Handler.workflow_vulnerable = "created"
            return True

        return executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=base + "/workflow/vulnerable/step1",
                step_two_url=base + "/workflow/vulnerable/step2",
                read_state=lambda: _Handler.workflow_vulnerable,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )

    def workflow_clean(base: str, executor: LocalProofExecutor):
        plan = build_plan(
            ProofClass.WORKFLOW_SEQUENCE,
            "BENCH-WORKFLOW-CLEAN",
            available_authority={
                "fixture_write_access",
                "fixture_state_readback",
                "fixture_reset",
            },
        )

        def reset_fixture() -> bool:
            _Handler.workflow_clean = "created"
            return True

        return executor.execute(
            plan,
            WorkflowSequenceHttpSpec(
                step_one_url=base + "/workflow/clean/step1",
                step_two_url=base + "/workflow/clean/step2",
                read_state=lambda: _Handler.workflow_clean,
                reset_fixture=reset_fixture,
                expected_start_state="created",
                expected_intermediate_state="approved",
                expected_final_state="completed",
                expected_safe_bypass_state="created",
            ),
        )

    return (
        BenchmarkCase("STATE-VULNERABLE", "state-transition", ProofBehavior.VULNERABLE_BEHAVIOR, state_vulnerable),
        BenchmarkCase("STATE-CLEAN", "state-transition", ProofBehavior.SECURE_BEHAVIOR, state_clean),
        BenchmarkCase("PAYMENT-VULNERABLE", "payment-invariant", ProofBehavior.VULNERABLE_BEHAVIOR, payment_vulnerable),
        BenchmarkCase("PAYMENT-CLEAN", "payment-invariant", ProofBehavior.SECURE_BEHAVIOR, payment_clean),
        BenchmarkCase("MONEY-FLOW-VULNERABLE", "money-flow-invariant", ProofBehavior.VULNERABLE_BEHAVIOR, money_flow_vulnerable),
        BenchmarkCase("MONEY-FLOW-CLEAN", "money-flow-invariant", ProofBehavior.SECURE_BEHAVIOR, money_flow_clean),
        BenchmarkCase("SETTLEMENT-REFUND-VULNERABLE", "settlement-refund-sequence", ProofBehavior.VULNERABLE_BEHAVIOR, settlement_refund_vulnerable),
        BenchmarkCase("SETTLEMENT-REFUND-CLEAN", "settlement-refund-sequence", ProofBehavior.SECURE_BEHAVIOR, settlement_refund_clean),
        BenchmarkCase("WORKFLOW-VULNERABLE", "workflow-sequence", ProofBehavior.VULNERABLE_BEHAVIOR, workflow_vulnerable),
        BenchmarkCase("WORKFLOW-CLEAN", "workflow-sequence", ProofBehavior.SECURE_BEHAVIOR, workflow_clean),
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def run_dynamic_proof_benchmark(*, sechelix_commit: str = "NOT_MEASURED") -> dict[str, object]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    policy = NetworkPolicy(ExecutionMode.LOCAL)
    policy.grant(
        "127.0.0.1",
        port,
        protocol="http",
        purpose="SecHelix deterministic dynamic proof benchmark",
        scope_id="EVAL-DYNAMIC-PROOFS",
    )
    executor = LocalProofExecutor(policy, timeout_seconds=2, max_requests=8)
    base = f"http://127.0.0.1:{port}"

    rows: list[dict[str, object]] = []
    started = time.perf_counter()
    try:
        for case in _cases():
            _reset()
            case_started = time.perf_counter()
            result = case.run(base, executor)
            elapsed_ms = round((time.perf_counter() - case_started) * 1000, 3)
            behavior = result.behavior
            rows.append(
                {
                    "case_id": case.case_id,
                    "family": case.family,
                    "expected_behavior": case.expected.value,
                    "observed_behavior": behavior.value,
                    "correct": behavior is case.expected,
                    "request_count": result.request_count,
                    "elapsed_ms": elapsed_ms,
                    "promotes_finding": result.to_dict()["promotes_finding"],
                }
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    duration_ms = round((time.perf_counter() - started) * 1000, 3)
    vulnerable_rows = [row for row in rows if row["expected_behavior"] == ProofBehavior.VULNERABLE_BEHAVIOR.value]
    clean_rows = [row for row in rows if row["expected_behavior"] == ProofBehavior.SECURE_BEHAVIOR.value]
    inconclusive = sum(row["observed_behavior"] == ProofBehavior.INCONCLUSIVE.value for row in rows)
    correct = sum(bool(row["correct"]) for row in rows)

    return {
        "schema_version": "sechelix-dynamic-proof-benchmark/v1",
        "measurement_status": "MEASURED",
        "result_kind": "DYNAMIC_PROOF_PRIMITIVE_BENCHMARK",
        "is_full_sechelix_workflow": False,
        "run": {
            "sechelix_commit": sechelix_commit,
            "execution_mode": "LOCAL",
            "network_scope": "literal-loopback-only",
            "case_count": len(rows),
            "duration_ms": duration_ms,
            "model": "NONE",
            "provider": "NONE",
            "external_scanners": [],
        },
        "metrics": {
            "case_accuracy": _ratio(correct, len(rows)),
            "vulnerable_behavior_recall": _ratio(
                sum(bool(row["correct"]) for row in vulnerable_rows),
                len(vulnerable_rows),
            ),
            "clean_behavior_rejection_rate": _ratio(
                sum(bool(row["correct"]) for row in clean_rows),
                len(clean_rows),
            ),
            "inconclusive_rate": _ratio(inconclusive, len(rows)),
        },
        "cases": rows,
        "limitations": [
            "Measures deterministic proof primitives only, not candidate discovery or model reasoning.",
            "Does not measure independent-verifier accuracy, remediation, regression generation, or release-gate accuracy.",
            "Synthetic loopback fixtures do not represent production latency, concurrency, infrastructure, or deployment policy.",
            "A passing clean fixture establishes only the bounded declared invariant for that fixture.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--sechelix-commit", default="NOT_MEASURED")
    args = parser.parse_args(argv)

    result = run_dynamic_proof_benchmark(sechelix_commit=args.sechelix_commit)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0 if result["metrics"]["case_accuracy"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
