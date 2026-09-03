import unittest

from sechelix_runner.guidance import (
    DismissalExample,
    GuidanceEffect,
    GuidanceError,
    guidance_for_candidate,
    synthesize,
)
from sechelix_runner.threat_model import (
    Stride,
    Threat,
    ThreatModel,
    ThreatModelError,
    ThreatState,
    apply_adversarial_verdict,
    registry,
    validate_against_surface,
)


def attack_surface() -> dict:
    return {
        "schema_version": "1.0",
        "graph_id": "GRAPH-DEMO",
        "scope_id": "SCOPE-DEMO",
        "title": "demo",
        "nodes": [
            {"id": "N-ENTRY", "type": "ENTRYPOINT", "label": "API", "evidence_ids": ["EV-ENTRY"]},
            {"id": "N-STORE", "type": "STORE", "label": "Orders", "evidence_ids": ["EV-STORE"]},
        ],
        "edges": [
            {
                "id": "E-READ",
                "from": "N-ENTRY",
                "to": "N-STORE",
                "type": "READS",
                "label": "loads order",
                "evidence_ids": ["EV-EDGE"],
            }
        ],
        "boundaries": [
            {"id": "B-APP", "label": "application", "node_ids": ["N-ENTRY", "N-STORE"], "evidence_ids": []}
        ],
        "role_object_actions": [],
        "unknowns": [],
        "assumptions": [],
    }


class ThreatModelTests(unittest.TestCase):
    def candidate(self) -> Threat:
        return Threat(
            threat_id="THREAT-ORDER-READ",
            category=Stride.ELEVATION_OF_PRIVILEGE,
            statement="A caller may cross the order ownership boundary.",
            node_ids=("N-ENTRY", "N-STORE"),
        )

    def test_candidate_must_reference_real_attack_surface_nodes(self) -> None:
        model = ThreatModel("TM-DEMO", "GRAPH-DEMO", "SCOPE-DEMO", (self.candidate(),))
        validate_against_surface(model, attack_surface())
        bad = Threat(
            threat_id="THREAT-MISSING-NODE",
            category=Stride.TAMPERING,
            statement="generic claim",
            node_ids=("N-NOT-THERE",),
        )
        with self.assertRaises(ThreatModelError):
            validate_against_surface(
                ThreatModel("TM-DEMO", "GRAPH-DEMO", "SCOPE-DEMO", (bad,)),
                attack_surface(),
            )

    def test_supported_threat_requires_evidence(self) -> None:
        with self.assertRaises(ThreatModelError):
            Threat(
                threat_id="THREAT-NO-EVIDENCE",
                category=Stride.SPOOFING,
                statement="claim",
                node_ids=("N-ENTRY",),
                state=ThreatState.SUPPORTED,
            )

    def test_adversarial_pass_can_support_refute_or_leave_unknown(self) -> None:
        threat = self.candidate()
        supported = apply_adversarial_verdict(
            threat,
            state=ThreatState.SUPPORTED,
            rationale="ownership predicate is absent on the object lookup",
            evidence_ids=("EV-LOOKUP",),
        )
        self.assertEqual(supported.state, ThreatState.SUPPORTED)
        self.assertEqual(supported.evidence_ids, ("EV-LOOKUP",))

        refuted = apply_adversarial_verdict(
            threat,
            state=ThreatState.REFUTED,
            rationale="query is scoped by subject before the object leaves the repository",
        )
        self.assertEqual(refuted.state, ThreatState.REFUTED)

        unknown = apply_adversarial_verdict(threat, state=ThreatState.UNKNOWN, rationale="trace blocked")
        self.assertEqual(unknown.state, ThreatState.UNKNOWN)

        with self.assertRaises(ThreatModelError):
            apply_adversarial_verdict(threat, state=ThreatState.SUPPORTED, rationale="looks real")

    def test_registry_orders_supported_before_unresolved_and_refuted(self) -> None:
        base = self.candidate()
        supported = apply_adversarial_verdict(
            base,
            state=ThreatState.SUPPORTED,
            rationale="grounded",
            evidence_ids=("EV-1",),
        )
        refuted = apply_adversarial_verdict(base, state=ThreatState.REFUTED, rationale="killed")
        second = Threat(
            threat_id="THREAT-SECOND",
            category=Stride.INFORMATION_DISCLOSURE,
            statement="possible disclosure",
            node_ids=("N-STORE",),
            state=ThreatState.UNKNOWN,
        )
        model = ThreatModel("TM-DEMO", "GRAPH-DEMO", "SCOPE-DEMO", (refuted, second, supported))
        self.assertEqual([item["state"] for item in registry(model)], ["SUPPORTED", "UNKNOWN", "REFUTED"])


class GuidanceTests(unittest.TestCase):
    def example(self, number: int, target: str, control: str = "framework blocks javascript URLs") -> DismissalExample:
        return DismissalExample(
            example_id=f"FP-{number}",
            target_id=target,
            class_key="BROWSER_XSS",
            reason_code="COMPENSATING_CONTROL",
            compensating_control=control,
            verifier_rationale="the candidate reached a sink, but the runtime rewrote the dangerous scheme before navigation",
            framework_tags=("react",),
            evidence_ids=(f"EV-{number}",),
        )

    def test_guidance_requires_repeated_cross_target_dismissals(self) -> None:
        examples = [self.example(1, "A"), self.example(2, "A"), self.example(3, "A")]
        self.assertEqual(synthesize(examples), [])
        examples.append(self.example(4, "B"))
        rules = synthesize(examples)
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].effect, GuidanceEffect.REQUIRE_RECHECK)
        self.assertEqual(rules[0].target_count, 2)
        self.assertFalse(rules[0].to_dict()["auto_dismiss"])
        self.assertIn("not evidence for the current target", rules[0].check)

    def test_candidate_lookup_returns_questions_not_verdicts(self) -> None:
        rules = synthesize([self.example(1, "A"), self.example(2, "B"), self.example(3, "B")])
        matched = guidance_for_candidate(rules, "BROWSER_XSS")
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["effect"], "REQUIRE_RECHECK")
        self.assertFalse(matched[0]["auto_dismiss"])

    def test_guidance_rejects_secret_like_material(self) -> None:
        with self.assertRaises(GuidanceError):
            DismissalExample(
                example_id="FP-SECRET",
                target_id="A",
                class_key="SECRETS",
                reason_code="TEST",
                compensating_control="password=hunter2",
                verifier_rationale="fixture",
            )

    def test_guidance_rejects_single_target_policy(self) -> None:
        with self.assertRaises(GuidanceError):
            synthesize([self.example(1, "A"), self.example(2, "A")], min_targets=1)


if __name__ == "__main__":
    unittest.main()
