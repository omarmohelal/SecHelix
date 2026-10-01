from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from sechelix_core.attack_surface import validate_attack_surface
from sechelix_runner.pentest.attack_surface import build_live_attack_surface
from sechelix_runner.pentest.engagement import LiveEngagement
from sechelix_runner.pentest.scope import (
    AuthorizationContext,
    ScopeEndpoint,
    TargetScope,
)
from sechelix_runner.sandbox import ExecutionMode


def scope() -> TargetScope:
    return TargetScope(
        primary_url="https://staging.example.test",
        mode=ExecutionMode.STAGING,
        endpoints=(ScopeEndpoint("staging.example.test"),),
        ownership_verified=True,
        verification_method="scope-manifest:SCOPE-LIVE-TEST:owner",
        authorization=AuthorizationContext(
            scope_id="SCOPE-LIVE-TEST",
            basis="OWNER",
            statement="Fixture owner authorization.",
            authorized_by="fixture-owner",
            confirmed_at="2026-10-01T07:00:00Z",
        ),
    )


def world() -> dict:
    return {
        "browser_pages": [
            {
                "url": "https://staging.example.test/account",
                "title": "Account",
                "status": 200,
                "challenge": "NONE",
                "blocked_requests": 0,
            }
        ],
        "api_surfaces": [
            {
                "method": "GET",
                "surface": "https://staging.example.test/api/orders",
                "status": 200,
                "source": "browser",
            }
        ],
        "roles": ["buyer"],
        "authorization_matrix": [
            {
                "kind": "observed_api_surface",
                "method": "GET",
                "surface": "https://staging.example.test/api/orders",
                "observations": [
                    {
                        "profile_name": "buyer-fixture",
                        "role": "buyer",
                        "authenticated_evidence": True,
                        "status": 200,
                    }
                ],
                "observation_only": True,
            }
        ],
    }


class LiveAttackSurfaceTests(unittest.TestCase):
    def test_builder_emits_valid_observation_only_graph(self) -> None:
        graph = build_live_attack_surface(scope(), world())
        validate_attack_surface(graph)
        self.assertEqual(graph["scope_id"], "SCOPE-LIVE-TEST")
        self.assertTrue(graph["graph_id"].startswith("GRAPH-LIVE-"))
        self.assertEqual(
            graph["role_object_actions"][0]["decision"],
            "UNKNOWN",
        )
        self.assertEqual(
            graph["role_object_actions"][0]["enforcement_nodes"],
            [],
        )
        labels = {node["label"] for node in graph["nodes"]}
        self.assertIn("Role: buyer", labels)
        self.assertTrue(any(label.startswith("GET ") for label in labels))

    def test_builder_is_deterministic_for_same_observations(self) -> None:
        self.assertEqual(
            build_live_attack_surface(scope(), world()),
            build_live_attack_surface(scope(), world()),
        )

    def test_engagement_persists_graph_and_delta_hypotheses(self) -> None:
        base = build_live_attack_surface(scope(), world())
        newer_world = deepcopy(world())
        newer_world["api_surfaces"].append(
            {
                "method": "POST",
                "surface": "https://staging.example.test/api/refunds",
                "source": "openapi",
                "operation_id": "createRefund",
            }
        )
        newer = build_live_attack_surface(scope(), newer_world)

        with tempfile.TemporaryDirectory() as tmp:
            engagement = LiveEngagement(tmp, scope(), engagement_id="RUN-SURFACE-TEST")
            engagement.create()
            delta = engagement.record_attack_surface(
                newer,
                previous_graph=base,
            )
            graph_path = engagement.workspace.path / engagement.ATTACK_SURFACE_PATH
            diff_path = engagement.workspace.path / engagement.ATTACK_SURFACE_DIFF_PATH
            persisted = json.loads(graph_path.read_text(encoding="utf-8"))
            persisted_delta = json.loads(diff_path.read_text(encoding="utf-8"))

        self.assertEqual(persisted["graph_id"], newer["graph_id"])
        self.assertIsNotNone(delta)
        self.assertEqual(persisted_delta, delta)
        self.assertGreater(len(delta["new_hypotheses"]), 0)
        self.assertTrue(
            all(
                item["status"] == "NEW_HYPOTHESIS"
                for item in delta["new_hypotheses"]
            )
        )

    def test_live_graph_never_promotes_observation_to_verified(self) -> None:
        rendered = json.dumps(build_live_attack_surface(scope(), world()))
        self.assertNotIn('"decision": "ALLOW"', rendered)
        self.assertNotIn('"status": "VERIFIED"', rendered)


if __name__ == "__main__":
    unittest.main()
