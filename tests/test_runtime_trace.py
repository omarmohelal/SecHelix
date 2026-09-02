"""A trace records, redacts, and correlates — and never verifies anything.

The invariants asserted here are the ones that make runtime observation safe to
ship: it cannot generate traffic, it cannot select production by accident, it
cannot carry a secret, it cannot promote a claim, and it cannot report "we could
not tell" as "nothing to see".
"""

import inspect
import types
import unittest

from sechelix_core import runtime_trace
from sechelix_core.contracts import ContractValidationError, validate_contract
from sechelix_core.proof_bundle import REDACTED
from sechelix_core.runtime_trace import (
    CONFIRMS,
    CONTRADICTS,
    COOKIE_METADATA,
    EXACT,
    FILE,
    HTTP_EXCHANGE,
    HYPOTHESIS,
    INSUFFICIENT,
    LOCAL,
    NONE,
    PRODUCTION_SAFE,
    REDIRECT_CHAIN,
    RuntimeTraceError,
    STAGING,
    TEMPLATE,
    UNDETERMINED,
    UNRELATED,
    assess_support,
    build_trace,
    claim,
    cookie_metadata,
    correlate,
    correlate_all,
    observe,
    traffic_capabilities,
)

# Credential-shaped fixtures are assembled at runtime. A literal here would be
# flagged by this project's own secret gate, and a scanner that learns to ignore
# the tests directory stops protecting it.
GITHUB = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"
BEARER_HEADER = "Bearer " + "abcdefghijklmnopqrstuvwxyz012345"
COOKIE_PAIR = "sid=" + "9f8e7d6c5b4a39281706"
SECRET_QUERY = "abcdefghij" + "klmnopqrst"


def http(observation_id="OBS-1", surface="GET /api/orders/42", **signals):
    return observe(observation_id, HTTP_EXCHANGE, surface=surface, signals=signals)


def order_claim(claim_id="SHX-F-1", *, evidence=("EV-001",), **expected):
    return claim(
        claim_id,
        surfaces=["GET /api/orders/{id}", "app/orders.py:41"],
        expected_signals=expected or {"status_code": 200},
        evidence_ids=evidence,
        statement="the order lookup omits the tenant predicate",
    )


class ExecutionModeTests(unittest.TestCase):
    def test_the_default_mode_is_local(self):
        self.assertEqual(build_trace("TRACE-A")["execution_mode"], LOCAL)

    def test_staging_needs_no_extra_ceremony(self):
        self.assertEqual(build_trace("TRACE-A", mode=STAGING)["execution_mode"], STAGING)

    def test_production_safe_without_stated_restrictions_is_refused(self):
        with self.assertRaises(RuntimeTraceError) as raised:
            build_trace("TRACE-A", mode=PRODUCTION_SAFE)
        self.assertIn("chosen under", str(raised.exception))

    def test_production_safe_records_the_restrictions_it_was_chosen_under(self):
        artifact = build_trace(
            "TRACE-A", mode=PRODUCTION_SAFE,
            production_safeguards=["read-only replica", "no write endpoints"],
        )
        self.assertEqual(artifact["execution_mode"], PRODUCTION_SAFE)
        self.assertEqual(len(artifact["production_safeguards"]), 2)
        validate_contract("runtime-trace", artifact)

    def test_restrictions_that_were_never_in_force_are_refused(self):
        """Recording a safeguard on a LOCAL trace overstates what was done."""
        with self.assertRaises(RuntimeTraceError):
            build_trace("TRACE-A", mode=LOCAL, production_safeguards=["read-only replica"])

    def test_an_unknown_mode_is_refused(self):
        for mode in ("STATIC", "UNTRUSTED_REPO", "PRODUCTION", ""):
            with self.subTest(mode=mode), self.assertRaises(RuntimeTraceError):
                build_trace("TRACE-A", mode=mode)

    def test_the_contract_also_refuses_unrestricted_production(self):
        artifact = build_trace("TRACE-A", mode=PRODUCTION_SAFE, production_safeguards=["x"])
        artifact.pop("production_safeguards")
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)


class NoTrafficTests(unittest.TestCase):
    def test_the_module_holds_nothing_that_could_emit_traffic(self):
        self.assertEqual(traffic_capabilities(), ())

    def test_a_leaked_traffic_capable_import_fails_the_module(self):
        """The guarantee is checked, not asserted; prove the check can fail."""
        runtime_trace.__dict__["socket"] = types.ModuleType("socket")
        try:
            self.assertTrue(traffic_capabilities())
            with self.assertRaises(RuntimeTraceError):
                runtime_trace._refuse_traffic_capability()
        finally:
            del runtime_trace.__dict__["socket"]
        self.assertEqual(traffic_capabilities(), ())

    def test_no_public_callable_offers_to_send_anything(self):
        forbidden = ("send", "request", "fetch", "emit", "attack", "exploit", "payload", "post")
        for name, value in vars(runtime_trace).items():
            if name.startswith("_") or not callable(value):
                continue
            with self.subTest(name=name):
                self.assertFalse(
                    any(word in name.lower() for word in forbidden),
                    f"{name} reads like something that produces traffic",
                )

    def test_the_artifact_says_it_generated_nothing(self):
        self.assertIs(build_trace("TRACE-A")["emits_traffic"], False)

    def test_the_contract_refuses_a_trace_that_claims_it_generated_traffic(self):
        artifact = build_trace("TRACE-A")
        artifact["emits_traffic"] = True
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)


class RedactionTests(unittest.TestCase):
    def test_a_cookie_value_is_dropped_not_stored(self):
        observation = observe(
            "OBS-C", COOKIE_METADATA,
            surface="GET /login",
            signals={"name": "sid", "value": COOKIE_PAIR, "secure": True},
        )
        self.assertNotIn("value", observation.signal_map)
        self.assertIn("value", observation.dropped_signals)
        self.assertNotIn(COOKIE_PAIR, str(observation.as_dict()))

    def test_the_cookie_helper_has_nowhere_to_put_a_value(self):
        """A filter can be bypassed; a missing parameter cannot."""
        parameters = set(inspect.signature(cookie_metadata).parameters)
        self.assertEqual(parameters & {"value", "cookie_value", "cookie"}, set())
        self.assertLessEqual({"secure", "http_only", "same_site", "domain", "path"}, parameters)

    def test_credential_headers_are_dropped(self):
        observation = http(authorization=BEARER_HEADER, cookie=COOKIE_PAIR, status_code=200)
        self.assertEqual(observation.signal_map, {"status_code": 200})
        self.assertEqual(observation.dropped_signals, ("authorization", "cookie"))

    def test_bodies_are_dropped_rather_than_redacted(self):
        """A redactor that has to be right about a whole request body will be wrong."""
        observation = http(request_body="{'a': 1}", response_body="ok", status_code=200)
        self.assertEqual(observation.signal_map, {"status_code": 200})
        self.assertEqual(observation.dropped_signals, ("request_body", "response_body"))

    def test_session_identifiers_are_dropped(self):
        observation = http(session_id="abc", sid="def", status_code=200)
        self.assertEqual(observation.signal_map, {"status_code": 200})

    def test_query_string_values_never_survive(self):
        observation = http(surface=f"GET /reset?token={SECRET_QUERY}&user=alice")
        self.assertNotIn(SECRET_QUERY, observation.surface)
        self.assertNotIn("alice", observation.surface)
        self.assertIn("token=", observation.surface)
        self.assertIn(REDACTED, observation.surface)

    def test_known_secret_shapes_inside_a_signal_are_redacted(self):
        observation = http(note_header=f"issued {GITHUB}")
        self.assertNotIn(GITHUB, str(observation.as_dict()))
        self.assertIn(REDACTED, observation.signal_map["note_header"])

    def test_a_secret_in_a_note_is_redacted(self):
        observation = observe("OBS-N", HTTP_EXCHANGE, surface="/x", note=f"seen {GITHUB}")
        self.assertNotIn(GITHUB, observation.note)

    def test_redaction_counts_reach_the_artifact(self):
        artifact = build_trace("TRACE-A", observations=[http(note_header=f"x {GITHUB}")])
        self.assertGreater(artifact["redaction"]["total_values_redacted"], 0)
        self.assertIn("github_pat", artifact["redaction"]["by_pattern"])
        validate_contract("runtime-trace", artifact)

    def test_a_list_of_hops_is_redacted_element_by_element(self):
        observation = observe(
            "OBS-R", REDIRECT_CHAIN, surface="GET /login",
            signals={"hops": ["/login", f"/callback?code={SECRET_QUERY}"]},
        )
        self.assertNotIn(SECRET_QUERY, str(observation.as_dict()))

    def test_a_non_scalar_signal_is_refused(self):
        with self.assertRaises(RuntimeTraceError):
            http(headers={"a": "b"})

    def test_a_signal_name_that_cannot_be_recorded_is_refused(self):
        with self.assertRaises(RuntimeTraceError):
            http(**{"404": 1})

    def test_two_values_for_one_normalized_name_are_refused(self):
        with self.assertRaises(RuntimeTraceError):
            observe("OBS-D", HTTP_EXCHANGE, surface="/x",
                    signals={"Status-Code": 200, "status_code": 404})

    def test_a_claim_cannot_predict_a_signal_that_is_always_dropped(self):
        with self.assertRaises(RuntimeTraceError):
            claim("SHX-F-9", surfaces=["/x"], expected_signals={"cookie_value": "x"})


class SurfaceMatchTests(unittest.TestCase):
    def match(self, observed, claimed):
        return correlate(
            http(surface=observed),
            claim("SHX-F-1", surfaces=[claimed], expected_signals={"status_code": 200}),
        ).surface_match

    def test_a_templated_route_matches_a_concrete_path(self):
        self.assertEqual(self.match("GET /api/orders/42", "GET /api/orders/{id}"), TEMPLATE)
        self.assertEqual(self.match("GET /api/orders/42", "GET /api/orders/:id"), TEMPLATE)
        self.assertEqual(self.match("GET /api/orders/42", "/api/orders/<int:id>"), TEMPLATE)

    def test_an_absolute_url_matches_the_route_it_hit(self):
        self.assertEqual(self.match("https://app.example/api/orders/42", "/api/orders/{id}"), TEMPLATE)

    def test_a_method_mismatch_is_a_different_surface(self):
        self.assertEqual(self.match("POST /api/orders/42", "GET /api/orders/{id}"), NONE)

    def test_a_file_and_a_line_match_at_file_granularity(self):
        self.assertEqual(self.match("app/orders.py:41", "app/orders.py:99"), FILE)
        self.assertEqual(self.match("app/orders.py:41", "app/orders.py"), FILE)

    def test_a_windows_path_matches_its_posix_form(self):
        self.assertEqual(self.match(r"app\orders.py", "app/orders.py"), EXACT)

    def test_a_different_route_does_not_match(self):
        self.assertEqual(self.match("GET /api/invoices/42", "GET /api/orders/{id}"), NONE)


class CorrelationTests(unittest.TestCase):
    def test_agreement_confirms(self):
        result = correlate(http(status_code=200), order_claim(status_code=200))
        self.assertEqual(result.strength, CONFIRMS)
        self.assertEqual(result.compared_signals, ("status_code",))
        self.assertTrue(result.supports)

    def test_disagreement_contradicts(self):
        result = correlate(http(status_code=200), order_claim(status_code=403))
        self.assertEqual(result.strength, CONTRADICTS)
        self.assertEqual(result.disagreeing_signals, ("status_code",))

    def test_one_disagreement_outweighs_agreement_elsewhere(self):
        result = correlate(
            http(status_code=200, cache_control="no-store"),
            order_claim(status_code=200, cache_control="public"),
        )
        self.assertEqual(result.strength, CONTRADICTS)

    def test_an_unrelated_surface_is_unrelated(self):
        result = correlate(http(surface="GET /healthz", status_code=200), order_claim())
        self.assertEqual(result.strength, UNRELATED)
        self.assertEqual(result.surface_match, NONE)

    def test_an_observation_with_no_surface_is_insufficient(self):
        result = correlate(
            observe("OBS-X", HTTP_EXCHANGE, signals={"status_code": 200}), order_claim()
        )
        self.assertEqual(result.strength, INSUFFICIENT)
        self.assertEqual(result.surface_match, UNDETERMINED)
        self.assertIn("records no surface", result.reason)

    def test_a_claim_with_no_surface_is_insufficient(self):
        result = correlate(http(status_code=200),
                           claim("SHX-F-2", expected_signals={"status_code": 200}))
        self.assertEqual(result.strength, INSUFFICIENT)

    def test_a_claim_that_predicts_nothing_is_insufficient(self):
        result = correlate(
            http(status_code=200),
            claim("SHX-F-3", surfaces=["GET /api/orders/{id}"], evidence_ids=["EV-001"]),
        )
        self.assertEqual(result.strength, INSUFFICIENT)
        self.assertIn("predicts no runtime signal", result.reason)

    def test_a_prediction_nothing_observed_is_insufficient_not_confirmation(self):
        result = correlate(http(status_code=200), order_claim(content_security_policy="default-src"))
        self.assertEqual(result.strength, INSUFFICIENT)
        self.assertIn("content_security_policy", result.uncomparable_signals)

    def test_a_redacted_signal_is_uncomparable_rather_than_a_disagreement(self):
        """Comparing a placeholder to a real value would invent a contradiction."""
        observation = http(referer=f"https://app.example/reset?token={SECRET_QUERY}")
        result = correlate(
            observation,
            order_claim(referer="https://app.example/reset?token=" + SECRET_QUERY),
        )
        self.assertEqual(result.strength, INSUFFICIENT)
        self.assertIn("referer", result.uncomparable_signals)
        self.assertEqual(result.disagreeing_signals, ())

    def test_a_redacted_surface_is_insufficient_never_unrelated(self):
        """proof_bundle redacts home-shaped paths, so /home/... loses its surface."""
        observation = http(surface="GET /home/dashboard", status_code=200)
        self.assertTrue(observation.surface_redacted)
        result = correlate(
            observation,
            claim("SHX-F-4", surfaces=["GET /home/dashboard"],
                  expected_signals={"status_code": 200}, evidence_ids=["EV-001"]),
        )
        self.assertEqual(result.strength, INSUFFICIENT)
        self.assertNotEqual(result.strength, UNRELATED)

    def test_insufficient_is_never_reported_as_unrelated(self):
        """'We saw nothing relevant' and 'we could not tell' are different answers."""
        undecidable = [
            observe("OBS-A", HTTP_EXCHANGE, signals={"status_code": 200}),
            http("OBS-B", surface="GET /home/dashboard", status_code=200),
            http("OBS-C", surface="GET /api/orders/42", other_signal=1),
        ]
        static = order_claim()
        results = correlate_all(undecidable, [static])
        self.assertTrue(all(r.strength == INSUFFICIENT for r in results),
                        [(r.observation_id, r.strength) for r in results])
        assessment = assess_support(static, results)
        self.assertEqual(assessment.unrelated, ())
        self.assertEqual(len(assessment.insufficient), len(undecidable))

    def test_correlations_are_ordered_deterministically(self):
        observations = [http("OBS-B"), http("OBS-A")]
        claims = [order_claim("SHX-F-2"), order_claim("SHX-F-1")]
        pairs = [(c.claim_id, c.observation_id) for c in correlate_all(observations, claims)]
        self.assertEqual(pairs, sorted(pairs))
        self.assertEqual(
            build_trace("TRACE-A", observations=observations, claims=claims),
            build_trace("TRACE-A", observations=observations, claims=claims),
        )


class ClaimStatusTests(unittest.TestCase):
    def test_runtime_agreement_alone_leaves_a_claim_a_hypothesis(self):
        static = order_claim(evidence=())
        assessment = assess_support(static, correlate_all([http(status_code=200)], [static]))
        self.assertEqual(assessment.status, HYPOTHESIS)
        self.assertFalse(assessment.verification_ready)
        self.assertIn("cites no static evidence", assessment.reason)

    def test_combined_with_static_evidence_it_is_ready_for_a_verifier_not_verified(self):
        static = order_claim(evidence=("EV-001", "EV-002"))
        assessment = assess_support(static, correlate_all([http(status_code=200)], [static]))
        self.assertEqual(assessment.status, HYPOTHESIS)
        self.assertTrue(assessment.verification_ready)
        self.assertIn("not enough to be verified", assessment.reason)

    def test_a_contradiction_blocks_readiness_even_with_static_evidence(self):
        static = order_claim(status_code=403)
        assessment = assess_support(static, correlate_all([http(status_code=200)], [static]))
        self.assertEqual(assessment.status, HYPOTHESIS)
        self.assertFalse(assessment.verification_ready)

    def test_a_claim_nothing_was_correlated_against_says_nothing(self):
        static = order_claim()
        assessment = assess_support(static, ())
        self.assertEqual(assessment.status, HYPOTHESIS)
        self.assertFalse(assessment.verification_ready)
        self.assertIn("says nothing about it", assessment.reason)

    def test_every_assessment_in_an_artifact_is_a_hypothesis(self):
        artifact = build_trace(
            "TRACE-A",
            observations=[http(status_code=200), http("OBS-2", surface="GET /healthz")],
            claims=[order_claim(), order_claim("SHX-F-2")],
        )
        self.assertEqual({a["status"] for a in artifact["assessments"]}, {HYPOTHESIS})

    def test_the_contract_cannot_express_any_other_status(self):
        artifact = build_trace("TRACE-A", observations=[http(status_code=200)],
                               claims=[order_claim()])
        artifact["assessments"][0]["status"] = "VERIFIED"
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)

    def test_the_contract_refuses_readiness_without_static_evidence(self):
        artifact = build_trace("TRACE-A", observations=[http(status_code=200)],
                               claims=[order_claim(evidence=())])
        artifact["assessments"][0]["verification_ready"] = True
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)


class ContractTests(unittest.TestCase):
    def artifact(self):
        return build_trace(
            "TRACE-DEMO",
            mode=STAGING,
            observations=[
                http(status_code=200),
                cookie_metadata("OBS-2", "sid", surface="GET /login",
                                secure=False, http_only=True, same_site="Lax"),
            ],
            claims=[
                order_claim(),
                claim("SHX-F-2", surfaces=["GET /login"],
                      expected_signals={"secure": True}, evidence_ids=["EV-002"]),
            ],
            repository="owner/app",
            commit="06ab8ca680d477b8005805d67ab44d11507e3321",
        )

    def test_a_built_trace_satisfies_its_contract(self):
        validate_contract("runtime-trace", self.artifact())

    def test_the_contract_refuses_a_signal_that_would_carry_a_secret(self):
        for name in ("token", "api_key", "cookie_value", "authorization", "request_body"):
            with self.subTest(name=name):
                artifact = self.artifact()
                artifact["observations"][0]["signals"][name] = "x"
                with self.assertRaises(ContractValidationError):
                    validate_contract("runtime-trace", artifact)

    def test_the_contract_refuses_an_undecidable_correlation_filed_as_unrelated(self):
        artifact = self.artifact()
        artifact["correlations"][0]["strength"] = UNRELATED
        artifact["correlations"][0]["surface_match"] = UNDETERMINED
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)

    def test_the_contract_refuses_confirmation_without_a_matched_surface(self):
        artifact = self.artifact()
        artifact["correlations"][0]["strength"] = CONFIRMS
        artifact["correlations"][0]["surface_match"] = NONE
        with self.assertRaises(ContractValidationError):
            validate_contract("runtime-trace", artifact)

    def test_all_four_strengths_are_counted(self):
        counts = self.artifact()["counts"]
        self.assertEqual(set(counts), {CONFIRMS, CONTRADICTS, UNRELATED, INSUFFICIENT})
        self.assertEqual(sum(counts.values()), len(self.artifact()["correlations"]))

    def test_a_duplicate_observation_id_is_refused(self):
        with self.assertRaises(RuntimeTraceError):
            build_trace("TRACE-A", observations=[http("OBS-1"), http("OBS-1")])

    def test_a_duplicate_claim_id_is_refused(self):
        with self.assertRaises(RuntimeTraceError):
            build_trace("TRACE-A", claims=[order_claim(), order_claim()])

    def test_the_notes_state_what_the_trace_is_not(self):
        notes = " ".join(self.artifact()["notes"])
        self.assertIn("No traffic was generated", notes)
        self.assertIn("HYPOTHESIS", notes)
        self.assertIn("INSUFFICIENT and UNRELATED are different answers", notes)


if __name__ == "__main__":
    unittest.main()
