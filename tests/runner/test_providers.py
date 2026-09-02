"""Provider layer tests.

Every test here uses a fake provider. The suite must never call a real model:
it would cost money, need credentials, and fail on a network blip. The real
provider is exercised by hand and the results are recorded in the run
documentation, not asserted here.
"""

import unittest

from sechelix_runner.executor import NodeOutcome
from sechelix_runner.graph import GraphNode
from sechelix_runner.providers import (
    ProviderError,
    ProviderResult,
    ReasoningExecutor,
    build_prompt,
    extract_json,
    validate_node_output,
    verifier_view,
)
from sechelix_runner.providers.claude_code import ClaudeCodeExecutor, _accounting
from sechelix_runner.providers.reasoning import FORBIDDEN_VERIFIER_FIELDS
from sechelix_runner.roles import NodeRole, NodeStatus

VALID = '{"candidates": [{"claim": "missing owner check", "location": "a.py:1", "why": "queried by id alone"}]}'


class FakeProvider:
    name = "fake"

    def __init__(self, text: str = VALID, *, raises: Exception | None = None, **usage) -> None:
        self.text = text
        self.raises = raises
        self.usage = usage
        self.prompts: list[str] = []

    def invoke(self, prompt: str, *, timeout: float) -> ProviderResult:
        self.prompts.append(prompt)
        if self.raises:
            raise self.raises
        return ProviderResult(text=self.text, **self.usage)


def run_node(provider, role=NodeRole.AUTHORIZATION, view=None) -> NodeOutcome:
    executor = ReasoningExecutor(provider, timeout=5)
    return executor.execute(GraphNode("n", role), view or {"routes": ["/a"]})


class JsonExtractionTests(unittest.TestCase):
    def test_plain_object(self) -> None:
        self.assertEqual(extract_json('{"candidates": []}'), {"candidates": []})

    def test_fenced_block(self) -> None:
        self.assertEqual(extract_json('```json\n{"candidates": []}\n```'), {"candidates": []})

    def test_prose_prefix_is_tolerated(self) -> None:
        self.assertEqual(extract_json('Sure:\n{"candidates": []}'), {"candidates": []})

    def test_nested_braces_and_strings(self) -> None:
        payload = extract_json('{"candidates": [{"why": "a } brace in a string"}]}')
        self.assertEqual(payload["candidates"][0]["why"], "a } brace in a string")

    def test_truncated_object_is_refused_not_repaired(self) -> None:
        with self.assertRaises(ProviderError):
            extract_json('{"candidates": [')

    def test_no_json_at_all_is_refused(self) -> None:
        with self.assertRaises(ProviderError):
            extract_json("I was unable to complete that request.")


class SchemaTests(unittest.TestCase):
    def test_valid_output_passes(self) -> None:
        self.assertEqual(validate_node_output(extract_json(VALID)), [])

    def test_empty_candidate_list_is_valid(self) -> None:
        """Finding nothing is a real answer; only inventing one is not."""
        self.assertEqual(validate_node_output({"candidates": []}), [])

    def test_missing_candidates_key_is_rejected(self) -> None:
        self.assertTrue(validate_node_output({"notes": "hi"}))

    def test_candidates_must_be_a_list(self) -> None:
        self.assertTrue(validate_node_output({"candidates": "nope"}))

    def test_each_candidate_needs_claim_location_and_why(self) -> None:
        problems = validate_node_output({"candidates": [{"claim": "a claim here"}]})
        self.assertTrue(any("location" in p for p in problems))
        self.assertTrue(any("why" in p for p in problems))

    def test_blank_strings_do_not_satisfy_required_fields(self) -> None:
        self.assertTrue(
            validate_node_output({"candidates": [{"claim": "  ", "location": "a", "why": "b"}]})
        )


class FailClosedTests(unittest.TestCase):
    def test_provider_error_fails_the_node(self) -> None:
        outcome = run_node(FakeProvider(raises=ProviderError("provider down")))
        self.assertIs(outcome.status, NodeStatus.FAILED)
        self.assertIn("provider down", outcome.error)

    def test_prose_instead_of_json_fails_closed(self) -> None:
        outcome = run_node(FakeProvider("I think there may be an issue somewhere."))
        self.assertIs(outcome.status, NodeStatus.FAILED)
        self.assertIn("unparseable", outcome.error)

    def test_schema_violation_fails_closed_rather_than_partially_parsing(self) -> None:
        outcome = run_node(FakeProvider('{"candidates": [{"claim": "only a claim"}]}'))
        self.assertIs(outcome.status, NodeStatus.FAILED)
        self.assertIn("schema", outcome.error)
        self.assertEqual(outcome.output, {})

    def test_accounting_survives_a_schema_failure(self) -> None:
        """Spend happened even though the answer was unusable."""
        outcome = run_node(
            FakeProvider('{"candidates": [{}]}', cost_usd=0.5, model="m", provider="p")
        )
        self.assertIs(outcome.status, NodeStatus.FAILED)
        self.assertEqual(outcome.cost_usd, 0.5)
        self.assertEqual(outcome.model, "m")


class AccountingTests(unittest.TestCase):
    def test_usage_is_copied_verbatim(self) -> None:
        outcome = run_node(
            FakeProvider(model="claude-x", provider="firstParty",
                         input_tokens=11, output_tokens=22, cost_usd=1.5)
        )
        self.assertIs(outcome.status, NodeStatus.SUCCEEDED)
        self.assertEqual(
            (outcome.model, outcome.provider, outcome.input_tokens, outcome.output_tokens,
             outcome.cost_usd),
            ("claude-x", "firstParty", 11, 22, 1.5),
        )

    def test_unreported_usage_stays_none(self) -> None:
        outcome = run_node(FakeProvider())
        for value in (outcome.model, outcome.input_tokens, outcome.cost_usd):
            self.assertIsNone(value)

    def test_envelope_without_model_usage_yields_none_not_zero(self) -> None:
        model, provider, cost, tin, tout = _accounting({})
        self.assertEqual((model, provider, cost, tin, tout), (None, None, None, None, None))

    def test_envelope_usage_is_summed_and_named(self) -> None:
        model, provider, cost, tin, tout = _accounting(
            {"modelUsage": {"m": {"canonicalModel": "claude-x", "provider": "firstParty",
                                  "costUSD": 0.25, "inputTokens": 5, "outputTokens": 7}}}
        )
        self.assertEqual((model, provider, cost, tin, tout),
                         ("claude-x", "firstParty", 0.25, 5, 7))


class RoleIsolationTests(unittest.TestCase):
    CANDIDATE = {
        "claim": "IDOR on /orders/{id}", "location": "app.py:42", "why": "no owner check",
        "confidence": "HIGH", "severity": "CRITICAL", "verdict": "exploitable",
        "hunter_notes": "definitely real", "exploitability": "trivial",
    }

    def test_verifier_view_keeps_observations_and_drops_conclusions(self) -> None:
        kept = verifier_view(self.CANDIDATE)
        self.assertEqual(sorted(kept), ["claim", "location", "why"])

    def test_conclusion_values_never_reach_the_verifier_evidence(self) -> None:
        prompt = build_prompt(
            GraphNode("v", NodeRole.INDEPENDENT_VERIFIER), {"candidates": [self.CANDIDATE]}
        )
        evidence = prompt.split("Evidence:", 1)[1]
        for leaked in ("HIGH", "CRITICAL", "exploitable", "definitely real", "trivial"):
            with self.subTest(value=leaked):
                self.assertNotIn(leaked, evidence)

    def test_observations_do_survive_into_the_verifier_evidence(self) -> None:
        prompt = build_prompt(
            GraphNode("v", NodeRole.INDEPENDENT_VERIFIER), {"candidates": [self.CANDIDATE]}
        )
        evidence = prompt.split("Evidence:", 1)[1]
        for kept in ("IDOR on /orders/{id}", "app.py:42", "no owner check"):
            self.assertIn(kept, evidence)

    def test_a_hunter_prompt_is_not_stripped(self) -> None:
        """Only the verifier is blinded; a hunter may see its own context."""
        prompt = build_prompt(
            GraphNode("h", NodeRole.AUTHORIZATION), {"candidates": [self.CANDIDATE]}
        )
        self.assertIn("CRITICAL", prompt)

    def test_verifier_is_asked_to_refute(self) -> None:
        prompt = build_prompt(GraphNode("v", NodeRole.INDEPENDENT_VERIFIER), {"candidates": []})
        self.assertIn("REFUTE", prompt)
        self.assertIn("Refuting a claim is a success", prompt)

    def test_every_forbidden_field_is_stripped(self) -> None:
        candidate = {"claim": "c", "location": "l", "why": "w"}
        candidate.update({field: "LEAK" for field in FORBIDDEN_VERIFIER_FIELDS})
        self.assertNotIn("LEAK", str(verifier_view(candidate)))


class PromptTests(unittest.TestCase):
    def test_prompt_tells_the_model_it_has_no_tools(self) -> None:
        """Denying tools by flag stops them working; saying so stops it trying."""
        prompt = build_prompt(GraphNode("n", NodeRole.MAPPER), {"file_index": ["a.py"]})
        self.assertIn("You have NO tools", prompt)

    def test_oversized_context_is_truncated_and_says_so(self) -> None:
        prompt = build_prompt(
            GraphNode("n", NodeRole.MAPPER), {"file_index": ["x" * 200] * 500}, max_chars=500
        )
        self.assertIn("context truncated", prompt)

    def test_computed_roles_are_not_sent_to_a_provider(self) -> None:
        provider = FakeProvider()
        outcome = run_node(provider, role=NodeRole.RELEASE_GATE)
        self.assertIs(outcome.status, NodeStatus.SUCCEEDED)
        self.assertEqual(provider.prompts, [])


class ClaudeCodeAdapterTests(unittest.TestCase):
    def test_command_never_uses_a_shell(self) -> None:
        import inspect

        source = inspect.getsource(ClaudeCodeExecutor.invoke)
        self.assertIn("shell=False", source)

    def test_no_session_resumption_flags(self) -> None:
        """Two nodes must not share conversation memory."""
        import inspect

        source = inspect.getsource(ClaudeCodeExecutor)
        self.assertNotIn("--resume", source)
        self.assertNotIn("--continue", source)

    def test_missing_binary_reports_clearly(self) -> None:
        executor = ClaudeCodeExecutor(binary="definitely-not-a-real-binary-xyz")
        self.assertFalse(executor.available)
        with self.assertRaises(ProviderError):
            executor.invoke("hi", timeout=1)


if __name__ == "__main__":
    unittest.main()
