from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from sechelix_runner.cli import build_parser
from sechelix_runner.pentest.static_tools import StaticSecurityRunner


class StaticSecurityRunnerTests(unittest.TestCase):
    def test_semgrep_is_bounded_and_normalized_as_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as work:
            payload = '{"results":[{"check_id":"python.test","path":"app.py","start":{"line":1,"col":1},"extra":{"message":"test signal","severity":"WARNING"}}],"errors":[]}'
            completed = Mock(returncode=0, stdout=payload, stderr="")
            with patch("sechelix_runner.pentest.static_tools.subprocess.run", return_value=completed) as run:
                result = StaticSecurityRunner(repo, work).semgrep()
            command = run.call_args.args[0]
            self.assertEqual(command[0], "semgrep")
            self.assertNotIn("sh", command)
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(result.candidates[0]["status"], "CANDIDATE")
            self.assertEqual(result.candidates[0]["assessment"], "UNASSESSED")
            decisions = Path(work, "tool-decisions.jsonl").read_text(encoding="utf-8")
            self.assertIn('"network": false', decisions.lower())

    def test_session_token_trust_is_curated_bounded_and_candidate_only(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as work:
            payload = '{"results":[{"check_id":"sechelix.jwt.decode-only-payload","path":"device.ts","start":{"line":4,"col":1},"extra":{"message":"decode-only jwt","severity":"WARNING"}}],"errors":[]}'
            completed = Mock(returncode=0, stdout=payload, stderr="")
            with patch("sechelix_runner.pentest.static_tools.subprocess.run", return_value=completed) as run:
                result = StaticSecurityRunner(repo, work).session_token_trust()
            command = run.call_args.args[0]
            self.assertEqual(command[0], "semgrep")
            self.assertIn("session-token-trust.yml", " ".join(command))
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(result.tool, "session-token-trust")
            self.assertEqual(result.candidates[0]["status"], "CANDIDATE")
            self.assertEqual(result.candidates[0]["assessment"], "UNASSESSED")
            decisions = Path(work, "tool-decisions.jsonl").read_text(encoding="utf-8")
            self.assertIn('"network": false', decisions.lower())

    def test_session_token_rules_are_review_leads_not_findings(self) -> None:
        rules = (
            Path(__file__).resolve().parents[2]
            / "rules"
            / "session-token-trust.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("sechelix_status: CANDIDATE", rules)
        self.assertIn("SEC-SESSION-TOKEN-001", rules)
        self.assertIn("pinned issuer", rules)
        self.assertNotIn("VERIFIED", rules)

    def test_cli_exposes_session_token_trust_scout(self) -> None:
        args = build_parser().parse_args(
            ["scout", ".", "--capability", "session-token-trust", "--json"]
        )
        self.assertEqual(args.command, "scout")
        self.assertEqual(args.capability, "session-token-trust")
        self.assertTrue(args.json)

    def test_session_token_trust_uses_local_rules_without_auto_config(self) -> None:
        with tempfile.TemporaryDirectory() as repo, tempfile.TemporaryDirectory() as work:
            payload = '{"results":[{"check_id":"sechelix.jwt.decode-only-payload","path":"auth.ts","start":{"line":7,"col":1},"extra":{"message":"decode-only token","severity":"WARNING"}}],"errors":[]}'
            completed = Mock(returncode=0, stdout=payload, stderr="")
            with patch("sechelix_runner.pentest.static_tools.subprocess.run", return_value=completed) as run:
                result = StaticSecurityRunner(repo, work).session_token_trust()

            command = run.call_args.args[0]
            self.assertEqual(command[0], "semgrep")
            self.assertIn("--config", command)
            config_path = Path(command[command.index("--config") + 1])
            self.assertEqual(config_path.name, "session-token-trust.yml")
            self.assertNotIn("auto", command)
            self.assertFalse(run.call_args.kwargs["shell"])
            self.assertEqual(result.candidates[0]["status"], "CANDIDATE")
            self.assertEqual(result.candidates[0]["assessment"], "UNASSESSED")
            self.assertTrue(Path(result.report_path).name.startswith("session-token-trust"))

    def test_runner_exposes_no_generic_run_command(self) -> None:
        runner_methods = {name for name in dir(StaticSecurityRunner) if not name.startswith("_")}
        self.assertNotIn("run", runner_methods)
        self.assertNotIn("shell", runner_methods)


if __name__ == "__main__":
    unittest.main()
