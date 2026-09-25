from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

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

    def test_runner_exposes_no_generic_run_command(self) -> None:
        runner_methods = {name for name in dir(StaticSecurityRunner) if not name.startswith("_")}
        self.assertNotIn("run", runner_methods)
        self.assertNotIn("shell", runner_methods)


if __name__ == "__main__":
    unittest.main()
