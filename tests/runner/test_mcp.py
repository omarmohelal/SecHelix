"""MCP adapter tests.

The adapter wraps the runner. Its job is to expose SecHelix operations without
becoming a second engine, a shell, or a way out of the configured root.
"""

import io
import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner.mcp_server import (
    PROTOCOL_VERSION,
    TOOLS,
    PathOutsideRoot,
    SecHelixMCP,
    handle_request,
    serve_stdio,
)


def rpc(api, method, **params):
    request = {"jsonrpc": "2.0", "id": 1, "method": method}
    if params:
        request["params"] = params
    return handle_request(api, request)


def call(api, name, **arguments):
    response = rpc(api, "tools/call", name=name, arguments=arguments)
    if "error" in response:
        return response
    return json.loads(response["result"]["content"][0]["text"])


class ProtocolTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = SecHelixMCP(tempfile.mkdtemp())

    def test_initialize_reports_protocol_and_server(self) -> None:
        result = rpc(self.api, "initialize")["result"]
        self.assertEqual(result["protocolVersion"], PROTOCOL_VERSION)
        self.assertEqual(result["serverInfo"]["name"], "sechelix")

    def test_tools_list_exposes_every_declared_tool(self) -> None:
        tools = rpc(self.api, "tools/list")["result"]["tools"]
        self.assertEqual({t["name"] for t in tools}, set(TOOLS))
        for tool in tools:
            self.assertTrue(tool["description"])
            self.assertEqual(tool["inputSchema"]["type"], "object")

    def test_unknown_method_is_an_error_not_a_crash(self) -> None:
        self.assertEqual(rpc(self.api, "nope")["error"]["code"], -32601)

    def test_unknown_tool_is_an_error(self) -> None:
        response = rpc(self.api, "tools/call", name="rm_rf", arguments={})
        self.assertEqual(response["error"]["code"], -32601)

    def test_a_notification_gets_no_reply(self) -> None:
        self.assertIsNone(
            handle_request(self.api, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        )


class NoShellTests(unittest.TestCase):
    def test_no_tool_exposes_a_shell_or_arbitrary_execution(self) -> None:
        """An agent gets the operations SecHelix defines, not a terminal."""
        for name in TOOLS:
            for banned in ("shell", "exec", "command", "run_command", "eval", "bash"):
                self.assertNotIn(banned, name.lower())


class PathConfinementTests(unittest.TestCase):
    """An MCP client is driven by a model reading untrusted content, so a
    traversal argument will eventually arrive."""

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        self.api = SecHelixMCP(self.root)

    def test_paths_inside_the_root_resolve(self) -> None:
        self.assertTrue(str(self.api._resolve("app.py")).startswith(str(self.root)))

    def test_dotdot_traversal_is_refused(self) -> None:
        with self.assertRaises(PathOutsideRoot):
            self.api._resolve("../../etc/passwd")

    def test_absolute_path_outside_is_refused(self) -> None:
        with self.assertRaises(PathOutsideRoot):
            self.api._resolve("/etc/passwd")

    def test_traversal_through_a_tool_call_returns_an_error(self) -> None:
        response = call(self.api, "sechelix_audit", path="../../etc")
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], -32602)

    def test_a_traversal_that_stays_inside_is_allowed(self) -> None:
        self.api._resolve("sub/../app.py")


class ToolBehaviourTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "app.py").write_text("def handler(request): pass\n", encoding="utf-8")
        self.api = SecHelixMCP(self.root)

    def test_doctor_never_fails_for_a_missing_optional_component(self) -> None:
        payload = call(self.api, "sechelix_doctor")
        self.assertIn("runner_version", payload)
        self.assertIn("container_runtime", payload)

    def test_audit_reports_incomplete_and_says_why(self) -> None:
        payload = call(self.api, "sechelix_audit", path=".", depth="quick")
        self.assertTrue(payload["incomplete"])
        self.assertIn("makes no security claim", payload["note"])

    def test_findings_carry_the_reason_an_empty_list_is_empty(self) -> None:
        run_id = call(self.api, "sechelix_audit", path=".", depth="quick")["run_id"]
        payload = call(self.api, "sechelix_findings", run_id=run_id)
        self.assertEqual(payload["findings"], [])
        self.assertIn("not a statement that no vulnerabilities exist", payload["note"])
        self.assertTrue(payload["unsatisfied_mandatory"])

    def test_run_status_reports_integrity(self) -> None:
        run_id = call(self.api, "sechelix_audit", path=".", depth="quick")["run_id"]
        self.assertEqual(call(self.api, "sechelix_run_status", run_id=run_id)["integrity"], "ok")

    def test_report_renders_every_format(self) -> None:
        run_id = call(self.api, "sechelix_audit", path=".", depth="quick")["run_id"]
        for fmt in ("markdown", "json", "sarif", "html"):
            with self.subTest(format=fmt):
                payload = call(self.api, "sechelix_report", run_id=run_id, format=fmt)
                self.assertTrue(payload["content"].strip())

    def test_unknown_format_is_rejected(self) -> None:
        run_id = call(self.api, "sechelix_audit", path=".", depth="quick")["run_id"]
        self.assertIn("error", call(self.api, "sechelix_report", run_id=run_id, format="pdf"))

    def test_unknown_run_id_is_an_error(self) -> None:
        self.assertIn("error", call(self.api, "sechelix_run_status", run_id="RUN-NOPE"))

    def test_invalid_run_id_is_rejected_by_the_same_rule_the_cli_uses(self) -> None:
        self.assertIn("error", call(self.api, "sechelix_run_status", run_id="../../etc"))

    def test_verify_returns_plans_and_refuses_to_execute_them(self) -> None:
        payload = call(self.api, "sechelix_verify", finding_id="F-1")
        self.assertTrue(payload["plans"])
        self.assertIn("Plans only", payload["note"])
        for plan in payload["plans"].values():
            self.assertEqual(plan["state"], "BLOCKED")

    def test_coverage_reports_blind_spots(self) -> None:
        call(self.api, "sechelix_audit", path=".", depth="quick")
        payload = call(self.api, "sechelix_coverage", path=".")
        self.assertIn("totals", payload)


class StdioTests(unittest.TestCase):
    def test_a_full_stdio_session_round_trips(self) -> None:
        root = Path(tempfile.mkdtemp())
        stdin = io.StringIO(
            '{"jsonrpc":"2.0","id":1,"method":"initialize"}\n'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
        )
        stdout = io.StringIO()
        serve_stdio(root, stdin=stdin, stdout=stdout)
        replies = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]["result"]["serverInfo"]["name"], "sechelix")
        self.assertEqual(len(replies[1]["result"]["tools"]), len(TOOLS))

    def test_malformed_json_gets_a_parse_error_not_a_crash(self) -> None:
        stdout = io.StringIO()
        serve_stdio(tempfile.mkdtemp(), stdin=io.StringIO("{not json\n"), stdout=stdout)
        self.assertEqual(json.loads(stdout.getvalue())["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
