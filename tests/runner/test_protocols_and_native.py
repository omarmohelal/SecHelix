import json
import tempfile
import unittest
from pathlib import Path

from sechelix_runner.native import native_lane, scan_native_sources
from sechelix_runner.protocols import PACKS, Protocol, detect_protocols, selected_packs
from sechelix_runner.world import build_world


class ProtocolPackTests(unittest.TestCase):
    def test_all_required_protocol_families_have_deep_checks(self) -> None:
        self.assertEqual(
            set(PACKS),
            {
                Protocol.GRAPHQL,
                Protocol.WEBSOCKET,
                Protocol.GRPC,
                Protocol.OAUTH_OIDC,
                Protocol.SAML,
                Protocol.JWT_SESSION,
                Protocol.WEBHOOK,
                Protocol.HTTP_DESYNC,
                Protocol.CACHE_BOUNDARY,
            },
        )
        for protocol, pack in PACKS.items():
            with self.subTest(protocol=protocol.value):
                self.assertGreaterEqual(len(pack.checks), 3)
                self.assertTrue(pack.catalog_hypothesis_ids)
                for check in pack.checks:
                    self.assertTrue(check.question.endswith("?"))
                    self.assertTrue(check.safe_validation)
                    self.assertTrue(check.false_positive_filter)

    def test_protocol_presence_routes_questions_but_never_a_vulnerability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "package.json").write_text(
                json.dumps({"dependencies": {"graphql": "1", "socket.io": "1", "jsonwebtoken": "1"}}),
                encoding="utf-8",
            )
            (root / "schema.graphql").write_text("type Query { node(id: ID!): String }", encoding="utf-8")
            world = build_world(root)
            detected = detect_protocols(root, world)
            self.assertIn(Protocol.GRAPHQL, detected)
            self.assertIn(Protocol.WEBSOCKET, detected)
            self.assertIn(Protocol.JWT_SESSION, detected)
            packs = selected_packs(root, world)
            self.assertGreaterEqual(len(packs), 3)
            rendered = json.dumps(packs)
            self.assertIn("APPLICABLE_FOR_REVIEW", rendered)
            self.assertIn("protocol presence routes questions", rendered)
            self.assertNotIn('"status": "VERIFIED"', rendered)
            self.assertNotIn('"severity": "HIGH"', rendered)

    def test_unrelated_repository_routes_no_protocol_pack(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("plain library", encoding="utf-8")
            world = build_world(root)
            self.assertEqual(detect_protocols(root, world), {})
            self.assertEqual(selected_packs(root, world), [])


class NativeLaneTests(unittest.TestCase):
    def test_native_lane_is_not_applicable_without_native_sources(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('hello')", encoding="utf-8")
            result = native_lane(root, build_world(root))
            self.assertEqual(result["applicability"], "NOT_APPLICABLE")
            self.assertEqual(result["signals"], [])

    def test_native_patterns_emit_candidate_unassessed_signals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "parser.c").write_text(
                "#include <string.h>\nvoid copy(char *dst, char *src) { strcpy(dst, src); }\n",
                encoding="utf-8",
            )
            (root / "bridge.rs").write_text(
                'extern "C" { fn native(x: *const u8); }\nunsafe fn view(p: *const u8, n: usize) { let _ = std::slice::from_raw_parts(p,n); }\n',
                encoding="utf-8",
            )
            world = build_world(root)
            result = native_lane(root, world)
            self.assertEqual(result["applicability"], "APPLICABLE")
            self.assertGreaterEqual(len(result["signals"]), 3)
            for signal in result["signals"]:
                self.assertEqual(signal["status"], "CANDIDATE")
                self.assertEqual(signal["assessment"], "UNASSESSED")
                self.assertEqual(signal["severity"], "UNASSESSED")
                self.assertTrue(signal["review_question"])
                self.assertTrue(signal["false_positive_filter"])

    def test_native_scanner_refuses_path_escape_and_bounds_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            external = Path(outside) / "evil.c"
            external.write_text("strcpy(a,b);", encoding="utf-8")
            inside = root / "safe.c"
            inside.write_text("int main(void) { return 0; }", encoding="utf-8")
            signals = scan_native_sources(root, ["safe.c", str(external)])
            self.assertEqual(signals, [])


if __name__ == "__main__":
    unittest.main()
