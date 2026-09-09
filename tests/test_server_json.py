"""`server.json` is a public install instruction, so it is tested like one.

A registry entry that claims a version nobody published, or a tool surface that
does not match the code, is worse than no entry: it sends people a command that
fails, or tells them the server can do something it cannot.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER_JSON = ROOT / "server.json"
PYPROJECT = ROOT / "pyproject.toml"
PYPI_README = ROOT / "docs/packaging/PYPI_README.md"


def load():
    return json.loads(SERVER_JSON.read_text(encoding="utf-8"))


def declared_python_version():
    match = re.search(
        r'^version\s*=\s*"([^"]+)"', PYPROJECT.read_text(encoding="utf-8"), re.M
    )
    assert match, "pyproject.toml declares no version"
    return match.group(1)


class ServerJsonTests(unittest.TestCase):
    def setUp(self):
        self.server = load()
        self.package = self.server["packages"][0]

    def test_name_matches_the_github_namespace(self):
        """The namespace is granted by an OIDC claim; it cannot be chosen freely."""
        self.assertEqual(self.server["name"], "io.github.omarmohelal/sechelix")

    def test_description_fits_the_registry_limit(self):
        self.assertLessEqual(len(self.server["description"]), 100)
        self.assertLessEqual(len(self.server["title"]), 100)

    def test_version_agrees_with_pyproject(self):
        version = declared_python_version()
        self.assertEqual(self.server["version"], version)
        self.assertEqual(self.package["version"], version)

    def test_package_points_at_the_public_pypi_project(self):
        self.assertEqual(self.package["registryType"], "pypi")
        self.assertEqual(self.package["registryBaseUrl"], "https://pypi.org")
        self.assertEqual(self.package["identifier"], "sechelix")

    def test_transport_matches_the_implementation(self):
        """The adapter speaks JSON-RPC over stdio and nothing else."""
        self.assertEqual(self.package["transport"], {"type": "stdio"})

    def test_first_argument_is_the_mcp_subcommand(self):
        first = self.package["packageArguments"][0]
        self.assertEqual(first["value"], "mcp")
        from sechelix_runner.cli import build_parser

        # `sechelix mcp` must remain a real subcommand, or the published
        # install instruction stops working.
        actions = build_parser()._subparsers._group_actions[0].choices
        self.assertIn("mcp", actions)

    def test_pypi_readme_carries_the_ownership_token(self):
        """The registry verifies ownership by finding this token in the description."""
        readme = PYPI_README.read_text(encoding="utf-8")
        token = f"mcp-name: {self.server['name']}"
        self.assertIn(token, readme)
        # The token must be followed by a boundary, not glued to text.
        line = next(l for l in readme.splitlines() if token in l)
        self.assertTrue(
            line.strip().endswith("-->") or line.strip() == token,
            f"token needs a clean boundary, got {line!r}",
        )

    def test_readme_declares_python_not_a_node_runtime(self):
        self.assertEqual(self.package["runtimeHint"], "uvx")

    def test_claimed_tool_count_matches_the_server(self):
        from sechelix_runner.mcp_server import TOOLS

        claimed = self.server["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
        self.assertEqual(claimed["io.sechelix"]["toolCount"], len(TOOLS))

    def test_no_shell_claim_is_true(self):
        """The listing says there is no shell access. Check that stays true."""
        from sechelix_runner import mcp_server
        from sechelix_runner.mcp_server import TOOLS

        claimed = self.server["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
        self.assertFalse(claimed["io.sechelix"]["shellAccess"])

        source = Path(mcp_server.__file__).read_text(encoding="utf-8")
        for banned in ("subprocess", "os.system", "shell=True", "os.popen"):
            self.assertNotIn(banned, source, f"MCP adapter must not reach a shell ({banned})")
        # "run" in `sechelix_run_status` is a SecHelix run, not a verb. These
        # words are the ones that would mean executing something arbitrary.
        for name in TOOLS:
            self.assertFalse(
                any(word in name for word in ("exec", "shell", "command", "spawn", "eval")),
                f"tool {name} reads as command execution",
            )

    def test_credentials_claim_is_true(self):
        claimed = self.server["_meta"]["io.modelcontextprotocol.registry/publisher-provided"]
        self.assertFalse(claimed["credentialsRequired"] if "credentialsRequired" in claimed
                         else claimed["io.sechelix"]["credentialsRequired"])
        self.assertNotIn("environmentVariables", self.package)

    def test_path_confinement_is_advertised_and_enforced(self):
        import tempfile

        from sechelix_runner.mcp_server import PathOutsideRoot, SecHelixMCP

        with tempfile.TemporaryDirectory() as root:
            api = SecHelixMCP(root)
            for escape in ("../..", "../../etc/passwd", "a/../../..", "/etc/passwd"):
                with self.subTest(escape=escape):
                    with self.assertRaises(PathOutsideRoot):
                        api._resolve(escape)
            self.assertTrue(str(api._resolve("inside/dir")).startswith(str(api.root)))


if __name__ == "__main__":
    unittest.main()
