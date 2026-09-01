"""Property-based tests over generated inputs.

Example-based tests check the cases someone thought of. These check invariants
over many generated inputs, which is how you find the case nobody thought of.

No third-party dependency: this project is standard library only, so generation
uses `random` with a **fixed seed per test**. That keeps runs reproducible — a
failure reported in CI reproduces exactly on a laptop — at the cost of not
exploring new inputs on every run. Widen `ROUNDS` or change `SEED` deliberately
when hunting, not silently.

Each test states the invariant it defends. An invariant that cannot be stated in
one sentence is usually not an invariant.
"""

import random
import string
import unittest

from sechelix_core.attack_chains import CONFIRMED, POTENTIAL, correlate
from sechelix_core.patch_mode import PatchModeError, propose, write_patch_set
from sechelix_core.untrusted_repo import _normalize
from sechelix_core.variant_rules import VariantRuleError, generate_rule

SEED = 20260901
ROUNDS = 400

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNASSIGNED"]
STATUSES = ["VERIFIED", "HYPOTHESIS", "LIKELY_BUT_UNPROVEN",
            "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE", "BLOCKED_BY_ENVIRONMENT"]

WORDS = [
    "enumeration", "reset", "token", "mfa", "idor", "tenant", "export", "listing",
    "webhook", "replay", "idempotent", "refund", "ledger", "prompt injection",
    "tools", "mcp", "egress", "upload", "unpinned", "postinstall", "secret",
    "stack trace", "listener", "runtime", "sender", "toolkit", "cache", "header",
]


def rng(salt=0):
    return random.Random(SEED + salt)


def a_finding(r, **over):
    base = {
        "finding_id": "SHX-F-" + "".join(r.choices(string.ascii_uppercase + string.digits, k=8)),
        "title": " ".join(r.choices(WORDS, k=r.randint(1, 6))),
        "status": r.choice(STATUSES),
        "severity": r.choice(SEVERITIES),
        "affected_surface": [f"app/{r.choice(['a','b','c'])}.py:{r.randint(1, 400)}"],
    }
    base.update(over)
    return base


class AttackChainProperties(unittest.TestCase):
    def test_severity_is_never_inherited_from_a_component(self):
        """A chain's severity comes from its outcome, never from a component."""
        r = rng(1)
        for _ in range(ROUNDS):
            findings = [a_finding(r) for _ in range(r.randint(0, 6))]
            for chain in correlate(findings):
                if chain["status"] == CONFIRMED:
                    # The definition's severity, not any component's.
                    self.assertIn(chain["severity"], {"CRITICAL", "HIGH"})
                else:
                    self.assertEqual(chain["severity"], "UNASSIGNED")

    def test_a_potential_chain_never_carries_severity(self):
        r = rng(2)
        for _ in range(ROUNDS):
            findings = [a_finding(r, status=r.choice(
                ["HYPOTHESIS", "LIKELY_BUT_UNPROVEN", "FALSE_POSITIVE"]))
                for _ in range(r.randint(0, 6))]
            for chain in correlate(findings):
                self.assertNotEqual(chain["status"], CONFIRMED)
                self.assertEqual(chain["severity"], "UNASSIGNED")
                self.assertEqual(chain["claim_status"], "HYPOTHESIS")

    def test_confirmed_requires_every_link_verified(self):
        """No composition of unverified findings can ever reach CONFIRMED."""
        r = rng(3)
        for _ in range(ROUNDS):
            findings = [a_finding(r) for _ in range(r.randint(0, 8))]
            verified = {f["finding_id"] for f in findings if f["status"] == "VERIFIED"}
            for chain in correlate(findings):
                if chain["status"] == CONFIRMED:
                    for component in chain["component_findings"]:
                        self.assertIn(component["finding_id"], verified)

    def test_every_chain_cites_at_least_one_component(self):
        """A chain that cannot name a component must not be emitted."""
        r = rng(4)
        for _ in range(ROUNDS):
            findings = [a_finding(r) for _ in range(r.randint(0, 6))]
            for chain in correlate(findings):
                self.assertTrue(chain["component_findings"], chain["chain_id"])

    def test_a_potential_chain_always_names_a_gap(self):
        """POTENTIAL means something is missing; it must say what."""
        r = rng(5)
        for _ in range(ROUNDS):
            findings = [a_finding(r) for _ in range(r.randint(0, 6))]
            for chain in correlate(findings):
                if chain["status"] == POTENTIAL:
                    self.assertTrue(
                        chain["missing_links"] or chain["unverified_components"],
                        chain["chain_id"],
                    )

    def test_correlation_is_order_independent(self):
        """Shuffling the findings must not change the verdict."""
        r = rng(6)
        for _ in range(120):
            findings = [a_finding(r) for _ in range(r.randint(2, 7))]
            first = {c["chain_id"]: c["status"] for c in correlate(findings)}
            shuffled = findings[:]
            r.shuffle(shuffled)
            second = {c["chain_id"]: c["status"] for c in correlate(shuffled)}
            self.assertEqual(first, second)


class PathConfinementProperties(unittest.TestCase):
    """No generated finding id may ever produce a path outside the output directory."""

    HOSTILE_BITS = ["..", "/", "\\", ":", "%2e", "~", "\x00", " ", ".", "*", "?",
                    "NUL", "CON", "COM1", "LPT1", "a", "1", "-", "_"]

    def test_no_id_escapes_the_output_directory(self):
        r = rng(7)
        base = {
            "title": "t", "status": "VERIFIED", "severity": "HIGH",
            "affected_surface": ["a.py:1"],
            "verification": {"independent": True, "outcome": "VERIFIED",
                             "evidence_ids": [], "refutation_attempt": "x"},
            "remediation": {"root_cause_fix": "x", "evidence_ids": []},
            "regression": {"status": "NOT_RUN", "command": "x",
                           "assertion": "x", "evidence_ids": []},
        }
        escaped = 0
        for _ in range(ROUNDS * 2):
            fid = "".join(r.choices(self.HOSTILE_BITS, k=r.randint(1, 6)))
            finding = dict(base, finding_id=fid)
            try:
                result = propose([finding], output_dir="work/out")
            except PatchModeError:
                continue  # refusing is the correct outcome
            for proposal in result.proposals:
                for path in (proposal.patch_path, proposal.rationale_path):
                    segments = path.split("/")
                    # Traversal is a path *segment* equal to "..", not the substring.
                    # "work/out/NULa.._.patch" contains ".." and escapes nothing.
                    if not path.startswith("work/out/") or ".." in segments:
                        escaped += 1
                    self.assertNotIn("\\", path, fid)
                    self.assertEqual(len(segments), 3, f"{fid!r} -> {path!r}")
        self.assertEqual(escaped, 0)

    def test_writes_never_leave_the_declared_directory(self):
        r = rng(8)
        base = {
            "title": "t", "status": "VERIFIED", "severity": "HIGH",
            "affected_surface": ["a.py:1"],
            "verification": {"independent": True, "outcome": "VERIFIED",
                             "evidence_ids": [], "refutation_attempt": "x"},
            "remediation": {"root_cause_fix": "x", "evidence_ids": []},
            "regression": {"status": "NOT_RUN", "command": "x",
                           "assertion": "x", "evidence_ids": []},
        }
        for _ in range(200):
            fid = "SHX-F-" + "".join(r.choices(string.ascii_uppercase + string.digits, k=6))
            written = {}
            patch_set = propose([dict(base, finding_id=fid)],
                                diffs={fid: "--- a\n+++ b\n"}, output_dir="work/x")
            write_patch_set(patch_set, "work/x",
                            writer=lambda p, c: written.__setitem__(p, c))
            for path in written:
                self.assertTrue(path.startswith("work/x/"), path)


class NormalizationProperties(unittest.TestCase):
    """Path normalization must never invent a leading dot or lose one."""

    def test_a_leading_dot_directory_survives_normalization(self):
        r = rng(9)
        names = [".claude", ".github", ".agents", "src", "app", ".env.example"]
        for _ in range(ROUNDS):
            parts = r.choices(names, k=r.randint(1, 4))
            path = "/".join(parts)
            for prefix in ("", "./", "././", "//"):
                normalized = _normalize(prefix + path)
                self.assertFalse(normalized.startswith("/"), normalized)
                self.assertFalse(normalized.startswith("./"), normalized)
                if parts[0].startswith("."):
                    self.assertTrue(
                        normalized.startswith(parts[0]),
                        f"{prefix + path!r} -> {normalized!r} lost its leading dot",
                    )

    def test_normalization_is_idempotent(self):
        r = rng(10)
        chars = string.ascii_lowercase + "./\\-_"
        for _ in range(ROUNDS):
            raw = "".join(r.choices(chars, k=r.randint(1, 24)))
            once = _normalize(raw)
            self.assertEqual(once, _normalize(once), raw)

    def test_backslashes_are_always_folded(self):
        r = rng(11)
        for _ in range(ROUNDS):
            raw = "\\".join("".join(r.choices(string.ascii_lowercase, k=3))
                            for _ in range(r.randint(1, 4)))
            self.assertNotIn("\\", _normalize(raw))


class VariantRuleProperties(unittest.TestCase):
    """A generated rule can never inherit its seed's authority."""

    def test_rule_severity_is_always_info(self):
        r = rng(12)
        made = 0
        for _ in range(ROUNDS):
            seed = a_finding(r, status="VERIFIED",
                             affected_surface=[f"app/x.{r.choice(['py','ts','go','java'])}:1"])
            try:
                rule = generate_rule(seed, ["$X == $Y"])
            except VariantRuleError:
                continue
            made += 1
            emitted = rule.as_semgrep()["rules"][0]
            self.assertEqual(emitted["severity"], "INFO", seed["severity"])
            self.assertEqual(emitted["metadata"]["claim_status"], "HYPOTHESIS")
            self.assertEqual(emitted["metadata"]["confidence"], "LOW")
        self.assertGreater(made, 0, "generation never succeeded; the property is untested")

    def test_an_unverified_seed_never_produces_a_rule(self):
        r = rng(13)
        for _ in range(ROUNDS):
            status = r.choice([s for s in STATUSES if s != "VERIFIED"])
            seed = a_finding(r, status=status, affected_surface=["app/x.py:1"])
            with self.assertRaises(VariantRuleError):
                generate_rule(seed, ["$X == $Y"])


if __name__ == "__main__":
    unittest.main()
