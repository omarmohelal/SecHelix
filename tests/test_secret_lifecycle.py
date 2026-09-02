"""A lifecycle record must never hold the secret, and never round a step up.

The negative cases here are the reason the module exists: deleting a secret from
the working tree recorded as a fix for git history, and a rotation recorded as a
remediation while the old credential still authenticates.
"""

import json
import unittest

from sechelix_core.contracts import validate_contract
from sechelix_core.proof_bundle import REDACTED
from sechelix_core.secret_lifecycle import (
    ACCEPTED_CLEANUP,
    CLAIMED,
    CONFIRMED,
    EXPOSED,
    NOT_DONE,
    PARTIALLY_REMEDIATED,
    REMEDIATED,
    RESIDUAL_NOTES,
    SURFACES,
    UNKNOWN,
    SecretIdentity,
    SecretLifecycle,
    SecretLifecycleError,
    fingerprint,
    is_remediated,
    render_markdown,
)


# Credential-shaped fixtures are assembled at runtime. A literal here would be
# flagged by this project's own secret gate and by GitHub's, and a scanner that
# learns to ignore the tests directory stops protecting it.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"
OPENAI = "sk" + "-" + "abcdefghijklmnopqrstuvwxyz012345"


def a_secret(value=AWS, kind="aws_access_key"):
    return SecretIdentity.from_value(value, kind=kind, detector="tests")


def a_record(record_id="SEC-1", value=AWS):
    return SecretLifecycle(record_id, a_secret(value))


def fully_remediated():
    """A record that legitimately reaches REMEDIATED, for the negative tests to break."""
    record = a_record()
    record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
    record.locate("GIT_HISTORY", "commit 9a1f2c3", evidence_ids=["EV-2"])
    record.clean("SOURCE", "REMOVED_FROM_SOURCE", evidence_ids=["EV-3"])
    record.clean("GIT_HISTORY", "HISTORY_REWRITTEN", evidence_ids=["EV-4"])
    for surface in ("BUILD_ARTIFACT", "FRONTEND_BUNDLE", "LOGS", "CI_CONFIG", "CONTAINER_IMAGE"):
        record.searched_clean(surface, evidence_ids=[f"EV-S-{surface}"])
    record.revoke(status=CONFIRMED, method="provider console", evidence_ids=["EV-5"])
    record.rotate(status=CONFIRMED, method="new key issued", evidence_ids=["EV-6"])
    record.record_retest(
        status=CONFIRMED,
        assertion="the old key is rejected by the provider",
        evidence_ids=["EV-7"],
    )
    return record


class FingerprintTests(unittest.TestCase):
    def test_the_same_value_fingerprints_the_same_way(self):
        self.assertEqual(fingerprint(AWS), fingerprint(AWS))

    def test_different_values_fingerprint_differently(self):
        self.assertNotEqual(fingerprint(AWS), fingerprint(GH))

    def test_the_fingerprint_is_not_a_bare_sha256_of_the_value(self):
        """A published fingerprint must not be lookupable in a general-purpose table."""
        import hashlib

        plain = hashlib.sha256(AWS.encode("utf-8")).hexdigest()
        self.assertFalse(plain.startswith(fingerprint(AWS)))

    def test_an_empty_value_is_refused(self):
        with self.assertRaises(SecretLifecycleError):
            SecretIdentity.from_value("", kind="k", detector="tests")

    def test_the_identity_has_no_field_that_could_hold_the_value(self):
        identity = a_secret()
        for value in vars(identity).values():
            self.assertNotIn(AWS, str(value))


class NoSecretEscapesTests(unittest.TestCase):
    def test_no_full_value_survives_anywhere_in_the_export(self):
        record = fully_remediated()
        blob = json.dumps(record.as_dict())
        self.assertNotIn(AWS, blob)

    def test_no_full_value_survives_the_markdown_render(self):
        record = fully_remediated()
        self.assertNotIn(AWS, render_markdown(record.as_dict()))

    def test_a_secret_pasted_into_a_locator_is_redacted(self):
        """The operator who pastes the value into a locator field is a real person."""
        record = a_record()
        record.locate("LOGS", f"app.log line 40: {GH}", evidence_ids=["EV-1"])
        exported = record.as_dict()
        blob = json.dumps(exported)
        self.assertNotIn(GH, blob)
        self.assertIn(REDACTED, blob)
        self.assertTrue(exported["redaction"]["applied"])

    def test_a_secret_pasted_into_a_step_note_is_redacted(self):
        record = a_record()
        record.revoke(status=CLAIMED, method="rotated", note=f"old value was {OPENAI}")
        blob = json.dumps(record.as_dict())
        self.assertNotIn(OPENAI, blob)

    def test_the_redaction_count_is_recorded(self):
        record = a_record()
        record.locate("SOURCE", f"config.py: {AWS}", evidence_ids=["EV-1"])
        redaction = record.as_dict()["redaction"]
        self.assertGreater(redaction["total_values_redacted"], 0)
        self.assertIn("aws_key", redaction["by_pattern"])


class GitHistoryTests(unittest.TestCase):
    """The conflation this module exists to make impossible."""

    def test_removing_from_source_cannot_be_recorded_against_git_history(self):
        record = a_record()
        record.locate("GIT_HISTORY", "commit 9a1f2c3", evidence_ids=["EV-1"])
        with self.assertRaises(SecretLifecycleError) as caught:
            record.clean("GIT_HISTORY", "REMOVED_FROM_SOURCE", evidence_ids=["EV-2"])
        self.assertIn("working tree", str(caught.exception))

    def test_removing_from_source_cannot_be_recorded_against_any_other_surface(self):
        for surface in SURFACES:
            if surface == "SOURCE":
                continue
            with self.subTest(surface):
                record = a_record()
                record.locate(surface, "somewhere", evidence_ids=["EV-1"])
                with self.assertRaises(SecretLifecycleError):
                    record.clean(surface, "REMOVED_FROM_SOURCE", evidence_ids=["EV-2"])

    def test_the_accepted_cleanup_sets_are_disjoint(self):
        """Nothing may clear two surfaces at once, or the conflation returns by another name."""
        seen: dict[str, str] = {}
        for surface, actions in ACCEPTED_CLEANUP.items():
            for action in actions:
                self.assertNotIn(action, seen, f"{action} also clears {seen.get(action)}")
                seen[action] = surface

    def test_cleaning_source_leaves_git_history_exposed(self):
        record = a_record()
        record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
        record.locate("GIT_HISTORY", "commit 9a1f2c3", evidence_ids=["EV-2"])
        record.clean("SOURCE", "REMOVED_FROM_SOURCE", evidence_ids=["EV-3"])
        exported = record.as_dict()
        surfaces = {item["surface"]: item["status"] for item in exported["surfaces"]}
        self.assertEqual(surfaces["SOURCE"], "CLEANED")
        self.assertEqual(surfaces["GIT_HISTORY"], EXPOSED)
        self.assertFalse(is_remediated(exported))

    def test_every_surface_carries_what_its_cleanup_does_not_reach(self):
        record = a_record()
        for surface in record.as_dict()["surfaces"]:
            self.assertTrue(surface["residual_note"].strip(), surface["surface"])
        self.assertIn("clones", RESIDUAL_NOTES["GIT_HISTORY"])

    def test_the_source_residual_note_says_it_touches_nothing_else(self):
        self.assertIn("no other surface", RESIDUAL_NOTES["SOURCE"])


class RevocationTests(unittest.TestCase):
    def test_rotation_without_revocation_is_not_remediation(self):
        record = fully_remediated()
        record.revoke(status=NOT_DONE)
        self.assertNotEqual(record.state(), REMEDIATED)
        self.assertEqual(record.state(), PARTIALLY_REMEDIATED)

    def test_rotation_without_revocation_says_so_in_the_blockers(self):
        record = a_record()
        record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
        record.rotate(status=CONFIRMED, method="new key issued", evidence_ids=["EV-2"])
        blockers = " ".join(record.blockers())
        self.assertIn("rotated but not revoked", blockers)
        self.assertIn("does not invalidate the old one", blockers)

    def test_a_claimed_revocation_does_not_satisfy_revocation(self):
        record = fully_remediated()
        record.revoke(status=CLAIMED, method="someone said so")
        self.assertNotEqual(record.state(), REMEDIATED)
        self.assertIn("claimed but carries no evidence", " ".join(record.blockers()))

    def test_a_confirmed_step_requires_evidence(self):
        record = a_record()
        with self.assertRaises(SecretLifecycleError):
            record.revoke(status=CONFIRMED, method="provider console")

    def test_revocation_is_required_even_when_every_surface_is_clean(self):
        record = fully_remediated()
        record.revoke(status=NOT_DONE)
        record.rotate(status=NOT_DONE)
        blockers = " ".join(record.blockers())
        self.assertIn("every other step is cosmetic", blockers)


class StateTests(unittest.TestCase):
    def test_a_complete_record_is_remediated(self):
        record = fully_remediated()
        self.assertEqual(record.state(), REMEDIATED)
        self.assertEqual(record.blockers(), [])
        self.assertTrue(is_remediated(record.as_dict()))

    def test_an_untouched_record_is_unknown(self):
        record = a_record()
        self.assertEqual(record.state(), UNKNOWN)

    def test_a_located_untouched_record_is_exposed(self):
        record = a_record()
        record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
        self.assertEqual(record.state(), EXPOSED)

    def test_an_unsearched_surface_blocks_remediation(self):
        record = fully_remediated()
        record.surfaces["LOGS"].status = "NOT_SEARCHED"
        record.surfaces["LOGS"].evidence_ids = []
        self.assertNotEqual(record.state(), REMEDIATED)
        self.assertIn("never searched", " ".join(record.blockers()))

    def test_a_retest_is_required_before_remediation(self):
        record = fully_remediated()
        record.record_retest(status=NOT_DONE)
        self.assertNotEqual(record.state(), REMEDIATED)
        self.assertIn("old credential is now rejected", " ".join(record.blockers()))

    def test_is_remediated_is_false_for_every_other_state(self):
        for state in (UNKNOWN, EXPOSED, PARTIALLY_REMEDIATED):
            with self.subTest(state):
                self.assertFalse(is_remediated({"state": state}))

    def test_a_clean_search_requires_evidence(self):
        record = a_record()
        with self.assertRaises(SecretLifecycleError):
            record.searched_clean("LOGS", evidence_ids=[])

    def test_a_clean_search_cannot_retract_a_located_exposure(self):
        record = a_record()
        record.locate("LOGS", "app.log:40", evidence_ids=["EV-1"])
        with self.assertRaises(SecretLifecycleError):
            record.searched_clean("LOGS", evidence_ids=["EV-2"])

    def test_a_surface_nobody_searched_cannot_be_cleaned(self):
        record = a_record()
        with self.assertRaises(SecretLifecycleError) as caught:
            record.clean("SOURCE", "REMOVED_FROM_SOURCE", evidence_ids=["EV-1"])
        self.assertIn("never searched", str(caught.exception))

    def test_not_applicable_requires_a_reason(self):
        record = a_record()
        with self.assertRaises(SecretLifecycleError):
            record.not_applicable("FRONTEND_BUNDLE", "  ")

    def test_not_applicable_does_not_block_remediation(self):
        record = fully_remediated()
        record.surfaces["FRONTEND_BUNDLE"].status = "NOT_SEARCHED"
        record.not_applicable("FRONTEND_BUNDLE", "this target ships no frontend")
        self.assertEqual(record.state(), REMEDIATED)

    def test_an_unknown_surface_is_refused(self):
        record = a_record()
        with self.assertRaises(SecretLifecycleError):
            record.locate("SLACK_DM", "somewhere", evidence_ids=["EV-1"])


class RenderingTests(unittest.TestCase):
    def test_unknown_never_renders_as_remediated(self):
        """A reader skimming a page for the word will find it wherever it appears."""
        record = a_record()
        text = render_markdown(record.as_dict())
        self.assertIn("`UNKNOWN`", text)
        self.assertNotIn("REMEDIATED", text)

    def test_exposed_never_renders_as_remediated(self):
        record = a_record()
        record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
        text = render_markdown(record.as_dict())
        self.assertIn("`EXPOSED`", text)
        self.assertNotIn("`REMEDIATED`", text)

    def test_a_partial_record_renders_its_outstanding_work(self):
        record = fully_remediated()
        record.revoke(status=NOT_DONE)
        text = render_markdown(record.as_dict())
        self.assertIn("`PARTIALLY_REMEDIATED`", text)
        self.assertIn("Outstanding", text)

    def test_a_remediated_record_renders_as_remediated(self):
        text = render_markdown(fully_remediated().as_dict())
        self.assertIn("**State: `REMEDIATED`.**", text)


class ContractTests(unittest.TestCase):
    def test_a_complete_record_validates(self):
        validate_contract("secret-lifecycle", fully_remediated().as_dict())

    def test_an_untouched_record_validates(self):
        validate_contract("secret-lifecycle", a_record().as_dict())

    def test_a_partial_record_validates(self):
        record = a_record()
        record.locate("SOURCE", "app/settings.py:12", evidence_ids=["EV-1"])
        record.locate("GIT_HISTORY", "commit 9a1f2c3", evidence_ids=["EV-2"])
        record.clean("SOURCE", "REMOVED_FROM_SOURCE", status=CLAIMED)
        record.rotate(status=CONFIRMED, method="new key", evidence_ids=["EV-3"])
        validate_contract("secret-lifecycle", record.as_dict())

    def test_every_surface_appears_in_the_export(self):
        exported = a_record().as_dict()
        self.assertEqual([s["surface"] for s in exported["surfaces"]], list(SURFACES))


if __name__ == "__main__":
    unittest.main()
