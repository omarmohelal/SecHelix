"""Evidence may be reused only where its inputs can be shown to still hold.

The failure this suite guards is quiet: a record whose provenance cannot be
established gets rounded up to "unchanged", and a clean result from yesterday is
attached to code nobody inspected. So the load-bearing assertions here are the
negative ones — UNKNOWN is never reusable, an empty dependency set is never
reusable, and a missing change set costs work rather than correctness.
"""

import copy
import json
import random
import unittest

from sechelix_core.contracts import validate_contract
from sechelix_core.evidence_cache import (
    CACHE_STATES,
    INVALIDATED,
    RECOMPUTED,
    REUSED,
    UNKNOWN,
    UNRECORDED_FINGERPRINT,
    CachedEvidence,
    EvidenceCacheError,
    cache_entry,
    content_hash,
    evaluate_cache,
    fingerprint,
    hypotheses_to_rerun,
    mark_recomputed,
)
from tests.helpers import evidence

REPO = "omarmohelal/example"
BASE = "06ab8ca680d477b8005805d67ab44d11507e3321"
NEXT = "a7f1f4799234c5410c872a54de18f3dbbcc316cc"

AUTH_V1 = content_hash("def require_owner(user, record): return user.id == record.owner_id\n")
AUTH_V2 = content_hash("def require_owner(user, record): return True\n")
ROUTE_V1 = content_hash("@app.get('/orders/{id}')\n")


def entry(evidence_id, *, inputs, commit=BASE, repository=REPO, context=None, hypotheses=()):
    """A cached record with a complete fingerprint unless a test breaks it."""
    return CachedEvidence(
        evidence_id=evidence_id,
        fingerprint=fingerprint(
            repository=repository, commit=commit, inputs=inputs, context=context
        ),
        hypothesis_ids=tuple(hypotheses),
    )


def replay(entries, **kwargs):
    options = {"repository": REPO, "commit": NEXT}
    options.update(kwargs)
    return evaluate_cache(entries, **options)


class FingerprintTests(unittest.TestCase):
    def test_paths_and_hashes_are_normalized(self):
        fp = fingerprint(
            repository=REPO,
            commit=BASE.upper(),
            inputs={"./src\\auth.py": AUTH_V1.upper(), "src/routes.py": ROUTE_V1},
        )
        self.assertEqual(fp.commit, BASE)
        self.assertEqual(fp.paths, ("src/auth.py", "src/routes.py"))
        self.assertEqual(dict(fp.inputs)["src/auth.py"], AUTH_V1)

    def test_inputs_are_sorted_so_read_order_cannot_change_identity(self):
        forward = fingerprint(
            repository=REPO, commit=BASE,
            inputs=[("src/auth.py", AUTH_V1), ("src/routes.py", ROUTE_V1)],
        )
        backward = fingerprint(
            repository=REPO, commit=BASE,
            inputs=[("src/routes.py", ROUTE_V1), ("src/auth.py", AUTH_V1)],
        )
        self.assertEqual(forward, backward)

    def test_two_hashes_for_one_path_are_refused(self):
        with self.assertRaises(EvidenceCacheError):
            fingerprint(
                repository=REPO, commit=BASE,
                inputs=[("src/auth.py", AUTH_V1), ("./src/auth.py", AUTH_V2)],
            )

    def test_a_malformed_input_pair_is_refused(self):
        with self.assertRaises(EvidenceCacheError):
            fingerprint(repository=REPO, commit=BASE, inputs=["src/auth.py"])

    def test_a_bare_string_is_not_read_character_by_character(self):
        """A two-character string unpacks into a pair, so it must be refused by type."""
        for inputs in ("ab", ["ab"], [b"ab"]):
            with self.subTest(inputs=inputs):
                with self.assertRaises(EvidenceCacheError):
                    fingerprint(repository=REPO, commit=BASE, inputs=inputs)

    def test_a_complete_fingerprint_reports_no_incompleteness(self):
        fp = fingerprint(repository=REPO, commit=BASE, inputs={"src/auth.py": AUTH_V1})
        self.assertTrue(fp.complete)
        self.assertIsNone(fp.incompleteness())

    def test_an_empty_dependency_set_is_incomplete(self):
        fp = fingerprint(repository=REPO, commit=BASE, inputs={})
        self.assertFalse(fp.complete)
        self.assertIn("no dependencies", fp.incompleteness())

    def test_a_missing_commit_is_incomplete(self):
        fp = fingerprint(repository=REPO, commit="", inputs={"src/auth.py": AUTH_V1})
        self.assertFalse(fp.complete)
        self.assertIn("commit", fp.incompleteness())

    def test_a_missing_repository_is_incomplete(self):
        fp = fingerprint(repository="", commit=BASE, inputs={"src/auth.py": AUTH_V1})
        self.assertFalse(fp.complete)
        self.assertIn("repository", fp.incompleteness())

    def test_an_unusable_content_hash_is_incomplete(self):
        fp = fingerprint(repository=REPO, commit=BASE, inputs={"src/auth.py": "unknown"})
        self.assertFalse(fp.complete)
        self.assertIn("content hash", fp.incompleteness())

    def test_the_unrecorded_fingerprint_says_so_plainly(self):
        self.assertFalse(UNRECORDED_FINGERPRINT.complete)
        self.assertIn("no dependency fingerprint", UNRECORDED_FINGERPRINT.incompleteness())


class CacheEntryTests(unittest.TestCase):
    def test_caching_never_mutates_the_evidence_record(self):
        """evidence-v1 forbids extra properties, and a cache is not a claim evidence makes."""
        record = evidence("EV-OBS")
        before = copy.deepcopy(record)
        cache_entry(record, fingerprint(repository=REPO, commit=BASE, inputs={"src/auth.py": AUTH_V1}))
        self.assertEqual(record, before)
        validate_contract("evidence", record)

    def test_hypothesis_ids_are_carried_from_the_record(self):
        cached = cache_entry(evidence("EV-OBS"), None)
        self.assertEqual(cached.hypothesis_ids, ("SHX-AUTH-L01",))

    def test_duplicate_hypothesis_ids_are_collapsed(self):
        record = evidence("EV-OBS")
        record["related_hypothesis_ids"] = ["SHX-AUTH-L01", "SHX-AUTH-L01", "SHX-AUTHZ-L03"]
        self.assertEqual(cache_entry(record).hypothesis_ids, ("SHX-AUTH-L01", "SHX-AUTHZ-L03"))

    def test_a_record_without_an_id_cannot_be_cached(self):
        with self.assertRaises(EvidenceCacheError):
            cache_entry({"schema_version": "1.0"})

    def test_a_non_mapping_record_is_refused(self):
        with self.assertRaises(EvidenceCacheError):
            cache_entry(["EV-OBS"])

    def test_a_record_with_no_fingerprint_is_accepted_and_evaluates_unknown(self):
        cached = cache_entry(evidence("EV-OBS"))
        self.assertIs(cached.fingerprint, UNRECORDED_FINGERPRINT)
        self.assertEqual(replay([cached]).get("EV-OBS").state, UNKNOWN)


class ReuseTests(unittest.TestCase):
    def test_an_unchanged_dependency_is_reused(self):
        verdict = replay([entry("EV-A", inputs={"src/auth.py": AUTH_V1})], changed_paths=["README.md"])
        record = verdict.get("EV-A")
        self.assertEqual(record.state, REUSED)
        self.assertTrue(record.reusable)
        self.assertFalse(record.must_recompute)

    def test_nothing_changed_is_still_a_real_answer(self):
        verdict = replay([entry("EV-A", inputs={"src/auth.py": AUTH_V1})], changed_paths=[])
        self.assertEqual(verdict.get("EV-A").state, REUSED)

    def test_a_hash_that_still_matches_is_reused(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1})],
            changed_paths=["src/routes.py"],
            current_hashes={"src/auth.py": AUTH_V1},
        )
        self.assertEqual(verdict.get("EV-A").state, REUSED)

    def test_a_path_listed_as_changed_whose_content_is_identical_is_reused(self):
        """A hash beats a change set: an edit that was reverted changed nothing."""
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1})],
            changed_paths=["src/auth.py"],
            current_hashes={"src/auth.py": AUTH_V1},
        )
        self.assertEqual(verdict.get("EV-A").state, REUSED)

    def test_the_same_revision_reuses_without_a_change_set(self):
        verdict = replay([entry("EV-A", inputs={"src/auth.py": AUTH_V1})], commit=BASE)
        record = verdict.get("EV-A")
        self.assertEqual(record.state, REUSED)
        self.assertIn("this exact revision", record.reason)


class InvalidationTests(unittest.TestCase):
    def test_a_changed_dependency_invalidates(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1, "src/routes.py": ROUTE_V1})],
            changed_paths=["src/auth.py"],
        )
        record = verdict.get("EV-A")
        self.assertEqual(record.state, INVALIDATED)
        self.assertFalse(record.reusable)
        self.assertTrue(record.must_recompute)
        self.assertEqual(record.changed_paths, ("src/auth.py",))
        self.assertIn("src/auth.py", record.reason)

    def test_a_changed_hash_invalidates_even_outside_the_change_set(self):
        """A change set can be wrong or incomplete; the content cannot."""
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1})],
            changed_paths=[],
            current_hashes={"src/auth.py": AUTH_V2},
        )
        self.assertEqual(verdict.get("EV-A").state, INVALIDATED)

    def test_a_dirty_tree_at_the_same_commit_still_invalidates(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1})],
            commit=BASE,
            current_hashes={"src/auth.py": AUTH_V2},
        )
        self.assertEqual(verdict.get("EV-A").state, INVALIDATED)

    def test_separator_style_cannot_hide_a_change(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1})],
            changed_paths=["./src\\auth.py"],
        )
        self.assertEqual(verdict.get("EV-A").state, INVALIDATED)

    def test_a_record_from_another_repository_is_never_reused(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1}, repository="someone/else")],
            changed_paths=[],
        )
        record = verdict.get("EV-A")
        self.assertEqual(record.state, INVALIDATED)
        self.assertIn("someone/else", record.reason)

    def test_the_reason_truncates_instead_of_listing_everything(self):
        paths = {f"src/mod{index}.py": content_hash(str(index)) for index in range(9)}
        verdict = replay([entry("EV-A", inputs=paths)], changed_paths=list(paths))
        record = verdict.get("EV-A")
        self.assertEqual(len(record.changed_paths), 9)
        self.assertIn("and 4 more", record.reason)


class UnknownTests(unittest.TestCase):
    """Unprovable is not the same as unchanged, and must never read as unchanged."""

    def test_an_empty_dependency_set_is_unknown_not_reused(self):
        verdict = replay([entry("EV-A", inputs={})], changed_paths=[])
        record = verdict.get("EV-A")
        self.assertEqual(record.state, UNKNOWN)
        self.assertFalse(record.reusable)
        self.assertIn("no dependencies", record.reason)

    def test_a_partial_fingerprint_is_unknown(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1}, commit="")],
            changed_paths=[],
        )
        self.assertEqual(verdict.get("EV-A").state, UNKNOWN)

    def test_a_missing_fingerprint_is_unknown(self):
        verdict = replay([CachedEvidence("EV-A")], changed_paths=[])
        self.assertEqual(verdict.get("EV-A").state, UNKNOWN)

    def test_an_unusable_hash_is_unknown_not_reused(self):
        verdict = replay([entry("EV-A", inputs={"src/auth.py": "NOT_MEASURED"})], changed_paths=[])
        self.assertEqual(verdict.get("EV-A").state, UNKNOWN)

    def test_no_change_set_at_a_new_revision_is_unknown(self):
        """Forgetting the change set must cost work, never correctness."""
        verdict = replay([entry("EV-A", inputs={"src/auth.py": AUTH_V1})])
        record = verdict.get("EV-A")
        self.assertEqual(record.state, UNKNOWN)
        self.assertEqual(record.undetermined_paths, ("src/auth.py",))

    def test_partial_hash_coverage_without_a_change_set_is_unknown(self):
        verdict = replay(
            [entry("EV-A", inputs={"src/auth.py": AUTH_V1, "src/routes.py": ROUTE_V1})],
            current_hashes={"src/auth.py": AUTH_V1},
        )
        record = verdict.get("EV-A")
        self.assertEqual(record.state, UNKNOWN)
        self.assertEqual(record.undetermined_paths, ("src/routes.py",))

    def test_an_incomplete_fingerprint_is_checked_before_anything_can_reuse_it(self):
        """A record that declared nothing must not benefit from an empty change set."""
        for broken in (
            entry("EV-A", inputs={}, commit=NEXT),
            CachedEvidence("EV-A"),
        ):
            with self.subTest(fingerprint=broken.fingerprint):
                self.assertEqual(replay([broken], changed_paths=[]).get("EV-A").state, UNKNOWN)

    def test_only_reused_is_reusable(self):
        entries = [
            entry("EV-REUSE", inputs={"src/auth.py": AUTH_V1}),
            entry("EV-INVALID", inputs={"src/routes.py": ROUTE_V1}),
            entry("EV-EMPTY", inputs={}),
            CachedEvidence("EV-NONE"),
        ]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual({record.state for record in verdict.verdicts},
                         {REUSED, INVALIDATED, UNKNOWN})
        for record in verdict.verdicts:
            self.assertEqual(record.reusable, record.state == REUSED)
            self.assertEqual(record.must_recompute, record.state in {INVALIDATED, UNKNOWN})


class InputRefusalTests(unittest.TestCase):
    def test_an_unnamed_revision_is_refused(self):
        for options in ({"repository": "", "commit": NEXT}, {"repository": REPO, "commit": " "}):
            with self.subTest(**options):
                with self.assertRaises(EvidenceCacheError):
                    evaluate_cache([], **options)

    def test_two_fingerprints_for_one_record_are_refused(self):
        entries = [
            entry("EV-A", inputs={"src/auth.py": AUTH_V1}),
            entry("EV-A", inputs={"src/routes.py": ROUTE_V1}),
        ]
        with self.assertRaises(EvidenceCacheError):
            replay(entries, changed_paths=[])

    def test_a_raw_mapping_is_not_a_cache_entry(self):
        with self.assertRaises(EvidenceCacheError):
            replay([{"evidence_id": "EV-A"}], changed_paths=[])


class TelemetryTests(unittest.TestCase):
    def build(self):
        entries = [
            entry("EV-REUSE", inputs={"src/auth.py": AUTH_V1}, hypotheses=["SHX-AUTH-L01"]),
            entry("EV-CHANGED", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"]),
            entry("EV-EMPTY", inputs={}, hypotheses=["SHX-DB-L04"]),
            CachedEvidence("EV-NONE", hypothesis_ids=("SHX-CRYPTO-L07",)),
        ]
        return replay(entries, changed_paths=["src/routes.py"])

    def test_counts_are_correct_per_state(self):
        counts = self.build().counts
        self.assertEqual(counts[REUSED], 1)
        self.assertEqual(counts[INVALIDATED], 1)
        self.assertEqual(counts[UNKNOWN], 2)
        self.assertEqual(counts[RECOMPUTED], 0)

    def test_counts_sum_to_the_record_count(self):
        verdict = self.build()
        self.assertEqual(sum(verdict.counts.values()), len(verdict.verdicts))
        self.assertEqual(verdict.as_dict()["record_count"], len(verdict.verdicts))
        self.assertEqual(sorted(verdict.counts), sorted(CACHE_STATES))

    def test_counts_still_sum_after_recomputation(self):
        verdict = mark_recomputed(self.build(), ["EV-CHANGED", "EV-EMPTY"])
        counts = verdict.counts
        self.assertEqual(counts[RECOMPUTED], 2)
        self.assertEqual(sum(counts.values()), len(verdict.verdicts))

    def test_every_invalidation_carries_its_reason(self):
        payload = self.build().as_dict()
        self.assertEqual(len(payload["invalidations"]), payload["counts"][INVALIDATED])
        for item in payload["invalidations"]:
            self.assertTrue(item["reason"].strip())
            self.assertEqual(item["changed_paths"], ["src/routes.py"])

    def test_every_unknown_carries_its_reason(self):
        payload = self.build().as_dict()
        self.assertEqual(len(payload["unresolved"]), payload["counts"][UNKNOWN])
        for item in payload["unresolved"]:
            self.assertTrue(item["reason"].strip())

    def test_telemetry_states_that_unknown_is_not_a_pass(self):
        notes = " ".join(self.build().as_dict()["notes"])
        self.assertIn("UNKNOWN is not a pass", notes)

    def test_telemetry_is_json_serializable(self):
        json.dumps(self.build().as_dict())

    def test_id_views_agree_with_the_states(self):
        verdict = self.build()
        self.assertEqual(verdict.reusable_evidence_ids, ("EV-REUSE",))
        self.assertEqual(set(verdict.stale_evidence_ids), {"EV-CHANGED", "EV-EMPTY", "EV-NONE"})
        self.assertIsNone(verdict.get("EV-ABSENT"))


class RecomputationTests(unittest.TestCase):
    def verdict(self):
        entries = [
            entry("EV-REUSE", inputs={"src/auth.py": AUTH_V1}),
            entry("EV-CHANGED", inputs={"src/routes.py": ROUTE_V1}),
            entry("EV-EMPTY", inputs={}),
        ]
        return replay(entries, changed_paths=["src/routes.py"])

    def test_an_invalidated_record_becomes_recomputed(self):
        record = mark_recomputed(self.verdict(), ["EV-CHANGED"]).get("EV-CHANGED")
        self.assertEqual(record.state, RECOMPUTED)
        self.assertFalse(record.reusable)
        self.assertFalse(record.must_recompute)
        self.assertIn("INVALIDATED", record.reason)
        self.assertIn("regenerated", record.reason)

    def test_an_unknown_record_becomes_recomputed(self):
        record = mark_recomputed(self.verdict(), ["EV-EMPTY"]).get("EV-EMPTY")
        self.assertEqual(record.state, RECOMPUTED)
        self.assertIn("UNKNOWN", record.reason)

    def test_a_reused_record_cannot_be_reported_as_recomputed(self):
        with self.assertRaises(EvidenceCacheError):
            mark_recomputed(self.verdict(), ["EV-REUSE"])

    def test_an_unevaluated_record_cannot_be_reported_as_recomputed(self):
        with self.assertRaises(EvidenceCacheError):
            mark_recomputed(self.verdict(), ["EV-ABSENT"])

    def test_marking_twice_changes_nothing(self):
        once = mark_recomputed(self.verdict(), ["EV-CHANGED"])
        twice = mark_recomputed(once, ["EV-CHANGED"])
        self.assertEqual(once.as_dict(), twice.as_dict())

    def test_the_original_verdict_is_untouched(self):
        original = self.verdict()
        before = original.as_dict()
        mark_recomputed(original, ["EV-CHANGED"])
        self.assertEqual(original.as_dict(), before)


class RerunTests(unittest.TestCase):
    def test_invalid_and_unknown_records_put_their_hypotheses_back_in_the_queue(self):
        entries = [
            entry("EV-REUSE", inputs={"src/auth.py": AUTH_V1}, hypotheses=["SHX-AUTH-L01"]),
            entry("EV-CHANGED", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"]),
            entry("EV-EMPTY", inputs={}, hypotheses=["SHX-DB-L04"]),
        ]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual(hypotheses_to_rerun(verdict), ["SHX-API-L02", "SHX-DB-L04"])

    def test_a_hypothesis_is_rerun_when_any_of_its_evidence_falls(self):
        """Four observations minus one is not three-quarters of a conclusion."""
        entries = [
            entry("EV-1", inputs={"src/auth.py": AUTH_V1}, hypotheses=["SHX-AUTHZ-L03"]),
            entry("EV-2", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-AUTHZ-L03"]),
        ]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual(verdict.get("EV-1").state, REUSED)
        self.assertEqual(hypotheses_to_rerun(verdict), ["SHX-AUTHZ-L03"])

    def test_nothing_is_rerun_when_everything_was_reused(self):
        entries = [entry("EV-1", inputs={"src/auth.py": AUTH_V1}, hypotheses=["SHX-AUTH-L01"])]
        self.assertEqual(hypotheses_to_rerun(replay(entries, changed_paths=[])), [])

    def test_a_recomputed_record_leaves_the_queue(self):
        entries = [entry("EV-1", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"])]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual(hypotheses_to_rerun(verdict), ["SHX-API-L02"])
        self.assertEqual(hypotheses_to_rerun(mark_recomputed(verdict, ["EV-1"])), [])

    def test_the_queue_is_deduplicated_and_sorted(self):
        entries = [
            entry("EV-1", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-DB-L04", "SHX-API-L02"]),
            entry("EV-2", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"]),
        ]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual(hypotheses_to_rerun(verdict), ["SHX-API-L02", "SHX-DB-L04"])

    def test_the_queue_matches_the_telemetry(self):
        entries = [
            entry("EV-1", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"]),
            entry("EV-2", inputs={}, hypotheses=["SHX-DB-L04"]),
        ]
        verdict = replay(entries, changed_paths=["src/routes.py"])
        self.assertEqual(verdict.as_dict()["hypotheses_to_rerun"], hypotheses_to_rerun(verdict))


class DeterminismTests(unittest.TestCase):
    def entries(self):
        return [
            entry("EV-REUSE", inputs={"src/auth.py": AUTH_V1}, hypotheses=["SHX-AUTH-L01"]),
            entry("EV-CHANGED", inputs={"src/routes.py": ROUTE_V1}, hypotheses=["SHX-API-L02"]),
            entry("EV-EMPTY", inputs={}, hypotheses=["SHX-DB-L04"]),
            CachedEvidence("EV-NONE"),
            entry("EV-MIXED", inputs={"src/auth.py": AUTH_V1, "src/routes.py": ROUTE_V1}),
        ]

    def test_the_same_inputs_produce_the_same_verdict(self):
        first = replay(self.entries(), changed_paths=["src/routes.py"]).as_dict()
        second = replay(self.entries(), changed_paths=["src/routes.py"]).as_dict()
        self.assertEqual(first, second)

    def test_entry_order_cannot_change_the_verdict(self):
        expected = replay(self.entries(), changed_paths=["src/routes.py"]).as_dict()
        shuffled = self.entries()
        random.Random(1789).shuffle(shuffled)
        self.assertEqual(replay(shuffled, changed_paths=["src/routes.py"]).as_dict(), expected)
        self.assertEqual(
            replay(list(reversed(self.entries())), changed_paths=["src/routes.py"]).as_dict(),
            expected,
        )

    def test_change_set_order_cannot_change_the_verdict(self):
        changed = ["src/routes.py", "README.md", "src/other.py"]
        expected = replay(self.entries(), changed_paths=changed).as_dict()
        self.assertEqual(
            replay(self.entries(), changed_paths=list(reversed(changed))).as_dict(), expected
        )

    def test_records_are_reported_in_a_stable_order(self):
        verdict = replay(self.entries(), changed_paths=["src/routes.py"])
        ids = [record.evidence_id for record in verdict.verdicts]
        self.assertEqual(ids, sorted(ids))

    def test_content_hash_is_stable_across_str_and_bytes(self):
        self.assertEqual(content_hash("guard"), content_hash(b"guard"))
        self.assertEqual(len(content_hash("guard")), 64)


if __name__ == "__main__":
    unittest.main()
