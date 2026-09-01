"""Calibration must withhold every number it has not earned."""

import json
import unittest
from pathlib import Path

from sechelix_core.calibration import (
    DEFAULT_MINIMUM_SAMPLE_SIZE,
    MEASURED,
    NOT_MEASURED,
    CalibrationError,
    Contamination,
    Sample,
    calibrate,
    render_markdown,
    samples_from_report,
)
from sechelix_core.contracts import validate_contract

ROOT = Path(__file__).resolve().parents[1]

CLEAN = Contamination(False, "NONE")
DIRTY = Contamination(True, "the scoring session authored the findings")


def samples(confidence, verified, refuted, unresolved=0):
    out = []
    n = 0
    for _ in range(verified):
        n += 1
        out.append(Sample(f"SHX-F-V{n}", confidence, "VERIFIED"))
    for _ in range(refuted):
        n += 1
        out.append(Sample(f"SHX-F-R{n}", confidence, "FALSE_POSITIVE"))
    for _ in range(unresolved):
        n += 1
        out.append(Sample(f"SHX-F-U{n}", confidence, "BLOCKED_BY_ENVIRONMENT"))
    return out


class WithholdingTests(unittest.TestCase):
    def test_a_thin_sample_set_is_not_measured(self):
        record = calibrate(samples("HIGH", 4, 1), contamination=CLEAN)
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertEqual(record["calibration_error"], NOT_MEASURED)

    def test_a_thin_sample_set_also_withholds_bucket_rates(self):
        """A per-bucket number escapes its caveat the moment it is published."""
        record = calibrate(samples("HIGH", 4, 1), contamination=CLEAN)
        for bucket in record["buckets"]:
            self.assertEqual(bucket["observed_rate"], NOT_MEASURED)
            self.assertEqual(bucket["gap"], NOT_MEASURED)

    def test_contamination_withholds_everything_even_with_many_samples(self):
        record = calibrate(samples("HIGH", 90, 10), contamination=DIRTY)
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertEqual(record["calibration_error"], NOT_MEASURED)
        for bucket in record["buckets"]:
            self.assertEqual(bucket["observed_rate"], NOT_MEASURED)

    def test_contamination_reason_leads_the_limitations(self):
        record = calibrate(samples("HIGH", 90, 10), contamination=DIRTY)
        self.assertIn("Contaminated", record["limitations"][0])
        self.assertIn("authored the findings", record["limitations"][0])

    def test_an_empty_sample_set_is_not_measured(self):
        record = calibrate([], contamination=CLEAN)
        self.assertEqual(record["measurement_status"], NOT_MEASURED)
        self.assertEqual(record["sample_size"], 0)

    def test_limitations_are_never_empty(self):
        for contamination in (CLEAN, DIRTY):
            record = calibrate(samples("HIGH", 90, 10), contamination=contamination)
            self.assertTrue(record["limitations"])


class MeasurementTests(unittest.TestCase):
    def test_a_well_calibrated_set_measures_with_low_error(self):
        # HIGH asserts 0.90; 90 verified of 100 resolved is exactly that.
        record = calibrate(samples("HIGH", 90, 10), contamination=CLEAN)
        self.assertEqual(record["measurement_status"], MEASURED)
        self.assertLess(record["calibration_error"], 0.01)
        self.assertEqual(record["overconfident_buckets"], [])

    def test_overconfidence_is_named(self):
        """HIGH asserts 0.90; verifying half the time is the failure that matters."""
        record = calibrate(samples("HIGH", 50, 50), contamination=CLEAN)
        self.assertEqual(record["measurement_status"], MEASURED)
        self.assertIn("HIGH", record["overconfident_buckets"])
        self.assertNotIn("HIGH", record["underconfident_buckets"])

    def test_underconfidence_is_named(self):
        record = calibrate(samples("LOW", 90, 10), contamination=CLEAN)
        self.assertIn("LOW", record["underconfident_buckets"])

    def test_the_minimum_is_recorded_not_implied(self):
        record = calibrate(samples("HIGH", 90, 10), contamination=CLEAN)
        self.assertEqual(record["minimum_sample_size"], DEFAULT_MINIMUM_SAMPLE_SIZE)

    def test_a_zero_minimum_is_refused(self):
        with self.assertRaises(CalibrationError):
            calibrate(samples("HIGH", 5, 5), contamination=CLEAN, minimum_sample_size=0)


class UnresolvedTests(unittest.TestCase):
    """An unresolved candidate is evidence for neither side."""

    def test_unresolved_samples_do_not_enter_the_rate(self):
        with_blocked = calibrate(samples("HIGH", 90, 10, unresolved=50),
                                 contamination=CLEAN)
        without = calibrate(samples("HIGH", 90, 10), contamination=CLEAN)
        high_with = next(b for b in with_blocked["buckets"] if b["confidence"] == "HIGH")
        high_without = next(b for b in without["buckets"] if b["confidence"] == "HIGH")
        self.assertEqual(high_with["observed_rate"], high_without["observed_rate"])
        self.assertEqual(high_with["unresolved"], 50)

    def test_an_all_unresolved_bucket_has_no_rate(self):
        """An environment failure must never look like a calibration result."""
        record = calibrate(samples("HIGH", 0, 0, unresolved=100), contamination=CLEAN)
        high = next(b for b in record["buckets"] if b["confidence"] == "HIGH")
        self.assertEqual(high["observed_rate"], NOT_MEASURED)
        self.assertEqual(record["measurement_status"], NOT_MEASURED)

    def test_not_assessed_is_tracked_but_never_scored(self):
        """A finding that stated no confidence made no prediction to score."""
        record = calibrate(samples("NOT_ASSESSED", 90, 10), contamination=CLEAN)
        bucket = next(b for b in record["buckets"] if b["confidence"] == "NOT_ASSESSED")
        self.assertEqual(bucket["sample_size"], 100)
        self.assertEqual(bucket["stated_probability"], "NOT_APPLICABLE")
        self.assertEqual(bucket["observed_rate"], NOT_MEASURED)


class ContractTests(unittest.TestCase):
    def test_the_schema_exists_and_the_record_satisfies_it(self):
        record = calibrate(samples("HIGH", 90, 10), contamination=CLEAN)
        validate_contract("calibration", record)

    def test_a_not_measured_record_also_satisfies_the_contract(self):
        validate_contract("calibration", calibrate([], contamination=DIRTY))


class ReportIntegrationTests(unittest.TestCase):
    def test_samples_come_from_the_verifier_not_the_finding_status(self):
        report = {
            "findings": [{
                "finding_id": "SHX-F-1",
                "confidence": "HIGH",
                "status": "VERIFIED",
                "verification": {"outcome": "FALSE_POSITIVE"},
            }]
        }
        sample = samples_from_report(report)[0]
        self.assertEqual(sample.outcome, "FALSE_POSITIVE")

    def test_a_finding_without_verification_is_skipped(self):
        report = {"findings": [{"finding_id": "SHX-F-1", "confidence": "HIGH"}]}
        self.assertEqual(samples_from_report(report), [])

    def test_a_malformed_report_is_refused(self):
        with self.assertRaises(CalibrationError):
            samples_from_report({"findings": "none"})

    def test_the_real_example_report_yields_a_not_measured_record(self):
        report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
        record = calibrate(samples_from_report(report), contamination=CLEAN)
        self.assertEqual(record["measurement_status"], NOT_MEASURED)


class RenderTests(unittest.TestCase):
    def test_the_rendered_record_never_shows_a_withheld_number(self):
        text = render_markdown(calibrate(samples("HIGH", 4, 1), contamination=CLEAN))
        self.assertIn("NOT_MEASURED", text)
        self.assertNotIn("0.8", text)

    def test_the_rendered_record_always_states_limitations(self):
        text = render_markdown(calibrate(samples("HIGH", 90, 10), contamination=CLEAN))
        self.assertIn("Limitations", text)


if __name__ == "__main__":
    unittest.main()
