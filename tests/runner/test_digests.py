import unittest

from sechelix_runner.digests import canonical_json, digest, digest_bytes, verify


class CanonicalDigestTests(unittest.TestCase):
    def test_key_order_does_not_change_the_digest(self) -> None:
        self.assertEqual(
            digest({"b": 1, "a": [3, 2]}), digest({"a": [3, 2], "b": 1})
        )

    def test_list_order_does_change_the_digest(self) -> None:
        self.assertNotEqual(digest({"a": [1, 2]}), digest({"a": [2, 1]}))

    def test_verify_detects_a_single_changed_value(self) -> None:
        payload = {"finding": "F-1", "severity": "HIGH"}
        expected = digest(payload)
        self.assertTrue(verify(payload, expected))
        self.assertFalse(verify({**payload, "severity": "LOW"}, expected))

    def test_digest_is_algorithm_prefixed(self) -> None:
        self.assertTrue(digest({}).startswith("sha256:"))

    def test_nan_is_rejected_rather_than_hashed(self) -> None:
        """NaN never equals itself, so a record containing one can never verify."""
        with self.assertRaises(ValueError):
            canonical_json({"x": float("nan")})

    def test_unserializable_values_do_not_collide(self) -> None:
        class A:
            pass

        class B:
            pass

        self.assertNotEqual(digest({"x": A()}), digest({"x": B()}))

    def test_digest_bytes_matches_for_identical_payloads(self) -> None:
        self.assertEqual(digest_bytes(b"abc"), digest_bytes(b"abc"))
        self.assertNotEqual(digest_bytes(b"abc"), digest_bytes(b"abd"))


if __name__ == "__main__":
    unittest.main()
