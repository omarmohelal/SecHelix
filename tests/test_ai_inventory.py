"""An inventory that guesses is worse than no inventory.

The two negative cases here are the ones that make a BOM misleading rather than
merely incomplete: an asset whose boundary nobody established being recorded as
INTERNAL, and an asset a config file mentions being counted as one somebody
observed.
"""

import json
import unittest

from sechelix_core.ai_inventory import (
    DECLARED,
    INTERNAL,
    OBSERVED,
    PUBLIC,
    THIRD_PARTY,
    UNKNOWN,
    AiInventoryError,
    Asset,
    Inventory,
    classify_boundary,
    credential_shapes,
    render_markdown,
    to_ai_bom,
)
from sechelix_core.contracts import validate_contract
from sechelix_core.proof_bundle import REDACTED


# Assembled at runtime so this project's own secret gate keeps working here.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"


def an_inventory():
    inventory = Inventory("BOM-1", subject="support agent service")
    inventory.add(Asset(
        asset_id="AS-model", kind="MODEL", name="hosted chat model",
        provenance=DECLARED, locator="config/model.yaml",
        boundary=THIRD_PARTY, boundary_basis="served by an external provider",
    ))
    inventory.add(Asset(
        asset_id="AS-provider", kind="PROVIDER", name="inference provider",
        provenance=DECLARED, boundary=THIRD_PARTY,
        boundary_basis="declared as not operator-controlled",
    ))
    inventory.add(Asset(
        asset_id="AS-agent", kind="AGENT", name="support agent",
        provenance=OBSERVED, evidence_ids=("EV-1",),
        boundary=INTERNAL, boundary_basis="defined in this repository and deployed by us",
    ))
    inventory.add(Asset(
        asset_id="AS-server", kind="MCP_SERVER", name="community docs server",
        provenance=DECLARED, locator=".mcp.json",
    ))
    inventory.add(Asset(
        asset_id="AS-rag", kind="RAG_STORE", name="support knowledge index",
        provenance=OBSERVED, evidence_ids=("EV-2",),
    ))
    inventory.add(Asset(
        asset_id="AS-endpoint", kind="NETWORK_DESTINATION", name="api.example.invalid",
    ))
    inventory.add_secret_reference(
        "AS-token", "SUPPORT_API_TOKEN", read_from="environment variable",
        boundary=THIRD_PARTY, boundary_basis="authenticates to the external provider",
    )
    inventory.link("AS-agent", "AS-server", "USES")
    inventory.link("AS-agent", "AS-model", "USES")
    inventory.link("AS-agent", "AS-token", "AUTHENTICATES_WITH")
    inventory.link("AS-server", "AS-endpoint", "REACHES")
    return inventory


class BoundaryTests(unittest.TestCase):
    def test_an_asset_defaults_to_unknown_not_internal(self):
        asset = Asset(asset_id="A", kind="TOOL", name="a tool")
        self.assertEqual(asset.boundary, UNKNOWN)

    def test_internal_requires_a_stated_basis(self):
        with self.assertRaises(AiInventoryError) as caught:
            Asset(asset_id="A", kind="TOOL", name="a tool", boundary=INTERNAL)
        self.assertIn("requires a basis", str(caught.exception))

    def test_every_non_unknown_boundary_requires_a_basis(self):
        for boundary in (INTERNAL, THIRD_PARTY, PUBLIC):
            with self.subTest(boundary):
                with self.assertRaises(AiInventoryError):
                    Asset(asset_id="A", kind="TOOL", name="a tool", boundary=boundary)

    def test_classify_never_produces_internal_from_an_unclear_answer(self):
        for answer in ("", "  ", "maybe", "UNKNOWN", "no", "probably", "yes please"):
            with self.subTest(answer):
                boundary, _basis = classify_boundary(answer)
                self.assertNotEqual(boundary, INTERNAL)

    def test_classify_produces_unknown_when_control_was_not_established(self):
        boundary, basis = classify_boundary("UNKNOWN")
        self.assertEqual(boundary, UNKNOWN)
        self.assertIn("not established", basis)

    def test_classify_refuses_internal_without_a_basis(self):
        with self.assertRaises(AiInventoryError):
            classify_boundary("YES")

    def test_classify_produces_internal_only_from_an_explicit_yes_with_a_basis(self):
        self.assertEqual(classify_boundary("YES", basis="deployed from this repository"),
                         (INTERNAL, "deployed from this repository"))

    def test_classify_produces_third_party_from_an_explicit_no(self):
        boundary, _basis = classify_boundary("NO")
        self.assertEqual(boundary, THIRD_PARTY)

    def test_unresolved_boundaries_are_published_as_their_own_list(self):
        bom = to_ai_bom(an_inventory())
        self.assertEqual(bom["unknown_boundary_asset_ids"],
                         ["AS-endpoint", "AS-rag", "AS-server"])

    def test_the_render_calls_out_unknown_boundaries(self):
        text = render_markdown(to_ai_bom(an_inventory()))
        self.assertIn("`UNKNOWN` trust boundary", text)
        self.assertIn("reviewed as though they were", text)

    def test_a_third_party_endpoint_is_never_counted_as_internal(self):
        summary = to_ai_bom(an_inventory())["summary"]["by_trust_boundary"]
        self.assertEqual(summary[INTERNAL], 1)
        self.assertEqual(summary[UNKNOWN], 3)


class ProvenanceTests(unittest.TestCase):
    def test_observed_requires_evidence(self):
        with self.assertRaises(AiInventoryError) as caught:
            Asset(asset_id="A", kind="TOOL", name="a tool", provenance=OBSERVED)
        self.assertIn("OBSERVED requires an evidence id", str(caught.exception))

    def test_declared_is_the_default(self):
        self.assertEqual(Asset(asset_id="A", kind="TOOL", name="a tool").provenance, DECLARED)

    def test_a_declared_asset_never_appears_in_the_observed_list(self):
        bom = to_ai_bom(an_inventory())
        declared = set(bom["declared_only_asset_ids"])
        observed = set(bom["observed_asset_ids"])
        self.assertTrue(declared)
        self.assertTrue(observed)
        self.assertEqual(declared & observed, set())
        for asset in bom["assets"]:
            bucket = observed if asset["provenance"] == OBSERVED else declared
            self.assertIn(asset["asset_id"], bucket)

    def test_the_two_provenances_are_counted_apart(self):
        summary = to_ai_bom(an_inventory())["summary"]["by_provenance"]
        self.assertEqual(summary[OBSERVED], 2)
        self.assertEqual(summary[DECLARED], 5)
        self.assertEqual(summary[OBSERVED] + summary[DECLARED],
                         to_ai_bom(an_inventory())["summary"]["total"])

    def test_the_render_labels_a_declared_asset_as_declaration_only(self):
        text = render_markdown(to_ai_bom(an_inventory()))
        self.assertIn("declaration only", text)
        self.assertIn("declared and not observed", text)

    def test_the_limitations_say_a_declared_asset_was_not_observed(self):
        limitations = " ".join(to_ai_bom(an_inventory())["limitations"])
        self.assertIn("has not been observed in a running system", limitations)
        self.assertIn("not a synonym for INTERNAL", limitations)


class SecretReferenceTests(unittest.TestCase):
    def test_a_credential_shaped_name_is_refused(self):
        inventory = Inventory("BOM")
        with self.assertRaises(AiInventoryError) as caught:
            inventory.add_secret_reference("AS-1", AWS, read_from="environment")
        self.assertIn("inventoried by reference", str(caught.exception))

    def test_a_credential_shaped_locator_is_refused(self):
        inventory = Inventory("BOM")
        with self.assertRaises(AiInventoryError):
            inventory.add_secret_reference("AS-1", "PROVIDER_TOKEN", read_from=GH)

    def test_a_home_directory_locator_is_not_mistaken_for_a_credential(self):
        """A local server legitimately lives under a home directory."""
        inventory = Inventory("BOM")
        inventory.add_secret_reference("AS-1", "PROVIDER_TOKEN",
                                       read_from="/home/deploy/.config/agent/env")
        self.assertIn("AS-1", inventory.assets)

    def test_credential_shapes_ignores_paths_and_catches_tokens(self):
        self.assertEqual(credential_shapes("/home/deploy/.env"), [])
        self.assertEqual(credential_shapes(f"token {AWS}"), ["aws_key"])

    def test_a_secret_value_elsewhere_in_the_bom_is_redacted(self):
        inventory = Inventory("BOM")
        inventory.add(Asset(asset_id="AS-1", kind="TOOL", name="a tool",
                            attributes={"example_call": f"Authorization: Bearer {GH}"}))
        bom = to_ai_bom(inventory)
        blob = json.dumps(bom)
        self.assertNotIn(GH, blob)
        self.assertIn(REDACTED, blob)
        self.assertTrue(bom["redaction"]["applied"])

    def test_a_clean_bom_records_that_nothing_needed_redacting(self):
        bom = to_ai_bom(an_inventory())
        self.assertEqual(bom["redaction"]["total_values_redacted"], 0)


class InventoryTests(unittest.TestCase):
    def test_a_duplicate_asset_id_is_refused(self):
        inventory = Inventory("BOM")
        inventory.add(Asset(asset_id="A", kind="TOOL", name="one"))
        with self.assertRaises(AiInventoryError):
            inventory.add(Asset(asset_id="A", kind="TOOL", name="two"))

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(AiInventoryError):
            Asset(asset_id="A", kind="VIBES", name="one")

    def test_a_relationship_to_an_unknown_asset_is_refused(self):
        inventory = Inventory("BOM")
        inventory.add(Asset(asset_id="A", kind="TOOL", name="one"))
        with self.assertRaises(AiInventoryError):
            inventory.link("A", "B", "USES")

    def test_an_unknown_relation_is_refused(self):
        inventory = Inventory("BOM")
        inventory.add(Asset(asset_id="A", kind="TOOL", name="one"))
        inventory.add(Asset(asset_id="B", kind="TOOL", name="two"))
        with self.assertRaises(AiInventoryError):
            inventory.link("A", "B", "VIBES_WITH")

    def test_the_ai_bom_covers_the_declared_asset_classes(self):
        bom = to_ai_bom(an_inventory())
        self.assertEqual(sorted(bom["summary"]["by_kind"]), [
            "AGENT", "MCP_SERVER", "MODEL", "NETWORK_DESTINATION", "PROVIDER",
            "RAG_STORE", "SECRET_REFERENCE",
        ])

    def test_extra_unresolved_questions_reach_the_limitations(self):
        inventory = an_inventory()
        inventory.unresolved_questions.append("Nobody enumerated locally connected servers.")
        self.assertIn("Nobody enumerated locally connected servers.",
                      to_ai_bom(inventory)["limitations"])


class ContractTests(unittest.TestCase):
    def test_the_ai_bom_validates(self):
        validate_contract("ai-bom", to_ai_bom(an_inventory()))

    def test_an_empty_inventory_validates(self):
        validate_contract("ai-bom", to_ai_bom(Inventory("BOM-EMPTY")))

    def test_every_asset_kind_validates(self):
        from sechelix_core.ai_inventory import KINDS

        inventory = Inventory("BOM-ALL")
        for index, kind in enumerate(KINDS):
            inventory.add(Asset(asset_id=f"AS-{index}", kind=kind, name=f"{kind.lower()} asset"))
        validate_contract("ai-bom", to_ai_bom(inventory))


if __name__ == "__main__":
    unittest.main()
