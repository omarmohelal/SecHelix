from copy import deepcopy
import unittest

from sechelix_core.contracts import ContractValidationError, validate_contract
from tests.helpers import attack_graph, evidence, finding, report, scope


class ContractTests(unittest.TestCase):
    def test_valid_artifacts_satisfy_contracts(self) -> None:
        for name, artifact in (
            ("scope", scope()),
            ("attack-surface", attack_graph()),
            ("evidence", evidence()),
            ("finding", finding()),
            ("report", report()),
        ):
            with self.subTest(contract=name):
                validate_contract(name, artifact, require_authorization=name == "scope")

    def test_high_verified_finding_requires_independent_verifier(self) -> None:
        artifact = finding()
        artifact["verification"]["independent"] = False
        artifact["verification"].pop("verifier")
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def test_verified_finding_requires_complete_evidence_chain(self) -> None:
        artifact = finding()
        artifact["evidence_chain"]["impact"]["established"] = False
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def test_established_evidence_chain_link_requires_evidence(self) -> None:
        artifact = finding()
        artifact["evidence_chain"]["root_cause"]["evidence_ids"] = []
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def _unproven_finding(self, *established: str) -> dict:
        """A non-VERIFIED finding whose chain establishes only the named links."""
        artifact = finding()
        artifact["status"] = "LIKELY_BUT_UNPROVEN"
        artifact["verification"]["outcome"] = "LIKELY_BUT_UNPROVEN"
        for name, link in artifact["evidence_chain"].items():
            if name not in established:
                link["established"] = False
                link["evidence_ids"] = []
        return artifact

    def test_impact_cannot_be_established_without_attacker_control(self) -> None:
        artifact = self._unproven_finding("impact", "reachability")
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def test_impact_cannot_be_established_without_reachability(self) -> None:
        artifact = self._unproven_finding("impact", "attacker_control")
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def test_reproduction_cannot_be_established_without_reachability(self) -> None:
        artifact = self._unproven_finding("safe_reproduction")
        with self.assertRaises(ContractValidationError):
            validate_contract("finding", artifact)

    def test_impact_is_accepted_once_its_prerequisites_hold(self) -> None:
        artifact = self._unproven_finding("impact", "attacker_control", "reachability")
        validate_contract("finding", artifact)

    def test_chain_prerequisites_do_not_suppress_partial_findings(self) -> None:
        """A static boundary failure stands alone; demanding reachability first would
        suppress a true finding about a handler nobody has traced yet."""
        for established in ((), ("attacker_control",), ("boundary_failure",), ("root_cause",)):
            with self.subTest(established=established):
                validate_contract("finding", self._unproven_finding(*established))

    def test_authorization_can_be_recorded_but_required_before_execution(self) -> None:
        artifact = scope(confirmed=False)
        validate_contract("scope", artifact)
        with self.assertRaises(ContractValidationError):
            validate_contract("scope", artifact, require_authorization=True)

    def test_report_rejects_missing_evidence_reference(self) -> None:
        artifact = report()
        artifact["evidence"] = artifact["evidence"][:1]
        with self.assertRaises(ContractValidationError):
            validate_contract("report", artifact)

    def test_report_rejects_dishonest_coverage_total(self) -> None:
        artifact = deepcopy(report())
        artifact["coverage"]["UNKNOWN"] -= 1
        with self.assertRaises(ContractValidationError):
            validate_contract("report", artifact)


if __name__ == "__main__":
    unittest.main()
