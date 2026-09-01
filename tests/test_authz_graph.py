"""The authorization graph must show the gaps without inventing certainty."""

import unittest

from sechelix_core.authz_graph import (
    ALLOWED,
    CONFLICTED,
    CONFLICTING_POLICY,
    CROSS_TENANT_PATH,
    DENIAL_VERDICTS,
    DENIED,
    MISSING_POLICY,
    UI_ONLY_AUTHORIZATION,
    UNEXPECTED_GRANT,
    UNGOVERNED,
    UNKNOWN,
    AuthorizationGraphError,
    build_authorization_graph,
    render_mermaid,
)


def policy(pid, effect="ALLOW", subject="role:support", resource="orders", action="read",
           enforced_at="SERVER", **extra):
    base = {
        "id": pid,
        "effect": effect,
        "subject": subject,
        "resource": resource,
        "action": action,
        "enforced_at": enforced_at,
    }
    base.update(extra)
    return base


def declarations(**overrides):
    """A small tenanted model: support reads and exports orders."""
    base = {
        "identities": [
            {"id": "alice", "roles": ["support"], "tenant": "acme"},
            {"id": "mallory", "roles": [], "tenant": "evil"},
        ],
        "roles": [{"id": "support", "permissions": ["orders.read", "orders.export"]}],
        "permissions": [
            {"id": "orders.read", "resource": "orders", "action": "read"},
            {"id": "orders.export", "resource": "orders", "action": "export"},
        ],
        "resources": [
            {"id": "orders", "actions": ["read", "export", "delete"], "tenant": "acme"},
        ],
        "policies": [policy("P-1", source="app/policy.py:10")],
    }
    base.update(overrides)
    return base


def kinds(result):
    return {h["kind"] for h in result.as_dict()["hypotheses"]}


def of_kind(result, kind):
    return [h for h in result.as_dict()["hypotheses"] if h["kind"] == kind]


class DeclarationTests(unittest.TestCase):
    def test_structural_nonsense_raises_rather_than_analyzing_an_empty_model(self):
        """An unreadable model analyzed as empty produces no hypotheses — which reads clean."""
        for hostile in [
            "not a mapping",
            {"identities": "alice"},
            {"identities": [{"roles": []}]},
            {"policies": [policy("P", effect="MAYBE")]},
            {"policies": [policy("P", enforced_at="SOMEWHERE")]},
            {"policies": [policy("P", subject="support")]},
            {"policies": [policy("P", resource="")]},
            {"policies": [policy("P", tenant_scoped="yes")]},
            {"permissions": [{"id": "p", "resource": "orders"}]},
        ]:
            with self.subTest(hostile):
                with self.assertRaises(AuthorizationGraphError):
                    build_authorization_graph(hostile)

    def test_a_duplicate_id_is_refused_rather_than_overwriting(self):
        """The second declaration would otherwise replace the first and vanish."""
        cases = [
            {"policies": [policy("P-1"), policy("P-1")]},
            {"identities": [{"id": "alice"}, {"id": "alice", "roles": ["admin"]}]},
            {"roles": [{"id": "support"}, {"id": "support", "permissions": ["x"]}]},
            {"resources": [{"id": "orders"}, {"id": "orders", "actions": ["delete"]}]},
            {"permissions": [{"id": "p", "resource": "orders", "action": "read"},
                             {"id": "p", "resource": "orders", "action": "delete"}]},
        ]
        for case in cases:
            with self.subTest(sorted(case)[0]):
                with self.assertRaises(AuthorizationGraphError):
                    build_authorization_graph(declarations(**case))

    def test_an_empty_model_is_readable_and_says_nothing(self):
        result = build_authorization_graph({})
        payload = result.as_dict()
        self.assertEqual(payload["hypotheses"], [])
        self.assertEqual(payload["matrix"]["rows"], [])
        self.assertEqual(payload["graph"]["nodes"], [])

    def test_undeclared_references_are_recorded_not_swallowed(self):
        result = build_authorization_graph(declarations(
            identities=[{"id": "alice", "roles": ["ghost"], "tenant": "acme"}],
        ))
        gaps = " ".join(result.as_dict()["declaration_gaps"])
        self.assertIn("undeclared role ghost", gaps)

    def test_an_inheritance_cycle_is_recorded_and_does_not_hang(self):
        result = build_authorization_graph(declarations(
            roles=[
                {"id": "support", "permissions": [], "inherits": ["lead"]},
                {"id": "lead", "permissions": [], "inherits": ["support"]},
            ],
        ))
        gaps = " ".join(result.as_dict()["declaration_gaps"])
        self.assertIn("cycle", gaps)

    def test_a_policy_governing_an_undeclared_action_is_recorded(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-9", action="purge")],
        ))
        gaps = " ".join(result.as_dict()["declaration_gaps"])
        self.assertIn("orders:purge", gaps)


class ReachabilityTests(unittest.TestCase):
    def test_inherited_roles_carry_their_permissions(self):
        result = build_authorization_graph(declarations(
            identities=[{"id": "alice", "roles": ["support"], "tenant": "acme"}],
            roles=[
                {"id": "support", "permissions": [], "inherits": ["viewer"]},
                {"id": "viewer", "permissions": ["orders.read"]},
            ],
        ))
        self.assertTrue(result.cell("alice", "orders", "read").grant_path)

    def test_a_wildcard_permission_expands_over_declared_actions(self):
        result = build_authorization_graph(declarations(
            roles=[{"id": "support", "permissions": ["orders.all"]}],
            permissions=[{"id": "orders.all", "resource": "orders", "action": "*"}],
        ))
        for action in ("read", "export", "delete"):
            self.assertTrue(result.cell("alice", "orders", action).grant_path, action)


class MatrixHonestyTests(unittest.TestCase):
    """Missing information must never be presented as a denial."""

    def test_an_identity_with_no_role_is_unknown_not_denied(self):
        cell = build_authorization_graph(declarations()).cell("mallory", "orders", "read")
        self.assertEqual(cell.verdict, UNKNOWN)
        self.assertNotIn(cell.verdict, DENIAL_VERDICTS)
        self.assertIn("not proof", cell.reason)

    def test_a_reachable_ungoverned_cell_is_ungoverned_not_denied(self):
        cell = build_authorization_graph(declarations()).cell("alice", "orders", "export")
        self.assertEqual(cell.verdict, UNGOVERNED)
        self.assertFalse(cell.is_denial)

    def test_denied_requires_a_server_enforced_deny_policy(self):
        """The one invariant that keeps a hole in the model from reading as a block."""
        models = [
            declarations(),
            declarations(policies=[policy("P-C", effect="DENY", enforced_at="CLIENT",
                                          action="delete", subject="*")]),
            declarations(policies=[policy("P-U", effect="DENY", enforced_at="UNKNOWN",
                                          subject="*", action="*")]),
            declarations(policies=[]),
            declarations(policies=[policy("P-D", effect="DENY", enforced_at="DATABASE")]),
        ]
        for index, model in enumerate(models):
            result = build_authorization_graph(model)
            for cell in result.cells:
                with self.subTest(model=index, cell=(cell.identity, cell.resource, cell.action)):
                    if cell.verdict == DENIED:
                        self.assertTrue(
                            cell.deciding_policies,
                            "DENIED must name the server-enforced policy that denies",
                        )
                    else:
                        self.assertFalse(cell.is_denial)

    def test_a_client_side_deny_never_produces_a_denied_cell(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-UI", effect="DENY", subject="*", action="delete",
                             enforced_at="CLIENT")],
        ))
        cell = result.cell("alice", "orders", "delete")
        self.assertNotEqual(cell.verdict, DENIED)
        self.assertIn("not an authorization control", cell.reason)

    def test_a_policy_with_an_undeclared_enforcement_point_decides_nothing(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-?", enforced_at="UNKNOWN")],
        ))
        cell = result.cell("alice", "orders", "read")
        self.assertIn(cell.verdict, (UNGOVERNED, UNKNOWN))
        self.assertIn("no enforcement point", cell.reason)

    def test_a_server_policy_allows_and_says_which_one(self):
        cell = build_authorization_graph(declarations()).cell("alice", "orders", "read")
        self.assertEqual(cell.verdict, ALLOWED)
        self.assertEqual(cell.deciding_policies, ("P-1",))

    def test_the_matrix_legend_states_that_unknown_is_not_a_denial(self):
        matrix = build_authorization_graph(declarations()).matrix()
        self.assertEqual(matrix["denial_verdicts"], [DENIED])
        self.assertIn("not a denial", matrix["legend"][UNKNOWN])
        self.assertIn("not a denial", matrix["legend"][UNGOVERNED])

    def test_every_cell_appears_in_the_matrix(self):
        matrix = build_authorization_graph(declarations()).matrix()
        cells = sum(len(row["cells"]) for row in matrix["rows"])
        self.assertEqual(cells, len(matrix["identities"]) * len(matrix["columns"]))
        self.assertEqual(sum(matrix["verdict_counts"].values()), cells)


class MissingEdgeTests(unittest.TestCase):
    def test_a_reachable_ungoverned_action_raises_a_missing_policy_hypothesis(self):
        result = build_authorization_graph(declarations())
        missing = of_kind(result, MISSING_POLICY)
        self.assertEqual([h["resource"] for h in missing], ["orders"])
        self.assertEqual(missing[0]["actions"], ["export"])
        self.assertIn("alice", missing[0]["identities"])

    def test_an_unreachable_action_raises_no_missing_policy(self):
        """Only what a role can actually reach is a missing edge."""
        result = build_authorization_graph(declarations(
            roles=[{"id": "support", "permissions": ["orders.read"]}],
        ))
        self.assertEqual(of_kind(result, MISSING_POLICY), [])

    def test_a_governed_action_raises_nothing(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-1"), policy("P-2", action="export")],
        ))
        self.assertEqual(of_kind(result, MISSING_POLICY), [])


class UnexpectedEdgeTests(unittest.TestCase):
    def test_a_policy_granting_beyond_the_role_model_is_unexpected(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-WILD", subject="*", resource="*", action="*")],
        ))
        unexpected = of_kind(result, UNEXPECTED_GRANT)
        self.assertTrue(unexpected)
        mallory = [h for h in unexpected if h["identities"] == ["mallory"]]
        self.assertTrue(mallory, "an identity with no role reaching orders is unexpected")
        self.assertIn("wildcard policy", mallory[0]["statement"])

    def test_an_allowance_matching_the_role_model_is_not_unexpected(self):
        result = build_authorization_graph(declarations())
        for hypothesis in of_kind(result, UNEXPECTED_GRANT):
            self.assertNotEqual(hypothesis["identities"], ["alice"])


class ConflictTests(unittest.TestCase):
    def test_opposite_policies_on_one_cell_are_reported_as_a_conflict(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-1"), policy("P-2", effect="DENY", enforced_at="DATABASE")],
        ))
        conflicts = of_kind(result, CONFLICTING_POLICY)
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(sorted(conflicts[0]["policies"]), ["P-1", "P-2"])
        self.assertEqual(result.cell("alice", "orders", "read").verdict, CONFLICTED)

    def test_a_conflicted_cell_is_not_reported_as_denied(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-1"), policy("P-2", effect="DENY")],
        ))
        self.assertFalse(result.cell("alice", "orders", "read").is_denial)

    def test_a_client_policy_does_not_conflict_with_a_server_policy(self):
        """The client is not a party to the authorization decision."""
        result = build_authorization_graph(declarations(
            policies=[policy("P-1"), policy("P-UI", effect="DENY", enforced_at="CLIENT")],
        ))
        self.assertEqual(of_kind(result, CONFLICTING_POLICY), [])


class ClientSideTests(unittest.TestCase):
    """A check that runs on the caller's machine is not an authorization control."""

    def test_a_client_only_gate_is_reported_as_ui_only(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-UI", effect="DENY", subject="*", action="delete",
                             enforced_at="CLIENT", source="ui/OrderRow.tsx:31")],
        ))
        ui_only = of_kind(result, UI_ONLY_AUTHORIZATION)
        self.assertEqual(len(ui_only), 1)
        self.assertEqual(ui_only[0]["detail"], "NO_SERVER_SIDE_POLICY")
        self.assertIn("not an authorization control", ui_only[0]["statement"])
        self.assertIn("ui/OrderRow.tsx:31", ui_only[0]["sources"])

    def test_a_hidden_button_over_an_allowing_server_is_reported(self):
        result = build_authorization_graph(declarations(
            policies=[
                policy("P-1", action="delete"),
                policy("P-UI", effect="DENY", subject="*", action="delete",
                       enforced_at="CLIENT"),
            ],
        ))
        ui_only = of_kind(result, UI_ONLY_AUTHORIZATION)
        self.assertEqual(ui_only[0]["detail"], "SERVER_ALLOWS_WHAT_THE_CLIENT_HIDES")
        self.assertIn("only in the interface", ui_only[0]["statement"])

    def test_a_client_gate_never_counts_as_the_policy_a_resource_needs(self):
        """A UI check must not close a MISSING_POLICY hypothesis."""
        result = build_authorization_graph(declarations(
            policies=[policy("P-1"),
                      policy("P-UI", subject="*", action="export", enforced_at="CLIENT")],
        ))
        missing = of_kind(result, MISSING_POLICY)
        self.assertEqual([h["actions"] for h in missing], [["export"]])
        self.assertIn(UI_ONLY_AUTHORIZATION, kinds(result))

    def test_a_server_side_gate_is_not_reported_as_ui_only(self):
        result = build_authorization_graph(declarations())
        self.assertNotIn(UI_ONLY_AUTHORIZATION, kinds(result))


class CrossTenantTests(unittest.TestCase):
    def test_reaching_another_tenants_resource_is_reported(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-ANY", subject="*", action="read")],
        ))
        crossings = of_kind(result, CROSS_TENANT_PATH)
        self.assertTrue(any(h["identities"] == ["mallory"] for h in crossings))

    def test_a_shared_store_with_no_tenant_predicate_is_reported(self):
        result = build_authorization_graph(declarations(
            resources=[{"id": "orders", "actions": ["read", "export", "delete"], "tenant": "*"}],
        ))
        crossings = of_kind(result, CROSS_TENANT_PATH)
        self.assertTrue(crossings)
        self.assertIn("shared multi-tenant store", crossings[0]["statement"])

    def test_a_tenant_scoped_policy_closes_the_shared_store_path(self):
        result = build_authorization_graph(declarations(
            resources=[{"id": "orders", "actions": ["read"], "tenant": "*"}],
            roles=[{"id": "support", "permissions": ["orders.read"]}],
            policies=[policy("P-1", tenant_scoped=True)],
        ))
        self.assertEqual(of_kind(result, CROSS_TENANT_PATH), [])

    def test_a_tenant_scoped_policy_does_not_reach_a_foreign_tenant(self):
        result = build_authorization_graph(declarations(
            identities=[{"id": "mallory", "roles": ["support"], "tenant": "evil"}],
            policies=[policy("P-1", tenant_scoped=True)],
        ))
        self.assertNotEqual(result.cell("mallory", "orders", "read").verdict, ALLOWED)

    def test_an_undeclared_tenant_is_undetermined_not_cleared(self):
        result = build_authorization_graph(declarations(
            identities=[{"id": "alice", "roles": ["support"]}],
        ))
        payload = result.as_dict()
        self.assertEqual(of_kind(result, CROSS_TENANT_PATH), [])
        self.assertTrue(any("could not be assessed" in item for item in payload["undetermined"]))

    def test_same_tenant_access_raises_nothing(self):
        result = build_authorization_graph(declarations(
            identities=[{"id": "alice", "roles": ["support"], "tenant": "acme"}],
        ))
        self.assertEqual(of_kind(result, CROSS_TENANT_PATH), [])


class ClaimHonestyTests(unittest.TestCase):
    def test_every_detection_is_a_hypothesis(self):
        result = build_authorization_graph(declarations(
            policies=[policy("P-WILD", subject="*", resource="*", action="*"),
                      policy("P-UI", effect="DENY", subject="*", action="delete",
                             enforced_at="CLIENT")],
        ))
        payload = result.as_dict()
        self.assertTrue(payload["hypotheses"])
        for hypothesis in payload["hypotheses"]:
            self.assertEqual(hypothesis["claim_status"], "HYPOTHESIS")
            self.assertTrue(hypothesis["verification_question"])
            self.assertTrue(hypothesis["refuted_if"])

    def test_no_severity_is_assigned_anywhere(self):
        payload = build_authorization_graph(declarations(
            policies=[policy("P-WILD", subject="*", resource="*", action="*")],
        )).as_dict()

        def walk(node, path="root"):
            if isinstance(node, dict):
                for key, value in node.items():
                    self.assertNotIn("severity", str(key).lower(), f"{path}.{key}")
                    walk(value, f"{path}.{key}")
            elif isinstance(node, list):
                for index, value in enumerate(node):
                    walk(value, f"{path}[{index}]")

        walk(payload)

    def test_the_notes_state_the_runtime_limit_of_the_graph(self):
        notes = " ".join(build_authorization_graph(declarations()).as_dict()["notes"])
        self.assertIn("unproven", notes)
        self.assertIn("not denials", notes)
        self.assertIn("No severity", notes)

    def test_hypothesis_ids_are_stable_across_runs(self):
        model = declarations(policies=[policy("P-WILD", subject="*", resource="*", action="*")])
        first = build_authorization_graph(model).as_dict()["hypotheses"]
        second = build_authorization_graph(model).as_dict()["hypotheses"]
        self.assertEqual([h["hypothesis_id"] for h in first],
                         [h["hypothesis_id"] for h in second])
        self.assertEqual([h["statement"] for h in first], [h["statement"] for h in second])


class GraphFormTests(unittest.TestCase):
    def test_the_graph_carries_the_whole_chain(self):
        graph = build_authorization_graph(declarations()).graph()
        node_kinds = {node["kind"] for node in graph["nodes"]}
        self.assertEqual(
            node_kinds,
            {"IDENTITY", "ROLE", "PERMISSION", "RESOURCE", "ACTION", "POLICY"},
        )
        edge_kinds = {edge["kind"] for edge in graph["edges"]}
        for expected in ("HOLDS_ROLE", "GRANTS", "TARGETS", "PERMITS", "GOVERNS", "SUBJECT_OF"):
            self.assertIn(expected, edge_kinds)

    def test_a_wildcard_subject_stays_a_wildcard_in_the_graph(self):
        """Expanding "*" into one edge per identity would hide what matters about it."""
        graph = build_authorization_graph(declarations(
            policies=[policy("P-WILD", subject="*", resource="*", action="*")],
        )).graph()
        wildcards = [n for n in graph["nodes"] if n["attributes"].get("wildcard")]
        self.assertTrue(wildcards)

    def test_a_policy_node_records_whether_it_is_a_control(self):
        graph = build_authorization_graph(declarations(
            policies=[policy("P-1"), policy("P-UI", enforced_at="CLIENT", action="delete")],
        )).graph()
        controls = {n["label"]: n["attributes"]["is_authorization_control"]
                    for n in graph["nodes"] if n["kind"] == "POLICY"}
        self.assertTrue(controls["P-1"])
        self.assertFalse(controls["P-UI"])

    def test_the_graph_is_json_serializable_and_stable(self):
        import json

        first = json.dumps(build_authorization_graph(declarations()).graph(), sort_keys=True)
        second = json.dumps(build_authorization_graph(declarations()).graph(), sort_keys=True)
        self.assertEqual(first, second)

    def test_mermaid_rendering_is_deterministic_and_escapes_labels(self):
        graph = build_authorization_graph(declarations(
            resources=[{"id": 'orders"|<x>', "actions": ["read"], "tenant": "acme"}],
        )).graph()
        rendered = render_mermaid(graph)
        self.assertTrue(rendered.startswith("flowchart LR"))
        self.assertNotIn('orders"|<x>', rendered)
        self.assertEqual(rendered, render_mermaid(graph))

    def test_an_unsupported_direction_is_refused(self):
        graph = build_authorization_graph(declarations()).graph()
        with self.assertRaises(AuthorizationGraphError):
            render_mermaid(graph, direction="SIDEWAYS")


if __name__ == "__main__":
    unittest.main()
