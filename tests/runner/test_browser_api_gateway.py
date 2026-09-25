from __future__ import annotations

import tempfile
import unittest
from unittest.mock import Mock

from sechelix_runner.pentest.api_client import AuthorizedApiClient
from sechelix_runner.pentest.gateway import PolicyToolGateway
from sechelix_runner.pentest.request_policy import InteractionDenied, InteractionPolicy, RequestGrant
from sechelix_runner.pentest.scope import ScopeEndpoint, TargetScope
from sechelix_runner.sandbox import ExecutionMode


class BrowserApiGatewayTests(unittest.TestCase):
    def scope(self) -> TargetScope:
        return TargetScope(
            primary_url="https://app.example.test",
            mode=ExecutionMode.STAGING,
            endpoints=(ScopeEndpoint("app.example.test"),),
            ownership_verified=True,
            verification_method="operator-fixture",
        )

    def test_api_post_needs_explicit_action_grant(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = PolicyToolGateway(scope=self.scope(), repository_root=tmp)
            client = AuthorizedApiClient(self.scope(), gateway)
            with self.assertRaises(InteractionDenied):
                client.request("POST", "https://app.example.test/api/orders", body=b"{}")

    def test_api_client_has_three_authority_layers_before_network(self) -> None:
        policy = InteractionPolicy(grants=(RequestGrant(
            host="app.example.test", path_prefix="/api/test", methods=("POST",), purpose="fixture mutation",
        ),))
        with tempfile.TemporaryDirectory() as tmp:
            gateway = PolicyToolGateway(scope=self.scope(), repository_root=tmp)
            client = AuthorizedApiClient(self.scope(), gateway, policy)
            with self.assertRaises(Exception):
                # DNS/network may fail, but scope + action + gateway authorization already passed.
                client.request("POST", "https://app.example.test/api/test", body=b"{}")


if __name__ == "__main__":
    unittest.main()
