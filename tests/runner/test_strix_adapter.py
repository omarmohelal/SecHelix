from __future__ import annotations

import pytest

from sechelix_runner.pentest.scope import ScopeEndpoint, ScopeError, TargetScope
from sechelix_runner.pentest.strix_adapter import StrixAdapterError, StrixEngine
from sechelix_runner.sandbox import ExecutionMode


def local_scope() -> TargetScope:
    return TargetScope(
        primary_url="http://127.0.0.1:3000",
        mode=ExecutionMode.LOCAL,
        endpoints=(ScopeEndpoint("127.0.0.1", ("http",), (3000,)),),
    )


def test_local_loopback_can_build_strix_command_without_proof() -> None:
    command = StrixEngine().build_command(scope=local_scope(), extra_args=("--headless",))
    assert command == ("strix", "--target", "http://127.0.0.1:3000", "--headless")


def test_non_loopback_cannot_hide_behind_local_mode() -> None:
    scope = TargetScope(
        primary_url="https://example.com",
        mode=ExecutionMode.LOCAL,
        endpoints=(ScopeEndpoint("example.com"),),
    )
    with pytest.raises(ScopeError, match="ownership/authorization proof"):
        StrixEngine().build_command(scope=scope)


def test_verified_staging_target_is_allowed() -> None:
    scope = TargetScope(
        primary_url="https://staging.example.com",
        mode=ExecutionMode.STAGING,
        endpoints=(ScopeEndpoint("staging.example.com"),),
        ownership_verified=True,
        verification_method="dns-txt",
    )
    command = StrixEngine().build_command(scope=scope)
    assert command[1:3] == ("--target", "https://staging.example.com")


def test_extra_args_cannot_replace_authorized_target() -> None:
    with pytest.raises(StrixAdapterError, match="cannot override"):
        StrixEngine().build_command(
            scope=local_scope(),
            extra_args=("--target=https://outside.example",),
        )


def test_production_active_testing_remains_refused() -> None:
    scope = TargetScope(
        primary_url="https://example.com",
        mode=ExecutionMode.PRODUCTION,
        endpoints=(ScopeEndpoint("example.com"),),
        ownership_verified=True,
        verification_method="dns-txt",
    )
    with pytest.raises(ScopeError, match="PRODUCTION"):
        StrixEngine().build_command(scope=scope)
