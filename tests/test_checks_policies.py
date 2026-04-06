from __future__ import annotations

import pytest

from entra_hygiene.checks.policies import (
    BlockLegacyAuthCheck,
    MfaForAllCheck,
    ReportOnlyPoliciesCheck,
)
from entra_hygiene.graph import BASE_URL
from entra_hygiene.models import Severity

CA_URL = (
    f"{BASE_URL}/identity/conditionalAccess/policies"
    "?$select=id,displayName,state,conditions,grantControls"
)


def _policy(
    pid: str = "p1",
    name: str = "Test Policy",
    state: str = "enabled",
    include_users: list[str] | None = None,
    include_apps: list[str] | None = None,
    client_app_types: list[str] | None = None,
    grant_controls: list[str] | None = None,
) -> dict:
    return {
        "id": pid,
        "displayName": name,
        "state": state,
        "conditions": {
            "users": {"includeUsers": include_users or []},
            "applications": {"includeApplications": include_apps or []},
            "clientAppTypes": client_app_types or [],
        },
        "grantControls": {"builtInControls": grant_controls or []},
    }


# POLICY_001 - MFA for All Users

class TestMfaForAll:
    async def test_no_mfa_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": []})
        findings = await MfaForAllCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    async def test_broad_mfa_policy_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(include_users=["All"], include_apps=["All"], grant_controls=["mfa"]),
        ]})
        findings = await MfaForAllCheck().run(graph)
        assert len(findings) == 0

    async def test_mfa_for_specific_users_only_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(include_users=["group-id-1"], include_apps=["All"], grant_controls=["mfa"]),
        ]})
        findings = await MfaForAllCheck().run(graph)
        assert len(findings) == 1

    async def test_disabled_mfa_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(
                state="disabled",
                include_users=["All"], include_apps=["All"], grant_controls=["mfa"],
            ),
        ]})
        findings = await MfaForAllCheck().run(graph)
        assert len(findings) == 1

    async def test_report_only_mfa_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(
                state="enabledForReportingButNotEnforced",
                include_users=["All"], include_apps=["All"], grant_controls=["mfa"],
            ),
        ]})
        findings = await MfaForAllCheck().run(graph)
        assert len(findings) == 1


# POLICY_002 - Block Legacy Authentication

class TestBlockLegacyAuth:
    async def test_no_block_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": []})
        findings = await BlockLegacyAuthCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    async def test_full_legacy_block_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(
                include_users=["All"],
                client_app_types=["exchangeActiveSync", "other"],
                grant_controls=["block"],
            ),
        ]})
        findings = await BlockLegacyAuthCheck().run(graph)
        assert len(findings) == 0

    async def test_split_policies_covering_all_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(pid="p1", include_users=["All"], client_app_types=["exchangeActiveSync"], grant_controls=["block"]),
            _policy(pid="p2", include_users=["All"], client_app_types=["other"], grant_controls=["block"]),
        ]})
        findings = await BlockLegacyAuthCheck().run(graph)
        assert len(findings) == 0

    async def test_only_eas_blocked_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(client_app_types=["exchangeActiveSync"], grant_controls=["block"]),
        ]})
        findings = await BlockLegacyAuthCheck().run(graph)
        assert len(findings) == 1
        assert "other legacy clients" in findings[0].detail

    async def test_disabled_block_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(
                state="disabled",
                client_app_types=["exchangeActiveSync", "other"],
                grant_controls=["block"],
            ),
        ]})
        findings = await BlockLegacyAuthCheck().run(graph)
        assert len(findings) == 1


# POLICY_003 - Report-Only Policies

class TestReportOnlyPolicies:
    async def test_report_only_policy_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(pid="p1", name="Pilot MFA Policy", state="enabledForReportingButNotEnforced"),
        ]})
        findings = await ReportOnlyPoliciesCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "Pilot MFA Policy" in findings[0].title

    async def test_enabled_policy_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(pid="p1", state="enabled"),
        ]})
        findings = await ReportOnlyPoliciesCheck().run(graph)
        assert len(findings) == 0

    async def test_multiple_report_only_each_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=CA_URL, json={"value": [
            _policy(pid="p1", name="Policy A", state="enabledForReportingButNotEnforced"),
            _policy(pid="p2", name="Policy B", state="enabledForReportingButNotEnforced"),
            _policy(pid="p3", name="Policy C", state="enabled"),
        ]})
        findings = await ReportOnlyPoliciesCheck().run(graph)
        assert len(findings) == 2
