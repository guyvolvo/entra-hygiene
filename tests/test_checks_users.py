from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from entra_hygiene.checks.users import (
    GlobalAdminCountCheck,
    MfaGapsCheck,
    PrivilegedGuestCheck,
    StaleAccountsCheck,
)
from entra_hygiene.graph import BASE_URL
from entra_hygiene.models import Severity


def _iso(days_ago: int) -> str:
    dt = datetime.now().astimezone() - timedelta(days=days_ago)
    return dt.isoformat()


# ---------------------------------------------------------------------------
# USER_001 - Stale Accounts
# ---------------------------------------------------------------------------

class TestStaleAccounts:
    @pytest.mark.asyncio
    async def test_stale_account_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,signInActivity,userType&$count=true",
            json={
                "value": [{
                    "id": "u1",
                    "userPrincipalName": "stale@contoso.com",
                    "accountEnabled": True,
                    "signInActivity": {"lastSignInDateTime": _iso(120)},
                }]
            },
        )
        findings = await StaleAccountsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "120 days" in findings[0].detail

    @pytest.mark.asyncio
    async def test_active_account_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,signInActivity,userType&$count=true",
            json={
                "value": [{
                    "id": "u2",
                    "userPrincipalName": "active@contoso.com",
                    "accountEnabled": True,
                    "signInActivity": {"lastSignInDateTime": _iso(10)},
                }]
            },
        )
        findings = await StaleAccountsCheck().run(graph)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_signin_activity_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,signInActivity,userType&$count=true",
            json={
                "value": [{
                    "id": "u3",
                    "userPrincipalName": "never@contoso.com",
                    "accountEnabled": True,
                    "signInActivity": None,
                }]
            },
        )
        findings = await StaleAccountsCheck().run(graph)
        assert len(findings) == 1
        assert "No sign-in recorded" in findings[0].title

    @pytest.mark.asyncio
    async def test_disabled_account_skipped(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,signInActivity,userType&$count=true",
            json={
                "value": [{
                    "id": "u4",
                    "userPrincipalName": "disabled@contoso.com",
                    "accountEnabled": False,
                    "signInActivity": {"lastSignInDateTime": _iso(200)},
                }]
            },
        )
        findings = await StaleAccountsCheck().run(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# USER_002 - MFA Gaps
# ---------------------------------------------------------------------------

class TestMfaGaps:
    @pytest.mark.asyncio
    async def test_no_mfa_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,userType&$filter=accountEnabled eq true&$count=true",
            json={
                "value": [{"id": "u1", "userPrincipalName": "nomfa@contoso.com", "accountEnabled": True}]
            },
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/u1/authentication/methods",
            json={
                "value": [{
                    "@odata.type": "#microsoft.graph.passwordAuthenticationMethod",
                    "id": "pwd1",
                }]
            },
        )
        findings = await MfaGapsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_mfa_registered_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/users?$select=id,displayName,userPrincipalName,"
                f"accountEnabled,userType&$filter=accountEnabled eq true&$count=true",
            json={
                "value": [{"id": "u2", "userPrincipalName": "hasmfa@contoso.com", "accountEnabled": True}]
            },
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/users/u2/authentication/methods",
            json={
                "value": [
                    {"@odata.type": "#microsoft.graph.passwordAuthenticationMethod", "id": "pwd1"},
                    {"@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod", "id": "auth1"},
                ]
            },
        )
        findings = await MfaGapsCheck().run(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# USER_003 - Privileged Guest Accounts
# ---------------------------------------------------------------------------

GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
OTHER_ROLE_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class TestPrivilegedGuest:
    @pytest.mark.asyncio
    async def test_guest_global_admin_critical(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/roleManagement/directory/roleAssignments?$expand=principal",
            json={
                "value": [{
                    "roleDefinitionId": GLOBAL_ADMIN_ROLE_ID,
                    "principal": {
                        "id": "g1",
                        "displayName": "External Consultant",
                        "userType": "Guest",
                    },
                }]
            },
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/roleManagement/directory/roleDefinitions/{GLOBAL_ADMIN_ROLE_ID}",
            json={"displayName": "Global Administrator"},
        )
        findings = await PrivilegedGuestCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_guest_other_role_high(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/roleManagement/directory/roleAssignments?$expand=principal",
            json={
                "value": [{
                    "roleDefinitionId": OTHER_ROLE_ID,
                    "principal": {
                        "id": "g2",
                        "displayName": "Partner Account",
                        "userType": "Guest",
                    },
                }]
            },
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/roleManagement/directory/roleDefinitions/{OTHER_ROLE_ID}",
            json={"displayName": "User Administrator"},
        )
        findings = await PrivilegedGuestCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_member_with_role_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=f"{BASE_URL}/roleManagement/directory/roleAssignments?$expand=principal",
            json={
                "value": [{
                    "roleDefinitionId": GLOBAL_ADMIN_ROLE_ID,
                    "principal": {
                        "id": "m1",
                        "displayName": "Internal Admin",
                        "userType": "Member",
                    },
                }]
            },
        )
        findings = await PrivilegedGuestCheck().run(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# USER_004 - Global Admin Count
# ---------------------------------------------------------------------------

class TestGlobalAdminCount:
    def _members_url(self):
        return (
            f"{BASE_URL}/directoryRoles(roleTemplateId='{GLOBAL_ADMIN_ROLE_ID}')/members"
            f"?$select=id,displayName,userPrincipalName,signInActivity"
        )

    @pytest.mark.asyncio
    async def test_excessive_admins_flagged(self, graph, httpx_mock):
        members = [
            {"id": f"a{i}", "userPrincipalName": f"admin{i}@contoso.com",
             "signInActivity": {"lastSignInDateTime": _iso(5)}}
            for i in range(7)
        ]
        httpx_mock.add_response(url=self._members_url(), json={"value": members})
        findings = await GlobalAdminCountCheck().run(graph)
        titles = [f.title for f in findings]
        assert any("Excessive" in t for t in titles)

    @pytest.mark.asyncio
    async def test_single_admin_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=self._members_url(),
            json={
                "value": [{
                    "id": "a1",
                    "userPrincipalName": "onlyadmin@contoso.com",
                    "signInActivity": {"lastSignInDateTime": _iso(2)},
                }]
            },
        )
        findings = await GlobalAdminCountCheck().run(graph)
        titles = [f.title for f in findings]
        assert any("Insufficient" in t for t in titles)

    @pytest.mark.asyncio
    async def test_stale_admin_critical(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=self._members_url(),
            json={
                "value": [
                    {"id": "a1", "userPrincipalName": "active@contoso.com",
                     "signInActivity": {"lastSignInDateTime": _iso(5)}},
                    {"id": "a2", "userPrincipalName": "stale@contoso.com",
                     "signInActivity": {"lastSignInDateTime": _iso(120)}},
                ]
            },
        )
        findings = await GlobalAdminCountCheck().run(graph)
        stale = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(stale) == 1
        assert "stale@contoso.com" in stale[0].title

    @pytest.mark.asyncio
    async def test_healthy_admin_count_no_findings(self, graph, httpx_mock):
        members = [
            {"id": f"a{i}", "userPrincipalName": f"admin{i}@contoso.com",
             "signInActivity": {"lastSignInDateTime": _iso(3)}}
            for i in range(3)
        ]
        httpx_mock.add_response(url=self._members_url(), json={"value": members})
        findings = await GlobalAdminCountCheck().run(graph)
        assert len(findings) == 0
