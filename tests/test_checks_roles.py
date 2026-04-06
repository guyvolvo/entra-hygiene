from __future__ import annotations

import pytest

from entra_hygiene.checks.roles import (
    PermanentPrivilegedAssignmentsCheck,
    PrivilegedServicePrincipalsCheck,
)
from entra_hygiene.graph import BASE_URL
from entra_hygiene.models import Severity

ROLE_ASSIGNMENTS_URL = (
    f"{BASE_URL}/roleManagement/directory/roleAssignments?$expand=principal"
)

GA_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRA_ROLE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"
SEC_ADMIN_ROLE_ID = "194ae4cb-b126-40b2-bd5b-6091b380977d"
NON_PRIV_ROLE_ID = "aaaaaaaa-0000-0000-0000-000000000000"


def _user_assignment(
    assignment_id: str, role_id: str, upn: str, user_id: str = "u1"
) -> dict:
    return {
        "id": assignment_id,
        "roleDefinitionId": role_id,
        "principalId": user_id,
        "principal": {
            "@odata.type": "#microsoft.graph.user",
            "id": user_id,
            "displayName": "Test User",
            "userPrincipalName": upn,
        },
    }


def _sp_assignment(
    assignment_id: str, role_id: str, sp_name: str, sp_id: str = "sp1"
) -> dict:
    return {
        "id": assignment_id,
        "roleDefinitionId": role_id,
        "principalId": sp_id,
        "principal": {
            "@odata.type": "#microsoft.graph.servicePrincipal",
            "id": sp_id,
            "displayName": sp_name,
        },
    }


# ROLES_001 - Permanent Privileged Assignments

class TestPermanentPrivilegedAssignments:
    async def test_ga_user_flagged_high(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _user_assignment("a1", GA_ROLE_ID, "admin@contoso.com"),
        ]})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Global Administrator" in findings[0].detail

    async def test_pra_user_flagged_high(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _user_assignment("a2", PRA_ROLE_ID, "priv@contoso.com"),
        ]})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    async def test_sec_admin_flagged_medium(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _user_assignment("a3", SEC_ADMIN_ROLE_ID, "sec@contoso.com"),
        ]})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    async def test_non_privileged_role_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _user_assignment("a4", NON_PRIV_ROLE_ID, "user@contoso.com"),
        ]})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 0

    async def test_service_principal_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _sp_assignment("a5", GA_ROLE_ID, "My App"),
        ]})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 0

    async def test_no_assignments_no_findings(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": []})
        findings = await PermanentPrivilegedAssignmentsCheck().run(graph)
        assert len(findings) == 0


# ROLES_002 - Service Principals with Privileged Roles

class TestPrivilegedServicePrincipals:
    async def test_sp_with_privileged_role_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _sp_assignment("a6", GA_ROLE_ID, "Automation App"),
        ]})
        findings = await PrivilegedServicePrincipalsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Automation App" in findings[0].title

    async def test_sp_with_non_privileged_role_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _sp_assignment("a7", NON_PRIV_ROLE_ID, "Safe App"),
        ]})
        findings = await PrivilegedServicePrincipalsCheck().run(graph)
        assert len(findings) == 0

    async def test_user_not_flagged_by_this_check(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _user_assignment("a8", GA_ROLE_ID, "admin@contoso.com"),
        ]})
        findings = await PrivilegedServicePrincipalsCheck().run(graph)
        assert len(findings) == 0

    async def test_role_name_in_detail(self, graph, httpx_mock):
        httpx_mock.add_response(url=ROLE_ASSIGNMENTS_URL, json={"value": [
            _sp_assignment("a9", SEC_ADMIN_ROLE_ID, "Security Bot"),
        ]})
        findings = await PrivilegedServicePrincipalsCheck().run(graph)
        assert len(findings) == 1
        assert "Security Administrator" in findings[0].detail
