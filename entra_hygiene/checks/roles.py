from __future__ import annotations

from entra_hygiene.checks.base import BaseCheck
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import Finding, Severity

_ROLE_ASSIGNMENTS_URL = "/roleManagement/directory/roleAssignments?$expand=principal"

# Assignments to these roles are flagged HIGH; all others in the privileged set are MEDIUM.
_HIGH_SEVERITY_ROLES = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
}

_MEDIUM_SEVERITY_ROLES = {
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
}

_ALL_PRIVILEGED_ROLES = {**_HIGH_SEVERITY_ROLES, **_MEDIUM_SEVERITY_ROLES}


class PermanentPrivilegedAssignmentsCheck(BaseCheck):
    id = "ROLES_001"
    title = "Permanent Privileged Role Assignments"
    description = (
        "Users with permanent (non-PIM) assignments to highly privileged roles. "
        "PIM-eligible assignments should be used for just-in-time access."
    )

    async def run(self, graph: GraphClient) -> list[Finding]:
        assignments = await graph.get_all(_ROLE_ASSIGNMENTS_URL)
        findings: list[Finding] = []
        for a in assignments:
            principal = a.get("principal") or {}
            if principal.get("@odata.type") != "#microsoft.graph.user":
                continue
            role_id = a.get("roleDefinitionId", "")
            role_name = _ALL_PRIVILEGED_ROLES.get(role_id)
            if not role_name:
                continue
            severity = Severity.HIGH if role_id in _HIGH_SEVERITY_ROLES else Severity.MEDIUM
            name = (
                principal.get("userPrincipalName")
                or principal.get("displayName")
                or principal.get("id")
            )
            findings.append(Finding(
                check_id=self.id,
                severity=severity,
                title=f"Permanent privileged assignment: {name}",
                detail=(
                    f"User holds a permanent '{role_name}' assignment. "
                    "PIM should be used for just-in-time access."
                ),
                affected_object=principal.get("id") or a.get("principalId", ""),
                remediation=(
                    "Migrate this assignment to a PIM-eligible role. "
                    "Require activation with justification and MFA."
                ),
            ))
        return findings


class PrivilegedServicePrincipalsCheck(BaseCheck):
    id = "ROLES_002"
    title = "Service Principals with Privileged Roles"
    description = "Non-human/workload identities holding highly privileged directory roles"

    async def run(self, graph: GraphClient) -> list[Finding]:
        assignments = await graph.get_all(_ROLE_ASSIGNMENTS_URL)
        findings: list[Finding] = []
        for a in assignments:
            principal = a.get("principal") or {}
            if principal.get("@odata.type") != "#microsoft.graph.servicePrincipal":
                continue
            role_id = a.get("roleDefinitionId", "")
            role_name = _ALL_PRIVILEGED_ROLES.get(role_id)
            if not role_name:
                continue
            name = principal.get("displayName") or principal.get("id")
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"Service principal with privileged role: {name}",
                detail=f"Service principal holds the '{role_name}' directory role.",
                affected_object=principal.get("id") or a.get("principalId", ""),
                remediation=(
                    "Review whether this service principal requires this level of access. "
                    "Apply least-privilege alternative roles where possible."
                ),
            ))
        return findings
