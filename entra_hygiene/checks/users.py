from __future__ import annotations

from datetime import datetime

from entra_hygiene.checks.base import BaseCheck
from entra_hygiene.config import settings
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import Finding, Severity

GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"


def _days_since(iso_timestamp: str | None) -> int | None:
    if not iso_timestamp:
        return None
    last = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    delta = datetime.now().astimezone() - last
    return delta.days


class StaleAccountsCheck(BaseCheck):
    id = "USER_001"
    title = "Stale Accounts"
    description = "User accounts with no sign-in activity beyond the configured threshold"

    async def run(self, graph: GraphClient) -> list[Finding]:
        users = await graph.get_all(
            "/users?$select=id,displayName,userPrincipalName,accountEnabled,"
            "signInActivity,userType&$count=true"
        )
        findings: list[Finding] = []
        for user in users:
            if not user.get("accountEnabled", True):
                continue
            activity = user.get("signInActivity") or {}
            last_signin = activity.get("lastSignInDateTime")
            days = _days_since(last_signin)

            if last_signin is None:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"No sign-in recorded: {user.get('userPrincipalName', user['id'])}",
                    detail="This account has no sign-in activity on record.",
                    affected_object=user["id"],
                    remediation="Verify whether this account is still needed. Disable if unused.",
                ))
            elif days is not None and days > settings.stale_days:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Stale account: {user.get('userPrincipalName', user['id'])}",
                    detail=f"Last sign-in was {days} days ago ({last_signin}).",
                    affected_object=user["id"],
                    remediation="Review and disable or delete this account.",
                ))
        return findings


class MfaGapsCheck(BaseCheck):
    id = "USER_002"
    title = "Accounts Without MFA"
    description = "User accounts that have not registered any MFA method"

    async def run(self, graph: GraphClient) -> list[Finding]:
        # Single call replaces the previous per-user loop.
        # Requires UserAuthenticationMethod.Read.All and Reports.Read.All.
        records = await graph.get_all(
            "/reports/authenticationMethods/userRegistrationDetails"
            "?$filter=isMfaRegistered eq false"
        )
        findings: list[Finding] = []
        for record in records:
            if record.get("isGuest") or record.get("isExternalUser"):
                continue
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"No MFA registered: {record.get('userPrincipalName', record['id'])}",
                detail="This account has no authentication methods beyond a password.",
                affected_object=record["id"],
                remediation="Require MFA registration for this user.",
            ))
        return findings


class PrivilegedGuestCheck(BaseCheck):
    id = "USER_003"
    title = "Guest Accounts with Privileged Roles"
    description = "External guest accounts holding directory roles"

    async def run(self, graph: GraphClient) -> list[Finding]:
        role_assignments = await graph.get_all(
            "/roleManagement/directory/roleAssignments?$expand=principal"
        )
        findings: list[Finding] = []
        for assignment in role_assignments:
            principal = assignment.get("principal", {})
            if principal.get("userType") == "Guest":
                role_def_id = assignment.get("roleDefinitionId", "")
                role_name = await self._resolve_role_name(graph, role_def_id)
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL if role_def_id == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
                    else Severity.HIGH,
                    title=f"Guest with role: {principal.get('displayName', principal.get('id'))}",
                    detail=f"Guest account holds the '{role_name}' directory role.",
                    affected_object=principal.get("id", ""),
                    remediation="Review whether this guest needs this role. Remove if not justified.",
                ))
        return findings

    @staticmethod
    async def _resolve_role_name(graph: GraphClient, role_def_id: str) -> str:
        try:
            data = await graph.get(f"/roleManagement/directory/roleDefinitions/{role_def_id}")
            return data.get("displayName", role_def_id)
        except Exception:
            return role_def_id


class GlobalAdminCountCheck(BaseCheck):
    id = "USER_004"
    title = "Global Administrator Count"
    description = "Checks the number of Global Administrators and their last sign-in"

    async def run(self, graph: GraphClient) -> list[Finding]:
        members = await graph.get_all(
            f"/directoryRoles(roleTemplateId='{GLOBAL_ADMIN_ROLE_TEMPLATE_ID}')/members"
            "?$select=id,displayName,userPrincipalName,signInActivity"
        )
        findings: list[Finding] = []
        if len(members) > 5:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"Excessive Global Admins: {len(members)} accounts",
                detail="Microsoft recommends no more than 5 Global Administrators.",
                affected_object="directoryRole/GlobalAdministrator",
                remediation="Reduce to 5 or fewer. Use least-privilege roles where possible.",
            ))
        if len(members) < 2:
            findings.append(Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"Insufficient Global Admins: {len(members)} account(s)",
                detail="At least 2 Global Admins are recommended for break-glass scenarios.",
                affected_object="directoryRole/GlobalAdministrator",
                remediation="Designate a second Global Administrator as a break-glass account.",
            ))

        for member in members:
            activity = member.get("signInActivity") or {}
            last_signin = activity.get("lastSignInDateTime")
            days = _days_since(last_signin)
            if days is not None and days > settings.stale_days:
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.CRITICAL,
                    title=f"Stale Global Admin: {member.get('userPrincipalName', member['id'])}",
                    detail=f"Last sign-in was {days} days ago. Unused admin accounts are a risk.",
                    affected_object=member["id"],
                    remediation="Disable this account or remove Global Admin role.",
                ))
        return findings
