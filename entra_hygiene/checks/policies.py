from __future__ import annotations

from entra_hygiene.checks.base import BaseCheck
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import Finding, Severity

_CA_POLICIES_URL = (
    "/identity/conditionalAccess/policies"
    "?$select=id,displayName,state,conditions,grantControls"
)


def _is_enabled(policy: dict) -> bool:
    return policy.get("state") == "enabled"


def _is_report_only(policy: dict) -> bool:
    return policy.get("state") == "enabledForReportingButNotEnforced"


def _grant_controls(policy: dict) -> list[str]:
    grant = policy.get("grantControls") or {}
    return grant.get("builtInControls") or []


def _include_users(policy: dict) -> list[str]:
    users = (policy.get("conditions") or {}).get("users") or {}
    return users.get("includeUsers") or []


def _include_apps(policy: dict) -> list[str]:
    apps = (policy.get("conditions") or {}).get("applications") or {}
    return apps.get("includeApplications") or []


def _client_app_types(policy: dict) -> list[str]:
    return (policy.get("conditions") or {}).get("clientAppTypes") or []


class MfaForAllCheck(BaseCheck):
    id = "POLICY_001"
    title = "No MFA Policy for All Users"
    description = (
        "No enabled Conditional Access policy requires MFA "
        "for all users across all cloud apps"
    )

    async def run(self, graph: GraphClient) -> list[Finding]:
        policies = await graph.get_all(_CA_POLICIES_URL)
        has_broad_mfa = any(
            _is_enabled(p)
            and "mfa" in _grant_controls(p)
            and "All" in _include_users(p)
            and "All" in _include_apps(p)
            for p in policies
        )
        if not has_broad_mfa:
            return [Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="No CA policy enforcing MFA for all users",
                detail=(
                    "No enabled Conditional Access policy requires MFA "
                    "for All Users across All Cloud Apps."
                ),
                affected_object="conditionalAccess/policies",
                remediation=(
                    "Create a Conditional Access policy targeting All Users and All Cloud Apps "
                    "with a grant control requiring MFA."
                ),
            )]
        return []


class BlockLegacyAuthCheck(BaseCheck):
    id = "POLICY_002"
    title = "Legacy Authentication Not Blocked"
    description = (
        "No enabled Conditional Access policy blocks legacy "
        "authentication protocols across the tenant"
    )

    async def run(self, graph: GraphClient) -> list[Finding]:
        policies = await graph.get_all(_CA_POLICIES_URL)
        # Legacy auth requires both exchangeActiveSync and other to be blocked.
        # Check across all enabled blocking policies - tenants may split these.
        blocks_eas = False
        blocks_other = False
        for p in policies:
            if not _is_enabled(p):
                continue
            if "block" not in _grant_controls(p):
                continue
            types = _client_app_types(p)
            if "exchangeActiveSync" in types:
                blocks_eas = True
            if "other" in types:
                blocks_other = True

        if not (blocks_eas and blocks_other):
            uncovered = []
            if not blocks_eas:
                uncovered.append("Exchange ActiveSync")
            if not blocks_other:
                uncovered.append("other legacy clients (IMAP, POP3, SMTP Auth)")
            return [Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title="Legacy authentication is not fully blocked",
                detail=f"Not covered by any block policy: {', '.join(uncovered)}.",
                affected_object="conditionalAccess/policies",
                remediation=(
                    "Create a Conditional Access policy targeting All Users, "
                    "client app types exchangeActiveSync and other, with a Block grant control."
                ),
            )]
        return []


class ReportOnlyPoliciesCheck(BaseCheck):
    id = "POLICY_003"
    title = "Policies in Report-Only Mode"
    description = "Conditional Access policies that are in report-only mode and not enforced"

    async def run(self, graph: GraphClient) -> list[Finding]:
        policies = await graph.get_all(_CA_POLICIES_URL)
        findings: list[Finding] = []
        for p in policies:
            if _is_report_only(p):
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.LOW,
                    title=f"Report-only policy: {p.get('displayName') or p['id']}",
                    detail=(
                        "This Conditional Access policy is in report-only mode "
                        "and is not being enforced."
                    ),
                    affected_object=p["id"],
                    remediation=(
                        "Review the policy impact in sign-in logs and enable it when ready."
                    ),
                ))
        return findings
