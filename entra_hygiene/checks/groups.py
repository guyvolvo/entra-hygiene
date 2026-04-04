from __future__ import annotations

from entra_hygiene.checks.base import BaseCheck
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import Finding, Severity

_GROUPS_URL = "/groups?$select=id,displayName,groupTypes"


class OwnerlessGroupsCheck(BaseCheck):
    id = "GROUPS_001"
    title = "Groups Without Owners"
    description = "Security and Microsoft 365 groups with no assigned owners"

    async def run(self, graph: GraphClient) -> list[Finding]:
        groups = await graph.get_all(_GROUPS_URL)
        findings: list[Finding] = []
        for group in groups:
            owners = await graph.get_all(f"/groups/{group['id']}/owners")
            if not owners:
                name = group.get("displayName") or group["id"]
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Ownerless group: {name}",
                    detail="This group has no assigned owners.",
                    affected_object=group["id"],
                    remediation="Assign at least one owner to this group.",
                ))
        return findings


class EmptyGroupsCheck(BaseCheck):
    id = "GROUPS_002"
    title = "Empty Groups"
    description = "Groups with no members, which may indicate stale or misconfigured objects"

    async def run(self, graph: GraphClient) -> list[Finding]:
        groups = await graph.get_all(_GROUPS_URL)
        findings: list[Finding] = []
        for group in groups:
            members = await graph.get_all(f"/groups/{group['id']}/members")
            if not members:
                name = group.get("displayName") or group["id"]
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.LOW,
                    title=f"Empty group: {name}",
                    detail="This group has no members.",
                    affected_object=group["id"],
                    remediation=(
                        "Delete the group if no longer needed, "
                        "or populate it with the intended members."
                    ),
                ))
        return findings
