from __future__ import annotations

from datetime import datetime

from entra_hygiene.checks.base import BaseCheck
from entra_hygiene.config import settings
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import Finding, Severity


def _days_until(iso_timestamp: str | None) -> int | None:
    if not iso_timestamp:
        return None
    expiry = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    return (expiry - datetime.now().astimezone()).days


class ExpiringSecretsCheck(BaseCheck):
    id = "APPS_001"
    title = "Expiring or Expired App Credentials"
    description = "App registrations with secrets or certificates that are expired or expiring soon"

    async def run(self, graph: GraphClient) -> list[Finding]:
        apps = await graph.get_all(
            "/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials"
        )
        findings: list[Finding] = []
        for app in apps:
            name = app.get("displayName") or app["appId"]
            for cred in app.get("passwordCredentials", []):
                f = self._check_credential(app["id"], name, cred, "secret")
                if f:
                    findings.append(f)
            for cred in app.get("keyCredentials", []):
                f = self._check_credential(app["id"], name, cred, "certificate")
                if f:
                    findings.append(f)
        return findings

    def _check_credential(
        self, app_id: str, app_name: str, cred: dict, cred_type: str
    ) -> Finding | None:
        days = _days_until(cred.get("endDateTime"))
        if days is None:
            return None
        cred_name = cred.get("displayName") or cred.get("keyId") or "unnamed"
        if days < 0:
            return Finding(
                check_id=self.id,
                severity=Severity.CRITICAL,
                title=f"Expired {cred_type}: {app_name}",
                detail=f"Credential '{cred_name}' expired {abs(days)} days ago.",
                affected_object=app_id,
                remediation="Rotate this credential and update any services using it.",
            )
        if days <= settings.secret_expiry_warning_days:
            return Finding(
                check_id=self.id,
                severity=Severity.HIGH,
                title=f"Expiring {cred_type}: {app_name}",
                detail=f"Credential '{cred_name}' expires in {days} days.",
                affected_object=app_id,
                remediation="Rotate this credential before it expires to avoid service disruption.",
            )
        return None


class OwnerlessAppsCheck(BaseCheck):
    id = "APPS_002"
    title = "Ownerless App Registrations"
    description = "App registrations with no assigned owners"

    async def run(self, graph: GraphClient) -> list[Finding]:
        apps = await graph.get_all(
            "/applications?$select=id,displayName,appId"
        )
        findings: list[Finding] = []
        for app in apps:
            owners = await graph.get_all(f"/applications/{app['id']}/owners")
            if not owners:
                name = app.get("displayName") or app["appId"]
                findings.append(Finding(
                    check_id=self.id,
                    severity=Severity.MEDIUM,
                    title=f"Ownerless app: {name}",
                    detail="This app registration has no assigned owners.",
                    affected_object=app["id"],
                    remediation="Assign at least one owner to this app registration.",
                ))
        return findings
