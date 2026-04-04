from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from entra_hygiene.checks.apps import ExpiringSecretsCheck, OwnerlessAppsCheck
from entra_hygiene.graph import BASE_URL
from entra_hygiene.models import Severity

APPS_URL = f"{BASE_URL}/applications?$select=id,displayName,appId,passwordCredentials,keyCredentials"
OWNERLESS_APPS_URL = f"{BASE_URL}/applications?$select=id,displayName,appId"


def _iso_in(days: int) -> str:
    dt = datetime.now(tz=timezone.utc) + timedelta(days=days)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# APPS_001 — Expiring / Expired App Credentials
# ---------------------------------------------------------------------------

class TestExpiringSecrets:
    @pytest.mark.asyncio
    async def test_expired_secret_is_critical(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app1",
                "displayName": "My App",
                "appId": "client-id-1",
                "passwordCredentials": [{
                    "keyId": "k1",
                    "displayName": "prod-secret",
                    "endDateTime": _iso_in(-10),
                }],
                "keyCredentials": [],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "expired" in findings[0].title.lower()
        assert "days ago" in findings[0].detail

    @pytest.mark.asyncio
    async def test_expiring_secret_is_high(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app2",
                "displayName": "My App",
                "appId": "client-id-2",
                "passwordCredentials": [{
                    "keyId": "k2",
                    "displayName": "prod-secret",
                    "endDateTime": _iso_in(15),
                }],
                "keyCredentials": [],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "expires in" in findings[0].detail

    @pytest.mark.asyncio
    async def test_expired_certificate_is_critical(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app3",
                "displayName": "Cert App",
                "appId": "client-id-3",
                "passwordCredentials": [],
                "keyCredentials": [{
                    "keyId": "c1",
                    "displayName": "prod-cert",
                    "endDateTime": _iso_in(-5),
                }],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "certificate" in findings[0].title.lower()

    @pytest.mark.asyncio
    async def test_fresh_secret_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app4",
                "displayName": "Fresh App",
                "appId": "client-id-4",
                "passwordCredentials": [{
                    "keyId": "k4",
                    "displayName": "fresh-secret",
                    "endDateTime": _iso_in(180),
                }],
                "keyCredentials": [],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_expiry_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app5",
                "displayName": "No Expiry App",
                "appId": "client-id-5",
                "passwordCredentials": [{
                    "keyId": "k5",
                    "displayName": "no-expiry",
                    "endDateTime": None,
                }],
                "keyCredentials": [],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_no_credentials_no_findings(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=APPS_URL,
            json={"value": [{
                "id": "app6",
                "displayName": "No Creds App",
                "appId": "client-id-6",
                "passwordCredentials": [],
                "keyCredentials": [],
            }]},
        )
        findings = await ExpiringSecretsCheck().run(graph)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# APPS_002 — Ownerless App Registrations
# ---------------------------------------------------------------------------

class TestOwnerlessApps:
    @pytest.mark.asyncio
    async def test_ownerless_app_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=OWNERLESS_APPS_URL,
            json={"value": [{"id": "app1", "displayName": "Orphan App", "appId": "client-id-1"}]},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/applications/app1/owners",
            json={"value": []},
        )
        findings = await OwnerlessAppsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "Orphan App" in findings[0].title

    @pytest.mark.asyncio
    async def test_app_with_owner_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(
            url=OWNERLESS_APPS_URL,
            json={"value": [{"id": "app2", "displayName": "Owned App", "appId": "client-id-2"}]},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/applications/app2/owners",
            json={"value": [{"id": "u1", "displayName": "Alice"}]},
        )
        findings = await OwnerlessAppsCheck().run(graph)
        assert len(findings) == 0
