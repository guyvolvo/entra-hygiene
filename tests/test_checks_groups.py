from __future__ import annotations

import pytest

from entra_hygiene.checks.groups import EmptyGroupsCheck, OwnerlessGroupsCheck
from entra_hygiene.graph import BASE_URL
from entra_hygiene.models import Severity

GROUPS_URL = f"{BASE_URL}/groups?$select=id,displayName,groupTypes"


def _group(gid: str, name: str) -> dict:
    return {"id": gid, "displayName": name, "groupTypes": []}


# GROUPS_001 - Ownerless Groups

class TestOwnerlessGroups:
    async def test_ownerless_group_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [_group("g1", "IT Security")]})
        httpx_mock.add_response(url=f"{BASE_URL}/groups/g1/owners", json={"value": []})
        findings = await OwnerlessGroupsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "IT Security" in findings[0].title

    async def test_group_with_owner_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [_group("g2", "Finance")]})
        httpx_mock.add_response(
            url=f"{BASE_URL}/groups/g2/owners",
            json={"value": [{"id": "u1", "displayName": "Alice"}]},
        )
        findings = await OwnerlessGroupsCheck().run(graph)
        assert len(findings) == 0

    async def test_multiple_groups_partial_ownerless(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [
            _group("g3", "Orphan Group"),
            _group("g4", "Owned Group"),
        ]})
        httpx_mock.add_response(url=f"{BASE_URL}/groups/g3/owners", json={"value": []})
        httpx_mock.add_response(
            url=f"{BASE_URL}/groups/g4/owners",
            json={"value": [{"id": "u2", "displayName": "Bob"}]},
        )
        findings = await OwnerlessGroupsCheck().run(graph)
        assert len(findings) == 1
        assert "Orphan Group" in findings[0].title

    async def test_no_groups_no_findings(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": []})
        findings = await OwnerlessGroupsCheck().run(graph)
        assert len(findings) == 0


# GROUPS_002 - Empty Groups

class TestEmptyGroups:
    async def test_empty_group_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [_group("g5", "Empty Team")]})
        httpx_mock.add_response(url=f"{BASE_URL}/groups/g5/members", json={"value": []})
        findings = await EmptyGroupsCheck().run(graph)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert "Empty Team" in findings[0].title

    async def test_populated_group_not_flagged(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [_group("g6", "Dev Team")]})
        httpx_mock.add_response(
            url=f"{BASE_URL}/groups/g6/members",
            json={"value": [{"id": "u3", "displayName": "Charlie"}]},
        )
        findings = await EmptyGroupsCheck().run(graph)
        assert len(findings) == 0

    async def test_no_groups_no_findings(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": []})
        findings = await EmptyGroupsCheck().run(graph)
        assert len(findings) == 0

    async def test_multiple_groups_partial_empty(self, graph, httpx_mock):
        httpx_mock.add_response(url=GROUPS_URL, json={"value": [
            _group("g7", "Ghost Group"),
            _group("g8", "Active Group"),
        ]})
        httpx_mock.add_response(url=f"{BASE_URL}/groups/g7/members", json={"value": []})
        httpx_mock.add_response(
            url=f"{BASE_URL}/groups/g8/members",
            json={"value": [{"id": "u4", "displayName": "Dave"}]},
        )
        findings = await EmptyGroupsCheck().run(graph)
        assert len(findings) == 1
        assert "Ghost Group" in findings[0].title
