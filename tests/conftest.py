from __future__ import annotations

import pytest

from entra_hygiene.graph import GraphClient


@pytest.fixture
def graph(httpx_mock) -> GraphClient:
    return GraphClient(access_token="fake-token-for-testing")
