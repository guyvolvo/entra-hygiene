from __future__ import annotations

import httpx

BASE_URL = "https://graph.microsoft.com/v1.0"


class GraphError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        self.status_code = status_code
        super().__init__(f"Graph API {status_code}: {message}")


class GraphClient:
    def __init__(self, access_token: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=BASE_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "ConsistencyLevel": "eventual",
            },
            timeout=30.0,
        )

    async def get(self, endpoint: str) -> dict:
        response = await self._client.get(endpoint)
        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After", "unknown")
            raise GraphError(429, f"Throttled. Retry after {retry_after}s")
        if response.status_code in (401, 403):
            body = response.json().get("error", {})
            raise GraphError(response.status_code, body.get("message", "Access denied"))
        response.raise_for_status()
        return response.json()

    async def get_all(self, endpoint: str) -> list[dict]:
        """Fetch all pages of a collection endpoint via @odata.nextLink."""
        results: list[dict] = []
        url = endpoint
        while url:
            data = await self.get(url)
            results.extend(data.get("value", []))
            url = data.get("@odata.nextLink")
        return results

    async def close(self) -> None:
        await self._client.aclose()
