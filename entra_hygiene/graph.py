from __future__ import annotations

import asyncio

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
                "User-Agent": "entra-hygiene/0.1.0",
            },
            timeout=30.0,
        )

    async def get(self, endpoint: str, _retries: int = 3) -> dict:
        response = await self._client.get(endpoint)
        if response.status_code == 429:
            if _retries > 0:
                retry_after = int(response.headers.get("Retry-After", 10))
                await asyncio.sleep(retry_after)
                return await self.get(endpoint, _retries - 1)
            raise GraphError(429, "Throttled - max retries exceeded")
        if response.status_code == 503:
            if _retries > 0:
                await asyncio.sleep(10)
                return await self.get(endpoint, _retries - 1)
            raise GraphError(503, "Service unavailable - max retries exceeded")
        if response.status_code in (401, 403):
            try:
                body = response.json().get("error", {})
            except ValueError:
                body = {}
            raise GraphError(response.status_code, body.get("message", "Access denied"))
        response.raise_for_status()
        try:
            return response.json()
        except ValueError as e:
            raise GraphError(response.status_code, f"Invalid JSON in response: {e}") from e

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
