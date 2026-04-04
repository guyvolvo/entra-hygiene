from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from entra_hygiene.graph import GraphClient
    from entra_hygiene.models import Finding


class BaseCheck(ABC):
    id: str
    title: str
    description: str

    @abstractmethod
    async def run(self, graph: GraphClient) -> list[Finding]:
        ...
