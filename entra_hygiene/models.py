from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    check_id: str
    severity: Severity
    title: str
    detail: str
    affected_object: str
    remediation: str


class CheckError(BaseModel):
    check_id: str
    check_title: str
    error: str


class ScanResult(BaseModel):
    tenant_id: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    checks_ran: list[str]
    findings: list[Finding] = Field(default_factory=list)
    errors: list[CheckError] = Field(default_factory=list)

    @property
    def success(self) -> bool:
        return len(self.errors) == 0

    @property
    def counts_by_severity(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @staticmethod
    def start_timer() -> datetime:
        return datetime.now().astimezone()
