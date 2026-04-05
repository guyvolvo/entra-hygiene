from __future__ import annotations

from prometheus_client import Gauge, start_http_server

from entra_hygiene.models import ScanResult

_findings_by_severity = Gauge(
    "entra_hygiene_findings_total",
    "Number of active findings by severity",
    ["severity"],
)
_findings_by_check = Gauge(
    "entra_hygiene_findings_by_check",
    "Number of findings per check",
    ["check_id"],
)
_check_errors = Gauge(
    "entra_hygiene_check_errors_total",
    "Number of checks that failed with an error on the last scan",
)
_last_scan_ts = Gauge(
    "entra_hygiene_last_scan_timestamp_seconds",
    "Unix timestamp of the last completed scan",
)
_scan_duration = Gauge(
    "entra_hygiene_scan_duration_seconds",
    "Duration of the last scan in seconds",
)
_scan_success = Gauge(
    "entra_hygiene_scan_success",
    "1 if the last scan completed without check errors, 0 otherwise",
)


def start_metrics_server(port: int) -> None:
    start_http_server(port)


def update_metrics(result: ScanResult) -> None:
    for severity, count in result.counts_by_severity.items():
        _findings_by_severity.labels(severity=severity.value).set(count)

    _findings_by_check.clear()
    check_counts: dict[str, int] = {}
    for finding in result.findings:
        check_counts[finding.check_id] = check_counts.get(finding.check_id, 0) + 1
    for check_id, count in check_counts.items():
        _findings_by_check.labels(check_id=check_id).set(count)

    _check_errors.set(len(result.errors))
    _last_scan_ts.set(result.finished_at.timestamp())
    _scan_duration.set(result.duration_seconds)
    _scan_success.set(0 if result.errors else 1)
