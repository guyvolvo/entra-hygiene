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
_findings_by_check_severity = Gauge(
    "entra_hygiene_findings_by_check_severity",
    "Number of findings per check per severity",
    ["check_id", "severity"],
)
_finding = Gauge(
    "entra_hygiene_finding",
    "Individual finding with full detail as labels",
    ["check_id", "severity", "title", "affected_object"],
)
_check_errors = Gauge(
    "entra_hygiene_check_errors_total",
    "Number of checks that failed with an error on the last scan",
)
_check_last_success = Gauge(
    "entra_hygiene_check_last_success_timestamp",
    "Unix timestamp of the last successful run for each check",
    ["check_id"],
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
_mfa_policy_enforced = Gauge(
    "entra_hygiene_mfa_policy_enforced",
    "1 if an enabled CA policy enforces MFA for all users, 0 otherwise",
)
_legacy_auth_blocked = Gauge(
    "entra_hygiene_legacy_auth_blocked",
    "1 if legacy authentication is fully blocked by CA policy, 0 otherwise",
)


_mfa_policy_enforced.set(0)
_legacy_auth_blocked.set(0)


def start_metrics_server(port: int) -> None:
    start_http_server(port)


def update_metrics(result: ScanResult) -> None:
    for severity, count in result.counts_by_severity.items():
        _findings_by_severity.labels(severity=severity.value).set(count)

    _findings_by_check.clear()
    _findings_by_check_severity.clear()
    _finding.clear()

    check_counts: dict[str, int] = {}
    check_severity_counts: dict[tuple[str, str], int] = {}
    failing_checks: set[str] = {e.check_id for e in result.errors}

    for finding in result.findings:
        check_counts[finding.check_id] = check_counts.get(finding.check_id, 0) + 1
        key = (finding.check_id, finding.severity.value)
        check_severity_counts[key] = check_severity_counts.get(key, 0) + 1
        _finding.labels(
            check_id=finding.check_id,
            severity=finding.severity.value,
            title=finding.title,
            affected_object=finding.affected_object,
        ).set(1)

    for check_id, count in check_counts.items():
        _findings_by_check.labels(check_id=check_id).set(count)

    for (check_id, severity), count in check_severity_counts.items():
        _findings_by_check_severity.labels(check_id=check_id, severity=severity).set(count)

    finished_ts = result.finished_at.timestamp()
    for check_id in result.checks_ran:
        if check_id not in failing_checks:
            _check_last_success.labels(check_id=check_id).set(finished_ts)

    _check_errors.set(len(result.errors))
    _last_scan_ts.set(result.finished_at.timestamp())
    _scan_duration.set(result.duration_seconds)
    _scan_success.set(0 if result.errors else 1)

    policy_check_ids = {f.check_id for f in result.findings}
    _mfa_policy_enforced.set(0 if "POLICY_001" in policy_check_ids else 1)
    _legacy_auth_blocked.set(0 if "POLICY_002" in policy_check_ids else 1)
