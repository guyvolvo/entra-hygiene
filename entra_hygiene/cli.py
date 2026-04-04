from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from entra_hygiene.auth import AuthError, get_token
from entra_hygiene.checks.users import (
    GlobalAdminCountCheck,
    MfaGapsCheck,
    PrivilegedGuestCheck,
    StaleAccountsCheck,
)
from entra_hygiene.config import settings
from entra_hygiene.graph import GraphClient
from entra_hygiene.models import CheckError, Finding, ScanResult, Severity
from entra_hygiene.reporters.html_reporter import render_html

app = typer.Typer(
    name="entra-hygiene",
    help="Automated Entra ID tenant hygiene auditing tool.",
    no_args_is_help=True,
)

console = Console()

ALL_CHECKS = [
    StaleAccountsCheck(),
    MfaGapsCheck(),
    PrivilegedGuestCheck(),
    GlobalAdminCountCheck(),
]

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


async def _run_check(check, graph: GraphClient) -> tuple[str, list[Finding], CheckError | None]:
    try:
        findings = await check.run(graph)
        return check.id, findings, None
    except Exception as e:
        error = CheckError(check_id=check.id, check_title=check.title, error=str(e))
        return check.id, [], error


async def _run_scan(graph: GraphClient, check_list: list) -> ScanResult:
    started_at = ScanResult.start_timer()
    tasks = [_run_check(check, graph) for check in check_list]
    results = await asyncio.gather(*tasks)

    all_findings: list[Finding] = []
    all_errors: list[CheckError] = []
    checks_ran: list[str] = []

    for check_id, findings, error in results:
        checks_ran.append(check_id)
        all_findings.extend(findings)
        if error:
            all_errors.append(error)

    finished_at = datetime.now().astimezone()
    return ScanResult(
        tenant_id=settings.tenant_id,
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=(finished_at - started_at).total_seconds(),
        checks_ran=checks_ran,
        findings=all_findings,
        errors=all_errors,
    )


def _print_console_report(result: ScanResult) -> None:
    console.print()
    console.rule("[bold]Entra Hygiene Scan Report[/bold]")
    console.print(f"Tenant:   {result.tenant_id}")
    console.print(f"Started:  {result.started_at:%Y-%m-%d %H:%M:%S %Z}")
    console.print(f"Duration: {result.duration_seconds:.1f}s")
    console.print(f"Checks:   {len(result.checks_ran)} ran, {len(result.errors)} failed")
    console.print()

    if result.errors:
        error_table = Table(title="Check Errors", show_lines=True)
        error_table.add_column("Check", style="bold")
        error_table.add_column("Error", style="red")
        for err in result.errors:
            error_table.add_row(f"{err.check_id} ({err.check_title})", err.error)
        console.print(error_table)
        console.print()

    if not result.findings:
        console.print("[bold green]No findings. Tenant looks clean.[/bold green]")
        return

    counts = result.counts_by_severity
    summary_parts = []
    for sev in Severity:
        if counts[sev] > 0:
            color = SEVERITY_COLORS[sev]
            summary_parts.append(f"[{color}]{sev.value.upper()}: {counts[sev]}[/{color}]")
    console.print("Findings: " + "  ".join(summary_parts))
    console.print()

    table = Table(show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Check", width=10)
    table.add_column("Title", min_width=30)
    table.add_column("Detail")
    table.add_column("Remediation")

    sorted_findings = sorted(
        result.findings,
        key=lambda f: list(Severity).index(f.severity),
    )
    for f in sorted_findings:
        color = SEVERITY_COLORS[f.severity]
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.check_id,
            f.title,
            f.detail,
            f.remediation,
        )
    console.print(table)


def _print_json_report(result: ScanResult) -> None:
    print(result.model_dump_json(indent=2))


@app.command()
def scan(
    auth: str = typer.Option(
        "client-credentials",
        "--auth",
        help="Authentication mode: client-credentials or device-code.",
    ),
    output: str = typer.Option(
        "console",
        "--output",
        "-o",
        help="Output format: console, json, or html.",
    ),
    checks: Optional[str] = typer.Option(
        None,
        "--checks",
        help="Comma-separated list of check IDs to run. Runs all if omitted.",
    ),
) -> None:
    """Run hygiene checks against your Entra ID tenant."""
    try:
        token = get_token(auth)
    except AuthError as e:
        console.print(f"[bold red]Authentication failed:[/bold red] {e}")
        raise typer.Exit(code=1)

    graph = GraphClient(access_token=token)

    check_list = ALL_CHECKS
    if checks:
        requested = {c.strip().upper() for c in checks.split(",")}
        check_list = [c for c in ALL_CHECKS if c.id in requested]
        unknown = requested - {c.id for c in ALL_CHECKS}
        if unknown:
            console.print(f"[yellow]Unknown check IDs (skipped): {', '.join(sorted(unknown))}[/yellow]")
        if not check_list:
            console.print("[bold red]No valid checks selected.[/bold red]")
            raise typer.Exit(code=1)

    result = asyncio.run(_run_scan(graph, check_list))

    if output == "json":
        _print_json_report(result)
    elif output == "html":
        print(render_html(result))
    else:
        _print_console_report(result)

    if not result.success:
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
