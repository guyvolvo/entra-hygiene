# entra-hygiene

A command-line tool that audits your Entra ID (Azure AD) tenant and tells you what's wrong before someone else finds out.

It connects to Microsoft Graph API, runs a suite of hygiene checks across users, apps, Conditional Access policies, groups, and roles, then produces a severity-graded report — in your terminal, as JSON, as a self-contained HTML file, or as live Prometheus metrics for your existing stack.

Built for IT admins and security teams at SMBs who need a scriptable, schedulable alternative to clicking through the Azure portal.

---

## Quick Start

**Requirements:** Docker

```bash
git clone https://github.com/guyvolvo/entra-hygiene.git
cd entra-hygiene
cp .env.example .env
# Fill in TENANT_ID, CLIENT_ID, CLIENT_SECRET in .env
```

**Background service** — rescans on interval, exposes Prometheus metrics:

```bash
docker compose up
```

**One-off scan:**

```bash
docker build -f docker/Dockerfile -t entra-hygiene .

# Terminal output
docker run --env-file .env entra-hygiene scan

# HTML report (open in browser or paste into an Outlook email body)
docker run --env-file .env entra-hygiene scan --output html > report.html

# JSON output (for SIEM ingestion or scripting)
docker run --env-file .env entra-hygiene scan --output json > report.json
```

**Run specific checks only:**

```bash
docker run --env-file .env entra-hygiene scan --checks USER_001,USER_002,APPS_001
```

**No app registration yet?** Use device-code auth to test against your tenant interactively:

```bash
docker run -it --env-file .env entra-hygiene scan --auth device-code
```

---

## Azure App Registration

The tool needs an App Registration in Entra ID with **Application permissions** (not delegated). A tenant admin must grant admin consent once.

| Permission | Purpose |
|---|---|
| `User.Read.All` | Read user profiles and sign-in activity |
| `AuditLog.Read.All` | Read last sign-in timestamps |
| `Directory.Read.All` | Read groups, roles, and service principals |
| `Application.Read.All` | Read app registrations and credential expiry |
| `Policy.Read.All` | Read Conditional Access policies |
| `RoleManagement.Read.Directory` | Read directory role assignments |
| `Mail.Send` | Send HTML scan reports by email (optional) |

> `Mail.Send` is only required if you use the `SENDER_EMAIL` / `REPORT_EMAIL` email feature. With application permission it can send as any mailbox in the tenant. Scope it to a dedicated alerts mailbox via an [Exchange application access policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access) if your org requires it.

**Setup steps:**
1. Azure Portal → Entra ID → App registrations → New registration
2. Name it anything (e.g. `entra-hygiene`)
3. API permissions → Add → Microsoft Graph → Application permissions → add all permissions above
4. Grant admin consent
5. Certificates & secrets → New client secret → copy the value into `.env`

For production use, prefer a certificate over a client secret.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# Required
TENANT_ID=your-tenant-id
CLIENT_ID=your-app-client-id
CLIENT_SECRET=your-client-secret

# Optional -- scan thresholds (these are the defaults)
STALE_DAYS=90
SECRET_EXPIRY_WARNING_DAYS=30

# Optional -- serve mode (these are the defaults)
SCAN_INTERVAL_HOURS=6
METRICS_PORT=5454

# Optional -- email report after each scan (requires Mail.Send permission)
SENDER_EMAIL=alerts@yourdomain.com
REPORT_EMAIL=recipient@yourdomain.com
```

---

## What It Checks

| ID | Severity | Check |
|---|---|---|
| `USER_001` | MEDIUM | Accounts with no sign-in activity beyond the configured threshold (default 90 days) |
| `USER_002` | HIGH | Enabled accounts with no MFA method registered |
| `USER_003` | CRITICAL / HIGH | Guest accounts holding directory roles |
| `USER_004` | HIGH / CRITICAL | Global Admin count out of range, or stale Global Admin accounts |
| `APPS_001` | CRITICAL / HIGH | App secrets and certificates that are expired or expiring within 30 days |
| `APPS_002` | MEDIUM | App registrations with no assigned owners |
| `POLICY_001` | HIGH | No enabled CA policy enforcing MFA for all users across all apps |
| `POLICY_002` | HIGH | Legacy authentication (Exchange ActiveSync, IMAP, POP3, SMTP Auth) not fully blocked |
| `POLICY_003` | LOW | Conditional Access policies stuck in report-only mode |
| `ROLES_001` | HIGH / MEDIUM | Users with permanent (non-PIM) assignments to privileged roles |
| `ROLES_002` | HIGH | Service principals holding privileged directory roles |
| `GROUPS_001` | MEDIUM | Groups with no assigned owners |
| `GROUPS_002` | LOW | Empty groups with no members |

---

## Serve Mode

`docker compose up` runs the tool as a long-lived service. It performs a full scan on startup, then rescans every `SCAN_INTERVAL_HOURS` hours, re-authenticating before each run to handle token expiry.

Metrics are exposed at `:5454/metrics` in Prometheus text format. Add this to your existing scrape config:

```yaml
scrape_configs:
  - job_name: entra-hygiene
    static_configs:
      - targets: ["<host>:5454"]
```

**Exposed metrics:**

```
entra_hygiene_findings_total{severity="critical|high|medium|low|info"}
entra_hygiene_findings_by_check{check_id="USER_001|APPS_001|..."}
entra_hygiene_check_errors_total
entra_hygiene_last_scan_timestamp_seconds
entra_hygiene_scan_duration_seconds
entra_hygiene_scan_success
```

---

## GitHub Actions

A scheduled workflow runs every Sunday at 09:00 UTC. It uploads HTML and JSON reports as workflow artifacts (retained 30 days) and optionally emails the HTML report.

The workflow file is already in the repo at `.github/workflows/weekly-scan.yml`. GitHub picks it up automatically — no installation required.

**Enabling the workflow:**

1. Go to your repo on GitHub → **Actions** tab
2. If prompted, click **Enable GitHub Actions**
3. The workflow will run on schedule from that point forward

**Adding secrets:**

Go to **Settings → Secrets and variables → Actions → New repository secret** and add each of the following:

| Secret | Required | Value |
|---|---|---|
| `TENANT_ID` | Yes | Your Entra tenant ID |
| `CLIENT_ID` | Yes | App registration client ID |
| `CLIENT_SECRET` | Yes | App registration client secret |
| `SENDER_EMAIL` | No | Mailbox to send the report from |
| `REPORT_EMAIL` | No | Recipient address for the emailed report |

Secrets are encrypted and never visible after saving. They are injected as environment variables at runtime only.

If `SENDER_EMAIL` or `REPORT_EMAIL` are absent the email step is skipped — the scan and artifact upload still run.

**Manual runs:**

Actions → **Entra Hygiene Scan** → **Run workflow**. You can optionally pass a comma-separated list of check IDs to run only a subset, and toggle whether to send the email.

**Finding the reports:**

After each run: Actions → click the run → scroll to **Artifacts** → download `entra-hygiene-<run_id>` (contains `report.html` and `report.json`, retained 30 days).

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Auth failure or invalid configuration |
| `2` | Scan completed, findings were found |

Exit code `2` is a normal operational state — your automation should treat it as a non-error.

---

## Design Principles

- **Read-only.** This tool never modifies your tenant. Every finding includes a remediation suggestion — acting on it is always a manual step.
- **Fail loudly.** Missing permissions or auth failures produce a clear error, not a silent partial scan.
- **Checks are independent.** One failing check never blocks the rest.
- **Self-contained output.** The HTML report is a single file with no external dependencies — safe to email or archive.
- **No telemetry.** Data goes to Microsoft Graph only. Nothing leaves your environment.
