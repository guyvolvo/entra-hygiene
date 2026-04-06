# entra-hygiene

A command-line tool that audits your Entra ID (Azure AD) tenant and reports security and hygiene issues across users, apps, policies, roles, and groups.

It connects to Microsoft Graph API, runs 14 hygiene checks across users, apps, Conditional Access policies, groups, and roles, then produces a severity-graded report - in your terminal, as JSON, as a self-contained HTML file, or as live Prometheus metrics for your existing stack.

Built for IT admins and security teams at SMBs who need a scriptable, schedulable alternative to clicking through the Azure portal.

<img width="591" height="489" alt="entra-hygiene-cli" src="https://github.com/user-attachments/assets/0833e812-2e6c-4f04-9c15-d783beafd04f" />

<img width="980" height="363" alt="entra-hygiene" src="https://github.com/user-attachments/assets/387962ad-ae60-480e-bdbf-93b6119129f7" />

---

## What It Checks

| ID | Severity | Check |
|---|---|---|
| `USER_001` | MEDIUM | Accounts with no sign-in activity beyond the configured threshold (default 90 days) |
| `USER_002` | HIGH | Enabled accounts with no MFA method registered |
| `USER_003` | CRITICAL / HIGH | Guest accounts holding directory roles |
| `USER_004` | HIGH / CRITICAL | Global Admin count out of range, or stale Global Admin accounts |
| `USER_005` | MEDIUM / HIGH / CRITICAL | Users flagged by Identity Protection as at-risk or confirmed compromised |
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

## Quick Start

**Requirements:** Docker

```bash
git clone https://github.com/guyvolvo/entra-hygiene.git
cd entra-hygiene
cp .env.example .env
# Fill in TENANT_ID, CLIENT_ID, CLIENT_SECRET in .env
```

**Background service** - rescans on interval, exposes Prometheus metrics:

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
| `UserAuthenticationMethod.Read.All` | Read MFA and authentication methods per user |
| `IdentityRiskyUser.Read.All` | Read risky user signals from Identity Protection |
| `Reports.Read.All` | Read MFA registration status reports |
| `Mail.Send` | Send HTML scan reports by email (optional) |

> `Mail.Send` is only required if you use the `SENDER_EMAIL` / `REPORT_EMAIL` email feature. With application permission it can send as any mailbox in the tenant. Scope it to a dedicated alerts mailbox via an [Exchange application access policy](https://learn.microsoft.com/en-us/graph/auth-limit-mailbox-access) if your org requires it.

**Setup steps:**
1. Azure Portal → Entra ID → App registrations → New registration
2. Name it anything (e.g. `entra-hygiene`)
3. API permissions → Add → Microsoft Graph → Application permissions → add all permissions above
4. Grant admin consent
5. Certificates & secrets → New client secret → copy the value into `.env`

For GitHub Actions, federated credentials are recommended over a client secret — no secret to rotate or store. See the GitHub Actions section for setup instructions.

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
# Required
TENANT_ID=your-tenant-id
CLIENT_ID=your-app-client-id
CLIENT_SECRET=your-client-secret

# Optional: scan thresholds (these are the defaults)
STALE_DAYS=90
SECRET_EXPIRY_WARNING_DAYS=30

# Optional: serve mode (these are the defaults)
SCAN_INTERVAL_MINUTES=15
METRICS_PORT=5454

# Optional: email report after each scan (requires Mail.Send permission)
SENDER_EMAIL=alerts@yourdomain.com
REPORT_EMAIL=recipient@yourdomain.com
```

---

## Serve Mode

`docker compose up` runs the tool as a long-lived service. It performs a full scan on startup, then rescans every `SCAN_INTERVAL_MINUTES` minutes, re-authenticating before each run to handle token expiry.

Serve mode exposes Prometheus metrics only. It does not send email reports - email delivery is handled by the `scan` command and the GitHub Actions workflow.

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

Runs every Sunday at 09:00 UTC. Uploads HTML and JSON reports as artifacts (retained 30 days) and optionally emails the HTML report.

**Setup:**

1. **Settings → Secrets and variables → Actions → New repository secret:**

| Secret | Required | Value |
|---|---|---|
| `TENANT_ID` | Yes | Your Entra tenant ID |
| `CLIENT_ID` | Yes | App registration client ID |
| `CLIENT_SECRET` | No | App registration client secret (only needed without OIDC) |
| `SENDER_EMAIL` | No | Mailbox to send the report from |
| `REPORT_EMAIL` | No | Recipient address |

2. **Configure federated credentials (recommended — no secret to store or rotate):**

   In the Azure Portal, open your app registration → **Certificates & secrets → Federated credentials → Add credential**:

   | Field | Value |
   |---|---|
   | Federated credential scenario | GitHub Actions deploying Azure resources |
   | Organization | your GitHub username or org |
   | Repository | `entra-hygiene` |
   | Entity type | Branch |
   | Branch | `main` |
   | Name | anything (e.g. `github-actions`) |

   Save, then add only `TENANT_ID` and `CLIENT_ID` as GitHub secrets — no `CLIENT_SECRET` required.

   If you skip this step, set `CLIENT_SECRET` instead and the workflow falls back to client secret auth automatically.

3. **Actions** tab → enable if prompted
4. Trigger a manual run to verify before the next scheduled run fires

**Manual runs:**

Actions → **Entra Hygiene Scan** → **Run workflow**. Optionally pass a comma-separated list of check IDs and toggle email sending.

**Reports:**

Actions → click the run → **Artifacts** → download `entra-hygiene-<run_id>` (`report.html` + `report.json`).

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Scan completed, no findings |
| `1` | Auth failure or invalid configuration |
| `2` | Scan completed, findings were found |

Exit code `2` is a normal operational state - your automation should treat it as a non-error.

---

## Design Principles

- **Read-only.** This tool never modifies your tenant. Every finding includes a remediation suggestion - acting on it is always a manual step.
- **Fail loudly.** Missing permissions or auth failures produce a clear error, not a silent partial scan.
- **Checks are independent.** One failing check never blocks the rest.
- **Self-contained output.** The HTML report is a single file with no external dependencies - safe to email or archive.
- **No telemetry.** Data goes to Microsoft Graph only. Nothing leaves your environment.
