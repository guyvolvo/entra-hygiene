# entra-hygiene

A command-line tool that audits your Entra ID (Azure AD) tenant and tells you what's wrong before someone else finds out.

It connects to Microsoft Graph API, runs a suite of hygiene checks across users, apps, Conditional Access policies, groups, and roles, then produces a severity-graded report — in your terminal, as JSON, as a self-contained HTML file, or as live Prometheus metrics for your existing Grafana stack.

Built for IT admins and security teams at SMBs who need a scriptable, schedulable alternative to clicking through the Azure portal.

---

## What It Checks

**Users**
- Accounts with no sign-in activity in 90+ days
- Accounts with no MFA registered
- Guest accounts with privileged roles
- Global Admin count and last sign-in per admin

**App Registrations & Service Principals**
- Client secrets expiring within 30 / 60 / 90 days
- Secrets that have already expired
- App registrations with no owners

**Conditional Access**
- No MFA enforcement policy for all users
- No policy blocking legacy authentication
- Users or groups excluded from all CA policies

**Groups & Roles**
- Permanent privileged role assignments (vs. PIM-eligible)
- External users holding directory roles
- Empty groups and groups with no owners

---

## Quick Start

**Requirements:** Docker

```bash
git clone https://github.com/guyvolvo/entra-hygiene.git
cd entra-hygiene
```

Fill in your credentials in `.env`, then choose a mode:

**Background service** — rescans on an interval, exposes Prometheus metrics on `:5555`:

```bash
docker compose up
```

**One-off scan** — run it manually, get a report:

```bash
# Terminal output
docker run --env-file .env entra-hygiene scan

# HTML report
docker run --env-file .env entra-hygiene scan --output html > report.html

# JSON output
docker run --env-file .env entra-hygiene scan --output json > report.json
```

No app registration yet? Try device-code auth first:

```bash
docker run -it --env-file .env entra-hygiene scan --auth device-code
```

---

## Prometheus Integration

When running in serve mode the tool exposes `/metrics` on `:5555`. Add this to your Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: entra-hygiene
    static_configs:
      - targets: ["<host>:5555"]
```

**Exposed metrics:**

```
entra_hygiene_findings_total{severity="critical|high|medium|low"}
entra_hygiene_stale_accounts_total
entra_hygiene_accounts_without_mfa_total
entra_hygiene_expiring_secrets_total{days_bucket="30|60|90"}
entra_hygiene_expired_secrets_total
entra_hygiene_global_admins_total
entra_hygiene_ca_policy_gaps_total
entra_hygiene_privileged_external_users_total
entra_hygiene_last_scan_timestamp_seconds
entra_hygiene_scan_duration_seconds
entra_hygiene_scan_success
```

---

## Azure App Registration

The tool needs an App Registration in Entra ID with the following **Application permissions**. A tenant admin must grant admin consent once.

| Permission | Purpose |
|---|---|
| `User.Read.All` | Read user profiles and sign-in activity |
| `AuditLog.Read.All` | Read last sign-in timestamps |
| `Directory.Read.All` | Read groups, roles, and service principals |
| `Application.Read.All` | Read app registrations and credential expiry |
| `Policy.Read.All` | Read Conditional Access policies |
| `RoleManagement.Read.Directory` | Read directory role assignments |

**Steps:**
1. Azure Portal → Entra ID → App registrations → New registration
2. Name it anything (e.g. `entra-hygiene`)
3. API permissions → Add → Microsoft Graph → Application permissions → add all permissions above
4. Grant admin consent
5. Certificates & secrets → New client secret → copy the value into `.env`

For production use, prefer a certificate over a client secret.

---

## Configuration

```env
TENANT_ID=your-tenant-id
CLIENT_ID=your-app-client-id
CLIENT_SECRET=your-client-secret

# Optional — these are the defaults
STALE_DAYS=90
SECRET_EXPIRY_WARNING_DAYS=30
SCAN_INTERVAL_HOURS=6
METRICS_PORT=5555
```

---

## Design Principles

- **Read-only.** This tool never modifies your tenant. Every finding includes a remediation suggestion — acting on it is always a manual step.
- **Fail loudly.** Missing permissions or auth failures produce a clear error, not a silent partial scan.
- **Checks are independent.** One failing check never blocks the rest.
- **Self-contained output.** The HTML report is a single file with no external dependencies — safe to email or archive.
- **No telemetry.** Data goes to Microsoft Graph only. Nothing leaves your environment.

