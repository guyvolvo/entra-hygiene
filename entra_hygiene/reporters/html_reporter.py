from __future__ import annotations

from jinja2 import Environment

from entra_hygiene.models import ScanResult, Severity

# autoescape=True prevents XSS if any Graph-sourced string contains HTML characters.
_env = Environment(autoescape=True)

SEVERITY_ORDER = list(Severity)

SEV_COLOR = {
    "critical": "#f87171",
    "high":     "#fb923c",
    "medium":   "#fde047",
    "low":      "#38bdf8",
    "info":     "#71717a",
}

SEV_BG = {
    "critical": "#450a0a",
    "high":     "#431407",
    "medium":   "#422006",
    "low":      "#082f49",
    "info":     "#27272a",
}

# Base styles applied as inline on every element so Outlook renders them correctly.
# The <style> block is a browser-only enhancement (hover row, font smoothing).
TEMPLATE = _env.from_string("""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Entra Hygiene \u2014 {{ result.tenant_id }}</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; -webkit-font-smoothing: antialiased; }
table { border-collapse: collapse; }
.row:hover td { background-color: #1c1c1f !important; }
</style>
</head>
<body style="margin:0;padding:16px;background-color:#09090b;color:#e4e4e7;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:13px;line-height:1.4;">

<table width="100%" cellpadding="0" cellspacing="0" style="max-width:960px;margin:0 auto;border-collapse:collapse;">
<tr><td>

  <!-- Header -->
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border-bottom:1px solid #27272a;padding-bottom:10px;margin-bottom:10px;">
    <tr>
      <td style="vertical-align:bottom;">
        <div style="font-size:10px;color:#52525b;text-transform:uppercase;letter-spacing:0.08em;font-family:monospace;margin-bottom:2px;">entra-hygiene</div>
        <div style="font-size:16px;font-weight:600;color:#ffffff;">Scan Report</div>
      </td>
      <td style="text-align:right;vertical-align:bottom;font-size:11px;color:#71717a;">
        <span style="font-family:monospace;color:#d4d4d8;">{{ result.tenant_id }}</span><br>
        {{ result.started_at.strftime('%Y-%m-%d %H:%M UTC') }}
        &nbsp;&middot;&nbsp;{{ '%.1f'|format(result.duration_seconds) }}s
        &nbsp;&middot;&nbsp;{{ result.checks_ran|length }} checks
        {% if result.errors %}&nbsp;&middot;&nbsp;<span style="color:#f87171;">{{ result.errors|length }} error{{ 's' if result.errors|length != 1 }}</span>{% endif %}
      </td>
    </tr>
  </table>

  <!-- Severity summary -->
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;margin-bottom:10px;">
    <tr>
      {% for sev in severities %}
      <td style="background-color:#18181b;border:1px solid #27272a;{% if not loop.last %}border-right:0;{% endif %}padding:8px 12px;text-align:center;">
        <div style="font-size:20px;font-weight:700;color:{{ sev_color[sev.value] }};font-variant-numeric:tabular-nums;">{{ counts[sev] }}</div>
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;margin-top:2px;">{{ sev.value }}</div>
      </td>
      {% endfor %}
    </tr>
  </table>

  <!-- Check errors -->
  {% if result.errors %}
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #7f1d1d;margin-bottom:10px;">
    <tr>
      <td colspan="2" style="background-color:#1c0a0a;padding:4px 8px;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#f87171;border-bottom:1px solid #7f1d1d;">Check Errors</td>
    </tr>
    {% for err in result.errors %}
    <tr>
      <td style="padding:4px 8px;font-family:monospace;font-size:11px;color:#71717a;white-space:nowrap;border-top:1px solid #27272a;">{{ err.check_id }}</td>
      <td style="padding:4px 8px;color:#fca5a5;font-size:12px;border-top:1px solid #27272a;">{{ err.error }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <!-- Findings -->
  {% if not result.findings %}
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #27272a;">
    <tr>
      <td style="padding:24px;text-align:center;color:#4ade80;font-size:13px;">No findings \u2014 tenant looks clean.</td>
    </tr>
  </table>
  {% else %}
  <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;border:1px solid #27272a;">
    <tr style="background-color:#18181b;">
      <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;font-weight:500;border-bottom:1px solid #27272a;white-space:nowrap;">Severity</th>
      <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;font-weight:500;border-bottom:1px solid #27272a;white-space:nowrap;">Check</th>
      <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;font-weight:500;border-bottom:1px solid #27272a;">Title</th>
      <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;font-weight:500;border-bottom:1px solid #27272a;">Detail</th>
      <th style="padding:6px 8px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:0.08em;color:#52525b;font-weight:500;border-bottom:1px solid #27272a;">Remediation</th>
    </tr>
    {% for f in findings %}
    <tr class="row">
      <td style="padding:5px 8px;white-space:nowrap;border-top:1px solid #27272a;">
        <span style="display:inline-block;padding:1px 6px;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:0.05em;background-color:{{ sev_bg[f.severity.value] }};color:{{ sev_color[f.severity.value] }};border:1px solid {{ sev_color[f.severity.value] }}33;">{{ f.severity.value }}</span>
      </td>
      <td style="padding:5px 8px;font-family:monospace;font-size:11px;color:#71717a;white-space:nowrap;border-top:1px solid #27272a;">{{ f.check_id }}</td>
      <td style="padding:5px 8px;color:#e4e4e7;font-size:12px;border-top:1px solid #27272a;">{{ f.title }}</td>
      <td style="padding:5px 8px;color:#a1a1aa;font-size:12px;border-top:1px solid #27272a;">{{ f.detail }}</td>
      <td style="padding:5px 8px;color:#a1a1aa;font-size:12px;border-top:1px solid #27272a;">{{ f.remediation }}</td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}

  <p style="margin:12px 0 0;text-align:center;font-size:10px;color:#3f3f46;">Generated by entra-hygiene</p>

</td></tr>
</table>
</body>
</html>
""")


def render_html(result: ScanResult) -> str:
    sorted_findings = sorted(
        result.findings,
        key=lambda f: SEVERITY_ORDER.index(f.severity),
    )
    return TEMPLATE.render(
        result=result,
        severities=SEVERITY_ORDER,
        counts=result.counts_by_severity,
        findings=sorted_findings,
        sev_color=SEV_COLOR,
        sev_bg=SEV_BG,
    )
