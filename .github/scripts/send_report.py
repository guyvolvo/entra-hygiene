"""Send the HTML scan report by email via Microsoft Graph sendMail.

Reads TENANT_ID, CLIENT_ID, CLIENT_SECRET, SENDER_EMAIL, REPORT_EMAIL from
the environment. Exits 0 without sending if either email address is unset.
"""
from __future__ import annotations

import base64
import os
import sys
from urllib.parse import quote

import httpx

from entra_hygiene.auth import AuthError, get_token

SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
REPORT_EMAIL = os.environ.get("REPORT_EMAIL", "")

if not SENDER_EMAIL or not REPORT_EMAIL:
    print("SENDER_EMAIL or REPORT_EMAIL not configured. Skipping email.")
    sys.exit(0)

try:
    token = get_token("client-credentials")
except AuthError as e:
    print(f"Auth failed: {e}")
    sys.exit(1)

with open("report.html", encoding="utf-8") as f:
    html_body = f.read()

html_attachment = base64.b64encode(html_body.encode()).decode("ascii")

with open("report.json", "rb") as f:
    json_attachment = base64.b64encode(f.read()).decode("ascii")

payload = {
    "message": {
        "subject": "Entra Hygiene Scan Report",
        "body": {"contentType": "HTML", "content": html_body},
        "toRecipients": [{"emailAddress": {"address": REPORT_EMAIL}}],
        "attachments": [
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "report.html",
                "contentType": "text/html",
                "contentBytes": html_attachment,
            },
            {
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": "report.json",
                "contentType": "application/json",
                "contentBytes": json_attachment,
            },
        ],
    }
}

response = httpx.post(
    f"https://graph.microsoft.com/v1.0/users/{quote(SENDER_EMAIL)}/sendMail",
    json=payload,
    headers={"Authorization": f"Bearer {token}"},
    timeout=30,
)

if response.status_code == 202:
    print(f"Report sent to {REPORT_EMAIL}.")
else:
    print(f"sendMail failed: {response.status_code} {response.text}")
    sys.exit(1)
