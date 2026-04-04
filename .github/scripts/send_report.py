"""Send the HTML scan report by email via Microsoft Graph sendMail.

Reads TENANT_ID, CLIENT_ID, CLIENT_SECRET, SENDER_EMAIL, REPORT_EMAIL from
the environment. Exits 0 without sending if either email address is unset.
"""
from __future__ import annotations

import base64
import os
import sys

import httpx
import msal

TENANT_ID = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL", "")
REPORT_EMAIL = os.environ.get("REPORT_EMAIL", "")

if not SENDER_EMAIL or not REPORT_EMAIL:
    print("SENDER_EMAIL or REPORT_EMAIL not configured. Skipping email.")
    sys.exit(0)

app = msal.ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=f"https://login.microsoftonline.com/{TENANT_ID}",
)
result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
if "access_token" not in result:
    print(f"Auth failed: {result.get('error_description', result.get('error', 'unknown'))}")
    sys.exit(1)

token = result["access_token"]

with open("report.html", encoding="utf-8") as f:
    html_body = f.read()

with open("report.json", "rb") as f:
    json_attachment = base64.b64encode(f.read()).decode("ascii")

payload = {
    "message": {
        "subject": "Entra Hygiene Scan Report",
        "body": {"contentType": "HTML", "content": html_body},
        "toRecipients": [{"emailAddress": {"address": REPORT_EMAIL}}],
        "attachments": [{
            "@odata.type": "#microsoft.graph.fileAttachment",
            "name": "report.json",
            "contentType": "application/json",
            "contentBytes": json_attachment,
        }],
    }
}

response = httpx.post(
    f"https://graph.microsoft.com/v1.0/users/{SENDER_EMAIL}/sendMail",
    json=payload,
    headers={"Authorization": f"Bearer {token}"},
    timeout=30,
)

if response.status_code == 202:
    print(f"Report sent to {REPORT_EMAIL}.")
else:
    print(f"sendMail failed: {response.status_code} {response.text}")
    sys.exit(1)
