from __future__ import annotations

import os

import httpx
import msal

from entra_hygiene.config import settings

SCOPES = ["https://graph.microsoft.com/.default"]


class AuthError(Exception):
    pass


def _build_authority() -> str:
    return f"https://login.microsoftonline.com/{settings.tenant_id}"


def _try_acquire_token_oidc() -> str | None:
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
    request_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "")
    if not request_token or not request_url:
        return None
    try:
        resp = httpx.get(
            f"{request_url}&audience=api://AzureADTokenExchange",
            headers={"Authorization": f"Bearer {request_token}"},
            timeout=10,
        )
        if resp.status_code != 200:
            return None
        github_token = resp.json().get("value", "")
        if not github_token:
            return None
        app = msal.ConfidentialClientApplication(
            client_id=settings.client_id,
            authority=_build_authority(),
            client_credential={
                "client_assertion": github_token,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            },
        )
        result = app.acquire_token_for_client(scopes=SCOPES)
        return result.get("access_token")
    except Exception:
        return None


def acquire_token_client_credentials() -> str:
    if not settings.tenant_id or not settings.client_id:
        raise AuthError(
            "Client credentials auth requires TENANT_ID and CLIENT_ID "
            "to be set in .env or environment variables."
        )
    oidc_token = _try_acquire_token_oidc()
    if oidc_token:
        return oidc_token
    if not settings.client_secret:
        raise AuthError(
            "Client credentials auth requires CLIENT_SECRET when OIDC is not available. "
            "Set CLIENT_SECRET in .env or environment variables."
        )
    try:
        app = msal.ConfidentialClientApplication(
            client_id=settings.client_id,
            client_credential=settings.client_secret,
            authority=_build_authority(),
        )
    except ValueError as e:
        raise AuthError(f"Invalid auth configuration: {e}") from e
    result = app.acquire_token_for_client(scopes=SCOPES)
    if "access_token" not in result:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise AuthError(f"Client credentials auth failed: {error}")
    return result["access_token"]


def acquire_token_device_code() -> str:
    if not settings.tenant_id or not settings.client_id:
        raise AuthError(
            "Device code auth requires TENANT_ID and CLIENT_ID "
            "to be set in .env or environment variables."
        )
    try:
        app = msal.PublicClientApplication(
            client_id=settings.client_id,
            authority=_build_authority(),
        )
    except ValueError as e:
        raise AuthError(f"Invalid auth configuration: {e}") from e
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise AuthError(f"Failed to initiate device code flow: {flow.get('error_description', '')}")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        error = result.get("error_description", result.get("error", "Unknown error"))
        raise AuthError(f"Device code auth failed: {error}")
    return result["access_token"]


def get_token(auth_mode: str = "client-credentials") -> str:
    if auth_mode == "device-code":
        return acquire_token_device_code()
    return acquire_token_client_credentials()
