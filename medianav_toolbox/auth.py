"""Authentication — credentials loading and session management.

Ref: toolbox.md §17.1 (auth modes: full-auth, device-auth)
"""

import os

from medianav_toolbox.models import Credentials, Session


class AuthenticationError(Exception):
    """Raised when login fails."""


def load_credentials(username: str | None = None, password: str | None = None) -> Credentials:
    """Load credentials from args, .env, or environment variables.

    Priority: explicit args > .env (loaded by dotenv at import) > env vars
    """
    user = username or os.environ.get("NAVIEXTRAS_USER", "")
    pwd = password or os.environ.get("NAVIEXTRAS_PASS", "")
    if not user or not pwd:
        raise AuthenticationError(
            "Missing credentials. Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS in .env "
            "or pass username/password explicitly."
        )
    return Credentials(username=user, password=pwd)


def auth_headers(session: Session, mode: str = "device-auth") -> dict[str, str]:
    """Build auth headers for a request.

    Modes (toolbox.md line 119102):
      - "full-auth": includes credentials (for LOGIN)
      - "device-auth": uses session token (for subsequent calls)
    """
    headers: dict[str, str] = {}
    if session.jsessionid:
        headers["Cookie"] = f"JSESSIONID={session.jsessionid}"
    if mode == "device-auth" and session.device_auth_token:
        headers["X-Auth-Token"] = session.device_auth_token
    return headers


def extract_jsessionid(cookies: dict | None) -> str | None:
    """Extract JSESSIONID from response cookies."""
    if not cookies:
        return None
    for name, value in cookies.items():
        if name.upper() == "JSESSIONID":
            return value
    return None
