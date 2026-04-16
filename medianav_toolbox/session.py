"""End-to-end session flow for the NaviExtras API.

Flow: boot → register (or use cached creds) → login → sendfingerprint → getprocess

CRITICAL: Wire protocol requests must NOT include Content-Type header.
The server returns HTTP 500 if Content-Type is present. The real Toolbox
sends only Content-Length, Host, and User-Agent for wire protocol calls.

Ref: toolbox.md §2 (wire protocol), §5 (boot), §8 (register), §6 (market calls)
"""

import json
from pathlib import Path

from medianav_toolbox.api.boot import boot
from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.register import register_device_wire
from medianav_toolbox.auth import extract_jsessionid
from medianav_toolbox.config import Config
from medianav_toolbox.device import parse_device_nng, read_device_status, validate_drive
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.models import DeviceCredentials, ServiceEndpoints, Session
from medianav_toolbox.protocol import SVC_MARKET, build_request, parse_response
from medianav_toolbox.swid import compute_swid
from medianav_toolbox.wire_codec import build_login_body, build_sendfingerprint_body

TOOLBOX_UA = "DaciaAutomotive-Toolbox-2026041167"
CREDS_FILE = ".medianav_creds.json"
MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"


def _wire_headers(session: Session | None = None) -> dict[str, str]:
    """Build headers for wire protocol requests. No Content-Type."""
    headers = {"User-Agent": TOOLBOX_UA}
    if session and session.jsessionid:
        headers["Cookie"] = f"JSESSIONID={session.jsessionid}"
    return headers


def run_session(
    usb_path: Path,
    username: str,
    password: str,
    config: Config | None = None,
) -> dict:
    """Run the full session flow against the live API."""
    config = config or Config()
    result = {"steps": [], "errors": []}

    errors = validate_drive(usb_path)
    if errors:
        result["errors"] = errors
        return result

    device = parse_device_nng(usb_path / "NaviSync" / "license" / "device.nng")
    drive_info = read_device_status(usb_path)
    result["device"] = device
    result["drive_info"] = drive_info

    with NaviExtrasClient(config) as client:
        endpoints = boot(client)
        result["endpoints"] = endpoints
        result["steps"].append("boot")

        creds = _load_creds(usb_path)
        if not creds:
            try:
                swid = compute_swid("linux-medianav-toolbox")
                creds = register_device_wire(
                    client,
                    endpoints,
                    swid=swid,
                    appcid=device.appcid,
                    uniq_id=device.brand_md5.upper(),
                )
                _save_creds(usb_path, creds)
                result["steps"].append("register")
            except RuntimeError as e:
                result["errors"].append(f"Registration failed: {e}")
                return result
        else:
            result["steps"].append("register (cached)")

        result["device_creds"] = creds

        session = _login_wire(client, creds)
        result["session"] = session
        result["market_url"] = MARKET_BASE
        result["steps"].append("login")

        if not session.is_authenticated:
            result["errors"].append("Login failed")
            return result

        fp_resp = _send_fingerprint(client, creds, session)
        result["fingerprint_status"] = fp_resp.status_code
        result["steps"].append("sendfingerprint")

        gp_resp = _get_process(client, creds, session)
        result["getprocess_status"] = gp_resp.status_code
        result["getprocess_body"] = gp_resp.content
        result["steps"].append("getprocess")

    return result


def _login_wire(client, creds):
    cred_block = build_credential_block(creds.name)
    query = bytes([0xC0, 0x20]) + cred_block
    body = build_login_body(
        os_name="Linux",
        os_version="6.0",
        os_build="0",
        agent_version="1.0.0",
        agent_aliases=["Dacia_ULC"],
        language="en",
    )
    wire = build_request(
        query=query,
        body=body,
        service_minor=SVC_MARKET,
        code=creds.code,
        secret=creds.secret,
    )
    resp = client.post(f"{MARKET_BASE}/1/login", content=wire, headers=_wire_headers())
    session = Session()
    jsid = extract_jsessionid(dict(resp.cookies))
    if jsid:
        session.jsessionid = jsid
    if resp.status_code == 200:
        session.is_authenticated = True
    return session


def _send_fingerprint(client, creds, session):
    query = bytes([0x53, 0x60])
    body = build_sendfingerprint_body()
    wire = build_request(
        query=query,
        body=body,
        service_minor=SVC_MARKET,
        code=creds.code,
        secret=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/sendfingerprint",
        content=wire,
        headers=_wire_headers(session),
    )


def _get_process(client, creds, session):
    cred_block = build_credential_block(creds.name)
    query = bytes([0x54, 0x20]) + cred_block
    wire = build_request(
        query=query,
        body=b"",
        service_minor=SVC_MARKET,
        code=creds.code,
        secret=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/getprocess",
        content=wire,
        headers=_wire_headers(session),
    )


def _load_creds(usb_path: Path) -> DeviceCredentials | None:
    creds_path = usb_path / CREDS_FILE
    if not creds_path.exists():
        return None
    try:
        data = json.loads(creds_path.read_text())
        return DeviceCredentials(
            name=bytes.fromhex(data["name"]),
            code=data["code"],
            secret=data["secret"],
        )
    except (KeyError, ValueError):
        return None


def _save_creds(usb_path: Path, creds: DeviceCredentials) -> None:
    creds_path = usb_path / CREDS_FILE
    creds_path.write_text(
        json.dumps(
            {
                "name": creds.name.hex(),
                "code": creds.code,
                "secret": creds.secret,
            }
        )
    )
