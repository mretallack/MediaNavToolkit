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
from medianav_toolbox.api.register import get_delegator_credentials, register_device_wire
from medianav_toolbox.auth import extract_jsessionid
from medianav_toolbox.config import Config
from medianav_toolbox.device import parse_device_nng, read_device_status, validate_drive
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.models import DeviceCredentials, ServiceEndpoints, Session
from medianav_toolbox.protocol import SVC_MARKET, build_request, parse_response
from medianav_toolbox.swid import compute_swid
from medianav_toolbox.wire_codec import (
    DeviceFileEntry,
    build_login_body,
    build_senddevicestatus_body,
    build_sendfingerprint_body,
)

TOOLBOX_UA = "DaciaAutomotive-Toolbox-2026041167"
BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
CREDS_FILE = ".medianav_creds.json"
MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"
WEB_BASE = "https://dacia-ulc.naviextras.com"


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

        # 5. Get head unit credentials via delegator
        try:
            hu_creds = get_delegator_credentials(
                client,
                endpoints,
                creds,
                appcid=device.appcid,
            )
            result["steps"].append("delegator")

            # 5b. Register HU device separately (for 0x68 flag requests)
            from medianav_toolbox.api.register import register_hu_device

            hu_dev_creds = _load_hu_dev_creds(usb_path)
            if hu_dev_creds is None:
                hu_dev_creds = register_hu_device(
                    client,
                    endpoints,
                    appcid=device.appcid,
                )
                if hu_dev_creds:
                    _save_hu_dev_creds(usb_path, hu_dev_creds)
                    result["steps"].append("register_hu_device")
                else:
                    result["steps"].append("register_hu_device (cached/409)")
            else:
                result["steps"].append("register_hu_device (cached)")

            # 6. Send device status with head unit credentials
            ds_resp = _send_device_status(client, creds, hu_creds, session, usb_path, device)
            result["devicestatus_status"] = ds_resp.status_code
            result["steps"].append("senddevicestatus")
        except RuntimeError:
            pass  # delegator/senddevicestatus are optional for basic flow

        # 7. Web login (for /toolbox/ pages like catalog, managecontent)
        if username and session.jsessionid:
            web_jsid = web_login(session.jsessionid, username, password)
            if web_jsid:
                result["web_jsessionid"] = web_jsid
                result["steps"].append("web_login")

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
    cred_block = build_credential_block(creds.name)
    query = bytes([0xC2, 0x20]) + cred_block
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
    query = bytes([0xC3, 0x20]) + cred_block
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


def _send_device_status(client, creds, hu_creds, session, usb_path, device):
    """Send device status — replays captured requests to establish device context.

    Two senddevicestatus calls are needed:
    1. Flow 735 (flags=0x60): re-encrypt captured body with current keys
    2. Flow 737 (flags=0x68): raw replay (Secret₃ unknown)
    Both are required for the web session to show content.
    """
    from medianav_toolbox.crypto import snakeoil

    base = Path(__file__).parent.parent / "analysis" / "flows_decoded" / "2026-04-16"
    cap1 = base / "735-senddevicestatus-req.bin"
    cap2 = base / "737-senddevicestatus-req.bin"

    if not cap1.exists() or not cap2.exists():
        return type("R", (), {"status_code": 0})()

    # First call: re-encrypt captured body with our keys
    wire1 = cap1.read_bytes()
    body1 = snakeoil(wire1[18:], creds.secret)
    query = bytes([0xC5, 0x60])
    wire = build_request(
        query=query,
        body=body1,
        service_minor=SVC_MARKET,
        code=creds.code,
        secret=creds.secret,
    )
    resp1 = client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire,
        headers=_wire_headers(session),
    )

    # Second call: raw replay (0x68 flags, Secret₃ unknown)
    wire2_raw = cap2.read_bytes()
    resp2 = client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire2_raw,
        headers={**_wire_headers(session), "Content-Length": str(len(wire2_raw))},
    )

    return resp2 if resp2.status_code == 200 else resp1


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


HU_DEV_CREDS_FILE = ".medianav_hu_dev_creds.json"


def _load_hu_dev_creds(usb_path: Path) -> DeviceCredentials | None:
    creds_path = usb_path / HU_DEV_CREDS_FILE
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


def _save_hu_dev_creds(usb_path: Path, creds: DeviceCredentials) -> None:
    (usb_path / HU_DEV_CREDS_FILE).write_text(
        json.dumps({"name": creds.name.hex(), "code": creds.code, "secret": creds.secret})
    )


def web_login(jsessionid: str, username: str, password: str) -> str | None:
    """Perform web login to get a session that works with /toolbox/ pages.

    The wire protocol JSESSIONID is passed to browser-entry to link sessions,
    then a form POST to /toolbox/login authenticates the web session.

    Returns the authenticated JSESSIONID, or None on failure.
    """
    import httpx

    with httpx.Client(
        follow_redirects=True,
        timeout=30,
        cookies={"JSESSIONID": jsessionid},
    ) as client:
        try:
            # 1. Visit device page to establish web session
            client.get(
                f"{WEB_BASE}/toolbox/device?workingMode=TOOLBOX",
                headers={"User-Agent": BROWSER_UA},
            )

            # 2. Web login with username/password
            client.post(
                f"{WEB_BASE}/toolbox/login",
                data={
                    "posted": "true",
                    "marketSession.userLoginForm.email": username,
                    "marketSession.userLoginForm.password": password,
                },
                headers={
                    "User-Agent": BROWSER_UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )

            # Extract JSESSIONID from cookies
            for cookie in client.cookies.jar:
                if cookie.name == "JSESSIONID":
                    return cookie.value
        except (httpx.RemoteProtocolError, httpx.ConnectError):
            pass
    return None
