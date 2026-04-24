"""End-to-end session flow for the NaviExtras API.

Flow: boot → register (or use cached creds) → login → sendfingerprint → getprocess

CRITICAL: Wire protocol requests must NOT include Content-Type header.
The server returns HTTP 500 if Content-Type is present. The real Toolbox
sends only Content-Length, Host, and User-Agent for wire protocol calls.

Ref: toolbox.md §2 (wire protocol), §5 (boot), §8 (register), §6 (market calls)
"""

import json
import os
import struct
from pathlib import Path

from medianav_toolbox.api.boot import boot
from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.register import get_delegator_credentials, register_device_wire
from medianav_toolbox.auth import extract_jsessionid
from medianav_toolbox.config import Config
from medianav_toolbox.device import parse_device_nng, read_device_status, validate_drive
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.models import DeviceCredentials, ServiceEndpoints, Session
from medianav_toolbox.protocol import SVC_MARKET, SVC_REGISTER, build_request, parse_response
from medianav_toolbox.swid import compute_swid
from medianav_toolbox.wire_codec import (
    DeviceFileEntry,
    build_getprocess_body,
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
                _save_creds(usb_path, creds, uniq_id=device.brand_md5.upper())
                result["steps"].append("register")
            except RuntimeError as e:
                result["errors"].append(f"Registration failed: {e}")
                return result
        else:
            result["steps"].append("register (cached)")

        result["device_creds"] = creds

        # --- Correct sequence (from run26 fresh session capture) ---
        # 1. Login
        session = _login_wire(client, creds)
        result["session"] = session
        result["market_url"] = MARKET_BASE
        result["steps"].append("login")

        if not session.is_authenticated:
            result["errors"].append("Login failed")
            return result

        # 2. Licenses (early check)
        try:
            licenses = get_licenses(client, creds, session)
            result["licenses"] = licenses
            result["steps"].append("licenses")
        except Exception:
            result["licenses"] = []

        # 3. GetProcess
        gp_resp = _get_process(client, creds, session)
        result["getprocess_status"] = gp_resp.status_code
        result["steps"].append("getprocess")

        # 4. SendFingerprint
        fp_resp = _send_fingerprint(client, creds, session)
        result["fingerprint_status"] = fp_resp.status_code
        result["steps"].append("sendfingerprint")

        # 5. Device descriptor list + hasActivatableService + model list
        try:
            from medianav_toolbox.api.register import (
                get_device_descriptor_list,
                get_device_model_list,
            )

            get_device_descriptor_list(client, endpoints, creds)
            result["steps"].append("get_device_descriptor_list")

            _has_activatable_service(client, endpoints, creds, session)
            result["steps"].append("hasActivatableService")

            get_device_model_list(client, endpoints)
            result["steps"].append("get_device_model_list")
        except Exception:
            pass  # non-fatal — these provide context but may not be required

        # 6. SendDeviceStatus (0x60 — standard, with tb credentials)
        ds_resp = _send_device_status_0x60(client, creds, session, usb_path, device)
        result["devicestatus_0x60"] = ds_resp.status_code
        result["steps"].append(f"senddevicestatus_0x60={ds_resp.status_code}")

        # 7. Delegator → head unit credentials
        hu_creds = None
        try:
            hu_creds = get_delegator_credentials(
                client,
                endpoints,
                creds,
                appcid=device.appcid,
            )
            result["steps"].append("delegator")

            # 8. SendDeviceStatus (delegated — with hu credentials)
            ds_resp2 = _send_device_status(client, creds, hu_creds, session, usb_path, device)
            result["devicestatus_delegated"] = ds_resp2.status_code
            result["steps"].append(f"senddevicestatus_delegated={ds_resp2.status_code}")
        except RuntimeError:
            pass  # delegator optional for basic flow

        # 9. Web login (for /toolbox/ pages like catalog, managecontent)
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


def _get_process(client, creds, session, swids=None):
    cred_block = build_credential_block(creds.name)
    query = bytes([0xC3, 0x20]) + cred_block
    body = build_getprocess_body(swids) if swids else b""
    wire = build_request(
        query=query,
        body=body,
        service_minor=SVC_MARKET,
        code=creds.code,
        secret=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/getprocess",
        content=wire,
        headers=_wire_headers(session),
    )


def _send_device_status_0x60(client, creds, session, usb_path, device):
    """Send standard 0x60 device status (tb credentials, variant=0x02)."""
    from medianav_toolbox.device_status import build_live_senddevicestatus

    body = build_live_senddevicestatus(usb_path, variant=0x02)
    cred_block = build_credential_block(creds.name)
    query = bytes([0x40, 0x20]) + cred_block
    wire = build_request(
        query=query, body=body,
        service_minor=SVC_MARKET, code=creds.code, secret=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire,
        headers=_wire_headers(session),
    )


def _has_activatable_service(client, endpoints, creds, session):
    """Call hasActivatableService — empty body, service minor 0x0E."""
    cred_block = build_credential_block(creds.name)
    query = bytes([0xC4, 0x20]) + cred_block
    wire = build_request(
        query=query, body=b"",
        service_minor=SVC_REGISTER, code=creds.code, secret=creds.secret,
    )
    return client.post(
        f"{endpoints.register}/hasActivatableService",
        content=wire,
        headers=_wire_headers(session),
    )


def _send_device_status(client, creds, hu_creds, session, usb_path, device):
    """Send delegated device status to establish device context.

    Uses build_dynamic_request() with session_key=creds.secret.
    Wire format: [header][prefix][snakeoil(query, secret)][snakeoil(body, secret)]
    See docs/chain-encryption.md for details.
    """
    from medianav_toolbox.device_status import build_live_senddevicestatus
    from medianav_toolbox.protocol import build_dynamic_request

    body = build_live_senddevicestatus(usb_path, variant=0x03)
    wire = build_dynamic_request(
        counter=0,
        body=body,
        hu_code=hu_creds.code,
        tb_code=creds.code,
        hu_secret=hu_creds.secret,
        session_key=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire,
        headers=_wire_headers(session),
    )


def _send_device_status_0x68(client, creds, hu_creds, session, usb_path):
    """Send delegated device status (variant 0x03).

    Same as _send_device_status but callable separately for the 0x68 flow.
    """
    from medianav_toolbox.device_status import build_live_senddevicestatus
    from medianav_toolbox.protocol import build_dynamic_request

    try:
        body = build_live_senddevicestatus(usb_path, variant=0x03)
    except Exception:
        return type("R", (), {"status_code": 0})()

    wire = build_dynamic_request(
        counter=0,
        body=body,
        hu_code=hu_creds.code,
        tb_code=creds.code,
        hu_secret=hu_creds.secret,
        session_key=creds.secret,
    )
    return client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire,
        headers=_wire_headers(session),
    )


def _browse_catalog(jsessionid: str) -> str | None:
    """Browse the catalog/managecontent page to establish content context.

    The Toolbox web UI navigates to /toolbox/device then /toolbox/managecontent
    before any content download. This may set server-side state that enables
    the 0x68 delegation flow.

    Returns the JSESSIONID or None on failure.
    """
    import httpx

    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=30,
            cookies={"JSESSIONID": jsessionid},
        ) as client:
            # Visit device page (sets working mode)
            client.get(
                f"{WEB_BASE}/toolbox/device?workingMode=TOOLBOX",
                headers={"User-Agent": BROWSER_UA},
            )
            # Visit managecontent page (triggers content tree population)
            resp = client.get(
                f"{WEB_BASE}/toolbox/managecontent",
                headers={"User-Agent": BROWSER_UA},
            )
            if resp.status_code == 200:
                for cookie in client.cookies.jar:
                    if cookie.name == "JSESSIONID":
                        return cookie.value
                return jsessionid
    except (Exception,):
        pass
    return None


def get_licenses(client, creds, session) -> list:
    """Fetch licenses via the wire protocol.

    Calls the licenses endpoint with 0x20 DEVICE mode flags and body 0x800000.
    Returns list of License objects with embedded .lyc data.
    """
    from medianav_toolbox.api.boot import boot
    from medianav_toolbox.catalog import parse_licenses_response

    endpoints = boot(client)
    cred_block = build_credential_block(creds.name)
    wire = build_request(
        query=bytes([0xC4, 0x20]) + cred_block,
        body=b"\x80\x00\x00",
        service_minor=SVC_REGISTER,
        code=creds.code,
        secret=creds.secret,
    )
    resp = client.post(
        f"{endpoints.register}/licenses",
        content=wire,
        headers=_wire_headers(session),
    )
    if resp.status_code != 200:
        return []

    body = parse_response(resp.content, creds.secret)
    return parse_licenses_response(body)


CONFIG_DIR = Path.home() / ".config" / "medianav-toolbox"


def _creds_paths(usb_path: Path) -> list[Path]:
    """Return candidate paths for credentials, in priority order."""
    return [usb_path / CREDS_FILE, CONFIG_DIR / CREDS_FILE]


def _load_creds(usb_path: Path) -> DeviceCredentials | None:
    for creds_path in _creds_paths(usb_path):
        if not creds_path.exists():
            continue
        try:
            data = json.loads(creds_path.read_text())
            creds = DeviceCredentials(
                name=bytes.fromhex(data["name"]),
                code=data["code"],
                secret=data["secret"],
            )
            creds._uniq_id = data.get("uniq_id", "")
            return creds
        except (KeyError, ValueError):
            continue
    return None


def _save_creds(usb_path: Path, creds: DeviceCredentials, uniq_id: str = "") -> None:
    payload = json.dumps(
        {
            "name": creds.name.hex(),
            "code": creds.code,
            "secret": creds.secret,
            "uniq_id": uniq_id,
        }
    )
    for creds_path in _creds_paths(usb_path):
        try:
            creds_path.parent.mkdir(parents=True, exist_ok=True)
            creds_path.write_text(payload)
            return
        except OSError:
            continue


HU_DEV_CREDS_FILE = ".medianav_hu_dev_creds.json"


def _load_hu_dev_creds(usb_path: Path) -> DeviceCredentials | None:
    for p in [usb_path / HU_DEV_CREDS_FILE, CONFIG_DIR / HU_DEV_CREDS_FILE]:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text())
            return DeviceCredentials(
                name=bytes.fromhex(data["name"]),
                code=data["code"],
                secret=data["secret"],
            )
        except (KeyError, ValueError):
            continue
    return None


def _save_hu_dev_creds(usb_path: Path, creds: DeviceCredentials) -> None:
    payload = json.dumps({"name": creds.name.hex(), "code": creds.code, "secret": creds.secret})
    for p in [usb_path / HU_DEV_CREDS_FILE, CONFIG_DIR / HU_DEV_CREDS_FILE]:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(payload)
            return
        except OSError:
            continue


def web_login(jsessionid: str, username: str, password: str) -> str | None:
    """Perform web login to get a session that works with /toolbox/ pages.

    The wire protocol JSESSIONID is passed to browser-entry to link sessions,
    then a form POST to /toolbox/login authenticates the web session.

    Returns the authenticated JSESSIONID, or None on failure.
    """
    import httpx

    for _attempt in range(3):
        try:
            with httpx.Client(
                follow_redirects=True,
                timeout=30,
                cookies={"JSESSIONID": jsessionid},
            ) as client:
                client.get(
                    f"{WEB_BASE}/toolbox/device?workingMode=TOOLBOX",
                    headers={"User-Agent": BROWSER_UA},
                )
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
                for cookie in client.cookies.jar:
                    if cookie.name == "JSESSIONID":
                        return cookie.value
        except (httpx.RemoteProtocolError, httpx.ConnectError, httpx.ReadTimeout):
            import time

            time.sleep(1)
    return None
