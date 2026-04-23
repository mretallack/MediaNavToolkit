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
                    tb_creds=creds,
                    appcid=device.appcid,
                )
                if hu_dev_creds:
                    _save_hu_dev_creds(usb_path, hu_dev_creds)
                    result["steps"].append("register_hu_device")
                else:
                    result["steps"].append("register_hu_device (cached/409)")
            else:
                result["steps"].append("register_hu_device (cached)")

            # 6. Send device status (0x60 only — 0x68 comes after web login)
            ds_resp = _send_device_status(client, creds, hu_creds, session, usb_path, device)
            result["devicestatus_status"] = ds_resp.status_code
            result["steps"].append("senddevicestatus")
        except RuntimeError:
            hu_creds = None
            pass  # delegator/senddevicestatus are optional for basic flow

        # 7. Web login (for /toolbox/ pages like catalog, managecontent)
        if username and session.jsessionid:
            web_jsid = web_login(session.jsessionid, username, password)
            if web_jsid:
                result["web_jsessionid"] = web_jsid
                result["steps"].append("web_login")

        # 8. Fetch licenses (available .lyc files)
        try:
            licenses = get_licenses(client, creds, session)
            result["licenses"] = licenses
            result["steps"].append("licenses")

            # 9. Second getprocess with license SWIDs (triggers download tasks)
            swids = list({lic.swid for lic in licenses})
            if swids:
                gp2 = _get_process(client, creds, session, swids=swids)
                result["getprocess2_status"] = gp2.status_code
                result["getprocess2_body"] = gp2.content
                result["getprocess2_swids"] = swids
                result["steps"].append("getprocess2")
        except Exception:
            result["licenses"] = []

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


def _send_device_status(client, creds, hu_creds, session, usb_path, device):
    """Send device status to establish device context.

    Sends two requests using the correct wire format (from SSL capture run25):
    1. 0x68 senddevicestatus — State=RECOGNIZED, Name₃ credential
    2. 0x28 senddevicestatus — State=REGISTERED, tb_name credential (after delegator)

    Both use ONE continuous SnakeOil(tb_code) stream for the entire payload.
    The body uses chain encryption (captured from the Toolbox).
    """
    from medianav_toolbox.protocol import build_0x68_request

    data_dir = Path(__file__).parent / "data"

    # Load captured chain data
    chain_0x68 = (data_dir / "chain_body_0x68.bin").read_bytes()
    extra_0x68 = (data_dir / "chain_extra_0x68.bin").read_bytes()

    # Send 0x68 (State=RECOGNIZED, Name₃ credential)
    wire_0x68 = build_0x68_request(
        counter=0xC5,
        tb_name=creds.name,
        hu_code=hu_creds.code,
        tb_code=creds.code,
        hu_secret=hu_creds.secret,
        chain_body=chain_0x68,
        extra_6=extra_0x68,
        code=creds.code,
    )
    resp = client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire_0x68,
        headers=_wire_headers(session),
    )
    if resp.status_code != 200:
        return resp

    # Send 0x28 (State=REGISTERED, tb_name credential)
    chain_0x28 = (data_dir / "chain_body_0x28.bin").read_bytes()
    extra_0x28 = (data_dir / "chain_extra_0x28.bin").read_bytes()

    cred_block_tb = build_credential_block(creds.name)
    query_0x28 = bytes([0xC6, 0x28]) + cred_block_tb + extra_0x28
    payload_0x28 = query_0x28 + chain_0x28

    header = struct.pack(
        ">BBBB Q B HB", 0x01, 0xC2, 0xC2, 0x30,
        creds.code, SVC_MARKET, 0x0000, 0x67,
    )
    from medianav_toolbox.crypto import snakeoil
    wire_0x28 = header + snakeoil(payload_0x28, creds.code)

    resp = client.post(
        f"{MARKET_BASE}/1/senddevicestatus",
        content=wire_0x28,
        headers=_wire_headers(session),
    )
    return resp


def _send_device_status_0x68(client, creds, hu_creds, session, usb_path):
    """Send 0x68 delegated device status after web login + catalog browse.

    The 0x68 uses the delegation HMAC and split encryption.
    Must be called AFTER the web UI has established a content context.
    """
    from medianav_toolbox.protocol import build_0x68_request

    bodies_dir = Path(__file__).parent.parent / "analysis" / "using-win32" / "run16_bodies"
    body_file = bodies_dir / "snakeoil_body_327_1646.bin"
    if body_file.exists():
        body = body_file.read_bytes()
    else:
        from medianav_toolbox.device_status import build_live_senddevicestatus
        try:
            body = build_live_senddevicestatus(usb_path, variant=0x03)
        except Exception:
            return type("R", (), {"status_code": 0})()

    wire = build_0x68_request(
        counter=0x08,
        tb_name=creds.name,
        hu_code=hu_creds.code,
        tb_code=creds.code,
        hu_secret=hu_creds.secret,
        body=body,
        secret=creds.secret,
        code=creds.code,
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
    payload = json.dumps({
        "name": creds.name.hex(),
        "code": creds.code,
        "secret": creds.secret,
        "uniq_id": uniq_id,
    })
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
