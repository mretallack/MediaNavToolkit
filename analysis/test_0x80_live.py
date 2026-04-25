"""Live test: send 0x80 delegated senddevicestatus and report raw results."""
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from medianav_toolbox.api.client import NaviExtrasClient
from medianav_toolbox.api.register import get_delegator_credentials
from medianav_toolbox.auth import extract_jsessionid
from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.device import parse_device_nng
from medianav_toolbox.device_status import build_live_senddevicestatus
from medianav_toolbox.igo_serializer import build_credential_block, build_delegation_name3
from medianav_toolbox.models import DeviceCredentials
from medianav_toolbox.protocol import SVC_MARKET, build_delegated_request, build_request, parse_response
from medianav_toolbox.session import _login_wire, _wire_headers

MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"
REGISTER_BASE = "https://zippy.naviextras.com/services/register/rest"


def main():
    usb = Path("/mnt/pen")
    assert (usb / "NaviSync").exists(), "USB not mounted"

    for p in [Path("analysis/usb_drive/disk/.medianav_creds.json"), Path(".medianav_creds.json")]:
        if p.exists():
            raw = json.loads(p.read_text()); break
    else:
        print("ERROR: No creds"); return

    creds = DeviceCredentials(name=bytes.fromhex(raw["name"]), code=raw["code"], secret=raw["secret"])
    device = parse_device_nng(usb / "NaviSync" / "license" / "device.nng")
    client = NaviExtrasClient()

    # Login
    print("=== Login ===")
    from medianav_toolbox.wire_codec import build_login_body
    cred_block_login = build_credential_block(creds.name)
    login_q = bytes([0xC0, 0x20]) + cred_block_login
    login_body = build_login_body(os_name="Linux", os_version="6.0", os_build="0",
                                   agent_version="1.0.0", agent_aliases=["Dacia_ULC"], language="en")
    login_wire = build_request(login_q, login_body, SVC_MARKET, code=creds.code, secret=creds.secret)
    resp = client.post(f"{MARKET_BASE}/1/login", content=login_wire, headers=_wire_headers())
    jsessionid = extract_jsessionid(dict(resp.cookies))
    print(f"  {resp.status_code}, JSESSIONID={'yes' if jsessionid else 'NO'}")
    if resp.status_code != 200: return

    hdr = _wire_headers()
    if jsessionid:
        hdr["Cookie"] = f"JSESSIONID={jsessionid}"

    # Boot (to get proper register URL)
    print("=== Boot ===")
    from medianav_toolbox.api.boot import boot
    endpoints = boot(client)
    print(f"  register: {endpoints.register}")

    # Fingerprint
    print("\n=== Fingerprint ===")
    from medianav_toolbox.wire_codec import build_sendfingerprint_body
    fp_body = build_sendfingerprint_body()
    fp_q = bytes([0xC1, 0x20]) + build_credential_block(creds.name)
    fp_wire = build_request(fp_q, fp_body, SVC_MARKET, code=creds.code, secret=creds.secret)
    r = client.post(f"{MARKET_BASE}/1/sendfingerprint", content=fp_wire, headers=hdr)
    print(f"  {r.status_code} ({len(r.content)}B)")

    # Delegator
    print("\n=== Delegator ===")
    hu_creds = get_delegator_credentials(client, endpoints, creds)
    print(f"  hu_code=0x{hu_creds.code:016X} hu_secret=0x{hu_creds.secret:016X}")

    # 0x60 SDS
    print("\n=== SDS 0x60 ===")
    body_0x60 = build_live_senddevicestatus(usb, variant=0x02)
    q_0x60 = bytes([0x40, 0x20]) + build_credential_block(creds.name)
    wire_0x60 = build_request(q_0x60, body_0x60, SVC_MARKET, code=creds.code, secret=creds.secret)
    r = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire_0x60, headers=hdr)
    print(f"  {r.status_code} ({len(r.content)}B)")

    # 0x80 delegated (41B query)
    print("\n=== SDS 0x80 (41B query) ===")
    name3 = build_delegation_name3(hu_creds.code, creds.code)
    body_d1 = build_live_senddevicestatus(usb, variant=0x02)
    wire_d1 = build_delegated_request(
        counter=0x08, body=body_d1, name3=name3,
        hu_code=hu_creds.code, tb_code=creds.code,
        hu_secret=hu_creds.secret, secret=creds.secret,
    )
    r = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire_d1, headers=hdr)
    print(f"  {r.status_code} ({len(r.content)}B)")
    if len(r.content) > 4:
        try:
            dec = parse_response(r.content, creds.secret)
            print(f"  Decrypted ({len(dec)}B): {dec[:32].hex()}")
        except Exception as e:
            print(f"  Decrypt err: {e}")
            print(f"  Raw: {r.content[:64].hex()}")

    # 0x80 delegated (58B envelope)
    print("\n=== SDS 0x80 (58B envelope) ===")
    ts = int(time.time()) & 0xFFFFFFFF
    hmac_data = b"\xC4" + struct.pack(">Q", hu_creds.code) + struct.pack(">Q", creds.code) + struct.pack(">I", ts)
    hmac_result = hmac_mod.new(struct.pack(">Q", hu_creds.secret), hmac_data, hashlib.md5).digest()
    cred_block_tb = build_credential_block(creds.name)
    query_58 = (
        bytes([0x48, 0x80])
        + cred_block_tb[1:]  # 16B XOR-encoded name
        + b"\x80" + name3
        + struct.pack(">I", ts) + b"\x30\x10" + hmac_result
    )
    body_d2 = build_live_senddevicestatus(usb, variant=0x03)
    sid = os.urandom(1)[0] | 0x01
    header = struct.pack(">BBBB Q B HB", 0x01, 0xC2, 0xC2, 0x30, creds.code, SVC_MARKET, 0x0000, sid)
    wire_d2 = header + snakeoil(query_58, creds.secret) + snakeoil(body_d2, creds.secret)
    r = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire_d2, headers=hdr)
    print(f"  {r.status_code} ({len(r.content)}B)")
    if len(r.content) > 4:
        try:
            dec = parse_response(r.content, creds.secret)
            print(f"  Decrypted ({len(dec)}B): {dec[:32].hex()}")
        except Exception as e:
            print(f"  Decrypt err: {e}")
            print(f"  Raw: {r.content[:64].hex()}")


    # Dynamic delegated (new build_dynamic_request)
    print("\n=== SDS Dynamic (build_dynamic_request) ===")
    from medianav_toolbox.protocol import build_dynamic_request
    body_dyn = build_live_senddevicestatus(usb, variant=0x03)
    SESSION_KEY = 0x000ACAB6C9FB66F8
    wire_dyn = build_dynamic_request(
        counter=0, body=body_dyn,
        hu_code=hu_creds.code, tb_code=creds.code,
        hu_secret=hu_creds.secret, session_key=SESSION_KEY,
    )
    r = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire_dyn, headers=hdr)
    print(f"  {r.status_code} ({len(r.content)}B)")
    if len(r.content) > 4:
        try:
            dec = parse_response(r.content, creds.secret)
            print(f"  Decrypted ({len(dec)}B): {dec[:32].hex()}")
        except Exception as e:
            print(f"  Decrypt err: {e}")
            print(f"  Raw: {r.content[:64].hex()}")


if __name__ == "__main__":
    main()
