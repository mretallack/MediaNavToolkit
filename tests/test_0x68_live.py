#!/usr/bin/env python3
"""Integration test: send 0x68 senddevicestatus with proper split encryption.

Runs the full session flow (boot → register → login → delegator → senddevicestatus)
but replaces the raw 0x68 replay with a properly encrypted request.

Usage: source .env && python tests/test_0x68_live.py
"""

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

import os
import httpx

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.protocol import SVC_MARKET, build_request, parse_response
from medianav_toolbox.wire_codec import build_login_body, build_sendfingerprint_body

USB_PATH = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))
USERNAME = os.environ.get("NAVIEXTRAS_USER", "")
PASSWORD = os.environ.get("NAVIEXTRAS_PASS", "")
MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"
TOOLBOX_UA = "DaciaAutomotive-Toolbox-2026041167"


def wire_headers(jsessionid=None):
    h = {"User-Agent": TOOLBOX_UA}
    if jsessionid:
        h["Cookie"] = f"JSESSIONID={jsessionid}"
    return h


def main():
    if not USERNAME or not PASSWORD:
        print("ERROR: Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS")
        return

    # Load cached creds
    creds_path = USB_PATH / ".medianav_creds.json"
    hu_creds_path = USB_PATH / ".medianav_hu_dev_creds.json"

    if not creds_path.exists():
        print("ERROR: No cached creds. Run the full session first.")
        return

    creds = json.loads(creds_path.read_text())
    code = creds["code"]
    secret = creds["secret"]
    name = bytes.fromhex(creds["name"])
    print(f"TB creds: code={code}, name={name.hex()[:16]}...")

    hu_creds = None
    if hu_creds_path.exists():
        hu_creds = json.loads(hu_creds_path.read_text())
        print(f"HU creds: code={hu_creds['code']}")

    # Run the session flow
    from medianav_toolbox.session import run_session
    print("\n--- Running full session flow ---")
    result = run_session(USB_PATH, USERNAME, PASSWORD)

    print(f"\nSteps completed: {result['steps']}")
    print(f"Errors: {result['errors']}")

    if "senddevicestatus" in result["steps"]:
        ds_status = result.get("devicestatus_status", "?")
        print(f"senddevicestatus status: {ds_status}")

    # Now test: can we build a fresh 0x68 request and get 200?
    session = result.get("session")
    jsessionid = session.jsessionid if session else None
    if not jsessionid:
        print("\nNo JSESSIONID — can't test 0x68 without session")
        return

    print(f"\nJSESSIONID: {jsessionid[:20]}...")

    # Get the 0x60 body plaintext from captured traffic
    base = Path("analysis/flows_decoded/2026-04-16")
    cap735 = base / "735-senddevicestatus-req.bin"
    cap737 = base / "737-senddevicestatus-req.bin"

    if not cap735.exists() or not cap737.exists():
        print("ERROR: Captured flows not found")
        return

    raw735 = cap735.read_bytes()
    raw737 = cap737.read_bytes()

    # Decrypt the 0x60 body (known good)
    body_plain = snakeoil(raw735[18:], secret)

    # Decrypt the delegation prefix from 0x68 flow
    prefix_plain = snakeoil(raw737[41:58], secret)

    # Get HU credential name from captured query
    query737_dec = snakeoil(raw737[16:41], code)
    hu_name = query737_dec[3:19]
    extra_bytes = query737_dec[19:25]

    print(f"\nBuilding fresh 0x68 request...")
    print(f"  HU Name: {hu_name.hex()}")
    print(f"  Body size: {len(body_plain)} bytes")
    print(f"  Prefix: {prefix_plain.hex()}")

    # Build the 0x68 request with split encryption
    cred_block = build_credential_block(hu_name)
    query = bytes([0xC7, 0x68]) + cred_block + extra_bytes
    encrypted_query = snakeoil(query, code)
    encrypted_prefix = snakeoil(prefix_plain, secret)
    encrypted_body = snakeoil(body_plain, secret)

    header = struct.pack(
        ">BBBB Q B HB",
        0x01, 0xC2, 0xC2, 0x30,
        code, SVC_MARKET, 0x0000, 0x67,
    )

    wire = header + encrypted_query + encrypted_prefix + encrypted_body
    print(f"  Wire size: {len(wire)} bytes")

    # Send it
    with httpx.Client(timeout=30) as client:
        resp = client.post(
            f"{MARKET_BASE}/1/senddevicestatus",
            content=wire,
            headers=wire_headers(jsessionid),
        )
        print(f"\n0x68 senddevicestatus response: {resp.status_code}")

        if resp.status_code == 200:
            dec = snakeoil(resp.content[4:], secret)
            print(f"✓ SUCCESS! Response decrypted ({len(dec)} bytes): {dec[:40].hex()}")
        else:
            print(f"  Response: {resp.content[:100]}")
            # Try decrypting anyway
            if len(resp.content) > 4:
                dec = snakeoil(resp.content[4:], secret)
                print(f"  Decrypted: {dec[:40].hex()}")


if __name__ == "__main__":
    main()
