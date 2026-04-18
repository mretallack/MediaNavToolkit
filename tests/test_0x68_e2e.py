#!/usr/bin/env python3
"""End-to-end test: run full session, then send fresh 0x68 with split encryption.

Uses run_session() for the full flow (boot→register→login→delegator→senddevicestatus),
then sends an ADDITIONAL fresh 0x68 request using the established session.
"""

import json
import struct
import sys
import re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

import os
import httpx

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.protocol import SVC_MARKET, build_request, parse_response
from medianav_toolbox.wire_codec import build_senddevicestatus_body
from medianav_toolbox.device import scan_device_files, parse_device_nng
from medianav_toolbox.session import run_session

USB_PATH = Path(os.environ.get("NAVIEXTRAS_USB_PATH", "analysis/usb_drive/disk"))
USERNAME = os.environ.get("NAVIEXTRAS_USER", "")
PASSWORD = os.environ.get("NAVIEXTRAS_PASS", "")
MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"
UA = "DaciaAutomotive-Toolbox-2026041167"


def main():
    if not USERNAME or not PASSWORD:
        print("ERROR: Set NAVIEXTRAS_USER and NAVIEXTRAS_PASS in .env")
        return

    print("=" * 60)
    print("Phase 1: Run full session flow (establishes delegation)")
    print("=" * 60)

    result = run_session(USB_PATH, USERNAME, PASSWORD)
    print(f"Steps: {result['steps']}")
    print(f"Errors: {result['errors']}")
    print(f"senddevicestatus: {result.get('devicestatus_status', 'N/A')}")

    session = result.get("session")
    creds = result.get("device_creds")
    if not session or not session.jsessionid or not creds:
        print("ERROR: Session not established")
        return

    jsid = session.jsessionid
    print(f"JSESSIONID: {jsid[:20]}...")

    print()
    print("=" * 60)
    print("Phase 2: Send FRESH 0x60 senddevicestatus")
    print("=" * 60)

    # Build fresh body from USB drive
    files = scan_device_files(USB_PATH)
    body_0x60 = build_senddevicestatus_body(files=files)
    print(f"Built 0x60 body: {len(body_0x60)} bytes")

    query = bytes([0xC5, 0x60])
    wire = build_request(query=query, body=body_0x60, service_minor=SVC_MARKET,
                         code=creds.code, secret=creds.secret)

    with httpx.Client(timeout=30) as client:
        headers = {"User-Agent": UA, "Cookie": f"JSESSIONID={jsid}"}
        resp = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire, headers=headers)
        print(f"0x60 response: {resp.status_code}")
        if resp.status_code == 200:
            dec = parse_response(resp.content, creds.secret)
            print(f"  ✅ Decrypted: {dec[:20].hex()}")

        print()
        print("=" * 60)
        print("Phase 3: Send FRESH 0x68 senddevicestatus (split encryption)")
        print("=" * 60)

        # Build 0x68 body: modify presence bits, remove UniqId
        body_0x68 = bytearray(body_0x60)
        body_0x68[1] = body_0x68[1] | 0x01   # set delegation bit
        body_0x68[2] = body_0x68[2] & ~0x01   # clear UniqId bit

        # Remove UniqId field (space + 32 hex chars after VIN)
        match = re.search(rb' [0-9A-F]{32}', bytes(body_0x68))
        if match:
            body_0x68 = body_0x68[:match.start()] + body_0x68[match.end():]
            print(f"Removed UniqId ({match.end()-match.start()}B) from body")

        body_0x68 = bytes(body_0x68)
        print(f"Built 0x68 body: {len(body_0x68)} bytes, presence={body_0x68[:4].hex()}")

        # Build delegation prefix (17 bytes)
        # Use a minimal prefix: [0x86] [16 zero bytes]
        # This may not work if the server validates the delegation data
        delegation_prefix = bytes([0x86]) + bytes(16)

        # Build HU credential block for query
        # Try to load HU creds
        hu_path = USB_PATH / ".medianav_hu_dev_creds.json"
        if hu_path.exists():
            hd = json.loads(hu_path.read_text())
            hu_name = bytes.fromhex(hd["name"])
        else:
            # Extract from captured traffic as fallback
            hu_name = bytes.fromhex("ad35bcc12654b893f7b5596a8057190c")

        hu_cred_block = build_credential_block(hu_name)
        query_0x68 = bytes([0xC7, 0x68]) + hu_cred_block + bytes(6)

        # Encrypt: query with code, body split with secret
        encrypted_query = snakeoil(query_0x68, creds.code)
        encrypted_prefix = snakeoil(delegation_prefix, creds.secret)
        encrypted_body = snakeoil(body_0x68, creds.secret)

        header = struct.pack(">BBBB Q B HB",
                             0x01, 0xC2, 0xC2, 0x30,
                             creds.code, SVC_MARKET, 0x0000, 0x67)

        wire_0x68 = header + encrypted_query + encrypted_prefix + encrypted_body
        print(f"Wire size: {len(wire_0x68)} bytes")

        resp2 = client.post(f"{MARKET_BASE}/1/senddevicestatus",
                            content=wire_0x68, headers=headers)
        print(f"0x68 split response: {resp2.status_code}")

        if resp2.status_code == 200:
            dec = parse_response(resp2.content, creds.secret)
            print(f"  ✅ SUCCESS! Decrypted: {dec[:20].hex()}")
        else:
            # Try alternative: send as single stream (prefix + body concatenated)
            print(f"\n--- Alt: single-stream 0x68 ---")
            full_body = delegation_prefix + body_0x68
            wire_alt = build_request(
                query=query_0x68, body=full_body, service_minor=SVC_MARKET,
                code=creds.code, secret=creds.secret, session_id=0x67,
            )
            resp3 = client.post(f"{MARKET_BASE}/1/senddevicestatus",
                                content=wire_alt, headers=headers)
            print(f"Single-stream: {resp3.status_code}")

            # Try: just the body without any prefix
            print(f"\n--- Alt: 0x68 body only (no prefix) ---")
            wire_noprefix = build_request(
                query=query_0x68, body=body_0x68, service_minor=SVC_MARKET,
                code=creds.code, secret=creds.secret, session_id=0x67,
            )
            resp4 = client.post(f"{MARKET_BASE}/1/senddevicestatus",
                                content=wire_noprefix, headers=headers)
            print(f"No-prefix: {resp4.status_code}")

            # Try: original 0x60 body (unmodified) with 0x68 query
            print(f"\n--- Alt: 0x60 body with 0x68 query ---")
            wire_60body = build_request(
                query=query_0x68, body=body_0x60, service_minor=SVC_MARKET,
                code=creds.code, secret=creds.secret, session_id=0x67,
            )
            resp5 = client.post(f"{MARKET_BASE}/1/senddevicestatus",
                                content=wire_60body, headers=headers)
            print(f"0x60-body+0x68-query: {resp5.status_code}")
            if resp5.status_code == 200:
                dec = parse_response(resp5.content, creds.secret)
                print(f"  ✅ SUCCESS! Decrypted: {dec[:20].hex()}")

    print(f"\n{'=' * 60}")
    print("DONE")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
