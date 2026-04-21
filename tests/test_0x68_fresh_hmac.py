#!/usr/bin/env python3
"""Test 0x68 senddevicestatus with freshly computed HMAC prefix.

Key insight: the captured Name₃ (ad35bcc1...) was from the ORIGINAL Toolbox
session using different credentials. Our Python session should compute its OWN
Name₃ HMAC. The serialized format may be correct — we just couldn't verify it
because we compared against the wrong HMAC target.
"""

import hashlib
import hmac
import json
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.protocol import SVC_MARKET, build_request
from medianav_toolbox.session import run_session

MARKET_BASE = "https://dacia-ulc.naviextras.com/rest"


def serialize_credential(hu_code, tb_code, timestamp, presence=0xC4):
    return (
        bytes([presence])
        + struct.pack(">Q", hu_code)
        + struct.pack(">Q", tb_code)
        + struct.pack(">I", timestamp)
    )


def test_0x68_in_session():
    """Run a full session, then try 0x68 with computed HMAC."""
    usb_path = Path("/home/mark/git/MediaNavToolbox/analysis/usb_drive/disk")

    # Run the standard session to get credentials
    result = run_session(usb_path, username="", password="")

    print("Session steps:", result.get("steps", []))
    if result.get("errors"):
        print("Errors:", result["errors"])
        return

    creds = result.get("device_creds")
    if not creds:
        print("No device credentials")
        return

    print(f"\ntb_code:   {creds.code}")
    print(f"tb_secret: {creds.secret}")

    # Get hu_creds from the session - they come from the delegator
    # The session module stores them internally. Let me re-do the delegator call.
    from medianav_toolbox.api.boot import boot
    from medianav_toolbox.api.client import NaviExtrasClient
    from medianav_toolbox.api.register import get_delegator_credentials
    from medianav_toolbox.config import Config
    from medianav_toolbox.device import parse_device_nng

    device = parse_device_nng(usb_path / "NaviSync" / "license" / "device.nng")

    with NaviExtrasClient(Config()) as client:
        endpoints = boot(client)

        # Login
        from medianav_toolbox.session import _login_wire

        session = _login_wire(client, creds)
        print(f"jsessionid: {session.jsessionid[:20]}...")

        # Delegator
        hu_creds = get_delegator_credentials(client, endpoints, creds, appcid=device.appcid)
        print(f"hu_code:   {hu_creds.code}")
        print(f"hu_secret: {hu_creds.secret}")

        # Send 0x60 first (known working)
        base = Path(__file__).parent.parent / "analysis" / "flows_decoded" / "2026-04-16"
        cap735 = base / "735-senddevicestatus-req.bin"
        raw735 = cap735.read_bytes()
        body_plain = snakeoil(raw735[18:], creds.secret)

        wire_0x60 = build_request(
            query=bytes([0xC5, 0x60]),
            body=body_plain,
            service_minor=SVC_MARKET,
            code=creds.code,
            secret=creds.secret,
        )
        hdrs = {
            "User-Agent": "DaciaAutomotive-Toolbox-2026041167",
            "Cookie": f"JSESSIONID={session.jsessionid}",
        }

        resp_0x60 = client.post(
            f"{MARKET_BASE}/1/senddevicestatus", content=wire_0x60, headers=hdrs
        )
        print(f"\n0x60: {resp_0x60.status_code}")

        # Now try 0x68 with different presence bytes
        for pres in [0xC4, 0x44, 0xC0, 0x84, 0x04, 0x40, 0x80]:
            ts = int(time.time()) & 0xFFFFFFFF
            key = struct.pack(">Q", hu_creds.secret)
            data = serialize_credential(hu_creds.code, creds.code, ts, pres)
            name3 = hmac.new(key, data, hashlib.md5).digest()
            prefix = b"\x86" + name3

            cred_block = build_credential_block(name3)
            query = bytes([0xC8, 0x68]) + cred_block + bytes(6)
            encrypted_query = snakeoil(query, creds.code)
            encrypted_prefix = snakeoil(prefix, creds.secret)
            encrypted_body = snakeoil(body_plain, creds.secret)

            header = struct.pack(
                ">BBBB Q B HB", 0x01, 0xC2, 0xC2, 0x30, creds.code, SVC_MARKET, 0x0000, 0x67
            )
            wire = header + encrypted_query + encrypted_prefix + encrypted_body

            resp = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire, headers=hdrs)
            status = "✓ SUCCESS!" if resp.status_code == 200 else ""
            print(f"0x68 pres=0x{pres:02X}: {resp.status_code} {status}")
            if resp.status_code == 200:
                print(f"  Serialized data ({len(data)}B): {data.hex()}")
                print(f"  Name₃: {name3.hex()}")
                break
        else:
            print("\nAll presence bytes returned non-200. Trying without timestamp...")
            # Try 17-byte format: [pres][hu_code][tb_code] (no timestamp)
            for pres in [0x84, 0x04, 0xC0, 0x40]:
                key = struct.pack(">Q", hu_creds.secret)
                data = (
                    bytes([pres]) + struct.pack(">Q", hu_creds.code) + struct.pack(">Q", creds.code)
                )
                name3 = hmac.new(key, data, hashlib.md5).digest()
                prefix = b"\x86" + name3

                cred_block = build_credential_block(name3)
                query = bytes([0xC9, 0x68]) + cred_block + bytes(6)
                encrypted_query = snakeoil(query, creds.code)
                encrypted_prefix = snakeoil(prefix, creds.secret)
                encrypted_body = snakeoil(body_plain, creds.secret)

                header = struct.pack(
                    ">BBBB Q B HB", 0x01, 0xC2, 0xC2, 0x30, creds.code, SVC_MARKET, 0x0000, 0x67
                )
                wire = header + encrypted_query + encrypted_prefix + encrypted_body

                resp = client.post(f"{MARKET_BASE}/1/senddevicestatus", content=wire, headers=hdrs)
                status = "✓ SUCCESS!" if resp.status_code == 200 else ""
                print(f"0x68 pres=0x{pres:02X} (no ts): {resp.status_code} {status}")
                if resp.status_code == 200:
                    break


if __name__ == "__main__":
    test_0x68_in_session()
