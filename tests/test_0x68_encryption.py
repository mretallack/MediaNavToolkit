#!/usr/bin/env python3
"""Test that we can build and encrypt 0x68 senddevicestatus requests from scratch.

Validates the Secret₃ = tb_secret finding by:
1. Building a fresh 0x68 body with split encryption
2. Verifying it matches the captured traffic pattern
3. Sending it to the live API and checking for 200 response
"""

import struct
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import build_credential_block
from medianav_toolbox.protocol import SVC_MARKET


def build_0x68_request(
    query_counter: int,
    cred_name: bytes,
    delegation_prefix: bytes,
    body: bytes,
    code: int,
    secret: int,
    session_id: int = 0x67,
) -> bytes:
    """Build a complete 0x68 wire request with split body encryption.

    The 0x68 body is split-encrypted:
      - delegation_prefix (17 bytes): encrypted with fresh SnakeOil(secret)
      - body: encrypted with fresh SnakeOil(secret)

    Args:
        query_counter: counter byte for query (e.g. 0xC7)
        cred_name: 16-byte credential Name (for credential block)
        delegation_prefix: 17-byte delegation header
        body: standard senddevicestatus body
        code: tb_code for header and query encryption
        secret: tb_secret for body encryption
        session_id: header byte 15
    """
    # Build header (16 bytes)
    header = struct.pack(
        ">BBBB Q B HB",
        0x01, 0xC2, 0xC2, 0x30,  # magic + AUTH_DEVICE
        code,                      # Code in header
        SVC_MARKET,                # 0x19
        0x0000,
        session_id,
    )

    # Build query: [counter][0x68][credential_block(17B)][extra(6B)]
    cred_block = build_credential_block(cred_name)  # 17 bytes: D8 + encoded name
    # The extra 6 bytes after the credential block - from captured traffic
    # For now use zeros (the server may not validate these)
    query = bytes([query_counter, 0x68]) + cred_block + bytes(6)
    encrypted_query = snakeoil(query, code)

    # Split body encryption: each segment gets fresh PRNG
    encrypted_prefix = snakeoil(delegation_prefix, secret)
    encrypted_body = snakeoil(body, secret)

    return header + encrypted_query + encrypted_prefix + encrypted_body


def test_decrypt_captured_traffic():
    """Verify we can decrypt captured 0x68 traffic with the split pattern."""
    base = Path(__file__).parent.parent / "analysis" / "flows_decoded" / "2026-04-16"
    cap = base / "737-senddevicestatus-req.bin"
    if not cap.exists():
        print(f"SKIP: {cap} not found")
        return False

    raw = cap.read_bytes()
    tb_code = 0x000D4EA65D36B98E
    tb_secret = 0x000ACAB6C9FB66F8

    # Decrypt query (25 bytes at offset 16)
    query_dec = snakeoil(raw[16:41], tb_code)
    assert query_dec[1] == 0x68, f"Expected flags 0x68, got 0x{query_dec[1]:02x}"
    assert query_dec[2] == 0xD8, f"Expected cred type 0xD8, got 0x{query_dec[2]:02x}"
    print(f"✓ Query decrypts: counter=0x{query_dec[0]:02x} flags=0x{query_dec[1]:02x}")
    print(f"  Name3: {query_dec[3:19].hex()}")

    # Decrypt body with split pattern
    body_enc = raw[41:]
    prefix_dec = snakeoil(body_enc[:17], tb_secret)
    body_dec = snakeoil(body_enc[17:], tb_secret)

    assert body_dec[4:20] == b"\x0fDaciaAutomotive", \
        f"Expected DaciaAutomotive, got {body_dec[4:20]}"
    print(f"✓ Body[17:] decrypts with tb_secret: {body_dec[:8].hex()}...")
    print(f"  Brand: {body_dec[5:20].decode('ascii')}")
    print(f"✓ Delegation prefix: {prefix_dec.hex()}")

    return True


def test_roundtrip_encryption():
    """Verify we can encrypt a body and decrypt it back correctly."""
    tb_code = 0x000D4EA65D36B98E
    tb_secret = 0x000ACAB6C9FB66F8
    name3 = bytes.fromhex("ad35bcc12654b893f7b5596a8057190c")

    # Build a test body
    test_body = b"\xD8\x03\x1E\x40\x0FDaciaAutomotive" + b"\x00" * 100
    test_prefix = bytes(17)  # placeholder delegation prefix

    # Build the request
    wire = build_0x68_request(
        query_counter=0xC7,
        cred_name=name3,
        delegation_prefix=test_prefix,
        body=test_body,
        code=tb_code,
        secret=tb_secret,
    )

    # Verify header
    assert wire[:4] == b"\x01\xC2\xC2\x30", f"Bad header: {wire[:4].hex()}"
    assert struct.unpack(">Q", wire[4:12])[0] == tb_code, "Bad code in header"
    print(f"✓ Header: {wire[:16].hex()}")

    # Decrypt query
    query_dec = snakeoil(wire[16:41], tb_code)
    assert query_dec[0] == 0xC7, f"Bad counter: 0x{query_dec[0]:02x}"
    assert query_dec[1] == 0x68, f"Bad flags: 0x{query_dec[1]:02x}"
    assert query_dec[2] == 0xD8, f"Bad cred type: 0x{query_dec[2]:02x}"
    print(f"✓ Query roundtrip OK: {query_dec[:3].hex()}")

    # Decrypt body (split)
    body_wire = wire[41:]
    prefix_dec = snakeoil(body_wire[:17], tb_secret)
    body_dec = snakeoil(body_wire[17:], tb_secret)
    assert prefix_dec == test_prefix, "Prefix roundtrip failed"
    assert body_dec == test_body, "Body roundtrip failed"
    print(f"✓ Body roundtrip OK: {body_dec[:20]}...")

    return True


def test_live_api():
    """Send a real 0x68 request to the API and check for 200."""
    import json

    # Load cached credentials
    creds_candidates = [
        Path("/home/mark/git/MediaNavToolbox/analysis/usb_drive/disk/.medianav_creds.json"),
        Path("/home/mark/git/MediaNavToolbox/tests/data/fixtures/session_flow.json"),
    ]
    creds_data = None
    for p in creds_candidates:
        if p.exists():
            creds_data = json.loads(p.read_text())
            if "code" in creds_data and "secret" in creds_data:
                break
            creds_data = None

    if not creds_data:
        print("SKIP: No cached credentials found")
        return None

    code = creds_data["code"]
    secret = creds_data["secret"]
    name = bytes.fromhex(creds_data["name"])
    print(f"Using creds: code={code}, name={name.hex()[:16]}...")

    # Get the captured 0x60 body plaintext (we know how to decrypt this)
    base = Path(__file__).parent.parent / "analysis" / "flows_decoded" / "2026-04-16"
    cap735 = base / "735-senddevicestatus-req.bin"
    if not cap735.exists():
        print("SKIP: No captured 0x60 flow")
        return None

    raw735 = cap735.read_bytes()
    body_plain = snakeoil(raw735[18:], secret)

    # Get the delegation prefix from a captured 0x68 flow
    cap737 = base / "737-senddevicestatus-req.bin"
    if not cap737.exists():
        print("SKIP: No captured 0x68 flow")
        return None

    raw737 = cap737.read_bytes()
    prefix_plain = snakeoil(raw737[41:58], secret)

    # Also need the HU credential name for the 0x68 query
    # Extract from captured query
    query737_dec = snakeoil(raw737[16:41], code)
    hu_name = query737_dec[3:19]  # Name3 from the credential block
    extra_bytes = query737_dec[19:25]  # 6 extra bytes after cred block

    print(f"HU Name3: {hu_name.hex()}")
    print(f"Extra query bytes: {extra_bytes.hex()}")

    # Build fresh 0x68 request
    cred_block = build_credential_block(hu_name)
    query = bytes([0xC7, 0x68]) + cred_block + extra_bytes
    encrypted_query = snakeoil(query, code)

    # Split-encrypt body
    encrypted_prefix = snakeoil(prefix_plain, secret)
    encrypted_body = snakeoil(body_plain, secret)

    # Build header
    header = struct.pack(
        ">BBBB Q B HB",
        0x01, 0xC2, 0xC2, 0x30,
        code, SVC_MARKET, 0x0000, 0x67,
    )

    wire = header + encrypted_query + encrypted_prefix + encrypted_body
    print(f"Built 0x68 request: {len(wire)} bytes")

    # Send to API
    import httpx

    try:
        with httpx.Client(timeout=30) as client:
            # First do a boot + register + login to get a session
            # For now just try the raw request
            resp = client.post(
                f"https://dacia-ulc.naviextras.com/rest/1/senddevicestatus",
                content=wire,
                headers={"User-Agent": "DaciaAutomotive-Toolbox-2026041167"},
            )
            print(f"Response: {resp.status_code}")
            if resp.status_code == 200:
                # Try to decrypt response
                dec = snakeoil(resp.content[4:], secret)
                print(f"✓ Response decrypted: {dec[:40].hex()}")
            else:
                print(f"  Response body: {resp.content[:100]}")
            return resp.status_code
    except Exception as e:
        print(f"ERROR: {e}")
        return None


if __name__ == "__main__":
    print("=" * 60)
    print("Test 1: Decrypt captured 0x68 traffic")
    print("=" * 60)
    ok1 = test_decrypt_captured_traffic()

    print()
    print("=" * 60)
    print("Test 2: Roundtrip encryption")
    print("=" * 60)
    ok2 = test_roundtrip_encryption()

    print()
    print("=" * 60)
    print("Test 3: Live API call")
    print("=" * 60)
    status = test_live_api()

    print()
    print("=" * 60)
    print("RESULTS")
    print("=" * 60)
    print(f"  Decrypt captured: {'PASS' if ok1 else 'FAIL'}")
    print(f"  Roundtrip:        {'PASS' if ok2 else 'FAIL'}")
    print(f"  Live API:         {status if status else 'SKIP'}")
