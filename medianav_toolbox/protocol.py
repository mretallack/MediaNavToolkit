"""Wire protocol envelope for the NaviExtras binary API.

Delegated wire format (verified run25+run32, see docs/chain-encryption.md):
  [16B header][1B prefix][snakeoil(query, session_key)][snakeoil(body, session_key)]

Each snakeoil() call resets the PRNG from session_key independently.
The body is standard plaintext format (NOT bitstream-encoded).

Standard wire format (login, fingerprint, etc.):
  [16B header][snakeoil(query, q_key)][snakeoil(body, b_key)]

Header (16 bytes, unencrypted):
  [01] [C2 C2] [mode] [key 8B BE] [svc_minor] [00 00] [nonce]

Key functions:
  build_request()          — standard requests (login, fingerprint, register)
  build_dynamic_request()  — delegated senddevicestatus (no captured data needed)
  build_0x68_request()     — LEGACY: replay with captured chain body
  build_delegated_request() — LEGACY: uses wrong encryption model
"""

import os
import struct

from medianav_toolbox.crypto import snakeoil

# Auth modes
AUTH_RANDOM = 0x20  # pre-registration, random key
AUTH_DEVICE = 0x30  # post-registration, Code in header

# Service minor versions
SVC_INDEX = 0x01
SVC_REGISTER = 0x0E
SVC_MARKET = 0x19

# Response mode bytes
RESP_RANDOM = 0x6B
RESP_DEVICE = 0xBC


def _generate_random_seed() -> int:
    return struct.unpack(">Q", os.urandom(8))[0]


def build_request(
    query: bytes,
    body: bytes,
    service_minor: int,
    seed: int | None = None,
    code: int | None = None,
    secret: int | None = None,
    session_id: int | None = None,
) -> bytes:
    """Build a complete wire request: header + encrypted query + encrypted body.

    Query and body are encrypted as separate SnakeOil streams.

    RANDOM mode: both encrypted with the random seed.
    DEVICE mode: query encrypted with Code, body encrypted with Secret.

    Args:
        query: counter + flags [+ credential_block] (2 or 19 bytes)
        body: igo-binary request body (may be empty)
        service_minor: SVC_INDEX, SVC_REGISTER, or SVC_MARKET
        seed: PRNG seed for RANDOM mode (auto-generated if None)
        code: Credentials.Code for DEVICE mode
        secret: Credentials.Secret for DEVICE mode
        session_id: per-session random byte for header byte 15 (auto-generated if None)

    Returns:
        Complete wire bytes ready to send
    """
    if code is not None and secret is not None:
        auth_mode = AUTH_DEVICE
        header_key = code
        q_seed = code
        b_seed = secret
    else:
        auth_mode = AUTH_RANDOM
        s = seed if seed is not None else _generate_random_seed()
        header_key = s
        q_seed = s
        b_seed = s

    sid = session_id if session_id is not None else (os.urandom(1)[0] | 0x01)

    header = struct.pack(
        ">BBBB Q B HB",
        0x01,
        0xC2,
        0xC2,
        auth_mode,
        header_key,
        service_minor,
        0x0000,
        sid,
    )

    encrypted_query = snakeoil(query, q_seed)
    encrypted_body = snakeoil(body, b_seed) if body else b""
    return header + encrypted_query + encrypted_body


def build_0x68_request(
    counter: int,
    tb_name: bytes,
    hu_code: int,
    tb_code: int,
    hu_secret: int,
    chain_body: bytes,
    extra_6: bytes,
    code: int,
    service_minor: int = SVC_MARKET,
    session_id: int | None = None,
) -> bytes:
    """Build a complete 0x68 wire request.

    The ENTIRE payload (query + chain_body) is encrypted as ONE continuous
    SnakeOil stream with tb_code. NOT split into separate segments.

    Wire format (from SSL_write capture run25):
      [16B header, key=tb_code]
      [SnakeOil(payload, tb_code)]
        payload = [counter][0x68][D8+Name₃_XOR(17B)][extra_6(6B)][chain_body]

    The chain_body is the igo-binary serialized body with field-level chain
    encryption applied. The extra_6 bytes must be consistent with the chain_body
    (server validates this).

    Args:
        counter: request sequence counter byte
        tb_name: 16-byte toolbox credential Name (for 0x28 variant)
        hu_code: head unit Code (uint64)
        tb_code: toolbox Code (uint64)
        hu_secret: head unit Secret (uint64)
        chain_body: pre-encrypted body (from chain encryption or captured data)
        extra_6: the 6 extra bytes that match the chain_body
        code: tb_code for encryption (uint64)
        service_minor: service version byte
        session_id: header nonce byte (auto-generated if None)

    Returns:
        Complete wire bytes ready to send
    """
    from medianav_toolbox.igo_serializer import (
        build_credential_block,
        build_delegation_name3,
    )

    sid = session_id if session_id is not None else (os.urandom(1)[0] | 0x01)

    header = struct.pack(
        ">BBBB Q B HB",
        0x01,
        0xC2,
        0xC2,
        AUTH_DEVICE,
        code,
        service_minor,
        0x0000,
        sid,
    )

    # Build Name₃ credential block for 0x68
    name3 = build_delegation_name3(hu_code, tb_code)
    cred_block = build_credential_block(name3[:16])

    # Build payload: query + chain_body, encrypted as ONE stream with tb_code
    query = bytes([counter, 0x68]) + cred_block + extra_6
    payload = query + chain_body
    encrypted_payload = snakeoil(payload, code)

    return header + encrypted_payload


def build_delegated_request(
    counter: int,
    body: bytes,
    name3: bytes,
    hu_code: int,
    tb_code: int,
    hu_secret: int,
    secret: int,
    service_minor: int = SVC_MARKET,
    session_id: int | None = None,
    timestamp: int | None = None,
) -> bytes:
    """Build a delegated wire request using the 0x80 query format.

    Wire format:
      [16B header, key=tb_code]
      [SnakeOil(query + body, tb_code)]  ← ONE continuous stream, no separator

    Query (41B) = [counter][0x80][Name₃(17B)][ts(4B)][0x30][0x10][HMAC(16B)]
    Separator (1B) = session nonce (same as header byte 15)
    Body (var) = standard plaintext body

    The entire encrypted payload is ONE continuous SnakeOil stream using
    the key from the header (tb_code). NOT separate streams.
    """
    import hashlib
    import hmac as hmac_mod
    import time

    ts = timestamp if timestamp is not None else int(time.time()) & 0xFFFFFFFF
    hmac_data = (
        b"\xc4" + struct.pack(">Q", hu_code) + struct.pack(">Q", tb_code) + struct.pack(">I", ts)
    )
    hmac_key = struct.pack(">Q", hu_secret)
    hmac_result = hmac_mod.new(hmac_key, hmac_data, hashlib.md5).digest()

    query = bytes([counter, 0x80]) + name3 + struct.pack(">I", ts) + b"\x30\x10" + hmac_result

    sid = session_id if session_id is not None else (os.urandom(1)[0] | 0x01)
    header = struct.pack(
        ">BBBB Q B HB",
        0x01,
        0xC2,
        0xC2,
        AUTH_DEVICE,
        tb_code,
        service_minor,
        0x0000,
        sid,
    )

    # One continuous stream: query + body
    payload = query + body
    return header + snakeoil(payload, tb_code)


def build_dynamic_request(
    counter: int,
    body: bytes,
    hu_code: int,
    tb_code: int,
    hu_secret: int,
    session_key: int,
    tb_name: bytes | None = None,
    service_minor: int = SVC_MARKET,
    session_id: int | None = None,
    timestamp: int | None = None,
) -> bytes:
    """Build a dynamic delegated wire request (no captured data needed).

    Correct wire format (verified against run25+run32 SnakeOil logs):
      [16B header]
      [1B prefix = snakeoil(0xE9, session_key)]
      [snakeoil(query, session_key)]
      [snakeoil(body, session_key)]

    Each snakeoil() call resets the PRNG from session_key.

    Query (41B without name, 58B with name):
      [flags(1B)][0x80]
      [optional: tb_name(16B) + 0x80]
      [C4 + hu_code(8B) + tb_code(8B) + timestamp(4B)]
      [0x30][0x10]
      [HMAC-MD5(hu_secret_BE, credential_data)(16B)]

    Args:
        counter: request sequence counter (0-based, used in flags byte)
        body: plaintext body (standard format, e.g. from build_senddevicestatus_body)
        hu_code: head unit Code from delegator response
        tb_code: toolbox Code from registration
        hu_secret: head unit Secret from delegator response
        session_key: SnakeOil key = creds.secret (toolbox Secret from registration)
        tb_name: 16-byte toolbox credential name (included if not None)
        service_minor: service version byte
        session_id: header nonce byte (auto-generated if None)
        timestamp: Unix timestamp (auto-generated if None)
    """
    import hashlib
    import hmac as hmac_mod
    import time

    ts = timestamp if timestamp is not None else int(time.time()) & 0xFFFFFFFF

    # Credential encoding (21B)
    cred_data = (
        b"\xc4" + struct.pack(">Q", hu_code) + struct.pack(">Q", tb_code) + struct.pack(">I", ts)
    )

    # HMAC-MD5(hu_secret_BE, credential_data)
    hmac_key = struct.pack(">Q", hu_secret)
    hmac_result = hmac_mod.new(hmac_key, cred_data, hashlib.md5).digest()

    # Flags byte: bit 3 always set, bit 6 = name present
    flags = 0x08
    if tb_name is not None:
        flags |= 0x40

    # Build query
    parts = [bytes([flags, 0x80])]
    if tb_name is not None:
        parts.append(tb_name[:16])
        parts.append(b"\x80")
    parts.append(cred_data)
    parts.append(b"\x30\x10")
    parts.append(hmac_result)
    query = b"".join(parts)

    # Header
    sid = session_id if session_id is not None else (os.urandom(1)[0] | 0x01)
    header = struct.pack(
        ">BBBB Q B HB",
        0x01,
        0xC2,
        0xC2,
        AUTH_DEVICE,
        tb_code,
        service_minor,
        0x0000,
        sid,
    )

    # Wire: header + prefix + snakeoil(query) + snakeoil(body)
    # Each snakeoil call resets the PRNG independently
    prefix = snakeoil(b"\xe9", session_key)
    encrypted_query = snakeoil(query, session_key)
    encrypted_body = snakeoil(body, session_key)

    return header + prefix + encrypted_query + encrypted_body


def parse_response(data: bytes, seed: int) -> bytes:
    """Parse and decrypt a wire response.

    For RANDOM mode: seed = same random key used in the request.
    For DEVICE mode: seed = Credentials.Secret.

    Args:
        data: raw response bytes (4-byte header + encrypted payload)
        seed: PRNG seed for decryption

    Returns:
        Decrypted igo-binary payload

    Raises:
        ValueError: if response header is malformed
    """
    if len(data) < 4:
        raise ValueError(f"Response too short: {len(data)} bytes")
    if data[0] != 0x01 or data[1] != 0x00 or data[2] != 0xC2:
        raise ValueError(f"Bad response header: {data[:4].hex()}")
    return snakeoil(data[4:], seed)
