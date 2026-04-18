"""Wire protocol envelope for the NaviExtras binary API.

Request:  16-byte header + SnakeOil-encrypted query + SnakeOil-encrypted body
Response:  4-byte header + SnakeOil-encrypted igo-binary payload

Query and body are encrypted as SEPARATE SnakeOil streams:
  RANDOM mode: both use the random seed (fresh PRNG state each)
  DEVICE mode: query uses Code, body uses Secret

Ref: toolbox.md §2 (wire protocol), credential_encoding_notes.md

Wire layout (DEVICE mode, sub-type 0x30):
  flags=0x20: [16B header] [SnakeOil(19B query, Code)] [SnakeOil(body, Secret)]
  flags=0x60: [16B header] [SnakeOil(2B query, Code)]  [SnakeOil(body, Secret)]
  flags=0x68: [16B header] [SnakeOil(2B query, Code)]  [SnakeOil(body, Secret₃)]
  Secret₃ for 0x68 flows is unknown — currently replayed from captured traffic.
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
