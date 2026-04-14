"""Wire protocol envelope for the NaviExtras binary API.

Request:  16-byte header + SnakeOil-encrypted igo-binary payload
Response:  4-byte header + SnakeOil-encrypted igo-binary payload

Ref: toolbox.md §2 (wire protocol), functions.md (FUN_100b3a60)
"""

import os
import struct
import time

from medianav_toolbox.crypto import snakeoil

# Auth modes
AUTH_RANDOM = 0x20  # pre-registration, random key
AUTH_DEVICE = 0x30  # post-registration, Code in header / Secret as seed

# Service minor versions
SVC_INDEX = 0x01
SVC_REGISTER = 0x0E
SVC_MARKET = 0x19

# Response mode bytes
RESP_RANDOM = 0x6B
RESP_DEVICE = 0xBC


def _generate_random_seed() -> int:
    """Generate a random uint64 seed using the same xorshift as the Toolbox.

    The Toolbox uses time() with xorshift. We just use os.urandom for better randomness.
    """
    return struct.unpack(">Q", os.urandom(8))[0]


def build_request(
    payload: bytes,
    service_minor: int,
    seed: int | None = None,
    code: int | None = None,
    secret: int | None = None,
) -> bytes:
    """Build a complete wire request: header + encrypted payload.

    For RANDOM mode (pre-registration): pass seed (or omit for auto-generated).
    For DEVICE mode (post-registration): pass code and secret.

    Args:
        payload: igo-binary body to encrypt
        service_minor: SVC_INDEX, SVC_REGISTER, or SVC_MARKET
        seed: PRNG seed for RANDOM mode (auto-generated if None and no code/secret)
        code: Credentials.Code for DEVICE mode header
        secret: Credentials.Secret for DEVICE mode PRNG seed

    Returns:
        Complete wire bytes ready to send
    """
    if code is not None and secret is not None:
        auth_mode = AUTH_DEVICE
        header_key = code
        prng_seed = secret
    else:
        auth_mode = AUTH_RANDOM
        prng_seed = seed if seed is not None else _generate_random_seed()
        header_key = prng_seed

    header = bytearray(16)
    header[0] = 0x01            # version
    header[1] = 0xC2            # envelope marker
    header[2] = 0xC2            # envelope marker
    header[3] = auth_mode       # 0x20 or 0x30
    struct.pack_into(">Q", header, 4, header_key)  # 8-byte key at bytes 4-11
    header[12] = service_minor
    header[13] = 0x00           # padding
    header[14] = 0x00           # padding
    header[15] = 0x3F           # end marker
    header = bytes(header)
    encrypted = snakeoil(payload, prng_seed)
    return header + encrypted


def parse_response(data: bytes, seed: int) -> bytes:
    """Parse and decrypt a wire response.

    For RANDOM mode: seed = same random key used in the request.
    For DEVICE mode: seed = Credentials.Secret (NOT Code).

    Args:
        data: raw response bytes (4-byte header + encrypted payload)
        seed: PRNG seed used for the corresponding request

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
