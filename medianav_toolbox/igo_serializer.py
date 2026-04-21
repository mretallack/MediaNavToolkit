"""igo-binary serializer for NaviExtras wire protocol requests.

Request payload format (after SnakeOil decryption with Code as seed):

RANDOM mode (pre-registration):
  [counter 1B] [flags 1B] [body...]

DEVICE mode (first request to a service):
  [counter 1B] [flags 1B] [0xD8] [15B encoded Name] [0xD9] [body...]

DEVICE mode (subsequent requests, session established via JSESSIONID):
  [counter 1B] [flags 1B] [body...]

The 17-byte credential block (D8...D9) contains the encoded credential Name.
The encoding is: 0xD8 || (Name XOR IGO_CREDENTIAL_KEY).
The 16-byte XOR key was extracted by comparing known Name/credential pairs
across multiple captured sessions.

Ref: toolbox.md §2, functions.md (FUN_100b3a60)
"""

import hashlib
import hmac
import struct
import time

IGO_CREDENTIAL_KEY = bytes.fromhex("6935b733a33d02588bb55424260a2fb5")


def build_delegation_name3(hu_code: int, tb_code: int) -> bytes:
    """Build the 16-byte Name₃ for delegated (0x08-flag) requests.

    Name₃ = 0xC4 || hu_code(8 bytes BE) || tb_code(first 7 bytes BE)

    Args:
        hu_code: head unit Code from delegator response
        tb_code: toolbox Code from registration response

    Returns:
        16-byte Name₃
    """
    return b"\xc4" + struct.pack(">Q", hu_code) + struct.pack(">Q", tb_code)[:7]


def _serialize_credential_binary(hu_code: int, tb_code: int, timestamp: int) -> bytes:
    """Serialize a delegation credential in igo-binary format.

    Format: [presence 1B] [hu_code 8B BE] [tb_code 8B BE] [timestamp 4B BE]

    The presence byte encodes the credential type (1) in bits 2-5,
    plus flags for tb_code (bit 7) and timestamp (bit 6) presence.

    Args:
        hu_code: head unit Code
        tb_code: toolbox Code
        timestamp: internal timestamp (Unix seconds)

    Returns:
        21-byte binary serialized credential
    """
    presence = 0xC4  # type=1, tb_code present, timestamp present
    return (
        bytes([presence])
        + struct.pack(">Q", hu_code)
        + struct.pack(">Q", tb_code)
        + struct.pack(">I", timestamp)
    )


def build_delegation_prefix(hu_code: int, tb_code: int, hu_secret: int) -> bytes:
    """Build the 17-byte delegation prefix for 0x68 request bodies.

    prefix = 0x86 || HMAC-MD5(hu_secret_BE, serialized_credential)

    The serialized credential is the igo-binary format:
    [0xC4][hu_code 8B BE][tb_code 8B BE][timestamp 4B BE]

    Confirmed by Win32 debugger capture (2026-04-20): the DLL produces
    exactly this 21-byte format. The HMAC output goes into the prefix,
    NOT into Name₃ (which is the first 16 bytes XOR-encoded).

    Args:
        hu_code: head unit Code from delegator response
        tb_code: toolbox Code from registration response
        hu_secret: head unit Secret from delegator response

    Returns:
        17-byte delegation prefix
    """
    timestamp = int(time.time()) & 0xFFFFFFFF
    data = _serialize_credential_binary(hu_code, tb_code, timestamp)
    key = struct.pack(">Q", hu_secret)
    hmac_result = hmac.new(key, data, hashlib.md5).digest()
    return b"\x86" + hmac_result


def build_credential_block(name_bytes: bytes) -> bytes:
    """Build the 17-byte credential block from a 16-byte Name.

    Args:
        name_bytes: 16-byte credential Name (from registration response)

    Returns:
        17-byte credential block: 0xD8 || (Name XOR IGO_CREDENTIAL_KEY)
    """
    if len(name_bytes) != 16:
        raise ValueError(f"Name must be 16 bytes, got {len(name_bytes)}")
    return b"\xd8" + bytes(a ^ b for a, b in zip(name_bytes, IGO_CREDENTIAL_KEY))


def build_boot_request_body(counter: int = 0x06, country: int = 0) -> bytes:
    """Build igo-binary body for a boot (IndexArg) request.

    RANDOM mode, 4 bytes: [counter] [0x8A] [0x50] [0x86]
    """
    return bytes([counter, 0x8A, 0x50, 0x86])


def build_empty_device_request(
    counter: int,
    credential_block: bytes | None = None,
) -> bytes:
    """Build igo-binary body for an empty DEVICE mode request.

    Used for: HasActivatableServiceArg, GetProcessArg, GetLicenseInfoArg.

    Args:
        counter: request sequence counter
        credential_block: 17-byte D8...D9 block (omit for subsequent requests with JSESSIONID)

    Returns:
        igo-binary payload (before SnakeOil encryption with Code)
    """
    if credential_block is not None:
        if (
            len(credential_block) != 17
            or credential_block[0] != 0xD8
            or credential_block[-1] != 0xD9
        ):
            raise ValueError(
                "credential_block must be 17 bytes starting with 0xD8 and ending with 0xD9"
            )
        return bytes([counter, 0x20]) + credential_block
    return bytes([counter, 0x20])


def extract_credential_block(decrypted_payload: bytes) -> bytes | None:
    """Extract the 17-byte credential block from a decrypted DEVICE mode request.

    Useful for capturing the credential block from a known-good request
    to replay in new requests.

    Args:
        decrypted_payload: decrypted request payload (after SnakeOil with Code)

    Returns:
        17-byte credential block (D8...D9), or None if not present
    """
    if len(decrypted_payload) >= 19 and decrypted_payload[2] == 0xD8:
        block = decrypted_payload[2:19]
        if block[-1] == 0xD9:
            return bytes(block)
    return None
