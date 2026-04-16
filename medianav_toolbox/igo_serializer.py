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

import struct

IGO_CREDENTIAL_KEY = bytes.fromhex("6935b733a33d02588bb55424260a2fb5")


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
