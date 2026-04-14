"""igo-binary serializer for NaviExtras wire protocol requests.

Request payload format (after SnakeOil decryption with Code as seed):

RANDOM mode (pre-registration):
  [counter 1B] [flags 1B] [body...]

DEVICE mode (first request to a service):
  [counter 1B] [flags 1B] [0xD8] [15B encoded Name] [0xD9] [body...]

DEVICE mode (subsequent requests, session established via JSESSIONID):
  [counter 1B] [flags 1B] [body...]

The 17-byte credential block (D8...D9) contains the encoded credential Name.
The encoding is a custom transform in the igo-binary serializer (nngine.dll):
- D8 = open tag, D9 = close tag (paired markers, differ by 1 bit)
- 15 inner bytes encode the 16-byte Name via a position-dependent transform
- NOT XOR, SnakeOil, Blowfish, MD5, or any standard algorithm
- Same Name always produces the same 17 bytes (deterministic, no random component)
- Generated client-side; the block is stable across sessions

For now, use extract_credential_block() to capture the block from a known-good
request, then reuse it. The block only changes if the device is re-registered
with a new Name.

Ref: toolbox.md §2, functions.md (FUN_100b3a60)
"""

import struct


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
        if len(credential_block) != 17 or credential_block[0] != 0xD8 or credential_block[-1] != 0xD9:
            raise ValueError("credential_block must be 17 bytes starting with 0xD8 and ending with 0xD9")
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
