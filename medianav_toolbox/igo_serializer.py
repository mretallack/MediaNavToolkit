"""igo-binary serializer for NaviExtras wire protocol requests.

The request payload format (after SnakeOil decryption):

RANDOM mode (pre-registration):
  [counter 1B] [flags 1B] [body...]

DEVICE mode (post-registration):
  [counter 1B] [flags 1B] [credentials 17B] [body...]

The credentials block is 17 bytes of encoded Name+Code.
The body encoding varies by request type.

Ref: toolbox.md §2, functions.md (FUN_100b3a60)

STATUS: Request serialization format is partially understood.
The counter, flags, and credential structure are identified.
The body encoding for each request type needs further Ghidra tracing.
For now, we provide builders for the known request types using
captured wire data as reference.
"""

import struct


def build_boot_request_body(counter: int = 0x06, country: int = 0) -> bytes:
    """Build the igo-binary body for a boot (IndexArg) request.

    The boot request is 4 bytes in RANDOM mode:
    [counter] [flags=0x8a] [2 bytes body]

    Args:
        counter: request sequence counter
        country: country code (default 0)

    Returns:
        4-byte igo-binary payload (before SnakeOil encryption)
    """
    # From captured wire data: 06 8a 50 86
    # counter=0x06, flags=0x8a, body=0x5086
    # The body encoding for Country=0 is 0x5086
    # This appears to be a fixed encoding
    return bytes([counter, 0x8A, 0x50, 0x86])


def build_device_request_credentials(
    counter: int,
    flags: int,
    name_bytes: bytes,
    code: int,
) -> bytes:
    """Build the credential prefix for DEVICE mode requests.

    Args:
        counter: request sequence counter
        flags: request flags (0x20 for most, 0x60 for large requests)
        name_bytes: 16-byte credential Name
        code: credential Code as uint64

    Returns:
        19-byte prefix: [counter][flags][17 bytes credentials]
    """
    # The 17-byte credential block is derived from Name (16 bytes) and Code (8 bytes)
    # but encoded in a compact form. From captured data, the same credentials
    # always produce the same 17 bytes: d892b31be54895f71218717c48c67dffd9
    #
    # This encoding needs further reverse engineering.
    # For now, we can't generate it from Name+Code directly.
    raise NotImplementedError(
        "Credential encoding not yet reversed. "
        "Use captured wire data or trace FUN_100b3a60 in Ghidra."
    )
