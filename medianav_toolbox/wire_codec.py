"""Request body encoder for the igo-binary wire format.

The wire format for request bodies (after SnakeOil decryption) is:

  [0x80] [field1] [field2] ...

Field types (from captured traffic analysis):
  String:  [length:1] [string_bytes:length]   — no null terminator, no type tag
  Int32:   [4 bytes big-endian]               — no type tag
  Int64:   [8 bytes big-endian]               — no type tag
  Array:   [count:1] [element1] [element2]... — count then inline elements
  Byte:    [value:1]                          — single raw byte

This is DIFFERENT from the response/Ghidra format (type-tagged, LE integers).
The response decoder in igo_binary.py handles the response format.

Ref: toolbox.md §2 (split encryption), credential_encoding_notes.md
"""

import struct


def encode_string(value: str) -> bytes:
    """Encode a string: [length:1][utf8_bytes]."""
    data = value.encode("utf-8")
    if len(data) > 255:
        raise ValueError(f"String too long for 1-byte length: {len(data)}")
    return bytes([len(data)]) + data


def encode_int32(value: int) -> bytes:
    """Encode a 32-bit integer as 4 bytes big-endian."""
    return struct.pack(">I", value & 0xFFFFFFFF)


def encode_int64(value: int) -> bytes:
    """Encode a 64-bit integer as 8 bytes big-endian."""
    return struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def encode_byte(value: int) -> bytes:
    """Encode a single byte."""
    return bytes([value & 0xFF])


def encode_array(elements: list[bytes]) -> bytes:
    """Encode an array: [count:1][element1][element2]..."""
    return bytes([len(elements)]) + b"".join(elements)


def encode_body(*fields: bytes) -> bytes:
    """Encode a request body: [0x80][fields...]."""
    return b"\x80" + b"".join(fields)


# --- Request body builders ---


def build_boot_body() -> bytes:
    """Build boot request body (IndexArg). Ref: toolbox.md §5.

    The boot body in the captured traffic is just presence bits in the query
    envelope (50 86). The body itself is empty for boot.
    """
    return b""


def build_register_device_body(
    brand_name: str,
    model_name: str,
    swid: str,
    imei: str,
    igo_version: str,
    first_use: int,
    appcid: int,
    uniq_id: str,
) -> bytes:
    """Build RegisterDeviceArg body. Ref: toolbox.md §8.

    From captured register request (RANDOM mode, 131 bytes):
      [0x1d] [0x00]
      [len] "DaciaAutomotive"
      [len] "DaciaToolbox"
      [len] "CK-153G-PF9R-KB6D-W8B0"
      [len] "x51x4Dx30x30x30x30x31"
      [len] "9.35.2.0"
      [int64 BE] first_use (0 = 1970.01.01)
      [int32 BE] appcid
      [0x00]
      [len] "BF7AE9C2D033892B19FB511A6F206AC9"
    """
    return (
        b"\x1d\x00"
        + encode_string(brand_name)
        + encode_string(model_name)
        + encode_string(swid)
        + encode_string(imei)
        + encode_string(igo_version)
        + encode_int64(first_use)
        + encode_int32(appcid)
        + b"\x00"
        + encode_string(uniq_id)
    )


def build_login_body(
    os_name: str,
    os_version: str,
    os_build: str,
    agent_version: str,
    agent_aliases: list[str],
    language: str,
    agent_type: int = 1,
) -> bytes:
    """Build LoginArg body. Ref: toolbox.md §6.

    From captured login request (DEVICE mode, 70 bytes):
      [0x80]
      [len] "Windows 10 (build 19044)"
      [len] "10.0.0"
      [len] "19044"
      [len] "5.28.2026041167"
      [count=1] [len] "Dacia_ULC"
      [len] "en"
      [0x01] agent_type (TB=1)
    """
    alias_data = encode_array([encode_string(a) for a in agent_aliases])
    return encode_body(
        encode_string(os_name),
        encode_string(os_version),
        encode_string(os_build),
        encode_string(agent_version),
        alias_data,
        encode_string(language),
        encode_byte(agent_type),
    )
