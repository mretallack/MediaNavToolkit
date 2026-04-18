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
from dataclasses import dataclass


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


def build_get_device_model_list_body(
    models: list[tuple[int, int]],
) -> bytes:
    """Build GetDeviceModelListArg body.

    From captured request (272 bytes):
      [0x00] [count:1] [entry * count]
      Entry: [0x80] [version:4B BE] [id:4B BE]

    Args:
        models: list of (version, model_id) tuples
    """
    entries = b""
    for version, model_id in models:
        entries += b"\x80" + encode_int32(version) + encode_int32(model_id)
    return b"\x00" + encode_byte(len(models)) + entries


def build_get_device_descriptor_list_body(
    device_context_id: int,
    agent_alias: str = "Dacia_ULC",
) -> bytes:
    """Build GetDeviceDescriptorListArg body.

    From captured request (16 bytes):
      [0x80] [device_context_id:4B BE] [0x01] [len] "Dacia_ULC"
    """
    return encode_body(
        encode_int32(device_context_id),
        encode_byte(0x01),
        encode_string(agent_alias),
    )


def _encode_varint(n: int) -> bytes:
    """Encode integer as varint (high bit = continuation, big-endian order)."""
    if n < 0x80:
        return bytes([n])
    # Multi-byte: high bytes first, continuation bit on all but last
    parts = []
    while n >= 0x80:
        parts.append(n & 0x7F)
        n >>= 7
    parts.append(n)
    # Reverse: high bits first, set continuation bit on all but last byte
    result = []
    for i, p in enumerate(reversed(parts)):
        result.append(p | 0x80 if i < len(parts) - 1 else p)
    return bytes(result)


def build_sendfingerprint_body(
    device_context_id: int = 0,
    cache_path: str = "/tmp/medianav_cache",
    total_space: int = 0,
    free_space: int = 0,
    info: str = "0_0",
) -> bytes:
    """Build SendFingerprintArg body.

    Structure (from captured traffic, verified byte-for-byte):
      [int32 BE] DeviceContextId
      [0xC0] flags (Partial=false, Synctool=false)
      [len] "N/A" checksum
      [varint] file_entry_count
      [entries...] — 0x22=directory, 0x28=file
      [0x01 0x00] storage (count=1, readonly=false)
      [len] path [int64] total [int64] free [int64] minfree
      [int32] blocksize [len] mountpath
      [len] info string

    Ref: toolbox.md §12
    """
    dir_entry = (
        b"\x22" + encode_string("0") + encode_string(cache_path) + b"\x00" * 24  # size + ts1 + ts2
    )

    storage = (
        b"\x01\x00"  # count=1, readonly=false
        + encode_string(cache_path)
        + encode_int64(total_space)
        + encode_int64(free_space)
        + encode_int64(0)
        + encode_int32(4096)
        + encode_string("/")
    )

    return (
        encode_int32(device_context_id)
        + b"\xc0"
        + encode_string("N/A")
        + _encode_varint(1)
        + dir_entry
        + storage
        + encode_string(info)
    )


@dataclass
class DeviceFileEntry:
    """A file on the USB drive for senddevicestatus."""

    md5: str  # 32-char hex MD5 of file content (empty for directories)
    filename: str
    mount: str  # "primary"
    path: str  # e.g. "NaviSync/license"
    size: int
    modified_ms: int  # epoch milliseconds
    created_ms: int = 0  # epoch milliseconds (0 = same as modified_ms)


def build_senddevicestatus_body(
    brand_name: str = "DaciaAutomotive",
    model_name: str = "DaciaAutomotiveDeviceCY20_ULC4dot5",
    swid: str = "",
    imei: str = "32483158423731362D42323938353431",
    igo_version: str = "9.12.179.821558",
    first_use_seconds: int = 0,
    appcid: int = 0x42000B53,
    serial: str = "",
    uniq_id: str = "",
    content_version: int = 46475,
    overall_md5: str = "",
    files: list[DeviceFileEntry] | None = None,
) -> bytes:
    """Build SendDeviceStatus request body (flags=0x60).

    Structure (from captured traffic flow 735, flags=0x60):
      [4B bitmask: D8 02 1F 40]
      [str] brand [str] model [str] swid [str] imei [str] igo_version
      [4B BE] first_use_seconds [4B zero] [4B BE] appcid
      [str] serial [str] uniq_id
      [0x00] separator
      [0x01] [2B BE content_version] [2B zero]
      [0x01] [4B zero]
      [0xE0] [str overall_md5]
      [1B file_count]
      [file_entries...]
      [trailer: 0x01 0x00 0x07 "primary" 0x00*20]

    File entry (0xA0):
      [str] md5 [str] filename [str] mount [str] path
      [8B BE] size [8B BE] modified_ms [8B BE] modified_ms

    Directory entry (0x22):
      [str] name [str] mount [str] path
      [8B BE] 0 [8B BE] modified_ms [8B BE] modified_ms

    Ref: toolbox.md §15
    """
    if files is None:
        files = []

    header = b"\xd8\x02\x1f\x40"

    device_info = (
        encode_string(brand_name)
        + encode_string(model_name)
        + encode_string(swid)
        + encode_string(imei)
        + encode_string(igo_version)
        + encode_int32(first_use_seconds)
        + b"\x00\x00\x00\x00"
        + encode_int32(appcid)
        + encode_string(serial)
        + encode_string(uniq_id)
    )

    # Content metadata
    meta = (
        b"\x00"
        + b"\x01"
        + struct.pack("<H", content_version & 0xFFFF)
        + b"\x00\x00"
        + b"\x00\x01\x00\x00\x00\x00"
    )

    # Overall MD5 + file list
    file_list = b"\xe0" + encode_string(overall_md5) if overall_md5 else b""

    # File count + entries
    file_data = bytes([len(files)])
    for f in files:
        ts2 = f.created_ms if f.created_ms else f.modified_ms
        if f.md5:
            # File entry
            file_data += (
                b"\xa0"
                + encode_string(f.md5)
                + encode_string(f.filename)
                + encode_string(f.mount)
                + encode_string(f.path)
                + encode_int64(f.size)
                + encode_int64(f.modified_ms)
                + encode_int64(ts2)
            )
        else:
            # Directory entry
            file_data += (
                b"\x22"
                + encode_string(f.filename)
                + encode_string(f.mount)
                + encode_string(f.path)
                + encode_int64(0)
                + encode_int64(f.modified_ms)
                + encode_int64(ts2)
            )

    # Trailer: mount info
    trailer = b"\x01\x00" + encode_string("primary") + b"\x00" * 20

    return header + device_info + meta + file_list + file_data + trailer
