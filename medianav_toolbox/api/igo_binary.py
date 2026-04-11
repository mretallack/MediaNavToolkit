"""igo-binary encoder/decoder for NaviExtras API.

Ref: toolbox.md §23 (igo-binary serialization format)

Wire format (boot response):
  Header: 80 80 [type_id: 2 bytes] [header_bytes] 51 80 [count: 1 byte]
  Entry:  [version: 1B] [name_len: 1B] [name] [0x00] [url_len: 1B] [url]
"""

from __future__ import annotations

import struct


def decode_boot_response(data: bytes) -> list[dict]:
    """Decode a v3 boot response into a list of service entries.

    Each entry: {"version": int, "name": str, "location": str}
    """
    if len(data) < 11 or data[0:2] != b"\x80\x80":
        raise ValueError(f"Invalid igo-binary header: {data[:4].hex()}")

    # Find the entry count — it's the byte just before the entries start.
    # Header pattern: 80 80 [type...] 51 80 [count]
    # Scan for 0x51 0x80 pattern
    count_pos = None
    for i in range(2, min(len(data) - 2, 20)):
        if data[i] == 0x51 and data[i + 1] == 0x80:
            count_pos = i + 2
            break

    if count_pos is None:
        raise ValueError("Could not find entry count marker (0x51 0x80)")

    count = data[count_pos]
    pos = count_pos + 1

    entries = []
    for _ in range(count):
        if pos >= len(data):
            break
        version = data[pos]
        pos += 1
        name_len = data[pos]
        pos += 1
        name = data[pos : pos + name_len].decode("ascii")
        pos += name_len
        pos += 1  # skip 0x00 separator
        url_len = data[pos]
        pos += 1
        url = data[pos : pos + url_len].decode("ascii")
        pos += url_len
        entries.append({"version": str(version), "name": name, "location": url})

    return entries


def encode_request_header(type_id: bytes = b"\x69\x8f") -> bytes:
    """Encode the igo-binary magic header."""
    return b"\x80\x80" + type_id


def decode_model_list_response(data: bytes) -> str | None:
    """Decode /get_device_model_list response. Returns version string."""
    # Format: 80 00 [len] [version_string] 00 00
    if len(data) < 4 or data[0] != 0x80:
        return None
    str_len = data[2]
    if len(data) < 3 + str_len:
        return None
    return data[3 : 3 + str_len].decode("ascii")
