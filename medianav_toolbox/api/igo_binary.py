"""igo-binary encoder/decoder for NaviExtras API.

Ref: toolbox.md §18 (serializer internals), §19 (wire format), §20 (field layouts), §22 (server protocol)

Encoding format (from Ghidra FUN_10204a50 switch, line 458440):
  Boot msg: [0x80 0x80] [container]
  Regular:  [0x80 0x00] [fields...]
  String:   [0x05] [string_data:N] [0x00]  (null-terminated, NO length prefix)
  Int32:    [0x01] [value:LE32]
  Byte:     [value:1]  (just the raw value, no type tag)

Type IDs (from nngine.dll serializer switch cases):
  0x01=int32, 0x03=int32_pair, 0x04=int64,
  0x05=string, 0x11=object, 0x15=embedded_string, 0x17=array
"""

from __future__ import annotations

import struct

# --- Type constants (from Ghidra FUN_10204a50 switch) ---
TYPE_INT32 = 0x01
TYPE_INT32P = 0x03   # int32 pair (8 bytes)
TYPE_INT64 = 0x04
TYPE_STRING = 0x05
TYPE_OBJECT = 0x11
TYPE_ESTRING = 0x15  # embedded string
TYPE_ARRAY = 0x17

ENVELOPE_BOOT = b"\x80\x80"  # boot requests only
ENVELOPE = b"\x80\x00"      # regular requests (market, register, etc.)


# --- Field encoders (from Ghidra FUN_1021d570..FUN_1021d660) ---

def encode_byte(value: int) -> bytes:
    """FUN_1021d570: default case — just the raw value byte, no type tag."""
    return struct.pack("<B", value & 0xFF)


def encode_int32(value: int) -> bytes:
    """FUN_1021d590: case 1 — [0x01][value:LE32]."""
    return struct.pack("<Bi", TYPE_INT32, value)


def encode_int64(value: int) -> bytes:
    """FUN_1021d770: case 4 — [0x04][value:LE64]."""
    return struct.pack("<Bq", TYPE_INT64, value)


def encode_string(value: str) -> bytes:
    """FUN_1021d660: case 5 — [0x05][string_data:N][0x00]. No length prefix."""
    data = value.encode("utf-8")
    return struct.pack("<B", TYPE_STRING) + data + b"\x00"


def encode_array(elements: list[bytes]) -> bytes:
    """Encode an array: [header][elements][footer]."""
    body = b"".join(elements)
    count = len(elements)
    header = struct.pack("<BI", TYPE_ARRAY, count)
    footer = struct.pack("<BI", TYPE_ARRAY, count)
    return header + body + footer


def encode_empty_array() -> bytes:
    """Empty array: [0x17][0:LE32][0x17][0:LE32]."""
    return struct.pack("<BI", TYPE_ARRAY, 0) + struct.pack("<BI", TYPE_ARRAY, 0)


# --- Container / message ---

def encode_container(type_id: int, fields: list[bytes]) -> bytes:
    """Encode a container: [type:1][count:LE32] fields [type:1][count:LE32]."""
    count = len(fields)
    body = b"".join(fields)
    header = struct.pack("<BI", type_id, count)
    footer = struct.pack("<BI", type_id, count)
    return header + body + footer


def encode_message(fields: list[bytes], type_id: int = TYPE_OBJECT) -> bytes:
    """Encode a full igo-binary message: envelope + fields (no container wrapper).
    
    The correct format is [0x80 0x00][field1][field2]... with fields directly
    after the envelope. The container wrapper [type][count]...[type][count]
    is NOT used in the wire format (it crashes the server).
    """
    return ENVELOPE + b"".join(fields)


# --- Market call encoders (toolbox.md §20) ---

def encode_login(
    username: str,
    password: str,
    brand: str,
    device_type: str,
    appcid: int,
    device_id: int = 0,
    version_major: int = 5,
    version_minor: int = 28,
) -> bytes:
    """Encode LOGIN request (76-byte arg, vtable PTR_FUN_102b0334, toolbox.md §20.2).

    17 fields: 5 strings, 5 bytes, 2 int32 (version), 2 int32, 1 empty array.
    """
    fields = [
        encode_byte(0),              # field_1: auth mode flag
        encode_string(username),     # field_2: username
        encode_byte(0),              # field_3
        encode_string(password),     # field_4: password
        encode_byte(0),              # field_5
        encode_string(brand),        # field_6: brand
        encode_byte(0),              # field_7
        encode_string(device_type),  # field_8: device_type
        encode_byte(0),              # field_9
        encode_empty_array(),        # field_10: empty array
        encode_byte(0),              # field_11
        encode_string(""),           # field_12: session token (empty on first login)
        encode_byte(0),              # field_13
        encode_int32(version_major), # field_14: version major
        encode_int32(version_minor), # field_15: version minor
        encode_int32(appcid),        # field_16
        encode_int32(device_id),     # field_17
    ]
    return encode_message(fields)


def encode_get_process(flag: int = 0) -> bytes:
    """Encode GET_PROCESS request (8-byte arg, vtable PTR_FUN_102b044c, toolbox.md §20.1)."""
    return encode_message([encode_byte(flag)])


def encode_send_drives(
    drive_count: int = 0,
    drive_id: int = 0,
    drives: list[bytes] | None = None,
) -> bytes:
    """Encode SEND_DRIVES request (32-byte arg, vtable PTR_FUN_102b03f4, toolbox.md §20.4)."""
    fields = [
        encode_byte(0),
        encode_int32(drive_count),
        encode_int32(drive_id),
        encode_array(drives or []),
        encode_byte(0),
    ]
    return encode_message(fields)


def encode_send_fingerprint(
    fp_type: int = 0,
    fp_subtype: int = 0,
    fp_data: str = "",
    fp_blocks: list[bytes] | None = None,
    fp_meta: list[bytes] | None = None,
    fp_extra: str = "",
) -> bytes:
    """Encode SEND_FINGERPRINT request (76-byte arg, vtable PTR_FUN_102b03bc, toolbox.md §20.3)."""
    fields = [
        encode_byte(0),
        encode_int32(fp_type),
        encode_int32(fp_subtype),
        encode_string(fp_data),
        encode_byte(0),
        encode_array(fp_blocks or []),
        encode_byte(0),
        encode_array(fp_meta or []),
        encode_byte(0),
        encode_string(fp_extra),
        encode_byte(0),
    ]
    return encode_message(fields)


def encode_send_backups(
    backup_id: int = 0,
    backup_type: int = 0,
    backups: list[bytes] | None = None,
) -> bytes:
    """Encode SEND_BACKUPS request (32-byte arg, vtable PTR_FUN_102b0404, toolbox.md §20.5)."""
    fields = [
        encode_byte(0),
        encode_int32(backup_id),
        encode_int32(backup_type),
        encode_array(backups or []),
        encode_byte(0),
    ]
    return encode_message(fields)


def encode_send_error(error_code: int = 0, sub_code: int = 0) -> bytes:
    """Encode SEND_ERROR request (32-byte arg, vtable PTR_FUN_102b0414, toolbox.md §20.6)."""
    sub_fields = [
        encode_byte(0),
        encode_int32(error_code),
        encode_int32(sub_code),
        encode_int32(0),
        encode_int32(0),
    ]
    fields = [
        encode_byte(0),
        encode_container(TYPE_OBJECT, sub_fields),
    ]
    return encode_message(fields)


def encode_send_md5(
    path: str = "",
    md5: str = "",
    extra: str = "",
    count: int = 0,
    flags: int = 0,
) -> bytes:
    """Encode SEND_MD5 request (40-byte arg, vtable PTR_FUN_102b03cc, toolbox.md §20.8)."""
    fields = [
        encode_byte(0),
        encode_string(path),
        encode_byte(0),
        encode_string(md5),
        encode_byte(0),
        encode_int32(count),
        encode_int32(flags),
        encode_string(extra),
        encode_byte(0),
    ]
    return encode_message(fields)


def encode_send_sgn_file_validity(
    path: str = "",
    signature: str = "",
    validity: int = 0,
    code1: int = 0,
    code2: int = 0,
) -> bytes:
    """Encode SEND_SGN_FILE_VALIDITY (36-byte arg, vtable PTR_FUN_102b03d4, toolbox.md §20.11)."""
    fields = [
        encode_byte(0),
        encode_string(path),
        encode_byte(0),
        encode_string(signature),
        encode_byte(0),
        encode_int32(validity),
        encode_int32(code1),
        encode_int32(code2),
    ]
    return encode_message(fields)


# --- Decoders (existing) ---

def decode_boot_response(data: bytes) -> list[dict]:
    """Decode a v3 boot response into a list of service entries."""
    if len(data) < 11 or data[0:2] != b"\x80\x80":
        raise ValueError(f"Invalid igo-binary header: {data[:4].hex()}")

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
        version = data[pos]; pos += 1
        name_len = data[pos]; pos += 1
        name = data[pos:pos + name_len].decode("ascii"); pos += name_len
        pos += 1  # 0x00 separator
        url_len = data[pos]; pos += 1
        url = data[pos:pos + url_len].decode("ascii"); pos += url_len
        entries.append({"version": str(version), "name": name, "location": url})
    return entries


def decode_model_list_response(data: bytes) -> str | None:
    """Decode /get_device_model_list response. Returns version string."""
    if len(data) < 4 or data[0] != 0x80:
        return None
    str_len = data[2]
    if len(data) < 3 + str_len:
        return None
    return data[3:3 + str_len].decode("ascii")
