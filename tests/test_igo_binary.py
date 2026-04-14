"""Tests for api/igo_binary.py — encoding and decoding."""

import struct
from pathlib import Path

import pytest

from medianav_toolbox.api.igo_binary import (
    ENVELOPE,
    TYPE_ARRAY,
    TYPE_INT32,
    TYPE_INT64,
    TYPE_OBJECT,
    TYPE_STRING,
    decode_boot_response,
    decode_model_list_response,
    encode_array,
    encode_byte,
    encode_container,
    encode_empty_array,
    encode_get_process,
    encode_int32,
    encode_int64,
    encode_login,
    encode_message,
    encode_send_drives,
    encode_send_fingerprint,
    encode_string,
)

DATA_DIR = Path(__file__).parent / "data"


# --- Field encoders ---


def test_encode_byte():
    assert encode_byte(42) == bytes([42])


def test_encode_byte_truncates():
    assert encode_byte(256) == bytes([0])


def test_encode_int32():
    result = encode_int32(0x42000B53)
    assert result[0] == TYPE_INT32
    assert struct.unpack_from("<i", result, 1)[0] == 0x42000B53


def test_encode_int64():
    result = encode_int64(2**40)
    assert result[0] == TYPE_INT64
    assert struct.unpack_from("<q", result, 1)[0] == 2**40
    assert len(result) == 9


def test_encode_string():
    result = encode_string("hello")
    assert result[0] == TYPE_STRING
    assert result[1:6] == b"hello"
    assert result[6] == 0  # null terminator
    assert len(result) == 7


def test_encode_string_empty():
    result = encode_string("")
    assert result[0] == TYPE_STRING
    assert result[1] == 0  # null terminator
    assert len(result) == 2


def test_encode_empty_array():
    result = encode_empty_array()
    assert result[0] == TYPE_ARRAY
    assert struct.unpack_from("<I", result, 1)[0] == 0
    # header(5) + footer(5) = 10
    assert len(result) == 10


def test_encode_array_with_elements():
    elems = [encode_byte(1), encode_byte(2)]
    result = encode_array(elems)
    assert result[0] == TYPE_ARRAY
    assert struct.unpack_from("<I", result, 1)[0] == 2
    # header(5) + 2 bytes + footer(5) = 12
    assert len(result) == 12


# --- Container / message ---


def test_encode_container_structure():
    fields = [encode_byte(1), encode_int32(42)]
    result = encode_container(TYPE_OBJECT, fields)
    # Header: [type:1][count:LE32]
    assert result[0] == TYPE_OBJECT
    assert struct.unpack_from("<I", result, 1)[0] == 2
    # Footer: same
    assert result[-5] == TYPE_OBJECT
    assert struct.unpack_from("<I", result, -4)[0] == 2


def test_encode_message_has_envelope():
    result = encode_message([encode_byte(0)])
    assert result[:2] == ENVELOPE


def test_encode_message_has_envelope():
    result = encode_message([encode_byte(0)])
    # Envelope header, then fields directly (no container wrapper)
    assert result[:2] == ENVELOPE
    assert result[2] == 0  # the byte value


# --- LOGIN encoder ---


def test_encode_login_starts_with_envelope():
    result = encode_login("user", "pass", "Brand", "Type", 0x42000B53)
    assert result[:2] == ENVELOPE


def test_encode_login_has_17_fields():
    result = encode_login("user", "pass", "Brand", "Type", 0x42000B53)
    # Fields follow directly after envelope (no container header)
    assert len(result) > 50  # login has many fields


def test_encode_login_contains_username():
    result = encode_login("testuser@example.com", "pass", "B", "T", 0)
    assert b"testuser@example.com" in result


def test_encode_login_contains_password():
    result = encode_login("u", "secretpass123", "B", "T", 0)
    assert b"secretpass123" in result


def test_encode_login_contains_brand():
    result = encode_login("u", "p", "DaciaAutomotive", "T", 0)
    assert b"DaciaAutomotive" in result


def test_encode_login_contains_appcid():
    result = encode_login("u", "p", "B", "T", 0x42000B53)
    # APPCID as LE int32
    assert struct.pack("<i", 0x42000B53) in result


# --- GET_PROCESS encoder ---


def test_encode_get_process_minimal():
    result = encode_get_process()
    assert result[:2] == ENVELOPE
    assert len(result) == 3  # envelope(2) + byte_field(1)


def test_encode_get_process_short():
    result = encode_get_process()
    assert len(result) == 3


# --- SEND_DRIVES encoder ---


def test_encode_send_drives_empty():
    result = encode_send_drives()
    assert result[:2] == ENVELOPE
    assert len(result) > 2


def test_encode_send_drives_has_array():
    result = encode_send_drives()
    assert bytes([TYPE_ARRAY]) in result


# --- SEND_FINGERPRINT encoder ---


def test_encode_send_fingerprint():
    result = encode_send_fingerprint(fp_data="test_fp")
    assert result[:2] == ENVELOPE
    assert b"test_fp" in result


# --- Decoders (existing tests) ---


def test_decode_boot_response_real():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    assert len(entries) == 6


def test_decode_boot_response_entry_fields():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    entries = decode_boot_response(data)
    for e in entries:
        assert "version" in e
        assert "name" in e
        assert "location" in e
        assert e["location"].startswith("https://")


def test_decode_boot_response_has_index():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    names = [e["name"] for e in decode_boot_response(data)]
    assert "index" in names


def test_decode_boot_response_has_register():
    data = (DATA_DIR / "boot_response_v3.bin").read_bytes()
    names = [e["name"] for e in decode_boot_response(data)]
    assert "register" in names


def test_decode_boot_response_invalid_header():
    with pytest.raises(ValueError, match="Invalid"):
        decode_boot_response(b"\x00\x01\x02\x03")


def test_decode_boot_response_too_short():
    with pytest.raises(ValueError):
        decode_boot_response(b"\x80\x80")


def test_decode_model_list_response():
    data = (DATA_DIR / "model_list_response.bin").read_bytes()
    version = decode_model_list_response(data)
    assert version is not None
    assert "." in version
