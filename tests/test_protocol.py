"""Tests for wire protocol envelope with split query/body encryption.

Test vectors from mitmproxy captures of real Toolbox sessions.
"""

import struct

import pytest

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.protocol import (
    AUTH_DEVICE,
    AUTH_RANDOM,
    SVC_INDEX,
    SVC_MARKET,
    SVC_REGISTER,
    build_request,
    parse_response,
)

# --- Test vectors from mitmproxy ---

# Boot: RANDOM mode, index service
BOOT_SEED = 0x00DE87C9A6A5AA6C
BOOT_QUERY = bytes.fromhex("068a5086")  # counter + flags + envelope presence bits
BOOT_BODY = b""  # no request body for boot
BOOT_WIRE = bytes.fromhex("01c2c22000de87c9a6a5aa6c0100003f6d6b6be1")

# Registration: RANDOM mode
REG_SEED = 0x00DE87C9A485AA7D
REG_RESP_WIRE = bytes.fromhex(
    "0100c26beb45c0e5b0fff8505ffb925caf98805b"
    "1d66016011875a93eda3b6b4e486231592f38797"
    "3a287b520a9f47"
)
REG_RESP_PLAINTEXT = bytes.fromhex(
    "80e0fb86acd6eba8f54a93c4286ce077d06c000d" "4ea65d36b98e000acab6c9fb66f8000000012c00" "000000"
)

# DEVICE mode credentials
DEVICE_CODE = 0x000D4EA65D36B98E
DEVICE_SECRET = 0x000ACAB6C9FB66F8

# hasActivatableService: DEVICE mode, empty body
HAS_ACT_QUERY = bytes.fromhex("5120d892b31be54895f71218717c48c67dffd9")
HAS_ACT_BODY = b""
HAS_ACT_RESP_WIRE = bytes.fromhex("0100c2bcbc")
HAS_ACT_RESP_PLAIN = bytes.fromhex("00")

# Login: DEVICE mode, query with credentials, body with igo-binary
LOGIN_QUERY = bytes.fromhex("4f20d892b31be54895f71218717c48c67dffd9")
LOGIN_BODY = bytes.fromhex(
    "801857696e646f777320313020286275696c6420"
    "3139303434290631302e302e300531393034340f"
    "352e32382e32303236303431313637010944616369615f554c4302656e01"
)
LOGIN_WIRE = bytes.fromhex(
    "01c2c230000d4ea65d36b98e1900003f"
    "6efcf5a43a9ee2f2d821246d3c0fd641"
    "f0d3ab3c6d08d55c507607a74ecfc807"
    "92c3f26aabdb9588764eb51e51d16390"
    "02bd6addc87cea7725c6b083f305e6ce"
    "964e9fb4265e3967aeb01debf5e5b270"
    "4256ff9f382f980442"
)


class TestBuildRequest:
    def test_random_mode_header(self):
        req = build_request(BOOT_QUERY, BOOT_BODY, SVC_INDEX, seed=BOOT_SEED)
        assert req[0] == 0x01
        assert req[1:3] == b"\xc2\xc2"
        assert req[3] == AUTH_RANDOM
        assert struct.unpack(">Q", req[4:12])[0] == BOOT_SEED
        assert req[12] == SVC_INDEX
        assert req[15] == 0x3F

    def test_random_mode_boot_matches_capture(self):
        req = build_request(BOOT_QUERY, BOOT_BODY, SVC_INDEX, seed=BOOT_SEED)
        assert req == BOOT_WIRE

    def test_device_mode_header(self):
        req = build_request(
            HAS_ACT_QUERY,
            HAS_ACT_BODY,
            SVC_REGISTER,
            code=DEVICE_CODE,
            secret=DEVICE_SECRET,
        )
        assert req[3] == AUTH_DEVICE
        assert struct.unpack(">Q", req[4:12])[0] == DEVICE_CODE

    def test_device_mode_query_encrypted_with_code(self):
        req = build_request(
            HAS_ACT_QUERY,
            HAS_ACT_BODY,
            SVC_REGISTER,
            code=DEVICE_CODE,
            secret=DEVICE_SECRET,
        )
        encrypted_query = req[16:]
        decrypted = snakeoil(encrypted_query, DEVICE_CODE)
        assert decrypted == HAS_ACT_QUERY

    def test_device_mode_login_matches_capture(self):
        req = build_request(
            LOGIN_QUERY,
            LOGIN_BODY,
            SVC_MARKET,
            code=DEVICE_CODE,
            secret=DEVICE_SECRET,
        )
        assert req == LOGIN_WIRE

    def test_device_mode_body_encrypted_with_secret(self):
        req = build_request(
            LOGIN_QUERY,
            LOGIN_BODY,
            SVC_MARKET,
            code=DEVICE_CODE,
            secret=DEVICE_SECRET,
        )
        # Body starts after header(16) + encrypted_query(19)
        encrypted_body = req[16 + 19 :]
        decrypted = snakeoil(encrypted_body, DEVICE_SECRET)
        assert decrypted == LOGIN_BODY

    def test_random_mode_split_encryption(self):
        """Query and body use same key but separate PRNG streams."""
        req = build_request(BOOT_QUERY, BOOT_BODY, SVC_INDEX, seed=BOOT_SEED)
        enc_q = req[16:]
        assert snakeoil(enc_q, BOOT_SEED) == BOOT_QUERY

    def test_auto_random_seed(self):
        req = build_request(b"\x06\x8a", b"\x50\x86", SVC_INDEX)
        assert len(req) == 16 + 2 + 2
        assert req[3] == AUTH_RANDOM

    def test_empty_body(self):
        req = build_request(
            HAS_ACT_QUERY, b"", SVC_REGISTER, code=DEVICE_CODE, secret=DEVICE_SECRET
        )
        assert len(req) == 16 + len(HAS_ACT_QUERY)


class TestParseResponse:
    def test_random_mode_response(self):
        plain = parse_response(REG_RESP_WIRE, REG_SEED)
        assert plain == REG_RESP_PLAINTEXT

    def test_device_mode_response(self):
        plain = parse_response(HAS_ACT_RESP_WIRE, DEVICE_SECRET)
        assert plain == HAS_ACT_RESP_PLAIN

    def test_response_starts_with_0x80(self):
        plain = parse_response(REG_RESP_WIRE, REG_SEED)
        assert plain[0] == 0x80

    def test_empty_payload(self):
        resp = bytes.fromhex("0100c26b")
        plain = parse_response(resp, 0x1234)
        assert plain == b""

    def test_bad_header_raises(self):
        with pytest.raises(ValueError):
            parse_response(b"\x02\x00\xc2\x00", 0)

    def test_too_short_raises(self):
        with pytest.raises(ValueError):
            parse_response(b"\x01\x00", 0)
