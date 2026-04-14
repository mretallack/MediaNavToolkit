"""Tests for wire protocol envelope.

Test vectors from mitmproxy captures of real Toolbox sessions.
"""

import struct

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.protocol import (
    AUTH_DEVICE,
    AUTH_RANDOM,
    RESP_DEVICE,
    RESP_RANDOM,
    SVC_INDEX,
    SVC_REGISTER,
    build_request,
    parse_response,
)

# --- Test vectors from mitmproxy ---

# Boot: RANDOM mode, index service
BOOT_SEED = 0x00DE87C9A6A5AA6C
BOOT_PLAINTEXT = bytes.fromhex("068a5086")
BOOT_WIRE = bytes.fromhex(
    "01c2c22000de87c9a6a5aa6c0100003f6d6b6be1"
)

# Registration response: RANDOM mode
REG_SEED = 0x00DE87C9A485AA7D
REG_RESP_WIRE = bytes.fromhex(
    "0100c26beb45c0e5b0fff8505ffb925caf98805b"
    "1d66016011875a93eda3b6b4e486231592f38797"
    "3a287b520a9f47"
)
REG_RESP_PLAINTEXT = bytes.fromhex(
    "80e0fb86acd6eba8f54a93c4286ce077d06c000d"
    "4ea65d36b98e000acab6c9fb66f8000000012c00"
    "000000"
)

# hasActivatableService: DEVICE mode
DEVICE_CODE = 0x000D4EA65D36B98E
DEVICE_SECRET = 0x000ACAB6C9FB66F8
HAS_ACT_RESP_WIRE = bytes.fromhex("0100c2bcbc")
HAS_ACT_RESP_PLAIN = bytes.fromhex("00")


class TestBuildRequest:
    def test_random_mode_header(self):
        req = build_request(BOOT_PLAINTEXT, SVC_INDEX, seed=BOOT_SEED)
        assert req[0] == 0x01
        assert req[1:3] == b"\xc2\xc2"
        assert req[3] == AUTH_RANDOM
        assert struct.unpack(">Q", req[4:12])[0] == BOOT_SEED
        assert req[12] == SVC_INDEX

    def test_random_mode_matches_capture(self):
        req = build_request(BOOT_PLAINTEXT, SVC_INDEX, seed=BOOT_SEED)
        assert req == BOOT_WIRE

    def test_device_mode_header(self):
        req = build_request(b"\x00", SVC_REGISTER, code=DEVICE_CODE, secret=DEVICE_SECRET)
        assert req[3] == AUTH_DEVICE
        assert struct.unpack(">Q", req[4:12])[0] == DEVICE_CODE
        assert req[12] == SVC_REGISTER

    def test_device_mode_encrypts_with_secret(self):
        payload = b"\x00"
        req = build_request(payload, SVC_REGISTER, code=DEVICE_CODE, secret=DEVICE_SECRET)
        encrypted = req[16:]
        decrypted = snakeoil(encrypted, DEVICE_SECRET)
        assert decrypted == payload

    def test_auto_random_seed(self):
        req = build_request(b"\x80\x00", SVC_INDEX)
        assert len(req) == 16 + 2
        assert req[3] == AUTH_RANDOM
        seed = struct.unpack(">Q", req[5:13])[0]
        assert seed != 0  # random, not zero

    def test_header_length_always_16(self):
        req = build_request(b"", SVC_INDEX, seed=1)
        assert len(req) == 16


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
        import pytest
        with pytest.raises(ValueError):
            parse_response(b"\x02\x00\xc2\x00", 0)

    def test_too_short_raises(self):
        import pytest
        with pytest.raises(ValueError):
            parse_response(b"\x01\x00", 0)
