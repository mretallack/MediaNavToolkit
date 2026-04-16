"""Tests for wire_codec.py — request body encoder.

Test vectors from decrypted mitmproxy captures.
"""

import struct

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.wire_codec import (
    build_login_body,
    build_register_device_body,
    encode_array,
    encode_body,
    encode_byte,
    encode_int32,
    encode_int64,
    encode_string,
)

# Captured login body (decrypted with Secret from DEVICE mode)
LOGIN_BODY = bytes.fromhex(
    "801857696e646f777320313020286275696c64203139303434290631302e302e30"
    "0531393034340f352e32382e32303236303431313637010944616369615f554c43"
    "02656e01"
)

# Captured register body (decrypted with random seed from RANDOM mode)
REGISTER_BODY = bytes.fromhex(
    "1d000f44616369614175746f6d6f746976650c4461636961546f6f6c626f7816"
    "434b2d313533472d504639522d4b4236442d573842301578353178344478333078"
    "333078333078333078333108392e33352e322e300000000000000000420009be00"
    "204246374145394332443033333839324231394642353131413646323036414339"
)


class TestPrimitiveEncoders:
    def test_encode_string(self):
        assert encode_string("en") == b"\x02en"

    def test_encode_string_empty(self):
        assert encode_string("") == b"\x00"

    def test_encode_int32(self):
        assert encode_int32(0x420009BE) == bytes.fromhex("420009be")

    def test_encode_int64_zero(self):
        assert encode_int64(0) == b"\x00" * 8

    def test_encode_byte(self):
        assert encode_byte(1) == b"\x01"

    def test_encode_array_single(self):
        assert encode_array([encode_string("Dacia_ULC")]) == b"\x01\x09Dacia_ULC"

    def test_encode_body(self):
        assert encode_body(b"\x01") == b"\x80\x01"


class TestBuildLoginBody:
    def test_matches_capture(self):
        body = build_login_body(
            os_name="Windows 10 (build 19044)",
            os_version="10.0.0",
            os_build="19044",
            agent_version="5.28.2026041167",
            agent_aliases=["Dacia_ULC"],
            language="en",
            agent_type=1,
        )
        assert body == LOGIN_BODY

    def test_starts_with_envelope(self):
        body = build_login_body("OS", "1.0", "1", "1.0", ["A"], "en")
        assert body[0] == 0x80


class TestBuildRegisterDeviceBody:
    def test_matches_capture(self):
        body = build_register_device_body(
            brand_name="DaciaAutomotive",
            model_name="DaciaToolbox",
            swid="CK-153G-PF9R-KB6D-W8B0",
            imei="x51x4Dx30x30x30x30x31",
            igo_version="9.35.2.0",
            first_use=0,
            appcid=0x420009BE,
            uniq_id="BF7AE9C2D033892B19FB511A6F206AC9",
        )
        assert body == REGISTER_BODY

    def test_contains_brand(self):
        body = build_register_device_body("TestBrand", "M", "S", "I", "V", 0, 1, "U")
        assert b"TestBrand" in body
