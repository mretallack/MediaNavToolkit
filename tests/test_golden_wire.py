"""Golden test: decode a known-good wire message, verify every field, re-encode, compare.

The run25 ssl_write_14_2218.bin returned HTTP 200 from the live server.
If we can decode it, verify all fields, and re-encode it byte-for-byte,
then we can generate new messages with fresh timestamps and be confident
they're correct.
"""

import json
import time
from pathlib import Path

import pytest

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.wire_message import WireMessage

WIRE_FILE = Path("analysis/using-win32/run25_ssl/ssl_write_14_2218.bin")
CREDS_FILES = [
    Path("analysis/usb_drive/disk/.medianav_creds.json"),
    Path(".medianav_creds.json"),
]

# Known values from this device
HU_CODE = 0x000BF28569BACB7C
HU_SECRET = 0x000EE87C16B1E812
TB_CODE = 0x000D4EA65D36B98E


def load_creds():
    for p in CREDS_FILES:
        if p.exists():
            return json.loads(p.read_text())
    pytest.skip("No credentials file")


@pytest.fixture
def golden_wire():
    if not WIRE_FILE.exists():
        pytest.skip("Captured wire data not available")
    return WIRE_FILE.read_bytes()


@pytest.fixture
def creds():
    return load_creds()


@pytest.fixture
def msg(golden_wire, creds):
    return WireMessage.decode(golden_wire, creds["secret"], HU_SECRET)


class TestGoldenDecode:
    """Decode the known-good message and verify every field."""

    def test_header_version(self, msg):
        assert msg.header.version == 0x01

    def test_header_magic(self, msg):
        assert msg.header.magic == b"\xc2\xc2"

    def test_header_auth_mode(self, msg):
        assert msg.header.auth_mode == 0x30

    def test_header_tb_code(self, msg):
        assert msg.header.tb_code == TB_CODE

    def test_header_svc_minor(self, msg):
        assert msg.header.svc_minor == 0x19

    def test_header_session_id(self, msg):
        assert msg.header.session_id == 0x21

    def test_prefix(self, msg):
        assert msg.prefix_plain == 0xE9

    def test_query_flags(self, msg):
        assert msg.query.flags == 0x08

    def test_query_format(self, msg):
        assert msg.query.format == 0x80

    def test_query_no_name(self, msg):
        assert msg.query.tb_name is None

    def test_query_cred_type(self, msg):
        assert msg.query.cred_type == 0xC4

    def test_query_hu_code(self, msg):
        assert msg.query.hu_code == HU_CODE

    def test_query_tb_code(self, msg):
        assert msg.query.tb_code == TB_CODE

    def test_query_timestamp(self, msg):
        assert msg.query.timestamp == 0x69E8FC9B

    def test_query_separator(self, msg):
        assert msg.query.separator == b"\x30\x10"

    def test_query_hmac_valid(self, msg):
        assert msg.query.hmac_valid

    def test_body_marker(self, msg):
        assert msg.body.marker == 0xD8

    def test_body_variant(self, msg):
        assert msg.body.variant == 0x03

    def test_body_bitmask(self, msg):
        assert msg.body.bitmask == b"\x1e\x40"

    def test_body_brand(self, msg):
        assert msg.body.brand_name == "DaciaAutomotive"

    def test_body_model(self, msg):
        assert msg.body.model_name == "DaciaAutomotiveDeviceCY20_ULC4dot5"

    def test_body_swid(self, msg):
        assert msg.body.swid == "CK-A80R-YEC3-MYXL-18LN"

    def test_body_imei(self, msg):
        assert msg.body.imei == "32483158423731362D42323938353431"

    def test_body_version(self, msg):
        assert msg.body.igo_version == "9.12.179.821558"

    def test_body_appcid(self, msg):
        assert msg.body.appcid == 0x42000B53

    def test_body_serial(self, msg):
        assert msg.body.serial == "UU1DJF00869579646"

    def test_body_size(self, msg):
        assert len(msg.body_raw) == 2160


class TestGoldenRoundTrip:
    """Re-encode the decoded message and verify byte-exact match."""

    def test_byte_exact_roundtrip(self, golden_wire, msg):
        """Decode → encode must produce identical wire bytes."""
        re_encoded = msg.encode()
        assert re_encoded == golden_wire

    def test_query_encode_roundtrip(self, msg):
        """Query encode → decode must preserve all fields."""
        encoded = msg.query.encode()
        decoded = msg.query.decode(encoded)
        assert decoded.flags == msg.query.flags
        assert decoded.hu_code == msg.query.hu_code
        assert decoded.tb_code == msg.query.tb_code
        assert decoded.timestamp == msg.query.timestamp
        assert decoded.hmac == msg.query.hmac

    def test_header_encode_roundtrip(self, msg):
        encoded = msg.header.encode()
        decoded = msg.header.decode(encoded)
        assert decoded.tb_code == msg.header.tb_code
        assert decoded.session_id == msg.header.session_id


class TestNewMessage:
    """Generate a fresh message with new timestamp, verify it's structurally valid."""

    def test_fresh_timestamp(self, golden_wire, creds):
        """Change timestamp, recompute HMAC, re-encode — must still decode cleanly."""
        msg = WireMessage.decode(golden_wire, creds["secret"], HU_SECRET)

        # Change timestamp
        msg.query.timestamp = 0x69F00000
        msg.query.recompute_hmac()

        # Re-encode
        new_wire = msg.encode()
        assert len(new_wire) == len(golden_wire)

        # Decode the new wire
        msg2 = WireMessage.decode(new_wire, creds["secret"], HU_SECRET)
        assert msg2.query.timestamp == 0x69F00000
        assert msg2.query.hmac_valid
        assert msg2.body.brand_name == "DaciaAutomotive"

    def test_fresh_body(self, creds):
        """Build a complete message from scratch with a fresh body."""
        usb = Path("/mnt/pen")
        if not (usb / "NaviSync").exists():
            pytest.skip("USB not mounted")

        from medianav_toolbox.device_status import build_live_senddevicestatus

        body = build_live_senddevicestatus(usb, variant=0x03)
        ts = int(time.time()) & 0xFFFFFFFF

        msg = WireMessage()
        msg.session_key = creds["secret"]
        msg.header.tb_code = creds["code"]
        msg.prefix_plain = 0xE9
        msg.query.hu_code = HU_CODE
        msg.query.tb_code = creds["code"]
        msg.query.timestamp = ts
        msg.query.hu_secret = HU_SECRET
        msg.query.recompute_hmac()
        msg.body_raw = body
        msg.body = msg.body.decode(body)

        wire = msg.encode()

        # Verify round-trip
        msg2 = WireMessage.decode(wire, creds["secret"], HU_SECRET)
        assert msg2.query.hmac_valid
        assert msg2.query.timestamp == ts
        assert msg2.body.brand_name == "DaciaAutomotive"
        assert msg2.body.serial == "UU1DJF00869579646"
        assert len(msg2.body_raw) == len(body)
