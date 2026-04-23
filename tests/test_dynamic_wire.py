"""Tests verifying the delegated wire format against captured data.

Ground truth: run25 SSL_write captures + SnakeOil/HMAC logs.
"""
import hashlib
import hmac as hmac_mod
import struct
from pathlib import Path

import pytest

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.protocol import build_dynamic_request

# --- Constants from captured sessions ---
HU_CODE = 0x000BF28569BACB7C
HU_SECRET = 0x000EE87C16B1E812
TB_CODE = 0x000D4EA65D36B98E
SESSION_KEY = 0x000ACAB6C9FB66F8

WIRE_FILE = Path("analysis/using-win32/run25_ssl/ssl_write_14_2218.bin")
RUN25_TIMESTAMP = 0x69E8FC9B
RUN25_SESSION_ID = 0x21


class TestWireFormat:
    """Verify the wire format: [16B header][1B prefix][snakeoil(query)][snakeoil(body)]"""

    @pytest.fixture
    def wire(self):
        if not WIRE_FILE.exists():
            pytest.skip("Captured wire data not available")
        return WIRE_FILE.read_bytes()

    def test_wire_size(self, wire):
        assert len(wire) == 2218

    def test_header_structure(self, wire):
        """Header: [01][C2 C2][0x30][tb_code(8B)][svc_minor][00 00][session_id]"""
        assert wire[0] == 0x01
        assert wire[1:3] == b"\xC2\xC2"
        assert wire[3] == 0x30  # AUTH_DEVICE
        assert struct.unpack(">Q", wire[4:12])[0] == TB_CODE
        assert wire[12] == 0x19  # SVC_MARKET
        assert wire[13:15] == b"\x00\x00"
        assert wire[15] == RUN25_SESSION_ID

    def test_prefix_byte(self, wire):
        """Prefix = snakeoil(0xE9, session_key) = 0x55"""
        assert wire[16] == 0x55
        assert snakeoil(b"\xE9", SESSION_KEY) == bytes([0x55])

    def test_query_decryption(self, wire):
        """Query (41B) decrypts to known plaintext with session_key."""
        query_enc = wire[17:58]
        query = snakeoil(query_enc, SESSION_KEY)
        assert len(query) == 41
        assert query[0] == 0x08  # flags: no name
        assert query[1] == 0x80  # format marker

    def test_body_decryption(self, wire):
        """Body decrypts to standard format starting with 0xD8."""
        body_enc = wire[58:]
        body = snakeoil(body_enc, SESSION_KEY)
        assert body[0] == 0xD8
        assert b"DaciaAutomotive" in body

    def test_independent_prng_resets(self, wire):
        """Each snakeoil() call resets the PRNG independently."""
        # Encrypt same plaintext twice — should produce same ciphertext
        plain = b"\x00" * 10
        enc1 = snakeoil(plain, SESSION_KEY)
        enc2 = snakeoil(plain, SESSION_KEY)
        assert enc1 == enc2

    def test_wire_size_decomposition(self, wire):
        """Wire = 16 (header) + 1 (prefix) + 41 (query) + 2160 (body) = 2218"""
        assert len(wire) == 16 + 1 + 41 + 2160


class TestQueryStructure:
    """Verify the 41B query: [flags][0x80][credential(21B)][0x30 0x10][HMAC(16B)]"""

    @pytest.fixture
    def query(self):
        if not WIRE_FILE.exists():
            pytest.skip("Captured wire data not available")
        wire = WIRE_FILE.read_bytes()
        return snakeoil(wire[17:58], SESSION_KEY)

    def test_flags_byte(self, query):
        assert query[0] == 0x08  # no name, bit 3 set

    def test_format_marker(self, query):
        assert query[1] == 0x80

    def test_credential_type(self, query):
        assert query[2] == 0xC4

    def test_credential_hu_code(self, query):
        assert struct.unpack(">Q", query[3:11])[0] == HU_CODE

    def test_credential_tb_code(self, query):
        assert struct.unpack(">Q", query[11:19])[0] == TB_CODE

    def test_credential_timestamp(self, query):
        assert struct.unpack(">I", query[19:23])[0] == RUN25_TIMESTAMP

    def test_hmac_separator(self, query):
        assert query[23:25] == b"\x30\x10"

    def test_hmac_value(self, query):
        """HMAC-MD5(hu_secret_BE, C4 + hu_code_BE + tb_code_BE + ts_BE)"""
        key = struct.pack(">Q", HU_SECRET)
        data = (
            b"\xC4"
            + struct.pack(">Q", HU_CODE)
            + struct.pack(">Q", TB_CODE)
            + struct.pack(">I", RUN25_TIMESTAMP)
        )
        expected = hmac_mod.new(key, data, hashlib.md5).digest()
        assert query[25:41] == expected


class TestHMAC:
    """Verify HMAC computation against captured HMAC log."""

    def test_run25_hmac_1(self):
        """HMAC #1 from hmac_log_run25_ssl.txt"""
        key = bytes.fromhex("000EE87C16B1E812")
        data = bytes.fromhex("C4000BF28569BACB7C000D4EA65D36B98E69E8FC9B")
        expected = bytes.fromhex("D21F264DF9CE422164E1B278ED8DC08B")
        assert hmac_mod.new(key, data, hashlib.md5).digest() == expected

    def test_run25_hmac_2(self):
        """HMAC #2 from hmac_log_run25_ssl.txt (different timestamp)"""
        key = bytes.fromhex("000EE87C16B1E812")
        data = bytes.fromhex("C4000BF28569BACB7C000D4EA65D36B98E69E8FC9D")
        expected = bytes.fromhex("ABA5982D0773B8028BD369373FB55EA2")
        assert hmac_mod.new(key, data, hashlib.md5).digest() == expected

    def test_hmac_key_is_hu_secret_not_hu_code(self):
        """The HMAC key is hu_secret, NOT hu_code."""
        key_correct = struct.pack(">Q", HU_SECRET)
        key_wrong = struct.pack(">Q", HU_CODE)
        data = b"\xC4" + struct.pack(">Q", HU_CODE) + struct.pack(">Q", TB_CODE) + struct.pack(">I", RUN25_TIMESTAMP)

        correct = hmac_mod.new(key_correct, data, hashlib.md5).digest()
        wrong = hmac_mod.new(key_wrong, data, hashlib.md5).digest()
        assert correct != wrong
        # The correct HMAC matches the captured value
        assert correct == bytes.fromhex("D21F264DF9CE422164E1B278ED8DC08B")


class TestBuildDynamicRequest:
    """Verify build_dynamic_request produces byte-exact output."""

    @pytest.fixture
    def wire(self):
        if not WIRE_FILE.exists():
            pytest.skip("Captured wire data not available")
        return WIRE_FILE.read_bytes()

    def test_byte_exact_match(self, wire):
        """build_dynamic_request output matches captured wire byte-for-byte."""
        body = snakeoil(wire[58:], SESSION_KEY)
        result = build_dynamic_request(
            counter=0,
            body=body,
            hu_code=HU_CODE,
            tb_code=TB_CODE,
            hu_secret=HU_SECRET,
            session_key=SESSION_KEY,
            timestamp=RUN25_TIMESTAMP,
            session_id=RUN25_SESSION_ID,
        )
        assert result == wire

    def test_different_timestamp_changes_query(self, wire):
        """Changing the timestamp produces different query bytes."""
        body = snakeoil(wire[58:], SESSION_KEY)
        result = build_dynamic_request(
            counter=0, body=body,
            hu_code=HU_CODE, tb_code=TB_CODE, hu_secret=HU_SECRET,
            session_key=SESSION_KEY, timestamp=RUN25_TIMESTAMP + 1,
            session_id=RUN25_SESSION_ID,
        )
        # Header same, prefix same, query different, body same
        assert result[:17] == wire[:17]  # header + prefix
        assert result[17:58] != wire[17:58]  # query differs
        assert result[58:] == wire[58:]  # body same

    def test_with_tb_name_produces_58b_query(self):
        """Including tb_name produces a 58B query (flags=0x48)."""
        tb_name = b"\x01" * 16
        result = build_dynamic_request(
            counter=0, body=b"\xD8\x00",
            hu_code=HU_CODE, tb_code=TB_CODE, hu_secret=HU_SECRET,
            session_key=SESSION_KEY, tb_name=tb_name,
            timestamp=RUN25_TIMESTAMP, session_id=0x01,
        )
        # 16 header + 1 prefix + 58 query + 2 body = 77
        assert len(result) == 77
        query = snakeoil(result[17:75], SESSION_KEY)
        assert query[0] == 0x48  # flags: name present
        assert len(query) == 58


class TestSessionKey:
    """Verify the session key is creds.secret (toolbox Secret from registration)."""

    CREDS_PATHS = [
        Path("analysis/usb_drive/disk/.medianav_creds.json"),
        Path(".medianav_creds.json"),
    ]

    def test_session_key_is_creds_secret(self):
        """The session key used for SnakeOil encryption IS creds.secret."""
        import json
        for p in self.CREDS_PATHS:
            if p.exists():
                raw = json.loads(p.read_text())
                assert raw["secret"] == SESSION_KEY
                return
        pytest.skip("No credentials file found")

    def test_session_key_encrypts_run25_prefix(self):
        """snakeoil(0xE9, session_key) = 0x55"""
        assert snakeoil(b"\xE9", SESSION_KEY) == b"\x55"

    def test_session_key_decrypts_run25_query(self):
        """Decrypting run25 query with session_key produces valid structure."""
        if not WIRE_FILE.exists():
            pytest.skip("Captured wire data not available")
        wire = WIRE_FILE.read_bytes()
        query = snakeoil(wire[17:58], SESSION_KEY)
        # Must start with flags + 0x80 + C4
        assert query[0] == 0x08
        assert query[1] == 0x80
        assert query[2] == 0xC4

    def test_snakeoil_calls_are_independent(self):
        """Each snakeoil call resets PRNG — verified by run25 SnakeOil log.

        SnakeOil #1 and #3 encrypt the same 18B plaintext with the same key
        and produce identical output, proving PRNG resets per call.
        """
        plain = bytes.fromhex("4080FB86ACD6EBA8F54A93C4286CE077D06C")
        enc = snakeoil(plain, SESSION_KEY)
        expected = bytes.fromhex("FCF5A43A9EE2F2D821246D3C0FD641F0D3AB")
        assert enc == expected
