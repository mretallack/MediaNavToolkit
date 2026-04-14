"""Tests for igo-binary serializer.

Test vectors from decrypted mitmproxy captures.
"""

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import (
    build_boot_request_body,
    build_empty_device_request,
    extract_credential_block,
)

# Boot request: seed=0x00DE87C9A6A5AA6C, wire payload=6d6b6be1
BOOT_SEED = 0x00DE87C9A6A5AA6C
BOOT_WIRE_PAYLOAD = bytes.fromhex("6d6b6be1")
BOOT_PLAINTEXT = bytes.fromhex("068a5086")

# DEVICE mode: hasActivatableService (decrypted with Code)
CODE = 0x000D4EA65D36B98E
HAS_ACT_WIRE = bytes.fromhex("01c2c230000d4ea65d36b98e0e00003f70fcf5a43a9ee2f2d821246d3c0fd641f0d3ab")
HAS_ACT_PLAIN = bytes.fromhex("5120d892b31be54895f71218717c48c67dffd9")
CRED_BLOCK = bytes.fromhex("d892b31be54895f71218717c48c67dffd9")


class TestBuildBootRequest:
    def test_matches_capture(self):
        assert build_boot_request_body(counter=0x06) == BOOT_PLAINTEXT

    def test_encrypts_to_wire(self):
        body = build_boot_request_body(counter=0x06)
        assert snakeoil(body, BOOT_SEED) == BOOT_WIRE_PAYLOAD


class TestBuildEmptyDeviceRequest:
    def test_with_credentials(self):
        body = build_empty_device_request(counter=0x51, credential_block=CRED_BLOCK)
        assert body == HAS_ACT_PLAIN

    def test_encrypts_to_wire(self):
        body = build_empty_device_request(counter=0x51, credential_block=CRED_BLOCK)
        encrypted = snakeoil(body, CODE)
        assert encrypted == HAS_ACT_WIRE[16:]  # skip 16-byte header

    def test_without_credentials(self):
        body = build_empty_device_request(counter=0x10)
        assert body == bytes([0x10, 0x20])
        assert len(body) == 2

    def test_bad_credential_block_raises(self):
        import pytest
        with pytest.raises(ValueError):
            build_empty_device_request(counter=1, credential_block=b"\x00" * 17)


class TestExtractCredentialBlock:
    def test_extracts_from_payload(self):
        block = extract_credential_block(HAS_ACT_PLAIN)
        assert block == CRED_BLOCK

    def test_starts_with_d8(self):
        block = extract_credential_block(HAS_ACT_PLAIN)
        assert block[0] == 0xD8
        assert block[-1] == 0xD9

    def test_returns_none_without_credentials(self):
        payload = bytes([0x10, 0x20])  # no credentials
        assert extract_credential_block(payload) is None
