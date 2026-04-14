"""Tests for igo-binary serializer.

Test vectors from decrypted mitmproxy captures.
"""

from medianav_toolbox.crypto import snakeoil
from medianav_toolbox.igo_serializer import build_boot_request_body


# Boot request: seed=0x00DE87C9A6A5AA6C, wire payload=6d6b6be1
BOOT_SEED = 0x00DE87C9A6A5AA6C
BOOT_WIRE_PAYLOAD = bytes.fromhex("6d6b6be1")
BOOT_PLAINTEXT = bytes.fromhex("068a5086")


class TestBuildBootRequest:
    def test_length(self):
        body = build_boot_request_body()
        assert len(body) == 4

    def test_matches_capture(self):
        body = build_boot_request_body(counter=0x06)
        assert body == BOOT_PLAINTEXT

    def test_encrypts_to_wire(self):
        body = build_boot_request_body(counter=0x06)
        encrypted = snakeoil(body, BOOT_SEED)
        assert encrypted == BOOT_WIRE_PAYLOAD

    def test_custom_counter(self):
        body = build_boot_request_body(counter=0x10)
        assert body[0] == 0x10
        assert len(body) == 4
