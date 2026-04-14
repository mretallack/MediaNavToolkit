"""Tests for SnakeOil cipher and crypto utilities.

Test vectors extracted from mitmproxy captures of real Toolbox sessions.
"""

from medianav_toolbox.crypto import snakeoil


# --- Test vectors from mitmproxy flows ---

# Boot request payload (RANDOM mode)
BOOT_SEED = 0x00DE87C9A6A5AA6C
BOOT_CIPHERTEXT = bytes.fromhex("6d6b6be1")
BOOT_PLAINTEXT = bytes.fromhex("068a5086")

# Registration response (RANDOM mode) — contains Name, Code, Secret
REG_SEED = 0x00DE87C9A485AA7D
REG_RESP_CIPHERTEXT = bytes.fromhex(
    "eb45c0e5b0fff8505ffb925caf98805b1d66016011875a93"
    "eda3b6b4e486231592f387973a287b520a9f47"
)
REG_RESP_PLAINTEXT = bytes.fromhex(
    "80e0fb86acd6eba8f54a93c4286ce077d06c000d4ea65d36"
    "b98e000acab6c9fb66f8000000012c00000000"
)

# hasActivatableService response (DEVICE mode, seed = Secret)
DEVICE_SEED = 0x000ACAB6C9FB66F8
HAS_ACT_CIPHERTEXT = bytes.fromhex("bc")
HAS_ACT_PLAINTEXT = bytes.fromhex("00")


class TestSnakeOilDecrypt:
    def test_boot_request_decrypt(self):
        assert snakeoil(BOOT_CIPHERTEXT, BOOT_SEED) == BOOT_PLAINTEXT

    def test_registration_response_decrypt(self):
        assert snakeoil(REG_RESP_CIPHERTEXT, REG_SEED) == REG_RESP_PLAINTEXT

    def test_device_mode_decrypt(self):
        assert snakeoil(HAS_ACT_CIPHERTEXT, DEVICE_SEED) == HAS_ACT_PLAINTEXT

    def test_registration_response_contains_credentials(self):
        plain = snakeoil(REG_RESP_CIPHERTEXT, REG_SEED)
        # Name: FB86ACD6EBA8F54A93C4286CE077D06C (as raw bytes in the igo-binary)
        assert bytes.fromhex("fb86acd6eba8f54a93c4286ce077d06c") in plain
        # Code: 0x000D4EA65D36B98E (as BE uint64)
        assert bytes.fromhex("000d4ea65d36b98e") in plain
        # Secret: 0x000ACAB6C9FB66F8 (as BE uint64)
        assert bytes.fromhex("000acab6c9fb66f8") in plain


class TestSnakeOilEncrypt:
    def test_symmetric_roundtrip(self):
        """Encrypt then decrypt returns original."""
        original = b"Hello, SnakeOil!"
        seed = 0xDEADBEEFCAFEBABE
        encrypted = snakeoil(original, seed)
        assert encrypted != original
        assert snakeoil(encrypted, seed) == original

    def test_encrypt_boot_plaintext(self):
        assert snakeoil(BOOT_PLAINTEXT, BOOT_SEED) == BOOT_CIPHERTEXT

    def test_empty_data(self):
        assert snakeoil(b"", 0x1234567890ABCDEF) == b""

    def test_different_seeds_different_output(self):
        data = b"\x00" * 16
        a = snakeoil(data, 0x1111111111111111)
        b = snakeoil(data, 0x2222222222222222)
        assert a != b
