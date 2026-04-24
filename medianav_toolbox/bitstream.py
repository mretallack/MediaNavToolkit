"""igo-binary bitstream writer.

Implements the bit-level encoding used by nngine.dll's serializer.
Verified against Unicorn traces of the credential serializer.

Encoding rules (all confirmed):
- Bits are packed MSB-first into bytes (bit 7 of each byte is written first)
- Presence bits: 1 bit per field (1=present, 0=absent)
- Strings: low nibble of each ASCII byte, 4 bits per char, MSB-first
- Integers: variable bit width from type descriptor, MSB-first
- Raw bytes: 8 bits per byte, MSB-first (used for codes, HMACs)

Ref: docs/serializer.md
"""

import struct


class BitStream:
    """MSB-first bitstream writer matching nngine.dll's format."""

    def __init__(self):
        self._bytes = bytearray()
        self._bit_pos = 0  # next bit to write (0 = MSB of current byte)

    def write_bit(self, value: int) -> None:
        """Write a single bit (0 or 1). MSB-first within each byte."""
        byte_idx = self._bit_pos // 8
        bit_idx = 7 - (self._bit_pos % 8)  # MSB first

        # Extend buffer if needed
        while byte_idx >= len(self._bytes):
            self._bytes.append(0)

        if value & 1:
            self._bytes[byte_idx] |= 1 << bit_idx

        self._bit_pos += 1

    def write_bits(self, value: int, num_bits: int) -> None:
        """Write N bits of value, MSB-first."""
        for i in range(num_bits - 1, -1, -1):
            self.write_bit((value >> i) & 1)

    def write_byte(self, value: int) -> None:
        """Write 8 bits (one byte)."""
        self.write_bits(value & 0xFF, 8)

    def write_bytes(self, data: bytes) -> None:
        """Write raw bytes (8 bits each, MSB-first)."""
        for b in data:
            self.write_byte(b)

    def write_string_4bit(self, s: str) -> None:
        """Write string as 4-bit low nibbles, MSB-first per nibble."""
        for c in s:
            self.write_bits(ord(c) & 0xF, 4)

    def write_presence(self, *present: bool) -> None:
        """Write presence bits for fields (1=present, 0=absent)."""
        for p in present:
            self.write_bit(1 if p else 0)

    def pad_to_byte(self) -> None:
        """Pad with zero bits to the next byte boundary."""
        remainder = self._bit_pos % 8
        if remainder > 0:
            for _ in range(8 - remainder):
                self.write_bit(0)

    @property
    def bit_count(self) -> int:
        return self._bit_pos

    def to_bytes(self) -> bytes:
        return bytes(self._bytes)


def test_credential_encoding():
    """Verify the BitStream against the known credential serializer output.

    The credential serializer produces:
      C4 000BF28569BACB7C 000D4EA65D36B98E 69D4BA80

    Encoding:
      write_bit(1)        → hu_code present
      write_bit(1)        → tb_code present
      write_bits(1, 4)    → type indicator = 1
      write_bytes(hu_code) → 8 bytes big-endian
      write_bytes(tb_code) → 8 bytes big-endian
      write_bytes(timestamp) → 4 bytes big-endian
    """
    bs = BitStream()

    # Presence bits
    bs.write_bit(1)  # hu_code present
    bs.write_bit(1)  # tb_code present

    # Type indicator (4 bits)
    bs.write_bits(1, 4)

    # Pad to byte boundary (the credential serializer byte-aligns after the header)
    bs.pad_to_byte()

    # hu_code (8 bytes BE)
    bs.write_bytes(struct.pack(">Q", 0x000BF28569BACB7C))

    # tb_code (8 bytes BE)
    bs.write_bytes(struct.pack(">Q", 0x000D4EA65D36B98E))

    # timestamp (4 bytes BE)
    bs.write_bytes(struct.pack(">I", 0x69D4BA80))

    result = bs.to_bytes()
    expected = bytes.fromhex("c4000bf28569bacb7c000d4ea65d36b98e69d4ba80")

    print(f"Result:   {result.hex()}")
    print(f"Expected: {expected.hex()}")
    print(f"Match: {result == expected}")
    assert result == expected, "Credential encoding mismatch!"
    print("✅ Credential encoding verified!")
    return True


if __name__ == "__main__":
    test_credential_encoding()
