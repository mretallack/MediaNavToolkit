#!/usr/bin/env python3
"""Try known keys/algorithms on encrypted NNG map files.

Tests:
1. XOR-CBC with .lyc-derived key
2. SnakeOil with magic bytes as seed
3. SnakeOil with tb_secret / hu_secret
4. Blowfish with known DLL key
5. Simple XOR with constant header bytes as key
6. SnakeOil with various seeds from the constant header

Usage:
    python tools/maps/try_lyc_key.py tools/maps/testdata/Vatican_osm.fbl
"""
import math
import struct
import sys
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c > 0)


def has_ascii_strings(data: bytes, min_len: int = 6) -> list[str]:
    """Find ASCII strings in data."""
    strings = []
    current = []
    for b in data:
        if 0x20 <= b < 0x7F:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def xor_cbc_decrypt(data: bytes, key: bytes) -> bytes:
    """XOR-CBC decryption with 16-byte key."""
    block_size = len(key)
    result = bytearray()
    prev = b"\x00" * block_size
    for i in range(0, len(data), block_size):
        block = data[i : i + block_size]
        if len(block) < block_size:
            block = block + b"\x00" * (block_size - len(block))
        decrypted = bytes(b ^ k for b, k in zip(block, key))
        plaintext = bytes(d ^ p for d, p in zip(decrypted, prev))
        result.extend(plaintext[: min(block_size, len(data) - i)])
        prev = block
    return bytes(result)


def snakeoil(data: bytes, seed: int) -> bytes:
    """SnakeOil xorshift128 stream cipher."""
    M = 0xFFFFFFFF
    result = bytearray(len(data))
    eax = seed & M
    esi = (seed >> 32) & M
    for i in range(len(data)):
        edx = (((esi << 21) | (eax >> 11)) ^ esi) & M
        ecx = (((eax << 21) & M) ^ eax) & M
        ecx = (ecx ^ (edx >> 3)) & M
        esi = ((((edx << 4) | (ecx >> 28)) & M) ^ edx) & M
        eax = (((ecx << 4) & M) ^ ecx) & M
        result[i] = data[i] ^ (((esi << 32) | eax) >> 23) & 0xFF
    return bytes(result)


def try_method(name: str, data: bytes, decrypted: bytes):
    ent = shannon_entropy(decrypted)
    strings = has_ascii_strings(decrypted)
    status = "✓ POSSIBLE" if ent < 7.0 else "✗"
    if strings:
        status = f"✓ STRINGS FOUND ({len(strings)})"
    print(f"  {name:<40s} entropy={ent:.3f}  {status}")
    if strings:
        for s in strings[:5]:
            print(f"    → \"{s}\"")
    if ent < 7.5:
        print(f"    First 32B: {decrypted[:32].hex()}")


def main():
    if len(sys.argv) < 2:
        print("Usage: try_lyc_key.py <encrypted_file>")
        sys.exit(1)

    path = Path(sys.argv[1])
    data = path.read_bytes()
    print(f"File: {path.name} ({len(data):,d} bytes)")
    print(f"Original entropy: {shannon_entropy(data):.3f}")
    print(f"Magic: {data[:8].hex()}")
    print()

    # The constant 16-byte header (bytes 0-15, same across all FBL/FPA files)
    constant_header = bytes.fromhex("f96d4a166fc578ee76fbc07e2c19aaed")

    # Payload starts after magic (offset 8) or after full header (offset 16)
    payload_8 = data[8:]
    payload_16 = data[16:]

    print("=== Trying keys on payload (offset 8) ===")

    # 1. SnakeOil with magic as uint64 seed
    magic_seed = struct.unpack(">Q", data[:8])[0]
    try_method("SnakeOil(magic BE)", payload_8, snakeoil(payload_8, magic_seed))
    magic_seed_le = struct.unpack("<Q", data[:8])[0]
    try_method("SnakeOil(magic LE)", payload_8, snakeoil(payload_8, magic_seed_le))

    # 2. SnakeOil with bytes 8-15 as seed
    seed2 = struct.unpack(">Q", data[8:16])[0]
    try_method("SnakeOil(hdr[8:16] BE)", payload_16, snakeoil(payload_16, seed2))
    seed2_le = struct.unpack("<Q", data[8:16])[0]
    try_method("SnakeOil(hdr[8:16] LE)", payload_16, snakeoil(payload_16, seed2_le))

    # 3. SnakeOil with known credential keys
    for name, seed in [
        ("tb_secret", 0x000ACAB6C9FB66F8),
        ("hu_secret", 0x000EE87C16B1E812),
        ("tb_code", 0x000D4EA65D36B98E),
        ("hu_code", 0x000BF28569BACB7C),
    ]:
        try_method(f"SnakeOil({name})", payload_8, snakeoil(payload_8, seed))

    # 4. Simple XOR with the 16-byte constant header as key (repeating)
    key16 = constant_header
    xored = bytes(payload_16[i] ^ key16[i % 16] for i in range(len(payload_16)))
    try_method("XOR(constant_header, repeating)", payload_16, xored)

    # 5. XOR-CBC with constant header as key
    try_method("XOR-CBC(constant_header)", payload_16, xor_cbc_decrypt(payload_16, key16))

    # 6. XOR with magic as 8-byte repeating key
    key8 = data[:8]
    xored8 = bytes(payload_8[i] ^ key8[i % 8] for i in range(len(payload_8)))
    try_method("XOR(magic, repeating 8B)", payload_8, xored8)

    print()
    print("=== Trying keys on full file ===")

    # 7. SnakeOil on entire file (magic might not be a header — could be ciphertext)
    for name, seed in [
        ("tb_secret", 0x000ACAB6C9FB66F8),
        ("magic BE", magic_seed),
    ]:
        try_method(f"SnakeOil full({name})", data, snakeoil(data, seed))

    # 8. Check if the file is just XOR'd with a single byte
    print()
    print("=== Single-byte XOR scan ===")
    best_ent = 8.0
    best_key = 0
    for key in range(256):
        dec = bytes(b ^ key for b in data[16:min(512, len(data))])
        ent = shannon_entropy(dec)
        if ent < best_ent:
            best_ent = ent
            best_key = key
    print(f"  Best single-byte XOR: key=0x{best_key:02X} entropy={best_ent:.3f}")


if __name__ == "__main__":
    main()
