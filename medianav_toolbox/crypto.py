"""Cryptographic primitives for the MediaNav Toolbox protocol.

SnakeOil: xorshift128 PRNG stream cipher used on the wire protocol.
Blowfish: ECB decryption for http_dump XML files.

Ref: toolbox.md §2 (SnakeOil), §7 (Blowfish key), functions.md (FUN_101b3e10)
"""

import struct

_M = 0xFFFFFFFF


def snakeoil(data: bytes, seed: int) -> bytes:
    """xorshift128 PRNG stream cipher. Symmetric encrypt/decrypt.

    Reversed from FUN_101b3e10 (nngine.dll 0x101b3e30).
    Uses SHRD x86 instruction for 64-bit output extraction.

    Args:
        data: plaintext or ciphertext bytes
        seed: uint64 PRNG seed (random key for RANDOM mode, Secret for DEVICE mode)

    Returns:
        XOR'd output (ciphertext if input was plaintext, and vice versa)
    """
    result = bytearray(len(data))
    eax = seed & _M
    esi = (seed >> 32) & _M
    for i in range(len(data)):
        edx = (((esi << 21) | (eax >> 11)) ^ esi) & _M
        ecx = (((eax << 21) & _M) ^ eax) & _M
        ecx = (ecx ^ (edx >> 3)) & _M
        esi = ((((edx << 4) | (ecx >> 28)) & _M) ^ edx) & _M
        eax = (((ecx << 4) & _M) ^ ecx) & _M
        result[i] = data[i] ^ (((esi << 32) | eax) >> 23) & 0xFF
    return bytes(result)


# Blowfish key for http_dump XML decryption (from DAT_102af9e8 in nngine.dll)
BLOWFISH_KEY = bytes.fromhex("b0caba3df8a23194f2a22f59cd0b39ab")


def decrypt_http_dump(data: bytes) -> bytes:
    """Decrypt a Blowfish-ECB encrypted http_dump XML file.

    Args:
        data: raw bytes from an .xml.enc file

    Returns:
        Decrypted plaintext (HTTP request/response with headers + XML body)
    """
    from Crypto.Cipher import Blowfish

    cipher = Blowfish.new(BLOWFISH_KEY, Blowfish.MODE_ECB)
    return cipher.decrypt(data)
