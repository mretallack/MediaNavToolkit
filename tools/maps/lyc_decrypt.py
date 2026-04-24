#!/usr/bin/env python3
"""Decrypt NNG .lyc license files.

Performs RSA verification (public key) + XOR-CBC decryption to extract
license content: SWID, product name, and activation data.

Usage:
    python tools/maps/lyc_decrypt.py path/to/license.lyc
    python tools/maps/lyc_decrypt.py path/to/license_dir/
"""

import struct
import sys
from pathlib import Path

# RSA modulus (byte-reversed in DLL at file offset 0x309988)
MOD_HEX = (
    "6B231771184FAAD886AE159BADB1D45A5BC4338D4F503A6193DA01A619E5D21A"
    "C873174C7D206CEAFED3AF22FEE1019DB84BA294B41339FCCD19048C95FB9CED"
    "ABCAE87113D188FC2D3050CA2FAF12EE5A292B17D3490364360B965665AECB52"
    "4265B9AFBDAAA0EDDAD5304293D70FBA49609AC25F8AF3464E55FF79BCE67681"
    "F4349625A7BA755DCC55476660134CB592F20AC01E2B4D37B3CBB05803DE7531"
    "BA5E464B031F65F9AC91F9BE6D133DA19400F6F17A4E697C6505FDEE34F45500"
    "52BCA43E2BCD5C63B46A96B432D2F393DB9E648D593D580141BC265CF3403905"
    "96CF667E577CC1BCB235759DB983CB191652667F85319A595812502FFC0B676F"
)
N = int(MOD_HEX, 16)
E = 65537


def nng_xor_cbc_decrypt(data: bytes, key_16: bytes) -> bytes:
    """NNG XOR-CBC: output = input XOR running_key; running_key ^= output."""
    k = list(struct.unpack("<4I", key_16))
    result = bytearray()
    for i in range(0, len(data), 16):
        block = data[i : i + 16]
        if len(block) < 16:
            block = block + b"\x00" * (16 - len(block))
        inp = struct.unpack("<4I", block)
        out = [inp[j] ^ k[j] for j in range(4)]
        result.extend(struct.pack("<4I", *out))
        k = [k[j] ^ out[j] for j in range(4)]
    return bytes(result[: len(data)])


def decrypt_lyc(lyc_data: bytes) -> dict | None:
    """Decrypt a .lyc file and return its contents."""
    if len(lyc_data) < 264:
        return None

    # Skip 8-byte header, RSA decrypt bytes 8-264
    ct = int.from_bytes(lyc_data[8:264], "big")
    pt_int = pow(ct, E, N)
    pt = pt_int.to_bytes(256, "big")

    # Find PKCS#1 v1.5 padding
    if pt[0] != 0x00 or pt[1] not in (0x01, 0x02):
        return None

    try:
        sep = pt.index(b"\x00", 2)
    except ValueError:
        return None

    payload = pt[sep + 1 :]
    if len(payload) < 40:
        return None

    magic = struct.unpack("<I", payload[:4])[0]
    if magic != 0x36C8B267:
        return None

    xor_key = payload[8:24]
    data_size = struct.unpack("<I", payload[36:40])[0]

    # XOR-CBC decrypt remaining data
    remaining = lyc_data[264:]
    decrypted = nng_xor_cbc_decrypt(remaining, xor_key)

    # Extract SWID and product name from decrypted content
    # SWID starts around offset 0x0E (after first garbled block)
    swid = ""
    product = ""
    for i in range(0x0C, min(0x30, len(decrypted))):
        if decrypted[i : i + 3] == b"CW-" or decrypted[i : i + 3] == b"CK-":
            end = decrypted.index(b"\x00", i)
            swid = decrypted[i:end].decode("ascii", errors="replace")
            break
        # First block may be garbled — look for -XXXX-XXXX pattern
        if decrypted[i : i + 1] == b"-" and i > 0x0C:
            # Reconstruct: assume CW- prefix
            end = decrypted.index(b"\x00", i - 2)
            raw = decrypted[i - 2 : end].decode("ascii", errors="replace")
            swid = "CW" + raw[2:] if len(raw) > 4 else ""
            break

    for i in range(0x1E, min(0x80, len(decrypted))):
        if decrypted[i] >= 0x41 and decrypted[i + 1 : i + 2] != b"\x00":
            end = decrypted.index(b"\x00", i)
            candidate = decrypted[i:end].decode("ascii", errors="replace")
            if len(candidate) > 5 and " " in candidate:
                product = candidate
                break

    return {
        "magic": f"0x{magic:08X}",
        "xor_key": xor_key.hex(),
        "data_size": data_size,
        "swid": swid,
        "product": product,
        "decrypted_size": len(decrypted),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: lyc_decrypt.py <file_or_dir>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    files = []
    if input_path.is_dir():
        files = sorted(input_path.rglob("*.lyc"))
    elif input_path.is_file():
        files = [input_path]

    for f in files:
        data = f.read_bytes()
        result = decrypt_lyc(data)

        if result:
            print(f"{f.name}:")
            print(f"  SWID:    {result['swid'] or '(not found)'}")
            print(f"  Product: {result['product'] or '(not found)'}")
            print(f"  Key:     {result['xor_key']}")
            print(
                f"  Size:    {result['data_size']}B encrypted, {result['decrypted_size']}B decrypted"
            )
        else:
            print(f"{f.name}: decryption failed")
        print()


if __name__ == "__main__":
    main()
