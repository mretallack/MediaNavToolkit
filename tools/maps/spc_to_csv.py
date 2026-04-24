#!/usr/bin/env python3
"""Export NNG speed camera files (.spc) to CSV.

Decrypts and parses .spc files, outputting GPS coordinates and speed limits.

Usage:
    python tools/maps/spc_to_csv.py tools/maps/testdata/Andorra_osm.spc
    python tools/maps/spc_to_csv.py tools/maps/testdata/Andorra_osm.spc -o andorra_cameras.csv
    python tools/maps/spc_to_csv.py /path/to/disk-backup/ -o all_cameras.csv
"""

import csv
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = Path(__file__).parent.parent.parent / "analysis" / "xor_table_normal.bin"
SCALE = 2**23


def decrypt(data: bytes, xor_table: bytes) -> bytes:
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def find_metadata_end(dec: bytes) -> int:
    """Find where the UTF-16LE metadata ends and camera records begin."""
    # Look for the end of the last UTF-16LE null terminator after the metadata
    i = 0x10  # skip initial header
    while i < len(dec) - 3:
        if dec[i] >= 0x20 and dec[i + 1] == 0x00:
            i += 2
        elif dec[i] == 0x00 and dec[i + 1] == 0x00:
            # End of UTF-16LE string — skip nulls and look for record data
            while i < len(dec) and dec[i] == 0x00:
                i += 1
            return i
        else:
            i += 1
    return min(0x100, len(dec))


def parse_spc(dec: bytes) -> list[dict]:
    """Parse decrypted .spc data into camera records."""
    cameras = []
    data_start = find_metadata_end(dec)

    # Scan for 12-byte camera records
    off = data_start
    while off + 12 <= len(dec):
        lon_raw = struct.unpack_from("<i", dec, off)[0]
        lat_raw = struct.unpack_from("<i", dec, off + 4)[0]
        lon = lon_raw / SCALE
        lat = lat_raw / SCALE

        # Validate: must be plausible coordinates
        if -180 < lon < 180 and -90 < lat < 90 and (abs(lon) > 0.1 or abs(lat) > 0.1):
            flags = struct.unpack_from("<H", dec, off + 8)[0]
            speed = dec[off + 10]
            cam_type = dec[off + 11]

            # Accept records with camera flag (0x0400) and plausible speed
            if flags == 0x0400 and speed <= 200:
                cameras.append(
                    {
                        "latitude": round(lat, 6),
                        "longitude": round(lon, 6),
                        "speed_kmh": speed,
                        "type": cam_type,
                        "flags": flags,
                    }
                )
            off += 12
        else:
            off += 2

    return cameras


def extract_country(dec: bytes) -> str:
    """Extract country code from metadata."""
    # Look for _XXX| pattern in UTF-16LE
    for i in range(0x10, min(0x200, len(dec)) - 8):
        if dec[i] == ord("_") and dec[i + 1] == 0x00:
            code = ""
            j = i + 2
            while j < len(dec) - 1 and dec[j + 1] == 0x00 and dec[j] != ord("|"):
                code += chr(dec[j])
                j += 2
            if 2 <= len(code) <= 4:
                return code
    return "UNK"


def main():
    if len(sys.argv) < 2:
        print("Usage: spc_to_csv.py <file_or_dir> [-o output.csv]")
        sys.exit(1)

    xor_table = XOR_TABLE_PATH.read_bytes()
    input_path = Path(sys.argv[1])
    output_path = None
    if "-o" in sys.argv:
        output_path = Path(sys.argv[sys.argv.index("-o") + 1])

    files = []
    if input_path.is_dir():
        files = sorted(input_path.rglob("*.spc"))
    elif input_path.is_file():
        files = [input_path]

    all_cameras = []
    for f in files:
        data = f.read_bytes()
        dec = decrypt(data, xor_table)
        country = extract_country(dec)
        cameras = parse_spc(dec)

        for cam in cameras:
            cam["country"] = country
            cam["source_file"] = f.name

        all_cameras.extend(cameras)
        print(f"{f.name}: {country}, {len(cameras)} cameras", file=sys.stderr)

    # Output
    if not all_cameras:
        print("No cameras found.", file=sys.stderr)
        sys.exit(0)

    fieldnames = ["country", "latitude", "longitude", "speed_kmh", "type", "flags", "source_file"]
    out = open(output_path, "w", newline="") if output_path else sys.stdout
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(all_cameras)

    if output_path:
        out.close()
        print(f"Wrote {len(all_cameras)} cameras to {output_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
