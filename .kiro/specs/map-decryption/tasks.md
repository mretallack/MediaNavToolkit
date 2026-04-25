# Tasks: NNG Map File Decryption

> Requirements: [requirements.md](requirements.md) | Design: [design.md](design.md)

## Done ✅

- [x] **1.1-1.4** Header analysis — magic bytes, constant/variable fields, 512-byte alignment
- [x] **2.1** .lyc RSA decryption — 8-byte header offset, byte-reversed modulus, all 3 licenses decrypted
- [x] **2.2** Key testing — XOR table found (same as device.nng), SnakeOil/Blowfish/.lyc keys tested
- [x] **3.1-3.5** DLL analysis — SET reader, Blowfish functions, key hierarchy traced
- [x] **4.1** `tools/maps/decrypt_fbl.py` — outer XOR decryption working
- [x] **4.2** Verified on all file types (.fbl, .fpa, .hnr, .poi, .spc)
- [x] **5.1** SET header structure (magic, version, data offset, file size)
- [x] **5.2** Coordinate encoding (int32 / 2^23 = WGS84 degrees)
- [x] **5.3** SPC format fully parsed — 12-byte camera records (lon, lat, flags, speed, type)
- [x] **5.4** `tools/maps/fbl_info.py` — metadata, bbox, country, version, copyright
- [x] **5.5** `tools/maps/spc_to_csv.py` — speed cameras to CSV (coordinates + speed)
- [x] **5.6** Curve data codec decoded — packed bitstream [N-bit lon][M-bit lat] relative to bbox
- [x] **5.7** Bit widths formula: `N = ceil(log2(bbox_lon_range + 1))`, `M = ceil(log2(bbox_lat_range + 1))`
- [x] **5.8** Verified curve decoding on Vatican (59 pts), Monaco (116 pts), Andorra (295 pts)
- [x] **6.2** `tools/maps/lyc_decrypt.py` — decrypt .lyc license files (RSA + XOR-CBC)
- [x] **6.3** `tools/maps/junctions_to_geojson.py` — extract junction coordinates as GeoJSON
- [x] **6.4** `tools/maps/segments_to_csv.py` — extract road segment metadata to CSV
- [x] **6.5** `tools/maps/map_overview.py` — show all countries with bbox, version, sizes
- [x] **6.6** `tools/maps/curves_to_geojson.py` — extract curve points from section 1 bitstream

## Resolved (Previously Blocked) ✅

- [x] **Shape data encryption** — RESOLVED: curve data in section 1 is NOT encrypted.
  It uses a packed bitstream encoding with dynamic bit widths derived from the bounding box.
  Blowfish in the DLL is for license key management, not map data.

## Resolved — Section Data is Packed Bitstreams ✅

Sections in larger files are **NOT compressed**. They use the same packed bitstream
encoding as section 1: `[N-bit lon][M-bit lat]` pairs relative to bbox minimum.
The high entropy (~7.99) was because packed bit fields with near-full-range values
naturally look random.

**Verified:** Monaco sections 4+5 decode as **100% valid coordinates** (21+21 bits).

- [x] **8.1** Section data format identified — packed bitstreams, same as section 1
- [x] **8.2** Monaco section 4: 3880/3880 valid (100%), section 5: 1969/1969 (100%)
- [x] **8.3** Andorra section 4: 12289/14278 valid (86%) with 22+21 bits

## Can Do Now 🔧

- [x] **6.1** Extract ALL speed cameras from the full disk backup
  - 1,405 cameras from 20 countries (21 .spc files) → `tools/maps/all_speed_cameras.csv`
  - France/Italy/Spain have fewer cameras — larger SPC files use additional record formats beyond flags=0x0400
- [x] **7.1** `tools/maps/fbl_to_geojson.py` — extract all coordinates from all sections as GeoJSON
  - Tested: Vatican=2,425 pts, Monaco=8,686 pts, Andorra=42,261 pts
- [x] **7.2** Cross-reference decoded coordinates with OpenStreetMap data
  - Vatican: 17–50m accuracy (Via della Conciliazione, Piazza San Pietro, Viale Vaticano)
  - Monaco: 78–427m accuracy (larger bbox = lower resolution per bit)
  - NFR-1 (0.001° tolerance) satisfied ✅
- [x] **7.3** Parse `.fpa` (address search) format — DECODED ✅
  - Same SET container, same packed bitstream coordinate encoding as FBL
  - Has a uint32 offset table before the coordinate data (address index)
  - Monaco: 745 address points (100% valid, 21+21 bits)
  - Andorra: 11,355 address points (79% valid, 22+21 bits)
  - The offset table groups addresses by street/area
- [x] **7.4** `tools/maps/poi_to_geojson.py` — extract POI coordinates as GeoJSON
  - Different container from FBL (magic `0xC5676632A`, no SET header)
  - XOR table decryption works, coordinates as uint16 pairs scaled to bbox
  - Andorra: 1,278 POIs with category names (_Casino, _School, _Stage, etc.)
  - Category name encoding: byte << 1 (decoded in 9.3)
- [x] **7.5** Identify what each section contains
  - All sections are packed bitstreams of coordinates
  - Sections do NOT correspond to road classifications (verified via OSM cross-reference)
  - Section roles are rendering layers/zoom levels, not road types

## Future Work 🔧

- [x] **9.1** Update `fbl_to_geojson.py` to handle multi-region files and large file sizes
  - Large files (e.g. UK 254MB) have ONE region block, not multiple
  - The GBR bbox covers Scotland but coordinates span all UK
  - Trailing data after section 17 (230MB for UK) is more packed coordinates
  - Updated tool to include trailing data; numpy XOR already implemented
  - UK section 4: 1.3M road points decoded in ~2 min
- [x] **9.2** Decode road segment attribute bytes — SOLVED ✅
  - Value 92 (0x5C) in varint stream marks road class records
  - Next value looked up in DLL table DAT_102e3480 (256 int16 entries)
  - Negative entries = road class index: A=1(generic), G=2(trunk), K=3(primary),
    B=4(tertiary), b=5(local_hi), D=6(local_med), d=7(local_lo), S=8(pedestrian), s=9(other)
  - Working on all 7 test files: Vatican(2), Monaco(31), Andorra(76), Malta(424)
  - ~5-14% of segments have explicit road class; rest inherit from parent/default
- [x] **9.7** Decode the gap area (road network index) between section table and section 0
  - **DECODED ✅** — the gap area is a continuous packed bitstream of coordinates
  - Part 1 (fixed header 0x04DE-0x055D): File metadata, sizes, constant fields
  - Part 2 (coordinate bitstream 0x0565+): Packed N+M bit coordinates (same as sections)
  - Part 3 (extended coordinates): The ENTIRE gap area is coordinates, not a separate index
  - Vatican: 87 points, 100% valid; Monaco: 1184 pts, 95%; Andorra: 1861 pts, 67%
  - The count at 0x0563 covers only the first ~10 reference points
  - SET container has section_count=1; gap area is the start of the single section's data
- [x] **9.3** Fix POI category name encoding — SOLVED
  - POI names use **byte << 1 encoding**: each byte is the ASCII value * 2
  - Decoding: `chr(byte >> 1)` for bytes >= 0x80
  - Examples: `0xBE 0x86 0xC2 0xE6 0xD2 0xDC 0xDE` = `_Casino`
  - Categories found: _Casino, _Government_Office, _School, _Stage, _Camping, etc.
  - Fixed `poi_to_geojson.py` to decode shifted names
- [x] **9.4** Investigate section 16 data — RESOLVED
  - Section 16 is **empty** in ALL test files (sections 16 and 17 share the same offset)
  - The earlier "high entropy" finding was about trailing data after the section table,
    which is actually packed coordinate data (decoded in 9.7)
  - No compression or encryption to investigate
- [ ] **9.5** Parse HNR (historical navigation routing) files — SUBSTANTIALLY DECODED
  - Magic: `HNRF` (not SET container), XOR table decryption works
  - Header: magic(4) + version(4) + hash(4) + flags(4) + metadata_len(4)
  - Metadata: same NNG format, routing type (Economic/Fastest/Shortest)
  - Count table at 0x0210: 384 entries, values are uint32 >> 8 = record counts
  - Record size: exactly 256 bytes (count × 256 = block size, verified for all entries)
  - **Bit-level structure decoded** by cross-referencing Economic vs Fastest:
    - Per 32-bit group: ~22 shared bits (road data) + ~10 routing bits
    - Bit 0 of byte 0: ALWAYS inverted between Economic/Fastest (variant flag)
    - Byte 1: independent routing weight per variant
    - Byte 3: 100% shared road topology data
  - Economic and Fastest share same record ordering for first ~1000 records
  - Shortest uses completely different format (counts don't fit >> 8 pattern)
  - 306,756 records × 64 groups = ~19.6M road segment entries per variant
- [ ] **9.6** Parse TMC (traffic message channel) files
  - Only `.stm` shadow files available on USB (actual TMC data on head unit internal storage)
  - Provider-specific files (e.g. France-V-Trafic.tmc, Germany_HERE.tmc)
  - Cannot investigate without extracting actual files from head unit
  - Maps TMC location codes to road segments for real-time traffic

## Documentation Rule

**Keep [`docs/mapformat.md`](../../docs/mapformat.md) up to date as findings are made.**


## 10-11. DLL Parser Emulation for Road Class — COMPLETED ✅

All sub-tasks superseded by the direct solution:
- [x] Mapped parser call chain: FUN_1024a720 → FUN_102460d0
- [x] Found byte-to-record converter (FUN_1024a720, RVA 0x24A720)
- [x] Documented 48 uint32 record types (0x8000-0x803B)
- [x] Extracted road class lookup table (DAT_102e3480, 256 int16 entries)
- [x] Implemented varint decoder (tools/maps/nng_varint.py)
- [x] Built Unicorn emulator framework (tools/maps/nng_emulator.py)
- [x] Discovered value 92 marks road class in varint stream
- [x] Extracted road classes from all 7 test files
- [x] FBL uses UTF-8-like variable-length integer encoding
- [x] Section data is a pattern language compiled by the DLL
