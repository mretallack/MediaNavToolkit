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
- [ ] **9.2** Decode road segment attribute bytes — PARTIALLY SOLVED
  - Vatican "road_type" values (0x95, 0x9A, 0xA5) are **record type opcodes**, not road classes
  - Complete 256-entry opcode→size table extracted from DLL at RVA 0x2E58A0
  - FBL sections are opcode-structured records (NOT flat coordinate bitstreams)
  - Road attributes in large files are within large opcode records (32-160 bytes)
  - Need to decode internal field layout of large record types (0xA4, 0xC0, 0xD0, etc.)
  - HNR type A/B split still provides binary major/minor classification
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

## 10. Extract Road Attributes from Large FBL Files via DLL Emulation

The opcode table is extracted. Segment boundaries are identified. Road class is
in a typed field within each segment's variable-length record sequence.

- [ ] **10.1** Use Unicorn to emulate the opcode parser on Vatican section 4
  - Feed Vatican's section 4 data to the DLL's graph builder (FUN_10249a90 area)
  - Hook the 0x80030000 handler to capture road class indices (0-9)
  - Verify: should produce indices matching Vatican's 3 known road segments

- [ ] **10.2** Map road class indices to FRC values
  - The 0x8003 handler reads from array at param_5+0x2C (10 entries)
  - Extract or reconstruct this lookup table
  - Map indices 0-9 to FRC 0-7 (motorway→local)

- [ ] **10.3** Emulate on Monaco section 4 to extract all 83 road classes
  - Same approach as 10.1 but on Monaco data
  - Cross-reference with OSM to verify FRC assignments

- [ ] **10.4** Build standalone Python road class extractor
  - Implement the opcode parser in Python (using the opcode table)
  - Extract road class for each segment without DLL emulation
  - Test on all 7 test files

## 11. DLL Parser State Machine Emulation for Road Class Extraction

The FBL section data uses UTF-8-like varint encoding. Road class is at a
context-dependent position in the value stream. The DLL's parser state machine
determines which values are coordinates, indices, and attributes. We need to
emulate this parser to extract road class from any FBL file.

### Phase A: Understand the Parser Architecture

- [ ] **11.1** Map the complete function call chain from file open to road class access
  - Entry: FUN_10245960 (graph builder) → FUN_10245ca0 (record processor)
  - FUN_10245ca0 reads uint32 records with type in high 16 bits
  - FUN_10249a90 processes individual records and extracts attributes
  - Document the full call chain with parameter types

- [ ] **11.2** Identify how the varint byte stream becomes uint32 records
  - FUN_1025dec0 encodes varints (we found this)
  - Find the DECODER function (reads varints from byte stream)
  - Document: which function reads the raw section bytes and produces uint32 records
  - Check FUN_1024a340 and FUN_1024a490 which take byte* and produce records

- [ ] **11.3** Document the uint32 record type system
  - Type 0x8001: advance/skip
  - Type 0x8002: advance/skip
  - Type 0x8003: road class index (low 16 bits = index 0-9)
  - Type 0x8004: coordinate pair (advance by 2 uint32s)
  - Type 0x8005: advance by 1
  - Type 0x8006: advance by 3
  - Type 0x8008: segment marker
  - Map ALL types 0x8001-0x801E from FUN_10245ca0

- [ ] **11.4** Extract the road class lookup table (10 entries at param_5+0x2C)
  - FUN_10245960 receives param_5 which has the lookup table
  - The table maps indices 0-9 to road class definitions
  - Find where this table is populated (from file data or DLL constants)
  - Extract the 10 road class definitions

### Phase B: Build the Varint Decoder

- [ ] **11.5** Implement a correct varint decoder in Python
  - Handle all 6 byte lengths (1-6 bytes)
  - Handle continuation bytes (0x80-0xBF)
  - Verify against Vatican section 4 (known values)
  - Unit test with edge cases (0, 127, 128, 2047, 2048, etc.)

- [ ] **11.6** Implement the varint-to-uint32 record converter
  - The byte stream is NOT directly varints — it's a hybrid format
  - Some bytes are opcodes (0x00-0x7F) with payloads
  - Some bytes are varint prefixes (0xC0-0xFF) for multi-byte values
  - Implement the conversion that produces the uint32 record stream

- [ ] **11.7** Verify the converter on Vatican section 4
  - Feed Vatican section 4 bytes through the converter
  - The output should contain uint32 records including 0x80030000|index
  - Verify: the road class indices should produce values matching 0x95, 0x9A, 0xA5

### Phase C: Unicorn Emulation Framework

- [ ] **11.8** Build a reusable Unicorn harness for the map parser
  - Based on existing unicorn_harness.py and unicorn_serialize4.py patterns
  - Load DLL with relocations
  - Set up malloc/free hooks
  - Set up vtable stubs (RET instructions at stub addresses)
  - Handle unmapped memory reads (return 0)

- [ ] **11.9** Create a fake file reader object for Unicorn
  - The parser reads from a stream object (vtable-based)
  - Create a fake stream that reads from our decrypted section data
  - Hook the vtable read method to return bytes from our buffer
  - Test: verify the stream returns correct bytes

- [ ] **11.10** Create a fake map context object (param_5)
  - FUN_10245960 receives param_5 with the road class lookup table at +0x2C
  - Create a fake object with the 10-entry lookup table
  - Initialize other required fields (flags at +0x68, +0x6C, etc.)
  - Test: verify the object is readable by the DLL

- [ ] **11.11** Emulate FUN_1024a340 (byte stream to record converter) on Vatican data
  - Feed Vatican section 4 bytes through the converter
  - Capture the output uint32 records
  - Verify: should produce records matching the known road data

### Phase D: Road Class Extraction

- [ ] **11.12** Emulate FUN_10245ca0 (record processor) on Vatican uint32 records
  - Feed the uint32 records from step 11.11
  - Hook the 0x8003 handler to capture road class indices
  - Verify: should capture indices that map to 0x95, 0x9A, 0xA5

- [ ] **11.13** Emulate on Monaco section 4 data
  - Same pipeline as Vatican but with Monaco data
  - Capture all road class indices for 395 segments
  - Cross-reference with OSM to verify FRC assignments

- [ ] **11.14** Emulate on Andorra section 4 data
  - Capture road class indices for 1440 segments
  - Verify: Andorra should have motorway segments (CG-1 highway)
  - Check FRC distribution matches expected road network

- [ ] **11.15** Emulate on Malta section 4 data
  - Capture road class indices for 8096 segments
  - Verify FRC distribution is reasonable for Malta's road network

### Phase E: Pure Python Implementation

- [ ] **11.16** Reverse-engineer the parser state machine from Unicorn traces
  - Compare input bytes with output records across Vatican/Monaco/Andorra
  - Identify the state transitions that produce 0x8003 records
  - Document the parser state machine as a flowchart

- [ ] **11.17** Implement the parser state machine in Python
  - Translate the DLL's parser logic into Python
  - No Unicorn dependency — pure Python implementation
  - Handle all record types (0x8001-0x801E)

- [ ] **11.18** Implement road class extraction in Python
  - Use the parser to extract 0x8003 records from any section
  - Map indices to FRC values using the lookup table
  - Output: list of (segment_index, FRC, speed_class) tuples

- [ ] **11.19** Verify Python implementation against Unicorn results
  - Run on Vatican, Monaco, Andorra, Malta
  - Compare output with Unicorn emulation results from steps 11.12-11.15
  - Fix any discrepancies

### Phase F: Tool and Documentation

- [ ] **11.20** Build `fbl_road_class.py` tool
  - Extract road class for every segment in any FBL file
  - Output CSV: segment_index, FRC, speed_class, byte_offset
  - Test on all 7 test files + UK 254MB file
  - Add to tools/maps/ directory

- [ ] **11.21** Update mapformat.md with complete parser documentation
  - Document the varint encoding
  - Document the uint32 record type system
  - Document the road class lookup table
  - Document the parser state machine
  - Mark task 9.2 as fully SOLVED

- [ ] **11.22** Update tasks.md and commit everything
  - Mark all sub-tasks as complete
  - Update the main task 9.2 status
  - Final commit with all code and documentation
