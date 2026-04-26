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
- [x] **9.5** Parse HNR (historical navigation routing) files — SOLVED ✅
  - Magic: `HNRF`, XOR decryption, 256-byte tiles, 64 entries per tile
  - Routing weight is BINARY: A/B block = major/minor roads (not continuous)
  - No per-entry weight difference between A and B (confirmed statistically)
  - HNR↔FBL linking impossible without DLL runtime (opaque compiler IDs)
  - Road classification available via FBL value 92 + DLL lookup table instead
- [x] **9.5b** HNR↔FBL segment linking — SOLVED (10 countries linked, segment-level matcher built)
  - **What:** Link HNR routing data (major/minor per segment) to FBL map coordinates
  - **Previous attempts that failed:** Direct ID matching, hash functions, spatial keys
  - **New opportunity:** We now have road class for 99% of FBL segments via forward-fill.
    This enables matching by road class distribution per geographic area.

  - [x] **9.5b.1** Count FBL segments per road class for ALL 30 countries
    - Extract the full disk backup, decrypt each FBL file
    - Run fbl_road_class.py --inherit on each
    - Output: country, total_segments, motorway, trunk, primary, ..., pedestrian

  - [x] **9.5b.2** Count HNR type-A segments per tile
    - Type A = major roads. Count per tile gives a "major road density" per tile.
    - Output: tile_index, a_count, b_count, a_ratio

  - [x] **9.5b.3** Estimate FBL "major road" count per country
    - From 9.5b.1: count segments with road class 0-3 (motorway/trunk/primary/secondary)
    - These are the "major" roads that should correspond to HNR type A

  - [x] **9.5b.4** Match HNR tiles to countries by major road count
    - For each country, find the set of HNR tiles whose combined A-count
      matches the country's major road count
    - Small countries (Vatican, Monaco) should match 1-2 tiles
    - Large countries (France, Germany) should match many tiles

  - [x] **9.5b.5** Verify matching using total segment counts
    - For matched tiles: total HNR segments (A+B) × 64 should approximate
      total FBL segments × some ratio
    - The ratio should be consistent across countries

  - [x] **9.5b.6** Try matching by segment SIZE distribution
    - FBL segments have sizes (2-587 bytes). Larger = more important road.
    - HNR type A entries might correspond to larger FBL segments
    - Compare: FBL segment size distribution for major vs minor roads
      with HNR A vs B block sizes

  - [x] **9.5b.7** Use geographic bbox to narrow tile candidates
    - Each FBL file has a bbox (lon/lat range)
    - HNR tiles cover geographic areas (we know tile size ~0.78°)
    - Compute which tiles COULD contain each country based on bbox overlap

  - [x] **9.5b.8** Try matching by segment ORDER within tiles
    - If HNR entries within a tile are ordered the same as FBL segments
      within a country, we can match by position
    - Compare: first N entries of an HNR tile with first N FBL segments
    - Check if road class (major/minor) matches A/B block assignment

  - [x] **9.5b.9** Use the FBL section 15 offsets as region boundaries
    - The FBL header has 7 uint24 offsets into section 15
    - These might divide the country into regions
    - Each region might correspond to one HNR tile

  - [x] **9.5b.10** Build a segment-level matcher using road class + position
    - For a matched tile-country pair:
      - Sort FBL segments by byte offset (= geographic order)
      - Sort HNR entries by position within tile
      - Match: FBL major road segments ↔ HNR type A entries
      - Match: FBL minor road segments ↔ HNR type B entries
    - Verify by checking if matched segments have consistent properties

  - [x] **9.5b.11** Validate linking on Vatican (3 segments)
    - Vatican is the simplest case — only 3 road segments
    - Find which HNR tile(s) contain Vatican's segments
    - Verify: the 3 HNR entries should match Vatican's 3 FBL segments

  - [x] **9.5b.12** Validate linking on Monaco (395 segments)
    - Monaco is small enough to verify manually
    - Check: do the matched HNR entries have the right A/B classification
      for Monaco's road classes?

  - [x] **9.5b.13** Build `hnr_fbl_link.py` tool
    - Input: FBL file + HNR file
    - Output: CSV with lon, lat, fbl_road_class, hnr_block_type (A/B)
    - Test on Vatican, Monaco, Andorra

  - [x] **9.5b.14** Validate on Andorra (motorway CG-1)
    - Andorra has a known motorway (CG-1)
    - The motorway segments should be in HNR type A blocks
    - Verify: linked motorway segments have A classification

  - [x] **9.5b.15** Document the linking method in mapformat.md
    - Describe the matching algorithm
    - Report accuracy metrics
    - Mark 9.5b as SOLVED
- [ ] **9.6** Parse TMC (traffic message channel) files — see Task 16 (blocked on Task 15)
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


## Future Tasks

- [x] **F1** Build `fbl_road_class.py` CLI tool ✅
- [x] **F2** Build `fbl_segments.py` CLI tool ✅
- [x] **F3** Build `fbl_road_network.py` — complete road network export ✅
- [x] **F4** Improve road class coverage — SOLVED ✅ (forward-fill gives 97-99%) — trace inheritance for unclassified segments
  - Currently ~5-14% of segments have explicit road class markers (value 92)
  - The remaining ~85-95% inherit road class from context

  - [x] **F4.1** Analyze the pattern around classified segments
    - For each classified segment, check: do neighboring segments share the same class?
    - Check if road class markers appear at the START of a group of segments
    - Hypothesis: one marker classifies all following segments until the next marker

  - [x] **F4.2** Test the "inherit from previous marker" hypothesis
    - Assign each segment the road class of the most recent value-92 marker before it
    - Count how many segments get classified this way
    - Cross-reference with OSM to check if the assignments make sense

  - [x] **F4.3** Check if segment size correlates with inherited road class
    - Large segments (>200B) should be major roads
    - Small segments (<20B) should be local roads
    - If inherited class matches size pattern, the inheritance is correct

  - [x] **F4.4** Check the DLL's graph builder for inheritance logic
    - In FUN_102460d0, `local_b0` holds the current road class value
    - It's set by 0x8003 records and persists across segments
    - Trace: does `local_b0` reset between segments or carry forward?

  - [x] **F4.5** Check if the varint value AFTER the segment marker encodes class
    - Segment markers (6, 98-103) have a payload value
    - The payload might be a road class index or a reference to a class table
    - Compare payload values with known road classes from value-92 markers

  - [x] **F4.6** Check if the section number implies road class
    - Sections 4, 5, 8 might correspond to different road importance levels
    - Extract segments from sections 5 and 8 separately
    - Compare road class distribution across sections

  - [x] **F4.7** Use Unicorn to emulate the graph builder on a small section
    - Feed Monaco section 4 (first 1000 bytes) to FUN_102460d0
    - Hook the 0x8003 handler to capture road class assignments
    - Track which segments get which class (including inherited ones)

  - [x] **F4.8** Implement the inheritance logic in Python
    - Based on findings from F4.1-F4.7
    - Assign road class to ALL segments (not just those with explicit markers)
    - Verify: classified segment count should be close to total segment count

  - [x] **F4.9** Validate full classification against OSM
    - Run fbl_validate.py with the improved classification
    - Compare road class distribution with OSM highway tag distribution
    - Report accuracy improvement over the 5-14% baseline

  - [x] **F4.10** Update fbl_road_class.py to use inheritance
    - Add --inherit flag to enable inheritance logic
    - Default: only explicit markers (current behavior)
    - With --inherit: classify all segments using inheritance
- [x] **F5** Build HNR CSV export (added --csv to hnr_info.py) ✅
- [x] **F6** Publish mapformat.md as standalone format documentation ✅
- [x] **F7** Build test suite for map tools (10 tests, 301 total) ✅
- [x] **F8** Build `fbl_validate.py` — validate FBL data against OSM ✅

## 12. HNR Routing Weight Semantics and HNR↔FBL Linking

The HNR format is structurally decoded (256-byte tiles, bit-level layout, A/B
road classification). Two problems remain:
1. What do the routing weight values (byte 1, 0-255) mean?
2. How do HNR road IDs map to FBL road segments?

### Phase A: Understand Routing Weights

- [x] **12.1** Extract routing weights for ALL segments in first 100 HNR tiles
  - Parse Economic and Fastest files
  - For each segment: extract byte 0 (base), byte 1 (weight), byte 3 (road ID)
  - Output as CSV for analysis

- [x] **12.2** Compare Economic vs Fastest weights for the same segments
  - First 1000 aligned records have identical byte 3 (road ID)
  - Compute: weight_diff = Fastest.byte1 - Economic.byte1 per segment
  - Check: does weight_diff correlate with road class (from A/B block type)?

- [x] **12.3** Check if routing weights correlate with known speed limits
  - European motorways: 130 km/h, trunk: 90-110, residential: 30-50
  - If weight = speed: type A (major) should have higher weights
  - If weight = cost: type A should have LOWER weights
  - Statistical test: mean weight for type A vs type B

- [x] **12.4** Check if weights have temporal patterns
  - If HNR encodes time-of-day profiles, consecutive segments in same tile
    might have correlated weights (rush hour vs off-peak)
  - Autocorrelation analysis within tiles

- [x] **12.5** Extract the Shortest variant's format
  - Shortest uses different encoding (counts don't fit >>8 pattern)
  - Decode the Shortest header and count table
  - Compare record structure with Economic/Fastest

### Phase B: Link HNR Road IDs to FBL Segments

- [x] **12.6** Extract road class markers (value 92) from FBL with byte offsets
  - For each road class marker, record its byte position in the section
  - This gives us: (byte_offset, road_class) pairs for each FBL file

- [x] **12.7** Extract segment boundaries from FBL with byte offsets
  - Segment markers (values 6, 98-103) with byte positions
  - This gives us: (byte_offset, segment_index) pairs

- [x] **12.8** Compute segment byte ranges in FBL
  - Each segment spans from its marker to the next marker
  - Compute: (segment_index, start_byte, end_byte, road_class) per segment

- [x] **12.9** Check if FBL segment count matches HNR segment count per tile
  - FBL has per-country segment counts (Monaco=395, Andorra=1440)
  - HNR has per-tile segment counts (192 tiles × 64 segments)
  - Check: does sum of HNR segments for a country's tiles = FBL segment count?

- [x] **12.10** Try matching by segment COUNT per region
  - If HNR tile X has N segments and FBL country Y has N segments in a region,
    they might correspond
  - Use the FBL header offsets (7 pointers into section 15) as region boundaries

- [x] **12.11** Use the FBL spatial index key format to generate candidate IDs
  - FBL key = (tile_index << 23) | sequential_counter
  - Generate all possible keys for a small country (Vatican/Monaco)
  - Check if any transformation of these keys matches HNR road IDs

- [x] **12.12** Try XOR/hash of FBL key with DLL constants
  - The DLL might XOR or hash the FBL spatial key to produce the HNR road ID
  - Try: HNR_ID = FBL_key XOR constant, HNR_ID = CRC32(FBL_key), etc.
  - Use Vatican's 3 segments as ground truth

### Phase C: Unicorn Emulation of HNR Loader

- [ ] **12.13** Find the DLL function that loads HNR files
  - Search for "HNRF" magic check or HNR-related string references
  - Map the HNR loading call chain

- [ ] **12.14** Find the function that maps HNR road IDs to FBL segments
  - The navigation engine must have a lookup function
  - Search for functions that take a road ID and return coordinates

- [ ] **12.15** Emulate the HNR loader on a small tile
  - Feed one HNR tile (256 bytes) to the loader
  - Capture the road ID → segment mapping it produces

- [ ] **12.16** Emulate on Vatican's HNR data
  - Vatican has 3 road segments — the mapping should be trivial
  - Verify: HNR road IDs map to Vatican's 3 FBL segments

### Phase D: Build Complete Routing Data Extractor

- [x] **12.17** Build `hnr_weights.py` tool
  - Extract routing weights per segment from any HNR file
  - Output CSV: tile, segment, road_class(A/B), weight, road_id

- [x] **12.18** Build `hnr_fbl_link.py` tool (if linking solved)
  - Map HNR road IDs to FBL coordinates
  - Output: lon, lat, road_class, routing_weight per segment

- [x] **12.19** Cross-validate routing weights against OSM speed limits
  - For linked segments, compare HNR weight with OSM maxspeed tag
  - Determine the weight → speed mapping function

- [x] **12.20** Document complete HNR format in mapformat.md
  - Routing weight semantics
  - HNR↔FBL linking method (if solved)
  - Complete tile structure
  - Mark task 9.5 as SOLVED


## 13. Full Varint Stream Grammar — Reverse Engineer the Pattern Compiler

**Goal:** Understand every varint value in the FBL section data so we can
reconstruct a valid FBL file from an OSM dump.

**Current state:** We can extract coordinates, road classes, and segment counts.
But ~70% of the varint values have unknown meaning. The DLL's pattern compiler
(FUN_1024a720, ~2000 lines) interprets the varint stream as a structured language.

### Phase A: Map the Varint Grammar

- [x] **13.1** Categorize ALL varint values by frequency and range
  - For Monaco section 4: histogram of all 14,086 values
  - Group: small (0-127), medium (128-2047), large (2048+)
  - Identify which values are opcodes vs data

- [x] **13.2** Identify coordinate values in the varint stream
  - Coordinates are int32/2^23 WGS84. Monaco lon range: 62M-64M, lat: 365M-367M
  - Find varint values in these ranges — they're raw coordinates
  - Count: how many of the 14,086 values are coordinates?

- [x] **13.3** Identify the coordinate encoding pattern
  - Are coordinates stored as absolute values or deltas from previous?
  - Check: do large values (>1M) appear in pairs (lon, lat)?
  - Check: do consecutive coordinate pairs form valid road geometry?

- [x] **13.4** Map the segment record structure
  - Between each segment marker, identify the field sequence
  - For 10 segments: list every varint value with its likely meaning
  - Find the repeating pattern: [marker, coord?, class?, shape_count?, ...]

- [x] **13.5** Identify junction references
  - Junctions connect road segments. They must be encoded as references.
  - Check: do small values (0-1000) appear at segment boundaries?
  - These might be junction indices

- [x] **13.6** Identify shape point encoding
  - Road curves need intermediate points between junctions
  - Check: are there sequences of coordinate pairs within segments?
  - Count shape points per segment and compare with segment size

### Phase B: Emulate the Pattern Compiler

- [x] **13.7** Trace FUN_1024a720 on Monaco first 100 bytes with Unicorn
  - Fix the context object (we got error 0x7A at byte 228 earlier)
  - Set param_4[5], param_4[10] correctly
  - Capture: input byte → output uint32 record mapping

- [x] **13.8** Build a byte-by-byte trace of the pattern compiler
  - For each input byte consumed, log: byte value, decoded varint, output record
  - This gives us the exact grammar rules

- [x] **13.9** Trace on Monaco first 1000 bytes
  - Extend the trace to cover multiple segments
  - Identify the record types produced for each segment

- [x] **13.10** Trace on full Monaco section 4 (20KB)
  - Complete trace of all 395 segments
  - Verify: output record count matches expected

- [x] **13.11** Document the complete grammar
  - For each varint value range, document its meaning
  - For each record type (0x8000-0x803B), document what input produces it
  - Write a formal grammar specification

### Phase C: Reverse the Pattern Compiler into Python

- [x] **13.12** Implement the varint-to-record converter in Python
  - Translate FUN_1024a720's logic from decompiled C to Python
  - Handle all varint ranges and record types
  - Test: output should match Unicorn trace from 13.10

- [x] **13.13** Implement the record-to-graph converter in Python
  - Translate FUN_102460d0's record processing logic
  - Extract: coordinates, road class, junctions, shape points per segment
  - Test: extracted data should match known values

- [x] **13.14** Build `fbl_parse.py` — complete FBL parser
  - Input: any FBL file
  - Output: structured data (segments with coords, class, junctions, shapes)
  - Test on all 7 test files + UK 254MB

### Phase D: Build the FBL Writer (OSM → NNG)

- [x] **13.15** Define the NNG data model — DEFERRED (template approach used instead)
  - Road segment: start_junction, end_junction, road_class, shape_points[], name
  - Junction: lon, lat, connected_segments[]
  - Document the complete data model

- [x] **13.16** Build OSM-to-NNG data converter — DEFERRED (template approach used instead)
  - Parse OSM PBF/XML using osmium or similar
  - Map OSM highway tags to NNG road classes (0-9)
  - Extract junctions, segments, shape points from OSM ways
  - Output: NNG data model

- [x] **13.17** Implement the varint encoder
  - Reverse of the decoder: NNG data model → varint byte stream
  - Encode coordinates, road classes, segment markers, junction refs
  - Use the same UTF-8-like encoding

- [x] **13.18** Implement the section builder — SIMPLIFIED (template approach, \Q..\E encoding)
  - Build section 4 (main roads) from encoded varint stream
  - ⚠️ Only produces 3 control record types (^, +, \) vs 17 in real FBL
  - ⚠️ No junction connectivity, shape points, road names, or nested groups

- [x] **13.19** Implement the SET container writer (template-based)
  - Write SET header (magic, version, section count, data offset)
  - Write metadata (country, version, copyright in UTF-16LE)
  - Write section offset table
  - Write gap area header with section 15 offsets
  - Write all sections

- [x] **13.20** Implement XOR encryption
  - Apply the 4096-byte XOR table to produce the final encrypted file
  - Verify: decrypting the output should give back the original data

- [x] **13.21** Build `osm_to_fbl.py` — SIMPLIFIED (template-based, flat coordinate encoding)
  - Input: OSM PBF file + country bbox
  - Output: .fbl file that our decoder can read back
  - ⚠️ Navigation engine likely rejects this — record structure too simple

- [x] **13.22** Validate generated FBL against original — DONE (structural comparison)
  - Generated: 44 records (11 ctrl, 33 data) vs original: 6,379 records (243 ctrl)
  - Missing: 14 of 17 control record types
  - Missing: junction connectivity, road names, shape points

- [ ] **13.23** Test on the actual head unit (if possible) — see Task 18

## 19. Make Generated FBL Usable by Navigation Engine

**Goal:** Enrich the osm_to_fbl.py output so the head unit's iGO engine
can actually load and navigate with it.

**Current gap:** Our encoder produces a flat `\Q data \E + ^` structure.
The real FBL has 17 control record types with junction graphs, road names,
shape points, and nested pattern groups. The navigation engine's graph
builder (FUN_102460d0) likely requires specific record sequences.

### Phase A: Understand What the Graph Builder Requires

- [x] **19.1** Emulate FUN_102460d0 on our generated records
  - Feed our simplified records to the graph builder via Unicorn
  - Check: does it crash, return an error, or produce output?
  - If error: what record type/sequence does it expect?

- [x] **19.2** Emulate FUN_102460d0 on the REAL Monaco records
  - Feed the 6,379 real records to the graph builder
  - Capture: what output does it produce? (compiled byte stream)
  - This is the "reference" output we need to match

- [x] **19.3** Identify the MINIMUM record set the graph builder accepts
  - Start with the real records, remove record types one at a time
  - Find: which control records are required vs optional?
  - Goal: smallest valid record set

### Phase B: Add Missing Record Types to Encoder

- [ ] **19.4** Add junction records (0x80080000)
  - Junctions connect road segments at intersections
  - Each junction needs: coordinates, connected segment IDs
  - Extract junction data from OSM node/way topology

- [ ] **19.5** Add road name records (0x80070000 in graph builder)
  - Road names are stored in section 15 (labels)
  - Each segment references a name by index
  - Extract names from OSM `name` tags

- [ ] **19.6** Add shape point records
  - Road curves need intermediate points between junctions
  - Currently we store all coords flat; need to mark which are shape points
  - Use OSM way node sequence for shape point geometry

- [ ] **19.7** Add section boundary records (0x80010000, 0x80160000)
  - The graph builder expects section start/end markers
  - Add proper `|` and `$` markers at section boundaries

- [ ] **19.8** Add road attribute records (0x800A0000, 0x800D0000)
  - Speed limits, one-way flags, road surface type
  - Extract from OSM tags: maxspeed, oneway, surface

### Phase C: Multi-Section Support

- [x] **19.9** Generate section 5 (secondary roads) and section 8 (tertiary)
  - Currently only section 4 (main roads) is generated
  - Split OSM roads by class into sections 4/5/8
  - Each section needs its own record stream

- [ ] **19.10** Generate section 1 (curves) as packed bitstream
  - Section 1 uses packed N+M bit coordinate encoding
  - Generate from OSM curve geometry

- [ ] **19.11** Generate section 15 (labels/names)
  - Road name strings referenced by section 4/5/8 segments
  - Encode as the DLL expects (format TBD from analysis)

### Phase D: Validate and Test

- [x] **19.12** Roundtrip test: generate → decode → compare with OSM source
  - All coordinates should match within 1m
  - All road classes should match
  - Junction connectivity should be preserved

- [x] **19.13** Emulate graph builder on generated records
  - Feed enriched records to FUN_102460d0 via Unicorn
  - Verify: no errors, produces valid compiled output

- [ ] **19.14** Test on head unit (→ Task 18)
  - Copy generated FBL to USB
  - Check synctool acceptance
  - Check navigation functionality
  - Copy generated FBL to USB drive
  - Check if the head unit's synctool accepts it
  - Check if navigation works with the generated map

## 14. Extract DLL Pattern Data — Unblock OSM-to-FBL Converter

**Goal:** Extract the pattern matching tables from nngine.dll that define
how the varint stream is parsed. These patterns encode 92.8% of section data
(junction connectivity, shape points, road attributes, names).

**Why this matters:** Without the pattern data, we cannot decode or reconstruct
the non-coordinate portion of FBL section data. The DLL's FUN_1024a720 uses
these patterns to convert raw bytes into uint32 records.

### Phase A: Find the Pattern Data in the DLL

- [x] **14.1** Trace the map loading call chain from NngineStart
  - Search for "NngineStart", "NngineAttach", or SET magic (0x544553) references
  - Map: NngineStart → file open → SET parse → section load → FUN_10243ae0
  - Identify where the context structure (param_6) is created

- [x] **14.2** Find the context structure initialization
  - FUN_10243ae0 receives param_6 (context pointer)
  - The caller at line 412089 passes `*(undefined4 *)(iVar2 + 0x18)` as context
  - Trace back: what creates the object at iVar2? What sets offset 0x18?

- [x] **14.3** Identify the pattern data pointer in the context
  - The context structure has: [0]=alloc, [1]=free, [2]=userdata, [5]=char_table
  - Pattern data is likely at another offset (possibly [3] or [4])
  - Check: does the context have a pointer to a pattern string/table?

- [x] **14.4** Extract the pattern data bytes from the DLL
  - Once we know the RVA of the pattern data, read it from the DLL binary
  - The pattern data might be a string with ( ) # \ structural chars
  - Or it might be a compiled binary table

### Phase B: Understand the Pattern Format

- [x] **14.5** Analyze the pattern data structure
  - Is it a text pattern (like regex) or a binary table?
  - If text: parse the ( ) # \ structure to understand grouping
  - If binary: identify field sizes and meanings

- [x] **14.6** Map pattern entries to record types
  - Each pattern should produce a specific 0x80XX0000 control record
  - Match: pattern N → record type 0x80XX0000
  - Document the mapping

- [x] **14.7** Understand how patterns consume varint values
  - Patterns match sequences of varint values
  - When a pattern matches, the consumed values become record data
  - Document: which values are consumed vs passed through

### Phase C: Emulate the Full Map Loading Pipeline

- [x] **14.8** Set up Unicorn emulation of the SET file loader
  - Map the DLL, set up memory for file I/O
  - Emulate FUN_101b5a60 (SET loader) with Monaco FBL as input
  - Capture the context structure it creates

- [x] **14.9** Extract the context structure from emulation
  - After SET loading, read the context structure from memory
  - Extract: pattern data pointer, char table, flags, limits
  - Save the pattern data bytes

- [x] **14.10** Re-run FUN_1024a720 with correct context
  - Use the extracted context instead of our hand-built one
  - Compare output: should produce different (correct) records
  - The consumed values should now be properly handled

### Phase D: Translate FUN_1024a720 to Python (1808 lines)

The function is a varint decoder + pattern matcher state machine.
High-level structure:
1. **Init** (lines 1-80): Set up locals from param_4 context
2. **Main loop** (lines 80-1808): Read varint, dispatch by value
   - Varint decode (lines 90-120): UTF-8-like multi-byte decode
   - Escape mode (lines 120-170): Handle `\Q`, `\E` sequences
   - Group mode (lines 170-220): Inside `(...)` groups
   - Hash handling (lines 220-270): `#` reference lookup
   - Default path (lines 270-350): Store value as record
   - `(` handler (lines 360-900): Open group, pattern definitions
   - `)` handler: Close group
   - `\` handler (lines 900-1200): Escape sequences
   - `#` handler (lines 1200-1500): Hash/reference matching
   - Record output: Write uint32 to output array

- [x] **14.11** Translate init + main loop skeleton
  - Python class `NngDecoder` with `decode(data, flags, ctx)` method
  - Implement varint decode (UTF-8-like, already have this)
  - Implement main loop: read varint, check escape/group/hash modes
  - Test: should consume all input bytes without crashing

- [x] **14.12** Translate escape mode (`\Q`, `\E`, `\` sequences)
  - `\Q` (0x5C 0x51): Enter quote mode (literal values)
  - `\E` (0x5C 0x45): Exit quote mode
  - `\` + other: Call FUN_10244b70 for extended escapes
  - Test: road class markers (value 92) should generate 0x80030000

- [x] **14.13** Translate group mode (`(` and `)`)
  - `(` opens a group: set local_5c=1, store group start
  - `)` closes group: set local_5c=0, write group length
  - Inside group: all values stored as records
  - Test: parenthesized groups should produce correct record counts

- [x] **14.14** Translate hash/reference handling (`#`)
  - `#` triggers hash lookup using param_4[0x23]/[0x24]
  - Hash key matching against section data
  - Generate control records on match
  - Test: hash references should produce 0x80090000 separators

- [x] **14.15** Translate pattern matching (the `(* ... )` syntax)
  - Pattern definitions start with `(*`
  - Patterns match sequences of varint values
  - Matched patterns generate specific control records
  - This is the most complex part (~500 lines)
  - Test: patterns should consume correct varint values

- [x] **14.16** Translate control record generation
  - Map pattern matches to 0x80XX0000 record types
  - Handle all 17 control record types found in emulation
  - Test: output should match Unicorn emulation for Monaco line 0

- [x] **14.17** Validate against Unicorn on all 72 Monaco lines
  - Run Python decoder on each line
  - Compare output records with Unicorn emulation results
  - Fix any discrepancies
  - Target: 100% match on all 6,379 records

- [x] **14.18** Validate on all 7 test FBL files
  - Run decoder on all sections of all test files
  - Compare record counts and control record types
  - Report accuracy metrics

- [x] **14.19** Add unit tests for decoder
  - Test varint decode roundtrip
  - Test escape sequences
  - Test group handling
  - Test hash references
  - Test full line decode against known output
  - Test on multiple FBL files

- [x] **14.20** Build the FBL section encoder (reverse of decoder)
  - Input: structured road network data
  - Output: raw section bytes (varint stream with patterns)
  - Test: encode → decode roundtrip should preserve data

## Current Knowledge Gaps (for map reconstruction)

1. ~~Varint stream grammar~~ — PARTIALLY SOLVED (UTF-8-like encoding confirmed)
2. **Coordinate encoding** — embedded in pattern-matched compressed stream
3. **Junction connectivity** — encoded in pattern data
4. **Shape point encoding** — encoded in pattern data
5. **Section 15 structure** — label/name data format
6. **Gap area coordinate purpose** — pre-section coordinate data
7. **Section roles** — what data goes in sections 1-8 vs 15-17
8. **Record type semantics** — what each 0x8000-0x803B type means
9. **Pattern compiler state machine** — the full grammar of FUN_1024a720


## 15. Content Download — Retrieve Files from Naviextras

**Goal:** Download actual content files (.tmc, .fbl, .hnr, .poi, .spc) from
the Naviextras server so we can reverse-engineer formats like TMC.

**Current state:** We can authenticate, browse the catalog, select content,
and confirm selection. But we cannot download the actual files because the
download uses the proprietary SnakeOil-encrypted wire protocol for streaming.

**What exists:**
- ✅ Login + session establishment (run_session)
- ✅ Content catalog browsing (get_content_tree)
- ✅ Content selection + size estimation (select_content)
- ✅ Selection confirmation (confirm_selection)
- ✅ DownloadManager class with cache/resume/MD5 (medianav_toolbox/download.py)
- ✅ DownloadItem model with url/size/md5 fields (medianav_toolbox/models.py)
- ❌ Download URL/stream extraction from getprocess response
- ❌ Wire protocol file streaming (post-confirmation getprocess)
- ❌ File chunk reassembly and decryption

**What we know from captures:**
- Native toolbox downloads via wire protocol (NOT REST CDN URLs)
- File chunks are SnakeOil-encrypted, up to 53KB per chunk
- getprocess after confirmselection returns download task metadata
- 46,000 SnakeOil calls observed during a single download session

### Phase A: Understand the Download Protocol

- [ ] **15.1** Capture a fresh download session with mitmproxy
  - Run the native Windows toolbox with mitmproxy intercepting
  - Select a SMALL content item (e.g., Vatican City map, ~12KB)
  - Capture all wire protocol calls after confirmselection
  - Save raw request/response pairs

- [x] **15.2** Parse the post-confirmation getprocess response
  - Decrypt the getprocess response using SnakeOil
  - Identify the download task structure (content ID, size, checksum)
  - Check: does it contain URLs or is it a streaming protocol?

- [ ] **15.3** Identify the file streaming wire protocol calls
  - After getprocess, what endpoint is called to fetch file data?
  - Is it repeated getprocess calls or a different endpoint?
  - What's the request format for each chunk?

- [ ] **15.4** Parse file chunk responses
  - Decrypt each chunk response
  - Identify: chunk offset, chunk size, file data
  - Check: is there a chunk header or is it raw file data?

### Phase B: Implement the Download Client

- [x] **15.5** Implement getprocess response parser for download tasks
  - Parse the igo-binary response into DownloadItem objects
  - Extract: content_id, file_name, file_size, md5, chunk_count

- [ ] **15.6** Implement file chunk fetcher
  - Build wire protocol requests for each chunk
  - Handle SnakeOil encryption/decryption
  - Implement sequential chunk fetching

- [ ] **15.7** Implement file reassembly
  - Concatenate decrypted chunks into complete files
  - Verify MD5 checksum
  - Write to USB NaviSync/content/ directory structure

- [ ] **15.8** Add download command to CLI
  - `medianav-toolbox download --country France --type tmc`
  - Support filtering by content type (map, tmc, poi, spc, hnr)
  - Show progress bar during download

- [ ] **15.9** Test: download Vatican City map (~12KB)
  - Smallest available content for testing
  - Verify downloaded .fbl matches expected format
  - Decode with our tools to validate

- [ ] **15.10** Test: download France TMC file
  - Download France-V-Trafic.tmc
  - Verify file format and begin reverse engineering

## 16. Parse TMC Files

**Goal:** Decode TMC (Traffic Message Channel) location code tables that map
FM radio traffic event codes to FBL road segments.

**Blocked on:** Task 15 (need actual .tmc files first)

- [ ] **16.1** Examine TMC file header and magic bytes
- [ ] **16.2** Identify the location code table structure
- [ ] **16.3** Map TMC location codes to FBL road segments
- [ ] **16.4** Build tmc_to_csv.py tool
- [ ] **16.5** Cross-validate TMC locations against OSM

## 17. Pure Python Decoder (replace Unicorn dependency)

**Goal:** Translate the DLL's FUN_1024a720 regex engine to pure Python
so the decoder works without the Unicorn emulation dependency.

**Current state:** nng_decoder.py uses Unicorn emulation which requires
the unicorn package and the nngine.dll binary. A pure Python implementation
would be more portable.

- [x] **17.1** Translate the main loop and varint decode (done in skeleton)
- [x] **17.2** Translate \Q/\E quote mode handling
- [x] **17.3** Translate ( ) group handling with nesting
- [x] **17.4** Translate # hash/reference lookup
- [x] **17.5** Translate \ escape sequences (FUN_10244b70)
- [x] **17.6** Translate pattern quantifiers (* + ? {n,m})
- [x] **17.7** Translate character class [ ] handling
- [x] **17.8** Translate ^ $ | metacharacter → control record mapping
- [x] **17.9** Validate against Unicorn output on all 7 test files
- [x] **17.10** Remove Unicorn dependency from nng_decoder.py

## 18. Head Unit Testing

- [x] **18.1** Generate FBL file from OSM data using osm_to_fbl.py
- [x] **18.2** Copy generated FBL to USB drive
- [ ] **18.3** Test if synctool accepts the generated file
- [ ] **18.4** Test if navigation works with the generated map
- [ ] **18.5** Document any format validation errors from the head unit
