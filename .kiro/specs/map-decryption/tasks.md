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
- [ ] **9.5b** HNR↔FBL segment linking — BLOCKED → REOPENED
  - **What:** Link HNR routing data (major/minor per segment) to FBL map coordinates
  - **Previous attempts that failed:** Direct ID matching, hash functions, spatial keys
  - **New opportunity:** We now have road class for 99% of FBL segments via forward-fill.
    This enables matching by road class distribution per geographic area.

  - [ ] **9.5b.1** Count FBL segments per road class for ALL 30 countries
    - Extract the full disk backup, decrypt each FBL file
    - Run fbl_road_class.py --inherit on each
    - Output: country, total_segments, motorway, trunk, primary, ..., pedestrian

  - [ ] **9.5b.2** Count HNR type-A segments per tile
    - Type A = major roads. Count per tile gives a "major road density" per tile.
    - Output: tile_index, a_count, b_count, a_ratio

  - [ ] **9.5b.3** Estimate FBL "major road" count per country
    - From 9.5b.1: count segments with road class 0-3 (motorway/trunk/primary/secondary)
    - These are the "major" roads that should correspond to HNR type A

  - [ ] **9.5b.4** Match HNR tiles to countries by major road count
    - For each country, find the set of HNR tiles whose combined A-count
      matches the country's major road count
    - Small countries (Vatican, Monaco) should match 1-2 tiles
    - Large countries (France, Germany) should match many tiles

  - [ ] **9.5b.5** Verify matching using total segment counts
    - For matched tiles: total HNR segments (A+B) × 64 should approximate
      total FBL segments × some ratio
    - The ratio should be consistent across countries

  - [ ] **9.5b.6** Try matching by segment SIZE distribution
    - FBL segments have sizes (2-587 bytes). Larger = more important road.
    - HNR type A entries might correspond to larger FBL segments
    - Compare: FBL segment size distribution for major vs minor roads
      with HNR A vs B block sizes

  - [ ] **9.5b.7** Use geographic bbox to narrow tile candidates
    - Each FBL file has a bbox (lon/lat range)
    - HNR tiles cover geographic areas (we know tile size ~0.78°)
    - Compute which tiles COULD contain each country based on bbox overlap

  - [ ] **9.5b.8** Try matching by segment ORDER within tiles
    - If HNR entries within a tile are ordered the same as FBL segments
      within a country, we can match by position
    - Compare: first N entries of an HNR tile with first N FBL segments
    - Check if road class (major/minor) matches A/B block assignment

  - [ ] **9.5b.9** Use the FBL section 15 offsets as region boundaries
    - The FBL header has 7 uint24 offsets into section 15
    - These might divide the country into regions
    - Each region might correspond to one HNR tile

  - [ ] **9.5b.10** Build a segment-level matcher using road class + position
    - For a matched tile-country pair:
      - Sort FBL segments by byte offset (= geographic order)
      - Sort HNR entries by position within tile
      - Match: FBL major road segments ↔ HNR type A entries
      - Match: FBL minor road segments ↔ HNR type B entries
    - Verify by checking if matched segments have consistent properties

  - [ ] **9.5b.11** Validate linking on Vatican (3 segments)
    - Vatican is the simplest case — only 3 road segments
    - Find which HNR tile(s) contain Vatican's segments
    - Verify: the 3 HNR entries should match Vatican's 3 FBL segments

  - [ ] **9.5b.12** Validate linking on Monaco (395 segments)
    - Monaco is small enough to verify manually
    - Check: do the matched HNR entries have the right A/B classification
      for Monaco's road classes?

  - [ ] **9.5b.13** Build `hnr_fbl_link.py` tool
    - Input: FBL file + HNR file
    - Output: CSV with lon, lat, fbl_road_class, hnr_block_type (A/B)
    - Test on Vatican, Monaco, Andorra

  - [ ] **9.5b.14** Validate on Andorra (motorway CG-1)
    - Andorra has a known motorway (CG-1)
    - The motorway segments should be in HNR type A blocks
    - Verify: linked motorway segments have A classification

  - [ ] **9.5b.15** Document the linking method in mapformat.md
    - Describe the matching algorithm
    - Report accuracy metrics
    - Mark 9.5b as SOLVED
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

  - [ ] **F4.3** Check if segment size correlates with inherited road class
    - Large segments (>200B) should be major roads
    - Small segments (<20B) should be local roads
    - If inherited class matches size pattern, the inheritance is correct

  - [ ] **F4.4** Check the DLL's graph builder for inheritance logic
    - In FUN_102460d0, `local_b0` holds the current road class value
    - It's set by 0x8003 records and persists across segments
    - Trace: does `local_b0` reset between segments or carry forward?

  - [ ] **F4.5** Check if the varint value AFTER the segment marker encodes class
    - Segment markers (6, 98-103) have a payload value
    - The payload might be a road class index or a reference to a class table
    - Compare payload values with known road classes from value-92 markers

  - [ ] **F4.6** Check if the section number implies road class
    - Sections 4, 5, 8 might correspond to different road importance levels
    - Extract segments from sections 5 and 8 separately
    - Compare road class distribution across sections

  - [ ] **F4.7** Use Unicorn to emulate the graph builder on a small section
    - Feed Monaco section 4 (first 1000 bytes) to FUN_102460d0
    - Hook the 0x8003 handler to capture road class assignments
    - Track which segments get which class (including inherited ones)

  - [x] **F4.8** Implement the inheritance logic in Python
    - Based on findings from F4.1-F4.7
    - Assign road class to ALL segments (not just those with explicit markers)
    - Verify: classified segment count should be close to total segment count

  - [ ] **F4.9** Validate full classification against OSM
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

- [ ] **12.1** Extract routing weights for ALL segments in first 100 HNR tiles
  - Parse Economic and Fastest files
  - For each segment: extract byte 0 (base), byte 1 (weight), byte 3 (road ID)
  - Output as CSV for analysis

- [ ] **12.2** Compare Economic vs Fastest weights for the same segments
  - First 1000 aligned records have identical byte 3 (road ID)
  - Compute: weight_diff = Fastest.byte1 - Economic.byte1 per segment
  - Check: does weight_diff correlate with road class (from A/B block type)?

- [ ] **12.3** Check if routing weights correlate with known speed limits
  - European motorways: 130 km/h, trunk: 90-110, residential: 30-50
  - If weight = speed: type A (major) should have higher weights
  - If weight = cost: type A should have LOWER weights
  - Statistical test: mean weight for type A vs type B

- [ ] **12.4** Check if weights have temporal patterns
  - If HNR encodes time-of-day profiles, consecutive segments in same tile
    might have correlated weights (rush hour vs off-peak)
  - Autocorrelation analysis within tiles

- [ ] **12.5** Extract the Shortest variant's format
  - Shortest uses different encoding (counts don't fit >>8 pattern)
  - Decode the Shortest header and count table
  - Compare record structure with Economic/Fastest

### Phase B: Link HNR Road IDs to FBL Segments

- [ ] **12.6** Extract road class markers (value 92) from FBL with byte offsets
  - For each road class marker, record its byte position in the section
  - This gives us: (byte_offset, road_class) pairs for each FBL file

- [ ] **12.7** Extract segment boundaries from FBL with byte offsets
  - Segment markers (values 6, 98-103) with byte positions
  - This gives us: (byte_offset, segment_index) pairs

- [ ] **12.8** Compute segment byte ranges in FBL
  - Each segment spans from its marker to the next marker
  - Compute: (segment_index, start_byte, end_byte, road_class) per segment

- [ ] **12.9** Check if FBL segment count matches HNR segment count per tile
  - FBL has per-country segment counts (Monaco=395, Andorra=1440)
  - HNR has per-tile segment counts (192 tiles × 64 segments)
  - Check: does sum of HNR segments for a country's tiles = FBL segment count?

- [ ] **12.10** Try matching by segment COUNT per region
  - If HNR tile X has N segments and FBL country Y has N segments in a region,
    they might correspond
  - Use the FBL header offsets (7 pointers into section 15) as region boundaries

- [ ] **12.11** Use the FBL spatial index key format to generate candidate IDs
  - FBL key = (tile_index << 23) | sequential_counter
  - Generate all possible keys for a small country (Vatican/Monaco)
  - Check if any transformation of these keys matches HNR road IDs

- [ ] **12.12** Try XOR/hash of FBL key with DLL constants
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

- [ ] **12.17** Build `hnr_weights.py` tool
  - Extract routing weights per segment from any HNR file
  - Output CSV: tile, segment, road_class(A/B), weight, road_id

- [ ] **12.18** Build `hnr_fbl_link.py` tool (if linking solved)
  - Map HNR road IDs to FBL coordinates
  - Output: lon, lat, road_class, routing_weight per segment

- [ ] **12.19** Cross-validate routing weights against OSM speed limits
  - For linked segments, compare HNR weight with OSM maxspeed tag
  - Determine the weight → speed mapping function

- [ ] **12.20** Document complete HNR format in mapformat.md
  - Routing weight semantics
  - HNR↔FBL linking method (if solved)
  - Complete tile structure
  - Mark task 9.5 as SOLVED
