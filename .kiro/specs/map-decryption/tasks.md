# Tasks: NNG Map Format — Reverse Engineering & OSM Conversion

> 157 completed, 46 open | [Format docs](../../docs/mapformat.md) | [Tools](../../tools/maps/)

---

## Completed ✅ (157 tasks)

All completed tasks from the original reverse engineering effort:

- **Tasks 1–8**: Header analysis, XOR decryption, SET container, coordinate encoding,
  speed cameras, license decryption, section data format, packed bitstreams
- **Task 9**: Multi-format parsing (FBL, FPA, POI, SPC, HNR), road class extraction,
  gap area decoding, HNR routing format, section roles
- **Task 9.5b**: HNR↔FBL segment linking (10 countries, segment-level matcher)
- **Tasks 10–11**: DLL parser emulation, road class lookup table, varint decoder
- **Task 12**: HNR routing weights (binary A/B), HNR↔FBL count ratios
- **Task 13**: Varint grammar, Unicorn emulation, FBL parser, varint encoder,
  XOR encryption, SET container writer, OSM-to-FBL converter
- **Task 14**: DLL pattern data extraction, character class table, context structure,
  record stream analysis, full pipeline emulation
- **Task 17**: Pure Python decoder (67–74% accuracy, no Unicorn dependency)
- **Task 18.1–18.2**: Generated Monaco FBL from real OSM data, copied to USB
- **Task 19.1–19.3, 19.9, 19.12–19.13**: Graph builder validation, minimum record set

**24 tools built**, **318 tests passing**, **1,842 lines of format documentation**.

---

## Open Tasks

### FBL Enrichment — Make Generated Maps More Complete

These improve the FBL output from osm_to_fbl.py. The basic format works
(graph builder accepts it) but richer data improves navigation quality.

**Junction Connectivity (19.4)**
- [x] **19.4a** Identify shared nodes between OSM ways (intersection detection)
- [x] **19.4b** Assign junction IDs to shared nodes
- [ ] **19.4c** Encode junction records (0x80080000 | junction_id) in section data
- [ ] **19.4d** Update network_to_records() to emit junction records between segments
- [ ] **19.4e** Verify graph builder accepts junction records
- [ ] **19.4f** Test: two roads sharing a node should produce a junction record

**Road Names (19.5 + 19.11)**
- [ ] **19.5a** Extract unique road names from OSM `name` tags
- [ ] **19.5b** Build name index (name → integer ID)
- [ ] **19.5c** Encode name strings for section 15 (determine encoding from real FBL)
- [ ] **19.5d** Emit name reference records in section 4/5/8 segment data
- [ ] **19.5e** Generate section 15 bytes and update section offset table
- [ ] **19.5f** Verify graph builder accepts name records

**Shape Points (19.6)**
- [ ] **19.6a** Identify junction nodes vs intermediate nodes in OSM ways
  - Junction = node shared by 2+ ways; intermediate = only in 1 way
- [ ] **19.6b** Split OSM ways at junctions into road segments
  - Each segment: junction → intermediate nodes → junction
- [ ] **19.6c** Encode shape points (intermediate coords) separately from junction coords
- [ ] **19.6d** Update network_to_records() to mark shape points vs junctions
- [ ] **19.6e** Test: a curved road should have shape points between its junctions

**Section Boundaries (19.7)**
- [ ] **19.7a** Analyse real FBL to find where 0x80010000/0x80160000 appear
- [ ] **19.7b** Determine what triggers section boundaries (geographic tiles? road groups?)
- [ ] **19.7c** Add boundary records to encoder
- [ ] **19.7d** Verify graph builder accepts boundary records

**Road Attributes (19.8)**
- [ ] **19.8a** Extract speed limits from OSM `maxspeed` tag → integer km/h
- [ ] **19.8b** Extract one-way from OSM `oneway` tag → boolean
- [ ] **19.8c** Extract surface type from OSM `surface` tag
- [ ] **19.8d** Determine how attributes are encoded in real FBL records
  - Analyse 0x800A0000 and 0x800D0000 records from Unicorn trace
- [ ] **19.8e** Add attribute records to encoder
- [ ] **19.8f** Test: a one-way street should produce a one-way attribute record

**Curve Data — Section 1 (19.10)**
- [ ] **19.10a** Analyse real section 1 packed bitstream format
  - Already know: N+M bit coordinate pairs relative to bbox
- [ ] **19.10b** Extract curve geometry from OSM ways (roads with many intermediate nodes)
- [ ] **19.10c** Encode as packed bitstream with correct bit widths
- [ ] **19.10d** Write section 1 data and update section offset table in fbl_builder.py
- [ ] **19.10e** Verify section 1 decodes correctly with fbl_to_geojson.py

### Generate Supporting Map Files from OSM

A complete map update needs more than just FBL road data.

**HNR — Routing Data**
- [ ] **20.1** Document HNR tile generation requirements
  - Format already decoded: 256-byte tiles, 64 entries, A/B major/minor blocks
- [ ] **20.2** Build osm_to_hnr.py — generate HNR from OSM highway classifications
- [ ] **20.3** Validate generated HNR against original

**POI — Points of Interest**
- [ ] **20.4** Document POI generation requirements
  - Format already decoded: XOR encryption, uint16 coord pairs, byte×2 names
- [ ] **20.5** Build osm_to_poi.py — generate POI from OSM amenity/shop/tourism tags
- [ ] **20.6** Validate generated POI against original

**SPC — Speed Cameras**
- [ ] **20.7** Document SPC generation requirements
  - Format already decoded: 12-byte records (lon, lat, flags, speed, type)
- [ ] **20.8** Build osm_to_spc.py — generate SPC from OSM enforcement data
- [ ] **20.9** Validate generated SPC against original

### TMC — Traffic Message Channel

UK TMC data (Inrix) is proprietary. Use publicly available tables instead.
France, Germany, Belgium, Italy, Spain, Sweden, Norway, Finland publish theirs.

- [ ] **16.1** Download France TMC location code list (public, free)
  - Source: http://diffusion-numerique.info-routiere.gouv.fr/tables-alert-c-a4.html
- [ ] **16.2** Parse the ISO 14819-3 format (points, lines, areas with coordinates)
- [ ] **16.3** Build tmc_locations.py — query TMC codes → coordinates
- [ ] **16.4** Match TMC locations to FBL road segments using coordinates
- [ ] **16.5** Validate against cached traffic events in trafficevents_A.txt
  - We have: `cc=12 ltn=10 loc=17602 event_1=807` (France, location 17602)
- [ ] **16.6** Build tmc_to_fbl.py — generate NNG .tmc file from public data

### Content Download from Naviextras

Download actual content files via the wire protocol. Currently blocked:
server won't offer files because device is already up to date.

- [ ] **15.1** Capture a fresh download session (needs device with older maps)
- [ ] **15.3** Identify the file streaming wire protocol calls
- [ ] **15.4** Parse file chunk responses
- [ ] **15.6** Implement file chunk fetcher
- [ ] **15.7** Implement file reassembly
- [ ] **15.8** Test: download a small content item

**Already built:** Manifest parser (160 entries from captured data),
getprocess polling loop, download CLI command. Needs live API test.

### Head Unit Testing

Requires physical Dacia MediaNav head unit.

- [ ] **18.3** Test if synctool accepts the generated FBL file
- [ ] **18.4** Test if navigation works with the generated map
- [ ] **18.5** Document any format validation errors from the head unit

### Low Priority / Blocked

**HNR DLL Emulation** — No HNRF magic found in nngine.dll. Low value
since road class is already extracted from FBL directly.

- [ ] **12.13** Find the DLL function that loads HNR files
- [ ] **12.14** Find the function that maps HNR road IDs to FBL segments
- [ ] **12.15** Emulate the HNR loader on a small tile
- [ ] **12.16** Emulate on Vatican's HNR data

---

## Key Files

| File | Purpose |
|------|---------|
| `tools/maps/osm_to_fbl.py` | OSM → FBL converter (main tool) |
| `tools/maps/fbl_builder.py` | Build FBL from scratch (no template) |
| `tools/maps/nng_decoder.py` | Decode FBL sections (pure Python default) |
| `tools/maps/nng_decoder_python.py` | Pure Python decoder (67–74% accuracy) |
| `tools/maps/fbl_road_class.py` | Road class extraction |
| `tools/maps/xor_key.bin` | 4096-byte XOR encryption key |
| `docs/mapformat.md` | Complete format specification (1,842 lines) |
