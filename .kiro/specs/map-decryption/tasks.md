# Tasks: NNG Map File Decryption

> Requirements: [requirements.md](requirements.md) | Design: [design.md](design.md)

## Phase 1: Header Analysis

- [ ] **1.1** Extract small test files from `disk-backup-with-map-Apr2026.zip`
  - Vatican_osm.fbl (11 KB), Vatican_osm.fpa (1.5 KB), Andorra_osm.spc (450 B)
  - Monaco_osm.fbl (53 KB), Monaco_osm.fpa (5 KB)
  - France_osm.fbl (first 1 KB only — for header comparison)
- [ ] **1.2** Build `tools/maps/analyse_header.py`
  - Read first 64 bytes of each extracted file
  - Output comparison table: offset, FBL value, FPA value, constant/variable
  - Identify the header structure (magic, type field, size field, encrypted payload start)
- [ ] **1.3** Check if file sizes are 8-byte or 16-byte aligned (block cipher indicator)
- [ ] **1.4** Document findings in `docs/mapformat.md`

## Phase 2: Try Known Keys

- [ ] **2.1** Extract the XOR-CBC key from a `.lyc` license file
  - RSA-decrypt `LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc`
  - Extract bytes 8-24 from the 40-byte header
  - Document the key value
- [ ] **2.2** Build `tools/maps/try_lyc_key.py`
  - Try XOR-CBC decrypt on `Vatican_osm.fbl` with the .lyc key
  - Try SnakeOil decrypt with magic bytes as uint64 seed
  - Try SnakeOil decrypt with tb_secret, hu_secret as seeds
  - Try Blowfish decrypt with the known DLL Blowfish key
  - For each attempt: measure Shannon entropy, check for ASCII strings
  - Report which (if any) produces structured output
- [ ] **2.3** If a key works: verify on 3+ other files (different countries, different types)
- [ ] **2.4** If no key works: proceed to Phase 3

## Phase 3: DLL Analysis (only if Phase 2 fails)

- [ ] **3.1** Search `nngine.dll` for magic bytes `f9 6d 4a 16 6f c5 78 ee`
  - Check .rdata and .data sections
  - Find all cross-references to the magic
- [ ] **3.2** Identify the file-open/validate function
  - Should read the 8-byte magic, validate, then call decryption
- [ ] **3.3** Trace the decryption function
  - Identify cipher (AES? XOR-CBC? SnakeOil? Blowfish? custom?)
  - Identify block size and mode
- [ ] **3.4** Trace the key source
  - Where does the key come from? (.lyc? device.nng? hardcoded? content_id-derived?)
- [ ] **3.5** Document the complete algorithm

## Phase 4: Implement Decryption

- [ ] **4.1** Implement `tools/maps/decrypt_fbl.py`
  - Input: encrypted file + key material
  - Output: decrypted file
  - Verify: entropy < 7.0, recognisable strings present
- [ ] **4.2** Verify on all file types: .fbl, .fpa, .hnr, .poi, .spc
- [ ] **4.3** Write tests with known input/output pairs

## Phase 5: Parse and Export

- [ ] **5.1** Analyse decrypted `.fbl` header structure
- [ ] **5.2** Identify coordinate encoding
- [ ] **5.3** Cross-reference with OSM data for Vatican (smallest, easiest to verify)
- [ ] **5.4** Build `tools/maps/fbl_info.py` — show bounding box, road count, stats
- [ ] **5.5** Build `tools/maps/spc_to_csv.py` — speed cameras to CSV
- [ ] **5.6** Build `tools/maps/fbl_to_geojson.py` — road network to GeoJSON

## Current Status

**Not started.** First task is 1.1 — extract test files from the zip.

## Documentation Rule

**Keep [`docs/mapformat.md`](../../docs/mapformat.md) up to date as findings are made.**
Every completed task that reveals new information about the format, encryption, keys,
or internal structure must be documented there before moving to the next task.
`mapformat.md` is the single source of truth for the map file format.
