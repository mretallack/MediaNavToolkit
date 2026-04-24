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
- [x] **5.4** `tools/maps/fbl_info.py` — metadata, bbox, country, version, copyright
- [x] **5.5** `tools/maps/spc_to_csv.py` — speed cameras to CSV (coordinates + speed)

## Blocked ❌

- [ ] **Shape data decryption** — second encryption layer (Blowfish), master key from head unit config
- [ ] **5.6** `tools/maps/fbl_to_geojson.py` — needs shape data decryption for full road geometry

## Can Do Now 🔧

- [ ] **6.1** Extract ALL speed cameras from the full disk backup
  - Extract all `.spc` files from `disk-backup-with-map-Apr2026.zip`
  - Run `spc_to_csv.py` to produce a complete speed camera database
  - Expected: ~20 countries × 10-100 cameras each
- [ ] **6.2** Build `tools/maps/lyc_decrypt.py` — decrypt .lyc license files
  - RSA decrypt (skip 8-byte header, use byte-reversed modulus)
  - XOR-CBC decrypt remaining data with key from RSA payload
  - Output: SWID, product name, activation data per license
- [ ] **6.3** Build `tools/maps/junctions_to_geojson.py`
  - Scan decrypted .fbl for full int32 coordinate pairs
  - Filter to valid coordinates within the bounding box
  - Output GeoJSON FeatureCollection of points
  - Verify against OSM for Vatican (smallest, easiest to check)
- [ ] **6.4** Build `tools/maps/segments_to_csv.py`
  - Parse the 12-byte segment metadata between junction coordinates
  - Output: from_lon, from_lat, to_lon, to_lat, road_type, shape_count
- [ ] **6.5** Build `tools/maps/map_overview.py`
  - Run fbl_info on all files in a directory or zip
  - Output summary table: country, type, version, size, bbox

## Documentation Rule

**Keep [`docs/mapformat.md`](../../docs/mapformat.md) up to date as findings are made.**
