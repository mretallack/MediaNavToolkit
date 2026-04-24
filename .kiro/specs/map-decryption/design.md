# Design: NNG Map File Decryption

> Requirements: [requirements.md](requirements.md) | Map format reference: [../../docs/mapformat.md](../../docs/mapformat.md)

## Architecture

All tools live in `tools/maps/` and are standalone Python scripts (no package install needed).

```
tools/maps/
├── README.md                # Usage docs
├── testdata/                # Extracted test files (gitignored)
│
│ ── Completed ──
├── analyse_header.py        # ✅ Compare headers across map files
├── try_lyc_key.py           # ✅ Try known keys on encrypted map data
├── decrypt_fbl.py           # ✅ Decrypt map files (outer XOR layer)
├── fbl_info.py              # ✅ Show map file metadata, bbox, version
├── spc_to_csv.py            # ✅ Export speed cameras to CSV
├── lyc_decrypt.py           # ✅ Decrypt .lyc licenses → SWID, product name
├── junctions_to_geojson.py  # ✅ Extract road junction coordinates as GeoJSON
├── segments_to_csv.py       # ✅ Extract road segment metadata to CSV
├── curves_to_geojson.py     # ✅ Extract curve points from section 1 bitstream
├── map_overview.py          # ✅ Show all countries with bbox, version, sizes
│
│ ── To Build ──
└── fbl_to_geojson.py        # Combine junctions + curves into road LineStrings
```

## What We Can Do With Decrypted Data

**Speed cameras** — fully parsed. Coordinates + speed limits for all 30 countries.
Can be exported to CSV, loaded into GPS apps, or used for analysis.

**Road junction coordinates** — the network topology (which roads connect where)
is accessible as full int32 coordinate pairs. Can be exported as GeoJSON points.

**Road curve points** — the shape of roads between junctions is decoded from the
section 1 bitstream. Uses packed [N-bit lon][M-bit lat] encoding relative to the
bounding box, with bit widths derived from `ceil(log2(bbox_range + 1))`.
Verified on Vatican (59 pts), Monaco (116 pts), Andorra (295 pts).

**Road segment metadata** — road type/speed class and shape point counts per segment.
Useful for understanding the road network structure.

**License content** — SWIDs, product names, activation data from all .lyc files.

**Map metadata** — country, version, bounding box, copyright, build info for every file.

## Investigation Strategy — COMPLETE ✅

All three approaches were executed:

- **Approach A (Try .lyc key):** Tested — .lyc XOR-CBC keys don't decrypt section data
- **Approach B (Trace in DLL):** Completed — found XOR table, Blowfish (for licenses only), SET reader
- **Approach C (Known-plaintext):** Not needed — XOR table decryption revealed SET format directly

## Encryption — RESOLVED ✅

The map files use a **single XOR table** (4096 bytes, hardcoded in `nngine.dll`) for
the outer encryption layer. This is the same table used for `device.nng` decryption.

```
plaintext[i] = ciphertext[i] XOR xor_table[i % 4096]
```

After XOR decryption, the file structure is:
- **SET header** (32 bytes): magic `SET\x00`, version, data offset, file size
- **Latin padding** (480 bytes): Cicero quote filler
- **UTF-16LE metadata**: country, version, copyright, build info
- **Country block**: 3-byte code + bounding box (int32 / 2^23 = WGS84)
- **Section offset table**: uint32 offsets to each data section
- **Pre-section data**: index tables, road topology
- **Sections 0-18**: geometry, coordinates, metadata, bulk data

**Curve data (section 1)** is NOT encrypted — it uses a packed bitstream encoding.
**Section 16 (bulk data)** has high entropy (~7.97) — likely compressed, not encrypted.
The Blowfish code in the DLL is for license key management, not map data.

### Previous Hypotheses (All Tested)

| Hypothesis | Result |
|-----------|--------|
| XOR-CBC with .lyc key | ❌ Doesn't decrypt sections |
| SnakeOil with magic seed | ❌ No entropy reduction |
| Blowfish with DLL key | ❌ For license keys only |
| AES/device-specific key | ❌ Not needed — XOR table suffices |

The XOR table was the only encryption layer. The high entropy in larger file sections
is due to compression (efficient bitstream packing), not additional encryption.

## Data Available for Analysis

| File | Size | Purpose |
|------|------|---------|
| `Vatican_osm.fbl` | 11 KB | Smallest map — fast iteration |
| `Vatican_osm.fpa` | 1.5 KB | Smallest address file |
| `Andorra_osm.spc` | 450 B | Smallest speed camera file |
| `Monaco_osm.fbl` | 53 KB | Small map, well-known geography |
| `France_osm.fbl` | 267 MB | Large map for performance testing |
| `*.lyc` | various | License files with extractable keys |
| `nngine.dll` | 3.3 MB | Contains decryption code |

## Key Observations for Analysis

1. **FBL and FPA share magic bytes** — same encryption scheme, different content type
2. **HNR and SPC have different magic** — possibly different keys or algorithms
3. **Same-country FBL/FPA share first 64 bytes** (mostly) — the header is partially
   shared, suggesting a common envelope with a file-type field
4. **Bytes 0x10-0x13 differ** between FBL and FPA for the same country — likely
   encodes file type or content length
5. **Byte 0x1E differs** — another type/size indicator
6. **All files have 8-byte aligned sizes** — suggests block-based encryption

## Implementation Plan — Steps 1-5 COMPLETE ✅

### Step 1: Header Analysis ✅ `analyse_header.py`
### Step 2: Key Extraction ✅ `try_lyc_key.py`
### Step 3: DLL Analysis ✅ (Ghidra + Unicorn emulation scripts)
### Step 4: Implement Decryption ✅ `decrypt_fbl.py`
### Step 5: Parse and Export ✅

Completed tools:
- `fbl_info.py` — metadata, bbox, country, version
- `spc_to_csv.py` — speed cameras to CSV
- `junctions_to_geojson.py` — junction coordinates as GeoJSON
- `segments_to_csv.py` — road segment metadata to CSV
- `curves_to_geojson.py` — curve points from section 1 bitstream
- `lyc_decrypt.py` — .lyc license decryption
- `map_overview.py` — summary of all map files

### Step 6: Full Road Geometry (Next)

Combine junctions + curves into complete road LineStrings:
1. Read junction coordinates from section 4
2. Read curve points from section 1
3. Link segments to curves via shape_offset/shape_count
4. Output GeoJSON LineString features with road_type properties

## Documentation

**All findings must be recorded in [`docs/mapformat.md`](../../docs/mapformat.md).**
This is the single source of truth for the NNG map file format. Update it after
every phase — header structure, encryption algorithm, key source, internal format,
coordinate encoding, etc. The doc should always reflect current knowledge.
