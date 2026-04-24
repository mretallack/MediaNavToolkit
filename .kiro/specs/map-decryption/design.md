# Design: NNG Map File Decryption

> Requirements: [requirements.md](requirements.md) | Map format reference: [../../docs/mapformat.md](../../docs/mapformat.md)

## Architecture

```
tools/maps/
├── analyse_header.py     # T1-T4: Compare headers across files
├── try_lyc_key.py        # T5-T6: Try .lyc XOR-CBC key on map data
├── find_decrypt_dll.py   # T7: Search nngine.dll for decryption functions
├── decrypt_fbl.py        # T9: Decrypt a map file
├── fbl_info.py           # T18: Show header info and stats
├── fbl_to_geojson.py     # T19: Export to GeoJSON
└── spc_to_csv.py         # T20: Export speed cameras to CSV
```

## Investigation Strategy

Three parallel approaches, ordered by effort:

### Approach A: Try the .lyc Key (Low effort, may work)

The `.lyc` license files use RSA + XOR-CBC. After RSA decryption, the 40-byte header
contains a 16-byte XOR-CBC key at offset 8. If NNG reuses this key for map encryption,
we can decrypt immediately.

```
.lyc file → RSA decrypt → 40-byte header → extract XOR-CBC key (bytes 8-24)
                                          → try on .fbl file
```

**Test:** XOR-CBC decrypt `Vatican_osm.fbl` (11 KB) with the key from
`LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc`. Check if output has lower entropy
or recognisable structure.

### Approach B: Trace in nngine.dll (Medium effort, definitive)

The DLL must decrypt maps at runtime. Find the decryption function by:

1. Search for the magic bytes `f9 6d 4a 16` in the DLL's data section or code
2. Find cross-references to the magic — these are the file-open/validate functions
3. Trace forward from validation to the decryption call
4. Identify the cipher (AES? XOR-CBC? SnakeOil? Blowfish?)
5. Trace the key source

**Tools:** Ghidra with the existing `analysis/nngine_decompiled.c` (15 MB).

### Approach C: Known-plaintext attack (Medium effort, if A and B fail)

If we can guess any plaintext in the decrypted file, we can derive the keystream:

- The `.fbl` header likely contains a version number, bounding box, or file size
- Older unencrypted iGO 8 `.fbl` files (if obtainable) would reveal the header format
- The `_osm` suffix confirms OpenStreetMap data — known structure

**Keystream derivation:** `keystream = encrypted_bytes XOR known_plaintext`

## Encryption Hypotheses

Based on what we know about NNG's crypto:

### Hypothesis 1: XOR-CBC with .lyc-derived key (Most likely)

NNG already uses XOR-CBC for `.lyc` file bodies. The map files may use the same
scheme with a key extracted from the license. Evidence:
- Same company, same DLL, same era
- The `.lyc` contains a content-specific key
- XOR-CBC is simple and fast (important for real-time map rendering)

### Hypothesis 2: SnakeOil (xorshift128) with a content key

NNG uses SnakeOil for the wire protocol. They might reuse it for file encryption.
Evidence:
- SnakeOil is already in `nngine.dll`
- It's a stream cipher — fast for large files
- The 8-byte magic could be the SnakeOil seed

**Test:** Try `snakeoil(encrypted_data[8:], magic_bytes_as_uint64)` — if the magic
IS the seed, the rest of the file decrypts with it.

### Hypothesis 3: AES or Blowfish with device-specific key

More standard encryption. NNG has Blowfish in the DLL (used for `http_dump` XML).
Evidence:
- Blowfish key already extracted from DLL (for XML decryption)
- AES would be the "proper" choice for content protection

**Test:** Try the known Blowfish key on the map data.

### Hypothesis 4: Custom block cipher or per-file key

Each file could have its own key derived from `content_id` or similar metadata.
This would explain why the magic bytes are constant (they're a signature, not a key)
while the rest varies.

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

## Implementation Plan

### Step 1: Header Analysis (`analyse_header.py`)

Extract and compare headers from multiple files. Output a table showing which
bytes are constant, which vary by country, and which vary by file type.

### Step 2: Key Extraction (`try_lyc_key.py`)

1. RSA-decrypt the `.lyc` file to get the 40-byte header
2. Extract the XOR-CBC key (bytes 8-24)
3. Try XOR-CBC on `Vatican_osm.fbl` starting at offset 8
4. Measure entropy of the result
5. Also try: SnakeOil with magic as seed, Blowfish with known key

### Step 3: DLL Analysis (`find_decrypt_dll.py`)

If Step 2 fails:
1. Search `nngine.dll` for the magic bytes `f9 6d 4a 16`
2. Find all cross-references
3. Identify the file-open function
4. Trace to the decryption routine
5. Document the algorithm and key source

### Step 4: Implement Decryption (`decrypt_fbl.py`)

Once the algorithm is known:
1. Implement in Python
2. Decrypt `Vatican_osm.fbl` and verify
3. Decrypt 3+ other files to confirm
4. Handle all file types (FBL, FPA, HNR, POI, SPC)

### Step 5: Parse and Export

Once decryption works:
1. Identify the internal binary format
2. Extract coordinates, road names, POI data
3. Export to GeoJSON/CSV/KML
