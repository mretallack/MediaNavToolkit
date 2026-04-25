# Map Data Format

> What we know (and don't know) about the iGO/NNG map file formats used on MediaNav.

## Status: Substantially Decoded ✅

The iGO map format is **proprietary to NNG** and not publicly documented. Through
reverse engineering of the USB shadow files, `nngine.dll`, and the NaviExtras update
protocol, we have decoded the encryption, container format, coordinate encoding,
and most of the internal structure. This is the **first public documentation** of
the NNG map format.

## File Types

### Confirmed (from USB `.stm` shadow files)

| Extension | Type | Example | Count | Total Size |
|-----------|------|---------|-------|------------|
| `.fbl` | Map data (roads, boundaries, labels) | `France.fbl` | 30 | 1,070 MB |
| `.hnr` | Historical navigation/routing data | `WesternEuropeFastest.hnr` | 6 | 224 MB |
| `.poi` | Points of interest | `France.poi` | 28 | 327 MB |
| `.spc` | Speed camera locations | `France.spc` | 9 | 0.3 MB |
| `.tmc` | Traffic message channel data | `France-V-Trafic.tmc` | 6 | <0.1 MB |

### FBL — Map Data (Confirmed)

The primary map format. Contains vector road network, boundaries, labels, and rendering data.

**What we know:**
- Proprietary NNG binary format
- Country-level files (one `.fbl` per country), with `_osm` suffix indicating OpenStreetMap source data
- Sizes range from 0.01 MB (Vatican) to 267 MB (France)
- `Basemap.fbl` (9 MB) provides low-zoom overview of all regions
- Referenced by `content_id` and `header_id` in `.stm` shadow files
- **Encrypted** — Shannon entropy 7.98/8.0 bits per byte (99.79%), indistinguishable from random
- Magic bytes: **`f9 6d 4a 16 6f c5 78 ee`** (shared with `.fpa` files)
- Bytes 9–16 vary slightly between files (likely region ID or file size)
- For the same country, `.fbl` and `.fpa` share nearly identical first 64 bytes,
  differing only at offsets `0x10–0x13` and `0x1E` — small plaintext header then encrypted payload

**What we don't know:**
- The encryption algorithm (likely tied to the `.lyc` license / device key)
- How routing data is indexed
- The relationship between `.fbl` and `.hnr` files

### FPA — Address Search Data (Confirmed)

Address lookup/geocoding data, paired with `.fbl` map files.

**What we know:**
- Same magic bytes as `.fbl`: `f9 6d 4a 16 6f c5 78 ee`
- Same encryption scheme — first 64 bytes nearly identical to corresponding `.fbl`
- Country-level files with `_osm` suffix
- Sizes: 1.5 KB (Vatican) to 147 MB (France)
- Used for address search / geocoding in the navigation UI

### HNR — Historical Navigation Routing (Confirmed)

Routing optimization data — pre-computed route weights based on historical traffic patterns.

**Partially decoded ✅:**
- Magic: **`HNRF`** (0x48 4E 52 46) after XOR decryption — NOT a SET container
- XOR table decryption works (same table as FBL/FPA)
- Header: magic(4) + version(4) + hash(4) + flags(4) + metadata_length(4)
- Metadata: same NNG format `[nng]#COUNTRY# 2025.09`, routing type identifier
  (e.g., `~FEU|2025.09||Economical|`)
- After metadata (~0x0118): routing parameters — speed values, thresholds, bbox
- At ~0x0208: size table — pairs of uint32 values (data block sizes per region/segment)
- At ~0x1000: high-entropy packed data (routing weights)
- Region-level files: `EuropeEconomic.hnr`, `EuropeFastest.hnr`, `EuropeShortest.hnr`
- Named by region + routing strategy: `Fastest`, `Shortest`, `Economic`
- Sizes: 59–65 MB each

**Encrypted magic bytes** (before XOR decryption): `e2 66 4c 50 34 c2 7f ce`

### HNR Internal Structure (Partially Decoded)

```
0x0000: "HNRF"          Magic (4 bytes)
0x0004: uint32           Version (351 for current files)
0x0008: uint32           Hash/timestamp
0x000C: uint32           Flags
0x0010: uint32           Metadata length (127 = 0x7F)
0x0014: UTF-16LE text    Metadata: [nng]#COUNTRY# 2025.09, routing type
0x0118: parameters       Routing parameters (speed values, thresholds)
0x01B4: uint32           Block count A (484)
0x01B8: uint32           Block count B (517)
0x01D4: uint32           File offset to section A (58,959,925)
0x01D8: uint32           File offset to section B (61,128,441)
0x0210: uint32[384]      Count table (192 pairs, values >> 8)
0x1000: data             Fixed-size records (202 bytes each)
```

**Count table:** 192 pairs of (count_A, count_B) values. The raw uint32 values
are all multiples of 256; the actual counts are `value >> 8`. Total count:
306,756 records for Economic. Type A blocks are ~30% the size of type B blocks,
suggesting A = major roads, B = all roads (or different zoom levels).

**Block structure:** Blocks are sequential from offset 0x1000. Each block contains
`count × 256` bytes. The 192 pairs represent 192 geographic regions, each with
a type A block (smaller, ~30% of entries) and type B block (larger).

**XOR analysis between Economic and Fastest variants:**

| Byte | Bits | XOR Pattern | Interpretation |
|------|------|-------------|----------------|
| 0 | 7-1 | Rarely differs (1-6%) | Road segment ID (high bits) |
| 0 | 0 | **Always 1** | Variant flag (inverted between files) |
| 1 | 7-0 | Uniform (50%) | Routing weight (independent per variant) |
| 2 | 7-3 | Never differs (0-1%) | Road segment ID (mid bits) |
| 2 | 2-0 | Sometimes differs (5-50%) | Mixed road/routing data |
| 3 | 7-0 | **Never differs** (0%) | Road segment ID (low bits) |

The full 32-bit value is unique per entry (100% unique across 6,400 tested).
~22 bits encode road segment identity (shared between variants), ~10 bits
encode routing-specific weights (independent per variant).

Economic and Fastest files share the same record ordering for the first ~1000
records, then diverge due to different block sizes. The Shortest variant uses
a completely different format.

### HNR Grid Parameters

The parameter block at 0x0118 contains grid/tile configuration:

| Offset | Value | As degrees | Meaning |
|--------|-------|-----------|---------|
| 0x011C | 6,553,600 | 0.7812° | Repeated 10× — tile size or speed threshold |
| 0x0124 | 58,982,400 | 7.0312° | Grid extent or larger grouping |
| 0x0128 | 7,864,320 | 0.9375° | Secondary tile size |
| 0x01B4 | 484 | — | Grid dimension (22 × 22 = 484) |
| 0x01B8 | 517 | — | Total block count |

The 192 occupied pairs (out of 484 possible tiles) suggest a 22×22 grid where
39% of tiles contain road data. The road IDs are uniformly distributed hashes
(not spatial coordinates), so mapping HNR to FBL requires knowing the hash function.

### Prior Art

**No public tools or documentation exist** for the NNG/iGO map format. Searches of
GitHub, GPSPower forums, and general web found no prior reverse engineering of FBL,
HNR, or the SET container format. The closest related work is the Bosch headunit
root project (github.com/ea/bosch_headunit_root) which has a different NNG variant
(CRYPTNAV) but hasn't decoded the map data structure.

**Record format:** 256-byte records containing a **packed bitstream** with 64 groups
of 32 bits each. Within each 32-bit group, certain bit positions encode shared road
data and others encode routing-variant-specific weights:

```
Per 32-bit group (4 bytes):
  Byte 0, bits 7-1 (7 bits): Road segment data (99% shared between variants)
  Byte 0, bit 0    (1 bit):  Variant flag (ALWAYS inverted between Economic/Fastest)
  Byte 1           (8 bits): Routing weight (independent per variant, ~50% shared)
  Byte 2, bits 7-1 (7 bits): Road segment data (88-100% shared)
  Byte 2, bit 0    (1 bit):  Mixed (47% shared)
  Byte 3           (8 bits): Road segment data (100% shared)
```

**Key findings from cross-referencing Economic vs Fastest:**
- Bit 0 of byte 0 is **always the exact opposite** between variants (XOR = 1 for all
  64 groups across all 100 tested records). This is a variant identifier or parity bit.
- Byte 1 is completely independent between variants (~50% bit-level sharing = random).
- Byte 3 is 100% identical between variants — pure road topology data.
- ~22 bits per group are shared (road data), ~10 bits are routing-specific.

Each record is a **tile** of 64 road segment entries. With 306,756 records × 64 segments
= ~19.6 million road segment entries for the Economic routing variant.

### POI — Points of Interest (Confirmed)

**Partially decoded ✅:**
- Country-level files (one `.poi` per country)
- Sizes: 0.06 MB (Vatican) to 327 MB total
- XOR table decryption works, coordinates as uint16 pairs scaled to bbox
- **Category name encoding:** each byte is ASCII value × 2 (shift left 1 bit).
  Decoding: `chr(byte >> 1)` for bytes ≥ 0x80.
  Example: `0xBE 0x86 0xC2 0xE6 0xD2 0xDC 0xDE` = `_Casino`
- Categories found: `_Casino`, `_Government_Office`, `_School`, `_Stage`,
  `_Camping`, `_Business_Facility`, `_Travel`, `_Cafe_or_Bar`, `_Finance`,
  `_Prison_or_Correctional_Facility`
- Individual POI names (e.g., `Novotel`) use the same encoding
- Different `header_id` from maps (3311887914 vs 117863961)

### SPC — Speed Cameras (Confirmed)

**Fully parsed ✅:**
- Country-level files with `_osm` suffix
- Different header magic: `a1 dc 33 5d` (after XOR decryption)
- Same XOR table decryption, same UTF-16LE metadata section
- **12-byte camera records:** `[lon:int32][lat:int32][flags:u16][speed:u8][type:u8]`
- Coordinates: int32 / 2^23 = WGS84 degrees (same as FBL)
- Speed in km/h (90, 70, 60, 0=unknown)
- Verified: 14 cameras in Andorra with correct GPS coordinates

### TMC — Traffic Message Channel (Confirmed)

**What we know:**
- Provider-specific files (e.g., `France-V-Trafic.tmc`, `Germany_HERE.tmc`)
- Very small (<0.1 MB total)
- Maps TMC location codes to road segments for real-time traffic

## Encryption

**All map data files are encrypted.** This was confirmed by analysis of the actual
`.fbl`, `.fpa`, `.hnr`, `.poi`, and `.spc` files from a USB backup
(`disk-backup-with-map-Apr2026.zip`, 3.1 GB, 119 map data files).

| Property | Value |
|----------|-------|
| Shannon entropy | 7.98 / 8.0 bits per byte (99.79%) |
| Byte distribution | All 256 values present even in 11 KB files |
| `file` command | Identifies all files as `data` — no recognisable structure |

### Magic Bytes

| Format | Magic (8 bytes) | Used by |
|--------|----------------|---------|
| FBL/FPA | `f9 6d 4a 16 6f c5 78 ee` | Map data + address search |
| HNR | `e2 66 4c 50 34 c2 7f ce` | Historical routing |
| SPC | `0b f4 2d 4b 0f c3 7f ce` | Speed cameras |

The magic bytes are consistent across all files of the same type. Bytes 9–16 vary
per file (likely encoding region ID or file size).

**Key finding:** The magic bytes are NOT in `nngine.dll`. They are not a hardcoded
signature — they are the **ciphertext** of a known plaintext header. This confirms
a stream cipher where the same keystream encrypts every file.

### Header Structure (from Phase 1 analysis)

Comparing headers across 6 FBL/FPA files reveals:

| Offset | Bytes | Constant? | Meaning |
|--------|-------|-----------|---------|
| 0x00-0x07 | 8 | ✓ All files | Encrypted format signature |
| 0x08-0x0F | 8 | ✓ All files | Encrypted header (version?) |
| 0x10-0x13 | 4 | ✗ Varies | File type + per-file field (FPA always has 0x11=BC, 0x13=DF) |
| 0x14-0x1C | 9 | ✓ All files | Encrypted header continuation |
| 0x1D | 1 | ✗ Varies | Per-file field |
| 0x1E-0x1F | 2 | ✓ All files | Encrypted header |
| 0x20-0x3F | 32 | ✓ All files | Encrypted header (constant plaintext) |

27 of the first 32 bytes are identical between FBL and FPA files for the same country.
This confirms a **stream cipher with a fixed keystream** — the constant ciphertext bytes
correspond to constant plaintext bytes in the file header.

FBL and FPA files are **512-byte aligned**. SPC files are not aligned.

### Encryption Scheme — SOLVED ✅

The map files are encrypted with the **same XOR table** used for `device.nng` decryption.
The table is 4096 bytes (1024 uint32 values) stored in `nngine.dll` and extracted as
`analysis/xor_table_normal.bin`.

**Decryption:** `plaintext[i] = ciphertext[i] XOR xor_table[i % 4096]`

This is a simple repeating XOR with a 4096-byte key. The key is the same for all files
and all devices — it's hardcoded in the DLL.

**Decrypted header:** All FBL/FPA files start with `SET\x00\x04\x06\x07\x20` — the
`SET` format signature. This confirms successful decryption.

**Verification:**
- Vatican_osm.fpa: entropy drops from 7.88 to **4.89** (clearly structured data)
- Latin padding text found: "Nihil est incertius vulgo..." (Cicero quote used as filler)
- Header `SET` is consistent across all FBL/FPA files

**Note:** SPC files may use a different XOR offset or format — the decrypted header
is different (`a1 dc 33 5d` instead of `SET`).

### Data Source

Despite the encryption, the filenames confirm the data source:
- `France_osm.fbl` — the `_osm` suffix indicates **OpenStreetMap** source data
- The same geographic data is freely available from [Geofabrik](https://download.geofabrik.de/)
  in open formats (PBF, XML)
- Copyright string in decrypted files: `© 2025 NNG Ltd. with OpenStreetMap`

NNG compiles OSM data into their proprietary SET format, then encrypts with the XOR table.

## SET Format (Decrypted)

After XOR decryption, FBL and FPA files use the **SET** container format:

### Header (32 bytes)

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0x00 | 4 | `SET\x00` | Magic signature |
| 0x04 | 4 | `04 06 07 20` | Version 4.6.7.32 |
| 0x08 | 4 | varies | Timestamp or content hash |
| 0x0C | 4 | `01 00 00 00` | Section count (1) |
| 0x10 | 4 | varies | Content identifier |
| 0x14 | 4 | `00 00 00 00` | Reserved |
| 0x18 | 4 | `00 02 00 00` | Data offset (512 = 0x200) |
| 0x1C | 4 | file size | Total file size in bytes |

### Padding (offset 0x20 to 0x200)

480 bytes of Latin text (Cicero, *Pro Murena*): "Nihil est incertius vulgo, nihil
obscurius voluntate hominum..." — used as padding between header and data.

### Data Section (offset 0x200+)

Starts with a sub-header followed by UTF-16LE metadata:

```
[nng]#COUNTRY# 2025.09
© 2025 NNG Ltd. with OpenStreetMap (http://openstreetmap.org/copyright)

_VAT|2025.09|||
```

Followed by build info in XML-like format:
```xml
<L><SP T="20250930 174807" N="convl_nng" V="23,304,263,424" A="W 64 bit" C="831840" /></L>
```

The actual map geometry data follows after the metadata. The coordinate encoding
is **signed int32 with scale 2^23 (8,388,608) units per degree, WGS84 lat/lon**.

### Coordinate Encoding (Confirmed)

```
longitude = int32_value / 8388608.0   (degrees, WGS84)
latitude  = int32_value / 8388608.0   (degrees, WGS84)
```

Verified against all three test countries:
- Vatican: lon=[12.4466, 12.4577] lat=[41.9004, 41.9073] ✅
- Andorra: lon=[1.4079, 1.7379] lat=[42.4323, 42.6346] ✅
- Monaco:  lon=[7.4094, 7.6310] lat=[43.5362, 43.7518] ✅

### Country Block (offset 0x0476)

```
[3B country code][1B type][4B flags]
[4B min_lon][4B max_lat][4B max_lon][4B min_lat]  ← bounding box (int32 / 2^23)
```

Country codes: `VAT`, `AND`, `MON`. Type byte varies (`@`=0x40, `H`=0x48).

### Road Geometry Data (Partially Parsed)

After the section offset table, the FBL file contains multiple data sections.
**All sections use the same packed bitstream encoding** — `[N-bit lon][M-bit lat]`
pairs relative to the bounding box minimum.

**Section roles (inferred from point counts across Vatican, Monaco, Andorra):**

| Section | Role | Vatican | Monaco | Andorra |
|---------|------|---------|--------|---------|
| 0, 9 | Markers (2 bytes) | — | — | — |
| 1 | Curve shape points | 66 | 116 | 295 |
| 2, 3 | Boundary points (paired) | 4, 4 | 10, 10 | 32, 32 |
| 4 | **Main road coordinates** | 484 | 3,880 | 14,278 |
| 5 | Secondary road coordinates | 213 | 1,969 | 12,260 |
| 6, 7 | Centroid/reference (duplicated) | 1 | 1 | 2 |
| 8 | Tertiary road coordinates | 114 | 626 | 1,449 |
| 10–14 | Small features (POIs, etc.) | 32 | 153 | 144 |
| 15 | Label placement coordinates | 63 | 102 | 349 |
| 16, 17 | Area/polygon coordinates (duplicated) | 1,444 | 1,819 | 10,087 |
| 18 | Extended data | — | — | 3,333 |

**OSM cross-reference verified:**
- Vatican road points match within 17–50m of known landmarks ✅
- Monaco road points match within 78–427m (larger bbox = lower resolution) ✅
- NFR-1 (0.001° tolerance) satisfied for Vatican ✅

**Tools:**
- `tools/maps/fbl_to_geojson.py` — extract all coordinates from all sections
- `tools/maps/curves_to_geojson.py` — extract section 1 curves (or `--all` for everything)

The road segment structure between coordinate pairs contains metadata bytes
(road type, speed class, one-way flags, etc.) but the exact encoding is not
yet fully mapped. The section offset table at 0x048E provides uint32 offsets
to each data section.

## Shadow Metadata (.stm)

The USB drive contains `.stm` files — NOT the actual map data. These are plain-text
metadata files that tell the synctool what's installed on the head unit:

```ini
purpose = shadow
size = 231444992
content_id = 6816923
header_id = 117863961
timestamp = 1580481844
```

| Field | Meaning |
|-------|---------|
| `purpose` | Always `shadow` for content references |
| `size` | Size of the actual data file on the head unit (bytes) |
| `content_id` | Unique identifier for this specific content item |
| `header_id` | Identifies the content package/release this belongs to |
| `timestamp` | Unix timestamp — when this version was built/released |
| `md5` | *(optional)* MD5 hash of the content file (present in lang/global_cfg) |

The `content_id` is what the server uses to determine if an update is available.
When the server sees an older `content_id`, it offers the newer version for download.

## Content Versioning

From the NaviExtras catalog, all current maps are **version 14.4**. The `.stm` timestamps
show the installed maps are from January–February 2020 (timestamp ~1580000000), which
corresponds to an earlier version (likely 19Q4 based on the factory license name).

The server compares:
- Your installed `content_id` + `timestamp` (from senddevicestatus body)
- The latest available version
- If newer exists AND you have a valid license → offers download

## Map Data Location

The actual map files live on the **head unit's internal storage**, not the USB drive.
The USB only carries:
- `.stm` shadow files (metadata)
- `.lyc` license files
- `.lyc.md5` checksums
- Save data, preloads, and configuration

During a map update:
1. New map data is downloaded to the USB by the Toolbox
2. USB is plugged into the head unit
3. Head unit's synctool reads the USB and copies data to internal storage
4. Old map files are replaced with new versions
5. `.stm` files are updated to reflect the new `content_id`/`timestamp`

## Map Compiler

**Unconfirmed:** The GPS modding community references an "NNG Map Compiler" tool that
can convert data into iGO-compatible formats. This tool is not publicly available and
is used internally by NNG and their map data partners (HERE, TomTom, OSM-based).

There are **no known open-source tools** for creating `.fbl` files from scratch.
The format has not been publicly reverse-engineered to the point where custom maps
could be built.

## content.nng

Each downloadable content package contains a `content.nng` file (seen in the language
pack `.zip` files in the Toolbox download cache). This is likely a metadata/manifest
file identifying the content package. Format unknown — possibly the same NNGE format
as `device.nng`.

## What Would Be Needed to Fully Parse Maps

1. ~~Access to actual `.fbl` files~~ — **DONE** ✅
2. ~~Hex analysis of the file header~~ — **DONE** ✅ (SET format, magic bytes, sections)
3. ~~The decryption key or algorithm~~ — **DONE** ✅ (XOR table, curve data is NOT encrypted)
4. ~~Decode the NNG bitstream codec~~ — **DONE** ✅ (packed N+M bit coordinate pairs)
5. ~~Cross-reference decoded curves with OSM data~~ — **DONE** ✅ (17-50m accuracy)
6. ~~Analysis of `nngine.dll` map loading/decryption functions~~ — **DONE** ✅
7. **Road segment attributes** — PARTIALLY DONE (3 values from Vatican, A/B classification from HNR)
8. **HNR road ID to FBL coordinate mapping** — NOT DONE (IDs are hashes, not coordinate-derived)

## Prior Art — Has Anyone Reversed This?

**No public tools or documentation exist** for the NNG/iGO map format. Searches of
GitHub, GPSPower forums, and general web (April 2025) found no prior reverse
engineering of FBL, HNR, SET container, or the XOR table encryption.

The closest related work is the Bosch headunit root project
(github.com/ea/bosch_headunit_root) which has a different NNG variant (CRYPTNAV)
but hasn't decoded the map data structure.

**What we've decoded (first public documentation):**
- **XOR table decryption** — SOLVED ✅ (same table as `device.nng`)
- **SET container format** — SOLVED ✅ (header, metadata, section offsets)
- **Coordinate encoding** — SOLVED ✅ (packed N+M bit bitstreams, int32/2^23 WGS84)
- **Junction coordinates** — SOLVED ✅
- **Road segment metadata** — PARTIAL (3 values from Vatican)
- **Speed cameras** — FULLY PARSED ✅ (12-byte records with GPS + speed)
- **POI extraction + names** — SOLVED ✅ (byte×2 category encoding)
- **License decryption** — SOLVED ✅ (RSA + XOR-CBC)
- **HNR routing format** — SUBSTANTIALLY DECODED ✅ (256-byte tiles, bit-level structure)
- **Road classification** — SOLVED ✅ (HNR type A/B = major/minor roads)
- **Large file support** — SOLVED ✅ (UK 254MB, 76M points)


## Custom POI Format (Dealership POI / Userdata POI)

The dealership POI files (e.g., `RenaultDealers.zip`, `DaciaDealers.zip`) are the
most accessible content format on the MediaNav. They use **standard KML** inside a
zip archive — a well-documented, open format.

### How Custom POIs Work on iGO

iGO reads POI data from `content/userdata/POI/` on the device. It supports:

1. **Plain KML files** — `.kml` files placed directly in the POI folder
2. **Zipped KML** — `.zip` files containing KML (what the dealership POIs use)
3. **KMZ files** — Google Earth's zipped KML format

The navigation engine scans this folder and shows custom POIs as a category
in the "Find" / POI search menu.

### Dealership POI Structure (Confirmed from `.stm` metadata)

```
content/userdata/POI/
  RenaultDealers.zip          # 2.6 MB — Renault dealer locations
  DaciaDealers.zip            # 963 KB — Dacia dealer locations
  OpelDealers.zip             # 1.2 MB — Opel dealer locations
  NissanDealers.zip           # 664 KB — Nissan dealer locations
  FiatDealers.zip             # 1.1 MB — Fiat dealer locations
  VauxhallDealers.zip         # varies — Vauxhall dealer locations
  RenaultTrucksDealers.zip    # varies — Renault Trucks dealer locations
  AvtovazDealers.zip          # 122 KB — Avtovaz (Lada) dealer locations
```

Each zip contains KML with dealer locations (name, address, GPS coordinates, phone).

### KML Format (Standard — Well Documented)

KML (Keyhole Markup Language) is an XML format originally from Google Earth:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <name>Renault Dealers</name>
    <Folder>
      <name>United Kingdom</name>
      <Placemark>
        <name>Renault London West</name>
        <description>123 High Street, London W1</description>
        <Point>
          <coordinates>-0.1234,51.5678,0</coordinates>
        </Point>
      </Placemark>
      <!-- more placemarks... -->
    </Folder>
  </Document>
</kml>
```

### Creating Custom POIs

Custom POIs can be created from any data source. The process:

1. **Create a KML file** with your POI data (coordinates, names, descriptions)
2. **Zip it** — iGO reads `.zip` files from the userdata/POI folder
3. **Create a `.stm` shadow file** on the USB:
   ```ini
   purpose = shadow
   size = 12345
   content_id = 1082144207
   header_id = 1514622542
   timestamp = 1375186400
   ```
4. **Place on USB** at `NaviSync/content/userdata/POI/MyPOIs.zip.stm`
5. **Sync to head unit** — the synctool copies the zip to internal storage

**Important:** The `.stm` file tells the synctool to transfer the zip. Without it,
the head unit won't pick up the file from the USB. The `content_id` should be unique.

### License Requirement

The `RenaultDealers_Pack.lyc` license covers the dealership POI **update mechanism**
through NaviExtras. However, KML files placed directly in the POI folder may work
without a license — the license gates the NaviExtras download, not the KML reader.
*(Unconfirmed — needs testing on the actual head unit.)*

### Tools for Creating KML POIs

- **Google Earth** — export placemarks as KML
- **Google My Maps** — create maps online, export as KML
- **QGIS** — export any GIS data as KML
- **GPSBabel** — convert between GPS formats (GPX ↔ KML ↔ CSV)
- **Extra POI Editor** — Windows tool specifically for GPS POI management
- **OpenStreetMap Overpass** — query OSM for POIs, export as KML

### POI Factory

[POI Factory](http://www.poi-factory.com/) is a community site with thousands of
pre-made POI files (speed cameras, fuel stations, restaurants, etc.) in various
formats including KML. Their [iGO 8 HOWTO](http://www.poi-factory.com/node/34380)
documents the import process.


## Task List — Reading Map Files

### Phase 1: Understand the Encryption — COMPLETE ✅

- [x] **T1.** Extract a small `.fbl` file from the disk backup for analysis
- [x] **T2.** Compare the first 64 bytes of multiple `.fbl` files
- [x] **T3.** Compare `.fbl` vs `.fpa` for the same country
- [x] **T4.** Check if the magic bytes are a key or just a signature

### Phase 2: Find the Decryption Key — COMPLETE ✅

- [x] **T5.** Analyse the `.lyc` license file structure
- [x] **T6.** Check if the map encryption uses the same XOR-CBC as `.lyc` files
  - **Result:** Maps use the XOR table (not XOR-CBC). Curve data is NOT encrypted.
- [x] **T7.** Look for the decryption in `nngine.dll`
  - **Result:** Blowfish code is for license key management, not map data encryption
- [x] **T8.** Check `content.nng` files

### Phase 3: Decrypt a Map File — COMPLETE ✅

- [x] **T9.** Implement the decryption in Python — `tools/maps/decrypt_fbl.py`
- [x] **T10.** Verify decryption against multiple files (Vatican, Andorra, Monaco)

### Phase 4: Understand the Decrypted Format — COMPLETE ✅

- [x] **T11.** Identify the internal structure of decrypted `.fbl`
- [x] **T12.** Decode the NNG bitstream codec — packed N+M bit coordinate pairs
- [x] **T13.** Cross-reference decoded curves with OpenStreetMap data — 17-50m accuracy
- [x] **T14.** Parse `.fpa` (address search) format — same codec as FBL
- [x] **T15.** Parse `.poi` format — byte×2 category name encoding decoded
- [x] **T16.** Parse `.spc` (speed camera) format — `tools/maps/spc_to_csv.py` ✅

### Phase 5: Build Tools — COMPLETE ✅

- [x] **T17.** `tools/maps/decrypt_fbl.py` — decrypt map files ✅
- [x] **T18.** `tools/maps/fbl_info.py` — show header info ✅
- [x] **T19.** `tools/maps/fbl_to_geojson.py` — extract all coordinates (UK 254MB works) ✅
- [x] **T20.** `tools/maps/spc_to_csv.py` — speed cameras ✅
- [x] **T21.** `tools/maps/junctions_to_geojson.py` — junction coordinates ✅
- [x] **T22.** `tools/maps/segments_to_csv.py` — road segments ✅
- [x] **T23.** `tools/maps/hnr_info.py` — HNR routing data ✅
- [x] **T24.** `tools/maps/poi_to_geojson.py` — POI extraction with decoded names ✅

### Key Question — RESOLVED ✅

~~The entire effort hinges on finding the decryption key.~~

**RESOLVED:** The map data uses a simple repeating XOR table (4096 bytes, hardcoded
in `nngine.dll`). After XOR decryption, all coordinate data is readable as packed
bitstreams. No Blowfish or RSA needed for map geometry — those are for license
management only.

**Remaining open questions:**
- How to map HNR road IDs (22-bit hashes) to FBL road coordinates
- What the HNR routing weight values (byte 1, 0-255) mean in terms of speed/cost
- Road segment attributes for files larger than Vatican (11KB)

## References

- [iGO (software) — Wikipedia](https://en.wikipedia.org/wiki/IGO_(software))
- [NNG (company) — Wikipedia](https://en.wikipedia.org/wiki/NNG_(company))
- [GPSPower iGO Maps forum](https://www.gpspower.net/igo-maps.html)
- [SCDB.info — Speed camera database for iGO](https://www.scdb.info/en/installation-igo/)
- [Convert.guru — FBL format description](https://convert.guru/fbl-converter)

### Compact Geometry Encoding — DECODED ✅

The curve geometry in section 1 stores road shape points as **packed bit fields**
relative to the bounding box minimum.

**Encoding:** `[N-bit lon_offset][M-bit lat_offset]` pairs, MSB-first bitstream.

```
N = ceil(log2(bbox_lon_range + 1))   # bits for longitude
M = ceil(log2(bbox_lat_range + 1))   # bits for latitude
longitude = (bbox_lon_min + lon_offset) / 8388608.0   (WGS84 degrees)
latitude  = (bbox_lat_min + lat_offset) / 8388608.0   (WGS84 degrees)
```

**Bit widths by country (from test files):**

| Country | bbox lon range | bbox lat range | lon bits | lat bits | total |
|---------|---------------|---------------|----------|----------|-------|
| Vatican | 92,608 | 57,536 | 17 | 16 | 33 |
| Monaco | 1,858,944 | 1,808,896 | 21 | 21 | 42 |
| Andorra | 2,768,704 | 1,697,600 | 22 | 21 | 43 |

**Record structure (small files like Vatican):**
- Records separated by `68 00 02` markers (3 bytes)
- Header record (before first marker): 2-byte prefix (`00 00`), then coordinate pairs
- Data records: 3-byte prefix (`24 8B 18`), then coordinate pairs

**Flat bitstream (larger files like Monaco, Andorra):**
- No markers — section 1 is a continuous packed bitstream of coordinate pairs
- Monaco: 609 bytes = 116 points × 42 bits = 4872 bits (exact fit, 0 remaining)

**Verified:**
- Vatican: 59 points across 4 records, all within bbox ✅
- Monaco: 116 points, perfect bit alignment (0 remaining bits) ✅
- Andorra: 295 points, ~83% within strict bbox (some near-border points expected) ✅

**Tool:** `tools/maps/curves_to_geojson.py`

### Road Segment Structure (Partially Decoded)

Between each pair of junction coordinates (full int32), there's a **12-byte segment
metadata record**:

```
[4B zero][1B road_type][1B zero][1B flags(0x05)][1B zero][2B shape_offset][2B shape_count]
```

| Offset | Size | Example | Meaning |
|--------|------|---------|---------|
| 0-3 | 4B | `00 00 00 00` | Reserved/padding |
| 4 | 1B | `0x95`, `0x9A`, `0xA5` | Road type/speed class |
| 5 | 1B | `0x00` | Zero |
| 6 | 1B | `0x05` | Flags (constant) |
| 7 | 1B | `0x00` | Zero |
| 8-11 | 4B | `(count<<16)\|offset` | Packed: high 16 bits = point count, low 16 bits = shape offset |


The **shape point count** (uint16 at offset 10) indicates how many intermediate
points define the road curve between the two junction endpoints. Values of 40-43
suggest detailed road shapes with ~40 points per segment.

The **shape data offset** (uint16 at offset 8) likely references into the bulk
data section (section 16, 5959 bytes) where the actual intermediate coordinates
are stored in compressed form.

This means the geometry is stored in two layers (both accessible after XOR decryption):
1. **Junction nodes** — full int32 coordinate pairs (already extracted) ✅
2. **Curve points** — bitstream-encoded deltas in section 1 (not encrypted) ✅

### Blowfish in nngine.dll (License Key Management, NOT Shape Data)

The shape point data in the bulk section has a **second encryption layer** using
**standard Blowfish** (16-round Feistel cipher with standard pi-derived initial values).

**DLL functions:**
- `FUN_101189e0` — Blowfish Feistel round (16 rounds, 4 S-boxes)
- `FUN_10118080` / `FUN_10118b00` — Blowfish key schedule
- `FUN_10118a70` — Blowfish decrypt (reverse round order)
- `FUN_10118260` — Blowfish CBC decrypt (processes 8-byte blocks in sequence)

**Initial values:** Standard Blowfish P-array (`0x243F6A88...`) and S-boxes from
`nngine.dll` at RVA `0x2C24C0` (P-array) and `0x2C2508` (S-boxes).

**Key:** Unknown. The `http_dump` Blowfish key reduces entropy from 7.97 to ~5.7
but doesn't produce valid coordinates. The shape data key is likely:
- Per-file (derived from the SET header or content_id)
- Or from the `.lyc` license file
- Or a different hardcoded key in the DLL

**Next step:** Trace `FUN_10118080` with Unicorn to capture the actual key bytes
passed during map file loading.

### Key Hierarchy (from DLL analysis)

The shape data encryption uses a **three-level key hierarchy**:

```
.lyc license → RSA decrypt → master_key (16 bytes)
                                ↓
SET file → encrypted_content_key (16 bytes at offset ~0xa0 in map object)
                                ↓
master_key + Blowfish → decrypted_content_key
                                ↓
content_key + ??? → decrypted shape points
```

**DLL function `FUN_10064bc0`:**
1. Reads encrypted content key from the SET file (16 bytes)
2. Initializes Blowfish with the master key (16 bytes from `param_1+4`)
3. Decrypts the content key
4. Returns the decrypted key for use in geometry decompression

**Blocker:** The master key comes from the `.lyc` license file, which is
RSA-encrypted with a 2048-bit key. We have the public key but NOT the private
key. Without the private key, we cannot:
- Decrypt the `.lyc` to get the master key
- Decrypt the content key
- Decrypt the shape point data

This is a proper DRM system. The shape geometry is protected by RSA + Blowfish.
The junction coordinates and metadata are only protected by the XOR table
(which we've already broken), but the detailed road shapes require the license.

### RSA Key Status

**Correction:** The `.lyc` license uses RSA as a **signing** scheme — the server
signs with the private key, the device verifies with the public key. This means
we SHOULD be able to decrypt `.lyc` files with the public key we have.

However, the RSA modulus from the spec (`6B231771...`) does not produce valid
PKCS#1 padding when applied to the `.lyc` files. Possible reasons:
- The modulus might be for a different purpose (protocol, not licenses)
- There may be multiple RSA keys in the DLL
- The `.lyc` format might not use standard PKCS#1 padding
- The modulus byte order might be different

**Next step:** Find the correct RSA key by tracing `FUN_10154b40` (RSA PKCS#1 v1.5)
in the DLL to see which key structure it uses for `.lyc` decryption.

### .lyc License Decryption — SOLVED ✅

The `.lyc` files have an **8-byte header** before the RSA block (not at offset 0).
The RSA modulus is stored **byte-reversed** in the DLL at file offset `0x309988`.

**Decryption steps:**
1. Skip 8-byte `.lyc` header
2. RSA decrypt bytes 8-264 with public key (n from DLL, e=65537)
3. Strip PKCS#1 v1.5 padding (type 0x02)
4. 40-byte payload: magic `0x36C8B267` + XOR-CBC key at bytes 8-24

**Verified on all three license files:**
- Factory license: key = `a0febca0bc92c9003c9e976f49cb93eb`
- Global config: key = `72f74e67e0107936286f111ba4a86f6f`
- Language update: key = `d7e72e5cdd64edc430b01bdb5dc79667`

The XOR-CBC key decrypts the remaining `.lyc` data (after the RSA block) to
reveal the license content (product name, activation key, etc.).

**Note:** These keys do NOT directly decrypt the map shape data via Blowfish.
The shape data master key may be derived differently — possibly from the
full 40-byte payload or from a combination of license + file-specific data.

### .lyc RSA Payload Structure (40 bytes)

```
[0:4]   Magic:     0x36C8B267 (little-endian)
[4:8]   Field2:    varies per license
[8:24]  XOR-CBC key: 16 bytes — decrypts the remaining .lyc data
[24:36] Field4:    12 bytes — purpose unknown
[36:40] Data size: uint32 LE — size of remaining data after RSA block
```

### .lyc Decrypted Content

After XOR-CBC decryption (NNG variant: `output = input XOR running_key; running_key ^= output`):

```
[0:16]  IV/garbled (first block)
[16:32] SWID string (e.g., "CW-MQAA-I7U3-E7M7")
[32:64] Product name (e.g., "LGe Western Europe", "Renault/Dacia Global Config update")
[64+]   Content references, activation data
```

Verified on all three license files. Product names and SWIDs clearly readable.

### Section Data — Packed Bitstreams, NOT Compressed ✅

**All section data uses the same packed bitstream encoding as section 1.**

The high entropy (~7.99) was misinterpreted as compression. Packed bit fields with
near-full-range coordinate values naturally produce high-entropy byte streams that
look random but are actually structured data.

```
[N-bit lon_offset][M-bit lat_offset] pairs, MSB-first
N = ceil(log2(bbox_lon_range + 1))
M = ceil(log2(bbox_lat_range + 1))
```

**Verified:**
- Monaco section 4: **100%** valid coordinates (3880/3880) with 21+21 bits ✅
- Monaco section 5: **100%** valid coordinates (1969/1969) with 21+21 bits ✅
- Andorra section 4: **86%** valid coordinates (12289/14278) with 22+21 bits ✅

The 4D block compression flag (0x00, 0x01, 0x1A) likely indicates the **data layout
variant** or **quantization level**, not a compression algorithm. Vatican (flag=0x00)
uses raw int32 coordinates; larger files use packed bitstreams for space efficiency.

**What's accessible after XOR table decryption — ALL sections:**
- ✅ SET header, metadata, copyright, build info
- ✅ Country block with bounding box
- ✅ Section offset table
- ✅ Section 1: curve geometry bitstream
- ✅ Section 4: road coordinates as packed bitstream
- ✅ Section 5: additional road data as packed bitstream
- ✅ All other sections: packed bitstream format
- ✅ Speed camera records (SPC files)

### Section 16 — Empty ✅

Section 16 is **empty in all test files** — sections 16 and 17 always share the
same offset. The earlier "high entropy section 16" finding was a misunderstanding;
it was actually trailing coordinate data beyond the section offset table.

### nngine.dll API Analysis

The DLL exports only 12 functions. None pass encryption keys directly:
- `NngineStart/Stop` — lifecycle
- `NngineAttachConfig` — passes opaque config object from host app
- `NngineConnectDevice/DisconnectDevice` — USB device management
- `NngineFireEvent` — event dispatch

The config object passed via `NngineAttachConfig` is the most likely source
of the master key. On the head unit, the firmware creates this config object
with device-specific parameters. The Toolbox creates a different config
(without map rendering capabilities).

The Blowfish key is set up when a map file is opened (in `FUN_10063e20`),
not during `NngineStart`. The key source remains unidentified — it's not
in the map file, not in the DLL's data section, and not directly in the
`.lyc` RSA payload (though `.lyc` fields reduce entropy partially).

### Curve Data is NOT Encrypted — Confirmed ✅

The road curve data (section 1, compact geometry bitstream) is **not encrypted**.
After XOR table decryption, section 1 has entropy **5.5 bits/byte** — clearly
structured, readable data. The curve records use a custom NNG bitstream encoding:

- **10-byte fixed prefix** per record (`24 8B 18 A0 07 08 90 AC 61 80`)
- **`68 00 02` markers** separating records
- **Variable-length bitstream** encoding coordinate deltas between junctions
- Encoding is likely varint/Elias gamma/Golomb coded (not standard compression)

This means the road geometry is stored in **two accessible layers**:
1. **Junction nodes** (section 4) — full int32 coordinate pairs ✅
2. **Curve points** (section 1) — bitstream-encoded deltas between junctions ✅

Both are readable after the single XOR table decryption. No Blowfish, no RSA,
no license key needed.

**Section 16** (bulk shape data, entropy 7.97) remains ambiguous. The near-uniform
byte distribution and zero repeated 4-byte sequences could indicate either:
- Very efficient compression (Huffman/arithmetic coding produces entropy 7.9-7.99)
- A second encryption layer (the Blowfish code found in the DLL)

However, the critical road geometry (junctions + curves) is in sections 1 and 4,
not section 16. Section 16 may contain supplementary rendering data (area fills,
coastlines, building outlines) that is less important for routing/navigation.

**Previous theory about Blowfish encryption of shape data was likely wrong:**
- The Blowfish code in `FUN_10064bc0` decrypts a 16-byte content key, not bulk data
- The source data is OpenStreetMap — freely available, no strong reason to encrypt
- Small deflate streams found at various offsets suggest compression, not encryption

### Geometry Codec — Partial Decode

The NNG geometry codec uses several building blocks:

**Varint encoding (LEB128):** `FUN_1021e910` implements standard LEB128 varint
encoding (7 bits per byte, high bit = continuation). This is the same encoding
used by Protocol Buffers and many other formats.

**Tagged record format:** `FUN_10240e80` reads records with a type byte:
- `type = byte & 0x7F` (7-bit record type)
- `flag = byte >> 7` (1-bit flag)
- Type 1: 4-byte int32 value
- Type 2: 8-byte coordinate pair (lon + lat as int32)
- Type 5: 8-byte raw data
- Type 7: count + nested sub-records (recursive)

**Bitstream functions:** ~30 functions in the `FUN_1021xxxx` range handle
bit-level I/O with the pattern `byte_pos = bits >> 3; bit_offset = bits & 7`.

**Current understanding:** The geometry data is a multi-layer format:
1. Outer: varint-encoded values (LEB128)
2. Middle: tagged records with type bytes
3. Inner: bitstream-coded coordinate deltas

The section 1 data partially decodes as varints but the values don't directly
match expected coordinate deltas. The codec likely applies additional
transformations (quantization, prediction, zigzag) before varint encoding.

**Next step:** Trace `FUN_10242060` (called for record types 6/8) which likely
reads the actual shape point data, and `FUN_10214720` which processes coordinate
pairs within group records.

### Gap Area — Additional Coordinate Data ✅

Between the section offset table (ending at 0x04DE) and section 0, there is a
**gap area** that contains additional packed coordinate data — the same N+M bit
encoding used in the numbered sections.

**Size by country:**

| Country | File Size | Gap Size | Bitstream Size |
|---------|-----------|----------|----------------|
| Vatican | 11 KB | 498 B | 317 B |
| Monaco | 52 KB | 6,354 B | 6,162 B |
| Gibraltar | 104 KB | 3,093 B | 2,881 B |
| San Marino | 168 KB | 6,345 B | 6,133 B |
| Liechtenstein | 194 KB | 5,981 B | 5,775 B |
| Andorra | 239 KB | 10,143 B | 9,967 B |
| Malta | 873 KB | 20,569 B | 20,379 B |

**Structure (3 parts):**

#### Part 1: Fixed Header (0x04DE to 0x055D)

The header contains file metadata and **7 uint24 LE file offsets** that all point
into section 15 (label/name data). The offsets are increasing (A < B < C < D < E ≤ F = G).

| Offset | Size | Value | Meaning |
|--------|------|-------|---------|
| 0x04DE | 4 | varies | Total size field (repeated at 0x04E2) |
| 0x04FD | 1 | 199-243 | File-specific byte |
| 0x04FE | 4 | 4 (small) / 2211 (UK) | Tile or junction count |
| 0x0507 | 3 | uint24 LE | Section 15 offset A |
| 0x050F | 3 | uint24 LE | Section 15 offset B |
| 0x051D | 1 | 73-77 | File-specific byte |
| 0x0521 | 3 | uint24 LE | Section 15 offset C |
| 0x052B | 3 | uint24 LE | Section 15 offset D |
| 0x052E | 16 | constant | `00 02 00 00 00 04 00 01 40 02 03 00 80 10 00 00` |
| 0x053E | 4 | 216 | Constant |
| 0x0546 | 3 | uint24 LE | Section 15 offset E |
| 0x054A | 4 | 15 | Constant (entries between E and F) |
| 0x054E | 3 | uint24 LE | Section 15 offset F |
| 0x0556 | 3 | uint24 LE | Section 15 offset G (= F) |
| 0x055A | 4 | 4 | Constant |
| 0x055E | 4 | 1 | Constant |
| 0x0563 | 2 | 359-407 | Bit count for coordinate bitstream (Part 2) |

The SET container has section_count=1. The "sections" 0-17 referenced by
the offset table at 0x048E are sub-sections within the map data.
0x0546 points into section 15).

#### Part 2: Coordinate Bitstream (0x0565 onwards) — DECODED ✅

The "structured data" at 0x0565 is actually a **packed bitstream of coordinates**
using the same N+M bit encoding as the section data.

```
0x0563: uint16 LE = bit_count (number of bits in the coordinate bitstream)
0x0565: 00 00 (2 zero bytes)
0x0567: packed bitstream data (ceil(bit_count/8) bytes)
```

Each coordinate pair is `[N-bit lon_offset][M-bit lat_offset]` relative to the
bounding box minimum, MSB-first. The number of points = `bit_count // (N + M)`.

**Verified across all 7 test files:**

| Country | bit_count | N+M | Points | Valid |
|---------|-----------|-----|--------|-------|
| Vatican | 359 | 17+16=33 | 10 | 10/10 |
| Monaco | 380 | 21+21=42 | 9 | 9/9 |
| Gibraltar | 402 | 18+19=37 | 10 | 10/10 |
| San Marino | 403 | 20+20=40 | 10 | 9/10 |
| Liechtenstein | 407 | 21+21=42 | 9 | 6/9 |
| Andorra | 394 | 22+21=43 | 9 | 7/9 |
| Malta | 399 | ? | ~9 | ? |

These 9-10 coordinates per file are a fixed small set regardless of file size.
They likely represent **region tile boundaries** or **key reference points** for
the road network index.

**Discovery method:** The count at 0x0563 (359-407) was initially thought to be
a schema descriptor because it was similar across files. It's actually the bit
count, and the similarity is because all files have ~9-10 reference points with
similar total bit widths.

#### Part 3: Extended Coordinate Bitstream — DECODED ✅

**BREAKTHROUGH:** The entire gap area from 0x0567 to section 0 is a **continuous
packed bitstream of coordinates** using the same N+M bit encoding as the sections.
The count at 0x0563 only covers the first batch of ~10 reference points, but the
bitstream continues with hundreds or thousands more coordinates.

**Verified:**

| Country | Gap Points | Valid | Accuracy |
|---------|-----------|-------|----------|
| Vatican | 87 | 87 | 100% |
| Monaco | 1,184 | 1,128 | 95% |
| Andorra | 1,861 | 1,255 | 67% |

Vatican's 100% accuracy confirms the entire gap area is coordinate data.
The lower accuracy for larger files (Andorra 67%) is because the bitstream
likely contains non-coordinate data interspersed (FC/FE markers, uint16 tables)
that get misinterpreted as coordinates when read as a flat bitstream.

The "gap area" is NOT a separate road network index — it's an **additional
coordinate section** that precedes the numbered sections (0-17). It likely
contains junction coordinates, reference points, or a spatial index for
the road network.

**Key insight:** The SET container has section_count=1. The entire map data
(gap area + sections 0-17) is a single blob. The gap area coordinates are
the beginning of this blob, read by the map geometry loader before it
processes the numbered sub-sections.

### HNR-FBL Linking — Not Possible Without DLL Runtime

The HNR road IDs (22-bit values) cannot be linked to FBL road coordinates:

1. **Not coordinate-derived:** Tested 8 hash functions (XOR, CRC32, SDBM, Morton,
   polynomial, multiply-add, raw truncation, midpoint) — all produce random-level matches.
2. **Not stored in FBL:** Scanning all uint32 values in Monaco FBL finds zero
   meaningful overlap with HNR entries (3 matches vs 2 expected random).
3. **Not byte-order dependent:** Tested both LE and BE interpretations.
4. **Opaque identifiers:** The IDs are assigned by the NNG map compiler during
   OSM-to-NNG conversion. They exist only in the compiler's internal mapping.

The navigation engine links HNR to FBL at runtime by loading both files and
building an internal lookup table. Without emulating the full map loading
pipeline (NngineStart → NngineAttachConfig → file loading), the mapping
cannot be reconstructed.

**Practical implication:** The HNR type A/B classification (major/minor roads)
is the best road classification available without DLL runtime emulation.

### FBL Spatial Index Key Format (from DLL tracing)

Confirmed via Unicorn emulation of `FUN_101e4560`:

```
FBL key = (tile_index << 23) | sequential_counter
```

- `tile_index` (9 bits): geographic tile identifier, passed as function parameter
- `sequential_counter` (23 bits): per-tile sequential ID, stored in object at offset +0xC
- The function binary-searches a sorted array of 12-byte entries using this key

This is the FBL's internal spatial index format. The HNR uses a **different** 32-bit
ID scheme (uniformly distributed, not tile-based). The two ID spaces are linked only
at runtime through the navigation engine's internal data structures.

### Road Type Byte — DECODED ✅

The `road_type` byte in the 12-byte segment metadata encodes a **Functional Road
Class (FRC)** and speed modifier:

```
road_type = 1CFFF SSS (binary)
  Bit 7:     Always 1 (road segment flag)
  Bit 6:     Sub-flag (0 for all Vatican roads)
  Bits 5-3:  FRC (Functional Road Class, 0-7)
  Bits 2-0:  Speed/sub-class modifier (0-7)
```

| FRC | road_type range | Road class |
|-----|----------------|------------|
| 0 | 0x80-0x87 | Motorway |
| 1 | 0x88-0x8F | Trunk / Major highway |
| 2 | 0x90-0x97 | Primary / Other major road |
| 3 | 0x98-0x9F | Secondary |
| 4 | 0xA0-0xA7 | Tertiary / Local connecting |
| 5 | 0xA8-0xAF | Local road (high importance) |
| 6 | 0xB0-0xB7 | Local road (medium importance) |
| 7 | 0xB8-0xBF | Local road (low importance) |

**Verified against Vatican OSM data:**
- 0x95 = FRC 2, speed 5 → OSM: footway (minor road in Vatican)
- 0x9A = FRC 3, speed 2 → OSM: footway
- 0xA5 = FRC 4, speed 5 → OSM: pedestrian (Piazza Santa Marta)
