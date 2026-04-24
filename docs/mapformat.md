# Map Data Format

> What we know (and don't know) about the iGO/NNG map file formats used on MediaNav.

## Status: Mostly Unknown

The iGO map format is **proprietary to NNG** and not publicly documented. This document
collects what we've observed from the USB shadow files, community knowledge, and the
NaviExtras update protocol. Much of this is inference — clearly marked where uncertain.

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

**What we know:**
- Region-level files (not per-country): `EuropeEconomic.hnr`, `EuropeFastest.hnr`, etc.
- Named by region + routing strategy: `Fastest`, `Shortest`, `Economic`
- Sizes: 17–62 MB each
- Different magic bytes from FBL/FPA: **`e2 66 4c 50 34 c2 7f ce`**
- Also encrypted (high entropy)

**Speculation:**
- Likely contains time-of-day traffic speed profiles for road segments
- Used by the routing engine to prefer historically faster routes
- May be optional — navigation works without them but with less optimal routing

### POI — Points of Interest (Confirmed)

**What we know:**
- Country-level files (one `.poi` per country)
- Sizes: 0.06 MB (Vatican) to 327 MB total
- Contains restaurant, fuel station, parking, etc. locations
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
Road node coordinates are stored as **full int32 pairs** (same encoding as bounding box)
interspersed with road metadata.

**Confirmed:** 7 unique road junction coordinates extracted from Vatican_osm.fbl,
corresponding to real roads (Via della Conciliazione area near St. Peter's Square).

The data sections include:
- **Section 1** (0x06D2): Compact geometry data (delta-encoded road shapes?)
- **Section 4** (0x0807): Road classification codes + full coordinate pairs
- **Section 5** (0x0FD6): Additional road data
- **Section 16** (0x16B9): Largest section — bulk map data

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

## What Would Be Needed to Reverse-Engineer

To fully understand the `.fbl` format, you would need:
1. ~~Access to actual `.fbl` files~~ — **DONE** (`disk-backup-with-map-Apr2026.zip` has 119 files)
2. Hex analysis of the file header to identify magic bytes and structure — **DONE** (magic bytes identified)
3. The decryption key or algorithm — **BLOCKER** (key is inside RSA-encrypted `.lyc`)
4. Comparison of decrypted data with known road network data (OSM) to identify encoding
5. Analysis of `nngine.dll` map loading/decryption functions (Ghidra)

The map rendering and routing code in `nngine.dll` would be the definitive reference
for the format, but it's a massive undertaking (the DLL is 3.3 MB of compiled code).

## Prior Art — Has Anyone Reversed This?

**No.** As of 2026, nobody has publicly reversed the NNG FBL map encryption.

- **No public decryption tools** — despite extensive searching, no working FBL decryptor
  exists on GitHub, GPSPower, XDA, or any GPS forum
- **"Fbl2kml"** — referenced on one site as a tool by "a Russian programmer named Alexey",
  but no download link, source code, or confirmation it exists
- **"NNG TOOL"** — a GPSPower thread discusses a tool for `device.nng` decryption
  (which we've already solved), not map data
- **Older iGO 8** used **unencrypted** `.fbl` files that could be freely copied between
  devices. NNG added encryption in Primo/NextGen specifically to prevent piracy
- **The GPS community works around it** — sharing pre-built packages for older unencrypted
  versions, or using NaviExtras Toolbox for newer encrypted versions
- **Maps are device-locked** — encrypted `.fbl` files can't be copied to another device
  without the matching `.lyc` license


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

### Phase 1: Understand the Encryption

- [ ] **T1.** Extract a small `.fbl` file from the disk backup for analysis
  - Use `Vatican_osm.fbl` (11 KB) — smallest file, fast to work with
  - Also extract `Vatican_osm.fpa` (1.5 KB) for comparison
- [ ] **T2.** Compare the first 64 bytes of multiple `.fbl` files
  - Extract 5-6 country files of different sizes
  - Document which bytes are constant vs variable
  - The magic `f9 6d 4a 16 6f c5 78 ee` is bytes 0-7 — what are bytes 8-63?
- [ ] **T3.** Compare `.fbl` vs `.fpa` for the same country
  - Report says they share "nearly identical first 64 bytes, differing only at
    offsets 0x10–0x13 and 0x1E" — verify this and document the exact differences
  - These differing bytes likely encode file type or size
- [ ] **T4.** Check if the magic bytes are a key or just a signature
  - XOR the magic bytes with known plaintext guesses (e.g., file size, "NNG", version)
  - If the magic is constant across all files, it's a signature not a key

### Phase 2: Find the Decryption Key

- [ ] **T5.** Analyse the `.lyc` license file structure
  - We already know the RSA layer (see `docs/license-system.md`)
  - After RSA decryption: 40-byte header with magic `0x36C8B267`
  - The XOR-CBC key is at header bytes 8-24
  - **Question:** Is this XOR-CBC key also the map decryption key?
- [ ] **T6.** Check if the map encryption uses the same XOR-CBC as `.lyc` files
  - Take the XOR-CBC key from a decrypted `.lyc` header
  - Try XOR-CBC decrypting `Vatican_osm.fbl` starting after the 8-byte magic
  - If the result has lower entropy or recognisable structure → we found the key
- [ ] **T7.** If T6 fails, look for the decryption in `nngine.dll`
  - The DLL must decrypt maps at runtime to render them
  - Search Ghidra for references to the magic bytes `f9 6d 4a 16`
  - Find the function that reads `.fbl` files — it must call a decryption routine
  - Trace the key source (from `.lyc`? from `device.nng`? hardcoded?)
- [ ] **T8.** Check if the `content.nng` file inside downloaded zips contains a key
  - The language pack zips have `content.nng` — extract and examine
  - May use the same NNGE format as `device.nng` (XOR-encoded)

### Phase 3: Decrypt a Map File

- [ ] **T9.** Implement the decryption in Python
  - Once the algorithm and key source are known
  - Start with `Vatican_osm.fbl` (smallest file)
  - Verify: decrypted output should have lower entropy and recognisable structure
- [ ] **T10.** Verify decryption against multiple files
  - Decrypt 3-4 different country `.fbl` files
  - Check that all produce valid output
  - Compare file sizes — decrypted size should match `.stm` `size` field

### Phase 4: Understand the Decrypted Format

- [ ] **T11.** Identify the internal structure of decrypted `.fbl`
  - Look for a header with version, bounding box, layer count
  - Search for recognisable patterns: coordinate pairs, string tables, road names
- [ ] **T12.** Cross-reference with OpenStreetMap data
  - Download the same country from Geofabrik (e.g., Vatican PBF)
  - Look for matching road names, coordinate values, node counts
  - This confirms we decrypted correctly and helps map the binary structure
- [ ] **T13.** Document the `.fbl` internal format
  - Header structure
  - How coordinates are encoded (fixed-point? delta-encoded?)
  - How road segments, names, and attributes are stored
  - Layer/zoom level organisation
- [ ] **T14.** Parse `.fpa` (address search) format
  - Likely a different internal structure optimised for text search
  - May contain street name → coordinate index
- [ ] **T15.** Parse `.poi` format
  - POI name, category, coordinates
  - May be simpler than `.fbl` since it's just point data
- [ ] **T16.** Parse `.spc` (speed camera) format
  - GPS coordinates + speed limit + camera type
  - Smallest and simplest format — good starting point after decryption

### Phase 5: Build Tools

- [ ] **T17.** `tools/maps/decrypt_fbl.py` — decrypt a `.fbl` file given the key
- [ ] **T18.** `tools/maps/fbl_info.py` — show header info, bounding box, stats
- [ ] **T19.** `tools/maps/fbl_to_geojson.py` — convert road network to GeoJSON for viewing
- [ ] **T20.** `tools/maps/spc_to_csv.py` — convert speed cameras to CSV (lat, lon, speed, type)

### Key Question

The entire effort hinges on **T5-T7**: finding the decryption key. If the key is
derived from the `.lyc` license (which we can already RSA-decrypt), then we can
read the maps. If it's a device-specific hardware key, we'd need to extract it
from the head unit.

The most promising path is T6 — trying the `.lyc` XOR-CBC key on the map data.
If that works, everything else follows.

## References

- [iGO (software) — Wikipedia](https://en.wikipedia.org/wiki/IGO_(software))
- [NNG (company) — Wikipedia](https://en.wikipedia.org/wiki/NNG_(company))
- [GPSPower iGO Maps forum](https://www.gpspower.net/igo-maps.html)
- [SCDB.info — Speed camera database for iGO](https://www.scdb.info/en/installation-igo/)
- [Convert.guru — FBL format description](https://convert.guru/fbl-converter)

### Compact Geometry Encoding (Not Yet Decoded)

The bulk of the road geometry is stored in a **variable-length bitstream** format
in section 1 (offset 0x06D2 in Vatican). This is NOT raw int32 coordinates — the
deltas between known road nodes (-23245, -20947, -3968, -4420, etc.) are not found
as raw bytes in the section.

**What we know:**
- Records have a 10-byte fixed prefix (`24 8B 18 A0 07 08 90 AC 61 80`)
- Records are separated by `68 00 02` markers
- Variable part encodes coordinate deltas in a bitstream
- Very few bits differ between adjacent records (consistent with small deltas)
- The encoding is likely a variable-length integer scheme (Elias gamma, Golomb, or custom)

**What would be needed to decode:**
- Trace the geometry reader in `nngine.dll` (the function that reads section 1)
- Or: brute-force test different variable-length integer encodings against known deltas
- The full int32 coordinates in section 4 provide ground truth for verification

This is the deepest layer of the format and would require significant reverse
engineering effort to fully decode.

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

This means the geometry is stored in two layers:
1. **Junction nodes** — full int32 coordinate pairs (already extracted)
2. **Shape points** — compressed intermediate points referenced by offset+count

### Shape Data Encryption — Blowfish (Confirmed)

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
