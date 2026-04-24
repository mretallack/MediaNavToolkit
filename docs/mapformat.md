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
- Country-level files (one `.fbl` per country)
- Sizes range from 0.02 MB (Vatican) to 221 MB (France)
- `Basemap.fbl` (9 MB) provides low-zoom overview of all regions
- Referenced by `content_id` and `header_id` in `.stm` shadow files
- **Not encrypted** — the `.lyc` license is the protection, not file encryption *(likely but unconfirmed)*
- Described by third parties as "compiled map data" containing "vector geometry, road networks, and points of interest"

**What we don't know:**
- Internal binary structure (header format, data encoding, compression)
- Whether there's a magic number/signature at the start of the file
- How routing data is indexed
- The relationship between `.fbl` and `.hnr` files

### HNR — Historical Navigation Routing (Inferred)

Routing optimization data, likely pre-computed route weights based on historical traffic patterns.

**What we know:**
- 6 files covering Eastern and Western Europe
- Named by region + routing strategy: `Fastest`, `Shortest`, `Economic`
- Sizes: 17–47 MB each
- Same `header_id` (1182797806–1182797819) suggesting they're part of one dataset

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

**What we know:**
- Country-level files for 9 countries
- Very small (total 0.3 MB)
- Contains GPS coordinates + speed limits + camera types
- The [SCDB.info](https://www.scdb.info/en/installation-igo/) project provides
  compatible speed camera databases, confirming the format is at least partially understood

### TMC — Traffic Message Channel (Confirmed)

**What we know:**
- Provider-specific files (e.g., `France-V-Trafic.tmc`, `Germany_HERE.tmc`)
- Very small (<0.1 MB total)
- Maps TMC location codes to road segments for real-time traffic

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
1. Access to actual `.fbl` files (on the head unit's internal storage)
2. Hex analysis of the file header to identify magic bytes and structure
3. Comparison of multiple country files to identify common patterns
4. Cross-reference with known road network data (OSM) to identify encoding
5. Analysis of `nngine.dll` map loading functions (Ghidra)

The map rendering and routing code in `nngine.dll` would be the definitive reference
for the format, but it's a massive undertaking (the DLL is 3.3 MB of compiled code).

## References

- [iGO (software) — Wikipedia](https://en.wikipedia.org/wiki/IGO_(software))
- [NNG (company) — Wikipedia](https://en.wikipedia.org/wiki/NNG_(company))
- [GPSPower iGO Maps forum](https://www.gpspower.net/igo-maps.html)
- [SCDB.info — Speed camera database for iGO](https://www.scdb.info/en/installation-igo/)
- [Convert.guru — FBL format description](https://convert.guru/fbl-converter)
