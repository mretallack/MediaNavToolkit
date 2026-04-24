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

## References

- [iGO (software) — Wikipedia](https://en.wikipedia.org/wiki/IGO_(software))
- [NNG (company) — Wikipedia](https://en.wikipedia.org/wiki/NNG_(company))
- [GPSPower iGO Maps forum](https://www.gpspower.net/igo-maps.html)
- [SCDB.info — Speed camera database for iGO](https://www.scdb.info/en/installation-igo/)
- [Convert.guru — FBL format description](https://convert.guru/fbl-converter)
