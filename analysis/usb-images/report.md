# MediaNav USB Map Data Analysis

## Overview

Analysis of map data extracted from a Dacia MediaNav USB backup (`disk-backup-with-map-Apr2026.zip`, ~3.1GB, 777 files).

## System Identification

| Field | Value |
|-------|-------|
| Brand | Dacia |
| Navigation Software | iGO Primo by NNG |
| Software Version | 9.12.179.821558 |
| OS | GNU/Linux 6.0.12.2.1166_r2 |
| Display | 800x480 |
| Device Profile | DaciaAutomotiveDeviceCY20_ULC4dot5 |
| NaviExtras Server | zippy.naviextras.com |
| Map Update | LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3 |
| Storage | ~4.4GB total, ~734MB free |

## Directory Structure

```
NaviSync/
├── license/          # DRM license files (.lyc), device identity
│   └── .reg/         # Registration data (device keys, NaviExtras account link)
├── content/
│   ├── map/          # Encrypted map data (.fbl, .fpa, .hnr)
│   ├── poi/          # Points of Interest (.poi)
│   ├── speedcam/     # Speed camera data (.spc)
│   ├── lang/         # Language packs (.zip.stm references)
│   ├── voice/        # Voice guidance packs (.zip.stm references)
│   ├── tmc/          # Traffic Message Channel data
│   ├── global_cfg/   # Global configuration
│   └── userdata/POI/ # Dealer POIs (Renault, Dacia, Nissan, etc.)
├── save/             # User settings, route history, preload caches
└── device_status.ini # Device capabilities and storage info
```

## Map File Types

| Extension | Purpose | Example |
|-----------|---------|---------|
| `.fbl` | Map geometry, road network, labels | `France_osm.fbl` (267MB) |
| `.fpa` | Address search data | `France_osm.fpa` (147MB) |
| `.hnr` | Historic speed profiles (Economic/Fastest/Shortest) | `EuropeEconomic.hnr` (62MB) |
| `.poi` | Points of Interest | `UnitedKingdom_osm.poi` |
| `.spc` | Speed camera locations | `France_osm.spc` |
| `.stm` | Metadata/status (plaintext) | `Basemap.fbl.stm` |
| `.lyc` | DRM license files | `LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc` |

## Countries Covered

Map data present for 30 regions: Algeria, Andorra, Austria, Belgium, Denmark, France, French Guiana, Germany, Gibraltar, Greece, Guadeloupe, Ireland, Italy, Liechtenstein, Luxembourg, Malta, Martinique, Mayotte, Monaco, Morocco, Netherlands, Portugal, Reunion, Saint Pierre and Miquelon, San Marino, Spain, Switzerland, Tunisia, United Kingdom, Vatican.

## Encryption Analysis

### Findings

The map data files (.fbl, .fpa, .hnr) are **encrypted**.

- **Shannon entropy**: 7.98 / 8.0 bits per byte (99.79%) — indistinguishable from random data
- **All 256 byte values present** in even the smallest file (11KB Vatican)
- `file` command identifies all map files simply as `data` — no recognisable structure

### Header Patterns

All `.fbl` and `.fpa` files share an 8-byte magic number:

```
f9 6d 4a 16 6f c5 78 ee
```

The `.hnr` files use a different magic:

```
e2 66 4c 50 34 c2 7f ce
```

Bytes 9–16 vary slightly between files (likely encoding region ID or file size), with the remainder being fully encrypted content.

For the same country, the `.fbl` and `.fpa` files share nearly identical first 64 bytes, differing only at offsets 0x10–0x13 and 0x1E — suggesting a small plaintext header followed by encrypted payload.

### DRM Licensing

Content is locked to the specific device via NNG's licensing system:

- License key: `CK-A80R-YEC3-MYXL-18LN`
- Multiple content activation keys in `reg.sav`
- `.lyc` files are themselves encrypted/binary

## .stm Metadata Files

The `.stm` files are plaintext and describe the status of their associated content file:

**Basemap.fbl.stm** (references pre-installed content):
```
purpose = shadow
size = 9409937
content_id = 536350286
header_id = 117863961
timestamp = 1558967844
```

**Vatican_osm.fbl.stm** (USB-delivered update):
```
purpose="copy"
```

- `purpose=shadow` — content lives on the device's internal storage; the `.stm` is a reference
- `purpose="copy"` — content on USB is to be copied to the device

## Conclusion

The map files **cannot be decoded**. NNG uses proprietary encryption tied to their device licensing and NaviExtras distribution platform. Although the underlying data source is OpenStreetMap (indicated by the `_osm` suffix in filenames), the compiled and encrypted `.fbl`/`.fpa` binary format is NNG's proprietary format with DRM.

### Alternative: Raw OSM Data

To work with the same geographic data in an open format, download directly from:

- https://download.geofabrik.de/ (pre-cut country extracts)
- https://planet.openstreetmap.org/ (full planet file)

These provide the same OpenStreetMap data in open formats (PBF, XML) that can be processed with tools like osmium, osm2pgsql, or OSRM.

---

## Golden Sample Archives

### `post-car-sync-20260716.tar.gz` (8.6 MB, 460 files)

Fresh sync from car on 16 July 2026, after the first map update (UK & Ireland OSM,
Oct 2025) was applied to the head unit. This is the **reference state** for testing
the Python toolbox against the NaviExtras server.

**Key facts:**
- Car running updated OSM maps (content_id 7343329 for UK, timestamp 2025-10-02)
- License `LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc` present (purchased 2026-04-14)
- Subscription: "latest map + 1 more update during the next year" (valid until ~Apr 2027)
- Server confirms: **31 updates available** (15.2 release for all Western Europe countries)
- Catalog shows UK & Ireland as **✓ purchased**
- Free space: 733 MB / 4.4 GB total (head unit storage after update)

**What changed from the pre-update state (March 2026 sync):**
- Map files renamed: `UnitedKingdom.fbl.stm` → `UnitedKingdom_osm.fbl.stm`
- New `.fpa.stm` files (address data) added alongside each `.fbl.stm`
- New license file added: `LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc`
- HNR routing renamed: `WesternEuropeEconomic.hnr.stm` → `EuropeEconomic.hnr.stm`
- Algeria added to map set
- Free space dropped from 2.3 GB to 733 MB

**Usage:**
```bash
# Extract to use as test USB image
mkdir -p /tmp/test_usb
tar xzf analysis/usb-images/post-car-sync-20260716.tar.gz -C /tmp/test_usb

# Run toolbox against it
NAVIEXTRAS_USB_PATH=/tmp/test_usb medianav-toolbox catalog
```
