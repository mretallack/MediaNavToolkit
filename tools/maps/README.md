# Map File Tools

Tools for analysing, decrypting, and converting NNG iGO map files.

- Spec: [.kiro/specs/map-decryption/](../../.kiro/specs/map-decryption/)
- Format docs: [docs/mapformat.md](../../docs/mapformat.md)

## Setup

Extract test files from the disk backup (one-time):

```bash
cd /home/mark/git/MediaNavToolbox

mkdir -p tools/maps/testdata

# Small files for fast iteration
unzip -j analysis/usb-images/disk-backup-with-map-Apr2026.zip \
  "*/Vatican_osm.fbl" \
  "*/Vatican_osm.fpa" \
  "*/Monaco_osm.fbl" \
  "*/Monaco_osm.fpa" \
  "*/Andorra_osm.fbl" \
  "*/Andorra_osm.fpa" \
  "*/Andorra_osm.spc" \
  "*/EuropeEconomic.hnr" \
  -d tools/maps/testdata/

# Verify
ls -lh tools/maps/testdata/
```

## Tools

### analyse_header.py — Compare file headers

Reads the first 64 bytes of each file and shows which bytes are constant
vs variable across files. Identifies the header structure.

```bash
python tools/maps/analyse_header.py tools/maps/testdata/

# Output:
# Offset  Vatican.fbl  Vatican.fpa  Monaco.fbl  Andorra.spc  Constant?
# 0x00    f9           f9           f9           0b           FBL/FPA=f9, SPC=0b
# 0x01    6d           6d           6d           f4           FBL/FPA=6d, SPC=f4
# ...
```

### try_lyc_key.py — Try known keys on encrypted data

Attempts to decrypt a map file using keys we already have:
1. XOR-CBC key from `.lyc` license file
2. SnakeOil with magic bytes as seed
3. SnakeOil with `tb_secret` / `hu_secret`
4. Blowfish with the known DLL key

Reports Shannon entropy for each attempt. Entropy < 7.0 = likely decrypted.

```bash
# Try all known keys on Vatican map
python tools/maps/try_lyc_key.py tools/maps/testdata/Vatican_osm.fbl

# Try with a specific .lyc file
python tools/maps/try_lyc_key.py tools/maps/testdata/Vatican_osm.fbl \
  --lyc analysis/usb-images-latest/NaviSync/license/LGe_Renault_ULC*.lyc

# Output:
# Method              Entropy  Result
# XOR-CBC (.lyc key)  7.98     No change — not the right key
# SnakeOil (magic)    3.21     ✓ DECRYPTED! Recognisable structure found
# SnakeOil (secret)   7.97     No change
# Blowfish (DLL key)  7.99     No change
```

### decrypt_fbl.py — Decrypt a map file

Once the algorithm is known, decrypt any map file.

```bash
# Decrypt a single file
python tools/maps/decrypt_fbl.py tools/maps/testdata/Vatican_osm.fbl -o vatican.dec

# Decrypt all files in a directory
python tools/maps/decrypt_fbl.py tools/maps/testdata/ -o tools/maps/decrypted/

# Show info without writing
python tools/maps/decrypt_fbl.py tools/maps/testdata/Vatican_osm.fbl --info
```

### fbl_info.py — Show map file info

Display header information, bounding box, road count, and statistics
from a decrypted `.fbl` file.

```bash
python tools/maps/fbl_info.py tools/maps/decrypted/Vatican_osm.fbl

# Output:
# File:        Vatican_osm.fbl
# Size:        11,776 bytes
# Bounding box: 12.445°E, 41.900°N → 12.458°E, 41.907°N
# Roads:       42
# Names:       15
# Version:     ...
```

### spc_to_csv.py — Speed cameras to CSV

Export decrypted `.spc` files to CSV format.

```bash
python tools/maps/spc_to_csv.py tools/maps/decrypted/UnitedKingdom_osm.spc -o uk_cameras.csv

# Output CSV:
# latitude,longitude,speed_limit_kmh,type,direction
# 51.5074,-0.1278,48,fixed,both
# 52.4862,-1.8904,64,average,northbound
```

### fbl_to_geojson.py — Road network to GeoJSON

Export decrypted `.fbl` files to GeoJSON for viewing in QGIS or geojson.io.

```bash
python tools/maps/fbl_to_geojson.py tools/maps/decrypted/Vatican_osm.fbl -o vatican.geojson

# View in browser
open https://geojson.io  # paste the file
```

## Status

| Phase | Status | Next Step |
|-------|--------|-----------|
| 1. Header analysis | Not started | Extract test files (setup above) |
| 2. Try known keys | Not started | Blocked on Phase 1 |
| 3. DLL analysis | Not started | Only if Phase 2 fails |
| 4. Decryption | Not started | Blocked on Phase 2/3 |
| 5. Parse & export | Not started | Blocked on Phase 4 |
