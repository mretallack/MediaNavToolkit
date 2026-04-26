# License System

> How map content is protected and activated on MediaNav head units.

## Overview

Map updates are distributed as data files on the USB drive. The head unit will only
accept an update if a valid `.lyc` license file is present. Licenses are RSA-signed
and tied to specific content packages and device SWIDs.

**The map data itself is not encrypted** — it's stored as plain `.fbl`, `.poi`, `.spc`
files on the head unit's internal storage. The `.lyc` license is the only protection.

## License File Format (.lyc)

`.lyc` files use a two-layer encryption scheme:

### Layer 1: RSA (PKCS#1 v1.5)

The first 256 bytes of the `.lyc` file are an RSA-encrypted block.

| Property | Value |
|----------|-------|
| Algorithm | RSA PKCS#1 v1.5 |
| Key size | **2048 bits** (256 bytes) |
| Exponent | **65537** (0x10001) |
| Padding | `00 02 [random] 00 [payload]` |
| Payload | 40-byte credential header |

The RSA public key is embedded in `nngine.dll` at RVA `0x30B588`:

```
Modulus (2048-bit):
  6B231771 184FAAD8 86AE159B ADB1D45A 5BC4338D 4F503A61 93DA01A6 19E5D21A
  C873174C 7D206CEA FED3AF22 FEE1019D B84BA294 B41339FC CD19048C 95FB9CED
  ABCAE871 13D188FC 2D3050CA 2FAF12EE 5A292B17 D3490364 360B9656 65AECB52
  4265B9AF BDAAA0ED DAD53042 93D70FBA 49609AC2 5F8AF346 4E55FF79 BCE67681
  A3E3E3E3 C3E3E3E3 ...
  (full 256 bytes in nngine.dll)
```

### Layer 2: XOR-CBC

After RSA decryption of the first block, the remaining blocks are decrypted using
XOR-CBC with a key derived from the RSA payload:

1. RSA decrypt first 256 bytes → 40-byte header
2. Header contains magic `0x36C8B267` + XOR-CBC key (16 bytes at offset 8-24)
3. XOR-CBC decrypt remaining data using the key
4. Result: license key string + product name

### DLL Functions

| RVA | Function | Purpose |
|-----|----------|---------|
| `0x0EA960` | Credential parser | Reads .lyc, calls provider decrypt |
| `0x158610` | Provider decrypt | Iterates chunks, calls RSA |
| `0x158710` | RSA validate | Calls PKCS#1 v1.5 decrypt |
| `0x154B40` | RSA PKCS#1 v1.5 | Decrypt with padding check |
| `0x154860` | RSA modexp | `m = c^e mod n` |
| `0x158410` | XOR-CBC transform | Validates MD5, XOR-CBC with key from header |

## License Distribution

Licenses are fetched via the wire protocol:

```
POST /services/register/rest/14/licenses
```

The response contains embedded `.lyc` file data:

```
[0x40][2B count BE] then for each entry:
  [0xC0][4B timestamp][4B expiry][1B swid_len][swid]
  [1B fname_len][filename][4B lyc_size][lyc_data]
```

Each license is tied to a **SWID** (Software ID) — a Crockford base32 string like
`CW-7UIM-QAUY-IIQY-73MI-773E`. The SWID identifies the content package.

## SWID Generation

SWIDs are computed from a serial number using MD5 + Crockford base32:

```python
md5 = MD5(f"SPEEDx{serial}CAM")
swid = crockford_base32(md5[:10])  # first 10 bytes → 16 chars
formatted = f"CK-{swid[0:4]}-{swid[4:8]}-{swid[8:12]}-{swid[12:16]}"
```

DLL function: `FUN_100BD380` (formats "SPEEDx%sCAM", computes MD5).

## USB Layout

Licenses are installed to `NaviSync/license/` on the USB drive:

```
NaviSync/license/
  device.nng                              # Device identity (268B)
  SomeMap_Update.lyc                      # License file (RSA-encrypted)
  SomeMap_Update.lyc.md5                  # MD5 checksum of .lyc
  SomeMap_Update.lyc.stm                  # Shadow metadata (purpose="copy")
```

The `.md5` file contains the uppercase hex MD5 of the `.lyc` file content.
The `.stm` file tells the synctool to copy the license to the head unit.

## Content Activation Flow

1. User purchases a map package on naviextras.com
2. Server generates an RSA-signed `.lyc` license for the device's SWID
3. Toolbox fetches the license via the `licenses` wire endpoint
4. Toolbox writes `.lyc` + `.lyc.md5` + `.lyc.stm` to USB
5. User plugs USB into head unit
6. Head unit's synctool reads the `.lyc` file
7. Head unit RSA-decrypts and validates the license
8. If valid, the map update is activated

## Map Content on USB

Map data is referenced by `.stm` (shadow metadata) files in `NaviSync/content/`:

```ini
# NaviSync/content/map/France.fbl.stm
purpose = shadow
size = 231444992
content_id = 6816923
header_id = 117863961
timestamp = 1580481844
```

The actual map data lives on the head unit's internal storage. The `.stm` file
tells the synctool what version is installed. The `content_id` and `timestamp`
identify the specific map version.

## Pricing (as of 2026-04)

| Region | Price (GBP) |
|--------|-------------|
| Dealership POI | Free |
| Morocco, Tunisia, Turkey | £49 |
| France, UK+Ireland, Italy, Romania, Cyprus, French overseas | £69 |
| Iberia, DACH, Benelux, Egypt, India, South Africa, NE Europe | £89 |
| Australia+NZ, Southern Africa | £99 |
| Western Europe, Eastern Europe | £119 |
| Middle East | £129 |

All maps are version 14.4. The catalog shows all packages compatible with the
device model, regardless of purchase status.

## Files

| File | Purpose |
|------|---------|
| `medianav_toolbox/installer.py` | `install_license()` — writes .lyc + .md5 + .stm |
| `medianav_toolbox/catalog.py` | `parse_licenses_response()` — parses wire license data |
| `medianav_toolbox/crypto.py` | `snakeoil()` — wire protocol encryption |
| `.kiro/specs/medianav-toolbox/reverse_engineer_nnge.md` | Full RSA reverse engineering notes |
