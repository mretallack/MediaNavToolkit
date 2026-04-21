# MediaNav Toolbox

> **⚠️ WARNING — USE AT YOUR OWN RISK ⚠️**
>
> This software is **experimental** and **completely unofficial**. It was built by
> reverse-engineering proprietary protocols and could behave in unexpected ways.
>
> **This tool could:**
> - **Brick your head unit** — corrupted updates may render your MediaNav permanently inoperable
> - **Void your warranty** — using unofficial tools to modify your head unit is not sanctioned by Dacia, Renault, or NNG
> - **Damage your vehicle** — the head unit is connected to vehicle systems; a bad update could have unpredictable consequences
> - **Violate terms of service** — using this tool may breach your naviextras.com account terms
> - **Produce incorrect map/navigation data** — potentially leading to dangerous driving situations
>
> The authors accept **no responsibility whatsoever** for any damage to your head unit,
> vehicle, naviextras.com account, or anything else that results from using this software.
>
> **You have been warned. Seriously.**

A Linux/Python replacement for the Windows-only **Dacia MediaNav Evolution Toolbox** — the official app for updating maps, POIs, speed cameras, and voice packs on Dacia/Renault MediaNav head units.

This project reverse-engineers the NaviExtras wire protocol and reimplements it as a Python library and CLI tool.

## Current Status

**Working end-to-end:**
- ✅ USB drive detection and device identity reading
- ✅ Device registration with NaviExtras server
- ✅ Full authentication flow (boot → login → fingerprint → delegator → senddevicestatus)
- ✅ Wire protocol encryption fully solved (SnakeOil xorshift128 cipher)
- ✅ Catalog browsing — 38 items (maps, POIs, safety cameras) from live server
- ✅ Free content purchase via web API (e.g., Dealership POI)
- ✅ License fetching — `.lyc` files downloaded live from server (no replay needed)
- ✅ License installation to USB drive (`.lyc` + `.lyc.md5`)
- ✅ 219 unit tests passing

## Requirements

- Python 3.11+
- A [naviextras.com](https://www.naviextras.com) account
- A USB drive previously used with your MediaNav head unit (contains `device.nng`)

## Quick Start

```bash
git clone https://github.com/mretallack/MediaNavToolkit.git
cd MediaNavToolkit
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

Create a `.env` file with your credentials:

```ini
NAVIEXTRAS_USER=your.email@example.com
NAVIEXTRAS_PASS=your_password
```

## CLI Commands

```bash
# Detect your MediaNav USB drive
medianav-toolbox --usb-path /media/usb detect

# Authenticate and show session info
medianav-toolbox --usb-path /media/usb login

# Browse available content (maps, POIs, safety cameras)
medianav-toolbox --usb-path /media/usb catalog

# Show and install available licenses
medianav-toolbox --usb-path /media/usb licenses
medianav-toolbox --usb-path /media/usb licenses --install

# Quick update check
medianav-toolbox --usb-path /media/usb updates

# Sync updates to USB drive (select → download → install)
medianav-toolbox --usb-path /media/usb sync
```

> **Note:** `--usb-path` is a global option that goes **before** the command name.
> If the USB is read-only, credentials are cached in `~/.config/medianav-toolbox/`.
```

### Usage Flow

1. **Sync your car** — plug the USB drive into your MediaNav head unit and let it sync
2. **Plug USB into PC** — the drive must contain `NaviSync/license/device.nng`
3. **Run the tool** — `medianav-toolbox catalog --usb-path /media/usb` to see available updates
4. **Download updates** — `medianav-toolbox sync --usb-path /media/usb` to download and install
5. **Sync back to car** — plug the USB drive back into the head unit to apply updates

### Example Output

```
$ medianav-toolbox detect --usb-path /media/usb
✓ MediaNav device detected
  AppCID:    0x42000B53
  BrandMD5:  3deaefba446c34753f036d584c053c6c
  Space:     2.3 GB free / 4.4 GB total
  OS:        6.0.12.2.1166_r2

$ medianav-toolbox catalog --usb-path /media/usb
                    Available Content (Catalog)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━┓
┃ Content                                       ┃ Release ┃      ID ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━┩
│ Dealership POI                                │ 2012 Q1 │   61811 │
│ Map of Europe                                 │    14.4 │   62038 │
│ Map of France                                 │    14.4 │  121256 │
│ Map of United Kingdom and Ireland             │    14.4 │   62122 │
│ Map of Western Europe                         │    14.4 │  123788 │
│ ...                                           │         │         │
└───────────────────────────────────────────────┴─────────┴─────────┘
Total: 38 items

$ medianav-toolbox licenses --usb-path /media/usb
                        Available Licenses
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━┓
┃ License File            ┃ SWID                        ┃  Size ┃ Status      ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━┩
│ RenaultDealers_Pack.lyc │ CW-7UIM-QAUY-IIQY-73MI-773E│ 440 B │ ✓ installed │
└─────────────────────────┴─────────────────────────────┴───────┴─────────────┘
```

## Supported Devices

Currently targets **Dacia MediaNav Evolution** head units (model: `DaciaAutomotiveDeviceCY20_ULC4dot5`). The same NaviExtras API is used by Renault, Opel, Nissan, and other brands with NNG-based navigation.

## Development

```bash
# Run tests
pytest tests/ -v

# Format
black medianav_toolbox/ tests/
isort medianav_toolbox/ tests/

# Integration tests (requires .env credentials + USB drive image)
pytest tests/integration/ -v
```

## Architecture

```
medianav_toolbox/
├── api/
│   ├── boot.py          # Service URL discovery
│   ├── client.py        # HTTP client with retry
│   └── register.py      # Device registration + delegator
├── catalog.py           # HTML catalog + content tree parsers
├── cli.py               # Click CLI (detect, login, catalog, updates, register)
├── config.py            # Brand defaults from plugin.dll
├── content.py           # Content selection + size estimation
├── crypto.py            # SnakeOil xorshift128 cipher
├── device.py            # USB drive detection, device.nng parsing
├── download.py          # Download manager with cache + MD5 verify
├── fingerprint.py       # Device fingerprint encoding
├── igo_parser.py        # igo-binary response parser
├── igo_serializer.py    # Credential block encoder
├── installer.py         # USB content writer (.stm, .lyc, checksums)
├── models.py            # Data classes
├── protocol.py          # Wire protocol envelope (header + SnakeOil)
├── session.py           # Full session flow orchestration
├── swid.py              # SWID generation (MD5 + Crockford base32)
└── wire_codec.py        # Request body encoder
```

### Protocol Overview

The NaviExtras API uses a custom binary wire protocol:

```
[16B header] [SnakeOil-encrypted query] [SnakeOil-encrypted body]

Header: [0x01] [0xC2 0xC2] [mode] [8B key] [svc_minor] [0x00 0x00] [nonce]
Mode:   0x20 = RANDOM (unauthenticated), 0x30 = DEVICE (authenticated)
Key:    Code (for query encryption), Secret (for body encryption)
```

For delegated requests (flags=0x68), the body is split-encrypted:
```
[16B header] [SnakeOil(25B query, Code)] [SnakeOil(17B prefix, Secret)] [SnakeOil(body, Secret)]
```
Each SnakeOil segment uses a fresh PRNG state.

Full session flow:
```
1. Boot          → service URLs           (RANDOM mode)
2. Register      → toolbox credentials    (RANDOM mode, cached)
3. Login         → JSESSIONID             (DEVICE mode)
4. Fingerprint   → 200                    (DEVICE mode)
5. Delegator     → head unit credentials  (DEVICE mode)
6. DeviceStatus  → 200 (×2: D802 + D803) (DEVICE mode, 0x60 flags)
7. Licenses      → .lyc file data         (DEVICE mode, 0x20 flags)
8. Web login     → authenticated session  (HTTP form POST)
9. Catalog       → content tree + sizes   (HTTP GET/POST)
```

See [toolbox.md](.kiro/specs/medianav-toolbox/toolbox.md) for detailed reverse engineering notes.

## License

MIT
