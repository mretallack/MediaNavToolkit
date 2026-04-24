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

**Protocol fully reverse-engineered.** All cryptographic parameters derived from credentials — no captured data or hardcoded values needed.

| Component | Status |
|-----------|--------|
| Wire protocol encryption (SnakeOil xorshift128) | ✅ Solved |
| Delegated request generation (`build_dynamic_request`) | ✅ Byte-exact match with captured data |
| Session key derivation | ✅ Solved: `creds.secret` (toolbox Secret) |
| HMAC-MD5 delegation auth | ✅ Verified against captured logs |
| USB detection + device identity | ✅ Working |
| Device registration | ✅ Working |
| Full authentication flow | ✅ Working (login → fingerprint → delegator → senddevicestatus) |
| senddevicestatus → server | ✅ Returns HTTP 200 |
| Catalog browsing (30 packages, 31 content items) | ✅ Working |
| Content selection + size estimation | ✅ Working |
| License fetch + install (.lyc + .lyc.md5) | ✅ Working |
| Sync command (select → confirm → install) | ✅ Working |

**340 tests passing** (57 wire format tests, 32 golden round-trip, 18 USB layout verification).

### How Map Updates Work

The NaviExtras catalog shows all map packages compatible with your head unit. Maps are
region-based (e.g., "UK + Ireland", "Western Europe") and cost £49–£129 each. The only
free content is the Dealership POI pack.

Map data can be downloaded by any registered device, but the head unit requires a valid
`.lyc` license file (RSA-signed) to accept the update. Purchasing a map through the
NaviExtras store generates the license. The `sync` command handles the full flow:
select content → confirm with server → download licenses → write to USB.

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
NAVIEXTRAS_USB_PATH=/mnt/pen
```

With `NAVIEXTRAS_USB_PATH` set, you can omit `--usb-path`:

## CLI Commands

```bash
# Detect your MediaNav USB drive
medianav-toolbox detect

# Authenticate and show session info
medianav-toolbox login

# Browse available content (maps, POIs, safety cameras)
medianav-toolbox catalog

# Show and install available licenses
medianav-toolbox licenses
medianav-toolbox licenses --install

# Quick update check
medianav-toolbox updates

# Sync updates to USB drive (select → download → install)
medianav-toolbox sync
```

> **Note:** You can also pass `--usb-path /mnt/pen` before the command instead of using the env var.
> If the USB is read-only, credentials are cached in `~/.config/medianav-toolbox/`.
```

### Usage Flow

1. **Sync your car** — plug the USB drive into your MediaNav head unit and let it sync
2. **Plug USB into PC** — the drive must contain `NaviSync/license/device.nng`
3. **Run the tool** — `medianav-toolbox catalog` to see available content
4. **Buy content** — `medianav-toolbox buy 61811` to purchase (free items install automatically)
5. **Install licenses** — `medianav-toolbox licenses --install` to write licenses to USB
6. **Sync back to car** — plug the USB drive back into the head unit to apply updates

### Example Output

```
$ medianav-toolbox detect
✓ MediaNav device detected
  AppCID:  0x42000B53
  Space:   2.3 GB free / 4.4 GB total
  OS:      6.0.12.2.1166_r2

$ medianav-toolbox catalog
  Dealership POI                       2012 Q1    61811  ✓ purchased
  Map of Europe                           14.4    62038
  Map of France                           14.4   121256
  Map of United Kingdom and Ireland       14.4    62122
  Map of Western Europe                   14.4   123788
  ... (38 items total)

$ medianav-toolbox sync --dry-run
Connecting...
Fetching content tree...
Selecting 31 items...
            Selected Content
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Content                   ┃      Size ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ France                    │  715.0 MB │
│ Germany                   │  529.7 MB │
│ United Kingdom            │  487.8 MB │
│ ...                       │       ... │
└───────────────────────────┴───────────┘
Total download: 6.10 GB

$ medianav-toolbox sync -c "United Kingdom"
Connecting...
Selecting 1 items...
Total download: 487.8 MB
✓ Selection confirmed

$ medianav-toolbox licenses --install
  RenaultDealers_Pack.lyc  440 B  ✓ installed
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
├── wire_codec.py        # Request body encoder
└── wire_message.py      # Structured wire message decode/encode
```

### Protocol Overview

The NaviExtras API uses a custom binary wire protocol over HTTPS:

**Standard requests** (login, fingerprint, register):
```
[16B header] [SnakeOil(query, Code)] [SnakeOil(body, Secret)]
```

**Delegated requests** (senddevicestatus):
```
[16B header] [1B prefix] [SnakeOil(query, Secret)] [SnakeOil(body, Secret)]
```
Each SnakeOil call resets the PRNG independently. The session key is `creds.secret`
(toolbox Secret from registration). The body is standard plaintext format.

See [docs/chain-encryption.md](docs/chain-encryption.md) for the complete payload
construction recipe with test vectors.

Full session flow:
```
1. Boot          → service URLs           (RANDOM mode)
2. Register      → toolbox credentials    (RANDOM mode, cached)
3. Login         → JSESSIONID             (DEVICE mode)
4. Fingerprint   → 200                    (DEVICE mode)
5. Delegator     → head unit credentials  (DEVICE mode)
6. DeviceStatus  → 200                    (delegated, session_key = creds.secret)
7. Web login     → authenticated session  (HTTP form POST)
8. Catalog       → content tree + sizes   (HTTP GET/POST)
```

See [docs/reverse-engineering.md](docs/reverse-engineering.md) for full protocol documentation.

## License

MIT
