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
> If your car catches fire, your maps point you into a lake, or this somehow triggers
> World War 3 — that's on you.
>
> **You have been warned. Seriously.**

A Linux/Python replacement for the Windows-only **Dacia MediaNav Evolution Toolbox** — the official app for updating maps, POIs, speed cameras, and voice packs on Dacia/Renault MediaNav head units.

This project reverse-engineers the NaviExtras API protocol used by the original Windows app and reimplements it as a Python library and CLI tool.

## What It Does

1. **Detects** your MediaNav USB drive and reads the device identity (`device.nng`)
2. **Authenticates** with the NaviExtras server using your naviextras.com account
3. **Fetches** the content catalog to show available map/POI/voice updates
4. **Downloads** update files with resume support and MD5 verification
5. **Installs** updates to the USB drive in the correct format for the head unit's synctool

## Requirements

- Python 3.11+
- A [naviextras.com](https://www.naviextras.com) account
- A USB drive previously used with your MediaNav head unit (contains `device.nng`)

## Quick Start

### Install

```bash
git clone https://github.com/youruser/MediaNavToolbox.git
cd MediaNavToolbox
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
```

### Configure

Copy the example env file and fill in your credentials:

```bash
cp .env.example .env
# Edit .env with your naviextras.com email and password
```

```ini
NAVIEXTRAS_USER=your.email@example.com
NAVIEXTRAS_PASS=your_password
NAVIEXTRAS_USB_PATH=/media/usb
```

### CLI Usage

```bash
# Detect your MediaNav USB drive
medianav-toolbox detect --usb-path /media/usb

# Check what updates are available
medianav-toolbox catalog --usb-path /media/usb

# Download and install all available updates
medianav-toolbox sync --usb-path /media/usb

# Or step by step:
medianav-toolbox download --usb-path /media/usb
medianav-toolbox install --usb-path /media/usb
```

### Python Library Usage

```python
from medianav_toolbox import Toolbox

# Credentials loaded from .env automatically
tb = Toolbox(usb_path="/media/usb")

# Or pass explicitly
tb = Toolbox(
    usb_path="/media/usb",
    username="your.email@example.com",
    password="your_password",
)

# Full sync (detect → login → catalog → download → install)
result = tb.sync()
print(f"Updated {result.installed_count} items")

# Or step by step
tb.boot()
tb.login()
device = tb.detect_device()
catalog = tb.catalog()

for item in catalog:
    print(f"  {item.name} ({item.content_type.value}) - {'installed' if item.installed else 'available'}")

files = tb.download(catalog)
tb.install(files)
```

## USB Drive Structure

The tool expects a USB drive with the standard MediaNav layout:

```
NaviSync/
├── device_checksum.md5
├── device_status.ini
├── content/
│   ├── brand.txt            # "dacia"
│   ├── map/*.fbl.stm        # Map metadata
│   ├── poi/*.poi.stm        # POI metadata
│   ├── speedcam/*.spc.stm   # Speed camera metadata
│   ├── voice/*.zip.stm      # Voice pack metadata
│   └── ...
├── license/
│   ├── device.nng           # Device identity (required)
│   └── *.lyc                # License files
└── save/                    # User data
```

## Supported Devices

Currently targets **Dacia MediaNav Evolution** head units (brand: `DaciaAutomotive`, model filter: `Dacia_ULC`). The same API is used by Renault, Opel, Nissan, and other brands with NNG-based navigation — support for those could be added by changing the brand configuration.

## Development

```bash
# Run tests
pytest tests/ -v

# Run with formatting
black medianav_toolbox/ tests/
isort medianav_toolbox/ tests/

# Run integration tests (requires credentials in .env)
pytest tests/integration/ -v -m integration
```

## How It Works

The original Windows app (`DaciaMediaNavEvolutionToolbox.exe`) is a CEF (Chromium) shell that loads `nngine.dll` — NNG's navigation engine library. All server communication goes through the NaviExtras API at `zippy.naviextras.com`.

This project was built by reverse-engineering the original app using Ghidra. See the `.kiro/specs/medianav-toolbox/` directory for:

- **[design.md](.kiro/specs/medianav-toolbox/design.md)** — Library architecture, module design, test plans
- **[toolbox.md](.kiro/specs/medianav-toolbox/toolbox.md)** — Detailed Ghidra decompilation traces with line references
- **[tasks.md](.kiro/specs/medianav-toolbox/tasks.md)** — Implementation plan

### API Flow

```
Boot (GET /rest/2/boot)
  → Service URLs (index, register, selfie)

Register (/get_device_model_list, /devinfo, /device)
  → Device recognized and registered

Login (POST /login with credentials + device)
  → Session (JSESSIONID + device-auth token)

Market calls (/senddrives, /sendfingerprint, /getprocess, ...)
  → Content catalog + download URLs

Download → Install to USB → Head unit syncs on next boot
```

## License

MIT
