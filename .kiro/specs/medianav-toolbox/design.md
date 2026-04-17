# Design: MediaNav Toolbox Python Library

> **Reverse engineering reference:** See [toolbox.md](toolbox.md) for protocol details, encryption keys, and data source locations.
> **Function reference:** See [functions.md](functions.md) for annotated Ghidra function map.
> **NNGE research:** See [reverse_engineer_nnge.md](reverse_engineer_nnge.md) for .lyc RSA decryption and credential analysis.

---

## 1. Goal

A CLI tool that replaces the Windows-only Dacia MediaNav Evolution Toolbox. The workflow:

1. User inserts USB in head unit → head unit writes sync data (device.nng, fingerprints, save files)
2. User plugs USB into PC → CLI reads sync data, registers device, authenticates
3. CLI shows available map/content updates with sizes
4. User selects updates → CLI downloads content files
5. CLI writes content + licenses + checksums to USB in the correct layout
6. User inserts USB back in head unit → synctool processes the update

**Out of scope:** Map purchase (handled by NaviExtras web store in browser). We handle everything else.

---

## 2. Library Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI (cli.py)                            │
│  detect │ register │ login │ catalog │ updates │ sync        │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│              medianav_toolbox (public API) (__init__.py)      │
│                                                              │
│  Toolbox(usb_path)                                           │
│    .detect_device() → DeviceInfo                             │
│    .boot()          → ServiceEndpoints                       │
│    .register()      → Credentials                            │
│    .login()         → Session                                │
│    .catalog()       → list[ContentItem]                      │
│    .download()      → list[Path]                             │
│    .install()       → InstallResult                          │
│    .sync()          → SyncResult  (full pipeline)            │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│                    Internal Modules                           │
│                                                              │
│  device.py ✓        protocol.py ✓       api/ ✓               │
│  - device.nng       - SnakeOil          - client.py          │
│  - brand.txt        - Envelope          - boot.py            │
│  - APPCID           - RANDOM/DEVICE     - register.py        │
│  - XOR decode                           - market.py          │
│                     crypto.py ✓         - catalog.py         │
│  config.py ✓        - SnakeOil          - igo_binary.py      │
│  models.py ✓        - Blowfish                               │
│  auth.py ✓                              installer.py ✓       │
│  fingerprint.py ✓   wire_codec.py ✓     - USB layout         │
│  swid.py ✓          igo_parser.py ✓     - .lyc/.stm/.md5     │
│  session.py ✓       igo_serializer.py ✓                      │
│  catalog.py ✓       download.py ✓                            │
│  content.py ✓                                                │
└──────────────────────────────────────────────────────────────┘
```

**All modules implemented and tested.** 204 unit tests passing.

---

## 3. Encryption — Fully Reversed

### SnakeOil (wire protocol)

xorshift128 PRNG stream cipher. Symmetric XOR. Reversed from `FUN_101b3e10`.

**Key management:**
- RANDOM mode: random seed for both query and body (separate PRNG streams)
- DEVICE mode: Code for query, **Secret for body** (both request and response)
- **All wire protocol bodies use tb_secret** (`3037636188661496`) as the SnakeOil key
- There is NO separate "Secret₃" — the 0x08 flag flows use the same tb_secret

### RSA + XOR-CBC (.lyc license files)

.lyc format: `[8B header][256B RSA block][XOR-CBC encrypted data]`
- RSA: 2048-bit, e=65537, public key embedded in DLL at RVA 0x30B588
- RSA payload: 40-byte credential header (magic `0x36c8b267`)
- Fields[1..4] of RSA payload = XOR-CBC key for remaining blocks
- Decrypted data contains license keys and product names

### Blowfish ECB (http_dump local storage)

Key: `b0caba3df8a23194f2a22f59cd0b39ab` (DLL RVA 0x2AF9E8). Used only for local XML cache files, not wire protocol.

### Credential Block XOR

`credential_block = 0xD8 || (Name XOR 6935b733a33d02588bb55424260a2fb5)`

### NNGE (device.nng)

Key `m0$7j0n4(0n73n71I)` with template `ZXXXXXXXXXXXXXXXXXXZ`. The NNGE parser in the DLL fails for device.nng (seeks to wrong offset). device.nng is used only for APPCID extraction (offset 0x5C) and MD5 fingerprinting. **No credential derivation from device.nng.**

---

## 4. Wire Protocol

### Request Format

```
[16B header] [SnakeOil-encrypted query] [SnakeOil-encrypted body]
```

Header: `01 C2 C2 {auth_mode} 00 {code:8B} {service_minor} 00 00 {nonce} 3F`

- `auth_mode`: 0x20 (unauthenticated) or 0x30 (authenticated)
- `code`: 8-byte key (random for RANDOM, Credentials.Code for DEVICE)
- `nonce`: random per-session byte

**CRITICAL:** Wire protocol requests must NOT include `Content-Type` HTTP header (server returns 500).

### Response Format

```
[4B header: 01 00 C2 {mode}] [SnakeOil-encrypted payload]
```

### Query Flags

| Flag | Meaning |
|------|---------|
| 0x20 | Has credential block (17 bytes) |
| 0x40 | Has body |
| 0x08 | Delegated device (uses Name₃ in credential block) |

- `0x60` = `0x20 | 0x40` — standard authenticated request
- `0x68` = `0x20 | 0x40 | 0x08` — delegated device request
- **Both use tb_secret for body encryption** (no key difference)

### Name₃ Construction

`Name₃ = 0xC4 || hu_code(8 bytes BE) || tb_code(7 bytes BE)`

Used in the credential block for 0x08-flag requests.

---

## 5. API Flow

### Complete Session (12 steps)

```
1. boot (RANDOM)           → service URL map
2. register (RANDOM)       → tb credentials (Name₁/Code₁/Secret₁) — cached permanently
3. login (DEVICE)          → session token
4. hasActivatableService   → boolean
5. sendfingerprint         → accepted
6. getprocess              → task list
7. delegator (DEVICE)      → hu credentials (Name₂/Code₂/Secret₂)
8. senddevicestatus (0x60) → device state accepted
9. senddevicestatus (0x68) → delegated device state accepted
10. web_login (form POST)  → browser session cookie
11. catalog (web)          → available content list
12. content selection (web)→ download URLs
```

### Three Credential Sets

| Set | Source | Purpose |
|-----|--------|---------|
| tb (Name₁/Code₁/Secret₁) | Registration response | All DEVICE mode requests |
| hu (Name₂/Code₂/Secret₂) | Delegator response | Delegation section in requests |
| Name₃ | Constructed from hu_code + tb_code | 0x08-flag credential blocks |

### Endpoints

| Endpoint | Mode | Service |
|----------|------|---------|
| `/services/index/rest/3/boot` | RANDOM | Boot |
| `/services/register/rest/1/device` | RANDOM | Register |
| `/rest/1/login` | DEVICE | Market |
| `/services/register/rest/1/hasActivatableService` | DEVICE | Register |
| `/rest/1/sendfingerprint` | DEVICE | Market |
| `/rest/1/getprocess` | DEVICE | Market |
| `/services/register/rest/1/delegator` | DEVICE | Register |
| `/rest/1/senddevicestatus` | DEVICE | Market |
| `/rest/1/licinfo` | DEVICE | Market |
| `/toolbox/login` | Web POST | Browser session |
| `/toolbox/cataloglist` | Web GET | Catalog HTML |
| `/toolbox/managecontentinitwithhierarchy/install` | Web GET | Content tree |
| `/rest/managecontent/supermarket/v1/updateselection` | Web POST | Content sizes |

---

## 6. USB Drive Structure

```
NaviSync/
├── content/
│   ├── brand.txt              ("dacia")
│   ├── map/                   *.fbl + *.fbl.stm
│   ├── poi/                   *.poi + *.poi.stm
│   ├── speedcam/              *.spc + *.spc.stm
│   ├── tmc/                   *.tmc + *.tmc.stm
│   ├── lang/                  *.zip + *.zip.stm
│   ├── voice/                 *.zip + *.zip.stm
│   ├── global_cfg/            *.zip + *.zip.stm
│   └── userdata/POI/          *.zip + *.zip.stm
├── license/
│   ├── device.nng             (268 bytes, device identity)
│   ├── *.lyc                  (RSA-encrypted license files)
│   ├── *.lyc.md5              (license checksums)
│   └── *.lyc.stm              (license timestamps)
├── save/
│   ├── service_register_v1.sav (tb + hu credentials)
│   ├── dlm_files_v2.sav       (download state)
│   └── ...
└── update_checksum.md5         (trigger file — MD5 of sorted .stm files)
```

### .stm Shadow Files

Every content file has a `.stm` companion:
```ini
purpose = shadow
size = 109490688
content_id = 7341211
header_id = 117863961
timestamp = 1580666002
md5 = EAC5E8CCCC4A28792251535B55A7B182
```

### Update Trigger

`update_checksum.md5` in USB root. Present → synctool processes update. Content: MD5 of all `.stm` files concatenated (sorted alphabetically by path).

---

## 7. Content Download Flow

```
1. Session established (steps 1-10 above)
2. web_login → browser session cookie
3. GET /toolbox/managecontentinitwithhierarchy/install → content tree with IDs
4. POST /rest/managecontent/supermarket/v1/updateselection → sizes
5. User confirms selection
6. POST /rest/managecontent/supermarket/v1/confirminstall → triggers server-side prep
7. Wire protocol getprocess → download task list with URLs
8. Download content files (HTTP GET with resume support)
9. Write to USB: content files + .stm + .lyc + update_checksum.md5
10. Verify: MD5 checksums match .stm metadata
```

---

## 8. Validation Requirements

The USB output must be byte-compatible with the original Toolbox:

1. **Directory structure** matches NaviSync layout exactly
2. **.stm files** have correct format (purpose, size, content_id, header_id, timestamp, md5)
3. **.lyc files** are copied verbatim from server (RSA-encrypted, not re-encrypted)
4. **.lyc.md5** contains hex MD5 of the .lyc file
5. **update_checksum.md5** is MD5 of all .stm file contents concatenated in sorted path order
6. **Content files** have correct MD5 matching .stm metadata
7. **No extra files** that would confuse synctool

---

## 9. Remaining Work

### Must Fix
- **SendDeviceStatus body generation** — currently uses captured body replay. Now that we know Secret₃ = tb_secret, we can generate the body properly with correct encryption.
- **R.10 SendDeviceStatus 409** — generated body returns 409. Need to match file list exactly.

### Must Implement
- **4.3 `sync` command** — select content → confirm → download → write to USB
- Wire up download URLs from `getprocess` to `DownloadManager`
- Wire up `installer.py` to write downloaded content to USB

### Nice to Have
- **R.4 IMEI encoding** — understand the `x51x4Dx30x30x30x30x31` format
- **R.7 XOR key universality** — test IGO_CREDENTIAL_KEY with a second device
- **.lyc file generation** — we can decrypt .lyc files (RSA public key known) but generating new ones requires the private key (server-side only)
