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

| Flag | Query Size | Meaning |
|------|-----------|---------|
| 0x20 | 19B | Standard DEVICE mode: `[counter][0x20][17B cred_block]` |
| 0x28 | 25B | Delegation mode: `[counter][0x28][17B cred_block][6B extra]` — cred block uses **tb_name** |
| 0x60 | 2B | Short query: `[counter][0x60]` — no credential block |
| 0x68 | 2B | Short delegation: `[counter][0x68]` — delegation data in body, not query |

**Bit meanings (from SSL wire capture run25):**
- `0x20` = DEVICE mode base
- `0x08` = has delegation/chain encryption in body
- `0x40` = short query (2 bytes, no credential block in query)

**Wire format (confirmed from SSL_write captures):**
- `0x60`: `[16B header][2B query enc(tb_code)][body enc(tb_secret)]` — simple body encryption
- `0x68`: `[16B header][2B query enc(tb_code)][body chain-encrypted]` — body uses field-level chain encryption
- `0x20`: `[16B header][19B query enc(tb_code)][body enc(tb_secret)]` — standard with cred block
- `0x28`: `[16B header][25B query enc(tb_code)][body chain-encrypted]` — delegation with cred block + chain body

**Critical finding (run25 SSL capture):**
The Toolbox sends `flags=0x68` (2B query) for the FIRST senddevicestatus and `flags=0x28` (25B query with tb_name) for the SECOND (delegation) senddevicestatus. The 0x28 credential block contains **tb_name** (NOT Name₃). The 0x08 bit indicates the body uses chain encryption (rotating SnakeOil keys per field), not simple tb_secret encryption.

### Name₃ Construction — FULLY CRACKED

**Name₃ = `0xC4 || hu_code(8 bytes BE) || tb_code(8 bytes BE)`** (17 bytes)

For the credential block (16 bytes): Name₃[:16] = `0xC4 || hu_code(8B) || tb_code(7B)`

The credential block in the 0x28 query uses **tb_name** (NOT Name₃).
Name₃ is used in the HMAC computation and the internal 41-byte delegation format.

### Delegation HMAC — FULLY CRACKED

```
key  = hu_secret (8 bytes big-endian)
data = 0xC4 + hu_code(8B BE) + tb_code(8B BE) + timestamp(4B BE) = 21 bytes
hmac = HMAC-MD5(key, data) = 16 bytes
```

Verified byte-for-byte against 2 captured values from Win32 debugger (run17). ✅

### Chain Encryption (0x08 bit)

When the 0x08 bit is set in the flags, the body uses **field-level chain encryption**:
- Each field is encrypted with a different SnakeOil key
- Keys rotate: each field's key is derived from the previous field's encryption
- The first key in the chain is tb_secret
- The SnakeOil debugger captures show 100+ individual SnakeOil calls per body

The chain-encrypted body starts with `FF B7 43 92...` when decrypted with tb_secret
(this is the first field's ciphertext, not the plaintext).

**Status: Chain encryption NOT yet implemented.** The captured plaintext bodies from
the SnakeOil debugger (BEFORE data) are fully decrypted. To send them on the wire,
they need to go through the chain encryption process, which we haven't reversed.
---

## 5. API Flow

### Complete Session (from SSL wire capture run25 + XML dump session 69BACB73)

```
 0. licinfo (36B, 0x20)           → license check (register endpoint, svc_minor=14)
 1. login (105B, 0x20)            → JSESSIONID (market endpoint, svc_minor=25)
 2. sendfingerprint (0x20)        → 200 (market, ~53KB)
 3. get_device_descriptor_list    → device descriptors (register, svc_minor=14)
 4. hasActivatableService         → boolean (register, svc_minor=14)
 5. getprocess (18B, 0x60)        → pending tasks (market, 2B query)
 6. get_device_model_list         → 103KB model list (register, RANDOM mode)
 7. senddevicestatus (0x68, 2B q) → State=RECOGNIZED, chain-encrypted body (market)
 8. delegator (0x20)              → hu_name/hu_code/hu_secret (register, svc_minor=14)
 9. senddevicestatus (0x28, 25B q)→ State=REGISTERED, chain-encrypted body, tb_name cred (market)
10. licinfo (76B, 0x28)           → extended license info (register, tb_name cred)
11. UploadLicenses (0x60)         → upload license data (register)
12. licenses (351B, 0x60)         → .lyc files with SWIDs (register)
13. senddevicestatus              → final status (market)
14. sendfingerprint               → second fingerprint (market)
15. sendfilecontent               → device_status.ini upload (market)
16+. getprocess + sendprocessstatus → download progress
```

**Wire format confirmed from SSL_write captures (run25):**
- Step 7: flags=0x68, 2B query, Content-Length=2218, body chain-encrypted
- Step 9: flags=0x28, 25B query with tb_name cred block, Content-Length=2235, body chain-encrypted
- Step 10: flags=0x28, 25B query with tb_name cred block, Content-Length=76
- Step 12: flags=0x60, 2B query, Content-Length=351

**Key: the 0x08 bit means chain encryption, NOT a separate 17B prefix segment.**
in the body. This prefix is a compressed encoding of the 41-byte internal format that
we cannot generate from scratch (see §4 Delegation Prefix).

**The 0x68 flow is only needed for paid/premium content.** Free content (e.g.,
RenaultDealers_Pack) can be browsed and downloaded via the web UI without 0x68.
The Windows Toolbox on QEMU confirms this — catalog browsing and free downloads
work without the delegation flow being triggered.

**Workaround:** The `licinfo` (76B) and `licenses` (94B) requests can be replayed
from Win32 captures. The 0x28 `licinfo` replay works across sessions (static extra
bytes). The 0x68 `licenses` replay is session-bound (returns 409 in new sessions).
```

**Content is obtained from step 9 (`licenses`).** The response contains available
packs with license keys, filenames, and the encrypted .lyc file data embedded
directly in the response. No separate download step is needed for license files.

**Note:** The `licenses` request (step 9) uses 0x68 flags with a delegation prefix
in the body. Currently this is replayed from a captured request. Building it from
scratch requires the igo-binary bitstream serializer which is not yet implemented.
The replay works because the same device credentials are used.

**Service minor for register endpoints is 14** (not 1). Using the wrong value
causes 409 responses from licinfo/licenses.

### Three Credential Sets

| Set | Source | Purpose |
|-----|--------|---------|
| tb (Name₁/Code₁/Secret₁) | Registration response | All DEVICE mode requests |
| hu (Name₂/Code₂/Secret₂) | Delegator response | Delegation section in requests |
| Name₃ | Constructed from hu_code + tb_code | 0x08-flag credential blocks |

### Endpoints

| Endpoint | Mode | Service Minor |
|----------|------|---------------|
| `/services/index/rest/3/boot` | RANDOM | — |
| `/services/register/rest/1/device` | RANDOM | 14 |
| `/rest/1/login` | DEVICE | 25 |
| `/services/register/rest/1/hasActivatableService` | DEVICE | 14 |
| `/rest/1/senddevicestatus` | DEVICE | 25 |
| `/rest/1/sendfingerprint` | DEVICE | 25 |
| `/services/register/rest/1/licinfo` | DEVICE | 14 |
| `/services/register/rest/1/licenses` | DEVICE (0x68) | 14 |
| `/services/register/rest/1/delegator` | DEVICE | 14 |
| `/toolbox/login` | Web POST | — |

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
- **Chain encryption (0x08 bit)** — the body encryption for 0x68/0x28 flags uses field-level chain encryption with rotating SnakeOil keys, NOT simple tb_secret encryption. Without this, senddevicestatus with delegation returns 409. The chain encryption is visible in the SnakeOil debugger captures (100+ calls per body with rotating keys). Need to reverse the key derivation chain.
- **Wire format flags** — our code sends 0x68 with 25B query, but the Toolbox sends 0x68 with 2B query and 0x28 with 25B query. The flag meanings are:
  - 0x40 bit = short query (2B)
  - 0x08 bit = chain-encrypted body
  - 0x28 = 25B query + chain body (for delegation senddevicestatus)
  - 0x68 = 2B query + chain body (for initial senddevicestatus)

### Must Implement
- **Chain encryption encoder** — encode plaintext bodies using the field-level chain encryption that the SnakeOil debugger shows
- **0x28 query format** — 25B query with tb_name (not Name₃) in credential block + 6B extra
- **Missing API calls** — get_device_descriptor_list, hasActivatableService, get_device_model_list, UploadLicenses
- **`sync` command** — select content → confirm → download → write to USB

### Solved
- **HMAC-MD5 formula** ✅ — verified byte-for-byte against captured data
- **Name₃ construction** ✅ — `C4 + hu_code(8B) + tb_code(8B)` = 17 bytes
- **Wire format structure** ✅ — confirmed from SSL_write captures (run25)
- **Catalog browsing** ✅ — 38 items via web API
- **License fetching** ✅ — 10 entries, installable to USB
- **Free content purchase** ✅ — via web API

### Nice to Have
- **R.4 IMEI encoding** — understand the `x51x4Dx30x30x30x30x31` format
- **R.7 XOR key universality** — test IGO_CREDENTIAL_KEY with a second device
