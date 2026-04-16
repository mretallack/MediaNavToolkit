# Tasks: MediaNav Toolbox Python Library

> Design: [design.md](design.md) | Reverse engineering: [toolbox.md](toolbox.md) | Functions: [functions.md](functions.md)

## Status Summary

The protocol has been fully reverse-engineered and verified against the live server:
- SnakeOil cipher: **cracked** (xorshift128 PRNG stream cipher)
- Wire format: **understood** (16-byte request header, 4-byte response header)
- DEVICE mode keys: **solved** (Code for request encryption, Secret for response decryption)
- Credential block: **solved** (`0xD8 || (Name XOR IGO_CREDENTIAL_KEY)`)
- Full login flow: **working** (boot → login → sendfingerprint → getprocess all return 200)
- Request body encoding: **solved** (login, fingerprint, register, model list, descriptor list all verified)
- Catalog parsing: **working** (HTML catalog, content tree, licenses, device status all parsed)
- Content-Type: **must NOT be sent** for wire protocol requests (server returns 500)
- Delegator: **working** — returns head unit credentials (Name/Code/Secret)
- Catalog CLI: **working** — shows 31 map updates, 6.07 GB total (via captured body replay)

---

## Done

- [x] Project scaffolding (pyproject.toml, package structure, tests, CI)
- [x] `config.py` — brand defaults from plugin.dll
- [x] `models.py` — data classes (DeviceInfo, Credentials, etc.)
- [x] `device.py` — USB drive detection, device.nng APPCID extraction, XOR decode, brand.txt
- [x] `fingerprint.py` — read/write/encode fingerprint data
- [x] `api/client.py` — HTTP client with retry and cookies
- [x] `api/igo_binary.py` — basic type encoders (byte, int32, int64, string, array) and boot response decoder
- [x] `download.py` — download manager with cache, resume, MD5 verify (stub)
- [x] `installer.py` — content installer, .stm writer (stub)
- [x] `cli.py` — Click CLI with detect/login/catalog/sync commands (stub)
- [x] `auth.py` — credential loading from .env
- [x] Reverse engineering: SnakeOil cipher fully reversed
- [x] Reverse engineering: Blowfish key for http_dump decryption
- [x] Reverse engineering: wire protocol format (headers, modes, key management)
- [x] Reverse engineering: registration request/response XML format
- [x] Reverse engineering: device model list
- [x] Documentation: toolbox.md, design.md, functions.md
- [x] `wire_codec.py` — request body encoder for wire format (length-prefixed strings, BE integers)
- [x] Wire protocol: split query/body encryption (R.6 solved), `protocol.py` updated
- [x] Wire protocol: `boot_v3()`, `register_device_wire()`, `login_wire()` implemented
- [x] `session.py` — end-to-end session flow: boot → login → sendfingerprint → getprocess (all 200)
- [x] `catalog.py` — parsers for catalog HTML, content tree, licenses, device status, update selection
- [x] `content.py` — content selection: tree retrieval, size estimation, install confirmation
- [x] `download.py` — download manager with cache, resume, MD5 verification (tested)
- [x] Offline test fixtures from captured traffic (7 fixture files)
- [x] 201 unit tests, all passing
- [x] `cli.py` — working CLI: detect, register, login, catalog, updates commands
- [x] `session.py` — web login via form POST to `/toolbox/login`
- [x] `api/register.py` — device registration works (Content-Type fix), 409 handling for re-registration
- [x] `wire_codec.py` — senddevicestatus body encoder (built, needs correct credential block)
- [x] `api/register.py` — `get_delegator_credentials()` for head unit Name/Code/Secret
- [x] Full catalog flow working: login → fingerprint → delegator → senddevicestatus → web_login → catalog
- [x] `installer.py` — content installer: write files, .stm, .lyc, update_checksum.md5
- [x] 204 unit tests, all passing

## Phase 1: Protocol Implementation

- [x] **1.1** Implement SnakeOil cipher in `medianav_toolbox/crypto.py`
  - `snakeoil(data, seed) → bytes` — xorshift128 PRNG stream cipher
  - 8 tests verified against mitmproxy captures ✅

- [x] **1.2** Implement wire protocol envelope in `medianav_toolbox/protocol.py`
  - `build_request()` — 16-byte header + SnakeOil-encrypted payload
  - `parse_response()` — strip 4-byte header, decrypt payload
  - 12 tests including byte-for-byte match against capture ✅

- [x] **1.3** Implement igo-binary parser in `medianav_toolbox/igo_parser.py`
  - `parse_boot_response()` — extracts service name→URL map
  - `parse_register_response()` — extracts Name, Code, Secret, MaxAge
  - `parse_model_list_response()` — extracts device model list
  - 10 tests ✅

- [x] **1.4** Implement igo-binary serializer in `medianav_toolbox/igo_serializer.py`
  - `build_boot_request_body()` — builds IndexArg payload (RANDOM mode)
  - `build_empty_device_request()` — builds empty DEVICE mode requests (hasActSvc, getProcess, etc.)
  - `build_credential_block()` — generates 17-byte credential block from 16-byte Name
  - `extract_credential_block()` — extracts credential block from captured requests
  - 13 tests including live server verification ✅
  - **Credential block encoding SOLVED**: `0xD8 || (Name XOR 6935b733a33d02588bb55424260a2fb5)`
  - **Verified against live NaviExtras server** — server accepts generated credential blocks
  - **Partial**: non-empty request bodies (login, sendfingerprint, etc.) not yet buildable — these use the igo-binary bitstream serializer which is not yet reversed

### Key Protocol Findings (from Phase 1)

Request payload format (after decryption):
- RANDOM mode: `[counter 1B] [flags 1B] [body...]`
- DEVICE mode: `[counter 1B] [flags 1B] [credentials 17B] [body...]`

PRNG seed per mode:
- RANDOM requests: seed = key in wire header
- DEVICE requests: seed = **Code** (header also contains Code)
- RANDOM responses: seed = same key as request
- DEVICE responses: seed = **Secret**

Credential block encoding:
- `credential_block = 0xD8 || (Name XOR 6935b733a33d02588bb55424260a2fb5)`
- Verified against live server ✅

RANDOM mode seed generation:
- Derived from `_time64()` using xorshift128 (see toolbox.md §12)
- Server validates seed against current time
- Old captured seeds continue to work indefinitely

## Phase 2: Server Communication

- [x] **2.1** Implement boot flow
  - `boot()` — v2 JSON GET (existing, reliable fallback)
  - `boot_v3()` — v3 igo-binary wire protocol (RANDOM mode), parses service URLs
  - Both in `api/boot.py`

- [x] **2.2** Implement device registration
  - `register_device_wire()` in `api/register.py` — RANDOM mode wire protocol
  - Sends: BrandName, ModelName, Swid, Imei, IgoVersion, FirstUse, Appcid, UniqId
  - Returns: `DeviceCredentials` (Name, Code, Secret) for authenticated calls
  - Body format verified byte-for-byte against captured traffic

- [x] **2.3** Implement SWID generation
  - `compute_swid(serial)` in `swid.py` — MD5("SPEEDx{serial}CAM") → Crockford base32
  - `get_drive_serial(path)` — Linux drive serial via lsblk / /dev/disk/by-id/
  - Format: CK-XXXX-XXXX-XXXX-XXXX (16 Crockford base32 chars from first 10 MD5 bytes)

- [x] **2.4** Implement authenticated API calls (DEVICE mode)
  - ✅ `POST /rest/1/login` — `login_wire()` in `api/market.py`, DEVICE mode (Code for query, Secret for body)
  - ✅ `POST /services/register/rest/1/hasActivatableService` — WORKING
  - ✅ `POST /rest/1/getprocess` — WORKING (empty body + credential block)
  - ✅ `POST /services/register/rest/1/get_device_model_list` — `build_get_device_model_list_body()` verified
  - ✅ `POST /services/register/rest/1/get_device_descriptor_list` — `build_get_device_descriptor_list_body()` verified
  - ✅ `POST /rest/1/sendfingerprint` — fixed: varint file count, proper directory entry, credential block in query. Returns 200.
  - All use Code in header and as query encryption seed, Secret for body encryption
  - **CRITICAL**: Wire protocol requests must NOT include Content-Type header (server returns 500)

## Phase 3: Content Pipeline

- [x] **3.1** End-to-end session flow
  - `session.py` — boot → login(200) → sendfingerprint(200) → getprocess(200)
  - Market URL: `https://dacia-ulc.naviextras.com/rest/1/`
  - Credentials cached in `.medianav_creds.json`, permanent (from `service_register_v1.sav`)

- [x] **3.2** Catalog parsing (`catalog.py`)
  - `parse_catalog_html()` — `/toolbox/cataloglist` HTML (package codes, names, releases, providers)
  - `parse_managecontent_html()` — `/toolbox/managecontentinitwithhierarchy/install` (content tree with IDs)
  - `parse_update_selection()` — `/rest/managecontent/supermarket/v1/updateselection` JSON (content sizes)
  - `parse_licenses_response()` — wire protocol licenses (3 .lyc files with SWIDs)
  - `parse_senddevicestatus_response()` — wire protocol (process/task IDs, requested file paths)
  - 24 unit tests, all passing against offline fixtures

- [x] **3.3** Content selection and download management (`content.py`, `download.py`)
  - `get_content_tree()` — fetches and parses content tree from web endpoint
  - `select_content()` — selects content IDs, returns sizes and space indicator
  - `confirm_selection()` — triggers install via confirmation endpoint
  - `get_available_updates()` — convenience: fetches tree, selects all, gets sizes, deselects
  - `DownloadManager` — file downloads with cache, resume, MD5 verification
  - 8 unit tests (content selection + download manager), integration tests for live API
  - Note: actual file downloads are triggered by the native engine via wire protocol
    `getprocess` tasks. The web endpoints handle content selection and size estimation.

- [x] **3.4** Content installation (`installer.py`)
  - `install_content()` — copies content files + writes `.stm` shadow metadata
  - `install_license()` — writes `.lyc` + `.lyc.md5` checksum files
  - `write_update_checksum()` — writes `update_checksum.md5` to trigger synctool
  - `write_stm()` — creates `.stm` files matching exact USB format
  - `check_space()` — verifies USB free space
  - 9 unit tests, all passing
  - Note: download URLs come from `getprocess` after web content selection (not yet wired)

## Phase 4: CLI and Polish

- [x] **4.1** Wire up CLI commands (`cli.py`)
  - ✅ `medianav-toolbox detect` — detect USB drive, show device info, space, OS version
  - ✅ `medianav-toolbox register` — register new device, save credentials to USB
  - ✅ `medianav-toolbox login` — full session (boot → login → fingerprint → getprocess → delegator → senddevicestatus → web_login)
  - ✅ `medianav-toolbox catalog` — shows 31 map updates with sizes (6.07 GB total)
  - ✅ `medianav-toolbox updates` — quick update check with summary
  - Web login: `web_login()` authenticates via form POST to `/toolbox/login`

- [x] **4.2** SendDeviceStatus + Delegator — catalog/updates working
  - `get_delegator_credentials()` in `register.py` — gets head unit Name/Code/Secret
  - Body format: same as register but header `0x1E`, serial instead of uniq_id
  - Two senddevicestatus calls needed: flow 735 (re-encrypted) + flow 737 (raw replay)
  - `select_content()` fixed: Content-Type `application/json` + `X-Requested-With: XMLHttpRequest`
  - **Workaround**: senddevicestatus uses captured body replay (0x68 flag encryption unsolved)
  - Catalog shows 31 items across 31 countries, 6.07 GB total, 7.18 GB available

- [ ] **4.3** Wire up `medianav-toolbox sync` command
  - Select content, confirm, trigger download, write to USB
  - Depends on 3.4 (content installation)

## Known Bugs

- [x] **B.1** ~~Device registration returns HTTP 500~~ — **RESOLVED**
- [x] **B.2** ~~Catalog shows "norightsfordevice"~~ — **RESOLVED**
  - Root cause: server needs two senddevicestatus calls before web session shows content
  - Flow 735 (flags=0x60, re-encrypted) + flow 737 (flags=0x68, raw replay) both required
  - The `0xD8` header in senddevicestatus body is a presence bitmask, NOT a credential block

## Remaining Research

- [x] **R.1** ~~DEVICE mode request encryption~~ — RESOLVED
- [ ] **R.2** NNGE decryption — device.nng encryption algorithm
- [x] **R.3** ~~SWID format_swid()~~ — **RESOLVED**
- [ ] **R.4** Imei field — understand the `x51x4Dx30x30x30x30x31` encoding
- [x] **R.5** ~~DEVICE mode credential encoding~~ — RESOLVED
- [x] **R.6** ~~Request body encoding~~ — **RESOLVED**
- [ ] **R.7** XOR key universality — is `IGO_CREDENTIAL_KEY` the same for all devices?
- [x] **R.8** ~~Delegator endpoint~~ — **RESOLVED**
  - `get_delegator_credentials()` calls `/register/rest/1/delegator` (DEVICE mode, service minor 0x0E)
  - Body: `[0x1E 0x00] [brand] [model] [swid] [imei] [igo_ver] [int64:0] [int32:appcid] [serial]`
  - Response: parsed with `parse_register_response()` — returns Name, Code, Secret, MaxAge=300
  - Verified: returns `C10CD1FD4A2F23F921D6E3B093D5957A` / Code=3362879562238844 / Secret=4196269328295954
- [ ] **R.9** Query flags `0x68` encryption — body does NOT decrypt with toolbox Secret, Code, or delegator Secret/Code
  - Affects: senddevicestatus flows 737/741/754/792 and sendfilecontent flows 743/802
  - Currently worked around by raw replay of captured wire bytes
  - Solving this would allow generating senddevicestatus bodies dynamically
- [ ] **R.10** SendDeviceStatus body validation — our generated body returns 409 even with correct format
  - Device info section matches captured byte-for-byte
  - File entries differ (7 files vs ~11 in captured, different timestamps)
  - Server may validate file list against known device state or require specific files
