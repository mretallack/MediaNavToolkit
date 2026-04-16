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

- [ ] **3.4** Implement content installation
  - Write downloaded content to USB drive
  - Update .lyc, .stm, .md5 files
  - Write update_checksum.md5 to trigger head unit sync

## Phase 4: CLI and Polish

- [x] **4.1** Wire up CLI commands (`cli.py`)
  - ✅ `medianav-toolbox detect` — detect USB drive, show device info, space, OS version
  - ✅ `medianav-toolbox register` — register new device, save credentials to USB
  - ✅ `medianav-toolbox login` — full session flow (boot → login → fingerprint → getprocess → web_login)
  - ✅ `medianav-toolbox catalog` — fetches content tree (blocked by senddevicestatus, shows message)
  - ✅ `medianav-toolbox updates` — quick update check (same limitation)
  - Web login implemented: `web_login()` authenticates via form POST to `/toolbox/login`

- [ ] **4.2** Fix senddevicestatus to unblock catalog/updates
  - Encoder built (`build_senddevicestatus_body()` in `wire_codec.py`) but returns 409
  - **Root cause**: body must start with the **head unit's** credential block, not the toolbox's
  - The head unit's Name comes from the `delegator` endpoint (flow 736)
  - Three credential sets in play: toolbox registration, delegator (head unit), and a third unknown
  - Needs: reverse the `delegator` endpoint to get head unit credentials
  - Once fixed, catalog and updates CLI commands will show real content

- [ ] **4.3** Wire up `medianav-toolbox sync` command
  - Select content, confirm, trigger download, write to USB
  - Depends on 4.2 (senddevicestatus) and 3.4 (content installation)

## Known Bugs

- [x] **B.1** ~~Device registration returns HTTP 500~~ — **RESOLVED**
  - Root cause was the same Content-Type bug that blocked login
  - Registration now works with fresh SWIDs (returns Name, Code, Secret)
  - HTTP 409 = device already registered (expected, use cached creds or new SWID)
  - Tested: fresh registration returns 200 with valid credentials

## Remaining Research

- [x] **R.1** ~~DEVICE mode request encryption~~ — RESOLVED
- [ ] **R.2** NNGE decryption — device.nng encryption algorithm (key: `m0$7j0n4(0n73n71I)`, template: `ZXXXXXXXXXXXXXXXXXXZ`)
- [x] **R.3** ~~SWID format_swid()~~ — **RESOLVED**
- [ ] **R.4** Imei field — understand the `x51x4Dx30x30x30x30x31` encoding
- [x] **R.5** ~~DEVICE mode credential encoding~~ — RESOLVED
- [x] **R.6** ~~Request body encoding~~ — **RESOLVED**
- [ ] **R.7** XOR key universality — is `IGO_CREDENTIAL_KEY` the same for all devices?
- [ ] **R.8** Delegator endpoint — reverse the `/rest/1/delegator` wire protocol call
  - Returns a second set of credentials (Name/Code/Secret) for the head unit device
  - These credentials are needed for `senddevicestatus` body credential block
  - Captured: flow 736, request 155B, response 175B
  - Decoded response: Name=`C10CD1FD4A2F23F921D6E3B093D5957A`, Code=3362879562238844, Secret=4196269328295954
  - **Blocker for 4.2** (senddevicestatus) and therefore catalog/updates CLI commands
- [ ] **R.9** senddevicestatus query flags `0x68` vs `0x60`
  - Flow 735 uses flags `0x60` and decrypts with Secret — body is readable
  - Flows 737/741/754/792 use flags `0x68` and body does NOT decrypt with Secret or Code
  - The `0x08` bit may indicate a different encryption key (possibly delegator Secret)
  - Need to test decryption with delegator credentials
