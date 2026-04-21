# Tasks: MediaNav Toolbox Python Library

> Design: [design.md](design.md) | Reverse engineering: [toolbox.md](toolbox.md) | Functions: [functions.md](functions.md)

## Status Summary

The protocol has been fully reverse-engineered and verified against the live server:
- SnakeOil cipher: **cracked** (xorshift128 PRNG stream cipher)
- Wire format: **understood** (16-byte request header, 4-byte response header)
- DEVICE mode keys: **solved** (Code for query, Secret for body — all flows including 0x68)
- Credential block: **solved** (`0xD8 || (Name XOR IGO_CREDENTIAL_KEY)`)
- Full login flow: **working** (boot → login → sendfingerprint → getprocess all return 200)
- Request body encoding: **solved** (all endpoints verified)
- Delegator: **working** — returns head unit credentials
- **Secret₃ SOLVED** — 0x68 body key = tb_secret, split encryption (body[0:17] + body[17:] each fresh PRNG)
- **Name₃ SOLVED** — `0xC4 || hu_code(8B BE) || tb_code(7B BE)` (direct concatenation, verified)
- **.lyc decryption: solved** — RSA 2048-bit + XOR-CBC, public key extracted (R.2 RESOLVED)
- **HMAC-MD5 verified** — Win32 debugger confirmed format, Python implementation matches DLL output exactly
- **senddevicestatus body builder: working** — generates correct body from USB (server returns 200)
- **licenses API: working** — returns available content packs with embedded .lyc data
- **Service minor for register endpoints: 14** (not 1) — fixed, licinfo/licenses now return 200
- **Remaining**: Build `licenses` request body from scratch (currently replayed from capture), wire up full sync pipeline

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

Request wire layout (DEVICE mode):
```
flags=0x20: [16B header] [SnakeOil(19B query, Code)] [SnakeOil(body, Secret)]
flags=0x60: [16B header] [SnakeOil(2B query, Code)]  [SnakeOil(body, Secret)]
flags=0x68: [16B header] [SnakeOil(25B query, Code)] [SnakeOil(17B prefix, Secret)] [SnakeOil(body, Secret)]
```

PRNG seed per mode:
- RANDOM requests: seed = key in wire header
- DEVICE requests: Code for query, **Secret** for body (all flows)
- DEVICE delegated (0x68): Code for query, **Secret** for body — split encryption:
  - 17-byte delegation prefix: fresh SnakeOil(Secret)
  - Remaining body: fresh SnakeOil(Secret) (PRNG restarted)
- RANDOM responses: seed = same key as request
- DEVICE responses: seed = **Secret**

**Secret₃ = tb_secret — RESOLVED.** The 0x68 body uses the same key as 0x60.

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
  - Only 0x60 senddevicestatus is required for catalog — 0x68 is NOT needed
  - **Secret₃ SOLVED**: 0x68 body key = tb_secret, split encryption confirmed
  - **Name₃ SOLVED**: `0xC4 || hu_code(8B BE) || tb_code(7B BE)` (verified against all captured flows)
  - 0x60: single-stream SnakeOil(body, tb_secret) at offset 18
  - 0x68: split at offset 41 — SnakeOil(prefix[17B], tb_secret) + SnakeOil(body, tb_secret)
  - **0x68 NOT IMPLEMENTED** — delegation prefix HMAC format not fully reversed (see R.11)
  - Catalog shows 31 items across 31 countries, 6.07 GB total, 7.18 GB available

- [ ] **4.3** Wire up `medianav-toolbox sync` command — **THE MAIN REMAINING WORK**
  - [x] **4.3.1** Fix senddevicestatus body generation
    - 0x60 body: generated from USB file scan, server returns 200 ✓
    - Body builder fixed: trailer with timestamps, drive path, session ID, 14-byte padding
    - Service minor for register endpoints = **14** (was incorrectly 1, causing 409)
  - [x] **4.3.2** Get available content via `licenses` API
    - `licinfo` (36B + 76B) → 200 ✓
    - `licenses` (94B) → 200, returns available packs with embedded .lyc data ✓
    - Response contains license key + filename + encrypted .lyc content
    - **LIMITATION:** `licenses` request body is currently a replay from Win32 capture
      The 94B request uses 0x68 flags with a delegation prefix in the body that we
      cannot generate from scratch (requires igo-binary bitstream serializer).
      The replay works because the same credentials are used.
    - **TODO:** Build `licenses` request body from scratch (requires understanding the
      53B body format — it contains the delegation prefix `0x86 + 16B` which is an
      igo-binary bitstream encoding of the credential sub-object)
  - [ ] **4.3.3** Parse licenses response and present catalog
    - Parse available packs from `licenses` response (license key, filename, .lyc data)
    - Compare against installed files on USB
    - Present available/installed status to user
  - [ ] **4.3.4** Download and install content to USB
    - Extract .lyc data from `licenses` response
    - Write .lyc file to `NaviSync/license/` on USB
    - Write .lyc.md5 checksum file
    - Write .stm shadow file
    - Verify installation
  - [ ] **4.3.5** Validate USB output
    - Verify directory structure matches NaviSync layout
    - Verify .stm files have correct format
    - Verify MD5 checksums match
    - Compare output against original Toolbox output

## Known Bugs

- [x] **B.1** ~~Device registration returns HTTP 500~~ — **RESOLVED**
- [x] **B.2** ~~Catalog shows "norightsfordevice"~~ — **RESOLVED**
  - Root cause: server needs senddevicestatus (0x60) before web session shows content
  - Only the 0x60 call is required — 0x68 (delegated) is NOT needed for catalog/download
  - The `0xD8` header in senddevicestatus body is a presence bitmask, NOT a credential block

## Remaining Research

- [x] **R.1** ~~DEVICE mode request encryption~~ — RESOLVED
- [x] **R.2** ~~NNGE decryption~~ — **RESOLVED**
  - .lyc files use RSA (2048-bit, e=65537) + XOR-CBC. Public key extracted from DLL.
  - device.nng NNGE parser fails (seeks to wrong offset). device.nng used only for APPCID + MD5 fingerprint.
  - No credential derivation from device.nng. See [reverse_engineer_nnge.md](reverse_engineer_nnge.md).
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
- [x] **R.9** Query flags `0x68` encryption — **RESOLVED (2026-04-18)**
  - Secret₃ = tb_secret (`3037636188661496` / `0x000ACAB6C9FB66F8`)
  - 0x68 body starts at offset 41 (16B header + 25B query), NOT offset 35
  - Body is split-encrypted: `body[0:17]` + `body[17:]` each with fresh SnakeOil(tb_secret)
  - The 17-byte delegation prefix starts with `0x86` (presence bitmask)
  - Re-encrypted 0x60 body returns HTTP 200 from live server ✓
  - **Delegation prefix format cracked via Unicorn emulation:**
    - `prefix = 0x86 || HMAC-MD5(hu_secret_BE, binary_serialized_credential)`
    - Binary serialization (FUN_101a9930): `[presence_byte][hu_code 8B BE][tb_code 8B BE][timestamp 4B BE]`
    - HMAC key: hu_secret (8 bytes, big-endian)
    - Timestamp: internal timer value, converted to FILETIME via `(ts + 0x2B6109100) * 10M`
    - Two serializers discovered: FUN_101a9930 (binary, for HMAC) vs FUN_101b2c30 (XML, for wire)
    - Unicorn emulation runs 3000+ instructions, produces correct binary output
    - **Remaining:** verify presence byte value against captured traffic (0xC4 for test, may differ)
  - See [reverse_engineer_nnge.md](reverse_engineer_nnge.md) for full Unicorn analysis
- [x] **R.10** ~~SendDeviceStatus body generation~~ — **RESOLVED (0x60 fully, 0x68 not needed)**
  - 0x60 body: generated from USB file scan, matches captured traffic byte-for-byte
  - 0x60 alone is sufficient for catalog/download flow (verified 2026-04-19)
  - 0x68 body: encryption solved (tb_secret, split pattern), delegation prefix partially reversed
  - Body format fully decoded: bitmask + device info + content metadata + file entries + trailer

- [ ] **R.11** 0x68 delegation prefix HMAC — **BLOCKING** (required for content rights)
  - **What 0x68 does:** Sends device status using delegated head unit credentials (hu_code/hu_secret)
    rather than toolbox credentials (tb_code/tb_secret). The 0x08 flag means "delegated device" —
    it asserts the head unit hardware identity, not just the toolbox software identity.
  - **Why it's blocking:** Without 0x68, managecontent returns `norightsfordevice` and the catalog
    is empty. The earlier "4 packages" result was a false positive (counted JS references, not content).
    The 0x68 call grants content rights to the session — it IS required for the full pipeline.
  - **What's solved:**
    - Name₃ = `0xC4 || hu_code(8B BE) || tb_code(7B BE)` — verified against all captured flows ✓
    - Secret₃ = tb_secret — verified ✓
    - Split encryption: prefix(17B) + body each with fresh SnakeOil(tb_secret) ✓
    - Prefix = `0x86 || HMAC-MD5(hu_secret_BE, serialized_credential)` — format known ✓
    - HMAC-MD5 implementation verified identical (Unicorn vs Python) ✓
    - HMAC key = hu_secret big-endian (traced byte-by-byte from SHRD instructions) ✓
    - 0x68 query = 25B: `[counter][0x68][D8 + Name₃ XOR IGO_KEY][extra 6B]` ✓
  - **What's NOT solved:** The exact binary data passed to the HMAC
    - Exhaustive search (5 formats × 2^32 timestamps, 4 threads): NO MATCH
    - DelegationRO descriptor has 6 fields; Unicorn credential only populates 4
    - Real credential has additional fields from device manager runtime state
    - FUN_100567E0 (get inner credential) returns a static descriptor ptr, not runtime data
  - **Investigation plan — full Unicorn emulation of nngine.dll:**
    - [ ] R.11.1: Find the registration response handler that populates 0x1030EBC0
      - The inner credential at 0x1030EBC0 is a descriptor template (12-byte entries)
      - At runtime, registration overwrites descriptor pointers with actual Name/Code/Secret
      - Need to find the function that parses the registration response and calls setters
      - Look for callers of the credential store's setter vtable methods
    - [ ] R.11.2: Emulate the registration handler in Unicorn
      - Feed it our known tb credentials (Name/Code/Secret from `.medianav_creds.json`)
      - Verify memory at 0x1030EBD0 and 0x1030EBD8 contains expected values
      - This tells us exactly what `*(iVar5+0x10)` and `*(iVar5+0x18)` contain
    - [ ] R.11.3: Set up FUN_101aa050 dependencies in Unicorn
      - Pre-set DAT_1031445c (device manager singleton) to skip creation
      - Hook FUN_10011dd0 (credential store lookup) to return fake device object
      - Device object needs vtable PTR_FUN_102b5268, vtable[6] returns 0x1030EBC0
      - Hook FUN_101d2630 (timer) to return a known timestamp
      - Hook DAT_10326d38 (object manager) vtable chain for timer access
    - [ ] R.11.4: Run FUN_101aa050 end-to-end in Unicorn
      - Call with hu_code/hu_secret as params (from delegator response)
      - Capture the exact data passed to FUN_101aa3a0 (HMAC-MD5)
      - Capture the 16-byte HMAC output
    - [ ] R.11.5: Verify against captured traffic
      - Compute HMAC with captured timestamp range
      - Match against the 3 captured prefix values (flows 737, 754, 792)
      - If match: implement `build_delegation_prefix()` with correct format
      - If no match: compare Unicorn output byte-by-byte with our Python implementation
    - [ ] R.11.6: Implement and test against live server
      - Update `build_delegation_prefix()` in igo_serializer.py
      - Update `_send_device_status()` in session.py to send 0x68
      - Test: managecontent should return content (not `norightsfordevice`)
      - Test: catalog should show map updates
  - See [reverse_engineer_nnge.md](reverse_engineer_nnge.md) for full investigation log
