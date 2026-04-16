# Tasks: MediaNav Toolbox Python Library

> Design: [design.md](design.md) | Reverse engineering: [toolbox.md](toolbox.md) | Functions: [functions.md](functions.md)

## Status Summary

The protocol has been fully reverse-engineered and verified against the live server:
- SnakeOil cipher: **cracked** (xorshift128 PRNG stream cipher)
- Wire format: **understood** (16-byte request header, 4-byte response header)
- DEVICE mode keys: **solved** (Code for request encryption, Secret for response decryption)
- Credential block: **solved** (`0xD8 || (Name XOR IGO_CREDENTIAL_KEY)`)
- Full login flow: **working** (boot → login → getprocess all return 200 from live server)
- Request body encoding: **partially solved** (empty bodies work, complex bodies use captured replay)

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

- [ ] **2.1** Implement boot flow
  - `POST /selfie/rest/1/update` (plaintext JSON)
  - `POST /services/index/rest/3/boot` (RANDOM mode) → parse service URLs
  - Tests: boot against live API, verify URLs match known values

- [ ] **2.2** Implement device registration
  - `POST /services/register/rest/1/device` (RANDOM mode)
  - Send: BrandName, ModelName, Swid, Imei, IgoVersion, FirstUse, Appcid, UniqId
  - Receive: Credentials (Name, Code, Secret)
  - Tests: register with real device data

- [ ] **2.3** Implement SWID generation
  - Compute from drive serial: `MD5("SPEEDx{serial}CAM")` → `CK-XXXX-XXXX-XXXX-XXXX`
  - Extract `format_swid()` byte-to-char mapping from `FUN_1009c960`
  - Linux: get drive serial from `/dev/disk/by-id/` or `lsblk`
  - Tests: known serial → known SWID

- [ ] **2.4** Implement authenticated API calls (DEVICE mode)
  - ✅ `POST /services/register/rest/1/hasActivatableService` — WORKING
  - ✅ `POST /rest/1/login` (market) — WORKING (replayed captured body)
  - ✅ `POST /rest/1/getprocess` — WORKING (empty body + credential block)
  - [ ] `POST /rest/1/sendfingerprint` — needs replayed captured body
  - [ ] `POST /services/register/rest/1/get_device_model_list` — needs replayed captured body
  - [ ] `POST /services/register/rest/1/get_device_descriptor_list` — needs replayed captured body
  - All use Code in header and as query encryption seed, Secret for body encryption
  - Request bodies use igo-binary tagged format (same as responses) — R.6 SOLVED

## Phase 3: Content Pipeline

- [ ] **3.1** Implement catalog retrieval
  - Parse model list to find matching device
  - Get available updates from market
  - Compare with installed content on USB

- [ ] **3.2** Implement content download
  - Wire up download manager with real URLs from server
  - Progress reporting, MD5 verification

- [ ] **3.3** Implement content installation
  - Write downloaded content to USB drive
  - Update .lyc, .stm, .md5 files
  - Write update_checksum.md5 to trigger head unit sync

## Remaining Research

- [x] **R.1** ~~DEVICE mode request encryption~~ — RESOLVED: DEVICE mode requests use **Code** as PRNG seed, responses use **Secret**
- [ ] **R.2** NNGE decryption — device.nng encryption algorithm (key: `m0$7j0n4(0n73n71I)`, template: `ZXXXXXXXXXXXXXXXXXXZ`)
- [ ] **R.3** SWID format_swid() — extract exact byte-to-char mapping from Ghidra (`FUN_1009c960`)
- [ ] **R.4** Imei field — understand the `x51x4Dx30x30x30x30x31` encoding
- [x] **R.5** ~~DEVICE mode credential encoding~~ — RESOLVED: `0xD8 || (Name XOR 6935b733a33d02588bb55424260a2fb5)`. Verified against live server.
- [x] **R.6** ~~Request body encoding~~ — **RESOLVED**: Request bodies use the same igo-binary tagged format as responses (length-prefixed strings, type tags). The body appeared as random data because query and body are encrypted as **separate SnakeOil streams**: DEVICE mode uses Code for query, Secret for body. RANDOM mode uses the same random seed but independent PRNG state. `protocol.py` updated with `build_request(query, body, ...)` API. Verified byte-for-byte against all 8 captured requests.
- [ ] **R.7** XOR key universality — is `IGO_CREDENTIAL_KEY` the same for all devices, or derived from device-specific data? Needs testing with a second device.
