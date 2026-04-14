# Tasks: MediaNav Toolbox Python Library

> Design: [design.md](design.md) | Reverse engineering: [toolbox.md](toolbox.md) | Functions: [functions.md](functions.md)

## Status Summary

The protocol has been fully reverse-engineered:
- SnakeOil cipher: **cracked** (xorshift128 PRNG stream cipher)
- Wire format: **understood** (16-byte request header, 4-byte response header, SnakeOil-encrypted igo-binary payload)
- Registration flow: **documented** (from decrypted http_dump XML and mitmproxy captures)
- Model list, credentials, SWID format: **known**

The existing codebase has scaffolding (CLI, device parsing, download/install stubs) but the API layer was built on incorrect protocol assumptions (raw igo-binary without SnakeOil envelope). It needs reworking.

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

- [ ] **1.1** Implement SnakeOil cipher in `medianav_toolbox/crypto.py`
  - `snakeoil(data, seed) → bytes` — xorshift128 PRNG stream cipher
  - Symmetric: same function for encrypt and decrypt
  - Tests: encrypt known plaintext, verify against mitmproxy capture

- [ ] **1.2** Implement wire protocol envelope in `medianav_toolbox/protocol.py`
  - `build_request(payload, seed, auth_mode, service_minor) → bytes` — 16-byte header + SnakeOil-encrypted payload
  - `parse_response(data, seed) → bytes` — strip 4-byte header, decrypt payload
  - RANDOM mode: generate random seed, put in header
  - DEVICE mode: put Code in header, use Secret as seed
  - Tests: round-trip encrypt/decrypt, parse real response from mitmproxy

- [ ] **1.3** Implement igo-binary parser (deserializer)
  - Read type tags (0x01=int32, 0x02=byte, 0x04=int64, 0x05=string, 0x80=envelope)
  - Handle nested structures
  - Tests: parse decrypted boot response, registration response, model list

- [ ] **1.4** Implement igo-binary serializer
  - Write typed fields matching the format the server expects
  - Build RegisterDeviceArg, HasActivatableServiceArg, LoginArg, etc.
  - Tests: serialize and verify against known wire captures

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
  - `POST /services/register/rest/1/hasActivatableService`
  - `POST /rest/1/login` (market)
  - `POST /rest/1/sendfingerprint`
  - `POST /services/register/rest/1/get_device_model_list`
  - `POST /services/register/rest/1/get_device_descriptor_list`
  - All use Code in header, Secret as PRNG seed

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

- [ ] **R.1** DEVICE mode request encryption — verify that DEVICE mode requests also use Secret as PRNG seed (responses confirmed working)
- [ ] **R.2** NNGE decryption — device.nng encryption algorithm (key: `m0$7j0n4(0n73n71I)`, template: `ZXXXXXXXXXXXXXXXXXXZ`)
- [ ] **R.3** SWID format_swid() — extract exact byte-to-char mapping from Ghidra (`FUN_1009c960`)
- [ ] **R.4** Imei field — understand the `x51x4Dx30x30x30x30x31` encoding
