# Tasks: MediaNav Toolbox Python Library

> Implementation plan for the `medianav_toolbox` library.
> Design: [design.md](design.md) | Reverse engineering: [toolbox.md](toolbox.md)

---

## Phase 1: Project Scaffolding

- [x] **1.1** Create project structure with `pyproject.toml`, `medianav_toolbox/` package, `tests/` directory
  - `pyproject.toml` with dependencies: `httpx`, `click`, `rich`, `python-dotenv`
  - Dev dependencies: `pytest`, `respx`, `black`, `isort`
  - `.gitignore` (`.env`, `__pycache__`, `venv/`, `download_cache/`, `.pytest_cache`)
  - `.env.example` with `NAVIEXTRAS_USER`, `NAVIEXTRAS_PASS`, `NAVIEXTRAS_USB_PATH`
  - Empty `__init__.py` files for package and `api/` subpackage

- [x] **1.2** Implement `config.py` — defaults from plugin.dll (design §4)
  - `Config` dataclass with all defaults (api_base, brand, device_type, etc.)
  - Load from `.env` via `python-dotenv`
  - Tests: `tests/test_config.py` (4 tests) ✅

- [x] **1.3** Implement `models.py` — shared data classes (design §5, §6, §7)
  - `DeviceInfo`, `InstalledContent`, `ContentItem`, `ContentType` enum
  - `DriveInfo`, `ProcessInfo`, `DownloadItem`
  - `ServiceEndpoints`, `RegisterResult`, `SyncResult`, `InstallResult`
  - `Credentials`, `Session`

## Phase 2: Device & USB

- [x] **2.1** Implement `device.py` — device.nng parsing (design §5.1)
  - `xor_decode()` using extracted XOR tables (toolbox.md §22.3)
  - `parse_device_nng()` — extract APPCID (offset 0x5C LE), BrandMD5, SKU IDs
  - Bundle `xor_table_normal.bin` and `xor_table_china.bin` as package data
  - Tests: `tests/test_device.py` — XOR decode tests, APPCID extraction (6 tests) ✅

- [x] **2.2** Implement `device.py` — USB drive detection (design §5.2, §5.3)
  - `validate_drive()` — check NaviSync/, device.nng, device_status.ini exist
  - `read_device_status()` — parse device_status.ini key=value format
  - `read_installed_content()` — scan `NaviSync/content/**/*.stm`, parse each
  - `detect_drive()` — combines validation + device.nng parsing
  - Tests: `tests/test_device.py` — drive validation, .stm parsing, brand mapping (10 tests) ✅

- [x] **2.3** Implement `fingerprint.py` (design §5, toolbox.md §12)
  - `read_fingerprint()`, `save_fingerprint()`, `encode_fingerprint()`
  - `validate_fingerprint()` — check MD5, checksum file, drive info file
  - Tests: `tests/test_fingerprint.py` (6 tests) ✅

## Phase 3: API Client & Boot

- [x] **3.1** Implement `api/client.py` — HTTP client (design §3.4, toolbox.md §4)
  - `NaviExtrasClient` wrapping `httpx.Client`
  - Cookie jar for JSESSIONID
  - `User-Agent: WinHTTP ToolBox/1.0`
  - Retry with exponential backoff (3 attempts)
  - Tests: `tests/test_client.py` — retry logic, cookie handling (6 tests) ✅

- [x] **3.2** Implement `api/igo_binary.py` — codec (design §6.1, toolbox.md §23)
  - `decode_boot_response()` — parse 11-byte header + entry array
  - `encode_request()` — build igo-binary request with magic header `0x80 0x80`
  - `decode_response()` — generic response decoder
  - Varint encode/decode helpers
  - Tests: `tests/test_igo_binary.py` — decode real boot response, round-trip varint (8 tests) ✅

- [x] **3.3** Implement `api/boot.py` — service discovery (design §6.2, toolbox.md §5)
  - `boot()` — GET `/rest/2/boot`, parse JSON into `ServiceEndpoints`
  - Fallback: POST `/rest/3/boot` with igo-binary decode
  - Tests: `tests/test_boot.py` (4 tests) ✅

- [x] **3.4** Implement `auth.py` — credentials & session (design §3)
  - `Credentials` — load from args / `.env` / env vars
  - `Session` — JSESSIONID, device-auth token, expiry
  - `auth_headers()` — returns headers for full-auth or device-auth mode
  - Tests: `tests/test_auth.py` (10 tests) ✅

## Phase 4: Registration & Market API

- [x] **4.1** Implement `api/register.py` (design §6.3, toolbox.md §8)
  - `get_device_model_list()` — POST to `/get_device_model_list`
  - `get_device_descriptor_list()` — POST with device data
  - `get_device_info()` — POST to `/devinfo`
  - `register_device()` — POST to `/device`
  - `register_device_unbind()` — POST to `/registerdeviceandunbind`
  - Tests: `tests/test_register.py` (6 tests) ✅

- [x] **4.2** Implement `api/market.py` — market calls (design §6.4, toolbox.md §16)
  - `MarketAPI` class with all 13 methods
  - `login()` — POST `/login` with full-auth, returns Session
  - `send_drives()`, `send_fingerprint()`, `send_md5()`
  - `send_device_status()`, `send_sgn_file_validity()`
  - `get_process()` — POST `/getprocess`, returns ProcessInfo
  - `send_process_status()`, `send_backups()`, `send_error()`
  - `send_replacement_drives()`, `send_file_content()`, `get_settings()`
  - Tests: `tests/test_market.py` (12 tests) ✅

- [x] **4.3** Implement `api/catalog.py` (design §6.4)
  - `fetch_catalog()` — uses get_process response to build content list
  - Compare with installed content from USB `.stm` files
  - Mark items as `is_update` / `installed`
  - Tests: `tests/test_catalog.py` (4 tests) ✅

## Phase 5: Download & Install

- [x] **5.1** Implement `download.py` (design §7.1, toolbox.md §9)
  - `DownloadManager` with cache at `config.cache_dir`
  - `download_one()` — stream download with progress callback
  - `download_all()` — concurrent downloads via threading
  - MD5 verification after download
  - Resume via HTTP Range header
  - Cache hit detection (skip if file exists + MD5 matches)
  - Tests: `tests/test_download.py` (7 tests) ✅

- [x] **5.2** Implement `installer.py` (design §7.2, toolbox.md §20)
  - `ContentInstaller` class
  - `install()` — write content files to USB
  - `write_stm_files()` — create/update .stm shadow metadata
  - `update_checksums()` — write .md5 files
  - `write_update_checksum()` — write `update_checksum.md5` to trigger head unit sync
  - `check_space()` — verify sufficient free space
  - Tests: `tests/test_installer.py` (6 tests) ✅

## Phase 6: Public API & CLI

- [x] **6.1** Implement `__init__.py` — Toolbox class (design §8)
  - `Toolbox(usb_path, username, password, config)` — main entry point
  - Calls `load_dotenv()` on init
  - Step-by-step methods: `boot()`, `login()`, `detect_device()`, `register()`, `catalog()`, `download()`, `install()`
  - All-in-one: `sync(progress_cb)` — runs full pipeline
  - Tests: `tests/test_cli.py` — Toolbox + CLI tests (3 tests) ✅

- [x] **6.2** Implement `cli.py` — Click commands (design §8)
  - `detect` — show device info from USB
  - `login` — test credentials against API
  - `catalog` — list available updates
  - `sync` — full pipeline (detect → boot → catalog)
  - `--usb-path` option (fallback to `.env`)
  - `rich` progress bars for output
  - Tests: `tests/test_cli.py` (3 tests) ✅

- [x] **6.3** Implement `__main__.py` — entry point ✅
  - `python -m medianav_toolbox` runs CLI
  - Wire up click group from `cli.py`

## Phase 7: Integration Tests

- [x] **7.1** Set up integration test infrastructure
  - `tests/integration/conftest.py` with fixtures for real USB data and credentials
  - `pytest.ini` marker: `@pytest.mark.integration`
  - Skip if `NAVIEXTRAS_USER` not set (API tests only)
  - Rate limiting between API calls (1s delay) ✅

- [x] **7.2** Write integration tests (design §13)
  - `test_boot_live.py` — boot against real API (4 tests) ✅
  - `test_register_live.py` — model list, descriptor list, devinfo (3 tests) ✅
  - `test_device_live.py` — parse real device.nng, read real USB (4 tests) ✅
  - `test_end_to_end.py` — full detect+boot, installed catalog (2 tests) ✅

## Phase 8: Polish

- [x] **8.1** Copy test data files into `tests/data/` ✅
  - `device.nng`, `xor_table_normal.bin`, `xor_table_china.bin`
  - `device_status.ini`, `UnitedKingdom.fbl.stm`
  - `boot_response_v2.json`, `boot_response_v3.bin`, `model_list_response.bin`

- [x] **8.2** Add `README.md` with usage examples ✅
  - Library usage (Python API)
  - CLI usage
  - Configuration (.env setup)
  - Development setup (venv, tests)

- [x] **8.3** CI setup — GitHub Actions workflow ✅
  - `black --check`, `isort --check-only`
  - `pytest tests/ -v --ignore=tests/integration`
  - Integration tests as separate job (needs secrets)

## Phase 9: igo-binary Encoder & Live Market Calls

> Based on field layouts traced from Ghidra vtables (toolbox.md §20)

- [x] **9.1** Implement igo-binary field encoders in `api/igo_binary.py`
  - `encode_byte`, `encode_int16`, `encode_int32`, `encode_int64`, `encode_string`
  - `encode_bool`, `encode_array`, `encode_empty_array`
  - `encode_container(type_id, fields)`, `encode_message(fields)`
  - Tests: `tests/test_igo_binary.py` (31 tests total) ✅

- [x] **9.2** Implement LOGIN encoder
  - `encode_login(username, password, brand, device_type, appcid, ...)` → bytes
  - 17 fields: 5 strings, 5 bytes, 2 int16, 2 int32, 1 array (toolbox.md §20.2)
  - Tests: envelope, field count, contains username/password/brand/appcid ✅

- [x] **9.3** Implement GET_PROCESS encoder
  - `encode_get_process(flag=0)` → bytes
  - 1 field: byte flag (toolbox.md §20.1)
  - Tests: minimal encoding, correct length (14 bytes) ✅

- [x] **9.4** Implement SEND_DRIVES encoder
  - `encode_send_drives(drives)` → bytes
  - 5 fields: byte, 2×int32, array of drive objects, byte (toolbox.md §20.4)
  - Also implemented: `encode_send_fingerprint`, `encode_send_backups`,
    `encode_send_error`, `encode_send_md5`, `encode_send_sgn_file_validity` ✅

- [ ] **9.5** Test encoders against live API (LOGIN) — BLOCKED
  - Our encoded LOGIN gets 412 from index v3 (valid format, missing device data)
  - The container structure is parsed correctly (not 500)
  - But the server can't find device identification in our payload
  - Market call paths (`/login`, `/getprocess`) are NOT URL paths (all return 404)
  - The call routing must be embedded in the binary structure
  - **Blocker:** Need to determine how the serializer wraps the arg + path into
    the final wire format. The Ghidra serializer uses virtual dispatch through
    `FUN_101b41b0` lookup table — the actual encoder function is resolved at runtime.
  - **Wine doesn't work:** The exe is PE32 (32-bit) but Wine 10.10 runs in wow64
    mode which crashes on it. Docker with wine also fails. See toolbox.md §19.5.
  - **Next steps:**
    1. Install 32-bit Wine (not wow64) + Xvfb, or use a Windows VM with Wireshark
    2. Or: deeper Ghidra tracing of the serializer vtable chain
    3. Or: brute-force different binary structures against the live API

## Phase 10: Response Decoders & Catalog

- [ ] **10.1** Implement igo-binary response decoder
  - Generic field decoder: read type tag → decode value
  - Handle nested objects and arrays
  - Tests: decode real boot response field-by-field

- [ ] **10.2** Implement GET_PROCESS response parser
  - Extract download URLs, content IDs, sizes, MD5s
  - Build `ProcessInfo` with `list[DownloadItem]`
  - Tests: parse mocked response, parse real response

- [ ] **10.3** Update catalog to use real server data
  - `catalog()` calls login → get_process → parse response
  - Compare with installed .stm files
  - Show available updates vs installed content
  - Tests: end-to-end catalog with mocked market calls

## Phase 11: End-to-End Download & Install

- [ ] **11.1** Wire up full download pipeline
  - `Toolbox.download()` uses real download URLs from GET_PROCESS
  - Download with progress, MD5 verify, cache
  - Tests: download single real item

- [ ] **11.2** Wire up full install pipeline
  - `Toolbox.install()` writes to USB
  - `Toolbox.sync()` runs complete flow
  - POST /sendprocessstatus and /sendbackups after install
  - Tests: end-to-end sync dry run
