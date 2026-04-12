# Dacia MediaNav Evolution Toolbox — Reverse Engineering Notes

This document traces through the Ghidra decompiled output to understand exactly what the toolbox app does.

**Source files:**
- `main_exe_decompiled.c` — DaciaMediaNavEvolutionToolbox.exe (2,931 functions)
- `plugin_decompiled.c` — plugin.dll (438 functions)
- `nngine_decompiled.c` — nngine.dll (13,381 functions)

---

## 1. Main EXE — Entry Point & Initialization

**File:** `main_exe_decompiled.c`

### 1.1 Plugin Loading (line 17–84)

The exe's first action is loading `plugin.dll` and resolving its exports:

```c
// FUN_004011f0 (line 17)
pHVar1 = LoadLibraryA("plugin.dll");

// FUN_00401250 (line 50–84) — resolves 4 exported functions:
GetProcAddress(DAT_004902f4, "brand_has_value");   // line 61
GetProcAddress(DAT_004902f4, "brand_get_value");   // line 69
GetProcAddress(DAT_004902f4, "brand_set_value");   // line 77
GetProcAddress(DAT_004902f4, "brand_free_buffer"); // line 82
```

### 1.2 CEF Initialization (line 23154)

```c
iVar5 = cef_initialize(param_1, -(uint)(param_2 != 0) & param_2 + 4U, puVar4);
```

### 1.3 Main Loop (line 16107–16108)

```c
cef_run_message_loop();   // blocks until app exits
cef_shutdown();
```

The exe is a thin CEF shell. All business logic lives in nngine.dll.

---

## 2. Plugin.dll — Configuration

**File:** `plugin_decompiled.c`

### 2.1 Exported Functions

| Export | Line | Returns |
|--------|------|---------|
| `brand_group_mutex_name()` | 2 | `"Renault-Dacia.Agent.Mutex"` |
| `brand_registry_root()` | 11 | `"SOFTWARE\\DaciaAutomotive\\Toolbox4"` |
| `brand_window_class()` | 20 | `L"DaciaAutomotive.MsgWindow.Class"` |
| `brand_window_title()` | 29 | `L"DaciaAutomotive.MsgWindow.Title"` |
| `brand_has_value()` | 40 | Check if config key exists |
| `brand_get_value()` | 94 | Get config value by key |
| `brand_set_value()` | 154 | Set config value |
| `brand_free_buffer()` | 237 | Free allocated buffer |

### 2.2 Configuration Tree (FUN_100015c0, line 444–1190)

| Section | Key | Value | Line |
|---------|-----|-------|------|
| `naviextras` | `boot_service_address` | `https://zippy.naviextras.com/services/index/rest` | 486–537 |
| `toolbox_ui` | `live_domain` | `naviextras.com` | 548–564 |
| `services` | `brand` | `DaciaAutomotive` | 630–660 |
| `services` | `device_type` | `DaciaToolbox` | 670–672 |
| `services` | `timeout_idle` | `30000` | ~700 |
| `device_manager` | `model_filter` | `Dacia_ULC` | ~740 |
| `toolbox` | `display_version` | `5.28.2026041167` | ~770 |
| `toolbox_ui` | `appname` | `Dacia Media Nav Evolution Toolbox` | ~1000 |
| `self_update` | `address` | `https://zippy.naviextras.com/services/selfie/rest/1/update` | 1090 |
| `toolbox_ui` | `background_color` | `0xFFF5F5F5` | ~1160 |
| `toolbox` | `legacy_brand` | `Dacia` | ~1180 |

---

## 3. nngine.dll — Module Registration

### 3.1 Module Table (lines 100–2400)

| Module Name | Factory Function | Line |
|-------------|-----------------|------|
| `TARGET_FS_FACTORY` | `FUN_10026640` | 175 |
| `AUTH_HTTP_CLIENT` | `FUN_1008b2f0` | 422 |
| `NAVIEXTRAS_INDEX_SERVICE` | `FUN_1008b350` | 403 |
| `HTTP_SSE_CREATOR` | `FUN_10032660` | 2132 |
| `HTTP_LOG_ASSISTANT` | `FUN_10056a10` | 2151 |
| `SIMPLE_HTTP_CLIENT` | `FUN_100881d0` | 2170 |
| `HTTP_AUTHENTICATION_MANAGER` | `FUN_1000dcf0` | 2189 |
| `HTTP_PROXY_SETTINGS_MANAGER` | `FUN_100b3840` | 2208 |
| `HTTP_COOKIE_SERVER` | `FUN_1008fa70` | 2227 |
| `HTTP_CLIENT` | `FUN_100122f0` | 2246 |
| `CERTIFICATE_CHECKER_PASSIVE` | `FUN_10196110` | 2265 |

---

## 4. HTTP Communication

### 4.1 Proxy & User-Agent (line 332887)

```c
iVar5 = WinHttpOpen(L"WinHTTP ToolBox/1.0", 0, 0, 0, 0);
iVar6 = WinHttpGetIEProxyConfigForCurrentUser(&local_58);
```

### 4.2 SSL/TLS

Uses bundled OpenSSL (`libssl-1_1.dll`). Loads Windows root certificates into OpenSSL trust store (line 333194).

### 4.3 HTTP Headers

- `User-Agent: WinHTTP ToolBox/1.0`
- `X-Device` header (line 111407)
- `Content-Type: application/x-binary` (for market calls)
- CONNECT tunneling for HTTPS through proxy (line 338581)

### 4.4 Auth Modes (line 119090–119278)

```c
// Two modes:
"full-auth"    // full authentication (default for LOGIN)
"device-auth"  // device-only authentication (subsequent calls)
```

---

## 5. Boot & Catalog Flow

### 5.1 Boot Service (line 142100–142250)

```c
FUN_10166560(&local_b4, "naviextras", "boot_service_address");
FUN_101bad80("/boot");
FUN_101bae20(L"service_boot_v3");
```

Flow: Read config → append `/boot` → tag as `service_boot_v3` → send GET with `device_id`.

### 5.2 Boot Response (line 114250–114420)

Parses response to extract `index_service_address` and connect server address.

### 5.3 Catalog Fetch (line 142287–142360)

```c
FUN_101bae20(L"service_catalog_v3");
```

After boot, fetches catalog using the index URL from boot response.

---

## 6. Market API Calls

### 6.1 Call Sequence (lines 15591–22308)

| Order | Call | Sent Line | Response Line |
|-------|------|-----------|---------------|
| 1 | `LOGIN` | 16339 | 26333 |
| 2 | `SEND_DRIVES` | 18745 | 26750 |
| 3 | `SEND_FINGERPRINT` | 22308 | — |
| 4 | `SEND_MD5` | 18984 | — |
| 5 | `SEND_SGN_FILE_VALIDITY` | 19182 | — |
| 6 | `SEND_DEVICE_STATUS` | 22243 | — |
| 7 | `GET_PROCESS` | 15591 | 26194 |
| 8 | `SEND_BACKUPS` | 16918 | 26472 |
| 9 | `SEND_PROCESS_STATUS` | 19317 | — |

### 6.2 Error Handling (line 26217)

```c
"ERROR on response of market call \"%s\"! MainError: '%d' SubError: '%d (%s)'"
```

---

## 7. Device Recognition

### 7.1 device.nng Reading (line 70730)

```c
uVar3 = FUN_101c00a0(L"device.nng");
```

### 7.2 Recognition Flow

```
1. Read device.nng from USB: NaviSync/license/device.nng
2. XOR-decode using 4096-byte table (see §17)
3. Extract APPCID (offset 0x5C, LE 32-bit) → "APPCID found: %d" (line 77400)
4. Extract SKU IDs (via filter_factory_sku) → "SKU IDs found: %s" (line 77758)
5. Extract BrandMD5 → "BrandMD5 found in device.nng: %s" (line 77416)
6. Match APPCID → "Device models based on APPCID: %s" (line 79640)
7. Match SKU IDs → "Device models based on SKU IDs: %s" (line 79767)
8. Match BrandMD5 → "Device models based on Brand MD5: %s" (line 79884)
9. Result: "Device recognition success, recognized device ID: '%d' Name: '%s'" (line 77454)
```

### 7.3 Synctool Fingerprint Validation (line 78495–78608)

```c
"Invalid Synctool fingerprint: missing device checksum file"
"Invalid Synctool fingerprint: MD5 mismatch"
"Invalid Synctool fingerprint: missing drive info file"
```

---

## 8. Device Registration

### 8.1 Register Service (line 136314)

```c
FUN_101bad80("service_register_v1");
```

### 8.2 Register Endpoints

| Path | Line | Arg Size | Purpose |
|------|------|----------|---------|
| `/get_device_model_list` | 66635 | 0x18 | Get known device models |
| `/get_device_descriptor_list` | 66215 | 0x20 | Get device descriptors |
| `/devinfo` | 124813 | 0x08 | Get device info by serial |
| `/device` | 138401 | 0x7c | Register device (normal) |
| `/registerdeviceandunbind` | 138307 | 0x7c | Register + unbind previous |

---

## 9. Download Manager

### 9.1 Cache Path (line 108986)

```c
FUN_10166580(local_8, "download_manager", "cache_path", "%app%/download_cache");
```

### 9.2 Download Batch (line 36694)

```c
"Download added to batch: ID = %d, Target path: %ls"
```

### 9.3 MD5 Verification

```c
"check_md5_during_file_update"   // config key
"AcquireDownloader UpdateExpectedMD5Result: %s"
```

### 9.4 Alternative Host (line 37223)

```c
FUN_10166560(local_30, "debug", "alternative_download_host");
```

---

## 10. USB Drive Detection

```c
"USB drive [%ls] arrived"
"Drive added (context ID: %d, root ID: %ls)"
"Drive [%ls] removed"
```

---

## 11. Content Installation (Synctool)

### 11.1 Synctool Types

`CLASSIC_SYNCTOOL`, `EXTENDED_SYNCTOOL`, `EXTENDED_SYNCTOOL_WITHOUT_HU_MANAGE_CONTENT`, `LEGACY_SYNCTOOL`, `NO_SYNCTOOL`

### 11.2 Shadow Files (*.stm)

```c
FUN_101bae20(L"*.stm");   // line 45941, 46465
FUN_101bae20(L"*.md5");   // line 45936
```

### 11.3 Update Checksum

```c
FUN_101c0210(PTR_u_update_checksum_md5_1030b0ec);
// Logs: "Update checksum: %s"
```

`update_checksum.md5` on USB root signals head unit that new content is available.

---

## 12. Fingerprint Management (lines 53797–60729)

```c
FUN_101c00a0(L"fingerprints");
FUN_101c0210(PTR_u_fingerprint_xml_1030b110);
FUN_101baad0("encode_fingerprint");
```

Stored in `fingerprints/` on USB. Format: `fingerprint.xml`. Validated by MD5 + device checksum + drive info file.

---

## 13. Self-Update

Compares `engine_version.toolbox` with `current_version.self_update`.
URL: `https://zippy.naviextras.com/services/selfie/rest/1/update`

---

## 14. License Management

```c
"Failed to get new licenses after activation, error codes: %d/%d"
"Cannot persist registration data to device: device id=%d"
```

License types: `BinaryLicense`, `ClientLicense`, `GetFactoryLicensesArg/Ret`, `GetLicenseInfoArg/Ret`.

---

## 15. Market Call Implementation Pattern

Each market call follows an identical pattern (lines 155950–156900+):

```
1. Check service available: (**(code **)*param_1)()
2. Check serialization: FUN_101a98d0(0, 0)
3. Create request arg: FUN_100baXXX(param_2) — specific factory per call
4. Set URL path: FUN_101bad80("/sendXXX")
5. Build request: FUN_10093010(session, &callback, connection+7, arg, buffer, 0)
6. Send: FUN_100902e0(result, buffer)
```

### 15.1 Market Call → Function Mapping

| Call | Path | Arg Factory | Arg Size | Line |
|------|------|-------------|----------|------|
| LOGIN | `/login` | `FUN_100ba130` | 76 bytes | 155845 |
| GET_PROCESS | `/getprocess` | inline | 8 bytes | 155713 |
| SEND_BACKUPS | `/sendbackups` | `FUN_100ba210` | 32 bytes | 155977 |
| SEND_DEVICE_STATUS | `/senddevicestatus` | `FUN_100ba280` | 240 bytes | 156111 |
| SEND_DRIVES | `/senddrives` | `FUN_100ba460` | 32 bytes | 156243 |
| SEND_ERROR | `/senderror` | `FUN_100ba4d0` | 32 bytes | 156375 |
| SEND_FILE_CONTENT | `/sendfilecontent` | `FUN_100ba530` | 80 bytes | 156507 |
| SEND_FINGERPRINT | `/sendfingerprint` | `FUN_100ba070` | 76 bytes | 156646 |
| SEND_MD5 | `/sendmd5` | `FUN_100ba600` | 40 bytes | 156779 |
| SEND_PROCESS_STATUS | `/sendprocessstatus` | `FUN_100ba680` | 80 bytes | 156911 |
| SEND_REPLACEMENT_DRIVES | `/sendreplacementdrives` | `FUN_100ba700` | 40 bytes | 157043 |
| SEND_SGN_FILE_VALIDITY | `/sendsgnfilevalidity` | `FUN_100ba780` | 36 bytes | 157175 |
| SETTINGS | `/settings` | — | — | 157319 |

### 15.2 Complete API Path List

**Index/Market service** (appended to index URL):
`/boot`, `/login`, `/getprocess`, `/sendbackups`, `/senddevicestatus`, `/senddrives`, `/senderror`, `/sendfilecontent`, `/sendfingerprint`, `/sendmd5`, `/sendprocessstatus`, `/sendreplacementdrives`, `/sendsgnfilevalidity`, `/settings`

**Register service** (`/services/register/rest/1`):
`/get_device_model_list`, `/get_device_descriptor_list`, `/devinfo`, `/device`, `/registerdeviceandunbind`

**License/Connected services**:
`/license`, `/licenses`, `/licinfo`, `/activateService`, `/hasActivatableService`, `/delegator`, `/scratch`

---

## 16. Application Lifecycle (PROGRAM_DIRECTOR)

**Module:** `PROGRAM_DIRECTOR` (line 1809, factory `FUN_10014d00`)

```
1. INIT       → Load plugin.dll, CEF, nngine modules
2. BOOT       → GET {boot_url}/boot → service URLs
                 GET {index_url} → content catalog
3. DETECT     → USB drive → device.nng → XOR decode → APPCID/SKU/BrandMD5
4. REGISTER   → /get_device_model_list → /devinfo → /device
5. MARKET     → /login → /senddrives → /sendfingerprint → /getprocess
6. DOWNLOAD   → download_cache, batch, MD5 verify
7. INSTALL    → .stm + .md5 + update_checksum.md5
8. COMPLETE   → synctool validates, licenses updated, fingerprint updated
```

### 16.1 Task Types

`RegisterDeviceTask`, `DrivesTask`, `SendFingerprintTask`, `SgnCheckTask`, `ComputeMd5Task`, `DownloadTask`, `InstallTask`, `BackupTask`, `RestoreTask`, `DeleteBackupTask`, `FileContentTask`, `ReplacementTask`, `LanguageTask`, `UploadTask`, `SendLogTask`, `PollTask`, `SleepTask`, `CancelProcessTask`

---

## 17. XOR Tables & device.nng Decoding

### 17.1 Table Locations (extracted from nngine.dll)

| Table | Virtual Address | File Offset | Size |
|-------|----------------|-------------|------|
| Normal | `DAT_102b1260` | `0x002b0460` | 4096 bytes |
| China | `DAT_102b2260` | `0x002b1460` | 4096 bytes |

Both in `.rdata` section (image base `0x10000000`).
Extracted to: `analysis/xor_table_normal.bin`, `analysis/xor_table_china.bin`

### 17.2 Table Selection (line 33370–33440)

```c
"Switching XOR table, no China SKU IDs found"     → DAT_102b1260 (normal)
"Switching XOR table, China SKU ID(s) found: %s"  → DAT_102b2260 (China)
```

### 17.3 XOR Algorithm (line 453880–453960)

Operates on 32-bit words, NOT byte-by-byte:

```c
// Decode: word[i] = (xor_table[(i + offset) & 0x3ff] ^ word[i]) - iVar7
// Encode: word[i] = (word[i] + iVar7) ^ xor_table[(i + offset) & 0x3ff]
```

- `xor_table` = 1024 uint32 values (4096 bytes)
- `offset` = chunk index (0 for first 4096 bytes, increments per chunk)
- `iVar7` = 0 for first chunk, then `word[3]` (offset 0xC) of decoded data
- `& 0x3ff` = modulo 1024

### 17.4 XOR Stream Wrapper (FUN_10144380, line 281468)

First 12 bytes (0xC) are read as header before XOR begins. The NNGE marker at offset 0x50 and APPCID at offset 0x5C are in the RAW (un-XOR'd) data.

### 17.5 Normal XOR Table (first 64 bytes)

```
aa 28 1e 16 6b c3 7f ce 9c 04 1b 16 2d 19 aa ed
3c 8f 2a 99 d9 fa be 18 48 99 55 d8 7a ee 40 94
ef 62 a6 c2 e1 6e bd fa c6 7d 56 5e 31 a4 b6 ba
5c 06 09 0d a0 f4 88 40 26 86 8d e2 5c e0 0f 67
```

---

## 18. igo-binary Serialization Format

### 18.1 Source

```
engine\libraries\nbtapi\NNGAPI\API\Serializer.cpp  (line 482673)
engine\libraries\nbtapi\NNGAPI\API\UnitValue.cpp   (line 510687)
```

No public documentation exists. NNG's proprietary protocol.

### 18.2 Primitive Functions

| Function | Line | Operation |
|----------|------|-----------|
| `FUN_10242e10` | 514852 | Read uint32 (4 bytes LE) |
| `FUN_10242e60` | 514870 | Read null-terminated string |
| `FUN_10242dd0` | 514834 | Read N raw bytes |
| `FUN_10056ad0` | 69206 | Write N bytes to buffer |

### 18.3 Serializer Header/Footer

Header (`FUN_1021ee00`, line 483311):
```c
write(type_byte, 1);     // 1 byte: type tag
write(expected_count, 4); // 4 bytes: count (LE32)
```

Footer (`FUN_1021eee0`):
```c
write(type_byte, 1);     // 1 byte: type tag
write(actual_count, 4);  // 4 bytes: actual count (LE32)
```

### 18.4 UnitValue Type System

Lower 6 bits (`& 0x3f`) = type ID. Upper 2 bits = flags.

| Type ID | Name | Notes |
|---------|------|-------|
| 0x00 | null/container | |
| 0x01 | int8 | numeric |
| 0x03 | int32 | numeric |
| 0x04 | int64 | numeric |
| 0x07 | string | |
| 0x09 | bool/byte | |
| 0x0f | array | |
| 0x11 | object | 0x51 in boot = 0x11 + flag 0x40 |
| 0x12 | map | |
| 0x15 | embedded object | length-prefixed |
| 0x16 | list | with child elements |
| 0x47 | object reference | |

Flags: `0x40` = flag bit 1, `0x80` = flag bit 2 (container/continuation)

### 18.5 Request Serialization (FUN_10093010, line 123012)

```
1. Initialize 240-byte request structure
2. Increment global request counter (DAT_1031497c)
3. FUN_101b41b0 → look up serializer for service+arg type
4. Serializer converts arg object → igo-binary bytes
5. FUN_10091bf0 → queue request
```

### 18.6 Content Types

| Direction | Content-Type |
|-----------|-------------|
| Request (market calls) | `application/x-binary` |
| Response (from server) | `application/vnd.igo-binary; v=1` |
| Request (boot v3) | `application/json` (empty `{}`) |
| Request (boot v2) | none (GET request) |

---

## 19. igo-binary Wire Format (Empirical)

Tested against live API at `zippy.naviextras.com`.

### 19.1 Minimum Valid Request

```
< 6 bytes → 500 (parse error)
≥ 6 bytes → 412 (valid format, missing device data)

Format: [2 bytes envelope] [4 bytes type/version]
Byte 5 is validated (0xFF → 500). Envelope bytes can be any value.
```

### 19.2 Boot Response (350 bytes)

```
Header (11 bytes):
  [0-1]   0x80 0x80           Envelope
  [2-3]   0x69 0x8f           Message type ID
  [4-7]   0x05 0x0d 0x00 0x01 Flags/version
  [8]     0x51                Entry type (object 0x11 | flag 0x40)
  [9]     0x80                Array marker
  [10]    0x06                Entry count = 6

Entry × 6:
  [1B] version  [1B] name_len  [NB] name  [1B] 0x00  [1B] url_len  [NB] url
```

All 350 bytes consumed exactly by header + 6 entries. Zero remaining.

### 19.3 Model List Response (10 bytes)

```
[0] 0x80  [1] 0x00  [2] 0x05  [3-7] "3.857"  [8-9] 0x00 0x00
```

### 19.4 Server Endpoint Behavior

| Endpoint | 500 | 412 | 417 | 200 |
|----------|-----|-----|-----|-----|
| Index v3 POST | < 6 bytes | ≥ 6 bytes | — | boot `{}` |
| Register /get_device_model_list | — | — | — | JSON `{}` |
| Register /get_device_descriptor_list | igo-binary | — | JSON `{}` | — |
| Register /devinfo | — | any format | — | — |
| Register /device | igo-binary | — | — | — |

---

## TODO

- [ ] Capture real traffic (Wine + mitmproxy) to get exact igo-binary request bytes
- [ ] Trace LOGIN arg factory (`FUN_100ba130`, 76 bytes) field-by-field
- [ ] Trace GET_PROCESS response parser to understand download URL format
- [ ] Trace fingerprint.xml format
- [ ] Trace MTP communication path (mtp.dll)
