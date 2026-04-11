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

These are the only plugin.dll exports the exe uses — a key/value config store.

### 1.2 CEF Initialization (line 23154)

```c
// FUN_00419bb0 (line 23108)
iVar5 = cef_initialize(param_1, -(uint)(param_2 != 0) & param_2 + 4U, puVar4);
```

Checks CEF API hash compatibility first, then calls `cef_initialize`.

### 1.3 Main Loop (line 16107–16108)

```c
// FUN_00412440 (line 16095)
cef_run_message_loop();   // line 16107 — blocks until app exits
cef_shutdown();           // line 16108
```

The exe is essentially a thin CEF shell. All business logic lives in nngine.dll.

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

The config is a tree of `(section, key, value)` tuples, set via `FUN_10002b00`.
Pattern: `FUN_10002b00(param_1, section, key, value)`

**Decoded config (in order of initialization):**

| Section | Key | Value | Line |
|---------|-----|-------|------|
| `naviextras` | `boot_service_address` | `https://zippy.naviextras.com/services/index/rest` | 486–537 |
| `toolbox_ui` | `live_domain` | `naviextras.com` | 548–564 |
| `services` | `brand` | `DaciaAutomotive` | 630–660 |
| `services` | `device_type` | `DaciaToolbox` | 670–672 |
| `services` | `timeout_idle` | `30000` | ~700 |
| `device_manager` | `model_filter` | `Dacia_ULC` | ~740 |
| `toolbox` | `display_version` | `5.28.2026041167` | ~770 |
| `toolbox` | `eula_version` | (single char) | ~840 |
| `toolbox_ui` | `debug_mode` | (single char) | ~880 |
| `toolbox_ui` | `client_width` | (3 chars) | ~920 |
| `toolbox_ui` | `client_height` | (3 chars) | ~960 |
| `toolbox_ui` | `appname` | `Dacia Media Nav Evolution Toolbox` | ~1000 |
| `resources` | `preinstalled_cfg` | `resources/preinstalled_resources.txt` | ~1040 |
| `self_update` | `ignore` | (single char) | ~1060 |
| `self_update` | `address` | `https://zippy.naviextras.com/services/selfie/rest/1/update` | 1090 |
| `toolbox_ui` | `border_type` | (single char) | ~1120 |
| `toolbox_ui` | `background_color` | `0xFFF5F5F5` | ~1160 |
| `toolbox` | `detect_external_caches` | (value) | ~1170 |
| `toolbox` | `legacy_brand` | `Dacia` | ~1180 |

---

## 3. nngine.dll — Module Registration

**File:** `nngine_decompiled.c`

### 3.1 Module Table (lines 100–2400)

nngine.dll registers a large number of named modules/services at startup. Each module is registered with a name and a factory function. The pattern is:

```c
pcVar3 = "MODULE_NAME";
uVar1 = FUN_XXXXXXXX("MODULE_NAME", 2);  // 2 = registration type
```

**Complete module list (in registration order):**

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

*(TODO: extract remaining modules from lines 100–2400)*

---

## 4. HTTP Communication

### 4.1 Proxy Settings (line 332887–333089)

```c
// FUN at line 332887
iVar5 = WinHttpOpen(L"WinHTTP ToolBox/1.0", 0, 0, 0, 0);  // User-Agent
iVar6 = WinHttpGetIEProxyConfigForCurrentUser(&local_58);   // Read IE proxy
iVar6 = WinHttpGetProxyForUrl(local_88, *puVar8, local_7c, &local_64);
WinHttpCloseHandle(iVar5);
```

The app reads proxy settings from IE/system settings using WinHTTP, then uses them for its own OpenSSL-based connections.

### 4.2 SSL/TLS Setup

The app uses OpenSSL (bundled `libssl-1_1.dll`) for all HTTPS connections:

```c
// Symbol resolution (line 356734–356954)
"SSL_CTX_new"                    // line 356734
"SSL_CTX_load_verify_locations"  // line 356954
"SSL_CTX_get_cert_store"         // line 357053
"SSL_CTX_set_verify"             // (in symbol table)
```

**Certificate loading** (line 333194): Loads Windows root certificates into OpenSSL:
```c
"CertOpenSystemStoreA"           // line 333194 — opens Windows ROOT cert store
"CertEnumCertificatesInStore"    // line 333206 — iterates all certs
"CertCloseStore"                 // line 333218
// Then uses X509_STORE_add_cert to add each to OpenSSL's trust store
```

### 4.3 HTTP Request Construction

The app constructs HTTP requests with these headers:
- `User-Agent: WinHTTP ToolBox/1.0` (line 332887)
- `Content-Type: application/x-www-form-urlencoded` (found in strings)
- `X-Device` header (line 111407)
- `Accept` header
- `Proxy-Authorization` (line ~344900 area, if proxy requires auth)

CONNECT tunneling for HTTPS through proxy (line 338581):
```c
FUN_101ba3d0(local_34, "CONNECT %s HTTP/1.1", *puVar5);
```

---

## 5. Boot & Catalog Flow

### 5.1 Boot Service Address Setup (line 114723–114727)

```c
// Dev URL template:
FUN_101ba3d0(local_14, "http://zippy.dev.naviextras.com/services/index/rest/%d/boot", 2);
FUN_101665e0(local_18, "naviextras", "boot_service_address", local_14);

// Production URL (from plugin config):
FUN_101665e0(local_1c, "naviextras", "boot_service_address_prod", param_1 + 0x1d);
```

The dev URL uses version `2` in the path. The prod URL comes from plugin config: `https://zippy.naviextras.com/services/index/rest`.

### 5.2 BOOT_CATALOG_FETCHER (line 142100–142250)

```c
// FUN_100a8540 (line 142106)
FUN_10166560(&local_b4, "naviextras", "boot_service_address");  // line 142141
// ... creates HTTP session ...
FUN_1000d160(&local_44,
    "BOOT_CATALOG_FETCHER::%s creating session, boot_url=%s, device_id=%s",
    "BOOT_CATALOG_FETCHER::Cacheable_SendGet::...",
    *puVar5, uVar7);                                             // line 142180
FUN_101bad80("/boot");                                           // line 142218
FUN_101bae20(L"service_boot_v3");                                // line 142241
```

**Flow:**
1. Reads `boot_service_address` from config
2. Creates an HTTP session
3. Appends `/boot` to the URL
4. Tags the request as `service_boot_v3`
5. Sends GET request with `device_id` parameter

### 5.3 Boot Response Handler (line 114250–114420)

```c
// NAVIEXTRAS_INDEX_SERVICE::OnHttpResponseFromBoot
FUN_1000d160(&local_60,
    "NAVIEXTRAS_INDEX_SERVICE::OnHttpResponseFromBoot - result: %d, error code: %d, response: %s",
    *(undefined4 *)(iVar2 + 4), *(undefined4 *)(iVar2 + 8), *puVar4);  // line 114265
```

On success (result=0), parses the response to extract:
- `index_service_address` (line 114739)
- Connect server address

Then stores these for subsequent catalog/market calls.

### 5.4 MAIN_CATALOG_FETCHER (line 142287–142360)

```c
FUN_1000d160(&local_44, "MAIN_CATALOG_FETCHER::%s",
    "MAIN_CATALOG_FETCHER::Cacheable_SendGet::...");  // line 142287
FUN_101bae20(L"service_catalog_v3");                   // line 142360
```

After boot succeeds, fetches the main catalog using the index URL obtained from boot.

### 5.5 Index Response Handler (line 114416)

```c
FUN_1000d160(&local_78,
    "NAVIEXTRAS_INDEX_SERVICE::OnHttpResponseFromIndex - result: %d, error code: %d, response: %s",
    puVar9[1], puVar9[2], *puVar4);  // line 114416
```

---

## 6. Market API Calls

### 6.1 Call Sequence (lines 15591–22308)

The market API calls are sent sequentially. Each call is logged:

```c
FUN_1000d160(&local_48, "Market call \"%s\" has been SENT...", "CALL_NAME");
```

**Complete call sequence with line references:**

| Order | Call Name | Sent Line | Response Line | Notes |
|-------|-----------|-----------|---------------|-------|
| 1 | `LOGIN` | 16339 | 26333 | Authenticate session |
| 2 | `SEND_DRIVES` | 18745 | 26750 | Report USB drives |
| 3 | `SEND_FINGERPRINT` | 22308 | — | Send device fingerprint (delegated) |
| 4 | `SEND_MD5` | 18984 | — | Send checksums (delegated) |
| 5 | `SEND_SGN_FILE_VALIDITY` | 19182 | — | Validate signatures (delegated) |
| 6 | `SEND_DEVICE_STATUS` | 22243 | — | Report device status (delegated) |
| 7 | `GET_PROCESS` | 15591 | 26194 | Get available updates/downloads |
| 8 | `SEND_BACKUPS` | 16918 | 26472 | Send backup info |
| 9 | `SEND_PROCESS_STATUS` | 19317 | — | Report progress |
| 10 | `SEND_REPLACEMENT_DRIVES` | 21682 | — | Report replacement drives |
| 11 | `SEND_ERROR` | 22116 | — | Report errors |
| 12 | `SEND_FILE_CONTENT` | — | — | Send file content |

### 6.2 Market Call Error Handling

```c
// Response pattern (line 26217):
FUN_1000d160(&local_ac,
    "ERROR on response of market call \"%s\"! MainError: '%d' SubError: '%d (%s)'",
    "GET_PROCESS", local_40, local_3c, uVar2);
```

Each response has `MainError` and `SubError` codes.

### 6.3 API Endpoint Paths (from nngine.dll strings)

These paths are appended to the index service URL:

| Path | Market Call |
|------|------------|
| `/login` | LOGIN |
| `/senddrives` | SEND_DRIVES |
| `/sendfingerprint` | SEND_FINGERPRINT |
| `/sendmd5` | SEND_MD5 |
| `/sendsgnfilevalidity` | SEND_SGN_FILE_VALIDITY |
| `/senddevicestatus` | SEND_DEVICE_STATUS |
| `/getprocess` | GET_PROCESS |
| `/sendbackups` | SEND_BACKUPS |
| `/sendprocessstatus` | SEND_PROCESS_STATUS |
| `/sendreplacementdrives` | SEND_REPLACEMENT_DRIVES |
| `/senderror` | SEND_ERROR |
| `/sendfilecontent` | SEND_FILE_CONTENT |

---

## 7. Device Recognition

### 7.1 device.nng Reading (line 70730)

```c
uVar3 = FUN_101c00a0(L"device.nng");  // line 70730
FUN_10058a00(*(undefined4 *)(param_1 + 4), uVar3, param_2, puVar12, pcVar15);
```

### 7.2 BrandMD5 Extraction (line 77416–77430)

```c
FUN_1000d160(&local_60, "BrandMD5 found in device.nng: %s", *puVar5);  // line 77416
FUN_1000d160(&local_9c, "BrandMD5 is not specified in device.nng");     // line 77430
```

### 7.3 Device Model Recognition (line 79640–79884)

The app matches the device using three criteria:

```c
FUN_1000d160(&local_48, "Device models based on APPCID: %s", *puVar4);      // line 79640
FUN_1000d160(&local_84, "Device models based on SKU IDs: %s", *puVar4);     // line 79767
FUN_1000d160(&local_58, "Device models based on Brand MD5: %s", *puVar3);   // line 79884
```

**Recognition flow:**
1. Extract APPCID from device.nng → match against model list
2. Extract SKU IDs from device.nng → match against model list
3. Extract BrandMD5 from device.nng → match against model list
4. Intersect results to find the device model

```c
// Success (line 77454):
"Device recognition success, recognized device ID: '%d' Name: '%s' DisplayName: '%s'"

// Failures:
"Device recognition failed, no matching device model found!"           // line 77443
"Device recognition failed, found multiple model for this device!"     // line 77462
"Device recognition has failed! Model list might be empty..."          // line 33726
```

### 7.4 Synctool Fingerprint Validation (line 78495–78608)

```c
"Invalid Synctool fingerprint: missing device checksum file"  // line 78495
"Invalid Synctool fingerprint: MD5 mismatch"                  // line 78525
"Invalid Synctool fingerprint: missing drive info file"       // line 78608
```

### 7.5 XOR Table for device.nng Decoding (line 33370–33440)

device.nng data is XOR-decoded using a 4096-byte table:

```c
// Normal table (line 33388):
FUN_1027fa10(&DAT_10310028, &DAT_102b1260, 0x1000);  // copy 4096 bytes from DAT_102b1260

// China table (line 33429):
FUN_1027fa10(&DAT_10310028, &DAT_102b2260, 0x1000);  // copy 4096 bytes from DAT_102b2260
```

The table selection depends on whether China SKU IDs are found:
```c
"Switching XOR table, no China SKU IDs found"     // line 33383 → use DAT_102b1260
"Switching XOR table, China SKU ID(s) found: %s"  // line 33429 → use DAT_102b2260
```

### 7.6 Device Recognition Flow Summary

```
1. Read device.nng from USB: NaviSync/license/device.nng
2. Parse device.nng binary format (XOR-decoded)
3. Extract APPCID (at offset 0x5C, little-endian 32-bit)
4. Extract SKU IDs (via filter_factory_sku config)
5. Extract BrandMD5 (XOR-encoded at offset 0x40)
6. Call /get_device_model_list to get known models
7. Match APPCID → candidate models
8. Match SKU IDs → narrow candidates
9. Match BrandMD5 → final match
10. Result: device ID, Name, DisplayName
    OR: "no matching device model found"
    OR: "found multiple model for this device"
```

---

## 8. Device Registration

### 8.1 Register Service (line 136314–136840)

```c
FUN_101bad80("service_register_v1");  // line 136314, 136358, 136840
```

### 8.2 Register Endpoints

| Path | Purpose | Line |
|------|---------|------|
| `/get_device_model_list` | Get list of known device models | (strings) |
| `/get_device_descriptor_list` | Get device descriptors | (strings) |
| `/devinfo` | Get device info by serial | 66954 |
| `/device` | Register device | (strings) |
| `/registerdeviceandunbind` | Register + unbind previous | (strings) |

### 8.3 GetDeviceInfo (line 124876)

```c
FUN_1000d160(&local_40, "SERVICE_REGISTER::OnGetDeviceInfo SerialID=%d", param_2);
```

---

## 9. Download Manager

### 9.1 Download Cache (line 108986)

```c
FUN_10166580(local_8, "download_manager", "cache_path", "%app%/download_cache");  // line 108986
```

Default cache path: `%app%/download_cache`

### 9.2 Download Batch (line 36694)

```c
FUN_1000d160(&local_e4,
    "Download added to batch: ID = %d, Target path: %ls", uVar4, *puVar6);  // line 36694
```

### 9.3 Download Progress (line 36541–36577)

```c
FUN_101b9480(L"downloaded size: ", 0x11, *puVar4, uVar3);  // line 36546
local_20[0] = L" Bytes, download speed: ";                  // line 36541
FUN_1000d160(&local_7c, "Additional download info: %ls", *puVar4);  // line 36577
```

### 9.4 Alternative Download Host (line 37223)

```c
FUN_10166560(local_30, "debug", "alternative_download_host");  // line 37223
```

### 9.5 MD5 Verification (line ~various)

```c
"check_md5_during_file_update"   // config key
"File added to update checksum - path: %ls, MD5: %s"
"AcquireDownloader UpdateExpectedMD5Result: %s"
```

### 9.6 Download Failure (line 37739–37812)

```c
FUN_1000d160(&local_40, "download failed, cancelling...");  // line 37739, 37812
```

---

## 10. USB Drive Detection

### 10.1 Removable Device Manager

```c
"device [%S] is not known by REMOVABLE_DEVICE_MANAGER, trying to create"
"device [%S] has been created successfully"
"device [%S] inserted: %d ms"
"device [%S] removal is FILTERED by REMOVABLE_DEVICE_MANAGER"
"USB drive [%ls] arrived"
"Drive added (context ID: %d, root ID: %ls)"
"Drive [%ls] removed"
```

### 10.2 Drive Info

```c
"Cannot get volume information for '%ls', error code: %d"
"detect_fixed_drives"    // config key
"detect_folder_drive"    // config key
```

---

## 11. Content Installation (Synctool)

### 11.1 Synctool Types

```c
"CLASSIC_SYNCTOOL"
"EXTENDED_SYNCTOOL"
"EXTENDED_SYNCTOOL_WITHOUT_HU_MANAGE_CONTENT"
"LEGACY_SYNCTOOL"
"NO_SYNCTOOL"
```

### 11.2 Content Types (from strings)

```
content.map.map_file_open_error
content.poi.poi_file_open_error
content.voice.no_voice_file_found
content.voice.unsupported_voice
content._3d._3d_file_open_error
content.global_cfg.global_cfg_file_open_error
content.lang.no_lang_file_found
```

---

## 12. Fingerprint Management

### 12.1 Fingerprint Operations (lines 53797–60729)

```c
FUN_101c00a0(L"fingerprints");                                    // line 53797
FUN_101c0210(PTR_u_fingerprint_xml_1030b110);                     // line 54006
FUN_101baad0("encode_fingerprint");                                // line 56670
FUN_101baad0("fingerprint_manager");                               // line 56671
FUN_1000d160(&local_8c, "Error while saving fingerprint, null received");  // line 60318
FUN_1000d160(&local_8c, "Error while saving fingerprint");         // line 60361
FUN_1000d160(&local_78, "Failed to read data from fingerprint");   // line 60729
```

### 12.2 Fingerprint Files

- Stored in `fingerprints/` directory on USB
- Format: `fingerprint.xml` (line 54006 references `fingerprint_xml`)
- Encoded before sending to API (`encode_fingerprint`)
- Validated by MD5 checksum + device checksum file + drive info file

---

## 13. Self-Update

### 13.1 Self-Update Check (line 10848–10911)

```c
FUN_101baad0("engine_version");     // line 10842
FUN_101baad0("toolbox");
FUN_101baad0("current_version");    // line 10847
FUN_101baad0("self_update");        // line 10848
```

Compares `engine_version.toolbox` with `current_version.self_update`. If different, triggers update check.

### 13.2 Self-Update URL

From plugin config: `https://zippy.naviextras.com/services/selfie/rest/1/update`

---

## 14. Connected Services

### 14.1 Connected Service Files (line 145369)

```c
FUN_10166560(local_438, "debug", "connected_service_files_cfg");  // line 145369
```

### 14.2 Service Communication (line 111407)

```c
FUN_101bad80("X-Device");                          // line 111407
FUN_101bae20(L"application/x-binary");             // line 111415
```

Connected services use `X-Device` header and `application/x-binary` content type.

---

## 15. License Management

### 15.1 License Operations

```c
"Failed to get new licenses after activation, error codes: %d/%d"
"Cannot persist registration data to device: device id=%d, missing or invalid license paths."
"Cannot persist registration data to device: device id=%d, path=%ls"
"Cannot persist registration data to fingerprint: device id=%d, path=%ls"
"Can't copy license folder from primary drive to FingerPrint ID='%ls'"
"Error, could not open license file for itapi-connect: '%s'"
```

### 15.2 License Types (from strings)

```
LICTYPE~Skins
BinaryLicense
ClientLicense
AbstractGetLicensesRet
GetFactoryLicensesArg / GetFactoryLicensesRet
GetLicenseInfoArg / GetLicenseInfoRet
```

---

## 16. Market Call Implementation Pattern

Each market call follows an identical pattern (lines 155950–156900+):

```
Function signature: FUN_100bXXXX(param_1, param_2, param_3, param_4, param_5, param_6)

1. Check if service is available: (**(code **)*param_1)()
2. Serialize request: FUN_101a98d0(0, 0) — checks serialization readiness
3. Create request arg object: FUN_100baXXX(param_2) — specific to each call
4. Set URL path: FUN_101bad80("/sendXXX")
5. Build HTTP request: FUN_10093010(session_data, &callback, connection+7, arg_object, buffer, 0)
6. Set vtable: *puVar3 = &PTR_FUN_102bbXXX
7. Send: FUN_100902e0(result, buffer)
```

### Market Call → Function Mapping

| Call | Function | Path | Arg Factory | Arg Size | Line |
|------|----------|------|-------------|----------|------|
| LOGIN | `FUN_100b7c20` | `/login` | `FUN_100ba130` | 0x4c (76 bytes) | 155845 |
| GET_PROCESS | `FUN_100b7920` | `/getprocess` | inline (8 bytes) | 0x08 | 155713 |
| SEND_BACKUPS | `FUN_100b7f20` | `/sendbackups` | `FUN_100ba210` | 0x20 (32 bytes) | 155977 |
| SEND_DEVICE_STATUS | `FUN_100b8220` | `/senddevicestatus` | `FUN_100ba280` | 0xf0 (240 bytes) | 156111 |
| SEND_DRIVES | `FUN_100b8530` | `/senddrives` | `FUN_100ba460` | 0x20 (32 bytes) | 156243 |
| SEND_ERROR | `FUN_100b8830` | `/senderror` | `FUN_100ba4d0` | 0x20 (32 bytes) | 156375 |
| SEND_FILE_CONTENT | `FUN_100b8b30` | `/sendfilecontent` | `FUN_100ba530` | 0x50 (80 bytes) | 156507 |
| SEND_FINGERPRINT | `FUN_100b8e30` | `/sendfingerprint` | `FUN_100ba070` | 0x4c (76 bytes) | 156646 |
| SEND_MD5 | `FUN_100b9150` | `/sendmd5` | `FUN_100ba600` | 0x28 (40 bytes) | 156779 |
| SEND_PROCESS_STATUS | `FUN_100b9450` | `/sendprocessstatus` | `FUN_100ba680` | 0x50 (80 bytes) | 156911 |
| SEND_REPLACEMENT_DRIVES | `FUN_100b9750` | `/sendreplacementdrives` | `FUN_100ba700` | 0x28 (40 bytes) | 157043 |
| SEND_SGN_FILE_VALIDITY | `FUN_100b9a50` | `/sendsgnfilevalidity` | `FUN_100ba780` | 0x24 (36 bytes) | 157175 |
| SETTINGS | `FUN_100b9d50` | `/settings` | (unknown) | (unknown) | 157319 |

### GET_PROCESS Request Arg (8 bytes, line 155703–155710)

Simplest request — just a vtable + flag:
```c
local_c0 = FUN_1027e4f5(8);           // allocate 8 bytes
*local_c0 = &PTR_FUN_102b014c;        // vtable (base class)
*(byte *)(local_c0 + 1) = flag_byte;  // copy 1 byte from input
*local_c0 = &PTR_FUN_102b044c;        // update vtable (derived class)
```

### LOGIN Request Arg (76 bytes, factory FUN_100ba130)

Larger request — contains authentication data (76 bytes allocated).

### Complete API Path List (all paths found in nngine.dll)

**Register service** (`/services/register/rest/1`):
| Path | Line | Arg Size | Purpose |
|------|------|----------|---------|
| `/get_device_model_list` | 66635 | 0x18 (24 bytes) | Get known device models |
| `/get_device_descriptor_list` | 66215 | 0x20 (32 bytes) | Get device descriptors |
| `/devinfo` | 124813 | 0x08 (8 bytes) | Get device info by serial |
| `/device` | 138401 | 0x7c (124 bytes) | Register device (normal) |
| `/registerdeviceandunbind` | 138307 | 0x7c (124 bytes) | Register + unbind previous |

**Index/Market service** (appended to index URL from boot):
| Path | Line | Arg Size | Purpose |
|------|------|----------|---------|
| `/boot` | 142218 | — | Boot/service discovery |
| `/login` | 155845 | 0x4c | Authenticate session |
| `/getprocess` | 155713 | 0x08 | Get available updates |
| `/sendbackups` | 155977 | 0x20 | Send backup info |
| `/senddevicestatus` | 156111 | 0xf0 | Report device status |
| `/senddrives` | 156243 | 0x20 | Report USB drives |
| `/senderror` | 156375 | 0x20 | Report errors |
| `/sendfilecontent` | 156507 | 0x50 | Send file content |
| `/sendfingerprint` | 156646 | 0x4c | Send device fingerprint |
| `/sendmd5` | 156779 | 0x28 | Send checksums |
| `/sendprocessstatus` | 156911 | 0x50 | Report progress |
| `/sendreplacementdrives` | 157043 | 0x28 | Report replacement drives |
| `/sendsgnfilevalidity` | 157175 | 0x24 | Validate signatures |
| `/settings` | 157319 | — | Get/set settings |

**License/Connected services** (appended to register URL):
| Path | Line | Purpose |
|------|------|---------|
| `/license` | 132877, 140801 | Single license operation |
| `/licenses` | 128600, 133041, 140528 | Multiple license operations |
| `/licinfo` | 133142, 140668 | License info query |
| `/activateService` | 127862 | Activate a service |
| `/hasActivatableService` | 128268 | Check for activatable services |
| `/delegator` | 125371 | Delegation |
| `/scratch` | 140396 | Scratch/temp operations |

---

## 19. Application Lifecycle (PROGRAM_DIRECTOR)

**Module:** `PROGRAM_DIRECTOR` (line 1809, factory `FUN_10014d00`)

The app goes through numbered phases, logged as:
```c
"PROGRAM_DIRECTOR: changing phase from %d - \"%s\" to %d - \"%s\""  // line 246274
```

### 19.1 Overall Flow

```
1. INIT PHASE
   ├── Load plugin.dll config
   ├── Initialize CEF
   ├── Initialize nngine modules (HTTP, SSL, proxy, etc.)
   └── Start PROGRAM_DIRECTOR

2. BOOT PHASE
   ├── BOOT_CATALOG_FETCHER: GET {boot_url}/boot
   │   → Returns service URLs (index, register, selfie, mobile)
   ├── MAIN_CATALOG_FETCHER: GET {index_url} (service_catalog_v3)
   │   → Returns content catalog
   └── Wait for catalog ("waiting_for_catalog" / "had_to_wait_for_catalog")

3. DEVICE DETECTION
   ├── REMOVABLE_DEVICE_MANAGER detects USB drives
   ├── Read device.nng from NaviSync/license/device.nng
   ├── XOR-decode device data (4096-byte table)
   ├── Extract APPCID, SKU IDs, BrandMD5
   └── Match against model list → device ID

4. REGISTRATION (if needed)
   ├── /get_device_model_list → get known models
   ├── /get_device_descriptor_list → get device descriptors
   ├── /devinfo → get device info by serial
   ├── /device OR /registerdeviceandunbind → register device
   └── SERVICE_REGISTER::OnGetDeviceInfo SerialID=%d

5. MARKET CALLS (SERVICE_CHAIN_CONTROLLER_SCHEDULER)
   ├── /login → authenticate
   ├── /senddrives → report USB drives
   ├── /sendfingerprint → send device fingerprint
   ├── /sendmd5 → send checksums
   ├── /sendsgnfilevalidity → validate signatures
   ├── /senddevicestatus → report device status
   ├── /getprocess → get available updates
   └── Response: download URLs, content list

6. DOWNLOAD PHASE
   ├── Download to %app%/download_cache
   ├── Batch downloads: "Download added to batch: ID = %d, Target path: %ls"
   ├── Progress: "downloaded size: X Bytes, download speed: Y"
   ├── MD5 verification after each download
   └── Alternative host: debug.alternative_download_host

7. INSTALL PHASE
   ├── Write content to USB drive
   ├── Update *.stm shadow files
   ├── Update *.md5 checksum files
   ├── Update update_checksum.md5
   ├── /sendprocessstatus → report progress
   └── /sendbackups → send backup info

8. COMPLETION
   ├── Synctool validates installation
   ├── License files updated
   └── Fingerprint updated
```

### 19.2 Task Types

| Task | Purpose |
|------|---------|
| `RegisterDeviceTask` | Register device with server |
| `ReRegisterDeviceTask` | Re-register device |
| `DrivesTask` | Report USB drives |
| `SendFingerprintTask` | Send fingerprint |
| `SgnCheckTask` | Signature validation |
| `ComputeMd5Task` | Compute MD5 checksums |
| `DownloadTask` | Download content |
| `InstallTask` | Install to USB |
| `BackupTask` | Create backups |
| `RestoreTask` | Restore from backup |
| `DeleteBackupTask` | Delete backups |
| `FileContentTask` | Send file content |
| `ReplacementTask` | Handle drive replacement |
| `LanguageTask` | Language pack handling |
| `UploadTask` | Upload data to server |
| `SendLogTask` | Send logs |
| `PollTask` | Poll for updates |
| `SleepTask` | Wait/delay |
| `CancelProcessTask` | Cancel operation |

---

## 20. Content Installation Details

### 20.1 Shadow Files (*.stm)

The app scans for `*.stm` and `*.md5` files on the USB:
```c
FUN_101bae20(L"*.stm");   // line 45941, 46465
FUN_101bae20(L"*.md5");   // line 45936
```

### 20.2 Update Checksum

```c
FUN_101c0210(PTR_u_update_checksum_md5_1030b0ec);  // line 45787+
// Logs: "Update checksum: %s"
```

The `update_checksum.md5` file on the USB root signals to the head unit that new content is available.

### 20.3 Synctool Types

`CLASSIC_SYNCTOOL`, `EXTENDED_SYNCTOOL`, `EXTENDED_SYNCTOOL_WITHOUT_HU_MANAGE_CONTENT`, `LEGACY_SYNCTOOL`, `NO_SYNCTOOL`

---

## 21. device.nng XOR Decoding

### 21.1 XOR Table (line 33370–33440)

device.nng data is XOR-decoded using a 4096-byte table at `DAT_10310028`:

```c
// Normal table:
FUN_1027fa10(&DAT_10310028, &DAT_102b1260, 0x1000);  // line 33388

// China table:
FUN_1027fa10(&DAT_10310028, &DAT_102b2260, 0x1000);  // line 33429
```

### 21.2 Device Recognition Flow

```
1. Read device.nng from USB: NaviSync/license/device.nng
2. XOR-decode using 4096-byte table
3. Extract APPCID (offset 0x5C, LE 32-bit) → "APPCID found: %d" (line 77400)
4. Extract SKU IDs (via filter_factory_sku) → "SKU IDs found: %s" (line 77758)
5. Extract BrandMD5 → "BrandMD5 found in device.nng: %s" (line 77416)
6. Match APPCID → "Device models based on APPCID: %s" (line 79640)
7. Match SKU IDs → "Device models based on SKU IDs: %s" (line 79767)
8. Match BrandMD5 → "Device models based on Brand MD5: %s" (line 79884)
9. Result: "Device recognition success, recognized device ID: '%d' Name: '%s'" (line 77454)
```

---

## Remaining TODO

- [ ] Trace the fingerprint.xml format
- [ ] Trace the MTP communication path (mtp.dll)

---

## 22. XOR Tables (Extracted from nngine.dll)

### 22.1 Table Locations

| Table | Virtual Address | File Offset | Size | Purpose |
|-------|----------------|-------------|------|---------|
| Normal | `DAT_102b1260` | `0x002b0460` | 4096 bytes | Standard device.nng decoding |
| China | `DAT_102b2260` | `0x002b1460` | 4096 bytes | China SKU device.nng decoding |

Both tables are in the `.rdata` section of nngine.dll (image base `0x10000000`).

Extracted to:
- `/analysis/xor_table_normal.bin` (4096 bytes, 4080 non-zero)
- `/analysis/xor_table_china.bin` (4096 bytes, 4084 non-zero)

### 22.2 Normal XOR Table (first 64 bytes)

```
aa 28 1e 16 6b c3 7f ce 9c 04 1b 16 2d 19 aa ed
3c 8f 2a 99 d9 fa be 18 48 99 55 d8 7a ee 40 94
ef 62 a6 c2 e1 6e bd fa c6 7d 56 5e 31 a4 b6 ba
5c 06 09 0d a0 f4 88 40 26 86 8d e2 5c e0 0f 67
```

### 22.3 XOR Decode Algorithm (line 453880–453960)

The XOR is NOT a simple byte-by-byte operation. It operates on 32-bit words:

```c
// Decode mode (bVar2=false):
for (i = 0; i < num_words; i++) {
    word[i] = (xor_table[(i + offset) & 0x3ff] ^ word[i]) - iVar7;
}

// Encode mode (bVar2=true):
for (i = 0; i < num_words; i++) {
    word[i] = (word[i] + iVar7) ^ xor_table[(i + offset) & 0x3ff];
}
```

Where:
- `xor_table` = 1024 uint32 values (4096 bytes) at `DAT_10310028`
- `offset` = chunk index (0 for first 4096 bytes, 1 for next, etc.)
- `iVar7` = 0 for first chunk, then `word[3]` (offset 0xC) of decoded data for subsequent chunks
- `& 0x3ff` = modulo 1024 (wraps around the table)

### 22.4 XOR Stream Wrapper (FUN_10144380, line 281468)

The XOR decode is wrapped in a stream object:
```c
FUN_10144380(raw_data, &DAT_10310028, flags, extra_param)
```

This creates a virtual stream that XOR-decodes data on read. The first 12 bytes (0xC) are read as a header before XOR decoding begins (`FUN_10145390(param_2, 0xc, 0, 0)`).

### 22.5 device.nng Structure (after XOR decode)

The file has a 12-byte header that is NOT XOR-encoded, followed by XOR-encoded payload. The "NNGE" marker at offset 0x50 in the raw file is part of the unencoded header/metadata section.

**Note:** The simple XOR decode (with iVar7=0) does not produce readable strings, suggesting either:
1. The first 12 bytes are skipped before XOR is applied (header)
2. Additional transformations are applied after XOR
3. The data is a binary structure, not text

The APPCID at offset 0x5C (`0x42000B53`) is in the RAW (un-decoded) file, suggesting the NNGE section (0x50+) may not be XOR-encoded.

---

## 23. igo-binary Serialization Format

### 23.1 Source Reference

```
C:\TeamCity\work\18111e858c67866e\engine\libraries\nbtapi\NNGAPI\API\Serializer.cpp  (line 482673)
C:\TeamCity\work\18111e858c67866e\engine\libraries\nbtapi\NNGAPI\API\UnitValue.cpp   (line 510687)
```

### 23.2 Primitive Read Functions

| Function | Line | Operation |
|----------|------|-----------|
| `FUN_10242e10` | 514852 | Read 1 uint32 (4 bytes, little-endian) |
| `FUN_10242e60` | 514870 | Read null-terminated string (byte by byte) |
| `FUN_10242dd0` | 514834 | Read N raw bytes (memcpy) |
| `FUN_102426c0` | — | Read length-prefixed data |
| `FUN_10242740` | — | Read 64-bit value (2 × uint32) |

### 23.3 Type System

UnitValue types use lower 6 bits (`& 0x3f`) as type ID:
- Types 1, 3, 4 = numeric (can be multiplied)
- Type 0x47 = object reference

Deserializer switch cases (line 513100+):
| Case | Type |
|------|------|
| 0x0c | (basic type) |
| 0x0d | (basic type) |
| 0x0f | (basic type) |
| 0x10 | (basic type) |
| 0x12 | (basic type) |
| 0x14 | Object handle import |
| 0x15 | Embedded object (length-prefixed) |
| 0x16 | Object with child elements |
| 0x17 | Foreign object handle |
| 0x18 | Relative reference (offset - 0x30000000) |
| 0x19 | Array/list reference |

### 23.4 Boot Response Wire Format

Content-Type: `application/vnd.igo-binary; v=1`

```
Header (11 bytes):
  [0-1]  80 80     Magic/envelope marker
  [2-3]  69 8f     Message type identifier
  [4]    09        (varint: version or flags)
  [5]    ff        (varint continuation)
  [6-7]  00 01     (version/flags)
  [8]    51        Entry type marker ('Q' = 0x51)
  [9]    80        (high bit = array marker?)
  [10]   06        Count of entries = 6

Entry format (repeated 6 times):
  [1 byte]  version     Service version number
  [1 byte]  name_len    Length of service name
  [N bytes] name        Service name (ASCII, NOT null-terminated in wire)
  [1 byte]  0x00        Separator
  [1 byte]  url_len     Length of URL string
  [N bytes] url         Service URL (ASCII)
```

### 23.5 Request Serialization (FUN_10093010, line 123012)

The central request builder:
```c
FUN_10093010(output_buffer, service_name, connection_info, request_arg, response_buffer, flags)
```

1. Initializes a 0xf0-byte (240 bytes) request structure
2. Increments global request counter (`DAT_1031497c`)
3. Calls `FUN_101b41b0` to look up the serializer for the service+arg combination
4. Serializer converts the request arg object into igo-binary bytes
5. Request is queued via `FUN_10091bf0`

### 23.6 Request/Response Content Types

| Direction | Content-Type |
|-----------|-------------|
| Request (market calls) | `application/x-binary` |
| Response (from server) | `application/vnd.igo-binary; v=1` |
| Request (boot v3) | `application/json` (empty `{}`) |
| Request (boot v2) | none (GET request) |
