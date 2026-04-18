# Dacia MediaNav Evolution Toolbox — Reverse Engineering Notes

> NNGE Algorithm: [reverse_engineer_nnge.md](reverse_engineer_nnge.md) — Secret₃ derivation from device.nng

## Data Sources

| Source | Location | Description |
|--------|----------|-------------|
| Toolbox installer | `analysis/extracted/` | Extracted NSIS installer (nngine.dll, plugin.dll, exe) |
| Ghidra decompile | `analysis/nngine_decompiled.c` | 13,381 functions from nngine.dll |
| USB drive image | `analysis/usb_drive/disk/` | NaviSync data from head unit |
| Windows AppData | `analysis/DaciaAutomotive_extracted/` | `%APPDATA%/DaciaAutomotive` cache |
| HTTP dump (encrypted) | `analysis/DaciaAutomotive_extracted/DaciaAutomotive/http_dump/` | Blowfish-encrypted XML of every API call |
| HTTP dump (decrypted) | `analysis/http_dump_decrypted/` | Decrypted XML from session 69BAC5EC |
| mitmproxy flows | `analysis/flows/flows` (75 flows), `analysis/flows/flows-complete` (611 flows), `analysis/flows/flows16-04-2026` (892 flows) | Live wire captures |
| mitmproxy decoded | `analysis/flows_decoded/`, `analysis/flows_decoded/2026-04-16/` | Raw request/response binaries |
| Fingerprints | `analysis/DaciaAutomotive_extracted/DaciaAutomotive/tmp/fingerprints/` | device.nng, fingerprint.xml, licenses |
| Toolbox logs | `analysis/DaciaAutomotive_extracted/DaciaAutomotive/log/` | Encrypted .tblog files |

---

## 1. Application Architecture

The Toolbox is a CEF (Chromium Embedded Framework) app:

- `DaciaMediaNavEvolutionToolbox.exe` — thin CEF shell, loads plugin.dll
- `plugin.dll` — brand configuration, registry access (`SOFTWARE\DaciaAutomotive\Toolbox4`)
- `nngine.dll` — all business logic (13,381 functions), protocol handling, device management

### Brand Configuration (from plugin.dll)

| Key | Value |
|-----|-------|
| Brand | `DaciaAutomotive` |
| Model filter | `Dacia_ULC` |
| Registry | `SOFTWARE\DaciaAutomotive\Toolbox4` |
| License file | `DaciaAutomotive_ToolboxAgent_win.lyc` |
| Mutex | `Renault-Dacia.Agent.Mutex` |
| Product name | `Dacia Media Nav Evolution Toolbox` |

---

## 2. Wire Protocol

### Overview

The Toolbox communicates with naviextras servers using a **custom binary protocol** with XML semantics. The protocol has three layers:

1. **ProtocolEnvelopeRO** — binary header (16 bytes)
2. **SnakeOil encryption** — custom cipher on the payload
3. **igo-binary serialized XML** — the actual request/response data

### Binary Header Format

```
Byte 0:      0x01 (protocol version)
Bytes 1-2:   0xC2 0xC2 (envelope marker)
Byte 3:      Sub-type: 0x20 = unauthenticated, 0x30 = authenticated
Bytes 4-11:  SnakeOil key (8 bytes, big-endian uint64)
Byte 12:     Service minor version (0x01=index, 0x0E=register, 0x19=market)
Bytes 13-14: 0x00 0x00 (reserved)
Byte 15:     Session nonce — random per-session byte, constant within a session
             (e.g. 0x3F, 0x67, 0x11 observed across different sessions)
Byte 16+:    Encrypted payload starts here (2B query at 16, 17B ext_query at 18, body at 35)
```

**CRITICAL: No Content-Type header.** Wire protocol requests must NOT include a
`Content-Type` HTTP header. The server returns HTTP 500 if `Content-Type` is present.
The real Toolbox sends only `Content-Length`, `Host`, and `User-Agent` headers.
The `User-Agent` format is `DaciaAutomotive-Toolbox-{version}` (e.g. `DaciaAutomotive-Toolbox-2026041167`).

**Market URL:** Market calls (login, getprocess, sendfingerprint, etc.) go to
`https://dacia-ulc.naviextras.com/rest/1/{endpoint}`, NOT to the index URL from boot.
The brand-specific market URL is discovered via a second index v3 call with device
credentials, or stored locally from a previous session.

Response header (4 bytes):
```
Byte 0:    0x01 (protocol version)
Byte 1:    0x00 (response flag)
Byte 2:    0xC2 (envelope marker)
Byte 3:    Mode byte: 0x6B = RANDOM, 0xBC = DEVICE
Byte 4+:   Encrypted payload
```

### SnakeOil Encryption (FULLY REVERSED)

**Algorithm**: xorshift128 PRNG stream cipher (`FUN_101b3e10` at 0x101b3e30).

```python
M = 0xFFFFFFFF
def snakeoil(data, key_lo, key_hi):
    result = bytearray(len(data))
    eax, esi = key_lo, key_hi
    for i in range(len(data)):
        edx = (((esi << 21) | (eax >> 11)) ^ esi) & M
        ecx = (((eax << 21) & M) ^ eax) & M
        ecx = (ecx ^ (edx >> 3)) & M
        esi = ((((edx << 4) | (ecx >> 28)) & M) ^ edx) & M
        eax = (((ecx << 4) & M) ^ ecx) & M
        result[i] = data[i] ^ (((esi << 32) | eax) >> 23) & 0xFF
    return bytes(result)
```

**Key split**: uint64 → `key_lo = key & 0xFFFFFFFF`, `key_hi = key >> 32`

**Two modes:**
- **RANDOM** (0x20): PRNG seed = key in wire header (random per request). Same seed for request and response.
- **DEVICE** (0x30): wire header has Code. Response PRNG seed = **Secret**.

**Split query/body encryption (BREAKTHROUGH — R.6 SOLVED):**

Request payloads are split into **query** and **body**, each encrypted as a **separate SnakeOil stream** (independent PRNG state):

```
Wire layout:
  Offset  0-15:  [16B header]                          — cleartext
  Offset 16-17:  [SnakeOil(2B query, Code)]            — counter(1) + flags(1)
  Offset 18-34:  [SnakeOil(17B extended_query, Secret)] — credential block or envelope data
  Offset 35+:    [SnakeOil(body, Secret)]               — igo-binary request payload
```

**Key assignment (DEVICE mode, sub-type 0x30):**

| Field | Offset | Size | SnakeOil key | Contents |
|-------|--------|------|-------------|----------|
| Header | 0-15 | 16B | (cleartext) | version, marker, sub-type, Code(BE), service minor, nonce |
| Query | 16-17 | 2B | **Code** | counter(1) + flags(1) |
| Extended query | 18-34 | 17B | **Secret** | credential block (0xD8 + credential name XOR IGO_CREDENTIAL_KEY) |
| Body | 35+ | variable | **Secret** | igo-binary tagged request payload |

**The body key is always Secret (tb_secret).** It does not change after delegation. The delegation only changes the query flags byte (0x60 → 0x68) to indicate a delegated credential is in use. All pre- and post-delegation flows use the same Secret for body encryption.

**Query flags byte values:**
| Flags | Meaning |
|-------|---------|
| 0x20 | Unauthenticated (no JSESSIONID) |
| 0x28 | Unauthenticated, delegated |
| 0x60 | Authenticated (has JSESSIONID) |
| 0x68 | Authenticated, delegated |

The body uses the **same igo-binary tagged format** as responses:
- `0x80` = message envelope
- Length-prefixed strings: `[len:1][string_bytes:len]`
- Integers: `[0x01][LE32]` (int32), `[0x04][LE64]` (int64)
- Arrays: `[count:1]` followed by count elements

**Response**: payload at bytes 4+ encrypted as a single stream with Secret as PRNG seed.

**Response header byte 3**: `0x6B` = RANDOM mode, `0xBC` = DEVICE mode

**Verified decryptions (all 13 captured requests + responses from 2026-04-16 session):**
- All 0x20 flows (login, hasActivatable, sendfingerprint) ✓
- All 0x60 flows (senddevicestatus pre-delegation) ✓
- All 0x68 flows (senddevicestatus, licenses, sendfingerprint post-delegation) ✓
- All 0x28 flows (senddevicestatus unauthenticated delegated) ✓
- All responses → igo-binary tagged format ✓

### XML Semantics (from decrypted http_dump)

Each request has this XML structure:
```xml
<ProtocolEnvelopeRO>
  <Type>BINARY</Type>
  <Version>1</Version>
  <Response>false</Response>
  <SnakeOil>
    <Crypt>RANDOM|DEVICE</Crypt>
    <Key>{numeric_key}</Key>
    <Secret>{secret}</Secret>  <!-- only in DEVICE mode -->
  </SnakeOil>
  <ServiceMinor>{version}</ServiceMinor>
  <RequestId>{id}</RequestId>
</ProtocolEnvelopeRO>
<RequestEnvelopeRO>
  <Credentials>  <!-- only in authenticated requests -->
    <Name>{credential_name}</Name>
    <Code>{credential_code}</Code>
  </Credentials>
</RequestEnvelopeRO>

<{OperationName}Arg>
  {request fields}
</{OperationName}Arg>
```

### HTTP Headers

```
User-Agent: DaciaAutomotive-Toolbox-{version}
Content-Length: {length}
Host: {host}
Cookie: JSESSIONID={session}  (after first response)
```

No `Content-Type` header is sent for the binary protocol. **The server returns HTTP 500 if Content-Type is included.** This was the key blocker for our implementation — adding `Content-Type: application/vnd.igo-binary; v=1` caused all wire protocol requests to fail.

---

## 3. API Endpoints & Flow

### Service URLs (from boot cache)

| Service | URL |
|---------|-----|
| index | `https://zippy.naviextras.com/services/index/rest/3` |
| register | `https://zippy.naviextras.com/services/register/rest/1` |
| market | `https://dacia-ulc.naviextras.com/rest/1` |
| selfie | `https://zippy.naviextras.com/services/selfie/rest/1` |
| store | `https://zippy.naviextras.com/services/store/rest/1` |

### Startup Flow (from mitmproxy capture)

```
1. POST /selfie/rest/1/update          (JSON, plaintext version check)
2. POST /index/rest/3/boot             (get service URLs)
3. POST /register/rest/1/device        (register device → get Credentials)
4. POST /register/rest/1/hasActivatableService
5. POST /index/rest/3                  (get full service catalog)
6. POST /rest/1/login                  (market login)
7. POST /register/rest/1/get_device_descriptor_list
8. POST /rest/1/sendfingerprint        (send device fingerprint, ~13KB)
9. POST /register/rest/1/get_device_model_list
```

### Full Session Lifecycle (from 2026-04-16 capture, 892 flows)

```
 1. POST /index/rest/3/boot             → service URLs (RANDOM mode)
 2. POST /register/rest/1/device        → Credentials: Name, Code, Secret (RANDOM mode)
 3. POST /rest/1/login                  → JSESSIONID cookie (DEVICE mode, Code/Secret)
 4. POST /rest/1/sendfingerprint        → 200 (DEVICE mode, ~46KB body)
 5. POST /rest/1/getprocess             → empty (no updates pending)
 6. POST /rest/1/senddevicestatus       → 200 (DEVICE mode, ~1.5KB, lists USB files)
 7. POST /rest/1/delegator              → second Credentials for head unit device
 8. POST /rest/1/senddevicestatus       → 200 (repeated with head unit creds)
 9. POST /rest/1/sendfilecontent        → 200 (sends device_status.ini to server)
10. POST /rest/1/senddevicestatus       → 200 (with updated file list)
11. GET  /toolbox/browser-entry         → 302 (links wire JSESSIONID to web session)
12. GET  /toolbox/device?workingMode=TOOLBOX → 302
13. GET  /toolbox/startlogin            → 200 (login form)
14. POST /toolbox/login                 → 302 (web login with email/password)
15. GET  /toolbox/selector              → 200 (main menu)
16. POST /rest/1/licenses               → 200 (3 .lyc files with SWIDs)
17. POST /rest/1/sendfingerprint        → 200 (second fingerprint, ~46KB)
18. GET  /toolbox/managecontentinitwithhierarchy/install → 200 (content tree HTML)
19. POST /rest/managecontent/supermarket/v1/updateselection → JSON (content sizes)
```

**Three credential sets are in play:**
1. **Toolbox credentials** — from `/register/rest/1/device`, used for login/fingerprint/getprocess
2. **Head unit credentials** — from `/rest/1/delegator`, used for senddevicestatus body credential block
3. **Unknown third set** — decoded from senddevicestatus body, origin unclear

### Selfie Update (plaintext JSON)

```json
// Request
{"version": 2026041167, "alias": "Dacia_ULC", "platform": "win32", "lang": "en"}
// Response
null
```

### Device Registration

Request:
```xml
<RegisterDeviceArg>
  <Device>
    <BrandName>DaciaAutomotive</BrandName>
    <ModelName>DaciaToolbox</ModelName>
    <Swid>CK-153G-PF9R-KB6D-W8B0</Swid>
    <Imei>x51x4Dx30x30x30x30x31</Imei>
    <IgoVersion>9.35.2.0</IgoVersion>
    <FirstUse>1970.01.01 00:00:00</FirstUse>
    <Appcid>1107298750</Appcid>
    <UniqId>BF7AE9C2D033892B19FB511A6F206AC9</UniqId>
  </Device>
</RegisterDeviceArg>
```

Response:
```xml
<RegisterDeviceRet>
  <Credentials>
    <Name>FB86ACD6EBA8F54A93C4286CE077D06C</Name>
    <Code>3745651132643726</Code>
    <Secret>3037636188661496</Secret>
  </Credentials>
  <LicenseInfo>
    <MaxAge>300</MaxAge>
  </LicenseInfo>
</RegisterDeviceRet>
```

After registration, all subsequent requests use:
- `Code` in the wire header (bytes 4-11) AND as the SnakeOil PRNG seed for request encryption
- `Secret` as the SnakeOil PRNG seed for response decryption
- `Name` encoded as a 17-byte credential block in the request payload

---

## 4. SWID (Software ID)

### Format

`CK-XXXX-XXXX-XXXX-XXXX` — 4 groups of 4 uppercase alphanumeric characters.

Example: `CK-153G-PF9R-KB6D-W8B0`

### Computation

The SWID identifies the **PC running the Toolbox**, not the head unit. Derived from the PC's drive serial:

1. `FUN_100bd450` gets drive identifier:
   - **Primary**: `DeviceIoControl(\\.\PhysicalDrive0, IOCTL_STORAGE_QUERY_PROPERTY)` → physical drive serial as hex
   - **Fallback**: `GetVolumeInformationW("C:\\")` → volume serial as `sprintf("%u", serial)`
2. `FUN_100bd380` wraps in `"SPEEDx%sCAM"` salt, computes MD5 → 16 bytes
3. `FUN_1009c960` formats as `CK-XXXX-XXXX-XXXX-XXXX` — **SOLVED**: Crockford base32 encoding of first 10 MD5 bytes (80 bits → 16 chars at 5 bits each). Alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ`. Implemented in `swid.py`.

### Storage

In `service_register_v1.sav`, SWIDs are stored **base32-encoded** with `CW`/`CP` prefix:
- `CW-UQAQ-YAEQ-37QI-AA7A-QYQM` (5 groups of 4 chars, base32 of 12 bytes)
- These decode to `CK{uint32}-{uint32}-{uint32}` format for server communication

---

## 5. Device Recognition

### device.nng

Located at `NaviSync/license/device.nng` on the USB drive. Contains device identity encrypted with NNGE format.

```
Offset 0x00-0x0F: NNG header
Offset 0x10-0x2F: Device metadata
Offset 0x30-0x3F: Timestamp data (LE16: 0x0312=786, 0x07EA=2026)
Offset 0x40-0x4F: Encrypted data block (16 bytes)
Offset 0x50-0x53: "NNGE" signature
Offset 0x54-0x57: Version 0x20070619
Offset 0x58-0x5B: Nonce 0x65FAB84A
Offset 0x5C-0x5F: APPCID 0x42000B53 (1107299155)
Offset 0x60-0x63: Checksum 0xC44D75AC
Offset 0x82-0xB1: Extended encrypted data (48 bytes)
```

### NNGE Encryption Keys (from DLL)

- Key string: `m0$7j0n4(0n73n71I)` (18 bytes at 0x102c11e4)
- Template: `ZXXXXXXXXXXXXXXXXXXZ` (at 0x102c11f8)

### Model Matching

The Toolbox matches device.nng against the model list using:
1. **APPCID** — application content ID from NNGE header
2. **SKU IDs** — factory SKU (`factorySku: 2020970` from synctool)
3. **Brand MD5** — MD5 of `brand.txt` content

Brand MD5 values:
| Brand | MD5 |
|-------|-----|
| DaciaAutomotive | `1668ef160ef1fe7d41dc499bd65c1bde` |
| LADA | `a362aa826cb7ed9facd3f0b0e9548d10` |
| EV_Dacia | `e52acd6fd72c259a7450c476da35c477` |

---

## 6. Device Model List

Retrieved from `/register/rest/1/get_device_model_list`. Version: `3.857`.

Each model entry contains: Id, Name, DisplayName, BrandName, AgentBrands, Applications (with Appcid), Drives (with Checks), Connections, Paths.

### Dacia Models (from cached data)

| Server ID | Internal Name | Display Name |
|-----------|--------------|--------------|
| 100661 | DaciaAutomotiveDeviceCY17_ULC4 | Media Nav Evolution late 2018 |
| — | DaciaAutomotiveDeviceCY20_ULC4dot1 | Media Nav Evolution late 2018 |
| — | **DaciaAutomotiveDeviceCY20_ULC4dot5** | **Media Nav Evolution late 2018** |
| — | DaciaAutomotiveDevice | Media Nav |
| — | DaciaAutomotiveDeviceCY13 | Media Nav |
| — | DaciaAutomotiveDeviceCY14 | Media Nav |
| — | DaciaAutomotiveDeviceCY15 | Media Nav |
| — | DaciaAutomotiveDeviceCY16 | Media Nav |
| — | DaciaAutomotiveDeviceCY17 | Media Nav |
| — | DaciaAutomotiveDeviceCY21_ULC4dot1 | Media Nav Evolution late 2018 |
| — | DaciaAutomotiveDeviceCY21_ULC4dot5 | Media Nav Evolution late 2018 |
| — | DaciaAutomotiveDeviceCY22_ULC4dot5 | Media Nav Evolution late 2018 |
| — | DaciaAutomotiveDeviceCY23_ULC4dot5 | Media Nav Evolution late 2018 |
| — | EV_Dacia_EEU | Electric Dacia Vehicle |
| — | EV_Dacia_WEU | Electric Dacia Vehicle |
| — | EV_Dacia_NBI | Electric Dacia Vehicle |

Our device: **DaciaAutomotiveDeviceCY20_ULC4dot5** (APPCID 0x42000B53)

### Model Matching Checks

Each model specifies drive checks:
```xml
<Checks>
  <Method>MD5CHECK</Method>
  <Parameters>/NaviSync/CONTENT/brand.txt</Parameters>
  <Parameters>1668ef160ef1fe7d41dc499bd65c1bde</Parameters>
</Checks>
<Checks>
  <Method>DEVICENNG</Method>
  <Parameters>/NaviSync/license/device.nng</Parameters>
</Checks>
```

---

## 7. Encryption & Keys

### Blowfish (http_dump encryption)

- **Key**: `b0caba3df8a23194f2a22f59cd0b39ab` (16 bytes)
- **Mode**: ECB
- **Location in DLL**: `DAT_102af9e8`
- **Usage**: Encrypts the http_dump XML files stored in `%APPDATA%/DaciaAutomotive/http_dump/`

Decrypt with:
```python
from Crypto.Cipher import Blowfish
key = bytes.fromhex('b0caba3df8a23194f2a22f59cd0b39ab')
cipher = Blowfish.new(key, Blowfish.MODE_ECB)
plaintext = cipher.decrypt(open('file.xml.enc', 'rb').read())
```

### SnakeOil (wire protocol encryption)

See Section 2 for the full algorithm. xorshift128 PRNG stream cipher, fully reversed.

- Pre-registration (`RANDOM`): PRNG seed = random key in wire header (same for request and response)
- Post-registration (`DEVICE`): wire header has Code. Request seed = **Code**, response seed = **Secret**
- Encrypt function: `FUN_101b3e10` (line 382511)
- Decrypt function: `FUN_101b3e80` (line 382540)

### NNGE (device.nng encryption)

- Key: `m0$7j0n4(0n73n71I)` with template `ZXXXXXXXXXXXXXXXXXXZ`
- Custom algorithm in decoder plugin chain

### MD5 Usage

- `FUN_10157d40` — standard MD5 with optional salt via param_4
- SWID computation: MD5 of `"SPEEDx{drive_serial}CAM"`
- Brand verification: MD5 of `brand.txt` content
- Fingerprint: MD5 of `"toolbox_{brand}"` as UTF-16LE → hex string

---

## 8. USB Drive Structure

```
NaviSync/
├── content/
│   └── brand.txt              ("dacia")
├── license/
│   ├── device.nng             (device identity, NNGE encrypted)
│   ├── *.lyc                  (license files)
│   ├── *.lyc.md5              (license checksums)
│   └── *.lyc.stm              (license timestamps)
├── save/                      (device state backups)
│   ├── driving_log_*.dat
│   ├── route_*.dat
│   ├── fm_cache.txt
│   └── ...
└── CONTENT/
    └── brand.txt              (uppercase path variant)
```

---

## 9. Windows AppData Structure

```
%APPDATA%/DaciaAutomotive/
├── browser_cache/             (CEF browser cache)
├── cache/
│   ├── license_info/cached_license_info
│   ├── preloads/              (zip directory caches)
│   └── stored_bingo_cacheable/
│       ├── service_boot_v3    (igo-binary, service URLs)
│       └── service_catalog_v3 (igo-binary, full service catalog)
├── download_cache/            (downloaded update files)
│   ├── {id}/Lang_*.zip
│   ├── {id}/*.tgz
│   └── {id}/*.zip.md5
├── http_dump/                 (Blowfish-encrypted XML of every API call)
│   └── {session_id}/xml/
│       ├── {seq}-{service}-{Operation}Arg.xml.enc
│       └── {seq}-{service}-{Operation}Ret.xml.enc
├── log/                       (encrypted .tblog files)
├── save/
│   ├── service_register_v1.sav   (SWIDs, credentials)
│   ├── service_device_info_v1.sav (model list cache)
│   ├── dlm_files_v2.sav
│   └── url_address_file.sav
└── tmp/
    └── fingerprints/{id}/
        ├── device.nng
        ├── fingerprint.xml
        └── license/           (copied license files)
```

---

## 14. Delegator Endpoint — SOLVED

The `/register/rest/1/delegator` endpoint returns a **second set of credentials** for the head unit device (distinct from the toolbox registration credentials).

**Endpoint**: `POST {register_url}/delegator` (service minor `0x0E`, DEVICE mode)

**Request body** (155 bytes, identical format to register but header `0x1E`):
```
[0x1E 0x00]                     header (presence bitmask — differs from register's 0x1D)
[len] "DaciaAutomotive"          BrandName
[len] "DaciaAutomotiveDeviceCY20_ULC4dot5"  ModelName
[len] "CK-A80R-YEC3-MYXL-18LN"  SWID (head unit's SWID)
[len] "3248315842373133..."      IMEI
[len] "9.12.179.821558"          IGO Version (head unit firmware)
[int64] 0                        Timestamp
[int32] 0x42000B53               AppCID
[len] "UU1DJF00869579646"        Serial (VIN — present in delegator, absent in register)
```

**Key difference from register**: Header `0x1E` vs `0x1D`. Delegator has `serial` field; register has `uniq_id` field. The header byte is a presence bitmask encoding which fields are included.

**Query**: `[counter] [0x20] [17B credential_block]` — uses toolbox credentials (DEVICE mode).

**Response** (175 bytes): Parsed with `parse_register_response()`.
```
Name:   C10CD1FD4A2F23F921D6E3B093D5957A
Code:   3362879562238844
Secret: 4196269328295954
MaxAge: 300
SWIDs:  CW-UQAQ-YAEQ-37QI-AA7A-QYQM, CP-3IE3-EEMQ-MQAA-I7U3-E7M7,
        CW-YUEM-E7QU-UEA3-UUMM-UYY7, CW-AUM3-777Q-3IQM-ME7Y-QQ7M
```

**Implementation**: `get_delegator_credentials()` in `api/register.py`. Verified against live API.

---

## 15. SendDeviceStatus

The `/rest/1/senddevicestatus` endpoint tells the server what files are on the USB drive. The server uses this to determine what updates are available and what files to request.

### Request Body Structure (from flow 735, flags=0x60)

```
[credential_block: 17B]     — 0xD8 + (head_unit_Name XOR IGO_CREDENTIAL_KEY)
[0x40]                      — marker
[len] brand_name             "DaciaAutomotive"
[len] model_name             "DaciaAutomotiveDeviceCY20_ULC4dot5"
[len] swid                   "CK-A80R-YEC3-MYXL-18LN"
[len] imei                   "32483158423731362D42323938353431"
[len] igo_version            "9.12.179.821558"
[int64] timestamp_ms         epoch milliseconds
[int32] appcid               0x42000B53
[len] serial                 "UU1DJF00869579646"
[len] uniq_id                "9DF60F15136D64AC7E234644DD228027"
[0x00] separator
[int32] content_version      0x018BB5 = 101301
[int32] flags                1
[int32] zero                 0
[file_entries...]
```

### File Entry Types

**0xa0 — File entry** (single MD5):
```
[0xa0] [len] md5 [len] filename [len] mount [len] path [int64] size [int64] ts1 [int64] ts2
```

**0xe0 — File entry** (two MD5s, content + file):
```
[0xe0] [len] md5_content [0x0a] [0xa0] [len] md5_file [len] filename [len] mount [len] path [int64] size [int64] ts1 [int64] ts2
```

**0x22 — Directory entry**:
```
[0x22] [len] name [len] mount [len] path [int64:0] [int64] ts1 [int64] ts2
```

### Response

Returns process ID, task ID, and a list of file paths the server wants:
```
primary/*.nng
primary/R-LINK
primary/NaviSync/device_status.ini
primary/emptycard.emptycard
primary/NaviSync/content
primary/NaviSync/license
primary/NaviSync
```

### Query Flags

- `0x60` — body encrypted with Secret (standard). Only flow 735 uses this.
- `0x68` — body encrypted with unknown key (possibly delegator Secret). Flows 737/741/754/792 use this. The `0x08` bit may indicate delegator credentials for body encryption.

### Status

- Body format decoded: device info matches captured byte-for-byte ✓
- Encoder built: `build_senddevicestatus_body()` in `wire_codec.py` ✓
- **Captured body replay returns 200** — server accepts the full captured body
- **Generated body returns 409** — file entries differ from expected (R.10)
- **Two calls required**: flow 735 (flags=0x60) + flow 737 (flags=0x68) needed for web content
- The `0xD8` header byte is a **presence bitmask**, NOT a credential block marker
- Workaround: replay captured wire bytes for both calls

### Presence Bitmask Headers

The first bytes of request bodies encode which fields are present:
```
0x1D 0x00 = RegisterDevice    (brand, model, swid, imei, igo_ver, ts, appcid, [0x00], uniq_id)
0x1E 0x00 = Delegator         (brand, model, swid, imei, igo_ver, ts, appcid, serial)
0xD8 0x02 0x1F 0x40 = SendDeviceStatus (all fields + file entries)
```

---

## 16. SendFingerprint Body Structure

The `/rest/1/sendfingerprint` body lists files in the PC's download cache.

### Structure (verified byte-for-byte)

```
[int32] DeviceContextId      0 (always)
[0xC0]  flags                Partial=false, Synctool=false
[len]   checksum             "N/A"
[varint] file_entry_count    e.g. 114 (old capture) or 471 (new capture)
[entries...]                 0x22=directory, 0x28=file
[0x01 0x00] storage          count=1, readonly=false
[len] path [int64] total [int64] free [int64] minfree
[int32] blocksize [len] mountpath
[len] info_string            e.g. "1776158679_0"
```

### Varint Encoding

File count uses a varint: if high bit set, next byte continues.
- `0x72` = 114 (single byte)
- `0x83 0x57` = (0x03 << 7) | 0x57 = 471 (two bytes)

### Query

Must include credential block: `[counter] [0x20] [17B credential_block]`.
The old code used `[0x53] [0x60]` (no cred block) which returned 409.

---

## 17. Web Login Flow

The wire protocol JSESSIONID authenticates `/rest/` API calls, but `/toolbox/` web pages require a separate web login.

### Flow

```
1. Wire protocol login → JSESSIONID (for /rest/ endpoints)
2. GET /toolbox/device?workingMode=TOOLBOX (with JSESSIONID cookie)
3. POST /toolbox/login (form POST with email + password)
   → 302 redirect to /toolbox/checkuserstatements/selector
4. GET /toolbox/selector → 200 (main menu, web session authenticated)
```

### Form POST

```
POST /toolbox/login
Content-Type: application/x-www-form-urlencoded

posted=true
&marketSession.userLoginForm.email={email}
&marketSession.userLoginForm.password={password}
```

### Limitation

The web session shows "norightsfordevice" until `senddevicestatus` has been called with the correct head unit credentials. Without this, `/toolbox/cataloglist` and `/toolbox/managecontentinitwithhierarchy/install` return empty content.

---

## 18. Catalog and Content Management

### Web Endpoints (require authenticated web session + senddevicestatus)

| Endpoint | Method | Returns |
|----------|--------|---------|
| `/toolbox/cataloglist` | GET | HTML table of all available content (package codes, names, releases) |
| `/toolbox/managecontentinitwithhierarchy/install` | GET | HTML jstree of installable content with IDs and sizes |
| `/rest/managecontent/supermarket/v1/updateselection` | POST | JSON with content sizes and space indicator |
| `/toolbox/managecontentconfirmselection` | GET | Triggers install process |

### Catalog List HTML Structure

```html
<tr id="row{package_code}" class="content-osm|content-other" onclick="rowClick({code})">
  <td class="searchablePackage">
    <span class="provider-tag">NNG Maps</span>
    <a class="linknoeffect withprogress">{content_name}</a>
  </td>
  <td class="searchableRelease">{release_version}</td>
</tr>
```

### Content Tree HTML Structure (jstree)

```html
<li id="{package_code}#{content_id}" data-jstree='{"selected": true}'>
  <span name="content_name" snapshotcode="{snapshot_code}">
    <span class="provider-tag">NNG Maps</span>
    {content_name}
  </span>
  <span name="content_release">{version}</span>
  <span name="content_size">{size_mb}</span>
</li>
```

### Update Selection JSON

```json
{
  "contentSize": [
    {"id": "1182615#1008", "size": 749710097},
    {"id": "1182615#1177715", "size": 305868547}
  ],
  "spaceIndicator": {"fullSize": 4257076970, "required": 3523737322}
}
```

### Install Flow

1. User selects content in jstree → `POST /rest/managecontent/supermarket/v1/updateselection`
2. User clicks CONFIRM → `GET /toolbox/managecontentconfirmselection`
3. Native engine (nngine.dll) handles actual download via wire protocol
4. Browser polls `/event/` for PROGRESS events

---

## 19. Licenses

The `/rest/1/licenses` endpoint returns purchased content licenses.

### Response (3729 bytes decoded)

Contains 3 license entries, each with:
- **SWID**: `CW-AUM3-777Q-3IQM-ME7Y-QQ7M`, `CW-YUEM-E7QU-UEA3-UUMM-UYY7`, `CW-UQAQ-YAEQ-37QI-AA7A-QYQM`
- **.lyc file**: `LGe_Renault_ULC_OSM_UK_IL_Update_2025_Q3.lyc`, `Renault_Dacia_ULC2_Language_Update.lyc`, `Renault_Dacia_Global_Config_update.lyc`
- Binary license data (encryption keys, expiry, etc.)

---

## 20. Complete Working Session Flow

The full flow to get from cold start to browsing available content updates:

```
┌─────────────────────────────────────────────────────────────────┐
│                    WIRE PROTOCOL (binary)                        │
│                                                                 │
│  1. POST /index/rest/3/boot          → service URLs (RANDOM)    │
│  2. POST /register/rest/1/device     → Toolbox creds (RANDOM)   │
│  3. POST /rest/1/login               → JSESSIONID (DEVICE)      │
│  4. POST /rest/1/sendfingerprint     → 200 (DEVICE)             │
│  5. POST /rest/1/getprocess          → 200 (DEVICE)             │
│  6. POST /register/rest/1/delegator  → Head unit creds (DEVICE) │
│  7. POST /rest/1/senddevicestatus    → 200 (flags=0x60)         │
│  8. POST /rest/1/senddevicestatus    → 200 (flags=0x68)         │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    WEB SESSION (HTTP)                            │
│                                                                 │
│  9. GET  /toolbox/device?workingMode=TOOLBOX  (with JSESSIONID) │
│ 10. POST /toolbox/login              → 302 (email + password)   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│                    CONTENT BROWSING (HTTP)                       │
│                                                                 │
│ 11. GET  /toolbox/managecontentinitwithhierarchy/install         │
│     → HTML jstree with 31 content IDs                           │
│ 12. POST /rest/managecontent/supermarket/v1/updateselection      │
│     → JSON with content sizes and space indicator                │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Credential flow:**
```
Registration (step 2)  → Toolbox creds (Name₁, Code₁, Secret₁)
                          Used for: login, fingerprint, getprocess, delegator
                          Wire header key = Code₁
                          Response decryption = Secret₁

Delegator (step 6)     → Head unit creds (Name₂, Code₂, Secret₂)
                          Used for: senddevicestatus body (flags=0x68)
                          The 0x68 flag encryption is NOT yet reversed

Web login (step 10)    → Same JSESSIONID, now authenticated for /toolbox/ pages
```

**Key discovery**: Steps 7 AND 8 are both required. Step 7 alone returns 200 but the web session still shows "norightsfordevice". Step 8 (flags=0x68, raw replay) is what actually grants content access.

**Implementation**: `run_session()` in `session.py` performs steps 1-10. The CLI `catalog` command then performs steps 11-12.

---

## 21. Content Installation — USB Layout

### .stm Shadow Files

Every content file on the USB has a corresponding `.stm` metadata file. The head unit's synctool reads these to determine what's installed.

```ini
purpose = shadow
size = 109490688
content_id = 7341211
header_id = 117863961
timestamp = 1580666002
md5 = EAC5E8CCCC4A28792251535B55A7B182
```

- `size`: file size in bytes
- `content_id`: server content ID (matches catalog)
- `header_id`: package header ID
- `timestamp`: Unix epoch seconds of last update
- `md5`: MD5 hex of the content file (present for `.zip` files, absent for `.fbl`)

### Content Directories

```
NaviSync/content/
├── map/           *.fbl + *.fbl.stm     (map data — largest files)
├── poi/           *.poi + *.poi.stm     (points of interest)
├── speedcam/      *.spc + *.spc.stm     (speed cameras)
├── tmc/           *.tmc + *.tmc.stm     (traffic message channel)
├── lang/          *.zip + *.zip.stm     (language packs)
├── voice/         *.zip + *.zip.stm     (voice guidance)
├── global_cfg/    *.zip + *.zip.stm     (global config)
└── userdata/POI/  *.zip + *.zip.stm     (dealer POIs)
```

### License Files

```
NaviSync/license/
├── device.nng                           (device identity, NNGE encrypted)
├── {name}.lyc                           (license file from server)
└── {name}.lyc.md5                       (MD5 hex of .lyc file)
```

### Update Trigger

The synctool checks for `update_checksum.md5` in the USB root on insertion:
- **Present**: synctool processes the update (copies content to internal storage)
- **After processing**: synctool **deletes** `update_checksum.md5`
- **Content**: MD5 of all `.stm` files concatenated (sorted alphabetically)

### Install Process

```
1. Download content files from NaviExtras CDN to local cache
2. Copy content files to NaviSync/content/{type}/
3. Write .stm shadow files with metadata
4. Update .lyc license files in NaviSync/license/
5. Write update_checksum.md5 to USB root
6. Insert USB into head unit → synctool reads and applies update
```

**Implementation**: `installer.py` — `install_content()`, `install_license()`, `write_update_checksum()`

---

## 10. Open Questions

1. ~~**DEVICE mode request encryption**~~ — **SOLVED**: Request seed = Code, response seed = Secret.

2. **NNGE decryption** — the device.nng encryption using key `m0$7j0n4(0n73n71I)`.

3. ~~**igo-binary response format**~~ — **SOLVED**: Type-tagged format. Parser implemented.

4. ~~**igo-binary request body encoding**~~ — **SOLVED**: Split query/body encryption. Implemented in `wire_codec.py`.

5. **Credential block XOR key universality** — Unknown whether the XOR key is the same for all devices.

6. ~~**Delegator endpoint**~~ — **SOLVED**: `get_delegator_credentials()` calls `/register/rest/1/delegator`. Body format identical to register but header `0x1E` and serial field. Returns head unit Name/Code/Secret.

7. **senddevicestatus query flags 0x68** — **Name₃ CRACKED, Secret₃ unknown**
  - `0x68` = `0x20 | 0x40 | 0x08` — query has 19-byte cred block
  - The cred block contains **Name₃**: `C4000BF28569BACB7C000D4EA65D36B9`
  - **Name₃ derivation**: `0xC4` + `hu_code` (8 bytes BE) + `toolbox_code` (first 7 bytes BE)
  - Three credential sets in play:
    1. **Toolbox** (Name₁ `FB86ACD6...`): `/register/rest/1/device` with toolbox SWID
    2. **Delegator** (Name₂ `C10CD1FD...`): `/register/rest/1/delegator`
    3. **Constructed** (Name₃ `C4000BF2...`): built at runtime from Code₁ and Code₂
  - Name₃ is NOT from a separate registration — all RegisterDevice calls in http_dump are delegator calls (verified by Blowfish-decrypting the `.xml.enc` files)
  - NOT stored anywhere on disk — `service_register_v1.sav` has 2 entries, `reg.sav` has delegator creds
  - **Secret₃ (body encryption key) remains unknown**
  - Exhaustively tested: all 4 known keys, all uint32 half combos (320), byte rotations, XOR/ADD/SUB, z3 with 500 solutions from fingerprint known-plaintext
  - **Critical finding**: the 0x08 flag changes BOTH the encryption key AND the body format
    - 0x60 body starts with `D8 02 1F 40 0F DaciaAutomotive...` (device status)
    - 0x08 body does NOT start with `D8 02 1F 40` (z3 UNSAT with 10 constraint bytes)
    - 0x08 body format is unknown — possibly just file entries without device header
    - 0x28 response contains file paths (primary/*.nng, NaviSync/license, etc.)
    - 0x68 response is minimal (just process/task IDs)
  - **0x28 and 0x68 use DIFFERENT encryption keys** (confirmed by XOR analysis):
    - All 0x68 flows: enc[0:4] = `31DC598E` (same key, same plaintext prefix)
    - All 0x28 flows: enc[0:4] = `3F71B944` (same key, same plaintext prefix)
    - XOR between any 0x28 and 0x68 flow = constant `0EADE0CA50B57915...` = PRNG difference
    - All 0x08 bodies (both 0x28 and 0x68) share the same first 4 plaintext bytes regardless of endpoint (licinfo, senddevicestatus, sendfingerprint, etc.)
  - Two separate object instances handle 0x60 vs 0x28/0x68 paths
  - Credential provider at vtable `PTR_FUN_102baf34` method `+0x18` = `FUN_1019ec40` (RVA 0x19EC40)
  - Provider copies credential data from base object at `this - 0x9C`

### R.9 Investigation Log

**Attempts to find Secret₃ (body encryption key):**

1. **Known key tests**: tried all 4 keys (tb_code, tb_secret, hu_code, hu_secret) — none decrypt 0x08 bodies
2. **Key combinations**: XOR, ADD, SUB of all key pairs — no match
3. **uint32 half combos**: all 8×8×5=320 combinations of lo/hi halves with XOR/ADD — no match
4. **Byte rotations**: all 7 rotations of each key — no match
5. **Concat patterns**: first N bytes of one key + first M bytes of another (all splits) — no match
6. **Hash derivations**: MD5(Name₃), SnakeOil(Name₃, key) — no match
7. **z3 solver with D8 02 1F 40 header**: UNSAT with 10 constraint bytes — body does NOT start with this
8. **z3 with D8 02 XX YY variants**: D8 02 1F 08/28/48/68, D8 03/04 1F 40 — no Dacia in 100+ solutions each
9. **z3 with delegator body format** (1E 00 0F 44): UNSAT — body doesn't start with this either
10. **z3 with credential blocks** (Name₃, HU Name₂, TB Name₁): all UNSAT
11. **z3 with 00000000 header**: 200 solutions, none had readable content + Dacia
12. **z3 with "DaciaAutomotive" at offsets 0-9**: no match
13. **z3 with CK-A80R SWID**: no match
14. **Brute-force first byte (0x00-0xFF)**: 256 × 20 solutions cross-validated between flows — no confirmed match

**Attempts to load DLL in Wine:**

1. **Patched DllMain** (RVA 0x27F1EF) to `mov eax,1; ret 0Ch` — still hangs
2. **Patched TLS callbacks** (RVA 0x27F24C, 0x27F2DC) to NULL — still hangs
3. **Zeroed TLS directory** in PE header — still hangs
4. **Patched CRT DllMain** (RVA 0x27F0B9) — still hangs
5. **Created stub WINHTTP.dll** with 4 required exports — still hangs
6. **WINEDLLOVERRIDES=winhttp=n** — still hangs
7. **Conclusion**: Wine's PE loader hangs during CRT static initializer processing, not in DllMain

**Key structural findings from Ghidra:**

- `FUN_100b3a60` (protocol builder): both query and body encrypted with key from credential object `+0x1C/+0x20`
- `FUN_1019ec40` (credential getter): allocates 0xB0 bytes, copies from `this - 0x9C`
- `FUN_100b1670` (credential copier): copies 0x22 dwords from source `+0x10` to dest `+0x04`
- `FUN_100b0a80` (outer object constructor): sets up credential provider via `FUN_100b1670(param_3)`
- `FUN_100b10c0` (object factory): creates outer object with credential data from `param_1 + 0x84`
- `FUN_100b8220` (senddevicestatus builder): calls `FUN_10093010` with credential data from `iVar2 + 0x44`
- `FUN_10093010` (generic API builder): serializes body via `FUN_10091bf0`, stores in request object
- Two separate object instances handle 0x60 vs 0x28/0x68 paths — different credential data
  - **device.nng lead**: The HU descriptor's credential data at `+0x84` may come from `device.nng` (268B binary file from the HU), NOT from the delegator response. The device.nng contains "NNGE" marker and encrypted device identity data. This would explain why hu_secret (from delegator) doesn't work — the 0x08 body key is a DIFFERENT secret embedded in the device.nng file.
  - **Ghidra findings** (see §22 for annotated code):
    - Protocol builder at `FUN_100b3c80` (line 152100): builds wire envelope
    - Credential object at `local_c` / `iVar3`: obtained via virtual method `(**(param_1+0x1c))[0x18]()`
    - Key stored at credential object `+0x1c/+0x20` (Secret_lo/Secret_hi)
    - Both query and body encrypted with same key from `piVar11[0x10]`
    - Debug string at line 152354: `"name: %s\ncode: %lld\nsecret: %lld"`
  - **DLL patching**: DllMain (RVA 0x27F1EF), 2 TLS callbacks (RVA 0x27F24C/0x27F2DC), stub WINHTTP.dll — Wine still hangs (CRT static init)

---

## 22. Annotated Ghidra — Protocol Envelope Builder

### FUN_100b3c80 — Wire Protocol Envelope Builder (line 152100)

This function builds the encrypted wire protocol envelope for all API calls.
It selects the encryption key based on the credential mode (RANDOM vs DEVICE).

```
Source: nngine_decompiled.c lines 152100–152380
RVA: 0x000b3c80
```

#### Credential Object Structure (at iVar3 / local_c)

```
+0x00: vtable pointer
+0x08: Name pointer (-> 16-byte MD5 hex string)
+0x0C: Name length flag
+0x10: Code_lo  (uint32, little-endian)
+0x14: Code_hi  (uint32, little-endian)
+0x18: (padding or flags)
+0x1C: Secret_lo (uint32, little-endian)  ← ENCRYPTION KEY
+0x20: Secret_hi (uint32, little-endian)  ← ENCRYPTION KEY
```

#### Key Selection Logic (lines 152290–152320)

```c
// local_c = credential object, obtained from credential provider
iVar3 = (**(code **)(**(int **)(param_1 + 0x1c) + 0x18))();
local_c = iVar3;

// ...later...
if ((iVar3 == 0) || (piVar8[0xf] == 2)) {
    // RANDOM mode: generate time-based seed
    local_13c = 2;  // mode = RANDOM
    uVar13 = __time64(0);
    uVar13 = uVar13 << 0x15 ^ uVar13;           // xorshift step 1
    uVar9 = (uint)(uVar13 >> 0x20);
    uVar10 = (uint)uVar13 ^ uVar9 >> 3;          // xorshift step 2
    local_134 = CONCAT44(
        (uVar9 << 4 | uVar10 >> 0x1c) ^ uVar9,  // key_hi
        uVar10 << 4 ^ uVar10                      // key_lo
    );
    // Allocate 8-byte key buffer, store seed
    puVar6 = FUN_1027e4f5(8);
    *puVar6 = (uint)local_134;        // key_lo
    puVar6[1] = local_134._4_4_;      // key_hi
} else {
    // DEVICE mode: use credential object's Secret
    local_13c = 3;  // mode = DEVICE
    local_134 = *(undefined8 *)(iVar3 + 0x10);  // Code (for header)
    local_12c = *(undefined4 *)(iVar3 + 0x18);  // flags/padding
    puVar6 = FUN_1027e4f5(8);
    *puVar6 = *(uint *)(iVar3 + 0x1c);   // Secret_lo ← BODY KEY
    puVar6[1] = *(uint *)(iVar3 + 0x20); // Secret_hi ← BODY KEY
}

// Store key pointer in request object
param_3[0x10] = (int)puVar6;  // piVar11[0x10] = key pointer
```

#### Encryption (lines 152373–152375)

```c
// Encrypt query (piVar11[0xb] = query buffer, piVar11[0xd] = query length)
FUN_101b3e10(piVar11[0xb], piVar11[0xd], piVar11[0xb],
             *(uint *)piVar11[0x10], ((uint *)piVar11[0x10])[1]);

// Encrypt body (piVar11[1] = body buffer, piVar11[3] = body length)
FUN_101b3e10(piVar11[1], piVar11[3], piVar11[1],
             *(uint *)piVar11[0x10], ((uint *)piVar11[0x10])[1]);
```

**Assembly verification** (RVA 0x0B4143 and 0x0B4158):
Both calls use `[edi+0x40]` = `piVar11[0x10]` as the key pointer. Confirmed identical.

**Critical finding**: The key at `piVar11[0x10]` is `tb_secret` (NOT `tb_code`).
- The body decrypts with `tb_secret` ✓
- The query at `piVar11[0x0B]` likely has length 0 (first call is no-op)
- The wire query is encrypted with `tb_code` as part of the HEADER, not by this function
- The header is built separately and contains the tb_code-encrypted query

**Wire format** (from FUN_100b39e0, line 152004):
```
[1B marker] [header from +0x18, len=+0x20] [query from +0x2C, len=+0x34] [body from +0x04, len=+0x0C]
```
The "header" includes the tb_code-encrypted query bytes. The "query" field may be empty (len=0).
The "body" is encrypted with the credential Secret by FUN_100b3a60.

#### Debug Logging (line 152354)

```c
FUN_101b74e0(&param_2, "name: %s\ncode: %lld\nsecret: %lld",
    *puVar6,                              // Name string
    *(uint *)(local_c + 0x10),            // Code_lo
    *(uint *)(local_c + 0x14),            // Code_hi
    *(uint *)(local_c + 0x1c),            // Secret_lo
    *(uint *)(local_c + 0x20));           // Secret_hi
```

#### Credential Provider (line 152135)

```c
// The credential object comes from a virtual method call:
iVar3 = (**(code **)(**(int **)(param_1 + 0x1c) + 0x18))();
```

This calls vtable method index 6 (`0x18 / 4`) on the object at `param_1 + 0x1c`.
The credential provider is set up during session initialization.
For the 0x08 flag, a different provider returns the constructed credential object
with Name₃ and the unknown Secret₃.

### FUN_101b3e10 — SnakeOil Encrypt (line 382511)

```
RVA: 0x001b3e10
Signature: void __cdecl (byte *src, int len, byte *dst, uint key_lo, uint key_hi)
```

XORshift128 stream cipher. Each iteration:
```c
esi = (esi << 21 | eax >> 11) ^ esi;
eax = (eax << 21) ^ eax ^ (esi >> 3);
esi = (esi << 4 | eax >> 28) ^ esi;
eax = (eax << 4) ^ eax;
*dst = (eax >> 23) ^ *src;
```

### FUN_101b3e80 — SnakeOil Encrypt (thiscall variant, line 382534)

```
RVA: 0x001b3e80
Signature: void __thiscall (uint *this, int src_offset, int len, byte *dst)
```

Same algorithm but key state stored in `this[0]` (eax) and `this[1]` (esi).
Used when the key is part of an object (credential object encryption).

### DLL Entry Points

```
DllMain:        RVA 0x27F1EF (file offset 0x27E5EF)
TLS callback 0: RVA 0x27F24C
TLS callback 1: RVA 0x27F2DC
CRT DllMain:    RVA 0x27F0B9 (file offset 0x27E4B9)
Init function:  RVA 0x27F8F5 (called from DllMain on DLL_PROCESS_ATTACH)
```

### Call Flow: Wire Protocol Request

```
senddevicestatus (user action)
  │
  ├─ FUN_100b8220 (senddevicestatus builder, line 156024)
  │    ├─ FUN_100ba280 (copy device descriptor into body object)
  │    ├─ FUN_10093010 (generic API call builder, line 123012)
  │    │    ├─ Sets request object fields (counter, flags, body builder)
  │    │    ├─ FUN_10091bf0 (serialize body to igo-binary, line 121985)
  │    │    └─ FUN_101b30f0 (igo-binary writer)
  │    └─ Sets flags: param_5 = (puVar3[0x10] | param_4) & param_5
  │
  ├─ FUN_100bc640 (async wrapper, line 158836)
  │    └─ FUN_100b8220 (above)
  │
  ├─ FUN_100b0b50 (0x28/0x68 path — with cred block, line 149382)
  │    │   OR
  │    FUN_100b2380 (0x60 path — no cred block, line 150739)
  │    │
  │    ├─ FUN_100b3a60 (protocol envelope builder, line 152038)
  │    │    ├─ Credential provider: (**(this+0x1C))[0x18]() → credential object
  │    │    │    └─ FUN_1019ec40 (RVA 0x19EC40) → copies from this-0x9C
  │    │    │         └─ FUN_100b1670 (credential copier, line 149999)
  │    │    │              Copies: Name(+0x04), Code(+0x10/+0x14), Secret(+0x1C/+0x20)
  │    │    │
  │    │    ├─ Key selection (DEVICE mode):
  │    │    │    key_lo = *(cred + 0x1C)   ← Secret_lo
  │    │    │    key_hi = *(cred + 0x20)   ← Secret_hi
  │    │    │    piVar11[0x10] = &{key_lo, key_hi}
  │    │    │
  │    │    ├─ SnakeOil(query, qlen, query, key_lo, key_hi)  ← may be no-op (qlen=0)
  │    │    ├─ SnakeOil(body, blen, body, key_lo, key_hi)    ← encrypts body with Secret
  │    │    │
  │    │    └─ FUN_100b39e0 (wire output assembler, line 152004)
  │    │         Output: [1B marker] [header incl. tb_code-encrypted query] [body]
  │    │
  │    └─ FUN_100b05f0 (HTTP POST sender, line 149176)
  │         Sends: POST /senddevicestatus UDP

Credential source for each path:
  ┌─────────────┬──────────────────────────────────────────────┐
  │ Path        │ Credential source                            │
  ├─────────────┼──────────────────────────────────────────────┤
  │ 0x60        │ Toolbox descriptor → tb_secret               │
  │ 0x28/0x68   │ HU descriptor +0x84 → Secret₃ (from         │
  │             │ device.nng, NOT from delegator response)      │
  └─────────────┴──────────────────────────────────────────────┘

device.nng parsing:
  FUN_101c0860 (line 54102) — reads device.nng from USB
  Contains: NNGE marker, device identity, credential data
  268 bytes, partially encrypted
```

8. **Imei field encoding** — The `x51x4Dx30x30x30x30x31` format.

9. **SendDeviceStatus body validation** — Our generated body (correct device info, different file entries) returns 409. The captured body (with its specific file list) returns 200. Server may validate file list against known device state.

---

## 11. Credential Block Encoding

The 17-byte credential block in DEVICE mode request payloads encodes the 16-byte Name:

```
credential_block = 0xD8 || (Name XOR IGO_CREDENTIAL_KEY)
```

Where `IGO_CREDENTIAL_KEY = 6935b733a33d02588bb55424260a2fb5` (16 bytes).

**Verified**: Generated credential blocks are accepted by the live NaviExtras server.

The decrypted DEVICE mode payload format:
```
[counter 1B] [flags 1B] [0xD8 + 16B encoded Name] [request body...]
```

For empty-body requests (hasActivatableService, getProcess), the request body is omitted.

---

## 12. RANDOM Mode Seed Generation

The Toolbox generates the RANDOM mode seed from `_time64()` using xorshift128:

```python
M = 0xFFFFFFFF
t = int(time.time())
t_lo = t & M
esi = (t_lo >> 11) & M
ecx = (t_lo << 21) & M
edx = esi
edi = (t_lo ^ ecx) & M
ecx2 = (edx >> 3) & M
edi2 = (edi ^ ecx2) & M
ecx3 = ((edx << 4) | (edi2 >> 28)) & M
eax = (edi2 << 4) & M
seed = (((ecx3 ^ edx) & M) << 32) | ((eax ^ edi2) & M)
```

The server validates the seed against the current time (tight window). Old seeds from captured sessions continue to work indefinitely.

---

## 13. Wine Runtime Analysis (BREAKTHROUGH)

### Overview

We can load nngine.dll inside a Docker container running 32-bit Wine, then call its internal functions directly from C programs compiled with MinGW. This lets us:

1. **Dump BSS memory** after DllMain initializes the type descriptors
2. **Call the bit writer functions** directly to verify encoding hypotheses
3. **Read function code** at runtime to verify disassembly

### Architecture

```
Host (aarch64 / x86_64)
│
├── analysis/wine_prefix/     ← bind mount: persistent Wine prefix (survives restarts)
├── analysis/                 ← bind mount: C harness source files (read/write)
├── analysis/extracted/       ← bind mount: nngine.dll + other DLLs (read-only)
│
└── Docker container "wine32" (linux/amd64, QEMU if on ARM)
    ├── wine32-mingw image    ← scottyhardy/docker-wine + gcc-mingw-w64-i686 baked in
    ├── wine32-entrypoint.sh  ← creates user, inits prefix, starts wineserver
    ├── wineserver -p         ← persistent daemon (avoids slow per-command startup)
    └── tail -f /dev/null     ← keep-alive process
```

### Why This Design

**Problem**: The old approach (`docker run ... sleep 7200`) had several issues:
- **Slow startup**: Every container restart required re-running `wineboot -i` (~5-10 min under QEMU) because the Wine prefix lived inside the container
- **Ephemeral state**: `apt-get install mingw` was lost on every restart
- **Root ownership**: Container ran as root, so bind-mounted files were owned by root:root on the host, requiring sudo to manage
- **Blocking services**: Every `wine` invocation spawned `wineserver` + `services.exe` + `winedevice.exe` + `wineboot.exe`, each taking minutes under QEMU emulation

**Solution**:
1. **Custom Docker image** (`Dockerfile.wine32`): Bakes in `gcc-mingw-w64-i686` so it's never lost
2. **Bind-mounted Wine prefix** (`analysis/wine_prefix/`): Persists across container restarts — `wineboot` only runs once per Wine version
3. **User mapping**: Entrypoint creates a `wineuser` matching the host UID/GID (1000:100), so all files on bind mounts are owned by the host user
4. **Persistent wineserver**: `wineserver -p` starts in the entrypoint and stays running, so `wine` commands connect to the existing server instantly instead of spawning a new one
5. **Version marker** (`.wine-version`): Tracks whether `wineboot` has completed for the current Wine build. On restart, if the marker matches, wineboot is skipped entirely

### Key Files

| File | Purpose |
|------|---------|
| `analysis/Dockerfile.wine32` | Image definition: extends `scottyhardy/docker-wine` with mingw |
| `analysis/wine32-entrypoint.sh` | Container entrypoint: user creation, prefix init, wineserver startup |
| `analysis/wine_prefix/` | Persistent Wine prefix (bind-mounted into container) |
| `analysis/wine_prefix/.wine-version` | Our marker: stores `wine-11.0` etc. to skip wineboot on restart |
| `analysis/wine_prefix/.update-timestamp` | Wine's own marker: stores `wine` binary mtime. **Do not edit** — wineboot manages this |

### How the Entrypoint Works

1. **Create user**: `useradd -u $HOST_UID -g $HOST_GID wineuser` — matches host user so bind mount files have correct ownership
2. **Check prefix**: If `drive_c/windows/system32/` has < 100 files, run `wineboot -i` (first-time init, ~5-10 min under QEMU)
3. **Check version**: Compare `.wine-version` against `wine --version`. If different, run `wineboot -u` (upgrade, also slow). Write new version to marker
4. **Start wineserver**: `wineserver -p` as a persistent daemon — the `-p` flag means "don't exit when last client disconnects"
5. **Drop to user**: `exec su wineuser -c "tail -f /dev/null"` — keep-alive process running as the mapped user

### Setup

#### Prerequisites

- Docker with `linux/amd64` platform support (QEMU if on ARM host)
- nngine.dll from the extracted Toolbox installer (`analysis/extracted/nngine.dll`)

#### Step 1: Build the Image (one-time)

```bash
cd /home/mark/git/MediaNavToolbox/analysis
docker build --platform linux/amd64 -t wine32-mingw -f Dockerfile.wine32 .
```

This extends `scottyhardy/docker-wine:latest` (~3.5GB) with `gcc-mingw-w64-i686`.

#### Step 2: Create and Start the Container

```bash
docker run -d --name wine32 --platform linux/amd64 \
  --memory=8g \
  -e HOST_UID=$(id -u) \
  -e HOST_GID=$(id -g) \
  -v /home/mark/git/MediaNavToolbox/analysis/wine_prefix:/home/wineuser/.wine32 \
  -v /home/mark/git/MediaNavToolbox/analysis:/work \
  -v /home/mark/git/MediaNavToolbox/analysis/extracted:/dlls:ro \
  wine32-mingw \
  "tail -f /dev/null"
```

**Bind mounts explained:**
| Host Path | Container Path | Mode | Purpose |
|-----------|---------------|------|---------|
| `analysis/wine_prefix/` | `/home/wineuser/.wine32` | rw | Persistent Wine prefix — survives restarts |
| `analysis/` | `/work` | rw | C harness source files — edit on host, compile in container |
| `analysis/extracted/` | `/dlls` | ro | nngine.dll and other extracted DLLs |

**First run**: The entrypoint runs `wineboot -i` to populate the prefix. This takes **5-10 minutes under QEMU** (it installs ~865 DLLs into `system32/`). Watch progress with `docker logs -f wine32`. You'll see "Ready." when it's done.

**Subsequent runs**: The entrypoint sees the prefix is up to date and skips wineboot. Startup takes **~3 seconds**.

#### Step 3: Verify

```bash
# Check it's ready
docker logs wine32
# Expected: "Wine prefix up to date (wine-11.0, 866 DLLs)."
#           "Starting wineserver... done. Ready."

# Check user mapping
docker exec --user $(id -u):$(id -g) wine32 id
# Expected: uid=1000 gid=100

# Check mingw is available
docker exec --user $(id -u):$(id -g) wine32 which i686-w64-mingw32-gcc
# Expected: /usr/bin/i686-w64-mingw32-gcc
```

#### Step 4: Compile and Run a C Harness

```bash
# Compile (source files are on the bind mount at /work)
docker exec --user $(id -u):$(id -g) wine32 bash -c '
  cp /dlls/nngine.dll $WINEPREFIX/drive_c/
  i686-w64-mingw32-gcc -O2 -o $WINEPREFIX/drive_c/harness.exe /work/dump_bss.c -lkernel32
  wine C:\\harness.exe 2>/dev/null
'

# Output files appear on the host at analysis/wine_prefix/drive_c/
cat analysis/wine_prefix/drive_c/output.txt
```

**CRITICAL: Always compile with `-O2`**. The `-O0` flag causes stack alignment issues with `__fastcall` functions in nngine.dll, leading to silent crashes at `LoadLibraryA`.

### Container Lifecycle

```bash
# Restart (fast — skips wineboot if prefix is current)
docker restart wine32

# Check status
docker ps --filter name=wine32 --format "{{.Status}}"
docker logs wine32 | tail -3

# Execute commands as the mapped user
docker exec --user $(id -u):$(id -g) wine32 bash -c '...'

# Stop
docker stop wine32

# Remove (prefix is preserved on host)
docker rm wine32

# Recreate from scratch (if Wine version changes or prefix is corrupted)
rm -rf analysis/wine_prefix/*
docker rm -f wine32
# Then re-run the docker run command from Step 2
```

### Wineboot and .update-timestamp — How It Works

Wine's prefix update mechanism caused significant debugging effort. Here's how it works:

1. **Wine checks `.update-timestamp`** on every `wine` invocation. The file contains the epoch-seconds mtime of the `wine` binary at the time wineboot last ran.
2. **If the timestamp doesn't match** the current `wine` binary's mtime, Wine spawns `wineboot.exe --init` to update the prefix. Under QEMU, this takes 5-10 minutes.
3. **`wineboot.exe --init`** installs DLLs, registers COM objects, and runs `rundll32.exe setupapi,InstallHinfSection` — all extremely slow under QEMU emulation.
4. **Our workaround**: The entrypoint runs `wineboot -u` once per Wine version (tracked by `.wine-version` marker), then starts `wineserver -p`. Since wineboot has already completed, subsequent `wine` commands don't trigger it again.

**Important**: Do NOT manually edit `.update-timestamp`. Wineboot writes the correct value (`stat -c '%Y' /opt/wine-stable/bin/wine`). If you overwrite it with a different value (e.g., `wine-preloader`'s mtime), wineboot will re-run on every invocation.

### Loading nngine.dll — Two Modes

#### Mode A: With DllMain (initializes BSS, but blocks stdio)

```c
HMODULE h = LoadLibraryA("C:\\nngine.dll");
// DLL loads at ~0x7E9F0000
// DllMain runs: initializes type descriptors in BSS
// WARNING: After this call, printf/fflush may hang!
// Use file I/O (CreateFileA/WriteFile) for output instead
```

**Use this mode for**: Dumping initialized BSS memory (type descriptors, vtables).

**Gotcha**: DllMain creates threads/hooks that interfere with the C runtime. After `LoadLibraryA`, `printf` and `fflush` may hang indefinitely. Write output using Win32 API (`CreateFileA`/`WriteFile`) instead, or do all printf BEFORE loading the DLL.

#### Mode B: Without DllMain (safe, can call functions directly)

```c
HMODULE h = LoadLibraryExA("C:\\nngine.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
// DLL loads at ~0x7E9F0000
// DllMain does NOT run: BSS is zeroed (type descriptors not initialized)
// BUT: all code is present and relocated, functions can be called
// printf/fflush work normally
```

**Use this mode for**: Calling bit writer functions, reading function code, verifying encoding.

### Calling __thiscall Functions via Inline Assembly

nngine.dll uses MSVC `__thiscall` convention: `this` in ECX, parameters on stack, callee cleans stack. MinGW's `__thiscall` attribute doesn't always work correctly, so use inline assembly:

```c
// write_1bit_lsb (RVA 0x1a9e80): __thiscall(ecx=bitstream, stack: value) ret 4
static unsigned g_w1_addr;

static void w1(unsigned *bs, int value) {
    unsigned f = g_w1_addr, b = (unsigned)bs;
    __asm__ volatile(
        "push %2\n\t"
        "mov %0, %%ecx\n\t"
        "call *%1"
        :: "r"(b), "r"(f), "r"(value)
        : "ecx", "edx", "eax", "memory"
    );
}

// write_nbits_msb (RVA 0x1a8150): __thiscall(ecx=bitstream, stack: value, nbits) ret 8
// IMPORTANT: Mark as __attribute__((noinline)) to avoid register pressure errors
static unsigned g_wn_addr;

static void __attribute__((noinline)) wn(unsigned *bs, unsigned val, unsigned nb) {
    unsigned f = g_wn_addr, b = (unsigned)bs;
    __asm__ volatile(
        "mov %3, %%eax\n\t"
        "push %%eax\n\t"
        "push %2\n\t"
        "mov %0, %%ecx\n\t"
        "call *%1"
        :: "r"(b), "r"(f), "r"(val), "m"(nb)
        : "ecx", "edx", "eax", "memory"
    );
}

// Initialize addresses after loading DLL
g_w1_addr = (unsigned)h + 0x1a9e80;
g_wn_addr = (unsigned)h + 0x1a8150;
```

**Common errors:**
- `error: 'asm' operand has impossible constraints` → The function was inlined and GCC ran out of registers. Add `__attribute__((noinline))` to the function, or use `"m"(var)` instead of `"r"(var)` for one operand.
- Silent hang when calling functions → You loaded with `LoadLibraryA` (Mode A). Use `LoadLibraryExA` with `DONT_RESOLVE_DLL_REFERENCES` (Mode B) instead.

### BitStream Structure

The bit writer functions operate on a BitStream structure:

```c
struct BitStream {
    unsigned char *buf;    // [0x00] buffer pointer
    unsigned bit_pos;      // [0x04] bit offset within current byte (0-7)
    unsigned byte_pos;     // [0x08] current byte position in buffer
    unsigned capacity;     // [0x0C] buffer capacity in bytes
    unsigned char mode;    // [0x10] encoding mode flag
    // ... more fields
};
```

Initialize for testing:
```c
unsigned char buf[256] = {0};
unsigned bs[8] = {0};
bs[0] = (unsigned)buf;  // buffer pointer
bs[3] = 256;            // capacity
// bs[1] (bit_pos) and bs[2] (byte_pos) start at 0
```

The capacity check function (`FUN_101a8820` at RVA 0x1a8820) compares `bs[2] + needed_bytes` against `bs[3]`. If the buffer is too small, it tries to grow via the NNG allocator (which won't work without DllMain). Set capacity large enough to avoid growth.

### Verified Results

**Bit writer produces correct output:**

| Test | Code | Output | Notes |
|------|------|--------|-------|
| 8 presence bits (all 0) | `for(i=0;i<8;i++) w1(bs,0)` | `0x00` | ✓ |
| 1 presence bit = 1 | `w1(bs, 1)` | `buf[0]=0x01, bit=1, byte=1` | LSB-first |
| 8-bit MSB value 0xAB | `wn(bs, 0xAB, 8)` | `buf[0]=0xAB` | MSB-first ✓ |
| 16 presence bits → D8 14 | `{0,0,0,1,1,0,1,1, 0,0,1,0,1,0,0,0}` | `0xD8 0x14` | **Matches DEVICE index body** ✓ |
| 16 presence bits → 50 86 | `{0,0,0,0,1,0,1,0, 0,1,1,0,0,0,0,1}` | `0x50 0x86` | **Matches boot body** ✓ |

### Key Findings

**DLL loads at 0x7E9F0000** under Wine. DllMain runs successfully and initializes BSS.

**Type system** (from BSS dump after DllMain):
- 199 type objects share vtable at RVA 0x2D236C
- Type IDs: 1 (73 objects), 2 (23 objects), 4 (2 objects), 5 (101 objects)
- Type ID is at `type_object[1]` (offset 4, uint32)
- Serialize function at vtable[2] = RVA 0x1a67f0

**Field type mapping:**

| type_id | Count | Example fields | Meaning |
|---------|-------|---------------|---------|
| 1 | 73 | Country, BrandName, Code, Name, Swid | Presence-only (no value bits) |
| 2 | 23 | Category, Connections, UniqId, Vin | Compound / nested |
| 4 | 2 | Url | Special |
| 5 | 101 | OperatingSystemName, Appcid, DeviceContextId | String / variable-length |

**BSS Memory Layout:**
- BSS starts at DLL_BASE + 0x314200
- BSS size: 0x1A1F8 bytes (107,000 bytes)
- After DllMain: 5543 non-zero bytes (type descriptors initialized)
- Type objects are 12 bytes: `[vtable:4][type_id:4][sub_desc_ptr:4]`

**D8 14 and 50 86 are pure presence bits:**

The DEVICE index body `D8 14` is 16 presence bits (LSB-first):
```
Bits: 0,0,0,1,1,0,1,1, 0,0,1,0,1,0,0,0
Fields present: 3, 4, 6, 7, 10, 12
```

The boot body `50 86` is 16 presence bits (LSB-first):
```
Bits: 0,0,0,0,1,0,1,0, 0,1,1,0,0,0,0,1
Fields present: 4, 6, 9, 10, 15
```

`type_id=1` fields have **no value bits** — just a presence flag. Country=0 is encoded as a single presence bit (1 = present).

### Troubleshooting Checklist

| Symptom | Cause | Fix |
|---------|-------|-----|
| `wine: could not load kernel32.dll` | 64-bit Wine prefix or empty prefix | Delete `analysis/wine_prefix/*`, restart container to re-init |
| Silent crash at `LoadLibraryA` | Compiled with `-O0` | Always use `-O2` |
| `printf` hangs after `LoadLibraryA` | DllMain interferes with CRT | Use `LoadLibraryExA` with `DONT_RESOLVE_DLL_REFERENCES`, or use `CreateFileA`/`WriteFile` |
| `asm operand has impossible constraints` | Too many inline asm operands | Add `__attribute__((noinline))`, use `"m"()` for memory operands |
| `LoadLibrary error 126` | Missing DLL dependencies | Copy ALL DLLs from extracted/ to `drive_c/` (winhttp, advapi32 etc. are provided by Wine) |
| Container OOM killed (exit 137) | Not enough memory | Use `--memory=8g` |
| `wineboot` runs on every `wine` command | `.update-timestamp` mismatch | Let wineboot complete once; don't manually edit `.update-timestamp` |
| Container starts but wine hangs | wineserver not running | Check `docker logs wine32` — entrypoint should show "Ready." |
| Files on host owned by root | Container user mismatch | Pass `-e HOST_UID=$(id -u) -e HOST_GID=$(id -g)` |
| DLL loads then immediately unloads | DllMain returns FALSE | Normal with `LoadLibraryA` if dependencies fail; use `DONT_RESOLVE_DLL_REFERENCES` |

### Example: Complete BSS Dump Workflow

```bash
# 1. Compile the dumper (source is on the bind mount)
docker exec --user $(id -u):$(id -g) wine32 bash -c '
  cp /dlls/nngine.dll $WINEPREFIX/drive_c/
  i686-w64-mingw32-gcc -O2 -o $WINEPREFIX/drive_c/dump_bss.exe /work/dump_bss.c -lkernel32
  wine C:\\dump_bss.exe 2>/dev/null
'

# 2. Output is directly on the host (bind mount)
python3 -c "
bss = open('analysis/wine_prefix/drive_c/bss_init.bin','rb').read()
nz = sum(1 for b in bss if b)
print(f'BSS: {len(bss)} bytes, {nz} non-zero')
"
```


### Request Body Encoding — SOLVED

**The request body format is NOT the bitstream/presence-bit format described in earlier analysis.** That analysis was based on incorrectly decrypted data (query+body decrypted as one stream instead of separately).

**Actual format** (from correctly decrypted captured traffic):

```
Request body = [0x80] [field1] [field2] ...

String:  [length:1] [utf8_bytes:length]   — no null terminator, no type tag
Int32:   [4 bytes big-endian]             — no type tag
Int64:   [8 bytes big-endian]             — no type tag
Array:   [count:1] [elements...]          — count byte then inline elements
Byte:    [value:1]                        — single raw byte
```

**LoginArg body** (70 bytes, verified byte-for-byte):
```
80                              envelope
18 "Windows 10 (build 19044)"  OperatingSystemName (len=24)
06 "10.0.0"                    OperatingSystemVersion (len=6)
05 "19044"                     OperatingSystemBuildVersion (len=5)
0f "5.28.2026041167"           AgentVersion (len=15)
01 09 "Dacia_ULC"              AgentAliases (array count=1, string len=9)
02 "en"                        Language (len=2)
01                             AgentType (enum: TB=1)
```

**RegisterDeviceArg body** (131 bytes, verified byte-for-byte):
```
1d 00                           header (0x1d=29, 0x00)
0f "DaciaAutomotive"            BrandName (len=15)
0c "DaciaToolbox"               ModelName (len=12)
16 "CK-153G-PF9R-KB6D-W8B0"    Swid (len=22)
15 "x51x4Dx30x30x30x30x31"     Imei (len=21)
08 "9.35.2.0"                   IgoVersion (len=8)
00 00 00 00 00 00 00 00         FirstUse (int64 BE = 0 = 1970.01.01)
42 00 09 be                     Appcid (int32 BE = 0x420009BE)
00                              separator
20 "BF7AE9C2D033892B19FB511A6F206AC9"  UniqId (len=32)
```

**Key insight**: The "presence bits" (D8 14, 50 86, 58 0C) seen in earlier analysis are part of the **query envelope**, not the body. The body uses a simple length-prefixed format with no bitstream encoding.

**Implementation**: `wire_codec.py` — `build_login_body()`, `build_register_device_body()`

**Earlier analysis notes** (bitstream, presence bits, two-buffer architecture) describe the **envelope serializer** used for the XML logging layer inside the DLL, not the wire body format. The triplet array and field flags relate to the DLL's internal type system.
