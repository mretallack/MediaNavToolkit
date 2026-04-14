# Dacia MediaNav Evolution Toolbox — Reverse Engineering Notes

## Data Sources

| Source | Location | Description |
|--------|----------|-------------|
| Toolbox installer | `analysis/extracted/` | Extracted NSIS installer (nngine.dll, plugin.dll, exe) |
| Ghidra decompile | `analysis/nngine_decompiled.c` | 13,381 functions from nngine.dll |
| USB drive image | `analysis/usb_drive/disk/` | NaviSync data from head unit |
| Windows AppData | `analysis/DaciaAutomotive_extracted/` | `%APPDATA%/DaciaAutomotive` cache |
| HTTP dump (encrypted) | `analysis/DaciaAutomotive_extracted/DaciaAutomotive/http_dump/` | Blowfish-encrypted XML of every API call |
| HTTP dump (decrypted) | `analysis/http_dump_decrypted/` | Decrypted XML from session 69BAC5EC |
| mitmproxy flows | `analysis/flows/flows` (75 flows), `analysis/flows/flows-complete` (611 flows) | Live wire captures |
| mitmproxy decoded | `analysis/flows_decoded/` | Raw request/response binaries |
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
Bytes 13-14: 0x00 0x00 (padding)
Byte 15:     0x3F (end marker)
Byte 16+:    Encrypted payload starts here
```

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
- **DEVICE** (0x30): wire header has Code. Request PRNG seed = **Code**. Response PRNG seed = **Secret**.

**Request**: payload at bytes 16+ encrypted with PRNG seed
**Response**: payload at bytes 4+ encrypted with same PRNG seed

**Response header byte 3**: `0x6B` = RANDOM mode, `0xBC` = DEVICE mode

**Verified decryptions:**
- Boot response → service URLs (`https://zippy.naviextras.com/...`) ✓
- Registration response → Credentials (Name, Code, Secret) ✓
- Model list response → all 29 device model names ✓
- hasActivatableService response → single `0x00` byte (false) ✓

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

No `Content-Type` header is sent for the binary protocol.

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
- `Code` in the wire header (bytes 5-12) and in `RequestEnvelopeRO/Credentials`
- `Secret` as the SnakeOil PRNG seed for encryption/decryption
- `Name` + `Code` in the `RequestEnvelopeRO/Credentials` XML

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
3. `FUN_1009c960` formats as `CK-XXXX-XXXX-XXXX-XXXX`

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

- Pre-registration (`RANDOM`): PRNG seed = random key in wire header
- Post-registration (`DEVICE`): wire header has Code, PRNG seed = Secret
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

## 10. Open Questions

1. **DEVICE mode request encryption** — DEVICE mode requests don't decrypt with the Secret key. The request PRNG seed for DEVICE mode may be different from the response seed. Need to trace the exact key used for request encryption in DEVICE mode.

2. **NNGE decryption** — the device.nng encryption using key `m0$7j0n4(0n73n71I)`. The decoder plugin chain in nngine.dll handles this.

3. **igo-binary format** — the decrypted payloads are igo-binary serialized. Need to build a parser for the type-tagged format (0x01=int32, 0x02=byte, 0x05=string, 0x80=envelope, etc.).
