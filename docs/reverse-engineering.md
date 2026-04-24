# MediaNav Toolbox — Reverse Engineering Documentation

> Comprehensive record of the reverse engineering effort for the Dacia MediaNav Evolution Toolbox protocol.
> Covers architecture, protocol details, approaches tried (and failed), tools built, and current status.

## Table of Contents

- [Project Overview](#project-overview)
- [Target Application](#target-application)
- [Current Status](#current-status)
- [Protocol Architecture](#protocol-architecture)
- [Session Flow](#session-flow)
- [SnakeOil Cipher](#snakeoil-cipher)
- [Wire Protocol Format](#wire-protocol-format)
- [Request Body Encoding](#request-body-encoding)
- [Credential Block Encoding](#credential-block-encoding)
- [Delegation (0x68) Flow](#delegation-0x68-flow)
- [USB Drive Structure](#usb-drive-structure)
- [Map Data & Encryption](#map-data--encryption)
- [Reverse Engineering Approaches](#reverse-engineering-approaches)
- [Win32 Debugging Environment](#win32-debugging-environment)
- [Engineering Log](#engineering-log)
- [Source File Reference](#source-file-reference)
- [Remaining Work](#remaining-work)

---

## Project Overview

A Linux/Python replacement for the Windows-only **Dacia MediaNav Evolution Toolbox** — the official NNG app for updating maps, POIs, speed cameras, and voice packs on Dacia/Renault MediaNav head units.

The official Toolbox is a 32-bit Windows Electron/CEF app (`DaciaMediaNavEvolutionToolbox.exe`) that communicates with `naviextras.com` using a proprietary binary wire protocol implemented in `nngine.dll` (3.3MB PE32). This project reverse-engineers that protocol and reimplements it as a Python library and CLI tool.

**Repository:** `/home/mark/git/MediaNavToolbox`

---

## Target Application

| Property | Value |
|----------|-------|
| Application | Dacia MediaNav Evolution Toolbox |
| Path (Windows) | `C:\Program Files (x86)\DaciaAutomotive\Toolbox4\DaciaMediaNavEvolutionToolbox.exe` |
| Architecture | 32-bit (PE32) |
| Framework | Chromium Embedded Framework (CEF) — UI is a web app |
| Key DLL | `nngine.dll` (3.3MB, PE32) — all protocol logic |
| Other DLLs | `plugin.dll` (branding/config), `mtp.dll` (USB MTP) |
| Device Target | Dacia MediaNav Evolution (`DaciaAutomotiveDeviceCY20_ULC4dot5`) |
| Server | `naviextras.com` (NNG) |

### nngine.dll Key Exports

```
NngineStart, NngineStop, NngineIsRunning
NngineConnectDevice, NngineDisconnectDevice
NngineAttachConfig, NngineAttachHmi, NngineAttachLogger
NngineRestartWorkflow, NngineResumeTransfer, NngineSuspendTransfer
NngineFireEvent
```

### Key Function RVAs (nngine.dll)

| RVA | Function | Purpose |
|-----|----------|---------|
| `0x1B3E10` | SnakeOil | `void SnakeOil(byte* src, int len, byte* dst, uint32 key_lo, uint32 key_hi)` |
| `0x1AA3A0` | HMAC_MD5 | `void HMAC_MD5(void* output, uint8_t* key, uint32 key_len, uint8_t* data, uint32 data_len)` |
| `0x05D860` | FUN_1005d860 | 41B→17B delegation prefix compression + encryption |
| `0x0567E0` | FUN_100567E0 | Get inner credential descriptor |
| `0x1A9930` | FUN_101a9930 | igo-binary bitstream serializer |

---

## Current Status

### Working End-to-End ✅

- USB drive detection and device identity reading
- Device registration with NaviExtras server
- Full authentication flow (boot → login → fingerprint → delegator → senddevicestatus)
- Wire protocol encryption fully solved (SnakeOil xorshift128 cipher)
- **Delegated senddevicestatus** — `build_dynamic_request()` generates from scratch, verified byte-exact against captured data (24 tests)
- Catalog browsing — 38 items (maps, POIs, safety cameras) from live server
- Free content purchase via web API
- License fetching — `.lyc` files downloaded live from server
- License installation to USB drive (`.lyc` + `.lyc.md5`)
- 320+ unit tests passing

### Remaining ❌

- **Full sync pipeline** — `medianav-toolbox sync` command not yet wired end-to-end

---

## Protocol Architecture

The NaviExtras API uses a custom binary wire protocol over HTTPS. All communication goes through two server clusters:

| Server | Purpose |
|--------|---------|
| `zippy.naviextras.com` | Registration, boot, delegator, licenses |
| `dacia-ulc.naviextras.com` | Market (login, fingerprint, device status, content) |

### Two Communication Layers

1. **Wire protocol** (binary) — device registration, authentication, device status, licenses
2. **Web protocol** (HTTP/HTML/JSON) — catalog browsing, content selection, purchases

The wire protocol handles all security-sensitive operations. The web protocol is used for the storefront UI after authentication is established.

---

## Session Flow

```
1. Boot          → service URLs              (RANDOM mode, unauthenticated)
2. Register      → toolbox credentials       (RANDOM mode, cached permanently)
3. Login         → JSESSIONID cookie         (DEVICE mode, tb_code/tb_secret)
4. DeviceStatus  → 200 OK (×3, 1219B)       (DEVICE mode, 0x60 flags, variant=0x02)
5. Licenses      → .lyc file data (×4)      (DEVICE mode, service minor=14)
6. HasActivatable → 200 OK                  (DEVICE mode)
7. GetProcess    → process info              (DEVICE mode)
8. Fingerprint   → 200 OK                   (DEVICE mode, 53KB)
9. Delegator     → head unit credentials ×7  (DEVICE mode, service minor=0x0E)
10. DeviceStatus → 200 OK (×9, 1243B)       (DEVICE mode, 0x28 format)
11. LicInfo      → license info              (DEVICE mode)
12. Licenses     → .lyc file data            (DEVICE mode, 490B)
13. DeviceStatus → 200 OK (×9, 2218B)       (DEVICE mode, delegated format)
14. Fingerprint  → 200 OK (×9, 41KB)        (DEVICE mode)
15. SendFileContent → 200 OK                (DEVICE mode, sends device.nng)
16. SSE events   → long-poll                 (GET /sse/events)
17. GetProcess   → process info (×17)        (DEVICE mode, polling)
18. SendProcessStatus → status updates (×50+) (DEVICE mode)
```

> **Source:** `analysis/using-win32/hmac_log_run32_queries.txt` — captured from the
> real Windows Toolbox (run32, 2026-04-23). This is the most accurate sequence available.

### Critical Sequence Findings

**senddevicestatus comes FIRST** — before fingerprint, before delegator. The Toolbox
sends it immediately after login with the existing JSESSIONID. Our Python code sends
it after fingerprint and delegator, which may be why the server returns 409.

**Three different senddevicestatus sizes:**
- 1219B (steps 1-3): 0x60 flags, variant=0x02, tb credentials
- 1243B (step 10): 0x28 format, after delegator
- 2218B (step 13): delegated format with hu credentials

**No explicit login in run32** — the Toolbox reuses a JSESSIONID from a prior session.
Login happens once and the cookie persists across Toolbox restarts.

**licenses is called early** — interleaved with the first senddevicestatus batch,
before delegator. This is different from our flow which calls licenses last.

**sendfilecontent** — sends `device.nng` content to the server. We don't do this.

### Our Current Flow (WRONG ORDER)

```
1. Boot → 2. Login → 3. Fingerprint → 4. Delegator → 5. DeviceStatus → 6. Catalog
```

### Correct Flow — Fresh Session (from run26, no existing JSESSIONID)

```
1. licinfo                          ← before login!
2. login                            ← get JSESSIONID
3. licinfo + licenses               ← license check
4. SSE /sse/events                  ← establish event stream
5. getprocess                       ← check pending processes
6. sendfingerprint                  ← send USB file listing
7. get_device_descriptor_list       ← device capabilities
8. hasActivatableService            ← check activatable content
9. get_device_model_list            ← device model info
10. senddevicestatus (×8)           ← ONLY AFTER all the above
11. delegator                       ← get hu credentials
12. senddevicestatus (delegated)    ← with hu credentials
```

> **Source:** `analysis/using-win32/hmac_log_run26_envelope.txt` — fresh session,
> no pre-existing JSESSIONID. Shows the complete initial setup sequence.

### Correct Flow — Existing Session (from run32, JSESSIONID already valid)

```
1. senddevicestatus (×3, 1219B)     ← immediate, session already established
2. licenses (×4)
3. hasActivatableService
4. getprocess
5. sendfingerprint
6. delegator (×7)
7. senddevicestatus (×9, 1243B)     ← 0x28 format
8. licinfo + licenses
9. senddevicestatus (×9, 2218B)     ← delegated format
10. sendfingerprint (×9)
11. sendfilecontent
12. getprocess (polling) + sendprocessstatus
```

> **Source:** `analysis/using-win32/hmac_log_run32_queries.txt` — existing session.

### Why We Get 409

The server likely requires context from earlier calls before accepting senddevicestatus:
- `sendfingerprint` — tells the server what files are on the USB
- `get_device_descriptor_list` — tells the server the device capabilities
- `hasActivatableService` — checks what content is available
- `get_device_model_list` — identifies the device model

We skip most of these and jump straight to senddevicestatus. The server returns 409
because it doesn't have the device context it needs.

### Step Details

| Step | Endpoint | Mode | Body Format | Notes |
|------|----------|------|-------------|-------|
| Boot | `POST /services/register/rest/1/3` | RANDOM | igo-binary | Returns service name→URL map |
| Register | `POST /services/register/rest/1/device` | RANDOM | wire codec | Returns Name/Code/Secret (permanent) |
| Login | `POST /rest/1/login` | DEVICE | wire codec | Returns JSESSIONID |
| DeviceStatus (0x60) | `POST /rest/1/senddevicestatus` | DEVICE | wire codec | **FIRST** — sends device info + file metadata |
| Licenses | `POST /services/register/rest/14/licenses` | DEVICE | wire codec | Returns .lyc data (service minor=14!) |
| HasActivatable | `POST /services/register/rest/14/hasActivatableService` | DEVICE | wire codec | Checks for activatable content |
| GetProcess | `POST /rest/1/getprocess` | DEVICE | wire codec | Returns process/task info |
| Fingerprint | `POST /rest/1/sendfingerprint` | DEVICE | wire codec | Sends USB file listing (53KB) |
| Delegator | `POST /services/register/rest/14/delegator` | DEVICE | wire codec | Returns hu_name/hu_code/hu_secret |
| DeviceStatus (0x28) | `POST /rest/1/senddevicestatus` | DEVICE | wire codec | After delegator, tb_name credential |
| LicInfo | `POST /services/register/rest/14/licinfo` | DEVICE | wire codec | License metadata |
| DeviceStatus (delegated) | `POST /rest/1/senddevicestatus` | DEVICE | wire codec | Delegated — uses hu credentials, `session_key=creds.secret` |
| SendFileContent | `POST /rest/1/sendfilecontent` | DEVICE | wire codec | Sends device.nng to server |
| SSE Events | `GET /sse/events` | HTTP | SSE | Long-poll for server events |
| SendProcessStatus | `POST /rest/1/sendprocessstatus` | DEVICE | wire codec | Reports installation progress |

**Critical discoveries:**
- Wire protocol requests must **NOT** include `Content-Type` header (server returns 500)
- Service minor for register endpoints is **14** (not 1) — wrong value causes 409
- Credentials from registration are permanent — cached in `.medianav_creds.json`
- **Request ordering matters** — senddevicestatus must come before fingerprint/delegator

Source: [`session.py`](../medianav_toolbox/session.py), [`api/boot.py`](../medianav_toolbox/api/boot.py), [`api/register.py`](../medianav_toolbox/api/register.py), [`api/market.py`](../medianav_toolbox/api/market.py)

---

## SnakeOil Cipher

The wire protocol uses a custom stream cipher we named "SnakeOil" — an xorshift128 PRNG used as a keystream generator.

### Algorithm

```python
def snakeoil(data: bytes, seed: uint64) -> bytes:
    eax = seed & 0xFFFFFFFF        # low 32 bits
    esi = (seed >> 32) & 0xFFFFFFFF # high 32 bits
    for each byte:
        edx = eax
        eax ^= (eax << 11) & 0xFFFFFFFF
        eax ^= (eax >> 8)
        eax ^= esi ^ ((esi >> 19) & 0xFFFFFFFF)
        esi = edx
        # Extract keystream byte via SHRD (64-bit shift right by 8)
        combined = (esi << 32) | eax
        keystream_byte = (combined >> 8) & 0xFF
        output[i] = data[i] ^ keystream_byte
```

- Symmetric: same function encrypts and decrypts
- Reversed from `FUN_101b3e10` (nngine.dll RVA `0x1B3E10`)
- Uses x86 `SHRD` instruction for 64-bit output extraction
- Each encrypted segment uses a **fresh PRNG state** (seed restarted)

### Key Management

| Mode | Query Key | Body Key |
|------|-----------|----------|
| RANDOM (0x20) | Random seed from header | Same random seed |
| DEVICE (0x30) | Code | Secret |
| DEVICE delegated (0x68) | Code | Secret (split: prefix + body, each fresh) |

Source: [`crypto.py`](../medianav_toolbox/crypto.py)

---

## Wire Protocol Format

### Request Layout

```
[16B header] [SnakeOil-encrypted query] [SnakeOil-encrypted body]
```

### Header (16 bytes)

```
Offset  Size  Field
0x00    1     Magic: 0x01
0x01    2     Signature: 0xC2 0xC2
0x03    1     Sub-type: 0x20 (RANDOM) or 0x30 (DEVICE)
0x04    8     Key: seed (RANDOM) or Code (DEVICE), little-endian
0x0C    1     Service minor version
0x0D    2     Reserved: 0x00 0x00
0x0F    1     Nonce
```

### Response Layout

```
[4B header] [SnakeOil-encrypted igo-binary payload]

Header: [0x01] [0x00] [0xC2] [0xBC]
Key: same random seed (RANDOM) or Secret (DEVICE)
```

### Flag Variants (DEVICE mode)

| Flags | Query Size | Body Layout |
|-------|-----------|-------------|
| `0x20` | 19 bytes | `SnakeOil(body, Secret)` |
| `0x60` | 2 bytes | `SnakeOil(body, Secret)` |
| `0x68` | 25 bytes | `SnakeOil(17B prefix, Secret)` + `SnakeOil(body, Secret)` — each fresh PRNG |

The `0x68` flag indicates a **delegated** request — the body is split-encrypted with the 17-byte delegation prefix encrypted separately from the main body, each with a fresh SnakeOil PRNG state using `tb_secret`.

Source: [`protocol.py`](../medianav_toolbox/protocol.py)

---

## Request Body Encoding

After SnakeOil decryption, request bodies use a simple wire codec format:

```
[0x80] [field1] [field2] ...
```

| Type | Encoding | Notes |
|------|----------|-------|
| String | `[length:1][utf8_bytes]` | No null terminator, no type tag |
| Int32 | `[4 bytes big-endian]` | No type tag |
| Int64 | `[8 bytes big-endian]` | No type tag |
| Byte | `[value:1]` | Single raw byte |
| Array | `[count:1][elements...]` | Count then inline elements |

**This is DIFFERENT from the response format** (which uses type-tagged, little-endian integers in an igo-binary container format).

### igo-binary Response Format (from Ghidra)

Responses use a container format with type tags:

| Type Tag | Encoding |
|----------|----------|
| `0x05` | String: `[0x05][data][0x00]` (null-terminated, no length prefix) |
| `0x01` | Int32: `[0x01][4B LE]` |
| `0x40` | Array header: `[0x40][2B count BE]` |
| `0xC0` | Container entry |

### Native Serializer Findings

We extracted the igo-binary serializer from Ghidra's decompiled `nngine.dll` output and built a native C reference implementation ([`analysis/native_serializer/serialize.c`](../analysis/native_serializer/serialize.c)). Key corrections to our Python encoder:

| Field | Old (wrong) | Correct |
|-------|------------|---------|
| String type | `0x07` | `0x05` |
| String format | `[type][len:LE32][data][0x00]` | `[type][data][0x00]` |
| Byte format | `[type:0x01][value]` | `[value]` (no type tag) |
| Int32 type | `0x03` | `0x01` |
| Array | header only | header + footer |

Source: [`wire_codec.py`](../medianav_toolbox/wire_codec.py), [`igo_serializer.py`](../medianav_toolbox/igo_serializer.py), [`analysis/native_serializer/PLAN.md`](../analysis/native_serializer/PLAN.md)

---

## Credential Block Encoding

The credential block is a 17-byte value included in authenticated requests to identify the device.

### Format

```
credential_block = 0xD8 || (Name XOR IGO_CREDENTIAL_KEY)
```

Where:
- `Name` = 16-byte device identifier (from registration or delegator response)
- `IGO_CREDENTIAL_KEY` = `6935b733a33d02588bb55424260a2fb5` (constant, extracted from DLL analysis)
- `0xD8` = presence bitmask header byte

### Discovery Process

The credential block encoding was one of the hardest parts to crack. The igo-binary format turned out to be a **bitstream** (not byte-level), using:
- Presence bits before each field
- Field IDs and type tags mixed into the bitstream
- Variable-length prefixes
- Descriptor chains (linked lists of field descriptors)

After extensive static analysis of the bitstream serializer (`FUN_101a9930`), we discovered the encoding is simply an XOR of the Name with a fixed key, prefixed by `0xD8`.

Source: [`igo_serializer.py`](../medianav_toolbox/igo_serializer.py), [`analysis/credential_encoding_notes.md`](../analysis/credential_encoding_notes.md)

---

## Delegation (0x68) Flow

The 0x68 flow sends device status using **delegated head unit credentials** rather than toolbox credentials. This asserts the head unit hardware identity to the server.

### What's Solved

| Component | Value | Status |
|-----------|-------|--------|
| Name₃ (delegation name) | `0xC4 \|\| hu_code(8B BE) \|\| tb_code(7B BE)` | ✅ Verified |
| Secret₃ (body encryption) | `tb_secret` | ✅ Verified |
| Split encryption | prefix(17B) + body, each fresh SnakeOil(tb_secret) | ✅ Verified |
| Prefix format | `0x86 \|\| HMAC-MD5(hu_secret_BE, serialized_credential)` | ✅ Format known |
| HMAC key | `hu_secret` (8 bytes, big-endian) | ✅ Verified via Win32 debugger |
| Query format | `[counter][0x68][D8 + Name₃ XOR IGO_KEY][extra 6B]` | ✅ Verified |

### What's NOT Solved (Blocking) — Updated 2026-04-21

~~The HMAC key and input format are **fully known** from Win32 debugger captures (run17). The remaining blocker is that the Python implementation has not been updated to match the captured data, and the 41-byte query envelope format needs to be correctly assembled.~~

**UPDATE: HMAC fully solved.** Both HMAC outputs verified. The "mystery device_id" was a misparse — codes are 64-bit, not 32-bit. The HMAC input is simply:

```
C4 + hu_code(8B big-endian) + tb_code(8B big-endian) + timestamp(4B big-endian) = 21 bytes
```

Verified against both captured HMACs from run17:
- HMAC #3: timestamp `0x69E7A25E` → `17 1B 86 4D 18 19 6D BB 58 67 A5 A0 E9 68 DB 84` ✅
- HMAC #4: timestamp `0x69E7A262` → `CC AE 22 77 CB AF 26 5B 63 15 DA 29 20 C2 B6 42` ✅

**Remaining:** Implement `build_delegation_prefix()` and wire up the 0x68 request in `session.py`.

### HMAC-MD5 Key and Input (VERIFIED ✅)

```
Key (8 bytes):  00 0E E8 7C 16 B1 E8 12
                = hu_secret (uint64, big-endian)

Input (21 bytes):
C4 [00 0B F2 85 69 BA CB 7C] [00 0D 4E A6 5D 36 B9 8E] [69 E7 A2 5E]
│   └─ hu_code (8B BE)         └─ tb_code (8B BE)          └─ timestamp
│      = 0x000BF28569BACB7C       = 0x000D4EA65D36B98E        (4B BE)
└─ flag byte (0xC4)
```

- Codes are **64-bit** integers (not 32-bit as previously assumed)
- `hu_code` and `tb_code` are the same values used in the wire protocol header
- First 17 bytes are device constants (same across sessions)
- Last 4 bytes are a big-endian Unix timestamp that changes per request
- **Both HMACs verified** against captured run17 data

### 41-Byte Query Plaintext (SnakeOil #252 / #331)

The complete 0x68 query, captured before SnakeOil encryption:

```
#252: 08 80 C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E 69 E7 A2 54 30 10 F2 50 3A 86 39 C4 99 51 D5 94 30 D4 AD C0 93 D0
#331: 08 80 C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E 69 E7 A2 62 30 10 CC AE 22 77 CB AF 26 5B 63 15 DA 29 20 C2 B6 42

Layout:
[08]     counter byte (increments per request)
[80]     flags/presence byte
[C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E]  Name₃ (17 bytes)
[69 E7 A2 54]  timestamp (4B BE) — same as HMAC input last 4 bytes
[30]     separator (0x30)
[10]     length of HMAC output (16 = 0x10)
[F2 50 3A 86 39 C4 99 51 D5 94 30 D4 AD C0 93 D0]  HMAC-MD5 output (16 bytes)
```

**Key insight:** Name₃ is NOT the HMAC output. Name₃ = `C4 || hu_code(4B BE) || tb_code(4B BE) || device_id(8B)` = the first 17 bytes of the HMAC input. The HMAC output is appended AFTER the timestamp.

### 58-Byte Envelope (SnakeOil #302)

The 0x68 request also has a 58-byte SnakeOil call that wraps the query + HMAC:

```
48 80 FB 86 AC D6 EB A8 F5 4A 93 C4 28 6C E0 77 D0 6C
80 C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E
69 E7 A2 5E 30 10 17 1B 86 4D 18 19 6D BB 58 67 A5 A0
E9 68 DB 84

Layout:
[48]     counter
[80]     flags
[FB 86 AC D6 EB A8 F5 4A 93 C4 28 6C E0 77 D0 6C]  credential block (16B)
[80]     separator
[C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E]  Name₃ (17B)
[69 E7 A2 5E]  timestamp (4B BE)
[30]     separator
[10]     HMAC length (16)
[17 1B 86 4D 18 19 6D BB 58 67 A5 A0 E9 68 DB 84]  HMAC output (16B)
```

### Bugs in Current Python Implementation (`test_0x68_fresh_hmac.py`)

The test code has **two critical bugs** that prevent it from generating valid 0x68 requests:

| Bug | Current Code | Correct (from captures) |
|-----|-------------|------------------------|
| **Code width** | `struct.pack(">Q", hu_code)` then `struct.pack(">Q", tb_code)` with 32-bit values | Codes ARE 64-bit — use the full `hu_code`/`tb_code` from credentials (not truncated) |
| **Wrong hu_code value** | Uses `hu_creds.code` which may be the 32-bit delegator code | Must use the full 64-bit `hu_code` = `0x000BF28569BACB7C` from the delegator response |

The correct `serialize_credential` is:

```python
def serialize_credential(hu_code, tb_code, timestamp):
    return (
        b'\xC4'
        + struct.pack(">Q", hu_code)      # 8 bytes (full 64-bit code)
        + struct.pack(">Q", tb_code)      # 8 bytes (full 64-bit code)
        + struct.pack(">I", timestamp)    # 4 bytes
    )
```

The "mystery device_id" was a misparse — the 8 bytes `00 0D 4E A6 5D 36 B9 8E` are simply `tb_code` as a full 64-bit big-endian integer. The earlier analysis incorrectly assumed codes were 32-bit and split the remaining bytes as a separate "device_id" field.

### What Remains To Implement

1. ~~**Identify the device_id source**~~ — **SOLVED**: it's `tb_code` as 8B BE (codes are 64-bit)
2. **Implement `build_delegation_prefix()`** — `0x86 + HMAC-MD5(hu_secret_8B, C4 + hu_code_8B + tb_code_8B + timestamp_4B)`
3. **Build the 41-byte query** — `[counter][0x80][Name₃(17B)][timestamp(4B)][0x30][0x10][HMAC(16B)]`
4. **Build the 58-byte envelope** — `[counter][0x80][cred_block(16B)][0x80][Name₃(17B)][timestamp(4B)][0x30][0x10][HMAC(16B)]`
5. **Wire it up with split encryption** — query encrypted with tb_code, prefix+body encrypted with tb_secret (separate PRNG instances)
6. **Test against live server**

### Why 0x68 Matters

Without 0x68, `managecontent` returns `norightsfordevice` and the catalog is empty. The 0x68 call grants content rights to the session. Free content works without 0x68 (confirmed on Windows Toolbox), but paid/premium content requires it.

Source: [`analysis/using-win32/README.md`](../analysis/using-win32/README.md), [`analysis/using-win32/hmac_log_run17.txt`](../analysis/using-win32/hmac_log_run17.txt)

---

## USB Drive Structure

The MediaNav head unit communicates with the Toolbox via a USB drive. The drive must have been previously synced with the head unit.

### Directory Layout

```
NaviSync/
├── license/              # DRM license files (.lyc), device identity
│   ├── device.nng        # Device identity (APPCID, encrypted)
│   ├── *.lyc             # Content licenses
│   ├── *.lyc.md5         # License checksums
│   └── .reg/             # Registration data
│       └── reg.sav       # Device keys, NaviExtras account link
├── content/
│   ├── map/              # Encrypted map data (.fbl, .fpa, .hnr)
│   ├── poi/              # Points of Interest (.poi)
│   ├── speedcam/         # Speed camera data (.spc)
│   ├── lang/             # Language packs
│   ├── voice/            # Voice guidance packs
│   ├── tmc/              # Traffic Message Channel data
│   └── userdata/POI/     # Dealer POIs (Renault, Dacia, Nissan)
├── save/                 # User settings, route history
├── device_status.ini     # Device capabilities and storage info
└── device_checksum.md5   # Integrity checksum
```

### Key Files

| File | Purpose |
|------|---------|
| `device.nng` | Device identity — contains APPCID (XOR-decoded), used for fingerprint MD5 |
| `device_status.ini` | INI file with device capabilities, storage, OS version |
| `device_checksum.md5` | MD5 of device state — Toolbox checks this to detect sync status |
| `.medianav_creds.json` | Cached registration credentials (Name/Code/Secret) |
| `reg.sav` | Registration data from `service_register_v1.sav` |
| `.stm` files | Metadata: `purpose=shadow` (on-device) or `purpose="copy"` (USB-delivered) |

### Device Identification

```
Brand:    Dacia
Model:    DaciaAutomotiveDeviceCY20_ULC4dot5
Software: iGO Primo by NNG, v9.12.179.821558
OS:       GNU/Linux 6.0.12.2.1166_r2
Display:  800x480
Storage:  ~4.4GB total, ~734MB free
```

Source: [`device.py`](../medianav_toolbox/device.py), [`device_status.py`](../medianav_toolbox/device_status.py), [`analysis/usb-images/report.md`](../analysis/usb-images/report.md)

---

## Map Data & Encryption

### File Types

| Extension | Purpose | Example |
|-----------|---------|---------|
| `.fbl` | Map geometry, road network, labels | `France_osm.fbl` (267MB) |
| `.fpa` | Address search data | `France_osm.fpa` (147MB) |
| `.hnr` | Historic speed profiles | `EuropeEconomic.hnr` (62MB) |
| `.poi` | Points of Interest | `UnitedKingdom_osm.poi` |
| `.spc` | Speed camera locations | `France_osm.spc` |
| `.lyc` | DRM license files | RSA 2048-bit + XOR-CBC encrypted |

### Encryption Status

Map data files are **fully encrypted** by NNG:
- Shannon entropy: 7.98/8.0 bits per byte (99.79%) — indistinguishable from random
- All `.fbl`/`.fpa` files share magic: `f9 6d 4a 16 6f c5 78 ee`
- `.hnr` files use different magic: `e2 66 4c 50 34 c2 7f ce`
- **Cannot be decoded** — NNG proprietary encryption tied to device licensing

### .lyc License Decryption (Solved)

`.lyc` files use RSA 2048-bit (e=65537) + XOR-CBC. The public key was extracted from the DLL. This allows reading license metadata but not generating new licenses.

Source: [`analysis/usb-images/report.md`](../analysis/usb-images/report.md)

---

## Reverse Engineering Approaches

### Approach 1: DLL Injection Hook ❌ FAILED

**Concept:** Inject a DLL into the running Toolbox process that patches `SnakeOil`/`HMAC_MD5` with a `push addr; ret` trampoline, redirecting to a hook function that logs arguments.

**Implementation:**
- `hook_dll.c` — Injectable DLL: `DllMain` spawns thread, finds nngine.dll, saves original bytes, writes trampoline
- `injector2.c` — DLL injector: finds PID via `CreateToolhelp32Snapshot`, `VirtualAllocEx` + `WriteProcessMemory`, `CreateRemoteThread` calling `LoadLibraryA`

**Why it failed:**
1. **Timing** — Hook was injected AFTER the Toolbox had already made its API calls during startup. Both SnakeOil and HMAC_MD5 are called during the initial login flow, which completes before injection.
2. **DLL path accessibility** — Toolbox runs as `mark`, injector runs as `Administrator`. Fixed by placing DLL in `C:\temp\` with `Everyone:(R)`.
3. **Process restart** — Each restart required re-injection.

### Approach 2: Attach Debugger ❌ FAILED

**Concept:** Use `DebugActiveProcess()` to attach to the running Toolbox and set INT3 breakpoints.

**Implementation:**
- `dbg_snakeoil.c` / `dbg2.c` — Finds PID, attaches, writes `0xCC` at breakpoints, handles `EXCEPTION_BREAKPOINT` events

**Why it failed:**
1. **Same timing problem** — Attaching after startup means functions already called.
2. **Leftover INT3** — Killing the debugger with `taskkill` left `0xCC` bytes in the target process, causing crashes on subsequent calls.
3. **Session 0 vs Session 1** — Debugger via SSH runs in Session 0 (Services), can't interact with Session 1 (Console) Toolbox.

### Approach 3: Launch Under Debugger ✅ SUCCESS

**Concept:** Use `CreateProcess` with `DEBUG_ONLY_THIS_PROCESS` flag to launch the Toolbox as a child of the debugger. Control from the very first instruction.

**Implementation:** `dbg_launch2.c` / `dbg_launch3.exe`

```c
CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
               DEBUG_ONLY_THIS_PROCESS, NULL,
               "C:\\Program Files (x86)\\DaciaAutomotive\\Toolbox4",
               &si, &pi);
```

**Key design decisions:**
- `DEBUG_ONLY_THIS_PROCESS` (not `DEBUG_PROCESS`) — avoids debugging CEF child processes
- Working directory set to Toolbox install dir so it finds its DLLs
- Polls for nngine.dll via `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` between debug events
- Sets breakpoints as soon as nngine.dll is detected, before any functions are called
- **Must be run from interactive cmd window** (not SSH) so Toolbox gets a GUI

**Debug event loop:**
```
WaitForDebugEvent (100ms timeout)
  → EXCEPTION_BREAKPOINT: read stack args, log, restore byte, single-step
  → EXCEPTION_SINGLE_STEP: re-write INT3
  → Other: ContinueDebugEvent with DBG_EXCEPTION_NOT_HANDLED
  → Timeout: poll for nngine.dll if not yet found
```

**Results:**
- **146+ SnakeOil calls** captured with full key arguments
- **5 HMAC_MD5 calls** captured with 8-byte key and 21-byte input data
- Confirmed consistent across two independent runs

### Approach 4: Unicorn CPU Emulation (Partial)

**Concept:** Use Unicorn Engine to emulate specific nngine.dll functions in isolation, feeding known inputs and capturing outputs.

**Used for:**
- Tracing the igo-binary bitstream serializer (`FUN_101a9930`)
- Verifying HMAC-MD5 implementation matches DLL output
- Tracing credential block encoding

**Limitations:**
- Cannot emulate the full device manager runtime state
- The `DelegationRO` descriptor has 6 fields but Unicorn only populates 4
- Real credential has additional fields from runtime state not available in static analysis

**Scripts:** [`analysis/unicorn_*.py`](../analysis/) (7 scripts for different emulation targets)

### Approach 5: Native C Serializer Extraction ✅ SUCCESS

**Concept:** Extract the igo-binary serializer from Ghidra's decompiled output, convert to compilable C, compare byte-for-byte with Python encoder.

**Result:** Found 4 key differences between native and Python encoding. Fixed Python encoder to match native output exactly. All 113 tests pass.

Source: [`analysis/native_serializer/`](../analysis/native_serializer/), [`analysis/native_serializer/PLAN.md`](../analysis/native_serializer/PLAN.md)

### Approach 6: mitmproxy Traffic Capture (Supplementary)

**Concept:** HTTPS proxy to capture wire-level traffic between Toolbox and server.

**Setup:** mitmproxy on Windows VM with WinHTTP + WinINET proxy settings, CA cert installed in trusted root store.

**Limitations:**
- Causes intermittent "server closed connection" errors
- Must use `--ignore-hosts` to filter Microsoft/Google background traffic
- Session 0 instances use different CA keys, causing cert errors
- **Recommendation:** Use the debugger instead — captures plaintext before encryption

Source: [`analysis/using-win32/HOWTO.md`](../analysis/using-win32/HOWTO.md)

---

## Win32 Debugging Environment

All dynamic analysis was performed on a Windows 10 VM running under QEMU with KVM acceleration.

### QEMU VM

```bash
qemu-system-x86_64 -enable-kvm -m 4G -smp 2 \
  -drive file="NewWin10.qcow2",format=qcow2 \
  -net nic -net user,hostfwd=tcp::2222-:22,hostfwd=tcp::5678-:5678 \
  -vga virtio \
  -usb -device usb-ehci -device usb-host,vendorid=0x0951,productid=0x1666
```

- USB passthrough for the Kingston USB stick (physical device passed to VM)
- Port 2222 → SSH, Port 5678 → debugging
- VM disk converted from VirtualBox qcow2

### SSH Access

Win32-OpenSSH installed from GitHub releases. Built-in Administrator account activated (Microsoft account `mark` couldn't have password set via `net user`).

```
Host qemuwin
    HostName localhost
    Port 2222
    User Administrator
    ControlMaster auto
    ControlPath /tmp/ssh-%r@%h:%p
    ControlPersist 600
```

### Compiler: Tiny C Compiler (TCC)

No mingw32 cross-compiler available on Linux host (only mingw64). TCC installed directly on Windows VM at `C:\temp\tcc\tcc\tcc.exe` (32-bit, produces PE32).

**TCC limitations:** No `tlhelp32.h` (inlined structs), no `DebugSetProcessKillOnExit` (resolved via `GetProcAddress`), no `CP_ACP` (used literal `0`).

### Tools Built on VM

| File | Purpose |
|------|---------|
| `dbg_launch3.exe` | **Launch debugger — the one that works** |
| `hook_dll.dll` | Injectable DLL hooking SnakeOil (approach 1, failed) |
| `hook_hmac.dll` | Injectable DLL hooking HMAC_MD5 (approach 1, failed) |
| `injector2.exe` | DLL injector (approach 1, failed) |
| `dbg_snakeoil.exe` | Attach debugger (approach 2, failed) |
| `dbg2.exe` | Multi-breakpoint attach debugger (approach 2, failed) |
| `wrapper.exe` | Interactive CLI wrapper for nngine.dll exports |
| `check_hook.exe` | Reads process memory to verify hook bytes |

### Captured Data

| File | Description |
|------|-------------|
| `hmac_log_run*.txt` | HMAC_MD5 + SnakeOil capture logs (17 runs) |
| `snakeoil_body_*.bin` | Plaintext bodies >256 bytes |
| `flows_*apr*.json` | mitmproxy flow captures |
| `*_req.bin` / `*_resp.bin` | Raw binary request/response bodies |

### Lessons Learned

1. **Timing matters for hooking** — Functions called during startup cannot be hooked by attaching to a running process. Must launch target under debugger.
2. **`DEBUG_ONLY_THIS_PROCESS` vs `DEBUG_PROCESS`** — CEF apps spawn many child processes. `DEBUG_PROCESS` overwhelms the debugger. Use `DEBUG_ONLY_THIS_PROCESS`.
3. **DLL load event names are unreliable** — `LOAD_DLL_DEBUG_EVENT.lpImageName` is often NULL. Poll with `CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)` instead.
4. **xdotool can't type backslashes** into QEMU windows. Use SSH for all command execution.
5. **Session 0 vs Session 1** — SSH/WMIC processes run in Session 0 with no desktop. GUI apps must be launched from interactive session.
6. **Clean debugger detach** — Always restore original bytes. Killing debugger leaves INT3 bytes causing crashes.
7. **Zscaler** — Security agent on VM kept interfering. Disabled services and eventually uninstalled.

Source: [`analysis/using-win32/README.md`](../analysis/using-win32/README.md), [`analysis/using-win32/HOWTO.md`](../analysis/using-win32/HOWTO.md)

---

## Engineering Log

### Phase 1: Static Analysis & Protocol Basics (Apr 11–14)

- Extracted `DaciaMediaNavEvolutionToolbox-inst.exe` (115MB NSIS installer)
- Decompiled `nngine.dll` with Ghidra → `nngine_decompiled.c` (15MB, ~500K lines)
- Decompiled `plugin.dll` and main exe
- Identified SnakeOil cipher at RVA `0x1B3E10` — reversed xorshift128 PRNG
- Cracked wire protocol format: 16-byte header + encrypted query + encrypted body
- Discovered RANDOM vs DEVICE authentication modes
- Built initial Python library: `crypto.py`, `protocol.py`, `igo_parser.py`
- Captured traffic via mitmproxy — decoded boot, register, login flows
- Extracted Blowfish key for `http_dump` XML decryption
- Created USB drive backup and analysis (`disk-backup-with-map-Apr2026.zip`, 3.1GB)
- Discovered map files are fully encrypted (Shannon entropy 7.98/8.0)

### Phase 2: Credential Block & Registration (Apr 14–16)

- Spent days on credential block encoding — the igo-binary bitstream serializer
- Discovered format is a **bitstream** (not byte-level) with presence bits, field IDs, type tags
- Built Unicorn CPU emulation scripts to trace the serializer
- **Breakthrough:** credential block = `0xD8 || (Name XOR IGO_CREDENTIAL_KEY)`
- Verified against live server — server accepts generated credential blocks
- Implemented full registration flow: boot → register → login → fingerprint → getprocess
- All returning HTTP 200 from live server
- Built native C serializer from Ghidra output, found 4 encoding differences, fixed Python

### Phase 3: Delegation & Device Status (Apr 16–19)

- Implemented delegator endpoint — returns head unit credentials (hu_name/hu_code/hu_secret)
- Solved 0x60 senddevicestatus body generation from USB file scan
- Discovered 0x68 split encryption: prefix(17B) + body, each fresh SnakeOil(tb_secret)
- Identified Name₃ = `0xC4 || hu_code(8B BE) || tb_code(7B BE)` (direct concatenation)
- Built multiple brute-force tools in C: `brute_fast`, `brute_multi`, `brute_parallel`, `brute_ts`, `brute_d8`, `brute_0x44`
- Exhaustive search across 5 formats × 2³² timestamps with 4 threads: **no HMAC match**
- Attempted Wine harness to run nngine.dll on Linux — failed (32-bit DLL, complex dependencies)
- Built Docker harness with extracted .so libraries — failed (ARM libraries, not x86)

### Phase 4: Win32 Dynamic Analysis (Apr 19–21)

- Set up QEMU Windows 10 VM with KVM acceleration
- Installed Win32-OpenSSH, TCC compiler, mitmproxy on VM
- **Approach 1 (DLL injection): FAILED** — timing issue, functions called before hook installed
- **Approach 2 (attach debugger): FAILED** — same timing, leftover INT3 bytes
- **Approach 3 (launch under debugger): SUCCESS** — 146+ SnakeOil calls, 5 HMAC_MD5 calls captured
- Confirmed HMAC-MD5 key (8 bytes) and input format (21 bytes) across two independent runs
- Captured 17 debug runs with increasing detail (run1 through run17)
- Discovered service minor for register endpoints = **14** (not 1)
- Fixed licenses endpoint — returns .lyc data when session matches
- Implemented license installation to USB drive
- Reached 219 unit tests, all passing
- **Run17 breakthrough:** Captured full 0x68 flow including download (44617B body)
  - HMAC #3: key=`00 0E E8 7C 16 B1 E8 12`, input=21B, output=`17 1B 86 4D...`
  - HMAC #4: key=same, input=21B (different timestamp), output=`CC AE 22 77...`
  - SnakeOil #252/#331: 41B query plaintext showing Name₃ + timestamp + HMAC output
  - SnakeOil #302: 58B envelope plaintext showing credential block + Name₃ + HMAC
  - SnakeOil #303: 2160B body, #332: 44617B body (full device status with download)
- **Identified 3 bugs in Python test code:** wrong code width (8B vs 4B), missing device_id, wrong HMAC input length
- **Remaining blocker:** device_id identification (8 bytes in HMAC input) and Python implementation update

### Phase 5: HMAC Solved, Delegation Trigger Investigation (Apr 21 evening)

- **"device_id" mystery solved:** The 8 bytes `00 0D 4E A6 5D 36 B9 8E` are simply `tb_code` as a full 64-bit big-endian integer. Credential codes are uint64, not uint32. The earlier analysis incorrectly split the HMAC input as `C4 + hu_code(4B) + tb_code(4B) + device_id(8B) + timestamp(4B)` when it's actually `C4 + hu_code(8B) + tb_code(8B) + timestamp(4B)`.
- **Both HMACs verified:** `HMAC-MD5(hu_secret_8B, C4 + hu_code_8B + tb_code_8B + ts_4B)` matches both captured run17 outputs byte-for-byte.
- **16 new unit tests pass**, 235 total tests pass, zero regressions.
- **Live 0x68 still returns 409** — but this is NOT an HMAC problem. Even exact replay of captured wire bytes returns 409 in a new session (confirmed Apr 19).

#### What Triggers the 0x68 Delegation Flow?

Compared runs with and without delegation:

| Run | Delegation? | What happened |
|-----|------------|---------------|
| Run 11 | ❌ | Fresh USB, no updates available. Flow: `login → sds(0x60) → fingerprint → licinfo → sds(0x28)` |
| Run 12 | ❌ | Same USB, 9 sessions. Same flow as run 11. |
| Run 12b | ✅ | User clicked "download" on RenaultDealers_Pack in catalog UI. Flow: `login → sds(0x60) → delegator → sds(0x68) → licenses` |
| Run 15 | ❌ | After download, USB has .lyc. Server doesn't offer it again. |
| Run 17 | ✅ | Full download flow with content install. Multiple 0x68 calls. |

**Key findings:**

1. **The 0x60 response is IDENTICAL (88B) in both delegation and no-delegation runs.** The server does NOT signal delegation via the 0x60 response. Both have `presence2=0x80, flags=0000`.

2. **The DLL computes the HMAC proactively** after processing the delegator response, before even sending the 0x60. The delegation is prepared as soon as delegator credentials are available.

3. **The trigger is the web UI content selection.** `managecontent.js` has a jstree checkbox UI that POSTs selected content IDs to the server. When the user selects content to download, this triggers the delegation flow inside nngine.dll.

4. **The `/event/` polling endpoint** returns `RELOAD`, `FILE`, and `PROGRESS` events. The web UI polls this at 5-second intervals. The `FILE` event type may be how nngine.dll signals the web UI that content transfer is happening.

5. **The `/mds/` endpoint** returns device state, and `/ass/` returns agent state. The web UI uses these to navigate between pages (device detection → catalog → download progress).

#### Why Our Python 0x68 Gets 409

Our Python code sends the 0x68 during session setup, before any catalog interaction. The server rejects it because **no content download has been requested**. The 0x68 is not a session setup step — it's part of the content delivery flow that happens AFTER the user selects content in the web UI.

The flow should be:
```
1. Session setup: boot → login → fingerprint → sds(0x60) → delegator
2. Web login: POST /toolbox/login
3. Catalog browse: GET /toolbox/cataloglist (or /toolbox/managecontent)
4. Content selection: POST selected content IDs (jstree checkbox)
5. THEN: sds(0x68) → licenses → content transfer
```

We're doing step 5 immediately after step 1, skipping steps 2-4.

#### Next Steps

1. **Investigate the HU device registration** — `register_hu_device` returns 409 (already registered). The server may require the HU device to be registered with credentials that match the delegation Name₃. The real Toolbox may have registered the HU device during initial setup, and our Python tool inherited different credentials.
2. **Compare the delegator response** — the delegator returns hu_name/hu_code/hu_secret. These must match what the server expects in the 0x68 Name₃. If the server has a different HU registration than what the delegator returns, the 0x68 will be rejected.
3. **Try on the Win32 VM** — run the Toolbox with the debugger and capture the EXACT sequence of API calls, including any registration calls we might be missing.

#### 2026-04-21 19:45 — Flow Reordering Tests: Still 409

Tested the hypothesis that 0x68 needs to come after web login + catalog browse:

| Test | Description | Result |
|------|-------------|--------|
| 0x68 after web login + catalog browse | Full web flow before 0x68 | 409 |
| 0x68 with correct extra bytes (0x55 format) | igo-binary sub-structure | 409 |
| 0x68 without prefix segment | No 17B HMAC prefix | 409 |
| 0x20 with Name₃ credential block | Standard DEVICE mode, no delegation | 409 |

**Critical finding:** Even a standard 0x20 request with the Name₃ credential block returns 409. The server rejects the **Name₃ credential itself**, not the HMAC or the flow ordering. The server doesn't recognize the delegation credential.

**Wire format comparison** against captured working request:
- Header: ✅ identical
- Query credential block: ✅ identical (D8 + Name₃[:16] XOR IGO_KEY)
- Body: ✅ identical
- Extra 6 bytes: different (ours `8E 69 E7...` vs captured `55 BD E2...`) but confirmed NOT the cause
- Prefix HMAC: different timestamps but format correct

**Root cause hypothesis:** The server associates the delegation credential (Name₃) with a specific HU device registration. Our `register_hu_device()` returns 409 (already registered), meaning the server already has an HU device registration from the original Windows Toolbox. The delegator returns credentials that match that registration. But the server may require the 0x68 to come from the SAME session/client that performed the original HU registration — which was the Windows Toolbox, not our Python tool.

**The real blocker is not the HMAC, not the flow order, not the extra bytes — it's the server-side association between the HU device registration and the session.**

### Failed Approaches Summary

| Approach | Why It Failed | Worth Retrying? |
|----------|--------------|-----------------|
| DLL injection | Functions called during startup, before hook installed | No — superseded by launch debugger |
| Attach debugger | Same timing issue + leftover INT3 bytes crash target | No — superseded by launch debugger |
| Wine harness (Linux) | 32-bit DLL with complex Win32 dependencies | No — data already captured |
| Docker + .so libraries | ARM libraries extracted from Android APK, not x86 | No — wrong architecture |
| Brute-force HMAC | Wrong input format: used 8B codes, missing device_id | **Yes** — verify with correct 21B format |
| Unicorn emulation (full) | Cannot replicate device manager runtime state | No — data already captured |
| Deleting USB files for fresh sync | Toolbox tracks state via checksums, shows "please sync with car" | No — requires real head unit |
| Python `test_0x68_fresh_hmac.py` | 3 bugs: wrong code width, missing device_id, wrong input length | **Yes — top priority** |

---

## Source File Reference

### Core Library (`medianav_toolbox/`)

| File | Purpose |
|------|---------|
| [`crypto.py`](../medianav_toolbox/crypto.py) | SnakeOil xorshift128 cipher, Blowfish ECB |
| [`protocol.py`](../medianav_toolbox/protocol.py) | Wire protocol envelope (16B header + encryption) |
| [`wire_codec.py`](../medianav_toolbox/wire_codec.py) | Request body encoder (strings, ints, arrays) |
| [`igo_parser.py`](../medianav_toolbox/igo_parser.py) | igo-binary response parser |
| [`igo_serializer.py`](../medianav_toolbox/igo_serializer.py) | Credential block encoder |
| [`session.py`](../medianav_toolbox/session.py) | Full session flow orchestration |
| [`device.py`](../medianav_toolbox/device.py) | USB drive detection, device.nng parsing |
| [`device_status.py`](../medianav_toolbox/device_status.py) | Device status INI parsing |
| [`catalog.py`](../medianav_toolbox/catalog.py) | HTML catalog + content tree parsers |
| [`content.py`](../medianav_toolbox/content.py) | Content selection + size estimation |
| [`download.py`](../medianav_toolbox/download.py) | Download manager with cache + MD5 verify |
| [`installer.py`](../medianav_toolbox/installer.py) | USB content writer (.stm, .lyc, checksums) |
| [`cli.py`](../medianav_toolbox/cli.py) | Click CLI (detect, login, catalog, licenses, sync) |
| [`auth.py`](../medianav_toolbox/auth.py) | Credential loading from .env |
| [`config.py`](../medianav_toolbox/config.py) | Brand defaults from plugin.dll |
| [`fingerprint.py`](../medianav_toolbox/fingerprint.py) | Device fingerprint encoding |
| [`swid.py`](../medianav_toolbox/swid.py) | SWID generation (MD5 + Crockford base32) |
| [`models.py`](../medianav_toolbox/models.py) | Data classes (DeviceInfo, Credentials, etc.) |

### API Layer (`medianav_toolbox/api/`)

| File | Purpose |
|------|---------|
| [`boot.py`](../medianav_toolbox/api/boot.py) | Service URL discovery |
| [`client.py`](../medianav_toolbox/api/client.py) | HTTP client with retry and cookies |
| [`register.py`](../medianav_toolbox/api/register.py) | Device registration + delegator |
| [`market.py`](../medianav_toolbox/api/market.py) | Login, fingerprint, device status |
| [`igo_binary.py`](../medianav_toolbox/api/igo_binary.py) | igo-binary type encoders + boot decoder |
| [`catalog.py`](../medianav_toolbox/api/catalog.py) | Catalog API wrapper |

### Analysis (`analysis/`)

| File/Dir | Purpose |
|----------|---------|
| [`using-win32/README.md`](../analysis/using-win32/README.md) | Win32 debugging — full writeup |
| [`using-win32/HOWTO.md`](../analysis/using-win32/HOWTO.md) | QEMU VM setup guide |
| [`credential_encoding_notes.md`](../analysis/credential_encoding_notes.md) | Credential block analysis |
| [`native_serializer/`](../analysis/native_serializer/) | Native C serializer from Ghidra |
| [`usb-images/report.md`](../analysis/usb-images/report.md) | USB drive analysis |
| `unicorn_*.py` | Unicorn CPU emulation scripts (7 files) |
| `brute_*.c` | Brute-force HMAC search tools (8 files) |
| `trace_creds.c` | Win32 credential tracing tool |
| `nngine_decompiled.c` | Full Ghidra decompilation (15MB) |
| `flows/` | mitmproxy flow captures |
| `flows_decoded/` | Decoded flow responses |
| `http_dump_decrypted/` | Decrypted XML request/response pairs |

---

## Remaining Work

### R.11: Delegated senddevicestatus — STATUS: SOLVED ✅

**Fully implemented and verified.** `build_dynamic_request()` in `protocol.py` generates
complete wire requests from credentials + plaintext body. Verified byte-exact against
captured run25 wire data (24 tests in `test_dynamic_wire.py`).

See `docs/chain-encryption.md` for the complete payload construction recipe.

### R.12: Session Key Derivation — STATUS: SOLVED ✅

The session key is `creds.secret` — the toolbox Secret from device registration.

Ghidra analysis of `FUN_100b3a60`: in DEVICE mode (mode 3), the SnakeOil key is
read from `credential_obj[0x1c:0x24]` (the Secret field). For delegated requests,
this is the toolbox credential's Secret. Verified: `creds.secret = 0x000ACAB6C9FB66F8`
matches all captured SnakeOil calls.

No hardcoding needed — every device gets its own `creds.secret` at registration.

### R.13: session.py Integration — STATUS: OPEN

`_send_device_status()` in `session.py` still uses the old replay approach with
captured chain bodies. Needs to be updated to use `build_dynamic_request()`.

### R.14: Live Server 409s — STATUS: SOLVED ✅

Root cause: a single wrong byte in `_encode_e0_entry` in `device_status.py`.
The sub-marker between content MD5 and file MD5 was `0x0A` instead of `0x08`.
The server validates this marker and rejects the entire request if wrong.

Also fixed: file ordering (device.nng before .lyc files) and mount path
(defaults to `E:\` to match the Windows Toolbox).

senddevicestatus now returns 200 from the live server.

#### 2. Unicorn CPU Emulation ❌ (Partial success)

**What:** Emulate specific nngine.dll functions in Unicorn Engine on Linux, feeding known inputs.

**Tools:** `unicorn_harness.py`, `unicorn_serialize.py`, `unicorn_serialize2.py`, `unicorn_serialize3.py`, `unicorn_regflow.py`, `unicorn_regflow2.py`, `unicorn_regflow3.py`, `unicorn_trace_secret.py`, `unicorn_inner_cred.py`, `unicorn_trace_reads.py`, `unicorn_trace_writes.py`

**What worked:** Successfully traced the igo-binary bitstream serializer, verified HMAC-MD5 implementation, traced credential block encoding. Discovered the `0xD8 || (Name XOR IGO_CREDENTIAL_KEY)` format.

**Why it failed for 0x68:** The `DelegationRO` descriptor has 6 fields but Unicorn could only populate 4. The remaining 2 fields come from the device manager runtime state (singleton object, credential store, timer) which cannot be replicated in static emulation.

**Worth retrying?** **NO** — the Win32 debugger already captured the exact data. Unicorn emulation is no longer needed for this problem.

#### 3. Wine Harness (Linux) ❌

**What:** Run nngine.dll directly on Linux using Wine, calling the serializer functions.

**Tools:** `wine_harness.c`, `Dockerfile.wine32`, `wine32-entrypoint.sh`

**Why it failed:** nngine.dll is a 32-bit PE32 DLL with complex Win32 dependencies (WinHTTP, CRT, COM). Wine couldn't resolve all imports. The 32-bit Wine prefix had missing libraries.

**Worth retrying?** **NO** — same reason as Unicorn. Data already captured.

#### 4. Docker + ARM .so Libraries ❌

**What:** Extract shared libraries from the Android version of the NNG app and run them in Docker.

**Tools:** `docker_harness/Dockerfile`, extracted `.so` files (`liblib_nng_sdk.so`, `liblib_memmgr.so`, `liblib_base.so`, `libc++_shared.so`)

**Why it failed:** The extracted libraries are ARM architecture (from Android APK), not x86. Cannot run on x86 Docker.

**Worth retrying?** **NO** — wrong architecture, and data already captured.

#### 5. DLL Injection Hook ❌

**What:** Inject a DLL into the running Toolbox process to hook SnakeOil/HMAC_MD5.

**Tools:** `hook_dll.c`, `hook_hmac.dll`, `injector2.c`

**Why it failed:** Timing — functions are called during startup before the hook can be installed. The Toolbox completes its login/registration flow before injection.

**Worth retrying?** **NO** — superseded by the launch-under-debugger approach.

#### 6. Attach Debugger ❌

**What:** Use `DebugActiveProcess()` to attach to the running Toolbox.

**Tools:** `dbg_snakeoil.c`, `dbg2.c`

**Why it failed:** Same timing issue as DLL injection. Also, killing the debugger left INT3 bytes in the target process, causing crashes.

**Worth retrying?** **NO** — superseded by the launch-under-debugger approach.

#### 7. Launch Under Debugger ✅ SUCCESS

**What:** Use `CreateProcess` with `DEBUG_ONLY_THIS_PROCESS` to launch the Toolbox as a child of the debugger.

**Tools:** `dbg_launch2.c` / `dbg_launch3.exe`

**Result:** Captured 334+ SnakeOil calls and 4 HMAC_MD5 calls with full arguments. The HMAC key, input, and output are now known. The 41-byte and 58-byte query plaintexts are captured.

**Status:** This approach WORKED and provided all the data needed to implement 0x68.

#### 8. Deleting USB Files for Fresh Sync ❌

**What:** Delete `.reg/reg.sav`, `.stm`, `.lyc.md5` files from USB to make Toolbox treat it as fresh.

**Why it failed:** Toolbox checks `device_checksum.md5`, `device_status.ini`, and content checksums. Shows "please sync with car" and never reaches device detection. Zero senddevicestatus or delegator calls.

**Worth retrying?** **NO** — requires a real head unit sync to reset state.

#### 9. Python `test_0x68_fresh_hmac.py` ❌ (Fixable)

**What:** Generate fresh HMAC and send 0x68 request from Python.

**Why it failed:** Three bugs in the implementation:
1. Uses `struct.pack(">Q")` (8 bytes) for codes instead of `struct.pack(">I")` (4 bytes)
2. Missing device_id (8 bytes) from HMAC input
3. Query assembly doesn't match the captured 41-byte format

**Worth retrying?** **YES — this is the next step.** Fix the three bugs and test against live server. The data is now fully known.

---

### Approaches Worth Retrying (Priority Order)

#### Priority 1: Fix Python HMAC Implementation

The captured data from run17 gives us everything needed. Steps:

1. Verify HMAC output matches: compute `HMAC-MD5(key=00 0E E8 7C 16 B1 E8 12, data=C4 00 0B F2 85 69 BA CB 7C 00 0D 4E A6 5D 36 B9 8E 69 E7 A2 5E)` and confirm output = `17 1B 86 4D 18 19 6D BB 58 67 A5 A0 E9 68 DB 84`
2. Identify device_id source (the 8 bytes `00 0D 4E A6 5D 36 B9 8E`)
3. Fix `serialize_credential()` with correct packing
4. Build 41-byte query and 58-byte envelope
5. Test with split encryption against live server

#### Priority 2: Identify device_id Field

The 8 bytes `00 0D 4E A6 5D 36 B9 8E` appear in the HMAC input between tb_code and timestamp. Candidates:
- `tb_code` as 8-byte little-endian: `tb_code = 0x69BACB7C` → LE = `7C CB BA 69 00 00 00 00` — **doesn't match**
- Registration Name field (16 bytes, first 8?): check `.medianav_creds.json`
- Device APPCID from `device.nng`
- A hash of device identity data
- The `uniq_id` from registration

This is the last unknown. Once identified, the full 0x68 flow can be implemented.

### Sync Pipeline

Once 0x68 is solved:
- Wire up `medianav-toolbox sync` command
- Content download via `getprocess` tasks
- Full install pipeline: download → verify → write to USB → update checksums

### Open Research Questions

- **R.4** — Imei field encoding (`x51x4Dx30x30x30x30x31`)
- **R.7** — Is `IGO_CREDENTIAL_KEY` the same for all devices?
- ~~**R.12** — What is the device_id (8 bytes `00 0D 4E A6 5D 36 B9 8E`) in the HMAC input?~~ **SOLVED**: it's `tb_code` as 8B BE — codes are 64-bit integers

#### 2026-04-21 19:55 — Flow Analysis from run4 Captures: Flow Order is NOT the Issue

Parsed `flows_20apr_run4.json` (975 flows, 556 NaviExtras API calls, 5 sessions).

**Session 1 (WITH delegation, 0x68 works):**
```
#1   selfie/update
#2   licinfo (36B→14B)           ← BEFORE login!
#3   login (105B→397B)
#6   hasActivatableService
#7   sendfingerprint (53KB)
#175 senddevicestatus (1479B→247B)  ← 0x60, 247B response (has device identity)
#178 delegator (190B→179B)
#179 senddevicestatus (1486B→88B)   ← 0x68, 200 OK ✅
#180 licinfo (36B→14B)
#181 licinfo (76B→146B)
#182 licenses (193B→3733B)
#183 senddevicestatus (1939B→248B)
#184 sendfingerprint (46KB)
#185 sendfilecontent (311B)
```

**Session 4 (NO delegation):**
```
#369 login
#373 hasActivatableService
#374 senddevicestatus (1922B→88B)   ← 0x60, only 88B response (no device identity)
#409 sendfingerprint
#410 licinfo (76B→146B)
#414 senddevicestatus (227B→248B)
```

**Key observations:**
1. The Toolbox sends 0x68 **immediately after delegator** — same as our Python code. Flow ordering is NOT the issue.
2. The 0x60 response size differs: **247B** (with device identity) triggers delegation, **88B** (ACK only) does not.
3. Our Python code gets the 247B response — the server IS ready for delegation.
4. The Toolbox calls `licinfo (36B)` BEFORE login in session 1 — we don't do this.
5. No `get_device_descriptor_list` in the first session.
6. The 0x68 request is 1486B (same as our captured reference).

**Conclusion:** The flow order matches. The server accepts our 0x60 and returns the delegation-ready 247B response. The 409 on 0x68 must be caused by the request content itself — either the wire format details or the credential association. Need to do a byte-level comparison of our generated 0x68 against the captured working one, focusing on the encrypted wire bytes.


#### 2026-04-21 20:05 — BREAKTHROUGH: 0x60 with delegation body returns 200

Decoded ALL `.bin` files in `analysis/using-win32/`. Critical discovery: **every Toolbox senddevicestatus uses 0x68 flags** — even runs 11/12 that we thought had "no delegation." The Toolbox ALWAYS uses 0x68 and always gets 200.

Tested every possible cause of the 409:
- Exact captured wire bytes replayed in our session: **409**
- Raw TLS socket with identical headers: **409**
- SSE connection open: **409**
- Toolbox agent version in login: **409**
- Exact Toolbox flow order (selfie → licinfo → login → ...): **409**
- Login response structure: **identical** to Toolbox (393B, same fields)

Then tested flag variants with the same body:

| Test | Flags | Body | Result |
|------|-------|------|--------|
| A | 0x68 + single stream | delegation body | 409 |
| B | 0x68 + no prefix | delegation body | 409 |
| C | 0x68 + separate streams | delegation body | 409 |
| **D** | **0x60** | **delegation body** | **200 ✅** |

**The server rejects the 0x68 FLAG itself from our session, not the body content.** The same body with 0x60 flags returns 200. The Toolbox's session has a server-side privilege for 0x68 that our session doesn't have.

This is likely tied to the original HU device registration performed by the Windows Toolbox. Our `register_hu_device()` returns 409 (already registered) — we can't establish fresh delegation credentials.

**Workaround: use 0x60 flags for all senddevicestatus calls.** The delegation body content (byte1=0x03, with HU identity data) is accepted via 0x60. The 0x68 flag may only be needed for the server to associate the HU device with the session — but if 0x60 with the delegation body achieves the same result, we don't need 0x68 at all.

**Next steps:**
1. Test if 0x60 with the delegation body grants content rights (check managecontent page)
2. If yes, remove the 0x68 code path entirely and use 0x60 for everything
3. If no, investigate what server-side state the 0x68 flag establishes that 0x60 doesn't


#### 2026-04-21 20:10 — 0x60 workaround: body accepted but no content rights

Tested 0x60 with delegation body (byte1=0x03): server returns 200.
But `managecontent` returns 500 (GlassFish error) and `cataloglist` has 0 content items.
Licenses endpoint works (10 entries) but those work without delegation too.

The 0x60 flag doesn't establish the delegation context that the content tree needs.
The 0x68 flag is specifically what grants content rights on the server side.

**Current status:**
- HMAC: ✅ fully solved and verified
- Wire format: ✅ matches captured traffic byte-for-byte
- Body content: ✅ accepted by server via 0x60
- 0x68 flag: ❌ server rejects from our session (409)
- Content rights: ❌ not granted without 0x68

**Root cause:** The server associates the 0x68 delegation privilege with the original HU device registration performed by the Windows Toolbox. Our Python session can't use 0x68 because `register_hu_device()` returns 409 (already registered). The server won't let a new client claim delegation rights for an already-registered HU device.

**Possible solutions:**
1. Find a way to reset/re-register the HU device from Python
2. Run the Windows Toolbox once to establish the delegation, then use our Python tool for subsequent operations
3. Investigate if there's a different registration endpoint that grants 0x68 privileges
4. Check if the `service_register_v1.sav` on the USB contains data that the Toolbox uses to prove its registration


#### 2026-04-22 16:55 — XML Dump Reveals: "Second RegisterDevice" IS the Delegator

Decrypted the http_dump XML files from session 69BACB73 (the original Toolbox session with full download flow). The "second RegisterDevice" at step 8 is actually a call to **`/services/register/rest/1/delegator`** — the same endpoint we already call.

The XML body uses `RegisterDeviceArg` type but posts to `/delegator`:
```xml
POST /services/register/rest/1/delegator
Crypt: DEVICE, Key: tb_code
<RegisterDeviceArg>
  <Device>
    <BrandName>DaciaAutomotive</BrandName>
    <ModelName>DaciaAutomotiveDeviceCY20_ULC4dot5</ModelName>
    <Swid>CK-A80R-YEC3-MYXL-18LN</Swid>
    <Imei>32483158423731362D42323938353431</Imei>
    <IgoVersion>9.12.179.799872</IgoVersion>
    <FirstUse>2022.12.27 13:41:20</FirstUse>
    <Appcid>1107299155</Appcid>
    <Vin>555531444A463030383639353739363436</Vin>
  </Device>
</RegisterDeviceArg>
```

Response returns hu_name/hu_code/hu_secret — same credentials we get from our delegator call.

**Key differences from our delegator call:**
1. Body has `Vin` field (hex-encoded VIN) — we don't send this
2. `IgoVersion` is `9.12.179.799872` — we might send a different version
3. `FirstUse` is a real timestamp — we send 0

**This means there is NO missing registration step.** The delegator IS the "second RegisterDevice." The 0x68 409 is caused by something else — possibly the body content differences (missing Vin field, wrong IgoVersion, wrong FirstUse).


#### 2026-04-22 17:00 — Delegator body fixed to match captured format exactly — still 409

Fixed `get_delegator_credentials` body to match the captured 159B format byte-for-byte:
- Added `Vin` field as raw ASCII (was missing)
- Fixed `first_use` timestamp (was 0, now `0x63AAF600`)
- Added trailing 4 bytes `00 01 8B B5`
- Body now matches captured data exactly (159B, verified byte-for-byte)

Result: Delegator returns same hu_code/hu_secret. 0x68 still returns 409.

The delegator body format was NOT the cause of the 409. The server returns the same credentials regardless of whether the Vin field is present. The 0x68 rejection is caused by something else in the session state.

**Status: The 0x68 blocker remains unsolved.** All known differences between our requests and the Toolbox's have been eliminated. The HMAC, wire format, body content, login body, delegator body, and headers all match the captured traffic exactly. The server still rejects 0x68 from our Python session.


#### 2026-04-22 18:10 — Comprehensive review of all captured data

Decrypted ALL XML dumps from session 69BACB73 (complete download flow). Updated toolbox.md with accurate 16-step API sequence.

**Every observable difference has been eliminated:**
- Wire format: ✅ matches (verified by decrypting our output)
- Header: ✅ matches (16 bytes, correct service minor, correct key)
- Query: ✅ credential block matches byte-for-byte
- Prefix: ✅ HMAC formula verified
- Body: ✅ using captured plaintext bodies
- HTTP headers: ✅ tested with raw TLS socket, exact 4 headers only
- Login body: ✅ matches Toolbox format (70B, agent version 5.28.2026041167)
- Delegator body: ✅ matches captured 159B format with Vin field
- Register JSESSIONID: ✅ now forwarded to delegator
- Extra 6 bytes: tested with captured values, zeros, and constructed values

**Remaining hypothesis:** The server binds the 0x68 delegation privilege to the original toolbox registration. Our toolbox credentials were created by a different registration call than the one the Toolbox used. The server may track which registration created which credentials and only allow 0x68 from the original registrant. Since we can't re-register (409 — already registered), we can't establish this binding.

**To test this hypothesis:** Would need to either reset the device registration on the server (no known API) or register a completely new device (different APPCID/USB).


#### 2026-04-22 18:10 — Status: 0x68 remains blocked, all known differences eliminated

After exhaustive testing with correct HMAC, matched wire format, matched bodies, matched headers, raw sockets, register JSESSIONID forwarding, and every combination of extra bytes — the 0x68 still returns 409.

The 0x28 flag (used by Toolbox for licinfo and small senddevicestatus) has a different body encryption that we haven't decoded. This is a separate protocol variant, not directly related to the 0x68 issue.

**What works:** Catalog (38 items), licenses (10), free content purchase, license installation to USB. All via 0x60 and web API.

**What doesn't work:** 0x68 senddevicestatus → 409. This blocks the managecontent page (500 NullPointerException) and the content download flow.

**Next investigation needed:** Start the QEMU VM, run the Toolbox with our USB, and use Wireshark or the debugger to capture the EXACT bytes the Toolbox sends for the 0x68 in a fresh session. Then replay those exact bytes from Python in the SAME session (by sharing the JSESSIONID). This would definitively prove whether the issue is the request content or the session state.


#### 2026-04-22 21:00 — BREAKTHROUGH: SSL_write captures reveal wrong wire format

Hooked `SSL_write` in `libssl-1_1.dll` (run25) to capture raw HTTP traffic. The binary protocol uses OpenSSL directly, NOT WinHTTP.

**Critical findings from raw wire bytes:**

1. **The Toolbox's first senddevicestatus uses `flags=0x68` with a 2-byte query** (not 25B)
2. **The Toolbox's second senddevicestatus uses `flags=0x28` with a 25-byte query** (not 0x68)
3. **The 0x28 credential block contains `tb_name`** (NOT Name₃)
4. **Both bodies use chain encryption** (rotating SnakeOil keys per field), NOT simple tb_secret
5. **Content-Length: 2218 (0x68) vs 2235 (0x28)** — difference is exactly 17 bytes (the prefix)

**Flag bit meanings (corrected):**
- `0x40` = short query (2 bytes, no credential block)
- `0x08` = chain-encrypted body / delegation
- `0x60` = 0x20|0x40 = short query, simple body encryption
- `0x68` = 0x20|0x40|0x08 = short query, chain body encryption
- `0x28` = 0x20|0x08 = long query with tb_name cred block, chain body encryption

**What we were doing wrong:**
- Sending `flags=0x68` with 25B query — but 0x68 means 2B query (0x40 bit = short)
- Using Name₃ in the credential block — should be tb_name
- Using simple tb_secret encryption for body — should be chain encryption
- The 17B "prefix" is NOT a separate wire segment — it's part of the chain-encrypted body

**Next step:** Reverse the chain encryption (field-level rotating SnakeOil keys). The SnakeOil debugger captures show the key sequence. The first key is tb_secret, subsequent keys are derived from each field's encryption output.

Updated: design.md, toolbox.md, test_0x68_hmac_verified.py. All 238 tests pass.


#### 2026-04-22 21:15 — REPLAY SUCCESS: Captured 0x68 and 0x28 wire bytes return 200!

Replayed the EXACT captured SSL_write bytes from run25 in a fresh Python session:
- `ssl_write_14_2218.bin` (0x68, 2B query): **200** (88B response) ✅
- `ssl_write_59_2235.bin` (0x28, 25B query): **200** (248B response) ✅

This proves:
1. Our session IS valid — the server accepts 0x68/0x28 from Python
2. The issue was ALWAYS the wire format construction
3. The captured wire bytes are replayable across sessions
4. The chain encryption in the body is what we were getting wrong

managecontent still returns 500 — likely needs the full API sequence (delegator between the two SDS calls, plus licinfo/licenses after).

**Next: reverse the chain encryption to generate valid bodies from scratch.**


#### 2026-04-22 21:35 — DEFINITIVE: Wire format is ONE continuous SnakeOil(tb_code) stream

Decrypting the ENTIRE SSL-captured payload with tb_code as ONE stream reveals:

**0x68 (first SDS, 2218B):**
```
SnakeOil(tb_code): [counter=0x74][flags=0x68][D8+Name₃_XOR(17B)][extra(6B)][chain_body(2177B)]
```
- Credential block: Name₃ ✅
- Extra 6B: `55 BD EA 85 2B 16`
- Body: chain-encrypted (starts with `58 C6 F7 A9`, not `D8`)

**0x28 (second SDS, 2235B):**
```
SnakeOil(tb_code): [counter=0x7D][flags=0x28][D8+tb_name_XOR(17B)][extra(6B)][chain_body(2194B)]
```
- Credential block: tb_name ✅
- Extra 6B: `5B 10 02 72 42 A3`
- Body: chain-encrypted (starts with `21 AE 23 F3`)

**What we were doing wrong (ALL THREE):**
1. Split encryption (query with tb_code, body with tb_secret) — should be ONE stream with tb_code
2. Separate 17B prefix segment — prefix is INSIDE the chain-encrypted body
3. Simple tb_secret body encryption — body uses chain encryption THEN outer tb_code

**Correct wire format:**
```
[16B header, key=tb_code]
[SnakeOil(entire_payload, tb_code)]
  where payload = [25B query][chain_encrypted_body]
```

**Remaining work:** Reverse the chain encryption to generate valid bodies from the plaintext.


#### 2026-04-22 21:50 — Wire format FULLY understood, replay approach works

**Definitive wire format for 0x68 senddevicestatus:**
```
[16B header, key=tb_code in bytes 4-11]
[SnakeOil(entire_payload, tb_code)]
  payload = [counter(1B)][0x68][D8+Name₃_XOR(17B)][extra(6B)][chain_body]
```

- The ENTIRE payload (query + body) is ONE continuous SnakeOil stream with tb_code
- The chain_body is the igo-binary serialized body with field-level encryption
- The extra 6 bytes MUST match the chain body (server validates consistency)
- The counter byte can be any value
- The credential block contains Name₃ (for 0x68) or tb_name (for 0x28)

**Verified:**
- Replay exact captured wire: 200 ✅
- Reconstructed (same query + chain body, re-encrypted): 200 ✅
- New counter + same extra + same chain body: 200 ✅
- Different extra + same chain body: 409 ❌ (extra must match body)

**Implementation plan:**
1. Extract chain_body + extra from captured wire bytes
2. Store as templates per USB content state
3. Build query with correct Name₃/tb_name credential block
4. Encrypt as one stream with tb_code
5. Later: reverse chain encryption for dynamic body generation

