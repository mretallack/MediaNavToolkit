# Reverse Engineering the NNGE Algorithm — Finding Secret₃

> Parent: [toolbox.md](toolbox.md) | Design: [design.md](design.md) | Functions: [functions.md](functions.md)

## Goal

Find the 8-byte SnakeOil key (**Secret₃**) used to encrypt the body of `0x08`-flag wire protocol requests.

## Status

**SOLVED (2026-04-18 15:30)** — Secret₃ = **tb_secret** (`3037636188661496` / `0x000ACAB6C9FB66F8`).

The investigation was blocked for 24+ hours by two compounding errors:
1. **Wrong body offset**: Assumed body at offset 35 (`16 header + 19 query`). Actual query length for 0x68 flows is **25 bytes** (header byte 12 = 0x19), so body starts at offset **41**.
2. **Split encryption**: The 0x68 body is encrypted as **two separate SnakeOil streams**, not one continuous stream:
   - **Stream 1**: `body[0:17]` — 17-byte delegation prefix, encrypted with fresh tb_secret PRNG
   - **Stream 2**: `body[17:]` — standard senddevicestatus content, encrypted with **another fresh** tb_secret PRNG

Verified across all 0x68 flows (737, 754, 792): `snakeoil(body[17:], tb_secret)` → `D8 03 1E 40 0F DaciaAutomotive...` ✓

## Known Values

| Name | Value | Source |
|------|-------|--------|
| tb_code | `3745651132643726` (0x000D4EA65D36B98E) | Toolbox registration |
| tb_secret | `3037636188661496` (0x000ACAB6C9FB66F8) | Toolbox registration |
| hu_code | `3362879562238844` (0x000BF28569BACB7C) | Delegator response |
| hu_secret | `4196269328295954` (0x000EE87C16B1E812) | Delegator response |
| Name₃ (wire) | `ad35bcc12654b893f7b5596a8057190c` | 0x68 query credential block (all 3 flows identical) |
| Name₃ (old/wrong) | ~~`C4000BF28569BACB7C000D4EA65D36B9`~~ | Was misinterpretation of query format |
| Query cred type | `0xD8` | First byte of credential block in 0x68 query |
| Secret₃ | **UNKNOWN** | Derived from device.nng via NNGE algorithm |
| NNGE key | `m0$7j0n4(0n73n71I)` (19 bytes) | DLL RVA 0x2C11E4 |
| Blowfish key | `b0caba3df8a23194f2a22f59cd0b39ab` | DLL RVA 0x2AF9E8 |
| APPCID | `0x42000B53` (1107299155) | device.nng offset 0x5C |
| RSA public key | n=6B2317...0B676F (2048-bit), e=65537 | DLL RVA 0x30B588 |
| Brand MD5 | `3deaefba446c34753f036d584c053c6c` | device.nng[0x40:0x50] XOR-decoded |

## What We Know About Secret₃

**SOLVED: Secret₃ = tb_secret = `3037636188661496` (0x000ACAB6C9FB66F8)**

The same key is used for ALL encrypted bodies (both 0x60 and 0x68 flows). The confusion arose because:
- The 0x68 body starts at offset 41 (not 35)
- The body is split-encrypted: first 17 bytes (delegation prefix) and remaining bytes (standard content) are each encrypted with a **fresh** SnakeOil PRNG seeded with tb_secret
- Decrypting the entire body as one stream produces garbage from byte 17 onwards because the PRNG state is wrong for the second segment

## Tasks

- [x] **T1.** Map the full call chain from SnakeOil → credential object → device descriptor
- [x] **T2.** Reverse engineer .lyc file decryption (RSA + XOR-CBC)
- [x] **T3.** Dump RSA public key from DLL and decrypt all .lyc files
- [x] **T4.** Confirm Secret₃ is NOT in .lyc files (they contain map license data)
- [x] **T5.** Exhaustive search of device.nng raw/decoded values as SnakeOil keys
- [~] **T6.** ~~Trace `FUN_10044c60` → `vtable[27]` device.nng processing chain~~ — SUPERSEDED
- [~] **T7.** ~~Try Blowfish key on device.nng sections~~ — SUPERSEDED
- [~] **T8.** ~~Find the file system manager vtable and its `+0x6c` method~~ — SUPERSEDED
- [~] **T9.** ~~Extract the derivation algorithm~~ — N/A (no derivation needed, Secret₃ = tb_secret)

### Unicorn Engine Approach (T10–T15)

- [x] **T10.** Set up Unicorn Engine environment (Python venv with unicorn 2.1.4, capstone 5.0.7, pefile 2024.8.26)
- [x] **T11.** Build PE loader: `analysis/unicorn_harness.py` — maps nngine.dll at 0x10000000, applies relocations, stack at 0x00100000, heap at 0x00400000
- [x] **T12.** Validate harness: SnakeOil(zeros, tb_secret)→bc755fbc32341970 ✓, flow 735 body→DaciaAutomotive@offset 5 ✓
- [~] **T13.** ~~Find Secret₃ via emulation~~ — SUPERSEDED by wire protocol analysis (T16)
- [~] **T14.** ~~Read Secret₃ from emulated memory~~ — SUPERSEDED
- [x] **T15.** Validate Secret₃ — decrypt captured 0x68 body, verify "DaciaAutomotive" ✓

### Resolution (T16)

- [x] **T16.** Correct wire protocol structure and verify Secret₃ = tb_secret
  - Body offset for 0x68 flows = **41** (16 header + 25 query), not 35
  - Body is **split-encrypted**: `body[0:17]` + `body[17:]` each with fresh tb_secret PRNG
  - Verified across flows 737, 754, 792: `snakeoil(body[17:], tb_secret)` → "DaciaAutomotive" ✓
  - Flow 741 (0x28 flags) uses a different credential name — separate session, not part of main flow

## Architecture Overview

### Two Separate Credential Paths

```
┌─────────────────────────────────────────────────────────┐
│ PATH A: .lyc License Files (MAP CREDENTIALS) — SOLVED  │
│                                                         │
│ .lyc file → RSA decrypt (2048-bit public key)           │
│          → 40-byte header (magic 0x36c8b267)            │
│          → XOR-CBC decrypt remaining blocks              │
│          → License key + product name                    │
│          → Used for: map content activation              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PATH B: Wire Protocol Encryption — SOLVED               │
│                                                         │
│ ALL bodies encrypted with tb_secret (pre AND post       │
│ delegation). The 0x68 body has a 17-byte delegation     │
│ prefix that is separately encrypted.                    │
│                                                         │
│ Query encrypted with tb_code (2B or 25B depending on    │
│ whether credential block is present).                   │
└─────────────────────────────────────────────────────────┘
```

### Corrected Wire Protocol Structure

```
0x60 flows (pre-delegation, no credential block):
  [16B header] [2B query (tb_code)] [body (tb_secret)]
  Body offset: 18

0x68 flows (post-delegation, with credential block):
  [16B header] [25B query (tb_code)] [17B deleg prefix (tb_secret)] [body (tb_secret)]
  Query offset: 16, Body offset: 41
  Body split: body[0:17] and body[17:] each encrypted with FRESH tb_secret PRNG

0x20 flows (basic, no credential block):
  [16B header] [2B query (tb_code)] [body (tb_secret)]
  Body offset: 18

0x28 flows (different session credential):
  [16B header] [25B query (tb_code)] [body structure TBD]
  Uses different credential name — separate session
```

### Flag Bits

| Bit | Mask | Meaning |
|-----|------|---------|
| 3   | 0x08 | Has credential block in query (25B instead of 2B) |
| 5   | 0x20 | Always set (base flag) |
| 6   | 0x40 | senddevicestatus mode |

### All Captured Flows

| Flow | Endpoint | Flags | Credential Name | Key |
|------|----------|-------|-----------------|-----|
| 048 | login | 0x20 | — | tb_secret |
| 051 | hasActivatable | 0x20 | — | tb_secret |
| 053 | sendfingerprint | 0x20 | — | tb_secret |
| 735 | senddevicestatus | 0x60 | — | tb_secret |
| 736 | delegator | 0x20 | — | tb_secret |
| 737 | senddevicestatus | 0x68 | ad35bcc1...190c | tb_secret (split) |
| 740 | licenses | 0x68 | ad35bcc1...190c | tb_secret (split) |
| 741 | senddevicestatus | 0x28 | 92b31be5...ffd9 | different session |
| 742 | sendfingerprint | 0x68 | ad35bcc1...190c | tb_secret (split) |
| 748 | login | 0x20 | — | tb_secret |
| 754 | senddevicestatus | 0x68 | ad35bcc1...190c | tb_secret (split) |
| 792 | senddevicestatus | 0x68 | ad35bcc1...190c | tb_secret (split) |

### device.nng Structure (268 bytes)

```
Offset  Size  Description
------  ----  -----------
0x00    64    XOR-encoded header (decoded with xor_table_normal.bin)
0x40    16    Brand MD5 (XOR-encoded) = 3deaefba446c34753f036d584c053c6c
0x50    4     "NNGE" marker (plaintext)
0x54    4     Version: 19 06 07 20
0x58    4     Field1: 0x65FAB84A
0x5C    4     APPCID: 0x42000B53 (1107299155)
0x60    4     Field3: 0xC44D75AC  ← possible credential seed
0x64    168   Remaining data (encrypted/encoded)
```

The 8-byte value `BD756DD1BA989F17` repeats 3× (offsets 0x6C, 0xF4, 0x104) — likely a hash/checksum.

### Secret₃ Derivation Chain (device.nng path)

```
FUN_10044c60 (device.nng reader, line 54064)
│
├─ Opens "license/device.nng" via FUN_10041440
├─ Calls file_object->vtable[11](path) to find file
├─ Calls (**(code **)(**(int **)(this + 8) + 0x6c))(&this, &path, param)
│   │
│   └─ this+8 = file system manager object
│       └─ vtable[27] (+0x6c) = UNKNOWN FUNCTION ← need to find this
│           └─ Processes device.nng data
│           └─ Derives credential (Name, Code, Secret)
│
└─ Result: device descriptor with APPCID, brand, Secret₃
```

### .lyc Decryption Chain (SOLVED)

```
FUN_100be3c0 (credential provider constructor)
  → Wraps RSA key objects in FUN_101585f0 (vtable PTR_FUN_102c76b0)

Provider vtable PTR_FUN_102c76b0:
  [0] +0x00: RVA 0x158790  — destructor
  [1] +0x04: RVA 0x158610  — FUN_10158610: decrypt (iterates chunks)
  [2] +0x08: RVA 0x158710  — FUN_10158710: validate → FUN_10154b40 (RSA)
  [3] +0x0C: RVA 0x158740  — get value: this[1][1]
  [4] +0x10: RVA 0x158750  — get adjusted: this[1][1] - 11

FUN_10158610 → FUN_10158710 → FUN_10154b40 (RSA PKCS#1 v1.5)
  → FUN_10154860 (RSA modexp: m = c^e mod n)
  → Checks PKCS#1 padding: 00 02 [random] 00 [payload]
  → Returns 40-byte payload (credential header)
```

### RSA Key (embedded in DLL)

```
Key size: 2048 bits (256 bytes)
Exponent: 65537 (0x10001)
Modulus:  6B231771 184FAAD8 86AE159B ADB1D45A 5BC4338D 4F503A61 93DA01A6 19E5D21A
          C873174C 7D206CEA FED3AF22 FEE1019D B84BA294 B41339FC CD19048C 95FB9CED
          ABCAE871 13D188FC 2D3050CA 2FAF12EE 5A292B17 D3490364 360B9656 65AECB52
          4265B9AF BDAAA0ED DAD53042 93D70FBA 49609AC2 5F8AF346 4E55FF79 BCE67681
          F4349625 A7BA755D CC554766 60134CB5 92F20AC0 1E2B4D37 B3CBB058 03DE7531
          BA5E464B 031F65F9 AC91F9BE 6D133DA1 9400F6F1 7A4E697C 6505FDEE 34F45500
          52BCA43E 2BCD5C63 B46A96B4 32D2F393 DB9E648D 593D5801 41BC265C F3403905
          96CF667E 577CC1BC B235759D B983CB19 1652667F 85319A59 5812502F FC0B676F
```

### Decrypted .lyc Contents

| File | License Key | Product |
|------|-------------|---------|
| Global_Config | `CW-UQAQ-YAEQ-37QI-AA7A-QYQM` | Renault/Dacia Global Config update |
| Main | `CP-3IE3-EEMQ-MQAA-I7U3-E7M7` | LGe Western Europe |
| Language | (extracted) | Renault/Dacia Language Update |

## DLL Key Addresses

| RVA | Function | Role |
|-----|----------|------|
| 0x1B3E10 | SnakeOil | Stream cipher |
| 0x157D40 | MD5 | Standard MD5 (when param4=0) |
| 0x1583E0 | Credential data ctor | Creates 40-byte credential object |
| 0x158410 | XOR-CBC transform | Validates MD5, XOR-CBC with key from `this[2..5]` |
| 0x158610 | Provider decrypt | Iterates chunks, calls RSA |
| 0x158710 | RSA validate | Calls FUN_10154b40 |
| 0x154B40 | RSA PKCS#1 v1.5 | Decrypt with PKCS padding check |
| 0x154860 | RSA modexp | `m = c^e mod n` |
| 0x154920 | RSA CRT modexp | CRT-optimized RSA |
| 0x0BD380 | NNGE vtable[2] | Formats "SPEEDx%sCAM", computes MD5 |
| 0x0EA130 | NNGE file parser | Reads .nng files, finds NNGE block |
| 0x0EA960 | Credential parser | Reads .lyc, calls provider decrypt |
| 0x0EAB30 | _lb_ string builder | Base32 key encoding/decoding |
| 0x155C10 | Base32 decoder | 26 chars → 16 bytes |
| 0x044C60 | device.nng reader | **Key function for Secret₃** |
| 0x101120 | RSA key loader | Loads static RSA key from DLL data |
| 0x1AA050 | Credential constructor | Creates 0x58-byte credential, calls HMAC-MD5 for Name |
| 0x1AA3A0 | HMAC-MD5 | Standard HMAC-MD5 (ipad=0x36, opad=0x5C) |
| 0x101430 | RSA key register | Registers RSA key in global store |
| 0x100D20 | RSA key store init | Creates global RSA key linked list |
| 0x100E30 | RSA key copier | Copies 0x9C-byte RSA key objects |

## Vtables

### PTR_FUN_102bbbf4 (Credential Provider)
```
[0] 0x0BF300  destructor     [4] 0x0BEA40  get APPCID
[1] 0x0BE840  unknown        [5] 0x0BEC30  find by APPCID
[2] 0x0BE850  get cred list  [6] 0x0BECD0  get cred data
[3] 0x0BE920  get cred tree  [7] 0x0BED40  get cred name
```

### PTR_FUN_102c769c (Credential Data Object)
```
[0] 0x1585C0  destructor     [5] 0x158790  destructor (8B)
[1] 0x158410  XOR-CBC        [6] 0x158610  chunk decrypt
[2] 0x158590  returns false  [7] 0x158710  RSA validate
[3] 0x1585A0  returns 0x10   [8] 0x158740  get this[1][1]
[4] 0x1585B0  calls vt[3]    [9] 0x158750  get this[1][1]-11
```

### PTR_FUN_102c76b0 (Provider Wrapper)
```
[0] 0x158790  destructor     [3] 0x158740  get inner[1]
[1] 0x158610  chunk decrypt  [4] 0x158750  get inner[1]-11
[2] 0x158710  RSA validate
```

### NNGE Engine (0x2BBAB0, 18 methods)
```
[0] 0x0BD300  destructor     [7]  0x0EA130  NNGE file parser
[1] 0x0BD310  init           [13] 0x1093F0  unknown
[2] 0x0BD380  SPEEDx%sCAM    [16] 0x109610  unknown
```

### Device Manager (0x2B48E0)
```
[10] 0x044C60  device.nng reader  ← KEY FUNCTION
```

## Eliminated Approaches

| # | Approach | Result |
|---|----------|--------|
| 1 | Raw device.nng 8-byte windows as SnakeOil key | No match |
| 2 | XOR-decoded device.nng windows as key | No match |
| 3 | MD5/SHA1 of device.nng sections as key | No match |
| 4 | SnakeOil(nng_section, known_key) | No match |
| 5 | Known credential combinations | No match |
| 6 | DLL .rdata/.data section scan for valid keys | 2 candidates, both garbage |
| 7 | Wine DLL full init (DllMain/TLS/constructors) | All hang |
| 8 | Body reconstruction from http_dump XML | 23-byte prefix unknown |
| 9 | Brute-force field3 (0xC44D75AC) + 16-bit hi | No match |
| 10 | SnakeOil-decrypt device.nng with NNGE key | No match |
| 11 | Blowfish(NNGE key) on device.nng | No readable text |
| 12 | RSA-decrypt device.nng | Not RSA-encrypted |
| 13 | Search decrypted .lyc data for SnakeOil keys | No match |

## File References

| File | Description |
|------|-------------|
| `analysis/nngine_decompiled.c` | Ghidra decompiled output (~555K lines) |
| `analysis/DaciaAutomotive_extracted/.../device.nng` | Device identity file (268 bytes) |
| `analysis/usb_drive/disk/NaviSync/license/*.lyc` | License files (RSA encrypted) |
| `analysis/flows_decoded/2026-04-16/` | Decoded mitmproxy wire captures |
| `analysis/xor_table_normal.bin` | XOR table for device.nng decoding |
| `analysis/call_snakeoil.c` | Harness: calls SnakeOil from DLL |
| `analysis/test_xor_cbc.c` | Harness: XOR-CBC key tester |
| `analysis/dump_rsa5.c` | Harness: dumps RSA keys from DLL |

---

## Engineering Log

> **How to use this log:** Each entry is timestamped. When resuming, read the LATEST entry's "Next steps" to pick up where we left off. Append-only.

---

### 2026-04-17 13:00–14:00 — Traced credential chain, found MD5 and XOR-CBC

Mapped full call chain: SnakeOil → protocol builder → credential object → credential provider → NNGE engine. Found `FUN_10157d40` = standard MD5, `FUN_100bd380` formats "SPEEDx%sCAM", `FUN_10158410` = XOR-CBC validation. Tried MD5 of various device identity strings as XOR-CBC keys — no match.

### 2026-04-17 14:00–15:00 — Found Base32 encoding, provider vtable search

Found `FUN_100eab30` builds `_lb_` string with Base32-encoded 16-byte keys. `FUN_10155c10` = Base32 decoder (26 chars → 16 bytes). Scanned DLL for provider vtables — found file I/O objects but not crypto providers. Found credential block parser at line 221260 (reads magic 0x36c8b267/0x36c8b268).

### 2026-04-17 15:00–15:30 — RSA BREAKTHROUGH + .lyc decryption solved

**Major discovery:** .lyc files use RSA encryption (PKCS#1 v1.5), NOT XOR-CBC. Found 2048-bit RSA public key at DLL RVA 0x30B588. Successfully decrypted all 3 .lyc files. Format: `[8B header][256B RSA block][XOR-CBC data]`. RSA payload = 40-byte credential header, fields[1..4] = XOR-CBC key for remaining blocks.

Traced full RSA code path: `FUN_100be3c0` → `FUN_101585f0` (wrapper) → `FUN_10158610` → `FUN_10158710` → `FUN_10154b40` → `FUN_10154860` (modexp). RSA key objects are 0x9C bytes, stored in global `DAT_10316970`, loaded by `FUN_10100d20` → `FUN_10101120`/`FUN_10101430`.

**But:** Secret₃ is NOT in .lyc files. They contain map license data. Device credential comes from device.nng through `FUN_10044c60` → `vtable[27]`.

Exhaustive search: tried all 8-byte windows in raw/decoded device.nng, brute-forced field3 with 16-bit hi values, SnakeOil-decrypted with NNGE key, RSA-decrypted — all negative.

**Next steps:**
1. **T6: Trace `FUN_10044c60` → `vtable[27]`** — find the file system manager's vtable and its +0x6c method. This is the function that processes device.nng and derives Secret₃.
2. **T7: Try Blowfish key** on device.nng sections — the key at RVA 0x2AF9E8 hasn't been tried with the correct algorithm yet.
3. **T8: Find the file system manager vtable** — the object at `*(device_manager + 8)` has the vtable with the +0x6c method.

---

### 2026-04-17 15:40 — Traced vtable[27] chain, found file system vtables

**What we found:**
1. `DAT_10326bf4` = file system factory singleton, vtable `PTR_FUN_102c514c`
2. Factory `vtable[9]` (RVA `0x134B30`) creates file system objects
3. File system object vtable: `PTR_FUN_102c5038` (outer wrapper, 30 methods)
4. Outer `vtable[27]` = `FUN_10133de0` — thin wrapper, delegates to inner object
5. Inner object vtable: `PTR_FUN_102c5b84` (created by `FUN_1013d030`)
6. Inner `vtable[27]` = `FUN_1013d750` — **path builder**, NOT credential derivation
7. The `+0x6c` call in `FUN_10044c60` just builds the full path to device.nng

**Key realization:** The `vtable[27]` call is NOT the credential derivation. It's a path resolution step. The actual credential derivation happens through the credential provider (`FUN_100be3c0`) which is created by `FUN_1005ffe0`.

**reg.sav structure confirmed:**
- Entry 1: `hu_name(16) + hu_code(8 BE) + hu_secret(8 BE) + flags`
- Entry 2: `tb_name(16) + tb_code(8 BE) + tb_secret(8 BE) + flags`
- Name₃ is NOT in reg.sav — the third credential is derived at runtime
- APPCID `0x42000B53` is NOT in reg.sav or any .lyc file

**Tried credential combinations:**
- SnakeOil(name3, any_known_key) → no match
- MD5(name3) as uint64 → no match
- XOR of hu/tb code/secret → no match
- SnakeOil(credential_bytes, other_credential) → no match
- field3 combined with credentials → no match
- MD5 of credential string combinations → no match

**Revised understanding:**
The credential provider (`FUN_100be3c0`) creates credentials from:
1. RSA keys (from `DAT_10316970`) → decrypt .lyc files → map license credentials
2. reg.sav → hu and tb credentials (stored as Name+Code+Secret)
3. device.nng → device credential (Secret₃) — **this is the unknown path**

The device.nng credential is NOT stored in any file. It's derived at runtime by the NNGE engine from the device.nng NNGE block data. The NNGE engine is initialized during `FUN_100bed80` (license file loader) which calls `FUN_100ea130` (NNGE file parser).

**Next steps:**
1. Re-examine `FUN_100bed80` — it creates the NNGE engine and processes device.nng
2. The NNGE engine's `FUN_100ea130` reads device.nng and extracts the NNGE block
3. But device.nng is only 268 bytes and the NNGE parser seeks to `end - 24` = offset 244
4. At offset 244: `6DD1BA989F17000074C83CDAEA1059D8BD756DD1` — NOT "NNGE"
5. So the NNGE parser FAILS for device.nng → falls through to template check
6. The template `"ZXXXXXXXXXXXXXXXXXXZ"` is used instead
7. **The NNGE key `m0$7j0n4(0n73n71I)` might be XOR'd with the template to derive the credential**
8. Need to trace what happens when the NNGE parser falls through

---

### 2026-04-17 16:15 — Found MD5(device.nng) = fingerprint, NOT Secret₃

**What we found:**
1. `FUN_10058590` (fingerprint manager) reads device.nng and computes MD5
2. `FUN_10157f20` = standard MD5 hash of file contents
3. MD5(device.nng) = `65d0a4c07c1f1610e4dcc2297f5fbf8c`
4. This MD5 is used as a device FINGERPRINT, not as the SnakeOil key
5. Tested MD5 as SnakeOil key → no match

**File system vtable chain resolved:**
- `DAT_10326bf4` → factory vtable `PTR_FUN_102c514c`
- Factory `vtable[9]` → creates FS object with vtable `PTR_FUN_102c5038`
- FS object wraps inner object with vtable `PTR_FUN_102c5b84`
- Inner `vtable[27]` = `FUN_1013d750` = path builder (NOT credential derivation)

**Critical insight:** The NNGE parser (`FUN_100ea130`) FAILS for device.nng because:
- device.nng is 268 bytes (< 512 → 0x460 search skipped)
- Parser seeks to `end - 24` = offset 244
- Data at 244 does NOT start with "NNGE"
- Template fallback also fails (template starts with "Z", not "NNGE")
- Parser returns FALSE

**This means device.nng is NOT processed by the NNGE engine at all.** The NNGE block at offset 0x50 is never read by the parser. The device credential must come from a completely different mechanism.

**Next steps:**
1. The credential provider reads .lyc files (map licenses) and reg.sav (hu/tb credentials)
2. Neither contains APPCID `0x42000B53` or Secret₃
3. Secret₃ must be derived by a function we haven't found yet
4. Search the decompiled code for functions that read from offset 0x50 or 0x5C in a buffer (where the NNGE block and APPCID are in device.nng)
5. Search for functions that produce a uint64 output from device.nng data
6. The device.nng might be read as a binary blob and parsed by a custom function, not the NNGE parser

---

### 2026-04-17 16:30 — Blowfish negative, credential entry vtable mapped

**What we tried:**
1. Blowfish ECB/CBC with key `b0caba3df8a23194f2a22f59cd0b39ab` on all device.nng blocks → no match
2. Blowfish ECB with NNGE key on all device.nng blocks → no match
3. Mapped credential entry vtable `PTR_FUN_102bc54c` (16 methods)
4. Found `FUN_100dd970` = license validation callback (checks APPCID against license store)
5. Found `FUN_10058590` = fingerprint manager (computes MD5 of device.nng as file checksum)
6. MD5(device.nng) = `65d0a4c07c1f1610e4dcc2297f5fbf8c` — used as fingerprint, NOT as Secret₃

**Confirmed:**
- Blowfish key doesn't decrypt device.nng to produce Secret₃
- MD5(device.nng) is a fingerprint, not the SnakeOil key
- The NNGE parser (`FUN_100ea130`) FAILS for device.nng (seeks to wrong offset)
- device.nng NNGE block at offset 0x50 is NEVER read by the NNGE parser

**Next steps (revised priority):**
1. **Search for functions that read device.nng as a binary blob** — the NNGE block at offset 0x50 must be read by SOME function. Search for `fread` calls that read 20 bytes or for functions that check for "NNGE" at a specific offset.
2. **Trace the credential copy chain backwards** — `FUN_100b1670` copies from `parent+0x84`. Find where `parent+0x84` is FIRST set (not just copied).
3. **Try running the DLL on actual Windows** — attach debugger, break on SnakeOil, read the key. This bypasses all static analysis.
4. **Search for the APPCID 0x42000B53 in the DLL's runtime data** — the APPCID must be read from device.nng and stored somewhere. Find the function that reads it.

---

### 2026-04-17 18:30 — SECRET₃ SOLVED: It's tb_secret!

**BREAKTHROUGH:** There is NO separate Secret₃. ALL wire protocol flows use `tb_secret = 3037636188661496` (0x000ACAB6C9FB66F8) as the SnakeOil key.

**How we found it:**
1. Verified that `snakeoil(body735, tb_secret)` matches the decoded file ✓
2. Verified that `snakeoil(body737, tb_secret)` matches the decoded file ✓
3. Verified that `snakeoil(body741, tb_secret)` matches the decoded file ✓
4. Verified that `snakeoil(body754, tb_secret)` produces valid plaintext (starts with `8da90632`) ✓
5. Verified that `snakeoil(body792, tb_secret)` produces valid plaintext ✓

**The confusion was caused by:**
- Flows 754 and 792 had no pre-decoded files, leading me to believe they used a different key
- The header byte at offset 17 differs (`0x67` vs `0x11`) but this indicates message type, not encryption mode
- The "0x60 vs 0x68 flag" distinction was a misunderstanding of the wire protocol

**Conclusion:**
- Secret₃ = tb_secret = `3037636188661496` (0x000ACAB6C9FB66F8)
- ALL SnakeOil-encrypted wire protocol bodies use tb_secret
- The tb_secret is obtained during device registration and stored in service_register_v1.sav
- No device.nng derivation is needed — the key comes directly from the registration response

---

### 2026-04-17 19:30 — CORRECTION: Secret₃ ≠ tb_secret (circular verification error)

**The earlier finding that Secret₃ = tb_secret was WRONG.**

**What went wrong:**
1. The "decoded" files (`*-decoded.bin`) are NOT decrypted — they're just `raw[35:]` (header-stripped raw bytes, still SnakeOil-encrypted)
2. `snakeoil(raw[35:], tb_secret)` was compared against the decoded file, which IS `raw[35:]`
3. This comparison was `snakeoil(X, tb_secret) == X` — which is FALSE (SnakeOil is not identity)
4. But the comparison `snakeoil(body, tb_secret) == decoded` was TRUE because decoded = body (both are raw[35:])
5. Wait — that can't be right either. Let me re-check...

Actually: `snakeoil(raw737[35:], tb_secret)` was compared to `dec737_file` which is `raw737[35:]`. These are NOT the same — SnakeOil XORs with PRNG output. The match I found earlier must have been a bug in my test.

**Corrected understanding:**
- Flow 735 (0x60): 2-byte query, body at offset 18, decrypts with tb_secret ✓
- Flow 737 (0x68): 19-byte query, body at offset 35, does NOT decrypt with any known key
- Secret₃ is still UNKNOWN
- The senddevicestatus workaround (captured body replay) is still needed

**Next steps:**
1. Resume the NNGE reverse engineering to find Secret₃
2. Or: check if the 0x68 body can be avoided entirely (maybe only the 0x60 call is needed)
3. Or: check if the session works with just the 0x60 senddevicestatus + raw replay of 0x68

---

### 2026-04-17 19:45 — Resumed Secret₃ search, http_dump analysis

**What we found:**
1. The http_dump XML logs `<Key>` (= Code) but NOT `<Secret>` for SnakeOil
2. Both 0x60 and 0x68 requests use `<Crypt>DEVICE</Crypt>` with `<Key>3745651132643726</Key>` (tb_code)
3. Only TWO credential sets exist from server: TB (from first register) and HU (from second register)
4. Name₃ is constructed locally, not from server. Code₃/Secret₃ must also be derived locally.
5. The Delegation section has HMAC_MD5 digest `6467a86d4e779471076af473dab78b45` — tried as key, no match
6. The MAC is computed by the CLIENT, not the server

**What we tried:**
- MAC digest as SnakeOil key (all 8-byte windows, LE and BE) → no match
- hu_secret/tb_secret byte combinations → no match
- Constructed keys from hu_secret + tb_secret bytes → no match
- HMAC_MD5 with various keys and data → couldn't reproduce the MAC

**Key insight:** The 0x08 flag credential object has Name₃ (constructed), Code₃ (unknown), Secret₃ (unknown). These are NOT from any server response. They must be derived locally from the two known credential sets (TB and HU).

**Next steps:**
1. The credential object is populated by `FUN_100b1670` which copies from `parent+0x84`
2. The parent is the session object, and `+0x84` is set during session setup
3. Need to find WHERE `+0x84` is populated with the constructed credential
4. The construction likely happens in the delegator response handler or session setup code
5. Alternative: try to find the MAC computation in the DLL to understand the delegation HMAC key

---

### 2026-04-17 20:00 — DLL data scan negative, http_dump confirms DEVICE mode

**What we found:**
1. http_dump XML confirms both 0x60 and 0x68 use `<Crypt>DEVICE</Crypt>` with `<Key>3745651132643726</Key>` (tb_code)
2. The `<Secret>` field is NOT logged in request XMLs — only in RegisterDeviceRet responses
3. Only TWO credential sets exist from server: TB and HU. No third registration.
4. Name₃ is constructed locally. Code₃/Secret₃ must also be derived locally.
5. The Delegation MAC digest `6467a86d4e779471076af473dab78b45` doesn't work as key
6. DLL .rdata and .data section scan: no 8-byte value produces "Dacia" in decrypted output
7. Known value pairs (all combinations of hu/tb code/secret halves, APPCID, Name₃ parts, XOR/ADD combos): no match

**What we tried:**
- 529 known value pairs as (lo, hi) → no D8 + 0F + "Dacia" match
- ~95K values from DLL .rdata section → no "Dacia" in first 40 decrypted bytes
- ~28K values from DLL .data section → no "Dacia" in first 40 decrypted bytes
- MAC digest as key → no match

**Confirmed:**
- Secret₃ is NOT a static value in the DLL
- Secret₃ is NOT a simple combination of known credential values
- Secret₃ is derived at runtime through a computation we haven't found

**Next steps:**
1. The credential object for 0x08 flag has Name₃ (constructed from hu_code + tb_code). The Code₃ and Secret₃ must be constructed similarly.
2. The construction likely involves the delegator response data or the HMAC computation
3. Need to trace the code path from delegator response → credential object construction → Secret₃
4. Alternative: try running the full Toolbox on Windows with a debugger, break on SnakeOil, read the key

---

### 2026-04-17 20:15 — Exhaustive byte combination search negative

**What we tried:**
1. All 4+4 byte splits of hu_secret and tb_secret (BE and LE) as Secret₃ → 4 candidates produce D8 first byte but none contain "Dacia"
2. All 4+4 byte splits with variable start offsets → same result
3. The D8 matches are coincidental (1/256 probability)

**Conclusion:** Secret₃ cannot be derived from simple byte concatenation of known credentials. The derivation involves a more complex computation (likely involving the NNGE engine, MD5, or the credential provider chain we traced earlier).

**Practical decision:** The captured body replay workaround works for the catalog flow. Secret₃ remains a research item. Proceeding with task 4.3 (sync command) using the replay workaround.

---

### 2026-04-17 20:30 — Traced credential builder chain, found debug log format

**New findings from code tracing:**
1. `FUN_100b3a60` (protocol builder) reads credential via `(**(param_1+0x1c))[0x18]()` — credential provider vtable[6]
2. Found debug log: `"name: %s\ncode: %lld\nsecret: %lld"` at line 152350 — confirms credential has Name/Code/Secret as separate fields
3. `FUN_1005fb70` is the device manager credential handler — called from `FUN_1005fca9`
4. `FUN_10062a20` iterates credential entries (stride 0x80) with sub-entries (stride 0x20)
5. Sub-entry type 1 → `FUN_10062240` builds credential with Code/Secret
6. `FUN_10062240` calls `FUN_10063940` which parses a **comma-delimited string** (`", "` delimiter at `DAT_102b3260`)
7. The credential data (Name/Code/Secret) is stored as a text string, not binary

**Exhaustive offset scan:**
- Tried all 4 known keys (tb_secret, tb_code, hu_code, hu_secret) at all body offsets 16-39 → no match
- Secret₃ is confirmed to be a DIFFERENT value from all known credentials

**What we now know about the credential chain:**
```
.lyc files / reg.sav
    → credential provider (FUN_100be3c0)
        → credential entries (0x80-byte structs at +0x58)
            → sub-entries (0x20-byte structs at entry+0x1C)
                → type 1: FUN_10062240 → parses comma-delimited string → Name/Code/Secret
                → type 2/4: FUN_100623f0 → license credentials
```

**The credential string format:** `"field1, field2, field3, ..."` split by `", "` (comma-space)
- The string is at `sub_entry + 0x10 + 8`
- Fields are parsed by `FUN_10063940`
- For type 1 entries: fields include Name, Code, Secret

**Key question:** Where does the credential string for the 0x08 flag come from? It's NOT from reg.sav (which only has tb and hu credentials). It must be constructed during the delegator response processing or session setup.

**Untried approaches:**
1. **Hook the debug log** — the `"name: %s\ncode: %lld\nsecret: %lld"` format string is used to log the credential. If we can capture this log output, we get Secret₃ directly.
2. **Trace FUN_1019eaf0** — this is the session setup function that copies the credential from `this-0x9C`. The `this` object is the credential source for the 0x08 session.
3. **Check if the 0x68 body can be avoided** — test if the web catalog works with only the 0x60 senddevicestatus call (skip 0x68 entirely).
4. **Run the actual Toolbox on Windows** with a debugger, break on the debug log format string, read the credential values.

---

### 2026-04-17 20:06 — SESSION SUMMARY: Secret₃ still unknown after exhaustive search

**Result:** Secret₃ (the SnakeOil body encryption key for 0x08-flag / 0x68 requests) remains unknown. It is NOT any of the 4 known credential values, NOT in the DLL's static data, and NOT a simple derivation from known values.

**What IS confirmed:**
- 0x60 body: encrypted with tb_secret at offset 18 (2-byte query). Decrypts to readable binary with "DaciaAutomotive" brand string. ✓
- 0x68 query: encrypted with tb_code at offset 16 (19-byte query with Name₃ credential block). ✓
- 0x68 body: encrypted with Secret₃ at offset 35. Does NOT decrypt with any known key. ✗
- Name₃ = `0xC4 || hu_code(8B BE) || tb_code(7B BE)` — construction confirmed. ✓
- The credential chain: `.lyc`/`reg.sav` → credential provider → comma-delimited string → parsed into Name/Code/Secret
- Debug log format `"name: %s\ncode: %lld\nsecret: %lld"` exists in the DLL at line 152350

**What was tried and eliminated:**

| # | Approach | Result |
|---|----------|--------|
| 1 | Raw device.nng 8-byte windows as key | No match |
| 2 | XOR-decoded device.nng windows | No match |
| 3 | MD5/SHA1 of device.nng sections | No match |
| 4 | SnakeOil(nng_section, known_key) | No match |
| 5 | All known credential value combinations | No match |
| 6 | DLL .rdata/.data section scan (~123K values) | No match |
| 7 | Wine DLL full init attempts | All hang |
| 8 | Brute-force field3 + 16-bit hi | No match |
| 9 | SnakeOil-decrypt device.nng with NNGE key | No match |
| 10 | Blowfish on device.nng | No match |
| 11 | RSA-decrypt device.nng | Not RSA format |
| 12 | .lyc decrypted data as key source | No match |
| 13 | MAC digest (HMAC_MD5) as key | No match |
| 14 | All 4+4 byte splits of hu_secret/tb_secret (BE/LE) | No match |
| 15 | All body offsets 16-39 with all 4 known keys | No match |
| 16 | Known value pairs (529 combos incl XOR/ADD) | No match |
| 17 | Name₃ bytes as key | No match |

**Current workaround:** Raw replay of captured 0x68 body. Works for catalog flow.

**Next steps (in priority order):**
1. **Test if 0x68 can be skipped entirely** — send only the 0x60 senddevicestatus, skip the 0x68 call. If the web catalog still works, Secret₃ is irrelevant for the sync command. This is the fastest path forward.
2. **Hook the DLL debug log** — the format string `"name: %s\ncode: %lld\nsecret: %lld"` at line 152350 logs the credential. Capture this output by patching the DLL's log function to write to a file, then run a minimal session flow.
3. **Trace FUN_1019eaf0** — the session setup copies credential from `this-0x9C`. Find where `this-0x9C` is populated with the constructed credential (Name₃/Code₃/Secret₃).
4. **Run actual Toolbox on Windows with debugger** — break on SnakeOil (RVA 0x1B3E10), read key_lo and key_hi from the stack when the 0x68 body is encrypted.

---

### 2026-04-17 21:10 — Live test: 0x68 replay broken, catalog empty without senddevicestatus

**Test results:**

| Scenario | 0x60 | 0x68 | Catalog result |
|----------|------|------|----------------|
| Skip all senddevicestatus | — | — | 0 items, 1KB page (minimal) |
| 0x60 only (re-encrypted capture) | 200 | skipped | 0 items, 17KB page (full template, empty) |
| 0x60 + 0x68 raw replay | 200 | **409** | 0 items, 17KB page (same as 0x60 only) |

**Key findings:**
1. **The 0x68 raw replay now returns 409** — the captured body has expired or server state changed
2. **The 0x60 re-encrypted capture returns 200** but the catalog is empty (no actual map updates shown)
3. Without senddevicestatus, the catalog page is minimal (1KB). With 0x60 only, it's full (17KB) but has no content items.
4. The 0x68 call IS required for the catalog to show content — it tells the server the device is REGISTERED (delegated)
5. **Both the 0x60 and 0x68 captured bodies are stale** — the file list doesn't match current device state

**Impact:**
- The replay workaround is BROKEN. We must generate fresh senddevicestatus bodies.
- The 0x60 body format is known (decrypts to readable binary). We can build it from scratch.
- The 0x68 body requires Secret₃ which is still unknown.
- **This is now a BLOCKER** — without a working 0x68 senddevicestatus, the catalog shows no content.

**Next steps:**
1. **Generate a fresh 0x60 body from scratch** — we know the binary format from decrypting the capture. Build it from the actual USB drive data (brand, model, SWID, file list).
2. **For 0x68: try sending the same body as 0x60 but with 0x68 flags and Name₃ query** — maybe the server accepts the same body content regardless of the flag. The body content might be identical; only the query credential block differs.
3. **If step 2 fails: try hu_secret as the body key with the CORRECT body content** — maybe hu_secret IS the key but our earlier test failed because the body content was wrong (stale capture vs fresh data).
4. **If all else fails: hook the DLL debug log** to capture Secret₃ directly.

---

### 2026-04-17 21:30 — 0x68 returns 409 for ALL body variants, Secret₃ is the blocker

**Test results (0x68 with Name₃ query, various body keys):**

| Body content | Body key | Status |
|-------------|----------|--------|
| Stale capture (0x60 plaintext) | tb_secret | 409 |
| Stale capture | hu_secret | 409 |
| Stale capture | hu_code | 409 |
| Stale capture | tb_code | 409 |
| Random garbage (100 bytes) | tb_secret | 409 |
| Empty body | tb_secret | 409 |

**Analysis:** ALL 0x68 requests return 409 regardless of body content or key. Even empty/garbage bodies get 409. Meanwhile, 0x60 with the same stale body returns 200. This confirms:
- The server rejects 0x68 requests at the **decryption stage** (can't decrypt → 409)
- Secret₃ ≠ tb_secret, hu_secret, hu_code, or tb_code
- The 0x60 stale body is still accepted (server can decrypt with tb_secret and tolerates stale content)
- **Secret₃ is the sole blocker** — once we find it, even stale body content might work

**Also confirmed:** The 0x68 raw replay from the capture now returns 409 too. The captured request used a session-specific nonce in the wire header that no longer matches.

**Next steps:**
1. **Hook the DLL debug log** — patch the log function at the `"name: %s\ncode: %lld\nsecret: %lld"` call site to write to a file. Run a minimal session flow in Wine to capture Secret₃.
2. **Trace FUN_1019eaf0** — the session setup copies credential from `this-0x9C`. The `this` object has the constructed credential. Find where `this-0x9C` is populated.
3. **Try running the Toolbox on actual Windows** with x64dbg, break on SnakeOil (RVA 0x1B3E10), read key_lo/key_hi from the stack.

---

### 2026-04-17 21:45 — Arithmetic and hash derivations exhausted

**Additional approaches tried:**
- Multiply/add/subtract/XOR of all credential pairs → no match
- MD5 of each credential (as binary and as decimal string) → no match
- MD5 of Name₃ → no match
- Byte-swapped credentials → no match
- CRC32 of credentials → no match
- Rotated credentials (all 31 rotations) → no match
- Total: 162 + 98 unique candidates tested against "Dacia" in first 100 decrypted bytes

**Conclusion:** Secret₃ is NOT derivable from simple arithmetic, hashing, or byte manipulation of the known credential values. The derivation must involve:
- A complex multi-step computation in the DLL
- Or data from a source we haven't identified (e.g., a server response field we missed)
- Or the NNGE engine processing device.nng through a path we haven't traced

**Assembly confirmed:** At RVA 0x0B4055-0x0B4061, the credential object is in ECX with Secret at [ECX+0x1C] (lo) and [ECX+0x20] (hi). The CALL to sprintf at 0x0B406C logs these values.

**Next steps:**
1. **Run the actual Toolbox on Windows with x64dbg** — set breakpoint at RVA 0x0B4055, read ECX+0x1C and ECX+0x20 when hit. This is the most direct path to Secret₃.
2. **Alternative: patch the DLL binary** — replace the CALL at 0x0B406C with code that writes ECX+0x1C/0x20 to a fixed memory address, then read it after the session runs.
3. **Alternative: trace the NNGE engine** — the credential provider chain leads through FUN_100be3c0 → FUN_100bed80 (license loader) → NNGE engine. The NNGE engine might derive Secret₃ from device.nng through a path we haven't fully traced.

---

### 2026-04-17 22:00 — DLL hook failed (DllMain hangs), HMAC derivations exhausted

**DLL hooking attempt:**
- Patched SnakeOil (RVA 0x1B3E10) with JMP to hook function
- LoadLibrary hangs (DllMain blocks on COM/threading init)
- LoadLibraryEx + manual DllMain call also hangs
- Cannot run the DLL in Wine without full Windows environment

**Additional derivation attempts:**
- 3564 HMAC-MD5/SHA1 candidates (all key/data combinations of credentials, names, Name₃) → no match
- 96 delegation response candidates (HMAC with delegation data, MAC digest, MaxAge, response offsets) → no match
- All wire headers use tb_code — confirmed the 0x68 request uses tb_code for query, Secret₃ for body

**Wire header analysis confirmed:**
- ALL 15 captured requests use `code = tb_code` (3745651132643726) in the wire header
- The 0x68 query decrypts with tb_code to reveal Name₃ credential block
- The server uses Name₃ to look up the corresponding Secret₃ for body decryption
- Secret₃ must be known to both client and server — derived from shared data

**Total approaches tried: 20+** (see eliminated approaches table + this session's additions)

**Next steps:**
1. **Run the actual Toolbox on a real Windows machine** with x64dbg. Set hardware breakpoint on RVA 0x0B4055 (PUSH [ECX+0x20] = Secret_hi). Read ECX+0x1C and ECX+0x20. This is the only reliable path left.
2. **Alternative: capture fresh mitmproxy traffic** from the real Toolbox on Windows. The new capture will have a fresh 0x68 body. Even without knowing Secret₃, we can replay the fresh capture.
3. **Alternative: try the NNGE engine path** — FUN_100bed80 (license loader) creates credential entries. The NNGE engine at FUN_100ea130 might process device.nng through a different code path than we traced. Re-examine with focus on the credential entry creation, not the NNGE parser.

---

### 2026-04-17 22:15 — Traced credential entry creation, confirmed Name₃ not in any file

**FUN_100bed80 trace (license loader):**
1. Iterates `.lic` and `.lyc` files
2. For each file: `FUN_10101ab0` parses the file, `FUN_100ea6f0` creates a 0x70-byte credential entry, `FUN_10101e80` processes it
3. `FUN_10101e80` reads RSA payload: magic `0x36c8b267` (LE), then XOR-CBC key (16B), then credential data
4. The .lyc files contain LICENSE data (license keys like `CP-3IE3-EEMQ`), NOT Code/Secret values
5. The credential Code/Secret come from `reg.sav` / `service_register_v1.sav`, not from .lyc files

**File analysis:**
- `reg.sav`: Contains URL, device info (brand, model, SWID, IMEI, iGO version, APPCID, serial), then ONE credential entry (hu_name + hu_code + hu_secret + MaxAge=300). Format: `[0x80] [0xE0 field_mask] [name(16B)] [code(8B BE)] [secret(8B BE)] [maxage(4B)] [flags]`
- `service_register_v1.sav`: Contains TWO credential entries (hu and tb) plus three license SWIDs. No third credential.
- **Name₃ is NOT in any file** — confirmed by searching both reg.sav and service_register_v1.sav

**Credential object layout (from assembly at RVA 0x0B4055):**
```
+0x04: Name (16 bytes)
+0x10: Code_lo (uint32)  ← PUSH [ecx+16]
+0x14: Code_hi (uint32)  ← PUSH [ecx+20]
+0x18: ??? (4 bytes gap)
+0x1C: Secret_lo (uint32) ← PUSH [ecx+28]
+0x20: Secret_hi (uint32) ← PUSH [ecx+32]
```

**Conclusion:** The 0x08 credential (Name₃/Code₃/Secret₃) is constructed at runtime from the hu and tb credentials. It is NOT stored in any file and NOT returned by any server response. The construction algorithm is in the DLL code — likely in the session setup path between the delegator response handler and the protocol builder.

**Next steps:**
1. **Run the actual Toolbox on Windows with x64dbg** — breakpoint at RVA 0x0B4055, read ECX+0x1C and ECX+0x20 when the 0x08 credential is used. This is the most direct and reliable path.
2. **Capture fresh mitmproxy traffic** — even without knowing Secret₃, a fresh capture provides a working 0x68 body for replay.

---

### 2026-04-17 22:30 — CRITICAL: Assembly shows SAME key for query and body, contradicts protocol

**Assembly at RVA 0x0B4133-0x0B415D (two SnakeOil calls):**
```
; First call (query encryption):
0B4133: MOV eax, [edi+0x40]     ; eax = key pointer
0B4136: MOV ecx, [edi+0x2C]     ; ecx = query buffer
0B4139: PUSH [eax+0x04]         ; key_hi
0B413C: PUSH [eax]              ; key_lo
0B413E: PUSH ecx                ; dst (= src, in-place)
0B413F: PUSH [edi+0x34]         ; len
0B4142: PUSH ecx                ; src
0B4143: CALL SnakeOil

; Second call (body encryption):
0B4148: MOV eax, [edi+0x40]     ; eax = SAME key pointer
0B414B: MOV ecx, [edi+0x04]     ; ecx = body buffer
0B414E: PUSH [eax+0x04]         ; key_hi (SAME)
0B4151: PUSH [eax]              ; key_lo (SAME)
0B4153: PUSH ecx                ; dst
0B4154: PUSH [edi+0x0C]         ; len
0B4157: PUSH ecx                ; src
0B4158: CALL SnakeOil

0B415D: ADD ESP, 0x28           ; clean up 40 bytes (10 pushes)
```

**Contradiction:** Both calls use `[edi+0x40]` as the key pointer, reading `[eax]` (lo) and `[eax+4]` (hi). But we PROVED query uses tb_code and body uses tb_secret (XOR test: `enc_q[0] XOR enc_b[0] = 0x80 ≠ plain_q[0] XOR plain_b[0] = 0x1D`).

**Possible explanations:**
1. `[edi+0x40]` points to a **16-byte key pair** `[Code_lo, Code_hi, Secret_lo, Secret_hi]`, and the first call uses `[eax]/[eax+4]` (Code) while the second call SHOULD use `[eax+8]/[eax+12]` (Secret) — but the assembly shows `[eax]/[eax+4]` for both. **Ghidra may have the wrong disassembly.**
2. The SnakeOil function at 0x1B3E10 is a **wrapper** that internally selects the key based on a global counter or flag.
3. The `[edi+0x40]` pointer is modified by a **concurrent thread** between the two calls.

**What this means for Secret₃:** If explanation #1 is correct, the key object at `[edi+0x40]` contains `[Code₃_lo, Code₃_hi, Secret₃_lo, Secret₃_hi]`. For the 0x08 credential, Code₃ = tb_code (confirmed from wire headers). Secret₃ is at offset +8 in the key object. The key object is built from the credential object's Code and Secret fields.

**Next steps:**
1. **Verify explanation #1** — read the raw bytes at 0x0B414E more carefully. Maybe it's `FF 70 0C` (`PUSH [eax+0x0C]`) not `FF 70 04` (`PUSH [eax+0x04]`). A single byte difference would explain everything.
2. If the second call uses `[eax+8]` and `[eax+12]`, then Secret₃ is at key_object+8 and key_object+12. The key object is the 16-byte buffer allocated at `param_3[0x10]` in the protocol builder.

---

### 2026-04-17 22:45 — BREAKTHROUGH: Brand string at offset 23 (not 5), PRNG target corrected

**Critical finding:** XOR of flows 737 and 754 shows the brand string "DaciaAutomotive" is at **offset 23** in the 0x68 body, NOT offset 5 (as in the 0x60 body). The 0x68 body has 18 extra header bytes before the brand string.

**XOR analysis (737 vs 754):**
- Bytes 0-3: all zeros (identical header)
- Byte 4: 0x1D (differs — likely a counter or size field)
- Bytes 5-7: zeros
- Bytes 8-22: non-zero (different data — likely Delegation section)
- **Bytes 23-193: 171 consecutive zeros** (identical content — brand + model + SWID + file list)
- Bytes 194-226: non-zero (different data)
- Bytes 227-369: 143 consecutive zeros (more identical content)

**Corrected PRNG target:**
- PRNG[0] = 0xE9 (assuming plaintext[0] = 0xD8)
- PRNG[22] = 0x07 (verified: enc[22] = 0x08, plaintext[22] = 0x0F strlen)
- PRNG[22:38] = `07 20 17 22 95 5c 31 0d 67 d2 62 d0 f9 3a a3 a9`

**Previous PRNG target was WRONG:** We assumed "DaciaAutomotive" at offset 5, giving PRNG[5:20]. The correct target uses offset 22+ for the strlen byte and brand string.

**Brute-force launched:** Three parallel searches covering hi=0x00000000-0x00200000 (2M hi values). Each hi value tests all 2^32 lo values with PRNG[0] as fast filter and PRNG[22:26] as verification.

**Assembly contradiction explained (partially):** The two SnakeOil calls at 0x0B4143/0x0B4158 both use `[edi+0x40]` as key. The FUN_100b4600 debug logging calls show the body uses `piVar11[1]/piVar11[3]` and query uses `piVar11[0xb]/piVar11[0xd]` — these are the DATA pointers, not keys. The actual encryption key is at `piVar11[0x10]` for both. The contradiction (same key, different encrypted output) remains unexplained without a debugger.

**Next steps:**
1. Monitor brute-force results (running in background)
2. While waiting: investigate the 18 extra header bytes in the 0x68 body — what's the Delegation section format?
3. Try to reconstruct the 0x68 plaintext from the 0x60 plaintext + Delegation data

---

### 2026-04-17 23:00 — Corrected brand offset to 24, brute-force restarted

**Correction:** Brand "DaciaAutomotive" is at offset **24** (not 23). The strlen byte (0x0F) is at offset 23. Verified by XOR analysis: bytes 23-193 are identical across flows 737 and 754 (171 consecutive zero bytes in XOR).

**Corrected PRNG target:**
- PRNG[0] = 0xE9 (assuming plaintext[0] = 0xD8)
- PRNG[23] = 0x6B (enc[23]=0x64, plaintext[23]=0x0F strlen)
- PRNG[23:39] = `6B 32 20 9F 54 11 39 66 C9 60 D2 E2 27 BC BA 8D`

**0x68 body structure (revised):**
```
[0-3]   Header (4 bytes, constant across flows)
[4]     Variable byte (differs between flows — counter or size)
[5-7]   Constant data (3 bytes)
[8-22]  Variable data (15 bytes — Delegation section: timestamp + MAC?)
[23]    0x0F = strlen("DaciaAutomotive")
[24-38] "DaciaAutomotive" (brand)
[39+]   Model, SWID, etc. (same as 0x60 body from offset 20+)
```

**Brute-force status:** Running with 4 threads on 4-core machine, searching hi=0x000A0000-0x000F0000 (327K values). Uses PRNG[0]=0xE9 as fast filter, PRNG[23:27] as verification.

**Next steps:**
1. Monitor brute-force (estimated ~21 hours for full range)
2. If not found: try alternative first bytes (0xD9, 0xDC, 0xF8)
3. If not found: expand hi range beyond 0x000F0000

---

### 2026-04-17 23:15 — Delegator response decoded, Secret₃ not in any response field

**Delegator response (flow 736) decoded with `parse_response(tb_secret)`:**
```
80 E0 [hu_name(16B)] [hu_code(8B BE)] [hu_secret(8B BE)] [MaxAge=300] [00]
[04] [license SWIDs: CW-UQAQ-YAEQ, CP-3IE3-EEMQ, CW-YUEM-E7QU, CW-AUM3-777Q]
```
- hu_code = 3362879562238844 ✓
- hu_secret = 4196269328295954 ✓
- 4 license SWIDs (one more than in service_register_v1.sav)

**Tried as Secret₃:** Every 8-byte window (LE and BE) of the decrypted delegator response body (175 bytes) → no match.

**0x68 body structure (refined):**
- 0x60 XML has `<State>RECOGNIZED</State>` + `<UniqId>...</UniqId>`
- 0x68 XML has `<State>REGISTERED</State>`, NO UniqId
- Binary difference: 0x68 has 19 extra bytes (Delegation ref) but removes 33 bytes (UniqId)
- Net: 1461 - 33 + 19 + 4 = 1451 bytes ✓

**Brute-force status:** Two processes running (hi=0x00000000-0x000A0000 and 0x000A0000-0x000F0000). ~8.5 hi/sec. Estimated completion: ~10-21 hours. No results yet after 5 minutes.

**Next steps:**
1. Continue monitoring brute-force
2. Try alternative plaintext first bytes if D8 search fails
3. Consider: the 0x68 body might use a completely different binary format than 0x60

---

### 2026-04-18 05:35 — CORRECTION: Brand at offset 26, brute-force running 7 hours

**Supersedes entries at 22:45 and 23:00** — those had wrong brand offsets.

**Correct XOR analysis (all 3 flows: 737, 754, 792):**
- Bytes constant across ALL 3 flows: 0-3, 5-6, 25+
- Bytes variable: 4, 7-24 (21 bytes of variable data)
- Brand "DaciaAutomotive" starts at offset **26**, strlen=0x0F at offset **25**

**Correct PRNG target (used in running brute-force):**
- PRNG[0] = 0xE9 (assuming plaintext[0] = 0xD8)
- PRNG[25:41] = `4E B8 5C 13 11 72 FC 7A CB E2 3E BA B8 81 01 CB`

**0x68 body structure (final):**
```
[0-3]   Header (4 bytes, constant across all flows)
[4]     Variable (counter/size — differs between all flow pairs)
[5-6]   Constant (2 bytes)
[7-24]  Variable (18 bytes — Delegation data: timestamps + MAC?)
[25]    0x0F = strlen("DaciaAutomotive")
[26-40] "DaciaAutomotive" (brand)
[41+]   Model, SWID, etc. (same structure as 0x60 body from offset 20+)
```

**Brute-force status:** PID 757030 running since 22:38 (7 hours). 2 threads, searching hi=0x000A0000-0x000F0000 (327K values). At ~4 hi/sec = ~100K done (~30%). No result yet. Estimated completion: ~14 more hours.

**Risk:** If plaintext[0] ≠ 0xD8, the PRNG[0]=0xE9 filter rejects the correct key. Would need to restart with different first-byte assumptions.

**Next steps:**
1. Let brute-force continue running
2. If no result by completion: try plaintext[0] = 0xD9, 0xDC, 0xF8 (different presence bitmasks)
3. If still no result: expand hi range to 0x00000000-0x00200000
4. Alternative: capture fresh mitmproxy traffic on Windows (bypasses Secret₃ entirely)

### 2026-04-18 06:20 — Brute-force still running after 24h, telegram bot blocked by AccessDeniedException

**Status check:**
- PID 690738 (Z3 SnakeOil brute-force) has been running for 24+ hours with no result
- The process was spawned by the telegram-kiro-bot service's second kiro-cli session
- It searches hi=0x000A0000-0x000F0000 with PRNG[0]=0xE9 filter and PRNG[25:27] verification
- No matches found — likely wrong plaintext first-byte assumption (0xD8) or key outside search range

**Telegram bot issue:**
- Both kiro-cli sessions under the bot service are returning `AccessDeniedException` since ~06:12
- Re-authenticating with Kiro (browser login) does NOT refresh credentials for the bot's kiro-cli processes
- No `/refresh` or re-auth slash command exists in kiro-cli
- The only fix is restarting the service (`sudo systemctl restart telegram-kiro-bot.service`), which kills the Z3 process
- **Recommendation:** Use `KIRO_API_KEY` environment variable (long-lived API key from app.kiro.dev) in the bot's service unit to prevent future credential expiry

**Decision needed:**
- Kill the brute-force and restart the bot service (Z3 search is unlikely to converge)
- Or let it run and leave the bot broken until it finishes/is manually killed

**Next steps (unchanged from 2026-04-18 05:35):**
1. If brute-force completes with no result: try plaintext[0] = 0xD9, 0xDC, 0xF8
2. Expand hi range to 0x00000000-0x00200000
3. Alternative: capture fresh mitmproxy traffic on Windows (bypasses Secret₃ entirely)

---

### 2026-04-18 06:35 — Brute-force abandoned, switching to Unicorn Engine emulation

**Brute-force result:** Killed after 24+ hours with no result. The search covered hi=0x000A0000-0x000F0000 with PRNG[0]=0xE9 filter (assuming plaintext[0]=0xD8). Likely failed due to wrong first-byte assumption or key outside the search range. The search space is too large for blind brute-force without better constraints.

**New approach: Unicorn Engine (CPU emulator)**

Instead of trying to run the full DLL (Wine/LoadLibrary hangs on DllMain), we'll emulate individual x86-32 functions from `nngine.dll` using Unicorn Engine — a lightweight CPU emulator with Python bindings. This lets us:

1. Load the DLL as a raw binary blob into emulated memory (no DllMain, no Windows APIs)
2. Parse PE sections and apply relocations for the actual load base
3. Set up stack, heap, and data segments in emulated memory
4. Call specific functions by setting ESP/EIP and providing arguments on the stack
5. Hook/stub any Windows API imports (malloc → emulated heap, file I/O → injected data)
6. Read results from emulated registers/memory after execution

**Why this works:**
- x86 machine code is platform-independent — the instructions are the same on Windows and Linux
- Unicorn emulates the CPU only, no OS dependencies
- We can surgically execute just the credential derivation functions without the full DLL init chain
- External calls (kernel32, msvcrt) are intercepted and stubbed at the instruction level
- Python-only, no 32-bit compilation needed (this machine lacks `glibc-devel-32bit`)

**Execution plan:**
1. **T10: Setup** — Python venv with `unicorn` and `capstone` (disassembler for debugging)
2. **T11: PE loader** — Parse PE headers, map `.text`/`.rdata`/`.data` sections into Unicorn memory at correct RVAs, apply base relocations
3. **T12: Validate with SnakeOil** — Emulate `SnakeOil(RVA 0x1B3E10)` with known inputs (decrypt 0x60 body with tb_secret). If output contains "DaciaAutomotive", the harness works.
4. **T13: Emulate credential derivation** — Run `FUN_10044c60` (device.nng reader) or trace from `FUN_100bed80` (license loader). Provide device.nng data in emulated memory. Stub file I/O to return device.nng contents. Stub malloc to allocate from emulated heap.
5. **T14: Read Secret₃** — After derivation completes, read `cred+0x1C` (lo) and `cred+0x20` (hi) from emulated memory.
6. **T15: Validate** — Decrypt captured 0x68 body with the extracted Secret₃, verify "DaciaAutomotive" at offset 26.

**Key functions to emulate:**
| RVA | Function | Purpose | External deps |
|-----|----------|---------|---------------|
| 0x1B3E10 | SnakeOil | Stream cipher | None (pure computation) |
| 0x044C60 | device.nng reader | Reads device.nng, derives credential | File I/O (stub with injected data) |
| 0x0BD380 | NNGE vtable[2] | Formats "SPEEDx%sCAM", computes MD5 | sprintf (stub) |
| 0x0EA130 | NNGE file parser | Reads .nng files | File I/O (stub) |
| 0x157D40 | MD5 | Standard MD5 hash | None (pure computation) |

**Risk:** Complex functions with deep call chains may hit unstubbed Windows APIs, causing emulation failures. Mitigation: start with SnakeOil (pure computation, no external deps) to validate the approach, then incrementally add stubs as needed.

**Next steps:** T10 — set up the Unicorn Engine environment.

---

### 2026-04-18 06:40 — Unicorn harness working, HMAC-MD5 discovery, credential name correction

**Unicorn Engine harness validated (T10–T12 complete):**
- `analysis/unicorn_harness.py` loads nngine.dll at 0x10000000, maps all PE sections, applies relocations
- SnakeOil emulation works: `snakeoil(zeros, tb_secret)` → `bc755fbc32341970` ✓
- Flow 735 body decryption works: "DaciaAutomotive" at offset 5 ✓
- Stack at 0x00100000 (1MB), heap at 0x00400000 (1MB), stop sentinel at 0x00DEAD00

**HMAC-MD5 function identified:**
- `FUN_101aa3a0(output, key, key_len, data, data_len)` = standard HMAC-MD5
- XOR constants at RVA 0x2D2610 = `0x36` (ipad) and RVA 0x2D2620 = `0x5C` (opad) — confirmed standard HMAC
- Inner hash functions: `FUN_101577d0` (MD5 init), `FUN_10157820` (MD5 update), `FUN_101578e0` (MD5 final)
- Verified in Unicorn: `HMAC-MD5("key", "The quick brown fox...")` = `80070713463e7749b90c2dc24911e275` ✓

**Credential construction function `FUN_101aa050` traced:**
- Called from delegation handler with `(Code_ptr, Secret_ptr)` from delegation response
- Creates a 0x58-byte credential object with vtables at PTR_FUN_102b9590, PTR_FUN_102b9580, PTR_FUN_102b9588
- Object layout (uint32 indices):
  - `[0]`: vtable PTR_FUN_102b9590
  - `[2]`: vtable PTR_FUN_102b9580
  - `[4]`: type = 1
  - `[6..7]`: Code (from param_1, = hu_code from delegation response)
  - `[9..10]`: copied from device manager object at +0x10 (unknown)
  - `[0xb]`: copied from device manager object at +0x18 (unknown)
  - `[0xc..0xd]`: timestamp (from `FUN_101d2630`)
  - `[0xe]`: vtable PTR_FUN_102b9588
  - `[0x10]`: mode = 3
  - `[0x12]`: Name buffer pointer
  - `[0x13]`: Name length
  - `[0x14]`: Name capacity
- **Secret is NOT set in this function** — it must be set by a vtable method or inherited from the device manager
- The HMAC-MD5 output (16 bytes) is copied into the Name buffer (`puVar9[0x12]`)
- HMAC key = Secret (8 bytes, big-endian byte order)
- HMAC data = serialized by `FUN_101a9930(&local_44, 0)` — complex vtable-based serializer, data unknown

**Credential Name correction — Name₃ is NOT what we thought:**
- Previously assumed Name₃ = `C4000BF28569BACB7C000D4EA65D36B9` (0xC4 || hu_code BE || tb_code BE truncated)
- **Actual credential name from wire traffic:** `ad35bcc12654b893f7b5596a8057190c`
- Verified across all three 0x68 flows (737, 754, 792) — all have the same name
- The query credential block format is: `[0xD8 type] [16-byte name]`
- The `C4000BF28569BACB7C000D4EA65D36B9` value was likely a misinterpretation of the query format
- The actual name `ad35bcc12654b893f7b5596a8057190c` looks like HMAC-MD5 output (16 random-looking bytes)
- Tested HMAC-MD5 with all simple key/data combinations of known credentials — no match
- The HMAC data must include serialized fields beyond just the credential values

**Assembly analysis — query and body encryption:**
- At RVA 0x0B4133-0x0B415D, both SnakeOil calls use `[edi+0x40]` as key pointer, reading `[eax]` and `[eax+4]`
- This suggests both query and body use the SAME key (Secret from credential)
- **But wire traffic proves otherwise:** decrypting queries with tb_code gives clean counter+flags patterns (0xC0→0xC7 incrementing counter, 0x20/0x60/0x68 flags). Decrypting with tb_secret gives garbage.
- Possible explanation: the Ghidra decompilation is misleading, or there's an indirection/wrapper we're missing
- **For practical purposes:** query is encrypted with Code, body with Secret (as protocol.py implements)

**Credential object layout discrepancy:**
- The 0x58-byte object from `FUN_101aa050` has Code at byte offset +0x18/+0x1C (puVar9[6..7])
- The debug log at line 152354 reads Code from +0x10/+0x14 and Secret from +0x1C/+0x20
- These are DIFFERENT offsets → the protocol builder uses a DIFFERENT credential object than the 0x58-byte one
- The protocol builder gets its credential via `(**(code **)(**(int **)(param_1 + 0x1c) + 0x18))()` — a vtable[6] call
- The returned object has: Name at +0x00, Code at +0x10/+0x14, Secret at +0x1C/+0x20

**Updated known values:**

| Name | Value | Source |
|------|-------|--------|
| Actual credential name | `ad35bcc12654b893f7b5596a8057190c` | Wire traffic (0x68 query decrypted with tb_code) |
| Query cred type byte | `0xD8` | Wire traffic |
| HMAC-MD5 function | RVA 0x1AA3A0 | Confirmed in Unicorn |
| HMAC ipad constant | RVA 0x2D2610 = `0x36` repeated | Standard HMAC |
| HMAC opad constant | RVA 0x2D2620 = `0x5C` repeated | Standard HMAC |
| Credential ctor | RVA 0x1AA050 (`FUN_101aa050`) | Decompiled code |

**Next steps:**
1. Read vtable PTR_FUN_102b9590 to find the method that returns the credential with Code/Secret at the offsets the protocol builder expects
2. Trace where Secret₃ is actually set — it's not in `FUN_101aa050`, so it must be set by a vtable method or by the caller after construction
3. Alternative: emulate `FUN_101aa050` in Unicorn with stubbed vtable calls to see what the full credential object looks like

---

### 2026-04-18 06:55 — Phase 1 negative, Unicorn confirms same-key encryption, credential name corrected

**Phase 1 result: HMAC-MD5 as Secret₃ — NEGATIVE**
- 1200+ HMAC-MD5 candidates tested (all key/data combos of known credentials, device.nng fields, APPCID, brand MD5, NNGE key, credential name)
- Also tested plain MD5 of credential name + credential combos
- Also tested credential name bytes directly as Secret₃ (LE, BE, uint64)
- Also tested device.nng field combinations (field1, APPCID, field3) as Secret₃
- **No match.** Secret₃ is not a simple HMAC-MD5 or MD5 derivation of known values.

**Unicorn emulation of FUN_100b3a60 — CRITICAL FINDING:**
- Built `analysis/unicorn_trace_secret.py` — hooks vtable call, SnakeOil, malloc, and 20+ stub functions
- Set up fake credential object with sentinel values: Secret=0xCAFEBABEDEADBEEF, Code=tb_code
- Hooked SnakeOil to capture actual key used
- **Result: BOTH SnakeOil calls use the SAME key = Secret from cred+0x1C/0x20**
- Memory reads confirmed: cred+0x10 (Code, 8B), cred+0x18 (unknown, 4B), cred+0x1C (Secret_lo), cred+0x20 (Secret_hi)
- This contradicts `protocol.py` which claims query uses Code and body uses Secret

**Split encryption analysis:**
- Wire traffic with tb_code decryption gives clean counter+flags: 0x20 (basic), 0x60 (senddevicestatus), 0x68 (senddevicestatus+cred), 0x28 (unknown)
- Wire traffic with tb_secret decryption gives 0x89/0xC9/0xC1/0x81 — not clean flags
- But Unicorn proves the DLL uses same key for both → **the "clean flags" with tb_code may be coincidental or there's a transport-layer re-encryption**
- 8 total SnakeOil call sites in the DLL. The pair at 0x0B4143/0x0B4158 both use `[edi+0x40]` → `[eax]/[eax+4]` (same pointer, same offsets)
- **Ghidra decompilation may be misleading** — the assembly is clear but the actual runtime behavior might differ due to vtable indirection we can't see statically

**Credential object layout (confirmed by Unicorn memory trace):**
```
+0x00: (vtable or name pointer)
+0x10: Code_lo (uint32)     ← read as 8-byte movq xmm0
+0x14: Code_hi (uint32)
+0x18: Unknown field (uint32) ← read separately
+0x1C: Secret_lo (uint32)   ← used as SnakeOil key
+0x20: Secret_hi (uint32)   ← used as SnakeOil key
```

**0x58-byte object offset theory:**
- FUN_101aa050 creates 0x58-byte object with Code at puVar9[6..7] (offset 0x18/0x1C)
- Protocol builder reads Code from cred+0x10/0x14 — different offset!
- If vtable[6] returns `&puVar9[2]` (offset 8 into the object), then:
  - returned+0x10 = puVar9[6] = Code_lo ✓
  - returned+0x14 = puVar9[7] = Code_hi ✓
  - returned+0x1C = puVar9[9] = value from device manager +0x10
  - returned+0x20 = puVar9[10] = value from device manager +0x14
- **This means Secret₃ = the 8-byte value copied from the device manager at iVar5+0x10**
- iVar5 comes from `FUN_10011dd0` → vtable[6] call — the "NAVIEXTRAS_UNIQUE_DEVICE_ID" singleton

**Next steps:**
1. Phase 2: Trace what `FUN_10011dd0` returns and what its vtable[6] gives at +0x10/+0x14
2. The device manager singleton is initialized from device.nng or registration data
3. Alternative: try to emulate `FUN_101aa050` in Unicorn with stubbed dependencies to see the full credential object

---

### 2026-04-18 07:05 — Phase 2: Traced device manager chain, emulation hitting global object manager

**Device manager vtable chain traced:**
1. `FUN_10011dd0` — the "NAVIEXTRAS_UNIQUE_DEVICE_ID" singleton manager
2. Returns a device object with vtable `PTR_FUN_102b9688`
3. Vtable[6] (+0x18) = `FUN_10094CE0`: reads `this[0xF]` (offset 0x3C), if non-null calls `FUN_100a4bb0`
4. `FUN_100a4bb0`: returns `[ecx + 0x1C]` — the value at offset 0x1C in the inner object
5. In `FUN_101aa050`: `*(puVar9 + 9) = *(iVar5 + 0x10)` — copies 8 bytes from the returned object

**Offset theory refined:**
- The 0x58-byte credential object has Code at puVar9[6..7] (byte offset 0x18/0x1C)
- Protocol builder reads Code from cred+0x10/0x14 — offset difference = 8 bytes
- If vtable returns `&puVar9[2]` (8 bytes into the object):
  - cred+0x10 = puVar9[6] = Code_lo ✓
  - cred+0x1C = puVar9[9] = value from device manager
  - **Secret₃ = puVar9[9..10] = 8 bytes copied from device_obj[0xF][7] + 0x10**

**Device object construction:**
- `FUN_10094510` creates the device object (0x54 bytes)
- Fields 7-0x11 initialized to 0 (populated later during registration)
- `param_1[0xF]` (offset 0x3C) = inner object pointer, set during registration
- The inner object at `[0xF][7]` (offset 0x3C → 0x1C) has credential data at +0x10

**Global data references:**
- `DAT_10326d38` = global object manager (null in DLL, initialized during DllMain)
- `DAT_10314798` through `DAT_103147e8` = registration credential data (runtime-populated)
- `FUN_10056830` copies from these globals into credential objects
- The "REGISTER" string at `DAT_102d2aec` confirms this is the registration credential path

**service_register_v1.sav structure (270 bytes):**
```
[0x00] Header: 00 00 00 05 00 02
[0x06] Entry 1 name length + "DEVICE_1_NAVIEXTRAS_UNIQUE_DEVICE__ID"
[0x2E] Entry 1 credential:
       [16B name/hash: 69c1448b80e0c10cd1fd4a2f23f921d6]
       [6B gap: e3b093d5957a]
       [8B hu_code BE: 000bf28569bacb7c]
       [8B hu_secret BE: 000ee87c16b1e812]
       [4B flags: 00000001]
       [2B: 2c00]
       [license SWIDs...]
[0xC0] Entry 2 name length + "NAVIEXTRAS_UNIQUE_DEVICE__ID"
[0xDF] Entry 2 credential:
       [16B name/hash: 69c142e880e0fb86acd6eba8f54a93c4]
       [6B gap: 286ce077d06c]
       [8B tb_code BE: 000d4ea65d36b98e]
       [8B tb_secret BE: 000acab6c9fb66f8]
       [4B flags: 00000001]
```

**Emulation status:**
- `FUN_101aa050` emulation crashes at RVA 0x1AA21E — `call [eax + 8]` where eax = `*DAT_10326d38`
- The global object manager at `DAT_10326d38` is null (not initialized without DllMain)
- Stubbing it requires setting up a fake object manager with create/destroy methods
- Current stub setup has a bug — the function pointer at obj_mgr+8 isn't being called correctly
- Need to debug the heap memory layout or take a different approach

**What we tried and eliminated (Phase 2):**
- device.nng fields (field1, APPCID, field3) as Secret₃ → no match
- reg.sav credential hashes as Secret₃ → no match
- 6-byte gap values from credential entries → no match
- Credential name bytes as Secret₃ → no match

**Next steps:**
1. Fix the object manager stub in the Unicorn emulation
2. Or: skip `FUN_101aa050` entirely and focus on the device manager singleton — find what value is at device_obj[0xF][7]+0x10 by tracing the registration flow
3. Or: the 6-byte gap in the credential entries might encode the Secret₃ derivation key — investigate further

---

### 2026-04-18 07:20 — OFFSET THEORY CONFIRMED: Secret₃ = cred_data[0x10], object manager fixed

**FUN_101aa050 emulation SUCCESS after fixing two bugs:**
1. `FUN_10096700` (singleton constructor) needed stubbing — returns `ecx` (thiscall, return this)
2. `DAT_10326d38` (global object manager) was being overwritten by DLL section load — now written AFTER load

**Confirmed credential object layout (0x58 bytes):**
```
+0x00: 0x102B9590  vtable PTR_FUN_102b9590 ✓
+0x08: 0x102B9580  vtable PTR_FUN_102b9580 ✓
+0x10: 0x00000001  type = 1
+0x14: 0x00000001  flag
+0x18: 0x69BACB7C  hu_code_lo ✓ (from param_1)
+0x1C: 0x000BF285  hu_code_hi ✓
+0x20: 0x00000001  flag
+0x24: SENTINEL    ← from device manager +0x10 (Secret₃ lo)
+0x28: SENTINEL    ← from device manager +0x14 (Secret₃ hi)
+0x2C: SENTINEL    ← from device manager +0x18
+0x38: 0x102B9588  vtable PTR_FUN_102b9588
+0x40: 0x00000003  mode = 3
```

**Offset theory CONFIRMED:**
- `puVar9[9..10]` (byte offset 0x24/0x28) = values from `cred_data_obj+0x10/0x14`
- If the protocol builder's vtable returns `&puVar9[2]` (offset 8 into the 0x58-byte object):
  - `cred+0x10` = puVar9[6] = Code_lo ✓
  - `cred+0x1C` = puVar9[9] = Secret₃_lo ✓
- **Secret₃ = 8 bytes at offset 0x10 in the object returned by the device manager vtable[6] chain**

**Full pointer chain for Secret₃:**
```
Secret₃ = *(*(*(device_obj + 0x3C) + 0x1C) + 0x10)
           │         │              │           │
           │         │              │           └─ 8 bytes at +0x10 in innermost object
           │         │              └─ pointer at +0x1C in middle object
           │         └─ pointer at +0x3C (param_1[0xF]) in device object
           └─ device manager singleton from FUN_10011dd0
```

**What we still don't know:**
- The actual VALUE at the end of this pointer chain
- The innermost object is populated during registration, not from static data
- Tested all known credential values (LE, BE, byte-swapped) and gap bytes — no match
- The value must be derived during the registration flow or read from a file we haven't examined

**Files created/modified:**
- `analysis/unicorn_trace_secret.py` — protocol builder emulation (confirms same-key for both SnakeOil calls)
- Inline scripts for FUN_101aa050 emulation (confirms offset theory)

---

### 2026-04-18 07:35 — Traced full pointer chain, Secret₃ = Code of unknown third credential

**Full pointer chain confirmed:**
```
Secret₃ = *(*(*(device_obj + 0x3C) + 0x1C) + 0x10)
```
- `device_obj + 0x3C` = `param_1[0xF]` — pointer to middle object
- `middle + 0x1C` = `middle[7]` — pointer to innermost object (via `FUN_100a4bb0`)
- `innermost + 0x10` = Code field (8 bytes) — confirmed by copy constructor at line 22829

**Copy constructor layout (FUN_1001fc00, line 22829):**
```
param_1[4..5] = *(param_2 + 0x10)   → Code (8 bytes)
param_1[6]    = *(param_2 + 0x18)   → unknown field
param_1[7..8] = *(param_2 + 0x1c)   → Secret (8 bytes)
param_1[9]    = *(param_2 + 0x24)   → unknown field
param_1[10..11] = *(param_2 + 0x28) → unknown (8 bytes)
param_1[12]   = *(param_2 + 0x30)   → unknown field
param_1[13..14] = *(param_2 + 0x34) → unknown (8 bytes)
param_1[0xf]  = *(param_2 + 0x3c)   → inner object pointer
param_1[0x10] = *(param_2 + 0x40)   → flags (2 bytes)
```

**Key finding: Secret₃ = Code of the innermost credential object**
- The `+0x10` offset in the credential struct = Code field
- `FUN_101aa050` copies `*(iVar5 + 0x10)` into `puVar9[9..10]`
- This is the Code from the object returned by the device manager vtable[6] chain
- **Neither tb_code nor hu_code work as Secret₃**
- The innermost object must contain a THIRD credential — not TB, not HU

**Where does the third credential come from?**
- `device_obj[0xF]` is set by `FUN_10055c70` (param_1[0xf] = param_2)
- `FUN_10055c70` is called from 23 locations in the DLL
- The device manager area calls (0x095E09, 0x095E49) are in `FUN_10095d50` — a deserializer
- The credential is likely read from `service_register_v1.sav` during initialization
- The 6-byte "gap" in each credential entry might be part of this third credential

**service_register_v1.sav credential entry layout (raw bytes):**
```
Entry 1 (HU):
  +0x00: 69C1448B 80E0C10C D1FD4A2F 23F921D6  (16B name hash)
  +0x10: E3B093D5 957A000B                      (6B gap + 2B code start)
  +0x18: F28569BA CB7C000E                      (code cont + 2B secret start)
  +0x1C: E87C16B1                               (secret cont)
  +0x20: E8120000 00012C00                      (secret end + flags)

Entry 2 (TB):
  +0x00: 69C142E8 80E0FB86 ACD6EBA8 F54A93C4  (16B name hash)
  +0x10: 286CE077 D06C000D                      (6B gap + 2B code start)
  +0x18: 4EA65D36 B98E000A                      (code cont + 2B secret start)
  +0x1C: CAB6C9FB                               (secret cont)
  +0x20: 66F80000 00012C00                      (secret end + flags)
```

**6-byte gap analysis:**
- Entry 1 gap: `E3 B0 93 D5 95 7A` — not HMAC-MD5 truncation of any known value
- Entry 2 gap: `28 6C E0 77 D0 6C` — not HMAC-MD5 truncation of any known value
- Not XOR of hash halves, not hash substrings
- These 6 bytes are UNKNOWN — possibly a truncated hash, timestamp, or derived key

**Tested and eliminated:**
- tb_code as Secret₃ → no match
- hu_code as Secret₃ → no match
- All byte-order variations (BE as LE, swapped) → no match
- All 8-byte windows in both credential entries → no match
- All 8-byte windows in reg.sav credential entries → no match
- Body at all offsets 16-39 with all 4 known keys → no match
- 6-byte gaps padded to 8 bytes → no match
- 6-byte gaps + adjacent bytes → no match

**Singleton initialization (FUN_10096700):**
- `DAT_1031445c` = device manager singleton, initialized lazily
- `FUN_10096700` is the constructor (thiscall) — needed stubbing in Unicorn
- The singleton is created on first access, not during DllMain
- It manages the "NAVIEXTRAS_UNIQUE_DEVICE__ID" credential store

**Next steps:**
1. The innermost credential is a THIRD credential distinct from TB and HU
2. It might be derived during the first registration (before delegation)
3. Or it might be read from a file we haven't examined (e.g., device.nng parsed differently)
4. The 6-byte gap in credential entries is suspicious — investigate if it encodes part of the third credential
5. Alternative: emulate `FUN_10096700` (singleton constructor) to see what credential it creates from device.nng or registration data

---

### 2026-04-18 07:50 — Exhaustive brute-force negative, tracing registration flow

**Brute-force results — ALL NEGATIVE:**
- Every 8-byte window in delegation response (175 bytes) → no match
- Every 8-byte window in raw delegation response (179 bytes) → no match
- Every 8-byte window in service_register_v1.sav (270 bytes) → no match
- Every 8-byte window in reg.sav → no match
- Every 8-byte window in device.nng (268 bytes) → no match
- **Secret₃ is NOT stored in any file on disk. It must be computed at runtime.**

**Delegation response structure (flow 736):**
```
Offset 0x00: 80 E0 C1 0C D1 FD 4A 2F 23 F9 21 D6  (12B: type + hash fragment)
Offset 0x0C: E3 B0 93 D5 95 7A                      (6B gap)
Offset 0x12: 00 0B F2 85 69 BA CB 7C                (8B hu_code BE)
Offset 0x1A: 00 0E E8 7C 16 B1 E8 12                (8B hu_secret BE)
Offset 0x22: 00 00 00 01 2C 00                       (flags + maxage)
Offset 0x28: 04                                       (license count)
Offset 0x29: [license SWIDs with activation codes]
```

**service_register_v1.sav vs delegation response:**
- sav entry starts with 4 extra bytes: `69 C1 44 8B` (not in response)
- sav[4:] ≈ response data (same credential block)
- The 4 extra bytes might be a file-format header or hash prefix

**Device object lifecycle:**
1. `FUN_10094510` creates device object with all fields = 0
2. `FUN_10011dd0` stores it in the credential store tree
3. Registration response handler populates Code, Secret, and inner pointer
4. The inner pointer at `[0xF]` (offset 0x3C) is set during registration
5. For the TB credential (first registered), `[0xF]` might initially be NULL
6. `FUN_101aa050` checks `if (iVar5 != 0)` before reading from the inner object

**Critical question: What sets device_obj[0xF] for the TB credential?**
- The copy constructor copies it from another object
- `FUN_10055c70` sets it from a parameter
- `FUN_10056830` copies it from global data at `uRam103147d4`
- The global at `0x103147D4` is set by the service manager initialization
- But we can't trace the exact value without running the DLL

**Next approach: Emulate the full registration flow in Unicorn**
- Load device.nng data
- Emulate the registration response parser
- Trace what value ends up at device_obj[0xF][7]+0x10

---

### 2026-04-18 08:10 — tb_code confirmed as pointer chain result, but doesn't decrypt 0x68 body

**CRITICAL: Unicorn emulation with real TB credential data confirms:**
- `FUN_101aa050` with TB device manager → `puVar9[9..10]` = tb_code (3745651132643726)
- The full pointer chain `*(*(*(device_obj + 0x3C) + 0x1C) + 0x10)` returns tb_code
- **But tb_code does NOT decrypt the 0x68 body at ANY offset (16-59)**

**This means one of:**
1. The 0x58-byte credential from `FUN_101aa050` is NOT what the protocol builder uses for 0x68 flows
2. The protocol builder uses a DIFFERENT credential for 0x68 flows than for 0x60 flows
3. The body offset calculation is wrong (but we tried all offsets 16-59)
4. The 0x68 flows use a credential that is NOT created by `FUN_101aa050`

**Header analysis for flow 737 (0x68 senddevicestatus):**
```
01 C2 C2 30 00 0D 4E A6 5D 36 B9 8E 19 00 00 67
│  │     │  └─────────────────────┘  │        │
│  │     │  tb_code (BE)             │        │
│  size  auth=DEVICE                 0x19     0x67
```
- Byte 12 = 0x19 (25) — might be query length or something else
- tb_code is in the header (bytes 4-11)

**Exhaustive brute-force summary:**
- All 8-byte windows in: delegation response, service_register_v1.sav, reg.sav, device.nng → NO MATCH
- All body offsets 16-59 with tb_code, tb_secret, hu_code, hu_secret → NO MATCH
- Secret₃ is computed at runtime and is NOT any known credential value or file content

**Possible next steps:**
1. Re-examine the protocol builder — maybe 0x68 flows use a different code path
2. Check if the 0x68 credential is created by a DIFFERENT function than `FUN_101aa050`
3. Look at the callback `(*param_2)(param_4, puVar3, 0x40, -1, credential)` — maybe it transforms the credential
4. Fresh mitmproxy capture to get the actual key from a live session

---

### 2026-04-18 08:30 — CRITICAL: Found SnakeOil key source in protocol builder, post-delegation key change confirmed

**SnakeOil key derivation in FUN_100b3a60 (protocol builder):**
```c
if (credential == NULL || mode == RANDOM) {
    // RANDOM mode (0x20): key = xorshift(time64())
    mode = 2;
    seed = __time64(NULL);
    key = xorshift(seed);  // << 21, ^ self, >> 3, ^ 0, << 4, ^ self
} else {
    // DEVICE mode (0x30): key = Secret from credential
    mode = 3;
    Code = *(credential + 0x10);     // stored in wire header
    key_lo = *(credential + 0x1C);   // Secret_lo → SnakeOil key
    key_hi = *(credential + 0x20);   // Secret_hi → SnakeOil key
}
```

**Counter at piVar8[0x39..0x3a] is NOT the SnakeOil key:**
- `DAT_10314a60` = request counter (starts at 0, increments per request)
- `DAT_10314a50` = timestamp from `FUN_101d2630()` (Unix seconds)
- These are stored in the protocol builder but used for request sequencing, NOT encryption

**Post-delegation key change CONFIRMED:**
- Flow 735 (0x60, pre-delegation): body decrypts with tb_secret ✓
- Flow 736 (delegator request): body decrypts with tb_secret ✓
- Flow 737+ (0x68, post-delegation): body does NOT decrypt with tb_secret or tb_code ✗
- ALL post-delegation flows (0x68, 0x20, 0x28) fail to decrypt with any known key
- **The delegation changes the encryption key for ALL subsequent requests**

**Credential flow:**
1. Delegation handler creates credential via `FUN_101aa050(hu_code, hu_secret)`
2. Credential stored into session via `vtable[0xD]` callback (thiscall, ECX = session + offset)
3. Protocol builder reads credential via `vtable[6]` on credential provider at `this + 0x1C`
4. SnakeOil key = Secret from credential at `cred + 0x1C/0x20`

**The remaining mystery:**
- The 0x58-byte credential has Secret at `puVar9[9..10]` = tb_code (from device manager)
- But tb_code doesn't decrypt post-delegation flows
- Either the offset mapping (puVar9[2] → provider) is wrong, or the device manager returns a different value in the real DLL
- The session's `vtable[0xD]` might transform the credential before storing it

**Debug log format (line 152354):**
```
"name: %s\ncode: %lld\nsecret: %lld"
```
- name from credential name string
- code from `cred + 0x10/0x14` (8 bytes)
- secret from `cred + 0x1C/0x20` (8 bytes)
- Then dumps decoded body and query using `piVar8[0x39..0x3a]` as key

---

### 2026-04-18 08:50 — param_2 (hu_secret) NOT stored in credential Secret field!

**CRITICAL FINDING: FUN_101aa050 does NOT store param_2 (hu_secret) in the credential's Secret field!**

The 0x58-byte credential object layout:
```
puVar9[6..7]  = *param_1 = hu_code (Code)
puVar9[9..10] = *(iVar5 + 0x10) = tb_code (from device manager chain)
puVar9[0xb]   = *(iVar5 + 0x18) = unknown 4-byte field from device manager
puVar9[0xc]   = timestamp from FUN_101d2630()
```

**param_2 (hu_secret) is used for credential NAME encoding, NOT for the Secret field:**
```c
local_24 = *param_2;        // hu_secret_lo
iVar5 = param_2[1];         // hu_secret_hi
// ... builds byte array from hu_secret ...
FUN_101aa3a0(local_1c, &local_30, 8, local_44, local_3c);  // encodes into credential name
```

**Wire traffic analysis confirms split keys:**
- Header Code: tb_code (bytes 4-11) — SAME for 0x60 and 0x68 flows
- Query key: tb_code — decrypts to 0x60/0x68 flags for both flow types
- Body key for 0x60: tb_secret ✓
- Body key for 0x68: UNKNOWN — not tb_secret, not tb_code, not hu_code, not hu_secret

**Protocol builder key derivation (FUN_100b3a60):**
```c
credential = vtable[6] on credential provider at this + 0x1c
if (credential == NULL || mode == RANDOM):
    key = xorshift(time64())
else:
    Code = *(credential + 0x10)     // → wire header
    Secret_lo = *(credential + 0x1C)  // → SnakeOil key lo
    Secret_hi = *(credential + 0x20)  // → SnakeOil key hi
```

Both query and body SnakeOil calls use the SAME key from `param_3[0x10]`.

**The remaining mystery: what is at credential + 0x1C for the delegated credential?**
- If provider = &puVar9[2]: cred + 0x1C = puVar9[9] = tb_code → doesn't work
- If provider = &puVar9[0]: cred + 0x1C = puVar9[7] = hu_code_hi → only 4 bytes
- The provider offset determines the key — need to verify the EXACT offset

**Next: Emulate the full protocol builder with the delegated credential to trace the exact key**

---

### 2026-04-18 09:00 — Session credential storage traced, key still unknown

**FUN_1001f950 — credential copy constructor:**
```c
param_1[4] = *(param_2 + 0x10);   // Code_lo
param_1[5] = *(param_2 + 0x14);   // Code_hi
param_1[6] = *(param_2 + 0x18);   // unknown
param_1[7] = *(param_2 + 0x1c);   // Secret_lo → stored at session[7]
param_1[8] = *(param_2 + 0x20);   // Secret_hi
param_1[9] = *(param_2 + 0x24);   // unknown
```
- `param_1[7]` (offset 0x1C) is what the protocol builder reads as the SnakeOil key
- The source `param_2` is the credential object returned by the provider

**Session object layout (FUN_10093010):**
- `param_1[0]` = `PTR_FUN_102b9598` (main vtable, only 3 entries)
- `param_1[7]` = credential provider pointer (offset 0x1C)
- `param_1[0x15]` = `PTR_FUN_102b9590` (sub-object 1, offset 0x54)
- `param_1[0x17]` = `PTR_FUN_102b9580` (sub-object 2, offset 0x5C)
- `param_1[0x23]` = `PTR_FUN_102b9588` (sub-object 3, offset 0x8C)

**Multiple inheritance confusion:**
- `PTR_FUN_102b9580[6]` = RVA 0x0940C0 = DESTRUCTOR (not a getter!)
- The session has multiple vtables due to C++ multiple inheritance
- The credential provider is a SEPARATE object stored at `session[7]`
- The protocol builder calls `vtable[6]` on the provider, NOT on the session sub-object

**Brute-force attempts (all negative):**
- tb_secret ± N for N in [-1000, 1000] → no match
- hu_code ± N for N in [-1000, 1000] → no match
- tb_secret XOR (modifier << 56) for modifier in [0, 255] → no match
- Credential name bytes as key → no match
- SWID values from delegation response → no match

**Summary of what we know:**
1. The SnakeOil key for 0x68 body = Secret from the delegated credential
2. The delegated credential is created by `FUN_101aa050(hu_code, hu_secret)`
3. The credential's Secret field comes from the device manager chain
4. The device manager chain returns tb_code (confirmed by Unicorn)
5. But tb_code does NOT decrypt the 0x68 body
6. The session stores the credential via a complex callback chain
7. The credential might be TRANSFORMED during storage

**Possible explanations:**
1. The Unicorn emulation of the device manager is wrong (fake objects don't match real DLL state)
2. The credential provider's vtable[6] returns a DIFFERENT object than what we think
3. The session's credential storage transforms the key
4. There's a THIRD credential we haven't found that's created during the registration flow
5. The body offset (18) might be wrong for 0x68 flows despite working for 0x60 flows

---

### 2026-04-18 09:15 — BREAKTHROUGH: Body offset is 35, key is ALWAYS tb_secret!

**THE KEY NEVER CHANGES. The body offset was wrong.**

**Correct packet format:**
```
Offset 0-15:  [16B header] — cleartext
Offset 16-17: [2B query]   — encrypted with tb_code (Code)
Offset 18-34: [17B extended query] — encrypted with tb_secret (Secret)
Offset 35+:   [body]       — encrypted with tb_secret (Secret)
```

**Verification:**
- `snakeoil(raw[35:], tb_secret)` matches the decoded file for ALL flows (0x60, 0x68, 0x20, 0x28)
- `snakeoil(raw[16:18], tb_code)` gives the 2-byte query (counter + flags) for ALL flows
- The "extended query" at offset 18-34 is 17 bytes, also encrypted with tb_secret
- **tb_secret is the body key for ALL flows, pre- and post-delegation**

**What we got wrong:**
- We assumed body started at offset 18 (after 2-byte query)
- Actually body starts at offset 35 (after 16B header + 2B query + 17B extended query)
- The "DaciaAutomotive" match at offset 18 was a FALSE POSITIVE — it was decrypting the extended query, not the body
- The extended query bytes 18-34 happen to decrypt to igo-binary data that contains "Dacia"

**The "Secret₃" mystery is SOLVED: there is no Secret₃. The key is always tb_secret.**

**Implications:**
- No need to reverse-engineer the credential delegation chain
- The delegation only changes the query FLAGS (0x60 → 0x68), not the encryption key
- All captured traffic can be decrypted with just tb_code (query) and tb_secret (body)
- The credential store, device manager, and vtable chains are irrelevant to decryption

---

### 2026-04-18 10:30 — CORRECTION: Body offset 35 was WRONG

**The "body at offset 35" finding was incorrect.** The decoded files (`*-decoded.bin`) were
created by a script that stripped 35 bytes and decrypted with tb_secret. This produces
garbage for 0x68 flows — the decoded files are NOT the real plaintext.

**Actual verified state:**
- 0x60 flows: body at offset 18, key = tb_secret → "DaciaAutomotive" ✓
- 0x68 flows: body at offset 18, key = UNKNOWN (not tb_secret, tb_code, hu_code, or hu_secret)
- 0x68 flows: body at offset 35, key = tb_secret → garbage (matches decoded files, but decoded files are wrong)

**The Secret₃ mystery remains unsolved.** The 0x68 body encryption key is still unknown.

**Current workaround:** The session.py replays captured binary files for senddevicestatus.
This works because:
1. Flow 735 (0x60): re-encrypted with current tb_secret at offset 18
2. Flow 737 (0x68): raw binary replay (includes old session data)

**Impact on task 4.3.1:** Cannot generate 0x68 bodies from scratch until Secret₃ is found.
However, the 0x60 body CAN be generated (tb_secret at offset 18). The 0x68 call may not
be strictly required — need to test if the server accepts just the 0x60 call.


---

### 2026-04-18 13:30 — Packet structure clarified, body key still unknown

**CONFIRMED packet structure for all flag types:**

| Flags | Offset 16-17 | Offset 18-34 | Offset 35+ |
|-------|-------------|-------------|-----------|
| 0x20 | 2B query (tb_code) | 17B cred block (tb_code) | body (tb_secret) |
| 0x60 | 2B query (tb_code) | — (no cred block) | body at offset 18 (tb_secret) |
| 0x68 | 2B query (tb_code) | 17B cred block (tb_code) | body (UNKNOWN key) |
| 0x28 | 2B query (tb_code) | 17B cred block (???) | body (UNKNOWN key) |

**Evidence:**
- 0x20 flow 053: cred block decrypts with tb_code → marker 0xD4 ✓, body@35 with tb_secret → "N/A" ✓
- 0x60 flow 735: no cred block, body@18 with tb_secret → "DaciaAutomotive" ✓
- 0x68 flow 737: cred block decrypts with tb_code → marker 0xD4 ✓, body@35 with tb_secret → garbage ✗
- ALL 0x68 flows (737, 742, 754, 792, 800) have IDENTICAL ciphertext at offset 18-34 (same cred block, same key)
- XOR of 0x68 senddevicestatus and sendfingerprint at offset 35: first 4 bytes = 00000000 (same body prefix, same key)

**Brute-force attempts (all negative):**
- All 4 known keys (tb_secret, tb_code, hu_code, hu_secret) as body key at offset 35
- All pairwise XOR, ADD, SUB, MUL of the 4 known 64-bit values
- All byte-swapped, half-swapped, bitwise-NOT variants
- Fix key_hi from known 32-bit halves, brute-force key_lo (2^32 each, 22 candidates)
- Fix key_lo from known 32-bit halves, brute-force key_hi (2^32 each, 22 candidates)
- Credential block bytes as key
- Credential name (XOR-decoded) bytes as key
- Total: ~44 × 2^32 = ~1.9 × 10^11 candidates checked

**The body key for 0x68 flows does NOT share any 32-bit half with any known credential value.**

**Next: Execute nngine.dll in Wine/QEMU Docker container with SnakeOil function hook to capture the actual key at runtime.**


---

### 2026-04-18 14:00 — Wine SnakeOil parameter order FIXED, full brute-force running

**DISCOVERY: SnakeOil parameter order is (src, len, dst, key_lo, key_hi) — NOT (dst, len, src, key_lo, key_hi)!**

The first and third parameters are SWAPPED compared to what Ghidra showed. Verified by:
1. Calling with known tb_secret key and zeros → got correct keystream `BC755FBC32341970`
2. The `sub [ebp+08], edi` instruction computes `src_adjusted = src - dst` for the XOR loop

**Packet structure confirmed (from ciphertext analysis):**
- 0x68 flows: cred block at 18-34 encrypted with tb_code (marker 0xD4 ✓)
- 0x68 flows: body at 35+ encrypted with UNKNOWN key
- ALL 0x68 flows have identical ct at 18-34 (same cred block)
- XOR of 0x68 senddevicestatus and sendfingerprint at offset 35: first 4 bytes = 00000000
  → same body prefix, same key, different body content

**Full brute-force running (PID 799226):**
- Two threads: one assuming pt starts with D8021F40, one assuming 00000000
- Searching all 2^64 keys (2^32 key_hi × 2^32 key_lo per thread)
- Rate: ~2^24 key_hi values per 5 minutes per thread
- ETA: ~21 hours per thread
- Result file: /tmp/crack_result.txt
- Progress: /tmp/crack_progress.txt

**Brute-force attempts so far (all negative):**
- All 8-byte windows from sav, reg.sav, device.nng files (via Wine DLL)
- All pairwise XOR/ADD/SUB/MUL/mix of 4 known credential values
- Fix key_hi or key_lo from known 32-bit halves, brute-force other half (22 × 2^32)

---

### 2026-04-18 15:30 — SECRET₃ SOLVED: tb_secret, split encryption confirmed

**BREAKTHROUGH:** Secret₃ = tb_secret (`3037636188661496` / `0x000ACAB6C9FB66F8`).

**How it was found:**

1. Annotated `nngine_decompiled.c.backup` with 12,476 function headers, inline comments, cross-references, and Secret₃ path tags
2. While adding annotations, traced the credential chain through `FUN_10094390` → `FUN_100a4be0` → `FUN_100a4bb0` (the inner credential setter/getter)
3. Found `FUN_10094390` deserializes the registration response and stores Code+Secret in the inner object
4. Realized the `RegisterDeviceRet` response contains Code=tb_code, Secret=tb_secret
5. Re-examined the wire protocol header: byte 12 = 0x19 = 25 = **query length** for 0x68 flows
6. Corrected body offset: 16 (header) + 25 (query) = **41**, not 35
7. XOR analysis of flows 737 vs 754 vs 792 showed 171 consecutive zero bytes starting at body offset 17 → identical plaintext from that point
8. Extracted keystream from known plaintext alignment: `extracted[17+j]` matched `tb_secret_ks[j]` for 98/100 bytes
9. Decrypted `body[17:]` with fresh tb_secret PRNG → `D8 03 1E 40 0F DaciaAutomotive...` ✓

**Root cause of the 24h investigation:**

Two compounding errors:
1. **Wrong body offset (35 vs 41):** The query for 0x68 flows is 25 bytes (counter + flags + D8 type + 16B Name₃ + 6B extra), not 19. Body starts at 16+25=41.
2. **Split encryption:** The DLL calls SnakeOil twice on the body — once for the 17-byte delegation prefix, once for the standard content. Each call starts with a fresh PRNG. Decrypting the entire body as one stream gives correct bytes 0-16 but garbage from byte 17 onwards.

**Verification across all 0x68 flows:**

| Flow | `snakeoil(body[17:], tb_secret)` | Result |
|------|----------------------------------|--------|
| 737 | `D8 03 1E 40 0F DaciaAutomotive...` | ✓ |
| 754 | `D8 03 1E 40 0F DaciaAutomotive...` | ✓ |
| 792 | `D0 05 1E 40 0F DaciaAutomotive...` | ✓ (different presence bits) |

**Delegation prefix (body[0:17]) also decrypts with fresh tb_secret:**

| Flow | Prefix (hex) |
|------|-------------|
| 737 | `86a2188db854428f9c52c5192d1644f00b` |
| 754 | `86a2ce2009472bef8b9c5fa98b5ae9e00e` |
| 792 | `867acf51fb919cbb4c963a74decacc3965` |

All start with `0x86` — likely a delegation-specific presence bitmask.

**Flow 741 (0x28 flags):** Uses a different credential name (`92b31be5...` vs `ad35bcc1...`). This is a separate session — not part of the main delegation flow. Its body structure may differ.

**Impact:** The sync command can now generate fresh 0x68 bodies from scratch. No more replay workaround needed.

---

### 2026-04-18 16:00 — End-to-end encryption test PASSED

**Test results:**

| Test | Result | Details |
|------|--------|---------|
| Decrypt captured 0x68 traffic | ✅ PASS | `snakeoil(body[17:], tb_secret)` → "DaciaAutomotive" |
| Roundtrip encrypt/decrypt | ✅ PASS | Encrypt then decrypt produces identical output |
| Full session flow (run_session) | ✅ PASS | boot→register→login→delegator→senddevicestatus→web_login |
| Re-encrypted 0x60 to live API | ✅ **200** | Freshly encrypted captured body accepted by server |
| Raw replay 0x68 to live API | ❌ 409 | Stale captured data rejected (expected) |
| Re-encrypted 0x68 to live API | ❌ 409 | Stale captured body data, not encryption issue |

**Key finding:** The re-encrypted 0x60 call returns **HTTP 200**, proving:
1. SnakeOil encryption with tb_secret produces valid wire format
2. `build_request()` correctly constructs the wire protocol envelope
3. The server accepts freshly encrypted requests from our code

**The 0x68 409 is a body content issue, not encryption:**
- The raw replay of the captured 0x68 ALSO gets 409 (same stale data)
- The captured body is from weeks ago and contains expired session data
- The delegation prefix contains session-specific data that must be fresh

**Remaining work for fresh 0x68 bodies (wire_codec, not crypto):**
1. Build delegation prefix from current delegator response (17 bytes: `[0x86][16B session data]`)
2. Compute correct SWID (current `compute_swid()` produces different value than captured traffic)
3. Build body with correct file list from current USB drive state
4. Adjust presence bits: `byte[1] |= 0x01` (delegation), `byte[2] &= ~0x01` (no UniqId)
5. Remove UniqId field (33 bytes: space + 32-char hex string after VIN)

**The encryption layer is COMPLETE. Secret₃ = tb_secret is confirmed working end-to-end.**

---

### 2026-04-18 16:45 — getprocess task format decoded, blocker is stale USB data

**getprocess response format** (from captured login response, flow 048):

```
[process_id: 0x24 + 36-byte UUID]
[task_count: varint]
[tasks...]

Each task:
  [type_flag: 1B]  (0x88=SSE, 0x84=BROWSER, 0x80=FINGERPRINT)
  [00 00]
  [task_id: 0x24 + 36-byte UUID]
  [device_context_id: 4B BE]
  [type_code: 1B]  (0x03=SSE, 0x04=BROWSER, 0x02=FINGERPRINT)
  [url_string: length-prefixed]  (for SSE and BROWSER tasks)
```

After content confirmation, DOWNLOAD tasks should appear with CDN URLs.

**Actual blocker**: The content tree returns 0 items because the USB drive data is stale (last synced from car on March 23). The server compares the senddevicestatus file list against known device state. When they don't match, no content is offered.

**Resolution**: Sync the USB drive from the car head unit, then re-run the tool. The full pipeline (select → confirm → getprocess → download → install) should work once the server recognizes the device state.

**No mitmproxy needed**: We can call getprocess directly via the wire protocol (encryption solved). No certificate pinning issue since we're making the calls ourselves, not proxying the native engine.


---

### 2026-04-18 18:30 — Delegation prefix is the remaining blocker (not encryption, not USB sync)

**Status:** Encryption fully solved. Body format fully solved. The blocker is a 17-byte **delegation prefix** in 0x68 requests that we cannot yet generate.

**The 0x68 wire layout (confirmed):**
```
[16B header] [25B query, SnakeOil(tb_code)] [17B prefix, SnakeOil(tb_secret)] [body, SnakeOil(tb_secret)]
```

**What the delegation prefix looks like (decrypted):**
| Flow | Prefix (hex) |
|------|-------------|
| 737 | `86 a2 18 8d b8 54 42 8f 9c 52 c5 19 2d 16 44 f0 0b` |
| 742 | `86 a5 55 09 d9 17 6e d0 dc 8b a0 f3 60 ba 6a b3 16` |
| 754 | `86 a2 ce 20 09 47 2b ef 8b 9c 5f a9 8b 5a e9 e0 0e` |
| 792 | `86 7a cf 51 fb 91 9c bb 4c 96 3a 74 de ca cc 39 65` |
| 800 | `86 7a cf 51 fb 91 9c bb 4c 96 3a 74 de ca cc 39 65` |

**Observations:**
- Byte 0 is always `0x86` (presence bitmask)
- Bytes 1-16 change per request, but flows sent at the same time share the same prefix (792 = 800)
- This suggests a timestamp or counter component
- The prefix is NOT the delegator Name₂, Code₂, or Secret₂ (no match)
- XOR with Name₂ shows no constant pattern

**What we proved:**
- Re-encrypting the captured 0x60 body → HTTP 200 (encryption correct, body content accepted)
- Re-encrypting the captured 0x68 body → HTTP 409 (encryption correct, but prefix is stale)
- The 409 is caused by the prefix, not the body content (the body is identical format to 0x60)

**What we need to reverse-engineer:**
- How `FUN_101aa050` builds the 17-byte prefix from the delegator response + session state
- The prefix is likely: `[0x86] [timestamp/counter] [hash or token derived from delegation credentials]`
- The DLL creates this when processing the delegator response, before any senddevicestatus call

**Next step:** Trace `FUN_101aa050` in Ghidra/Unicorn to find the exact prefix construction logic. Focus on what happens to the delegator response (Name₂, Code₂, Secret₂) between the delegation call and the first 0x68 request.


---

### 2026-04-18 19:15 — Delegation prefix analysis from annotated Ghidra code

**Key findings from `nngine_decompiled.c.backup`:**

1. **Protocol builder (`FUN_100b3a60`) makes exactly 2 SnakeOil calls** — one for query, one for body. Both use the SAME key from `piVar11[0x10]`. Yet wire traffic shows query uses tb_code and body uses tb_secret. This contradiction is unresolved — the credential provider may return different objects for different call contexts.

2. **The body IS split-encrypted** (verified empirically):
   - `snakeoil(body[0:17], tb_secret)` → `86 a2 18 8d...` (valid prefix)
   - `snakeoil(body[17:], tb_secret)` → `D8 03 1E 40 0F DaciaAutomotive...` (valid body)
   - `snakeoil(body[0:], tb_secret)` as single stream → prefix OK but body[17:] is garbage
   - The PRNG resets at byte 17, meaning two separate SnakeOil calls

3. **The 17-byte prefix structure:**
   - Byte 0: always `0x86` (presence bitmask)
   - Bytes 1-16: 16 bytes of per-request data
   - Changes between requests (737≠754≠792), but identical for simultaneous requests (792=800)
   - NOT the HMAC-MD5 credential name (that's in the query)
   - NOT a direct copy of any known credential field (tb_code, tb_secret, hu_code, hu_secret)
   - Likely computed from session state + timestamp

4. **Credential object layout (`FUN_101aa050`):**
   ```
   puVar9[0]  = vtable1 (PTR_FUN_102b9590)
   puVar9[2]  = vtable2 (PTR_FUN_102b9580)
   puVar9[4]  = 1 (flag)
   puVar9[5]  = 1 (flag)
   puVar9[6]  = hu_code_lo
   puVar9[7]  = hu_code_hi
   puVar9[8]  = 1 (flag)
   puVar9[9..10] = *(iVar5 + 0x10) — from device manager chain (8B)
   puVar9[0xb] = *(iVar5 + 0x18) — from device manager chain (4B)
   puVar9[0xc] = timestamp from FUN_101d2630()
   puVar9[0xd] = CONCAT31(local_48._1_3_, 1)
   puVar9[0xe] = vtable3 (PTR_FUN_102b9588)
   puVar9[0x10] = 3 (mode = DEVICE)
   puVar9[0x12..0x14] = HMAC-MD5 name (16B, stored via loop from FUN_10156c60)
   ```

5. **The credential sub-object is copied into the request via `FUN_100a73d0`** when bit 6 of flags is set (0x40 bit, present in 0x60 and 0x68). The body serializer then includes it.

**Next step:** Trace the body serializer (`FUN_10091bf0` → `FUN_101b2c30`) to find exactly how the credential sub-object is serialized into the 17-byte prefix. The serializer likely writes `[0x86 presence bitmask] [serialized fields from credential]`. The 16 data bytes are probably: `[8B from puVar9[9..10]] [4B from puVar9[0xb]] [4B from puVar9[0xc]]` = device_manager_value + unknown_field + timestamp.


---

### 2026-04-18 19:45 — Serializer traced, prefix is per-request credential serialization

**Key discovery: `FUN_101aa050` is called PER REQUEST, not once per session.**

Each call creates a fresh 0x58-byte credential with a fresh timestamp from `FUN_101d2630()`. This explains why the prefix changes per request but is identical for simultaneous requests (792=800).

**Credential sub-object descriptor (8 fields):**
| Index | Name | Present in 0x86? |
|-------|------|-----------------|
| 0 | Type0 | No (bit 0 = 0) |
| 1 | Type1 | Yes (bit 1 = 1) |
| 2 | Delegation | Yes (bit 2 = 1) |
| 3 | Credentials | No (bit 3 = 0) |
| 4 | Version | No (bit 4 = 0) |
| 5 | Fault | No (bit 5 = 0) |
| 6 | Cellid | No (bit 6 = 0) |
| 7 | Elevation | Yes (bit 7 = 1) |

**Byte-by-byte analysis across flows:**
- Byte 0: always `0x86` (presence bitmask)
- Byte 1: constant within time window, changes between windows (session-level value?)
- Bytes 2-16: completely different between time windows, identical for simultaneous requests

**HMAC-MD5 computation in FUN_101aa050:**
- Key: hu_secret (8 bytes, big-endian)
- Data: igo-binary serialized credential via `FUN_101a9930`
- Result: 16-byte name stored in credential object
- The HMAC name goes into the QUERY (Name₃), NOT the prefix

**The prefix data (16 bytes after 0x86) is the igo-binary serialized form of the credential's Type1, Delegation, and Elevation fields.** The serialization uses a bitstream format with variable-width fields. The exact encoding depends on the igo-binary serializer internals.

**Annotated in nngine_decompiled.c.backup:**
- FUN_101aa050: full credential object layout, HMAC computation, per-request behavior
- SnakeOil section: corrected Secret3 = tb_secret, wire format for 0x68
- Binary serializer vtable: all 18 entries documented
- Credential descriptor: 8 fields with names

**Next: Execute FUN_101a9930 (igo-binary serializer) via Unicorn Engine to capture the exact serialized bytes for the credential sub-object. This will reveal the prefix format.**


---

### 2026-04-18 20:15 — Field structure decoded via Wine vtable traversal

**Credential sub-object field structure (from Wine DLL vtable traversal):**

| Field | Name | Sub-fields | Present in 0x86? |
|-------|------|-----------|-----------------|
| 0 | Type0 | Type, Delegator | No |
| 1 | Type1 | Type, **Digest** | **Yes** (bit 1) |
| 2 | Delegation | Delegation, **Mac** | **Yes** (bit 2) |
| 3 | Credentials | Credentials, Device | No |
| 4 | Version | Version, Value | No |
| 5 | Fault | Fault, ServiceLevel | No |
| 6 | Cellid | Cellid, Horizontal | No |
| 7 | Elevation | Elevation | **Yes** (bit 7) |

**The 17-byte prefix contains:**
1. `0x86` — presence bitmask (fields 1, 2, 7)
2. **Type1** value — contains a "Digest" (likely the HMAC-MD5 of the credential, 16 bytes)
3. **Delegation** value — contains a "Mac" (authentication code)
4. **Elevation** value — a simple value (timestamp?)

**Key insight:** The "Digest" sub-field of Type1 is likely the per-request HMAC-MD5 name computed in `FUN_101aa050`. The "Mac" sub-field of Delegation is likely derived from the delegator response. These are cryptographic values that change per request.

**The 16 data bytes are the igo-binary serialized form of these three fields.** The exact bit-level encoding depends on the serializer internals (variable-width fields in a bitstream). Need to either:
1. Execute the serializer in Wine/Unicorn to capture exact output
2. Reverse-engineer the bit-level encoding from the known field values

**Next step:** Set up the global serializer registry in Wine and call `FUN_101a9930` on the credential object to capture the serialized output.


---

### 2026-04-18 20:45 — Assembly decoded: serializer call and HMAC arguments confirmed

**Disassembly of FUN_101aa050 around the serializer + HMAC calls:**

```asm
; Set up serializer output buffer at [ebp-0x40]
lea  eax, [ebp-0x40]       ; output buffer address
lea  ecx, [ebx+8]          ; ECX = credential + 8 = vtable2 (thiscall)
push eax                    ; push output buffer
mov  [ebp-0x40], 0          ; data_ptr = 0
mov  [ebp-0x3C], 0          ; ??? = 0
mov  [ebp-0x38], 0          ; data_len = 0
mov  [ebp-0x34], 0          ; ??? = 0
mov  word [ebp-0x30], 0x101 ; version = 0x101
mov  byte [ebp-0x2E], 0     ; ??? = 0
call FUN_101a9930            ; serialize credential via vtable2

; Build HMAC key (hu_secret in big-endian, 8 bytes at [ebp-0x2C])
mov  edx, [ebp-0x20]        ; hu_secret_lo
mov  eax, esi               ; hu_secret_hi
; ... byte-by-byte reordering into [ebp-0x2C]..[ebp-0x25] ...

; Call HMAC-MD5
push [ebp-0x38]              ; data_len (serializer output length)
push [ebp-0x40]              ; data_ptr (serializer output pointer)
push 8                       ; key_len
push &[ebp-0x2C]             ; key_ptr (hu_secret BE)
push &[ebp-0x18]             ; output_ptr (16-byte HMAC result)
call FUN_101aa3a0             ; HMAC-MD5(output, key, key_len, data, data_len)
```

**Key finding:** The serializer is called as `thiscall` with `ECX = credential + 8` (vtable2 interface). The output buffer at `[ebp-0x40]` receives a pointer to dynamically allocated serialized data, and `[ebp-0x38]` receives the length.

**The HMAC input is the igo-binary serialized credential via vtable2.** To reproduce the prefix, we need to:
1. Serialize the credential object using the igo-binary format
2. Compute HMAC-MD5(key=hu_secret_BE, data=serialized_credential)
3. The result is the 16-byte credential name

**The 17-byte prefix is: `[0x86 presence] [16B HMAC-MD5 name]`**

Wait — that can't be right. The HMAC name goes into the QUERY (Name₃), not the prefix. And the query Name₃ is constant (`ad35bcc1...`) while the prefix changes per request.

**CORRECTION:** `FUN_101aa050` is called PER REQUEST. Each call creates a NEW credential with a fresh timestamp. The HMAC name changes because the timestamp changes. The QUERY uses the SESSION-level credential name (from the delegator response), while the PREFIX contains the PER-REQUEST credential name.

**So the 17-byte prefix IS: `[0x86] [16B per-request HMAC-MD5 name]`**

To reproduce it, we need to:
1. Build a credential object with current timestamp
2. Serialize it via igo-binary (vtable2)
3. HMAC-MD5(key=hu_secret_BE, data=serialized)
4. Prefix = `0x86` + HMAC result

**Next step:** Emulate the serializer via Unicorn to capture the exact serialized bytes for a credential with known field values. Then we can reproduce the serialization in Python.


---

### 2026-04-18 21:30 — HMAC oracle approach exhausted, need full serializer emulation

**Confirmed:** The DLL's HMAC-MD5 function (FUN_101aa3a0) works correctly in Wine. Verified: `HMAC-MD5(key=000EE87C16B1E812, data="hello") = 0344F48CAB00AE473B4992DF82F1BC1D` matches Python.

**Exhaustive HMAC oracle tests (all negative):**
- 4B timestamp (LE/BE) across ±28 hours
- 8B hu_code + 4B timestamp (LE)
- 8B tb_code + 4B timestamp (LE)
- 8B tb_secret + 4B timestamp (LE)
- 4B timestamp + 8B hu_code (LE)
- 8B hu_code + 8B tb_code + 4B timestamp (LE)
- Various presence byte + field value combinations

**Conclusion:** The serialized data uses the igo-binary **bitstream** format, NOT byte-aligned fields. The bitstream packs presence bits and field values at the bit level with variable-width encoding. Simple concatenation of field values does not produce the correct HMAC input.

**Wine serializer crashes** because `FUN_101b2910` (serializer init) needs thread-local storage and global state that isn't initialized without DllMain.

**Remaining approaches:**
1. **Full Unicorn emulation** — emulate the entire serializer chain with proper memory layout and hooks for all dependent functions
2. **Trace the bitstream writer** — follow `FUN_101a9e80` (write_1bit_lsb) and the value writers to understand the exact bit packing
3. **Patch DllMain** — modify the DLL to skip problematic init code and run with full DllMain in Wine
4. **mitmproxy capture** — run the Windows Toolbox and capture a fresh 0x68 request, then replay within the 300-second MaxAge window

Option 4 is the fastest path to a working end-to-end test. Options 1-3 are needed for the permanent solution.
