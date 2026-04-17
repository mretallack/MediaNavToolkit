# Reverse Engineering the NNGE Algorithm — Finding Secret₃

> Parent: [toolbox.md](toolbox.md) | Design: [design.md](design.md) | Functions: [functions.md](functions.md)

## Goal

Find the 8-byte SnakeOil key (**Secret₃**) used to encrypt the body of `0x08`-flag wire protocol requests. This key is derived at runtime from `device.nng` (268 bytes on the USB drive) through the NNGE algorithm in `nngine.dll`.

## Status

**BLOCKED** — We've fully reverse-engineered the .lyc license file decryption (RSA + XOR-CBC) but Secret₃ comes from a different code path: the device.nng reader. The next task is to trace the `FUN_10044c60` → `vtable[27]` call chain that processes device.nng and derives the device credential.

## Known Values

| Name | Value | Source |
|------|-------|--------|
| tb_code | `3745651132643726` (0x000D4EA65D36B98E) | Toolbox registration |
| tb_secret | `3037636188661496` (0x000ACAB6C9FB66F8) | Toolbox registration |
| hu_code | `3362879562238844` (0x000BF28569BACB7C) | Delegator response |
| hu_secret | `4196269328295954` (0x000EE87C16B1E812) | Delegator response |
| Name₃ | `C4000BF28569BACB7C000D4EA65D36B9` | Derived: `0xC4 \|\| hu_code(8B BE) \|\| tb_code(7B BE)` |
| Secret₃ | **UNKNOWN** | Derived from device.nng via NNGE algorithm |
| NNGE key | `m0$7j0n4(0n73n71I)` (19 bytes) | DLL RVA 0x2C11E4 |
| Blowfish key | `b0caba3df8a23194f2a22f59cd0b39ab` | DLL RVA 0x2AF9E8 |
| APPCID | `0x42000B53` (1107299155) | device.nng offset 0x5C |
| RSA public key | n=6B2317...0B676F (2048-bit), e=65537 | DLL RVA 0x30B588 |
| Brand MD5 | `3deaefba446c34753f036d584c053c6c` | device.nng[0x40:0x50] XOR-decoded |

## What We Know About Secret₃

1. It's a uint64 stored as two uint32s at `cred+0x1C` (lo) and `cred+0x20` (hi)
2. Used as SnakeOil seed for 0x08-flag request bodies
3. All 0x08 bodies share the same first 4 encrypted bytes → same key for all endpoints
4. NOT any known credential, NOT in .lyc files, NOT in device.nng raw data
5. NOT derived from simple MD5/SnakeOil of device.nng sections
6. Derived at runtime through the device.nng reader code path (`FUN_10044c60`)

## Tasks

- [x] **T1.** Map the full call chain from SnakeOil → credential object → device descriptor
- [x] **T2.** Reverse engineer .lyc file decryption (RSA + XOR-CBC)
- [x] **T3.** Dump RSA public key from DLL and decrypt all .lyc files
- [x] **T4.** Confirm Secret₃ is NOT in .lyc files (they contain map license data)
- [x] **T5.** Exhaustive search of device.nng raw/decoded values as SnakeOil keys
- [ ] **T6.** Trace `FUN_10044c60` → `vtable[27]` device.nng processing chain ← **NEXT**
- [ ] **T7.** Try Blowfish key (`b0caba3df8a23194f2a22f59cd0b39ab`) on device.nng sections
- [ ] **T8.** Find the file system manager vtable and its `+0x6c` method
- [ ] **T9.** Extract the derivation algorithm as standalone C and test it

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
│ PATH B: device.nng (DEVICE CREDENTIAL) — UNSOLVED       │
│                                                         │
│ device.nng → FUN_10044c60 (device.nng reader)           │
│           → vtable[27] on file system manager            │
│           → ??? (unknown derivation)                     │
│           → Secret₃ (uint64 SnakeOil key)               │
│           → Used for: 0x08-flag wire protocol            │
└─────────────────────────────────────────────────────────┘
```

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
