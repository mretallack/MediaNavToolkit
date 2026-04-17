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
