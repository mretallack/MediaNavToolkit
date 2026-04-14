# Credential Block Encoding — Analysis Notes

## Location in Code

The credential block (D8...D9) is generated in the igo-binary serializer chain:

```
FUN_100b3a60 (ProtocolEnvelopeRO builder, line 152038)
  ├── FUN_100935c0(param_3 + 1)     — copies envelope data to output buffer
  ├── FUN_101a9930(param_3 + 6)     — serializes envelope header (igo-binary)
  ├── FUN_10091bf0(piVar1, local_16c, piVar8, 0)  — serializes QUERY (credentials)
  │     ├── FUN_101b30f0(param_2, 0, 0)  — XML text serializer (for http_dump log)
  │     └── FUN_101b2c30(param_2, 0, 0)  — BINARY serializer ← THIS PRODUCES D8...D9
  │           ├── FUN_101b2a60()          — writes field open tag
  │           ├── vtable[0x38]()          — writes field value (dispatches to type-specific writer)
  │           └── FUN_101b2af0()          — writes field close tag
  ├── FUN_10091bf0(piVar1, &local_f8, piVar8, 0)  — serializes BODY (request args)
  ├── FUN_101b3e10(query, len, query, key_lo, key_hi)  — SnakeOil encrypt query
  └── FUN_101b3e10(body, len, body, key_lo, key_hi)    — SnakeOil encrypt body
```

## Stack Object Tree

The credential data flows through a tree of stack objects with vtable pointers:

```
local_16c  → query object (RequestEnvelopeRO)
  local_f8  = &PTR_FUN_102bb1bc  → body serializer vtable
  local_f0  = &PTR_FUN_102bb194  → ?
  local_c0  = &PTR_FUN_102b02d4  → ?
  local_94  = &PTR_FUN_102bb1a4  → ?
  local_7c  = &PTR_FUN_102b9590  → Device/Name field serializer
  local_74  = &PTR_FUN_102b9580  → ?
  local_44  = &PTR_FUN_102b9588  → ?
```

## Credential Data Source

```c
// iVar3 = credentials object (from vtable call at param_1 + 0x1c)
// Credential struct layout:
//   +0x08: Name string (via FUN_101bd970)
//   +0x0c: Name flag/type
//   +0x10: Code low 32 bits (LE)
//   +0x14: Code high 32 bits (LE)
//   +0x18: ? (copied to local_12c)
//   +0x1c: Secret low 32 bits (LE)
//   +0x20: Secret high 32 bits (LE)

// Name is copied to stack object:
if (((char)piVar8[0x12] != '\0') && (local_b8 != (undefined1 *)(iVar3 + 8))) {
    FUN_101b81b0((undefined1 *)(iVar3 + 8));  // copy Name string to local_b8
    local_b4 = *(undefined1 *)(iVar3 + 0xc);  // copy Name flag
}
```

## Binary Serializer Vtable

The binary serializer uses vtable `PTR_FUN_102d8d68`:

```
[0x00] FUN_101b2570  — destructor?
[0x04] FUN_10092e20  — timestamp writer (divides by 1000, formats .%04d)
[0x08] FUN_101b3d70  — ?
[0x0c] FUN_10092f60  — int writer (sprintf "%d")
[0x10] FUN_10092fd0  — bool writer ("true"/"false")
[0x14] FUN_10092ee0  — uint64 pair writer ("%I64u" × 2)
[0x18] FUN_10092f40  — int writer (format from DAT_102b90b0)
[0x1c] FUN_10092f20  — int writer (format from DAT_102b9118)
[0x20] FUN_10092fb0  — uint64 writer ("%I64u")
[0x24] FUN_10092f90  — int64 writer ("%I64d")
[0x28] FUN_10092d60  — string writer
[0x2c] FUN_101b3b50  — ?
[0x30] FUN_101b2d00  — ?
[0x34] FUN_101b3af0  — ?
[0x38] FUN_101b3cb0  — value writer (dispatches to type)
[0x3c] FUN_101b3bc0  — ?
[0x40] FUN_101b3d20  — ?
[0x44] FUN_101b3c70  — ?
```

**NOTE**: This vtable appears to be the XML TEXT serializer, not the binary one.
The actual binary serializer vtable may be set dynamically or may be a different
object entirely. The `FUN_101b2910` function sets `*param_1 = &PTR_FUN_102d8d68`
but this might be overwritten later.

## What We Know About the Encoding

- Input: 16-byte Name (e.g., FB86ACD6EBA8F54A93C4286CE077D06C)
- Output: 17 bytes (D8 + 15 inner bytes + D9)
- D8/D9 are paired open/close markers
- The 15 inner bytes are a position-dependent transform of the Name
- Same Name always produces the same output (deterministic)
- NOT: XOR, SnakeOil, Blowfish, MD5, base encoding, or any standard algorithm

## Next Steps

1. **Trace FUN_101b3cb0** (vtable[0x38]) — this is the value writer that dispatches
   to type-specific serializers. The credential Name goes through this path.

2. **Find the ACTUAL binary serializer** — the vtable at PTR_FUN_102d8d68 appears
   to be the XML text serializer. The binary serializer may use a different vtable
   that's set up in a different code path.

3. **Run nngine.dll in a harness** — call the serializer directly with a known Name
   and capture the output. This would bypass the need to understand the vtable chain.
