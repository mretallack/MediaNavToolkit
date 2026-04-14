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

## Binary Serializer Architecture (KEY DISCOVERY)

The igo-binary format is a **bitstream**, not a byte stream!

### Bit Writer: FUN_101a9e80 (line 371900)
Writes individual bits to the output buffer. Tracks bit position within each byte.
Bits are packed LSB-first within each byte (shifted left by bit position).

### Bitmap Writer: FUN_101a9a80 (line 371633)
Writes a bitmap MSB-first (from highest bit index down to 0).
Each bit is extracted from a uint32 array and written via FUN_101a9e80.
```c
// Iterates from param_1[3]-1 down to 0
// Extracts bit from: *(uint*)(*param_1 + (uVar1 >> 5) * 4) & (1 << (uVar1 & 0x1f))
// Writes each bit via FUN_101a9e80
```

### Bit Reader: FUN_101a9ae0 (line 371660)
Reads bits from the input stream (deserializer counterpart).

### Implications
- 17 bytes = 136 bits = 128 bits (Name) + 8 bits (type tags/field markers)
- The D8/D9 bytes are NOT simple byte-level markers — they're the first/last bytes
  of the bitstream that contains type tags + Name data + end markers
- The encoding includes field IDs, type tags, and possibly variable-length prefixes
  mixed into the bitstream alongside the Name data
- Simple bit-shifting of the Name does NOT produce the credential block
- The serializer uses descriptor chains (linked lists of field descriptors)
  that determine the encoding for each field type

## Serializer Type System

From the descriptor chain, the igo-binary serializer has these type handlers:

| Vtable | Function | Type | Bit width |
|--------|----------|------|-----------|
| 0x102d21cc | FUN_101a8e80 | Compound/nested object | recursive |
| 0x102d1e8c | FUN_101a5730 | Integer | N bits (from type_data[4]) |
| 0x102ce850 | FUN_101a1f80 | String/bytes | 4 bits per element |
| 0x102d23ac | FUN_101a6b90 | Unknown | ? |

### String Serializer (FUN_101a1f80)
- Calls `FUN_101a8310(value, 4)` — writes 4 bits per call
- The `4` comes from `(char)param_1[1]` where `param_1[1] = 0x0104`
- The value converter `vtable[8]` = `FUN_101a2030` (identity function)
- Called once per field, NOT per character — iteration happens at compound level

### Integer Serializer (FUN_101a5730)
- Uses `*(byte*)(param_1 + 4)` as bit width (e.g., 8 bits)
- Writes the value in the specified number of bits

### Compound Serializer (FUN_101a8e80)
- Iterates over field descriptors via linked list (FUN_101a9da0)
- For each field: calls getter to get value, then calls type-specific serializer
- Ghidra removed most code as "unreachable blocks" (optimized switch statement)

## RequestEnvelopeRO Descriptor Chain

```
Descriptor 0x1030de5c (RequestEnvelopeRO):
  sub0 (0x102cfeb8): compound, 3 fields
    [0] offset +0x08: compound (recursive)
    [1] offset +0x38: compound (recursive)  
    [2] offset +0x60: integer, 8 bits
  sub1 (0x102cfecc): compound, 2 fields  ← Device object
    [0] offset +0x08: STRING, 4 bits/elem ← Name field!
    [1] offset +0x10: unknown type
  sub2 (0x102cfee0): compound, 3 fields
    [0] offset +0x08: compound (recursive)
    [1] offset +0x38: integer, 8 bits
    [2] offset +0x3c: compound (recursive)
  sub3 (0x102cfef4): exists but not analyzed
```

## Key Insight: Bitstream Format

The igo-binary format is a **bitstream** with:
- Type tags and field IDs interleaved with data
- Variable bit widths per field type (4 bits for string elements, 8 bits for integers)
- Nested compound objects with recursive serialization
- MSB-first bitmap writing (FUN_101a9a80) for individual values
- LSB-first byte packing (FUN_101a9e80) for the output buffer

The 17-byte credential block (136 bits) contains:
- Structural overhead (type tags, field IDs, nesting markers) = 8 bits
- Name data = 128 bits (16 bytes × 8 bits, or 32 hex chars × 4 bits)

The exact bit layout requires tracing the compound serializer's iteration
over the descriptor chain, which Ghidra couldn't fully decompile due to
the optimized switch statement in FUN_101a8e80.
