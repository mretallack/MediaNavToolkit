# igo-binary Serializer

> How `nngine.dll` serializes request data into the igo-binary wire format.
> This is the deep technical reference for the DLL's serialization internals.

## Current Understanding

The serializer has two distinct roles:

1. **Query serialization** — Produces the 41B/58B query (credential + HMAC). We construct this directly in Python without the serializer.
2. **Body serialization** — For senddevicestatus, the body passes through as standard wire_codec format (NOT bitstream-encoded). The serializer is NOT needed for the body.

**However**, other request types (licenses, content operations) may use the bitstream serializer for their bodies. This reference documents the serializer internals for future use.

**Implementation:** `build_dynamic_request()` in `protocol.py` handles senddevicestatus.
Python model: `medianav_toolbox/igo_serializer_model.py`.

## Architecture

The serializer is data-driven. Each request type has a static descriptor chain defining its fields. The serializer walks the descriptor, checks field presence, and writes values to a bitstream buffer.

```
FUN_100b3a60 (envelope builder)
  ├── FUN_101a9930(credential_obj)     → serialize credential (21B)
  ├── FUN_101a9930(query_envelope_obj) → serialize query envelope
  ├── FUN_10091bf0(query_data)         → serialize query
  ├── FUN_10091bf0(body_data)          → serialize body
  ├── snakeoil(query, creds.secret)    → encrypt query  [RVA 0x0B4143]
  └── snakeoil(body, creds.secret)     → encrypt body   [RVA 0x0B4158]
```

## Key DLL Functions

| RVA | Name | Purpose |
|-----|------|---------|
| **Envelope** | | |
| `0x0B3A60` | `envelope_builder` | Top-level: build + encrypt query and body |
| `0x091BF0` | `serializer_dispatch` | Dispatch to serializer by type |
| `0x0921D0` | `set_stream_params` | Set stream config |
| **Serializer** | | |
| `0x1A9930` | `serializer_invoke` | Top-level serializer entry point |
| `0x1A8E80` | `compound_serialize` | Iterate fields, write presence + values (depth-first) |
| `0x1A9DA0` | `field_iterator` | Advance to next field in descriptor |
| `0x1A8BF0` | `prepare` | Prepare field state |
| `0x1A9730` | `compound_value` | Recursive compound serialize |
| **Bit Writers** | | |
| `0x1A8150` | `write_nbits_msb` | Write N bits MSB-first |
| `0x1A8310` | `write_nbits_lsb` | Write N bits LSB-first |
| `0x1A9E80` | `write_1bit` | Write 1 presence bit |
| `0x1A9A80` | `write_bitmap` | Write N-bit bitmap |
| **Leaf Serializers** | | |
| `0x1A5700` | `int_leaf` | Serialize integer (vtable[0x1C]) |
| `0x1A5610` | `uint64_leaf` | Serialize UInt64 → string → 4-bit (vtable[0x24]) |
| `0x1A2040` | `string_leaf` | Serialize string (vtable[0x2C]) |
| `0x1A6740` | `string_4bit_writer` | Write string as 4-bit encoded chars |
| `0x1A4700` | `bitmap_leaf` | Serialize bitmap |
| `0x1A4190` | `sint_leaf` | Serialize signed int |
| `0x1A6B70` | `int64_leaf` | Serialize Int64/UUID |
| **Stream** | | |
| `0x05C700` | `stream_ensure` | Buffer space + SnakeOil XOR encryption |
| `0x1B3E10` | `SnakeOil` | xorshift128 PRNG stream cipher |
| `0x1AA3A0` | `HMAC_MD5` | HMAC computation |

## Serialization Flow

### 1. `serializer_invoke` (FUN_101a9930)

```
1. type_info = body_obj->vtable[1]()     // get type descriptor
2. descriptor = type_info->sub_desc      // get field chain
3. version_key = descriptor->field_array  // get version info
4. version_lookup(registry, version_key)  // find version in table
5. descriptor->vtable[7]()               // prepare (set up field state)
6. descriptor->vtable[2]()               // compound_serialize
```

### 2. `compound_serialize` (FUN_101a8e80) — DEPTH-FIRST

For each field in the descriptor:
```
1. sub_obj = accessor(data_obj)
2. present = is_present(sub_obj)           // reads byte at sub_obj+4
3. write_1bit(present)                     // presence bit
4. If present AND compound: compound_serialize(sub_obj)  // RECURSE IMMEDIATELY
5. If present AND leaf: dispatch to type-specific serializer
```

**Critical:** Presence bits are interleaved with data in depth-first order. NOT written all-at-once then data.

### 3. Leaf Serializers

| Type | Vtable | Encoding |
|------|--------|----------|
| Compound | `0x102D21CC` | Recursive depth-first |
| Integer | `0x102D1E8C` | N bits MSB-first, width from descriptor |
| String | `0x102CE850` | Low nibble of each char, 4 bits MSB-first |
| Int64/UUID | `0x102D23AC` | Via string_4bit_writer |
| Bitmap | `0x102D1AB8` | N bits raw |
| SignedInt | `0x102D1948` | Sign bit + magnitude |

## BitStream Object Layout

```
Offset  Size  Purpose
+0x00   4     buffer pointer (heap-allocated)
+0x04   4     current bit position (within current byte, 0-7)
+0x08   4     byte position (bytes completed)
+0x0C   4     buffer capacity
+0x10   4     flags (0x0101 for credential/compound serializer)
```

## Encoding Rules (Verified)

| Rule | Evidence | Status |
|------|----------|--------|
| Bit ordering: MSB-first | Credential `C4` = `[1][1][0001][00]` | ✅ |
| Presence bits: 1 bit per field, depth-first | Assembly trace at 0x1A8F46 | ✅ |
| String encoding: low nibble of ASCII, 4 bits, MSB-first | Unicorn trace: `msb(0x44, 4b)` for 'D' | ✅ |
| Integer encoding: variable bit width from descriptor | Descriptor analysis | ✅ |
| Credential: raw BE bytes after presence+type header | Byte-exact match with DLL output | ✅ |
| Compound: depth-first interleaved presence + data | Assembly analysis | ✅ |

### String 4-bit Alphabet (low nibble mapping)

```
0: P p 0 @    4: D d T t 4    8: H h X x 8    C: L l \ |
1: A a Q q 1  5: E e U u 5    9: I i Y y 9    D: M m ] -
2: B b R r 2  6: F f V v 6    A: J j Z z :    E: N n . ^
3: C c S s 3  7: G g W w 7    B: K k [ ;      F: O o _ /
```

LOSSY — uppercase/lowercase/digits sharing a low nibble are indistinguishable.

## Credential Encoding (21 bytes)

```
[0xC4][hu_code 8B BE][tb_code 8B BE][timestamp 4B BE]
```

`0xC4` = `11000100`:
- bit 7: 1 → hu_code present
- bit 6: 1 → tb_code present
- bits 5-2: `0001` → type indicator (1)
- bits 1-0: `00` → padding

After the presence+type header, the serializer pads to byte boundary, then writes raw big-endian bytes.

## Type Hierarchy for RequestEnvelopeRO

```
RequestEnvelopeRO (5 fields):
  [0] CredentialsRO (4 fields):
       [0] Str4(3b) — credential name
       [1] ByteArray(240b) — 30 bytes
       [2] UInt64(64b) — Code
       [3] UInt64(64b) — Secret
  [1] DeviceCredentialsRO (3 fields):
       [0] ByteArray(240b) — Name
       [1] UInt64(64b) — Code
       [2] UInt64(64b) — Secret
  [2] Int(8b) — service type
  [3] GeoCoordRO (2 fields):
       [0] AbsCoord
       [1] AbsCoord
  [4] AuthenticatedDelegationRO (2 fields):
       [0] DelegationRO (4 fields):
            [0] Str4(4b) — name
            [1] UInt64(64b) — hu_code
            [2] UInt64(64b) — tb_code
            [3] UInt32(32b) — timestamp
       [1] MessageDigestRO (2 fields):
            [0] Str4(4b) — algorithm
            [1] Bool(1b) — data
```

### Complete Leaf Type Map

```
[ 1] RequestEnvelopeRO:     f2:Int(8b)
[ 2] UuidRO:                f0:Str(4b), f1:Int64(0b)
[ 4] AbsCoordRO:            f0:Bitmap(32b), f1:SInt(16b), f2:SInt(16b)
[ 6] AbstractCellRO:        f0:Bitmap(32b)
[ 9] CellStretchRO:         f0:?(5b), f1:?(1b), f2:?(8b)
[14] HyperlinkRO:           f0:Str(4b), f1:Str(4b)
[15] AttachmentRO:           f0:Str(5b), f1:?(4b), f2:?(2b)
[16] AddressRO:              f0:?(8b), f6:?(1b)
[26] PacketLengthRO:         f0:?(32b)
[27] ManifestRO:             f1:Bitmap(32b), f3:?(64b), f11:Bitmap(32b), f13:?(1b),
                             f15:?(1b), f16:?(16b), f17:?(16b), f22:?(0b)
[33] NavigationEventRO:      f0:Str(5b), f1:Str(4b)
```

## C++ Class Hierarchy (devirtualized)

```python
class EncryptingStream:     # FUN_1005c700 — buffer + SnakeOil XOR
class BitWriter:            # FUN_101a8150/8310/9e80 — bit-level writes
class SerializerContext:    # Leaf serializer dispatch (write_int, write_uint64, write_string)
class TypeDescriptor:       # FUN_101a8e80 — compound_serialize with depth-first field iteration
class FieldDescriptor:      # Field metadata: name, type, accessor offset, sub-fields
```

**Vtable dispatch mapping:**

| Ghidra C pattern | Meaning | Python |
|-----------------|---------|--------|
| `(**(code **)(*param + 0x1c))(val)` | `stream->write_int(val)` | `ctx.write_int(val)` |
| `(**(code **)(*param + 0x24))(lo, hi)` | `stream->write_uint64(lo, hi)` | `ctx.write_uint64(lo, hi)` |
| `(**(code **)(*param + 0x2c))(s, n)` | `stream->write_string(s, n)` | `ctx.write_string(s, n)` |
| `(**(code **)(*p + 8))(body, out, ver)` | `desc->compound_serialize(...)` | `desc.serialize(data, ctx)` |

## Python Model Status

| Component | File | Status |
|-----------|------|--------|
| EncryptingStream | `igo_serializer_model.py` | ✅ Complete |
| BitWriter (MSB + LSB) | `igo_serializer_model.py` | ✅ Complete |
| SerializerContext | `igo_serializer_model.py` | ✅ Complete |
| TypeDescriptor (depth-first) | `igo_serializer_model.py` | ✅ Complete |
| REQUEST_ENVELOPE type hierarchy | `igo_serializer_model.py` | ✅ Complete |
| Credential encoding test | `igo_serializer_model.py` | ✅ Byte-exact match |
| BitStream (simple writer) | `bitstream.py` | ✅ Verified |

## Files

| File | Description |
|------|-------------|
| `medianav_toolbox/igo_serializer_model.py` | Python model with Ghidra C as comments |
| `medianav_toolbox/wire_message.py` | Structured decode/encode of complete wire messages |
| `medianav_toolbox/bitstream.py` | Simple BitStream writer |
| `analysis/serializer_functions.c` | 18 Ghidra-decompiled C functions |
| `analysis/nngine_decompiled.c` | Full Ghidra decompilation (15MB) |
| `analysis/unicorn_serialize3.py` | Unicorn harness for credential serializer |
| `analysis/unicorn_compound.py` | Unicorn harness for compound serializer |
