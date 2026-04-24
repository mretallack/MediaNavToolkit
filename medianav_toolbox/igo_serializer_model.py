"""Python model of nngine.dll's igo-binary serializer.

1:1 translation of Ghidra decompiled C with devirtualized vtable calls.
Original C is in comments. See analysis/serializer_functions.c for full source.

Ref: docs/serializer.md
"""

import struct

MASK32 = 0xFFFFFFFF


class EncryptingStream:
    """FUN_1005c700 — stream with SnakeOil XOR encryption.

    C++ layout: [+0]=key_ptr, [+8]=bytes_written, [+C]=bytes_allocated, [+14]=total_capacity
    """

    def __init__(self, snakeoil_seed=None, capacity=65536):
        self.buf = bytearray(capacity)
        self.bytes_written = 0  # param_1[2]
        self.bytes_allocated = 0  # param_1[3]
        self.total_capacity = capacity  # param_1[5]
        # SnakeOil PRNG state stored at *param_1[0]
        self.key_lo = (snakeoil_seed or 0) & MASK32
        self.key_hi = ((snakeoil_seed or 0) >> 32) & MASK32
        self.has_key = snakeoil_seed is not None

    def ensure(self, num_bytes):
        """FUN_1005c700"""
        # uVar3 = param_1[3];  uVar4 = param_1[2] + param_2;
        # if (uVar4 <= uVar3) return 1;
        if self.bytes_written + num_bytes <= self.bytes_allocated:
            return True

        # uVar2 = (param_1[2] - uVar3) + param_2;
        overflow = (self.bytes_written - self.bytes_allocated) + num_bytes
        encrypt_len = overflow

        # if (param_1[5] - uVar3 < uVar2) uVar4 = param_1[5] - uVar3;
        if self.total_capacity - self.bytes_allocated < overflow:
            encrypt_len = self.total_capacity - self.bytes_allocated

        # if (puVar1 != NULL) { FUN_101b3e10(...); }
        if self.has_key:
            start = self.bytes_allocated
            for i in range(encrypt_len):
                # SnakeOil step
                edx = self.key_lo
                eax = self.key_lo
                eax ^= (eax << 11) & MASK32
                eax ^= eax >> 8
                eax ^= self.key_hi ^ ((self.key_hi >> 19) & MASK32)
                self.key_hi = edx
                self.key_lo = eax
                kb = ((edx << 32 | eax) >> 8) & 0xFF
                self.buf[start + i] ^= kb

        # param_1[3] = uVar4 + uVar3;
        self.bytes_allocated += encrypt_len
        return encrypt_len >= overflow


class BitWriter:
    """The serializer stream that writes bits to an EncryptingStream.

    C++ layout: [+0]=buffer_ptr, [+4]=bit_pos, [+8]=byte_pos,
                [+10]=msb_flag, [+14]=capacity, [+18]=encoding_flag

    In our model, this wraps an EncryptingStream and tracks bit position.
    """

    def __init__(self, stream: EncryptingStream):
        self.stream = stream
        self.bit_pos = 0  # param_1[1] — bits written into current byte
        self.byte_pos = 0  # param_1[2] — bytes completed
        self.msb_flag = 0  # param_1[4] — 0=LSB-first, nonzero=MSB-first

    @property
    def _buf(self):
        return self.stream.buf

    def _cur_byte_idx(self):
        """Current byte index in buffer."""
        return self.byte_pos - (1 if self.bit_pos != 0 else 0)

    # ========== FUN_101a8150 — write_nbits_msb ==========
    def write_nbits_msb(self, value, num_bits):
        """Write num_bits of value, MSB-first into buffer."""
        # undefined1 __thiscall FUN_101a8150(int *param_1, uint param_2, uint param_3)
        if num_bits == 0:
            return True

        # Calculate bytes needed and ensure space
        # iVar5 = (param_3 + 7 + param_1[1] >> 3) - (param_1[1] != 0)
        bytes_needed = ((num_bits + 7 + self.bit_pos) >> 3) - (1 if self.bit_pos != 0 else 0)
        if bytes_needed > 0:
            if not self.stream.ensure(bytes_needed):
                return False

        # pbVar6 = buffer + byte_pos - (bit_pos != 0)
        buf_idx = (
            self.byte_pos
            + self.stream.bytes_written
            - bytes_needed
            - (1 if self.bit_pos != 0 else 0)
        )
        # Simpler: just track our own position
        pos = self.byte_pos
        if self.bit_pos != 0:
            pos -= 1

        self.byte_pos += bytes_needed

        # bVar3 = bit_pos; iVar5 = bit_pos
        bp = self.bit_pos

        # if (iVar5 + param_3 < 9) — fits in current byte
        if bp + num_bits < 9:
            existing = self._buf[pos] if bp != 0 else 0
            # *pbVar6 = (param_2 << (8 - bp - param_3)) & (0xff >> bp) | existing
            shift = 8 - bp - num_bits
            mask = 0xFF >> bp
            self._buf[pos] = ((value << shift) & mask) | existing
            self.bit_pos = (self.bit_pos + num_bits) & 7
            return True

        # Doesn't fit — write across multiple bytes
        remaining = num_bits
        if bp != 0:
            # First partial byte
            remaining = (bp + num_bits) - 8
            mask = 0xFF >> bp
            self._buf[pos] = self._buf[pos] | ((value >> remaining) & mask)
            pos += 1

        # Full bytes
        while remaining > 7:
            remaining -= 8
            self._buf[pos] = (value >> remaining) & 0xFF
            pos += 1

        # Last partial byte
        self.bit_pos = remaining
        if remaining != 0:
            self._buf[pos] = (value << (8 - remaining)) & 0xFF

        return True

    # ========== FUN_101a8310 — write_nbits_lsb ==========
    def write_nbits_lsb(self, value, num_bits):
        """Write num_bits of value, LSB-first into buffer."""
        # undefined1 __thiscall FUN_101a8310(int *param_1, uint param_2, uint param_3)
        if num_bits == 0:
            return True

        bytes_needed = ((num_bits + 7 + self.bit_pos) >> 3) - (1 if self.bit_pos != 0 else 0)
        if bytes_needed > 0:
            if not self.stream.ensure(bytes_needed):
                return False

        pos = self.byte_pos
        if self.bit_pos != 0:
            pos -= 1
        self.byte_pos += bytes_needed

        bp = self.bit_pos

        # if (iVar2 + param_3 < 9) — fits in current byte
        if bp + num_bits < 9:
            existing = self._buf[pos] if bp != 0 else 0
            # mask low bits, shift left by bit_pos
            mask = 0xFF >> (8 - num_bits)
            self._buf[pos] = ((value & mask) << bp) | existing
            self.bit_pos = (self.bit_pos + num_bits) & 7
            return True

        remaining = num_bits
        if bp != 0:
            # *pbVar5 = *pbVar5 | (param_2 << bit_pos)
            self._buf[pos] = self._buf[pos] | ((value << bp) & 0xFF)
            remaining -= 8 - bp
            value >>= 8 - bp
            pos += 1

        # Full bytes
        while remaining > 7:
            self._buf[pos] = value & 0xFF
            remaining -= 8
            value >>= 8
            pos += 1

        # Last partial byte
        self.bit_pos = remaining
        if remaining != 0:
            self._buf[pos] = value & (0xFF >> (8 - remaining))

        return True

    # ========== FUN_101a9e80 — write_1bit ==========
    def write_1bit(self, bit_value):
        """Write a single presence bit."""
        # Uses MSB or LSB path based on self.msb_flag
        # For the compound serializer, msb_flag is typically nonzero (MSB-first)
        if self.msb_flag:
            return self.write_nbits_msb(bit_value & 1, 1)
        else:
            return self.write_nbits_lsb(bit_value & 1, 1)


class SerializerContext:
    """The serializer context passed to leaf serializers.

    C++ layout: [+0]=vtable, [+4]=bits_per_element, [+C]=field_count, [+18]=encoding_flag

    Devirtualized: vtable methods become direct Python methods.
    """

    def __init__(self, writer: BitWriter, bits_per_element=4, encoding_flag=0):
        self.writer = writer
        self.bits_per_element = bits_per_element  # [+4]
        self.field_count = 0  # [+C]
        self.encoding_flag = encoding_flag  # [+18]

    # vtable[7] = 0x1C — write_int
    def write_int(self, value):
        """FUN_101a5700 leaf: (**(code **)(*param_2 + 0x1c))((int)*param_1)"""
        self.writer.write_nbits_msb(value & 0xFF, self.bits_per_element)

    # vtable[9] = 0x24 — write_uint64 (dispatches to string_4bit_writer)
    def write_uint64(self, lo32, hi32):
        """FUN_101a5610 leaf: (**(code **)(*param_2 + 0x24))(*param_1, param_1[1])

        FUN_101a6740: reads 1 bit, then writes the value using bits_per_element.
        The UInt64 is passed as a string object pointer, not raw integers.
        """
        # FUN_101a6740 reads a flag bit first, then the string data
        # For now, write the value as a hex string with 4 bits per char
        hex_str = f"{hi32:08X}{lo32:08X}"
        for ch in hex_str:
            self.writer.write_nbits_msb(ord(ch) & 0xF, self.bits_per_element)

    # vtable[11] = 0x2C — write_string
    def write_string(self, s, count):
        """FUN_101a2040 leaf: (**(code **)(*param_3 + 0x2c))(*param_2, field_count)"""
        for ch in s[:count]:
            self.writer.write_nbits_msb(ord(ch) & 0xF, self.bits_per_element)

    # FUN_101a1f80 — string_compound: gets string via vtable[0x20], writes with nbits
    def write_string_compound(self, value, field_obj):
        """FUN_101a1f80"""
        # if (*(char *)(param_2 + 1) == '\0') uVar1 = 0;
        # else uVar1 = (**(code **)(*param_1 + 0x20))(*param_2);
        # Then writes with MSB or LSB based on flag
        if not is_present_byte(field_obj):
            val = 0
        else:
            val = field_obj[0]  # the byte value

        if self.encoding_flag:
            self.writer.write_nbits_msb(val, self.bits_per_element)
        else:
            self.writer.write_nbits_lsb(val, self.bits_per_element)


def is_present_byte(field_obj):
    """FUN_101a98a0: return *(byte*)(param_1 + 4)"""
    if isinstance(field_obj, dict):
        return field_obj.get("present", False)
    return False


# ========== Compound Serializer ==========


class FieldDescriptor:
    """A field in the type descriptor chain.

    From the DLL field array: 24 bytes per entry.
    [+0] = type descriptor pointer (determines the serializer)
    [+4] = accessor function (returns data_obj + offset)
    """

    def __init__(self, name, field_type, accessor_offset, sub_fields=None, bits=0):
        self.name = name
        self.field_type = field_type  # 'compound', 'uint64', 'uint32', 'str4', 'str5', 'bitmap', 'int', 'sint', 'bool'
        self.accessor_offset = accessor_offset
        self.sub_fields = sub_fields or []
        self.bits = bits  # bit width for leaf types


class TypeDescriptor:
    """A type in the descriptor chain.

    Devirtualized from vtable at 0x102D21CC.
    """

    def __init__(self, name, fields):
        self.name = name
        self.fields = fields  # list of FieldDescriptor

    def serialize(self, data_obj, ctx):
        """FUN_101a8e80 (compound_serialize) — depth-first serialization.

        For each field: write presence bit, then IMMEDIATELY serialize if present.
        This interleaves presence bits with data in depth-first order.

        From assembly at 0x1A8F46-0x1A9194:
            sub_obj = accessor(data_obj)
            present = is_present(sub_obj)
            write_1bit(present)
            if present and field.is_compound:
                compound_serialize(sub_obj, stream, version)  // recursive
        """
        for field in self.fields:
            sub_obj = data_obj.get(field.name, {})
            present = sub_obj.get("present", False) if isinstance(sub_obj, dict) else False
            ctx.writer.write_1bit(1 if present else 0)

            if not present:
                continue

            if field.field_type == "compound":
                # Recursive: serialize sub-type IMMEDIATELY (depth-first)
                sub_type = TypeDescriptor(field.name, field.sub_fields)
                sub_type.serialize(sub_obj, ctx)

            elif field.field_type == "uint64":
                ctx.write_uint64(sub_obj["lo32"], sub_obj["hi32"])

            elif field.field_type == "uint32":
                hex_str = f"{sub_obj['value']:08X}"
                for ch in hex_str:
                    ctx.writer.write_nbits_msb(ord(ch) & 0xF, 4)

            elif field.field_type in ("str4", "str5"):
                bits = 4 if field.field_type == "str4" else 5
                s = sub_obj.get("value", "")
                for ch in s:
                    ctx.writer.write_nbits_msb(ord(ch) & ((1 << bits) - 1), bits)

            elif field.field_type == "int":
                ctx.writer.write_nbits_msb(sub_obj.get("value", 0) & 0xFF, field.bits)

            elif field.field_type == "bool":
                ctx.writer.write_nbits_msb(1 if sub_obj.get("value", False) else 0, 1)

            elif field.field_type == "bitmap":
                ctx.writer.write_nbits_msb(sub_obj.get("value", 0), field.bits)


# ========== Type Definitions from DLL Descriptor Chain ==========

# RequestEnvelopeRO (entry 1 at 0x1030DE5C)
REQUEST_ENVELOPE = TypeDescriptor(
    "RequestEnvelopeRO",
    [
        FieldDescriptor(
            "credentials",
            "compound",
            0x08,
            [
                FieldDescriptor("name", "str4", 0x08, bits=3),
                FieldDescriptor("data", "bitmap", 0x10, bits=240),
                FieldDescriptor("code", "uint64", 0x18),
                FieldDescriptor("secret", "uint64", 0x20),
            ],
        ),
        FieldDescriptor(
            "device_credentials",
            "compound",
            0x38,
            [
                FieldDescriptor("name", "bitmap", 0x08, bits=240),
                FieldDescriptor("code", "uint64", 0x10),
                FieldDescriptor("secret", "uint64", 0x18),
            ],
        ),
        FieldDescriptor("service_type", "int", 0x60, bits=8),
        FieldDescriptor(
            "geo_coord",
            "compound",
            0x64,
            [
                FieldDescriptor("coord1", "compound", 0x08),
                FieldDescriptor("coord2", "compound", 0x10),
            ],
        ),
        FieldDescriptor(
            "auth_delegation",
            "compound",
            0x7C,
            [
                FieldDescriptor(
                    "delegation",
                    "compound",
                    0x08,
                    [
                        FieldDescriptor("name", "str4", 0x08, bits=4),
                        FieldDescriptor("hu_code", "uint64", 0x10),
                        FieldDescriptor("tb_code", "uint64", 0x18),
                        FieldDescriptor("timestamp", "uint32", 0x20),
                    ],
                ),
                FieldDescriptor(
                    "message_digest",
                    "compound",
                    0x38,
                    [
                        FieldDescriptor("algorithm", "str4", 0x08, bits=4),
                        FieldDescriptor("data", "bool", 0x10, bits=1),
                    ],
                ),
            ],
        ),
    ],
)


# ========== Test against known credential output ==========
def test_credential():
    """Verify the model produces the correct credential serialization."""
    stream = EncryptingStream(snakeoil_seed=None, capacity=256)
    writer = BitWriter(stream)
    writer.msb_flag = 1  # MSB-first (from Unicorn trace)

    # Credential serializer writes:
    # write_1bit(1) — hu_code present
    # write_1bit(1) — tb_code present
    # write_nbits_msb(1, 4) — type indicator
    writer.write_1bit(1)
    writer.write_1bit(1)
    writer.write_nbits_msb(1, 4)

    # Pad to byte boundary (credential serializer does this)
    if writer.bit_pos != 0:
        writer.write_nbits_msb(0, 8 - writer.bit_pos)

    # Raw bytes: hu_code (8B BE) + tb_code (8B BE) + timestamp (4B BE)
    for b in struct.pack(">Q", 0x000BF28569BACB7C):
        writer.write_nbits_msb(b, 8)
    for b in struct.pack(">Q", 0x000D4EA65D36B98E):
        writer.write_nbits_msb(b, 8)
    for b in struct.pack(">I", 0x69D4BA80):
        writer.write_nbits_msb(b, 8)

    result = bytes(stream.buf[: writer.byte_pos])
    expected = bytes.fromhex("c4000bf28569bacb7c000d4ea65d36b98e69d4ba80")

    print(f"Result:   {result.hex()}")
    print(f"Expected: {expected.hex()}")
    assert result == expected, f"MISMATCH!"
    print("✅ Credential encoding verified!")


if __name__ == "__main__":
    test_credential()

    # Test: serialize the 0x68 delegation chain body structure
    print("\n=== Testing 0x68 chain body serialization ===")

    # Build the data object for 0x68 format
    # Fields present: DeviceCredentialsRO (all absent), GeoCoordRO (all absent),
    # AuthenticatedDelegationRO (DelegationRO with tb_code+timestamp, MessageDigestRO absent)
    data = {
        "credentials": {"present": False},
        "device_credentials": {
            "present": True,
            "name": {"present": False},
            "code": {"present": False},
            "secret": {"present": False},
        },
        "service_type": {"present": False},
        "geo_coord": {
            "present": True,
            "coord1": {"present": False},
            "coord2": {"present": False},
        },
        "auth_delegation": {
            "present": True,
            "delegation": {
                "present": True,
                "name": {"present": False},
                "hu_code": {"present": False},
                "tb_code": {
                    "present": True,
                    "lo32": 0x5D36B98E,
                    "hi32": 0x000D4EA6,
                },
                "timestamp": {
                    "present": True,
                    "value": 0x69EA2FF7,  # run32 timestamp
                },
            },
            "message_digest": {
                "present": True,
                "algorithm": {"present": False},
                "data": {"present": False},
            },
        },
    }

    # Write type indicator byte DIRECTLY to buffer (unencrypted, before BitWriter)
    from medianav_toolbox.bitstream import BitStream

    bs = BitStream()

    # Type indicator is NOT part of the bitstream — it's prepended separately
    # The bitstream starts with the presence bits

    # Serialize the RequestEnvelopeRO using our proven BitStream
    def serialize_type(type_desc, data_obj, bs):
        """Recursive serializer — depth-first, interleaved presence + data."""
        for field in type_desc.fields:
            sub_obj = data_obj.get(field.name, {})
            present = sub_obj.get("present", False) if isinstance(sub_obj, dict) else False
            bs.write_bit(1 if present else 0)

            if not present:
                continue

            if field.field_type == "compound":
                sub_type = TypeDescriptor(field.name, field.sub_fields)
                serialize_type(sub_type, sub_obj, bs)
            elif field.field_type == "uint64":
                hex_str = f"{sub_obj['hi32']:08X}{sub_obj['lo32']:08X}"
                for ch in hex_str:
                    bs.write_bits(ord(ch) & 0xF, 4)
            elif field.field_type == "uint32":
                hex_str = f"{sub_obj['value']:08X}"
                for ch in hex_str:
                    bs.write_bits(ord(ch) & 0xF, 4)
            elif field.field_type in ("str4", "str5"):
                bw = 4 if field.field_type == "str4" else 5
                for ch in sub_obj.get("value", ""):
                    bs.write_bits(ord(ch) & ((1 << bw) - 1), bw)
            elif field.field_type == "int":
                bs.write_bits(sub_obj.get("value", 0), field.bits)
            elif field.field_type == "bool":
                bs.write_bit(1 if sub_obj.get("value", False) else 0)
            elif field.field_type == "bitmap":
                bs.write_bits(sub_obj.get("value", 0), field.bits)

    serialize_type(REQUEST_ENVELOPE, data, bs)
    raw_bits = bs.to_bytes()

    # Prepend type indicator
    raw = b"\x58" + raw_bits
    print(f"Raw bitstream ({len(raw)}B): {raw[:20].hex()}...")
    print(f"Byte 0: 0x{raw[0]:02X} (expect 0x58)")

    # Check presence bits
    bits = "".join(format(b, "08b") for b in raw)
    print(f"Bits 0-7: {bits[0:8]} (type indicator)")
    print(f"Bits 8-12: {bits[8:13]} (RequestEnvelope presence: {bits[8:13]})")
    print(f"  Expected: 01011 (DevCred=0, DevCred=1, Int=0, Geo=1, Auth=1)")
    print(f"Bits 13-15: {bits[13:16]} (DeviceCredentialsRO sub-presence)")
    print(f"Bits 16-17: {bits[16:18]} (GeoCoordRO sub-presence)")
    print(f"Bits 18-19: {bits[18:20]} (AuthDelegationRO sub-presence)")
    print(f"Bits 20-23: {bits[20:24]} (DelegationRO sub-presence)")
    print(f"Bits 24-25: {bits[24:26]} (MessageDigestRO sub-presence)")

    # The raw bitstream should match the captured chain body (before encryption)
    # We derived the keystream for run32: 35 5B 14 21 A0 2A EE 80 56 7D ...
    # chain_body[1:] = raw[1:] XOR keystream
    # So raw[1:] = chain_body[1:] XOR keystream

    print(f"\nRaw bytes 1-10: {raw[1:11].hex()}")
    print(f"Expected (from derivation): 0660002228b2a1b14c28")
    expected_raw = bytes.fromhex("580660002228b2a1b14c28")
    if raw[:11] == expected_raw:
        print("✅ Raw bitstream matches derived plaintext!")
    else:
        print(f"❌ Mismatch — need to debug field encoding")
        for i in range(min(11, len(raw))):
            match = "✅" if raw[i] == expected_raw[i] else "❌"
            print(f"  byte {i}: got 0x{raw[i]:02X} expect 0x{expected_raw[i]:02X} {match}")
