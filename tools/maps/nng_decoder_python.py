"""Pure Python FBL section decoder — no Unicorn dependency.

Translates the DLL's FUN_1024a720 regex-like pattern compiler.
The section data is a regex pattern language where:
- Whitespace (0x09-0x0D, 0x20) is consumed
- # triggers hash references that consume following varints
- Metacharacters (^ $ | [ ] ( ) \\ * + ? . {) generate control records
- Other values pass through as data records
"""


def decode_varint(data: bytes, pos: int):
    """Decode one UTF-8-like varint. Returns (value, new_pos)."""
    if pos >= len(data):
        return None, pos
    b0 = data[pos]
    if b0 <= 0xBF:
        return b0, pos + 1
    b1 = data[pos + 1] & 0x3F if pos + 1 < len(data) else 0
    if (b0 & 0x20) == 0:
        return ((b0 & 0x1F) << 6) | b1, pos + 2
    b2 = data[pos + 2] & 0x3F if pos + 2 < len(data) else 0
    if (b0 & 0x10) == 0:
        return (((b0 & 0x0F) << 6 | b1) << 6) | b2, pos + 3
    b3 = data[pos + 3] & 0x3F if pos + 3 < len(data) else 0
    if (b0 & 0x08) == 0:
        return ((((b0 & 0x07) << 6 | b1) << 6 | b2) << 6) | b3, pos + 4
    b4 = data[pos + 4] & 0x3F if pos + 4 < len(data) else 0
    if (b0 & 0x04) == 0:
        return (((((b0 & 0x03) << 6 | b1) << 6 | b2) << 6 | b3) << 6) | b4, pos + 5
    b5 = data[pos + 5] & 0x3F if pos + 5 < len(data) else 0
    return ((((((b0 & 0x01) << 6 | b1) << 6 | b2) << 6 | b3) << 6 | b4) << 6) | b5, pos + 6


# Character class table from DLL at RVA 0x2E5408
_CCLASS = bytearray(256)
_CCLASS[0x00] = 0x80
for _c in range(0x09, 0x0E):
    _CCLASS[_c] = 0x01
_CCLASS[0x20] = 0x01
for _c in [0x24, 0x28, 0x29, 0x2A, 0x2B, 0x2E, 0x3F, 0x5B, 0x5C, 0x5D, 0x5E, 0x7B, 0x7C]:
    _CCLASS[_c] = 0x80
for _c in range(0x30, 0x3A):
    _CCLASS[_c] = 0x1C
for _c in range(0x41, 0x47):
    _CCLASS[_c] = 0x1A
for _c in range(0x47, 0x5B):
    _CCLASS[_c] = 0x12
_CCLASS[0x5F] = 0x10
for _c in range(0x61, 0x67):
    _CCLASS[_c] = 0x1A
for _c in range(0x67, 0x7B):
    _CCLASS[_c] = 0x12


def _is_ws(v):
    return v < 0x100 and (_CCLASS[v] & 0x01) != 0


# Escape table from DLL at DAT_102e3480 (256 int16 entries)
# Positive = output as data, Negative = road class index, Zero = fall through
_ESC_TABLE = [
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    -1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    58,
    59,
    60,
    61,
    62,
    63,
    64,
    -1,
    -4,
    -14,
    -6,
    -25,
    0,
    -2,
    -18,
    0,
    0,
    -3,
    0,
    0,
    -12,
    0,
    -15,
    -26,
    -17,
    -8,
    0,
    0,
    -20,
    -10,
    -22,
    0,
    -23,
    91,
    92,
    93,
    94,
    95,
    96,
    7,
    -5,
    0,
    -7,
    27,
    12,
    0,
    -19,
    0,
    0,
    -28,
    0,
    0,
    10,
    0,
    -16,
    0,
    13,
    -9,
    9,
    0,
    -21,
    -11,
    0,
    0,
    -24,
    0,
    150,
    0,
    159,
    0,
    157,
    0,
    158,
    0,
    151,
    0,
    152,
    0,
    153,
    0,
    154,
    0,
    155,
    0,
    156,
    0,
    1285,
    1285,
    1285,
    1285,
    1285,
    1285,
    1540,
    0,
    160,
    0,
    64,
    0,
    -2,
    -1,
    128,
    0,
    -1,
    -1,
    0,
    0,
    96,
    0,
    -1,
    -1,
    0,
    0,
    160,
    0,
    -1,
    -1,
    2,
    0,
    224,
    0,
    288,
    0,
    0,
    0,
    0,
    0,
    -1,
    -1,
    1,
    0,
    288,
    0,
    -1,
    -1,
    0,
    0,
    64,
    0,
    -1,
    -1,
    0,
    0,
    192,
    0,
    -1,
    -1,
    0,
    0,
    224,
    0,
    -1,
    -1,
    0,
    0,
    256,
    0,
    -1,
    -1,
    0,
    0,
    0,
    0,
    -1,
    -1,
    0,
    0,
    160,
    0,
    -1,
    -1,
    0,
    0,
    32,
    0,
    -1,
    -1,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    10752,
    11008,
    11264,
    11520,
]


def _is_meta(v):
    return v < 0x100 and (_CCLASS[v] & 0x80) != 0


def decode_line_python(data: bytes, flags: int = 0x480080) -> list[int]:
    """Decode one line of FBL section data into uint32 records.

    Pure Python implementation matching the DLL's FUN_1024a720.
    """
    use_varint = bool(flags & 0x80000)
    use_pattern = bool(flags & 0x80)

    end = len(data)
    pos = 0
    records = []

    quote_mode = False  # \Q mode
    group_depth = 0
    in_hash = False  # consuming after #
    hash_depth = 0  # nesting depth for hash consumption

    while pos < end:
        # Read varint
        if use_varint and data[pos] > 0xBF:
            value, next_pos = decode_varint(data, pos)
        else:
            value = data[pos]
            next_pos = pos + 1
        if value is None:
            break

        # --- Quote mode: \Q...\E ---
        if quote_mode:
            if value == 0x5C and next_pos < end and data[next_pos] == 0x45:
                quote_mode = False
                pos = next_pos + 1
                continue
            records.append(value)
            pos = next_pos
            continue

        # --- Whitespace: always consumed ---
        if _is_ws(value):
            pos = next_pos
            continue

        # --- Hash consumption mode ---
        # After #, consume varints until we hit a delimiter that ends the reference.
        # The DLL searches for a matching delimiter (newline chars from context).
        # In practice, # consumes until the next metacharacter at the same nesting level.
        if in_hash:
            # # hash reference: scans character-by-character for NUL delimiter.
            # The DLL advances one byte, skips UTF-8 continuation bytes (0x80-0xBF),
            # then checks if the first byte of the next character == 0x00.
            # This means it scans varint-by-varint, checking the lead byte.
            p = pos
            found = False
            while p < end:
                if data[p] == 0x00:
                    # Found NUL delimiter — resume here
                    pos = p
                    in_hash = False
                    found = True
                    break
                # Advance past this character (skip continuations)
                p += 1
                if use_varint:
                    while p < end and (data[p] & 0xC0) == 0x80:
                        p += 1
            if not found:
                pos = end
                in_hash = False
            continue

        # --- Values > 0xFF: always data ---
        if value > 0xFF:
            records.append(value)
            pos = next_pos
            continue

        # --- Hash # (0x23): handled before metachar check ---
        # In the DLL, # is checked explicitly at LAB_1024ab11,
        # separate from the metacharacter table.
        if value == 0x23 and use_pattern:
            in_hash = True
            hash_depth = 0
            pos = next_pos
            continue

        # --- Metacharacter handling ---
        if _is_meta(value):
            if value == 0x00:  # NUL — stored as data (falls through to default in DLL)
                records.append(0)
                pos = next_pos
                continue

            elif value == 0x5C:  # backslash
                if next_pos < end:
                    esc = data[next_pos]
                    if esc == 0x51:  # \Q
                        quote_mode = True
                        pos = next_pos + 1
                        continue
                    if esc == 0x45:  # \E
                        pos = next_pos + 1
                        continue
                    # Use DLL escape table for other escapes
                    esc_val, esc_end = (
                        decode_varint(data, next_pos)
                        if use_varint and data[next_pos] > 0xBF
                        else (data[next_pos], next_pos + 1)
                    )
                    if esc_val is not None and esc_val < len(_ESC_TABLE):
                        tv = _ESC_TABLE[esc_val]
                        if tv > 0:
                            records.append(tv)
                            pos = esc_end
                            continue
                        elif tv < 0:
                            # Road class → 0x80180000 | class_index
                            records.append(0x80180000 | (-tv))
                            pos = esc_end
                            continue
                    # Fall through: handle octal escapes and others
                    if esc_val is not None and 0x30 <= esc_val <= 0x37:
                        # Octal escape: \0 = NUL, \012 = 10, etc.
                        octal_val = esc_val - 0x30
                        p = esc_end
                        for _ in range(2):
                            if p < end and 0x30 <= data[p] <= 0x37:
                                octal_val = octal_val * 8 + (data[p] - 0x30)
                                p += 1
                            else:
                                break
                        records.append(octal_val)
                        pos = p
                        continue
                    if esc_val is not None:
                        records.append(esc_val)
                    pos = esc_end
                    continue
                records.append(value)
                pos = next_pos
                continue

            elif value == 0x23:  # # hash reference (shouldn't reach here)
                in_hash = True
                hash_depth = 0
                pos = next_pos
                continue

            elif value == 0x28:  # (
                # Check for (?#...) comment — skip to )
                if next_pos + 1 < end and data[next_pos] == 0x3F and data[next_pos + 1] == 0x23:
                    p = next_pos + 2
                    while p < end and data[p] != 0x29:
                        p += 1
                    pos = p + 1 if p < end else end
                    continue
                # Check for (?...) group
                if next_pos < end and data[next_pos] == 0x3F:
                    group_depth += 1
                    if not hasattr(decode_line_python, "_jct"):
                        decode_line_python._jct = 0
                    decode_line_python._jct += 1
                    records.append(0x80080000 | decode_line_python._jct)
                    p = next_pos + 1
                    while p < end and data[p] not in (0x29, 0x3A):
                        p += 1
                    if p < end and data[p] == 0x3A:
                        pos = p + 1
                    elif p < end and data[p] == 0x29:
                        group_depth -= 1
                        pos = p + 1
                    else:
                        pos = p
                    continue
                # Plain ( — stored as data
                records.append(value)
                pos = next_pos
                continue

            elif value == 0x29:  # )
                # In the DLL, ) generates 0x80190000 and decrements local_8.
                # If local_8 == 0 (no matching open group), returns error 0x7A
                # which terminates processing for this line.
                if group_depth <= 0:
                    # No matching ( — terminate (like DLL return 0x7A)
                    records.append(0x80000000)
                    return records
                group_depth -= 1
                records.append(0x80190000)
                pos = next_pos
                continue

            elif value == 0x5E:  # ^ anchor → separator
                records.append(0x80090000)
                pos = next_pos
                continue

            elif value == 0x24:  # $ end anchor
                records.append(0x80160000)
                pos = next_pos
                continue

            elif value == 0x7C:  # | alternation
                records.append(0x80010000)
                pos = next_pos
                continue

            elif value == 0x5B:  # [ character class
                # Skip to matching ]
                p = next_pos
                while p < end and data[p] != 0x5D:
                    p += 1
                records.append(0x800A0000)
                pos = p + 1 if p < end else end
                continue

            elif value == 0x7B:  # { — repetition or data
                # Check if followed by valid {n,m} pattern
                # If not, it's data (falls through to default in DLL)
                p = next_pos
                has_digit = False
                while p < end and (0x30 <= data[p] <= 0x39 or data[p] == 0x2C):
                    has_digit = True
                    p += 1
                if has_digit and p < end and data[p] == 0x7D:
                    # Valid {n,m} — skip it (quantifier modifies previous)
                    pos = p + 1
                    continue
                # Not a valid repetition — store as data
                records.append(value)
                pos = next_pos
                continue

            elif value == 0x2B:  # + quantifier → 0x80330000
                records.append(0x80330000)
                pos = next_pos
                continue

            elif value == 0x2A:  # * quantifier → 0x80300000
                records.append(0x80300000)
                pos = next_pos
                continue

            elif value == 0x2E:  # . wildcard → 0x80170000
                records.append(0x80170000)
                pos = next_pos
                continue

            elif value == 0x3F:  # ? quantifier → 0x80360000
                records.append(0x80360000)
                pos = next_pos
                continue

            elif value == 0x5D:  # ] — NOT in DLL switch, falls through to data
                records.append(value)
                pos = next_pos
                continue

            else:
                # Unknown metachar — consume
                pos = next_pos
                continue

        # --- Default: data record ---
        records.append(value)
        pos = next_pos

    records.append(0x80000000)  # END marker
    return records
