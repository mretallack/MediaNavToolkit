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
            # # hash reference: scans RAW BYTES for delimiter (0x00).
            # The DLL scans byte-by-byte, skipping UTF-8 continuation bytes.
            # When delimiter found: advance past it (delimiter_length bytes).
            # When not found: advance to end of input.
            p = pos
            while p < end:
                if data[p] == 0x00:
                    # Found delimiter — advance past it (length=1 since param_4[0x24]=0→iVar12=0→skip 0 extra)
                    # Actually iVar12 = param_4[0x24] = delimiter length
                    # LAB_1024ac1b: pbVar18 = local_28 + iVar12
                    # local_28 was set to local_20 (current scan pos)
                    # So we advance by iVar12 bytes past the match start
                    # With iVar12=0, we don't advance at all — we stay at the NUL
                    # But then the main loop reads the NUL and hits the 0x00 metachar → break
                    pos = p
                    in_hash = False
                    break
                # Skip UTF-8 continuation bytes
                p += 1
                if use_varint:
                    while p < end and (data[p] & 0xC0) == 0x80:
                        p += 1
            else:
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
                    # Regex escape codes → control records
                    # From DLL's FUN_10244b70:
                    _ESC_CTRL = {
                        0x64: 0x80180007,  # \d → digit
                        0x44: 0x80180008,  # \D → non-digit
                        0x77: 0x80180009,  # \w → word
                        0x57: 0x8018000A,  # \W → non-word
                        0x73: 0x8018000B,  # \s → space
                        0x53: 0x8018000C,  # \S → non-space
                        0x62: 0x8018000D,  # \b → boundary
                        0x42: 0x8018000E,  # \B → non-boundary
                    }
                    if esc in _ESC_CTRL:
                        records.append(_ESC_CTRL[esc])
                        pos = next_pos + 1
                        continue
                    # Non-letter escapes: pass through the escaped value
                    esc_val, esc_end = (
                        decode_varint(data, next_pos)
                        if use_varint and data[next_pos] > 0xBF
                        else (data[next_pos], next_pos + 1)
                    )
                    records.append(esc_val)
                    pos = esc_end
                    continue
                pos = next_pos
                continue

            elif value == 0x23:  # # hash reference (shouldn't reach here)
                in_hash = True
                hash_depth = 0
                pos = next_pos
                continue

            elif value == 0x28:  # ( open group
                # Check for special groups: (?...) (*...)
                if next_pos < end:
                    nb = data[next_pos]
                    if nb == 0x3F:  # (?...)
                        if next_pos + 1 < end:
                            nb2 = data[next_pos + 1]
                            if nb2 == 0x27:  # (?'...) named group → junction
                                # Skip to matching ), generate junction record
                                p = next_pos + 2
                                while p < end and data[p] != 0x29:
                                    p += 1
                                group_depth_counter = getattr(decode_line_python, "_jct", 0) + 1
                                decode_line_python._jct = group_depth_counter
                                records.append(0x80080000 | group_depth_counter)
                                pos = p + 1 if p < end else end
                                continue
                        # Other (?...) — skip to matching )
                        p = next_pos + 1
                        depth = 1
                        while p < end and depth > 0:
                            if data[p] == 0x28:
                                depth += 1
                            elif data[p] == 0x29:
                                depth -= 1
                            p += 1
                        pos = p
                        continue
                    if nb == 0x2A:  # (*...)
                        p = next_pos + 1
                        depth = 1
                        while p < end and depth > 0:
                            if data[p] == 0x28:
                                depth += 1
                            elif data[p] == 0x29:
                                depth -= 1
                            p += 1
                        pos = p
                        continue
                group_depth += 1
                pos = next_pos
                continue

            elif value == 0x29:  # ) close group
                if group_depth > 0:
                    group_depth -= 1
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

            elif value == 0x7B:  # { repetition
                # Skip to matching }
                p = next_pos
                while p < end and data[p] != 0x7D:
                    p += 1
                pos = p + 1 if p < end else end
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

            elif value == 0x5D:  # ] stray
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
