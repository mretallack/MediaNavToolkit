# Spec: Build sendfilecontent and sendfingerprint from scratch

## Goal

Generate `sendfilecontent` and `sendfingerprint` wire bodies from scratch (not replayed from captures) so the full download flow can be automated end-to-end.

## Reference Data

All reference data is in `/home/mark/git/MediaNavToolbox/capture/July2026/`:

- `wire_103_311.bin` — captured sendfilecontent (311B wire, decrypts to 253B body)
- `wire_55_53279_sendfingerprint1.bin` — captured fingerprint 1 (53KB)
- `wire_101_46609_sendfingerprint2.bin` — captured fingerprint 2 (46KB)
- `query_89_53244_fingerprint_first4096.bin` — plaintext of fingerprint 1 (first 4096B)
- `query_507_41066_fingerprint2_first4096.bin` — plaintext of fingerprint 2 (first 4096B)

## Part 1: sendfilecontent

### Format (decoded)

Wire format: `build_dynamic_request(flags=0x08, no tb_name, 41B query)`

Body structure (253 bytes for device_status.ini):
```
0xE0                            marker
encode_string("primary")        mount name
encode_string("NaviSync")       path (parent directory)
encode_string("device_status.ini")  filename
00 00 00 01                     flags (4 bytes, always 1?)
varint(content_length)          length of file content
<file content bytes>            raw file data
00×14                           14 zero bytes padding
0xC3                            trailer byte
```

The varint for content length: `0x81 0x43` in the capture. This decodes as:
- `0x81` = continuation bit + low 7 bits = 1
- `0x43` = 67
- Value = 1 + (67 × 128) = 8577? BUT actual content is ~195 bytes.
- **Re-check**: Maybe `0x81` is just the raw length byte (129) and `0x43` is part of the content? Need to verify by counting bytes exactly.

### Implementation

Function: `build_sendfilecontent_body(usb_path) -> bytes`

Reads `NaviSync/device_status.ini` from USB and wraps it in the 0xE0 format.

### Test

Compare encrypted output against `wire_103_311.bin`:
- Decrypt both with same key, compare body structure
- Body should match byte-for-byte (same file content, same format)
- Note: timestamps may differ, so compare structure not exact bytes

## Part 2: sendfingerprint

### Format (decoded from captured plaintext)

Two fingerprints are needed:

#### Fingerprint 1 (ctx=0, flags=0xC0)
- Includes **Toolbox local cache** directory listing
- Standard DEVICE mode request (query encrypted with Code, body with Secret)
- Our minimal stub (113B) already returns 200 and is accepted
- Full version has 11,139 entries but minimal works fine

#### Fingerprint 2 (ctx=1, flags=0xD0)  
- Includes **USB drive** file listing only
- Standard DEVICE mode request
- Requires delegated senddevicestatus to have been called first
- Has 2,691 entries in capture (full USB listing)

### Entry Format (hierarchical tree with 0x70 nesting)

Header:
```
encode_int32(device_context_id)   0 for fp1, 1 for fp2
flags_byte                        0xC0 for fp1, 0xD0 for fp2
encode_string(checksum)           "N/A" for fp1, device_checksum.md5 for fp2
encode_varint(entry_count)        total entries
```

Entries (tree structure):
```
Top-level DIR:  0x22 + name + mount + size(8B) + ts(8B) + ts(8B)
  0x70 delimiter (signals children follow)
  Child DIR:  0x22 + name + mount + parent + size(8B) + ts(8B) + ts(8B)
    0x70 delimiter
    Child FILE: 0xA0 + md5 + name + mount + parent + size(8B) + ts(8B) + ts(8B)
    ... more files
  Next DIR: ...
```

- `mount` = "primary" for USB entries, cache path for fp1
- `parent` = parent directory relative path (e.g., "NaviSync", "NaviSync/content")
- Top-level entries have 2 strings (name + mount), children have 3-4

Storage block (at end):
```
01 00                             count=1, readonly=false
encode_string("primary")          mount name
encode_int64(total_space)
encode_int64(free_space)
encode_int64(0)                   min_free
00 00 10 00                       block_size (4096)
encode_string("E:\\")             drive path
```

Footer:
```
encode_string("{timestamp}_{count}")
```

### Key Unknown: 0x70 Nesting Rules

From captured data:
- After top-level "NaviSync" dir: `0x70` then child "content" dir
- After "content" dir: next marker appears (0xA0 file or 0x22 dir)
- It's unclear if EVERY parent-child boundary has 0x70 or just the first level

**Strategy**: Parse the full 4096-byte fragments to determine the exact nesting rules, then build a recursive directory walker that produces the correct byte sequence.

### Tests

1. Build fingerprint 2 from the current USB data
2. Decrypt `wire_101_46609_sendfingerprint2.bin` to get expected plaintext
3. Compare entry-by-entry (timestamps will differ but structure should match)
4. Also test: send the built fingerprint to the live server and verify 200 response

## Part 3: Integration Test

Once both are built from scratch:
1. Login
2. Send fingerprint 1 (minimal stub is fine — already works)
3. senddevicestatus 0x60
4. delegator
5. senddevicestatus delegated (0x28 with tb_name)
6. Send fingerprint 2 (built from scratch)
7. sendfilecontent (built from scratch)
8. Open SSE listener (threaded)
9. Web confirm content
10. Wait for SSE event or poll getprocess
11. Decrypt manifest → CDN URLs
12. Download files

## Files to modify

- `medianav_toolbox/wire_codec.py` — add `build_sendfilecontent_body()`, `build_fingerprint_body()`
- `medianav_toolbox/session.py` — add `_send_file_content()` using `build_dynamic_request`
- `tests/test_wire_codec.py` or new `tests/test_fingerprint.py` — unit tests against captures
