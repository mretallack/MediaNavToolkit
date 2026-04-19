#!/usr/bin/env python3
"""Phase 3: Parameter renaming, improved unknowns, cross-refs, DAT_ labels, Secret3 tags."""
import re

FILE = "/home/mark/git/MediaNavToolbox/analysis/nngine_decompiled.c.backup"

# Secret3 critical path functions
SECRET3_PATH = {
    "FUN_100b3a60", "FUN_101aa050", "FUN_100b1670", "FUN_100b10c0",
    "FUN_10044c60", "FUN_100be3c0", "FUN_100bed80", "FUN_10094510",
    "FUN_100a4bb0", "FUN_10055c70", "FUN_10056830", "FUN_1001fc00",
    "FUN_1001f950", "FUN_10011dd0", "FUN_10096700", "FUN_100bd380",
    "FUN_1005ffe0", "FUN_100b0b50", "FUN_1019eaf0", "FUN_10062240",
    "FUN_10062a20", "FUN_1005fb70", "FUN_100ea130", "FUN_100ea670",
    "FUN_100ea6f0", "FUN_100ea610", "FUN_100ea960", "FUN_100eab30",
    "FUN_10093010", "FUN_10091bf0", "FUN_10091410", "FUN_100935c0",
    "FUN_100b3100", "FUN_100b4600", "FUN_101b3e10", "FUN_10157d40",
    "FUN_10158410", "FUN_10154b40", "FUN_10158610", "FUN_10158710",
    "FUN_101585f0", "FUN_10101120", "FUN_101aa3a0",
}

# Known function names for cross-referencing
KNOWN_FUNCS = {
    "FUN_101b3e10": "SnakeOil",
    "FUN_100b3a60": "protocol_envelope_builder",
    "FUN_101aa050": "credential_constructor",
    "FUN_101aa3a0": "HMAC_MD5",
    "FUN_10157d40": "MD5",
    "FUN_10158410": "XOR_CBC_decrypt",
    "FUN_10154b40": "RSA_PKCS1",
    "FUN_10154860": "RSA_modexp",
    "FUN_10056ad0": "buf_write",
    "FUN_101a9930": "serializer_invoke",
    "FUN_101a8e80": "compound_serializer",
    "FUN_10091bf0": "envelope_writer",
    "FUN_100935c0": "envelope_data_copy",
    "FUN_100b1670": "credential_copier",
    "FUN_100b10c0": "credential_source",
    "FUN_10044c60": "device_nng_reader",
    "FUN_100ea130": "nnge_parser",
    "FUN_100bed80": "license_loader",
    "FUN_100be3c0": "credential_provider_ctor",
    "FUN_10094510": "device_obj_ctor",
    "FUN_100a4bb0": "inner_obj_accessor",
    "FUN_10011dd0": "device_mgr_lookup",
    "FUN_10096700": "singleton_ctor",
    "FUN_100bd380": "SPEEDx_CAM_MD5",
    "FUN_100eab30": "lb_string_parser",
    "FUN_10155c10": "base32_decode",
    "FUN_100ea960": "lyc_reader",
    "FUN_100ba130": "login_arg_factory",
    "FUN_101b41b0": "serializer_lookup",
    "FUN_101b2c30": "binary_serializer",
    "FUN_101b30f0": "xml_serializer",
    "FUN_10147c00": "http_connection_create",
    "FUN_10166560": "config_read",
    "FUN_101d2630": "timestamp_get",
    "FUN_1027e4f5": "malloc",
    "FUN_1027dfe8": "free",
    "FUN_1027fa10": "memcpy",
    "FUN_101baa50": "string_addref",
    "FUN_101b8130": "string_release",
    "FUN_101bad80": "string_set",
    "FUN_101b81b0": "string_copy",
    "FUN_101bd970": "string_get",
    "FUN_101babb0": "string_op",
    "FUN_101bae20": "log_section",
    "FUN_101b74e0": "sprintf_log",
    "FUN_101b8170": "log_end",
    "FUN_101baad0": "string_init",
    "FUN_101bdf30": "string_bool",
    "FUN_101bd8d0": "value_getter",
    "FUN_10056a10": "buf_init",
    "FUN_100b4600": "debug_dump",
    "FUN_100b4a30": "body_obj_ctor",
    "FUN_100b4ad0": "body_obj_cleanup",
    "FUN_10093010": "request_build",
    "FUN_10091410": "request_send",
    "FUN_100b3100": "session_bind",
    "FUN_10204a50": "type_dispatch_switch",
    "FUN_101a9da0": "field_iterator",
    "FUN_101a9e80": "write_1bit_lsb",
    "FUN_101a8150": "write_nbits_msb",
    "FUN_101a8310": "write_nbits_lsb",
    "FUN_101b3f20": "version_process",
    "FUN_100fc170": "buffer_insert",
    "FUN_100fc970": "buffer_copy",
    "FUN_101ec050": "read_uint32",
    "FUN_10055c70": "device_set_inner",
    "FUN_10056830": "device_copy_globals",
    "FUN_1001fc00": "cred_copy_ctor",
    "FUN_1001f950": "cred_copy",
    "FUN_100b0b50": "session_dispatch",
    "FUN_10062240": "cred_entry_parser",
    "FUN_10062a20": "cred_entry_iterator",
    "FUN_1005fb70": "device_mgr_cred_handler",
    "FUN_1005ffe0": "cred_provider_factory",
    "FUN_101585f0": "rsa_provider_wrapper",
    "FUN_10101120": "rsa_key1_init",
    "FUN_10158610": "provider_decrypt",
    "FUN_10158710": "rsa_validate",
    "FUN_100ea670": "cred_provider_find",
    "FUN_100ea6f0": "nnge_string_set",
    "FUN_100ea610": "nnge_block_store",
    "FUN_10154920": "RSA_CRT_modexp",
    "FUN_10158790": "provider_destructor",
    "FUN_1019eaf0": "session_setup",
    "FUN_100312a0": "protocol_utility",
    "FUN_10021060": "array_init",
}

# Additional DAT_ globals to annotate
EXTRA_DATS = {
    "DAT_10314a68": "counter init flag",
    "DAT_10316970": "RSA key store",
    "DAT_10314798": "registration cred data",
    "DAT_103147d4": "device cred globals",
    "PTR_s_network_1030dc74": "\"network\" string",
    "PTR_s_communicating_on_udp_1030b290": "\"communicating_on_udp\"",
    "PTR_u_device_nng_1030b108": "\"device.nng\" path",
    "PTR_u_license_1030b10c": "\"license\" path",
    "PTR_FUN_102bbbf4": "credential provider vtable",
    "PTR_FUN_102b9590": "credential vtable 1",
    "PTR_FUN_102b9580": "credential vtable 2",
    "PTR_FUN_102b9588": "credential vtable 3",
    "PTR_FUN_102b9688": "device object vtable",
    "PTR_FUN_102bb1bc": "envelope vtable 1",
    "PTR_FUN_102bb194": "envelope vtable 2",
    "PTR_FUN_102b02d4": "body serializer vtable",
    "PTR_FUN_102bb1a4": "envelope vtable 3",
    "PTR_FUN_102bb1cc": "request object vtable",
    "PTR_FUN_102d8d68": "binary/XML serializer vtable",
    "PTR_FUN_102d21cc": "shared serializer vtable",
    "PTR_FUN_102baf80": "connection object vtable",
    "PTR_FUN_102baedc": "connection sub-vtable",
    "PTR_FUN_102baf20": "credential copy vtable 1",
    "PTR_FUN_102baf34": "credential copy vtable 2",
    "PTR_FUN_102c769c": "credential data object vtable",
    "PTR_FUN_102c76b0": "RSA provider wrapper vtable",
    "PTR_FUN_102b5f64": "output buffer vtable",
    "s_ZXXXXXXXXXXXXXXXXXXZ_102c11f8": "NNGE template",
    "_DAT_102c11e4": "NNGE key: m0$7j0n4(0n73n71I)",
}

def improved_heuristic(body_lines, fname):
    """Deeper heuristic analysis for unknown functions."""
    body = "\n".join(body_lines)
    n = len(body_lines)
    clues = []

    # Lazy-init singleton pattern (LOCK/UNLOCK + DAT_ + Sleep)
    if re.search(r'LOCK\(\)', body) and re.search(r'Sleep\(1\)', body):
        dat = re.search(r'(DAT_[0-9a-f]+)\s*==\s*0', body)
        if dat:
            return f"Lazy-init singleton (guards {dat.group(1)})"
        return "Lazy-init singleton"

    # String builder pattern (string_op + string_release pairs)
    str_ops = body.count('FUN_101babb0') + body.count('FUN_101bad80')
    str_rels = body.count('FUN_101b8130')
    if str_ops >= 2 and str_rels >= 2:
        clues.append("String builder/formatter")

    # Logging pattern (log_section + log_end)
    if 'FUN_101bae20' in body and 'FUN_101b8170' in body:
        clues.append("Logging function")

    # Vector push_back (check capacity, realloc, copy)
    if re.search(r'param_1\[\d+\]\s*!=\s*param_1\[\d+\]', body) or \
       re.search(r'\(param_1\s*\+\s*\d+\)\s*!=.*\(param_1\s*\+\s*\d+\)', body):
        if 'FUN_1027e4f5' in body or 'FUN_1027ea51' in body or 'FUN_102839f9' in body:
            return "Vector/array push_back with reallocation"
        return "Vector/array operation"

    # Tree insert (red-black tree pattern with color/parent/left/right)
    if re.search(r'\+\s*0xd\)', body) and re.search(r'\+\s*0x[48]\)', body) and n > 20:
        if 'Insert_node' in body or re.search(r'param_\d+\[2\].*param_\d+\[1\]', body):
            return "Red-black tree insert/rebalance"

    # Tree find/lookup
    if re.search(r'while.*\+\s*0xd\)', body) and n < 30:
        clues.append("Tree node lookup/traversal")

    # Iterator pattern (begin/end comparison + increment)
    if re.search(r'param_\d+\s*!=\s*\(.*\)param_\d+\[', body) and n < 20:
        clues.append("Container iterator")

    # Ref-counted smart pointer
    if re.search(r'\+\s*1\s*;', body) and re.search(r'==\s*0\)', body) and 'code **' in body and n < 20:
        return "Smart pointer addref/release"

    # Object pool (alloc from free list or malloc)
    if re.search(r'0xffffffff', body) and 'FUN_1027e4f5' in body and n > 15:
        clues.append("Object pool (alloc from free list or new)")

    # Serializer/deserializer (calls serializer_invoke or compound_serializer)
    if 'FUN_101a9930' in body:
        clues.append("Calls serializer_invoke (igo-binary)")
    if 'FUN_101a8e80' in body:
        clues.append("Calls compound_serializer")

    # Config reader
    if 'FUN_10166560' in body:
        clues.append("Reads config value")

    # HTTP connection
    if 'FUN_10147c00' in body:
        clues.append("Creates HTTP connection")

    # Timestamp
    if 'FUN_101d2630' in body:
        clues.append("Gets timestamp")

    # sprintf/format
    if 'FUN_101b74e0' in body:
        clues.append("Formats log message")

    # Large switch with string comparisons
    if body.count('_strcmp') > 2 or body.count('_strncmp') > 2:
        clues.append("String comparison dispatch")

    # File I/O
    if '_fopen' in body or '_wfopen' in body:
        clues.append("Opens file")
    if '_fread' in body:
        clues.append("Reads file data")
    if '_fwrite' in body:
        clues.append("Writes file data")
    if '_fclose' in body:
        clues.append("File I/O")

    # Wide string operations
    if 'wcslen' in body or 'wcscpy' in body or 'wcscat' in body:
        clues.append("Wide string operations")

    # Path operations
    if 'FUN_101c0860' in body or 'FUN_101c0800' in body:
        clues.append("Path string builder")

    # Notification/callback dispatch
    if re.search(r'\(\*\*\(code\s*\*\*\).*\+\s*0x[0-9a-f]+\)\)', body) and body.count('code **') >= 3:
        clues.append("Multi-vtable dispatch (notification/callback)")

    # Simple field copy between objects
    if n < 15 and body.count('param_1[') > 3 and body.count('param_2') > 3:
        if not re.search(r'FUN_|code \*\*', body):
            return "Field copy between objects"

    # Destructor chain (multiple vtable resets + frees)
    vtable_resets = len(re.findall(r'\*param_1\s*=\s*&?PTR_', body))
    if vtable_resets >= 2 and ('FUN_1027dfe8' in body or 'FUN_101b8130' in body):
        return "Destructor chain (resets vtables, frees resources)"

    # Constructor chain (multiple vtable sets + field init)
    if vtable_resets >= 2 and '= 0;' in body and n < 30:
        return "Constructor chain (sets vtables, initializes fields)"

    # Comparison/equality
    if n < 15 and re.search(r'return.*==|return.*!=', body):
        clues.append("Equality/comparison check")

    if not clues:
        return None
    return "; ".join(clues[:3])


def build_crossref(body_lines):
    """Build cross-reference list of known functions called."""
    body = " ".join(body_lines)
    refs = []
    for func_addr, name in KNOWN_FUNCS.items():
        if func_addr + "(" in body or func_addr + ")" in body:
            refs.append(name)
    return refs


print(f"Reading {FILE}...")
with open(FILE) as f:
    lines = f.readlines()
total = len(lines)
print(f"{total} lines")

# Build function index
func_re = re.compile(r'^([A-Za-z_]\S*(?:\s+\S+)*?)\s+(?:__\w+\s+)?([A-Za-z_~][\w:~<>,\s]*?)\s*\(')
skip = {'if','while','for','switch','return','else','do','case','goto','sizeof'}
functions = []  # (line_idx, fname, body_start, body_end)

for i, line in enumerate(lines):
    s = line.rstrip('\n')
    if not s or s[0] in ' \t{}/*#':
        continue
    m = func_re.match(s)
    if m:
        fname = m.group(2).strip()
        if fname in skip:
            continue
        functions.append((i, fname))

print(f"Found {len(functions)} functions")

# Find body ranges
func_ranges = []
for idx, (line_i, fname) in enumerate(functions):
    # Find body end
    brace = 0
    opened = False
    end = line_i
    for j in range(line_i, min(line_i + 2000, total)):
        if '{' in lines[j]:
            opened = True
        if opened:
            brace += lines[j].count('{') - lines[j].count('}')
            if brace <= 0:
                end = j
                break
    func_ranges.append((line_i, fname, line_i, end))

print(f"Indexed {len(func_ranges)} function ranges")

# Process each function
improved_unknowns = 0
crossrefs_added = 0
secret3_tagged = 0
param_renames = 0

for line_i, fname, body_start, body_end in func_ranges:
    body_lines = [lines[j].rstrip('\n') for j in range(body_start, body_end + 1)]
    comment_line = line_i - 1

    # Skip if no comment line above
    if comment_line < 0:
        continue
    existing = lines[comment_line].rstrip('\n').strip()

    # === 1. Improve "Unknown function" with deeper heuristics ===
    if existing == '/* Unknown function */':
        better = improved_heuristic(body_lines, fname)
        if better:
            lines[comment_line] = f'/* {better} */\n'
            improved_unknowns += 1

    # === 2. Add Secret3 path tag ===
    if fname in SECRET3_PATH:
        cur = lines[comment_line].rstrip('\n')
        if '[SECRET3 PATH]' not in cur:
            # Insert tag at start of comment
            if cur.startswith('/*') and cur.endswith('*/') and '\n' not in cur:
                lines[comment_line] = cur[:-2].rstrip() + ' [SECRET3 PATH] */\n'
                secret3_tagged += 1
            elif cur.startswith('/*') and not cur.endswith('*/'):
                # Multi-line comment - add to first line
                lines[comment_line] = cur + ' [SECRET3 PATH]\n'
                secret3_tagged += 1

    # === 3. Add cross-references ===
    refs = build_crossref(body_lines)
    if refs and len(refs) <= 8:
        cur = lines[comment_line].rstrip('\n')
        if 'calls:' not in cur and 'Calls ' not in cur:
            ref_str = ", ".join(refs[:6])
            if cur.startswith('/*') and cur.endswith('*/') and len(cur) < 100:
                # Single-line comment - append calls
                lines[comment_line] = cur[:-2].rstrip() + f' | calls: {ref_str} */\n'
                crossrefs_added += 1
            elif cur == '/* Unknown function */' or (cur.startswith('/*') and cur.endswith('*/')):
                lines[comment_line] = cur[:-2].rstrip() + f' | calls: {ref_str} */\n'
                crossrefs_added += 1

print(f"Improved unknowns: {improved_unknowns}")
print(f"Secret3 tagged: {secret3_tagged}")
print(f"Cross-refs added: {crossrefs_added}")

# === 4. Annotate more DAT_/PTR_ globals (first 2 occurrences each) ===
dat_count = 0
for dat, comment in EXTRA_DATS.items():
    count = 0
    for i in range(total):
        if dat in lines[i]:
            rest = lines[i].split(dat)[-1]
            if '/*' not in rest and rest.strip() and not rest.strip().startswith('/*'):
                lines[i] = lines[i].rstrip('\n') + f'  /* {comment} */\n'
                dat_count += 1
                count += 1
                if count >= 2:
                    break

print(f"Extra DAT_ annotations: {dat_count}")

# === 5. Add parameter aliases as comments in critical function bodies ===
PARAM_ALIASES = {
    "FUN_101b3e10": {
        "param_1": "src_ptr",
        "param_2": "length",
        "param_3": "dst_ptr",
        "param_4": "key_lo",
        "param_5": "key_hi",
    },
    "FUN_100b3a60": {
        "param_1": "this (protocol_builder)",
        "param_2": "request_obj (240 bytes)",
        "param_3": "envelope_state",
        "param_4": "credential",
    },
    "FUN_101aa050": {
        "param_1": "code_ptr (hu_code)",
        "param_2": "secret_ptr (hu_secret, used for HMAC key)",
    },
    "FUN_10157d40": {
        "param_1": "data",
        "param_2": "data_len",
        "param_3": "result_out (uint32[4])",
        "param_4": "salt (0=standard MD5)",
    },
    "FUN_10158410": {
        "param_1": "this (credential_data_obj)",
        "param_2": "buffer_obj (+0x04=data_ptr, +0x08=data_size)",
    },
    "FUN_10154b40": {
        "param_1": "rsa_key_obj",
        "param_2": "mode (0=public/verify, 1=private/decrypt)",
        "param_3": "out_length_ptr",
        "param_4": "input_data",
        "param_5": "output_buffer",
    },
    "FUN_100ea130": {
        "param_1": "this (nnge_parser)",
        "param_2": "output_buffer",
        "param_3": "version_out",
    },
    "FUN_10044c60": {
        "param_1": "this (device_manager)",
        "param_2": "param_2",
        "param_3": "file_object",
    },
    "FUN_100b1670": {
        "param_1": "dest (0x9C-byte credential copy)",
        "param_2": "source (credential at session+0x84)",
    },
    "FUN_10094510": {
        "param_1": "this (0x54-byte device object)",
        "param_2": "name",
    },
    "FUN_1001fc00": {
        "param_1": "dest",
        "param_2": "source (credential object)",
    },
    "FUN_10091bf0": {
        "param_1": "output",
        "param_2": "data",
        "param_3": "request",
        "param_4": "format (0=binary, 1=text)",
    },
    "FUN_10056ad0": {
        "param_1": "this (growable buffer)",
        "param_2": "data",
        "param_3": "length",
    },
    "FUN_100be3c0": {
        "param_1": "this (credential_provider)",
        "param_2": "cred_sources",
        "param_3": "rsa_keys",
    },
}

# Insert parameter alias comments after the opening brace of each function
func_dict = {fname: line_i for line_i, fname, _, _ in func_ranges}
for fname, aliases in PARAM_ALIASES.items():
    if fname not in func_dict:
        continue
    start = func_dict[fname]
    # Find opening brace
    for j in range(start, min(start + 10, total)):
        if lines[j].strip() == '{':
            # Build alias comment
            parts = [f"{k} = {v}" for k, v in aliases.items()]
            alias_comment = "  /* Params: " + ", ".join(parts) + " */\n"
            # Check if already inserted
            if j + 1 < total and 'Params:' not in lines[j + 1]:
                lines.insert(j + 1, alias_comment)
                param_renames += 1
                # Shift everything
                total += 1
                for idx in range(len(func_ranges)):
                    li, fn, bs, be = func_ranges[idx]
                    if li > j:
                        func_ranges[idx] = (li + 1, fn, bs + 1, be + 1)
                    elif be > j:
                        func_ranges[idx] = (li, fn, bs, be + 1)
                for fn2 in list(func_dict.keys()):
                    if func_dict[fn2] > j:
                        func_dict[fn2] += 1
            break

print(f"Parameter aliases added: {param_renames}")

print(f"\nWriting {FILE}...")
with open(FILE, 'w') as f:
    f.writelines(lines)
print("Done!")
