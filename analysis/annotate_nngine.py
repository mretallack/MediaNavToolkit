#!/usr/bin/env python3
"""
Annotate nngine_decompiled.c.backup with comment headers for each function.
ONLY modifies .backup file. Never touches the original .c file.
"""
import re

INPUT = "/home/mark/git/MediaNavToolbox/analysis/nngine_decompiled.c.backup"
OUTPUT = INPUT

# ---- Known function mappings (from RE analysis) ----
KNOWN = {}
def k(name, desc):
    KNOWN[name] = desc

# Exported Nngine API
k("NngineStart", "Exported API: Initialize and start the Nngine engine")
k("NngineRestartWorkflow", "Exported API: Restart the current workflow")
k("NngineStop", "Exported API: Shut down the Nngine engine")
k("NngineSuspendTransfer", "Exported API: Suspend active data transfer")
k("NngineResumeTransfer", "Exported API: Resume suspended data transfer")
k("NngineConnectDevice", "Exported API: Connect to a device")
k("NngineDisconnectDevice", "Exported API: Disconnect from a device")
k("NngineIsRunning", "Exported API: Check if engine is running")
k("NngineAttachLogger", "Exported API: Attach a logging callback")
k("NngineAttachHmi", "Exported API: Attach HMI callback")
k("NngineFireEvent", "Exported API: Fire an event with parameters")
k("NngineAttachConfig", "Exported API: Attach configuration from file path")
# Core Serialization
k("FUN_10093010", "request_build: Builds request struct, looks up serializer, invokes, queues for HTTP")
k("FUN_101a9930", "serializer_invoke: Top-level serializer for ProtocolEnvelopeRO via vtable")
k("FUN_101b41b0", "serializer_lookup: Binary search through serializer registry")
k("FUN_101b45a0", "serializer_compare: Comparison for serializer registry binary search")
k("FUN_10204a50", "type_dispatch_switch: Master switch for igo-binary type encoding")
k("FUN_101a9da0", "field_iterator: Walks field descriptor linked list")
k("FUN_101a8e80", "compound_serializer: Iterates fields, writes presence bits + values to bitstream")
k("FUN_101a8bf0", "validate: Pre-serialization validation (vtable[7])")
k("FUN_101a92a0", "get_serializer: Returns self (vtable[1])")
k("FUN_101a2bd0", "pipeline_node_write: Writes fields for each pipeline node")
# igo-binary Encoders
k("FUN_1021d570", "enc_byte: Writes single type byte tag")
k("FUN_1021d590", "enc_int32: Writes [0x01][value:LE32]")
k("FUN_1021d5e0", "enc_int32_pair: Writes [0x03][val1:LE32][val2:LE32]")
k("FUN_1021d660", "enc_string: Writes [0x05][data][0x00] null-terminated")
k("FUN_1021d770", "enc_int64: Writes [0x04][value:LE64]")
k("FUN_1021ee00", "enc_container_header: Writes [type:1][count:LE32]")
k("FUN_1021eee0", "enc_container_footer: Writes [type:1][count:LE32]")
# Bitstream
k("FUN_101a9e80", "write_1bit_lsb: Writes bits LSB-first (presence bits)")
k("FUN_101a9a80", "bitmap_writer: Writes bitmap MSB-first")
k("FUN_101a9ae0", "bit_reader: Reads bits from input (deserializer)")
k("FUN_101a8150", "write_nbits_msb: Writes N bits MSB-first (field values)")
k("FUN_101a8310", "write_nbits_lsb: Writes N bits LSB-first (field values)")
k("FUN_101a5730", "int_serializer: Writes integer in N bits")
k("FUN_101a1f80", "string_serializer: Writes string 4 bits per element")
k("FUN_101a6b90", "unknown_type_serializer: Referenced in type system")
k("FUN_101a2030", "identity_converter: Pass-through value converter")
k("FUN_101a8820", "ensure_capacity: Ensures output buffer space")
k("FUN_101a67f0", "serialize_write: Type-specific serialize dispatch")
k("FUN_101a6900", "type_destructor: Destructor for type object")
k("FUN_101a6890", "type_get_descriptor: Returns descriptor pointer")
# SnakeOil
k("FUN_101b3e10", "SnakeOil: XOR stream cipher, 64-bit LFSR PRNG. (src, len, dst, key_lo, key_hi)")
# Protocol Envelope
k("FUN_100b3a60", "protocol_envelope_builder: Builds envelope, serializes, encrypts with SnakeOil")
k("FUN_100b1670", "credential_copier: Copies Name/Code/Secret to credential object")
k("FUN_100b10c0", "credential_source: Reads credential from device descriptor +0x84")
k("FUN_100935c0", "envelope_data_copy: Copies envelope data to output")
k("FUN_10091bf0", "envelope_writer: Serializes QUERY or BODY section")
k("FUN_10091410", "request_send: Sends queued HTTP request")
k("FUN_10091100", "connection_register: Registers HTTP connection")
k("FUN_10090f80", "session_init: Initializes session object")
k("FUN_100921d0", "protocol_build_helper")
k("FUN_10091da0", "protocol_build_helper2")
# XML/Binary Serializer
k("FUN_101b30f0", "xml_text_serializer: Produces XML for http_dump log")
k("FUN_101b2c30", "binary_serializer_entry: Produces D8..D9 credential block")
k("FUN_101b2a60", "write_field_open_tag")
k("FUN_101b2af0", "write_field_close_tag")
k("FUN_101b3cb0", "value_writer_dispatch: Dispatches to type-specific writer")
k("FUN_101b2910", "set_binary_serializer_vtable")
k("FUN_101b2570", "binary_serializer_destructor")
k("FUN_10092e20", "timestamp_writer: Divides by 1000, formats .%04d")
k("FUN_10092f60", "int_writer: sprintf \"%d\"")
k("FUN_10092fd0", "bool_writer: \"true\"/\"false\"")
k("FUN_10092ee0", "uint64_pair_writer: \"%I64u\" x2")
k("FUN_10092fb0", "uint64_writer: \"%I64u\"")
k("FUN_10092f90", "int64_writer: \"%I64d\"")
k("FUN_10092d60", "string_writer")
k("FUN_10092f40", "int_writer2")
k("FUN_10092f20", "int_writer3")
k("FUN_101b3d70", "binary_serializer_vtable_0x08")
k("FUN_101b3b50", "binary_serializer_vtable_0x2c")
k("FUN_101b2d00", "binary_serializer_vtable_0x30")
k("FUN_101b3af0", "binary_serializer_vtable_0x34")
k("FUN_101b3bc0", "binary_serializer_vtable_0x3c")
k("FUN_101b3d20", "binary_serializer_vtable_0x40")
k("FUN_101b3c70", "binary_serializer_vtable_0x44")
# Buffer/Memory
k("FUN_10056ad0", "buf_write: Write N bytes to growable buffer")
k("FUN_10056a10", "buf_init: Initialize growable buffer")
k("FUN_1027e4f5", "malloc_wrapper")
k("FUN_1027fa10", "memcpy_wrapper")
# String
k("FUN_101baa50", "string_addref: Increment NNG string refcount")
k("FUN_101b8130", "string_release: Decrement NNG string refcount / free")
k("FUN_101bad80", "string_set: Set NNG string value")
k("FUN_101b81b0", "string_copy: Copy NNG string")
k("FUN_101bd970", "string_get: Get NNG string data pointer")
k("FUN_101babb0", "string_op: NNG string operation")
k("FUN_101bdf30", "string_bool: Returns boolean from string")
k("FUN_101bd8d0", "value_getter: Returns transformed field value during serialization")
k("FUN_101bae20", "log_section: Logging section marker")
k("FUN_101b74e0", "sprintf_log: Logging/formatting")
k("FUN_101b8170", "log_end: Logging end marker")
k("FUN_101b87c0", "string_util")
# Market API
k("FUN_100ba130", "login_arg_factory: Builds LOGIN arg struct")
k("FUN_100b4a30", "body_object_constructor")
k("FUN_100b4ad0", "body_object_cleanup")
k("FUN_100b4600", "debug_dump")
k("FUN_100b4250", "body_object_destructor")
k("FUN_100b3100", "session_bind: Binds HTTP connection to session")
# NNGE/Device
k("FUN_100ea130", "nnge_parser: Reads .nng device file, extracts NNGE block")
k("FUN_100ea610", "nnge_block_store: Stores 20-byte NNGE block")
k("FUN_100ea670", "credential_provider_find")
k("FUN_100eab30", "nnge_lb_process: Processes _lb_ string, Base32-decodes keys")
k("FUN_100ea6f0", "nnge_string_set")
k("FUN_100fc170", "buffer_insert")
k("FUN_100fc970", "buffer_copy")
k("FUN_101ec050", "read_uint32: Reads uint32 from buffer")
k("FUN_100ea960", "lyc_provider_reader: Reads .lyc, decrypts, validates magic 0x36c8b267")
# Crypto
k("FUN_10154690", "rsa_init: Initializes RSA context with exponent/modulus")
k("FUN_10101120", "rsa_key1_init: RSA Key1 (2048-bit, e=65537)")
k("FUN_10157d40", "md5_hash: Computes MD5. void(data, len, result[4], param4)")
k("FUN_10158410", "xor_cbc_decrypt: XOR-CBC for .lyc files, validates magic 0x36c8b267")
k("FUN_101585b0", "credential_vtable4: Returns output size")
# HTTP
k("FUN_10147c00", "http_connection_create: Creates 216-byte HTTP connection object")
k("FUN_10166560", "config_read: Reads config value")
# Misc
k("FUN_100a73d0", "struct_copy: Copies large structure to query_this+0x7c")
k("FUN_101d2630", "timestamp_get: Gets current timestamp")
k("FUN_10021060", "array_init: Initializes array (begin, end, capacity)")
k("FUN_100312a0", "protocol_utility")
k("FUN_100940c0", "request_struct_destructor")
k("FUN_101b3f20", "version_process: Processes version info from descriptor")
# zlib
k("putShortMSB", "zlib: Write 16-bit value MSB-first to pending output")
k("bi_flush", "zlib: Flush the bit buffer")
k("bi_windup", "zlib: Write out remaining bits")
k("pqdownheap", "zlib: Restore heap property for Huffman tree")
k("__tr_init", "zlib: Initialize tree structures for deflate")
k("__tr_tally", "zlib: Tally literal/length or distance for deflate")
k("__tr_align", "zlib: Align output to byte boundary for deflate")
# CRT
k("guard_check_icall", "CRT: Control Flow Guard check for indirect calls")
k("_sprintf_s", "CRT: Safe sprintf with buffer size check")
k("_fprintf", "CRT: fprintf formatted output to FILE")
k("__break", "CRT: Debug break / trap instruction")
k("Insert_node", "Data structure: Insert node into tree/map")
k("mtx_do_lock", "CRT: Internal mutex lock")
k("__Mtx_destroy_in_situ", "CRT: Destroy mutex in-place")
k("__Mtx_init_in_situ", "CRT: Initialize mutex in-place")
k("__Mtx_lock", "CRT: Lock mutex")
k("__Mtx_unlock", "CRT: Unlock mutex")
k("xtime_diff", "CRT: Compute time difference")
k("__Xtime_diff_to_millis2", "CRT: Convert xtime diff to milliseconds")
k("__Xtime_get_ticks", "CRT: Get current time in ticks")
k("xtime_get", "CRT: Get current time as xtime")
k("__Thrd_sleep", "CRT: Sleep current thread")
k("__Cnd_signal", "CRT: Signal condition variable")
k("__Deletegloballocale", "CRT: Delete global locale")
k("tidy_global", "CRT: Clean up global locale state")
k("__Getctype", "CRT: Get ctype classification vector")
k("__Tolower", "CRT: Convert char to lowercase")
k("__Getcvt", "CRT: Get conversion vector")
k("__Toupper", "CRT: Convert char to uppercase")
k("___crtGetSystemTimePreciseAsFileTime", "CRT: Get precise system time")
k("___crtTryAcquireSRWLockExclusive", "CRT: Try acquire SRW lock")
k("__Mtxlock", "CRT: Lock recursive mutex")
# Win32 stubs
k("CreateToolhelp32Snapshot", "Win32: Create snapshot of processes/threads/modules")
k("Process32FirstW", "Win32: Get first process from snapshot")
k("Process32NextW", "Win32: Get next process from snapshot")
k("Thread32First", "Win32: Get first thread from snapshot")
k("Thread32Next", "Win32: Get next thread from snapshot")
k("Module32FirstW", "Win32: Get first module from snapshot")
k("Module32NextW", "Win32: Get next module from snapshot")
# CRefTime
k("CRefTime::Millisecs", "DirectShow: Convert CRefTime to milliseconds")
k("__crt_strtox::parse_digit", "CRT: Parse digit char for string-to-number")

# ---- Heuristic analysis ----
def analyze_body(lines):
    body = "\n".join(lines)
    n = len(lines)
    clues = []

    # Extract ALL string literals
    strings = re.findall(r'"([^"]{2,})"', body)

    # If function has meaningful string literals, use them
    if strings:
        # Filter out format strings and single chars
        meaningful = [s for s in strings if len(s) > 2 and s not in ("%d", "%s", "%u", "%x", "%p", "\\n", "\\0")]
        if meaningful:
            best = max(meaningful, key=len)[:60]
            clues.append(f'References: "{best}"')

    # Component registration pattern (very common in this DLL)
    if re.search(r'FUN_101bdac0.*FUN_101bdc10', body, re.DOTALL):
        comp = strings[0] if strings else "unknown"
        return f'Component registration: "{comp}"'

    # Known internal calls
    call_map = [
        (r'FUN_101b3e10', "Calls SnakeOil encryption"),
        (r'FUN_10157d40', "Calls MD5 hash"),
        (r'FUN_10158410', "Calls XOR-CBC decrypt"),
        (r'FUN_10154690', "Calls RSA init"),
        (r'FUN_101a9930', "Calls serializer_invoke"),
        (r'FUN_101a8e80', "Calls compound_serializer"),
        (r'FUN_10093010', "Calls request_build"),
        (r'FUN_100b3a60', "Calls protocol_envelope_builder"),
        (r'FUN_10091bf0', "Calls envelope_writer"),
        (r'FUN_10056ad0', "Calls buf_write"),
        (r'FUN_100ba130', "Calls login_arg_factory"),
        (r'FUN_100ea130', "Calls nnge_parser"),
        (r'FUN_10147c00', "Calls http_connection_create"),
        (r'FUN_10166560', "Calls config_read"),
    ]
    for pat, desc in call_map:
        if re.search(pat, body):
            clues.append(desc)
            break

    # Win32 API calls
    win32 = [
        (r'CreateFile[AW]', "Win32 file I/O"),
        (r'ReadFile|WriteFile', "Win32 file read/write"),
        (r'CreateThread', "Creates thread"),
        (r'WaitForSingleObject|WaitForMultipleObjects', "Thread synchronization"),
        (r'EnterCriticalSection|LeaveCriticalSection', "Critical section locking"),
        (r'InternetOpen|HttpOpenRequest|HttpSendRequest', "WinINet HTTP"),
        (r'WSAStartup|socket\b|connect\b|send\b|recv\b', "Winsock networking"),
        (r'RegOpenKeyEx|RegQueryValueEx|RegSetValueEx', "Windows Registry"),
        (r'LoadLibrary|GetProcAddress', "Dynamic library loading"),
        (r'CryptAcquireContext|CryptCreateHash|CryptHashData', "Windows CryptoAPI"),
        (r'FindFirstFile|FindNextFile', "Directory enumeration"),
        (r'CreateEvent|SetEvent|ResetEvent', "Win32 events"),
        (r'InitializeCriticalSection', "Critical section init"),
        (r'MultiByteToWideChar|WideCharToMultiByte', "Char encoding conversion"),
        (r'GetModuleFileName|GetModuleHandle', "Module query"),
        (r'VirtualAlloc|VirtualFree|VirtualProtect', "Virtual memory"),
        (r'HeapAlloc|HeapFree', "Heap memory"),
        (r'GetLastError', "Checks Win32 error"),
        (r'CloseHandle', "Closes Win32 handle"),
        (r'DeleteFile[AW]|RemoveDirectory|MoveFile', "File system operations"),
        (r'GetFileAttributes|SetFileAttributes', "File attributes"),
        (r'CreateDirectory[AW]', "Creates directory"),
        (r'GetTempPath|GetTempFileName', "Temp file operations"),
        (r'DeviceIoControl', "Device I/O control"),
        (r'SetupDi\w+', "Device setup/enumeration"),
    ]
    for pat, desc in win32:
        if re.search(pat, body):
            clues.append(desc)
            break

    # Structural patterns
    if re.search(r'__Mtx_init_in_situ.*_atexit', body, re.DOTALL) and n < 12:
        return "C++ static initialization: mutex init with atexit cleanup"
    if re.search(r'_atexit', body) and n < 8:
        clues.append("Static initialization with atexit")

    if re.search(r'_CxxThrowException', body):
        clues.append("Throws C++ exception")

    # Constructor pattern: sets vtable + initializes fields
    vtable_sets = re.findall(r'=\s*&?PTR_FUN_\w+', body)
    if vtable_sets and n < 20:
        if re.search(r'operator_delete|_free\b|FUN_1027dfe8', body):
            return "Destructor: resets vtable and frees resources"
        return "Constructor/initializer: sets up vtable"

    # Destructor pattern
    if re.search(r'operator_delete|FUN_1027dfe8', body) and n < 15:
        clues.append("Frees memory (likely destructor)")

    # Simple patterns for small functions
    if n <= 3:
        if re.search(r'return\s*;', body):
            return "Empty/stub function"
    if n <= 5:
        if re.search(r'return\s+\*?\(?\s*this', body):
            return "Getter: returns member field"
        if re.search(r'return\s+0x[0-9a-f]+\s*;|return\s+\d+\s*;', body) and not strings:
            return "Returns constant value"
        if re.search(r'\*\(.*this.*\)\s*=\s*\w', body):
            return "Setter: stores value to member field"

    # Comparison/sorting
    if n < 20 and re.search(r'<|>|<=|>=', body) and re.search(r'return.*[<>]|return.*-\s*\*', body):
        clues.append("Comparison function")

    # Loop with array access
    if re.search(r'while\s*\(|for\s*\(', body) and n > 20:
        if re.search(r'\[\w+\s*\+', body) or re.search(r'\*\(\w+\s*\+', body):
            if re.search(r'memcpy|memmove|FUN_1027fa10', body):
                clues.append("Data copy/transform loop")

    # Binary search pattern
    if re.search(r'>>.*1|/\s*2', body) and re.search(r'while|do\s*{', body) and n < 40:
        clues.append("Binary search or bisection")

    # Switch statement (type dispatch)
    case_count = body.count('case ')
    if case_count > 3:
        clues.append(f"Switch dispatch ({case_count} cases)")

    # Virtual method dispatch (very common in decompiled C++)
    if re.search(r'\(\*\*\(code\s*\*\*\)', body) and n < 10:
        clues.append("Virtual method dispatch (vtable call)")

    # Offset accessor (return this + N)
    m2 = re.search(r'return\s+param_1\s*\+\s*(0x[0-9a-f]+|\d+)', body)
    if m2 and n <= 5:
        return f"Offset accessor: returns this+{m2.group(1)}"

    # Wrapper/forwarder (calls one function and returns)
    if n <= 8:
        fwd = re.findall(r'(FUN_[0-9a-f]+)\(', body)
        if len(fwd) == 1 and re.search(r'return\s+FUN_|FUN_\w+\(.*\);\s*\n\s*return', body):
            clues.append(f"Wrapper/forwarder for {fwd[0]}")

    # QueryPerformance = timing
    if re.search(r'QueryPerformance', body):
        clues.append("High-resolution timing (QueryPerformanceCounter)")

    # Thunk/trampoline (tiny function that just jumps)
    if n <= 4 and re.search(r'\(\*\*\(code\s*\*\*\)', body):
        return "Thunk: virtual method dispatch"

    # Iterator/walker pattern
    if re.search(r'while.*!=.*\)', body) and re.search(r'\+\s*1\b|\+\+', body) and n < 25:
        clues.append("Iterator/list walker")

    # Array/vector push_back pattern
    if re.search(r'param_1\[\d+\]\s*!=\s*param_1\[\d+\]', body) or \
       re.search(r'\(param_1\s*\+\s*\d+\)\s*!=.*\(param_1\s*\+\s*\d+\)', body):
        if re.search(r'realloc|FUN_102839f9|operator_new', body):
            clues.append("Container growth/reallocation")
        else:
            clues.append("Container operation (vector/array)")

    # Ref counting
    if re.search(r'\+\s*1\s*;.*return|InterlockedIncrement|InterlockedDecrement', body) and n < 10:
        clues.append("Reference counting (addref/release)")

    # Error/exception path
    if re.search(r'GetLastError|ERROR|INVALID_HANDLE', body):
        clues.append("Error handling path")

    # Linked list operations (prev/next pointer manipulation)
    if re.search(r'param_\d+\s*\+\s*0xc\).*param_\d+\s*\+\s*0x10\)', body) or \
       re.search(r'\+\s*0x10\)\s*=.*\+\s*0xc\)', body):
        clues.append("Linked list operation (insert/remove)")

    # Tree/map operations (left/right child, red-black tree)
    if re.search(r'_Tree_|_Rb_tree|_Map_|_Set_', body):
        clues.append("STL tree/map/set operation")

    # Memory deallocation pattern
    if re.search(r'FUN_1027dfe8', body):
        clues.append("Frees memory (operator delete)")

    # Memory allocation pattern
    if re.search(r'FUN_102839f9|FUN_1027e4f5', body):
        clues.append("Allocates memory")

    # Null check + vtable call (common dispatch pattern)
    if n <= 8 and re.search(r'if\s*\(.*!=.*0x0\)', body) and re.search(r'\(\*\*\(code', body):
        return "Guarded virtual method call"

    # Field zeroing / reset
    if n <= 8 and body.count('= 0;') >= 2 and not re.search(r'FUN_', body):
        return "Field reset/clear"

    # CRT internal patterns
    if re.search(r'__acrt_|__crt_|_Locale_|_Locimp', body):
        clues.append("CRT locale/runtime internal")

    # Decrement + conditional free (release pattern)
    if re.search(r'param_\d+\[2\]\s*=\s*param_\d+\[2\]\s*\+\s*-1', body) or \
       re.search(r'-\s*1\s*;.*==\s*0.*free|delete', body, re.DOTALL):
        clues.append("Reference count release")

    if not clues:
        return None
    return "; ".join(clues[:3])


def classify_named(fname):
    """Classify non-FUN_ named functions."""
    if "scalar_deleting_destructor" in fname:
        cls = fname.split("::")[0] if "::" in fname else "unknown"
        return f"C++ scalar deleting destructor for {cls}"
    if fname.startswith("std::"):
        return f"C++ Standard Library: {fname}"
    if "MemMapBase" in fname:
        return f"Memory-mapped file base class: {fname}"
    if "MemMapReadOnly" in fname:
        return f"Read-only memory-mapped file: {fname}"
    if "CDebugS" in fname:
        return f"Debug section reader (PDB): {fname}"
    if fname.startswith("Concurrency::"):
        return f"MSVC Concurrency Runtime: {fname}"
    if "~" in fname:
        return f"C++ destructor: {fname}"
    if fname.startswith("_Init_atexit") or fname.startswith("~_Init_atexit"):
        return "CRT: atexit initialization/cleanup"
    if fname.startswith("___") or fname.startswith("__"):
        return f"CRT internal: {fname}"
    if fname.startswith("_") and len(fname) > 2:
        return f"CRT/internal: {fname}"
    if "environment" in fname.lower():
        return f"CRT environment: {fname}"
    if "initialize" in fname.lower() or "uninitialize" in fname.lower():
        return f"Initialization: {fname}"
    if "free_" in fname.lower() or "alloc" in fname.lower():
        return f"Memory management: {fname}"
    if "construct" in fname.lower() or "destroy" in fname.lower():
        return f"Object lifecycle: {fname}"
    if "locale" in fname.lower() or "Loc" in fname:
        return f"Locale handling: {fname}"
    if "crt" in fname.lower() or "acrt" in fname.lower():
        return f"CRT internal: {fname}"
    if "seh" in fname.lower() or "SEH" in fname:
        return f"Structured exception handling: {fname}"
    if "guard" in fname.lower():
        return f"Security guard: {fname}"
    return None


def main():
    print(f"Reading {INPUT}...")
    with open(INPUT, "r") as f:
        lines = f.readlines()

    total = len(lines)
    print(f"Total lines: {total}")

    # Match function definitions at start of line
    func_re = re.compile(
        r'^([A-Za-z_]\S*(?:\s+\S+)*?)\s+'
        r'(?:__\w+\s+)?'
        r'([A-Za-z_~][\w:~<>,\s]*?)'
        r'\s*\('
    )
    skip_names = {'if','while','for','switch','return','else','do','case','goto','sizeof','typeof'}

    output = []
    i = 0
    stats = {"known": 0, "named": 0, "heuristic": 0, "unknown": 0}

    while i < total:
        line = lines[i]
        s = line.rstrip('\n')

        if not s or s[0] in ' \t{}/*#':
            output.append(line)
            i += 1
            continue

        m = func_re.match(s)
        if not m:
            output.append(line)
            i += 1
            continue

        fname = m.group(2).strip()
        if not fname or fname in skip_names:
            output.append(line)
            i += 1
            continue

        # Collect body
        body = []
        j = i + 1
        brace = 0
        opened = False
        while j < total:
            bl = lines[j].rstrip('\n')
            bc = bl.count('{') - bl.count('}')
            if '{' in bl:
                opened = True
            brace += bc
            if opened:
                body.append(bl)
            if opened and brace <= 0:
                break
            j += 1

        # Classify
        comment = None
        if fname in KNOWN:
            comment = KNOWN[fname]
            stats["known"] += 1
        else:
            comment = classify_named(fname)
            if comment:
                stats["named"] += 1
            else:
                comment = analyze_body(body)
                if comment:
                    stats["heuristic"] += 1
                else:
                    comment = "Unknown function"
                    stats["unknown"] += 1

        output.append(f"/* {comment} */\n")
        output.append(line)
        i += 1

    t = sum(stats.values())
    print(f"Known: {stats['known']}, Named: {stats['named']}, "
          f"Heuristic: {stats['heuristic']}, Unknown: {stats['unknown']}, Total: {t}")

    print(f"Writing {OUTPUT}...")
    with open(OUTPUT, "w") as f:
        f.writelines(output)
    print("Done!")

if __name__ == "__main__":
    main()
