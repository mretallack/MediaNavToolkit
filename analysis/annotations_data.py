# annotations_data.py - Rich annotation data for nngine_decompiled.c.backup
# Part of Phase 2 annotation for MediaNavToolbox reverse engineering

# ============================================================
# SECTION BANNERS - inserted before key function groups
# ============================================================
SECTION_BANNERS = {
    "FUN_101b3e10": """/* ================================================================
 * SECTION: SnakeOil Encryption (XOR Stream Cipher)
 * RVA: 0x1B3E10
 * 
 * Custom stream cipher using 64-bit xorshift PRNG to generate
 * keystream. Used to encrypt both query and body sections of
 * the igo-binary wire protocol.
 *
 * Key: 64-bit split as (key_lo:uint32, key_hi:uint32)
 * Known keys:
 *   tb_code   = 0x000D4EA6_5D36B98E (query encryption)
 *   tb_secret = 0x000ACAB6_C9FB66F8 (body encryption, pre-delegation)
 *   Secret3   = UNKNOWN (body encryption, post-delegation)
 * ================================================================ */""",

    "FUN_100b3a60": """/* ================================================================
 * SECTION: Protocol Envelope Builder
 * RVA: 0x0B3A60
 *
 * Builds the complete wire protocol envelope:
 *   1. Gets credential from provider (vtable[6] at this+0x1C)
 *   2. Serializes envelope header via igo-binary serializer
 *   3. Serializes QUERY (credential block) and BODY (request args)
 *   4. Encrypts both with SnakeOil using credential's Secret
 *
 * Wire format: [header][encrypted_query][encrypted_body]
 *
 * Key state object (param_3 / piVar11):
 *   [0x01] = body data ptr    [0x03] = body length
 *   [0x06] = envelope start   [0x0B] = query data ptr
 *   [0x0D] = query length     [0x10] = SnakeOil key ptr (8 bytes)
 *
 * Credential object (local_c / iVar3):
 *   +0x10 = Code_lo (uint32)  +0x14 = Code_hi (uint32)
 *   +0x1C = Secret_lo (uint32) +0x20 = Secret_hi (uint32)
 *
 * Debug log: "name: %s\\ncode: %lld\\nsecret: %lld"
 * ================================================================ */""",

    "NngineStart": """/* ================================================================
 * SECTION: Nngine Exported API
 *
 * Public DLL exports for the Nngine engine lifecycle.
 * Called by DaciaMediaNavEvolutionToolbox.exe via LoadLibrary.
 *
 * Exports (from PE export table):
 *   NngineStart           - Initialize engine
 *   NngineStop            - Shut down engine
 *   NngineIsRunning       - Check engine state
 *   NngineAttachConfig    - Load configuration
 *   NngineAttachLogger    - Set log callback
 *   NngineAttachHmi       - Set HMI callback
 *   NngineFireEvent       - Dispatch event
 *   NngineConnectDevice   - Connect USB device
 *   NngineDisconnectDevice - Disconnect device
 *   NngineSuspendTransfer - Pause transfer
 *   NngineResumeTransfer  - Resume transfer
 *   NngineRestartWorkflow - Restart workflow
 * ================================================================ */""",

    "FUN_101a9930": """/* ================================================================
 * SECTION: igo-binary Serialization Engine
 *
 * Data-driven serializer for the igo-binary wire protocol.
 * Each request type (LOGIN, BOOT, etc.) has a static serializer
 * object with a pipeline of field descriptors.
 *
 * Architecture:
 *   serializer_invoke -> get_descriptor -> prepare -> compound_serialize
 *     -> field_iterator -> write_1bit_lsb (presence) + write_nbits (values)
 *
 * Bitstream format:
 *   - Presence bits: LSB-first, one bit per field
 *   - Value data: N bits per element (4 for strings, 8+ for ints)
 *   - Everything interleaved in a single bitstream buffer
 *
 * Global serializer registry at DAT_10314964 (singleton)
 * ================================================================ */""",

    "FUN_10157d40": """/* ================================================================
 * SECTION: Cryptography (MD5, RSA, XOR-CBC)
 *
 * MD5:     FUN_10157d40 - Standard MD5 with optional param4 salt
 * RSA:     FUN_10154b40 - PKCS#1 v1.5 (2048-bit, e=65537)
 * XOR-CBC: FUN_10158410 - Block cipher for .lyc credential files
 * HMAC:    FUN_101aa3a0 - Standard HMAC-MD5 (ipad=0x36, opad=0x5C)
 *
 * RSA keys embedded in DLL:
 *   Key1: RVA 0x30B588 (modulus), 0x30B580 (exponent)
 *   Key2: RVA 0x30B2D8 (protected_zip)
 *   Key3: RVA 0x30B8F8
 *
 * .lyc decryption chain:
 *   FUN_10158610 (chunk decrypt) -> FUN_10158710 (RSA validate)
 *   -> FUN_10154b40 (PKCS#1) -> FUN_10154860 (modexp)
 *   -> 40-byte payload: [magic 0x36c8b267][XOR-CBC key][data]
 * ================================================================ */""",

    "FUN_100ea130": """/* ================================================================
 * SECTION: NNGE Engine / Device File Parsing
 *
 * Reads .nng device files and .lyc license files.
 * NNGE block format: 20 bytes starting with "NNGE" magic.
 *
 * device.nng structure (268 bytes):
 *   0x00-0x3F: XOR-encoded header (xor_table_normal.bin)
 *   0x40-0x4F: Brand MD5 (XOR-encoded)
 *   0x50-0x53: "NNGE" marker
 *   0x54-0x57: Version (19 06 07 20)
 *   0x58-0x5B: Field1 (0x65FAB84A)
 *   0x5C-0x5F: APPCID (0x42000B53)
 *   0x60-0x63: Field3 (0xC44D75AC)
 *   0x64-0x10B: Remaining data
 *
 * NNGE key: "m0$7j0n4(0n73n71I)" at RVA 0x2C11E4
 * Template: "ZXXXXXXXXXXXXXXXXXXZ" at RVA 0x2C11F8
 *
 * CRITICAL: The NNGE parser FAILS for device.nng because
 * it seeks to end-24 (offset 244) which does NOT contain "NNGE".
 * The NNGE block at offset 0x50 is never read by this parser.
 * ================================================================ */""",

    "FUN_101aa050": """/* ================================================================
 * SECTION: Credential Construction (Delegation)
 *
 * Creates the post-delegation credential object (0x58 bytes).
 * Called after the delegator response provides hu_code/hu_secret.
 *
 * Credential object layout (0x58 bytes):
 *   +0x00: vtable PTR_FUN_102b9590
 *   +0x08: vtable PTR_FUN_102b9580
 *   +0x10: type = 1
 *   +0x14: flag = 1
 *   +0x18: Code_lo (from param_1 = hu_code)
 *   +0x1C: Code_hi
 *   +0x20: flag = 1
 *   +0x24: *(device_mgr+0x10) -> SECRET3_LO ???
 *   +0x28: *(device_mgr+0x14) -> SECRET3_HI ???
 *   +0x2C: *(device_mgr+0x18)
 *   +0x30: timestamp_lo
 *   +0x34: timestamp_hi
 *   +0x38: vtable PTR_FUN_102b9588
 *   +0x40: mode = 3
 *   +0x48: Name ptr (HMAC-MD5 output, 16 bytes)
 *   +0x4C: Name length
 *   +0x50: Name capacity
 *
 * HMAC-MD5 for credential name:
 *   key  = hu_secret (8 bytes, big-endian byte order)
 *   data = serialized via FUN_101a9930 (igo-binary format)
 *   output = 16-byte credential name
 *   Known result: ad35bcc12654b893f7b5596a8057190c
 *
 * Secret3 source: device manager singleton at DAT_1031445c
 *   Chain: FUN_10011dd0 -> vtable[6] -> FUN_100a4bb0
 *   -> *(*(device_obj+0x3C)+0x1C)+0x10 = Code field
 *   Unicorn emulation returns tb_code, but this does NOT
 *   decrypt 0x68 bodies. The real value is still UNKNOWN.
 * ================================================================ */""",

    "FUN_100be3c0": """/* ================================================================
 * SECTION: Credential Provider / License Management
 *
 * Manages credentials from three sources:
 *   1. .lyc files -> RSA decrypt -> map license credentials
 *   2. reg.sav / service_register_v1.sav -> hu/tb credentials
 *   3. device.nng -> device credential (Secret3) [UNSOLVED]
 *
 * Provider vtable: PTR_FUN_102bbbf4
 *   [0] destructor    [4] get_APPCID
 *   [1] unknown       [5] find_by_APPCID
 *   [2] get_cred_list [6] get_cred_data
 *   [3] get_cred_tree [7] get_cred_name
 * ================================================================ */""",

    "FUN_10044c60": """/* ================================================================
 * SECTION: Device Manager / device.nng Reader
 *
 * Reads device.nng from USB drive via file system manager.
 * The vtable[27] call at *(*(this+8)+0x6c) is a PATH BUILDER,
 * NOT the credential derivation (confirmed by tracing).
 *
 * Path resolution: "license/device.nng" -> full USB path
 * File search: vtable[11] on file object
 *
 * Device object (0x54 bytes, FUN_10094510):
 *   +0x00: vtable PTR_FUN_102b9688
 *   +0x1C-0x44: credential fields (init to 0)
 *   +0x3C: inner object ptr (set during registration)
 *   +0x40: tree for sub-objects
 *   +0x4C: tree for sub-objects
 * ================================================================ */""",
}

# ============================================================
# RICH HEADERS - replace single-line comments before functions
# ============================================================
RICH_HEADERS = {
    "FUN_101b3e10": """/* SnakeOil — XOR stream cipher using xorshift128 PRNG
 *
 * void __cdecl SnakeOil(uint8_t *src, int len, uint8_t *dst,
 *                        uint32_t key_lo, uint32_t key_hi)
 *
 * PRNG step (per byte):
 *   hi = (hi << 21 | lo >> 11) ^ hi
 *   lo = (lo << 21) ^ lo ^ (hi >> 3)
 *   hi = (hi << 4 | lo >> 28) ^ hi
 *   lo = (lo << 4) ^ lo
 *   keystream_byte = (lo >> 23) & 0xFF
 *   dst[i] = src[i] ^ keystream_byte
 *
 * Pure computation — no external dependencies.
 * Validated in Unicorn: snakeoil(zeros, tb_secret) = bc755fbc32341970
 */""",

    "FUN_100b3a60": """/* protocol_envelope_builder — Builds complete wire protocol envelope
 *
 * undefined4 __thiscall (int this, int *request_obj, int *envelope_state, int credential)
 *
 * param_1 (this)     : Protocol builder context
 *   +0x1C: credential provider ptr (vtable[6] returns credential)
 *   +0x18: session manager ptr
 *   +0x24: service name string
 *   +0x68: serializer lookup key
 *   +0x7C: serializer context
 *   +0x80: config flags object
 *
 * param_2 (piVar8)   : Request object (240 bytes)
 *   [0x0F]: mode (2=RANDOM, 3=DEVICE)
 *   [0x10]: flags (bit 6 = has credential block)
 *   [0x12]: has name flag
 *   [0x15]: credential sub-object start
 *   [0x2C]: output buffer start
 *   [0x39]: request counter lo (from DAT_10314a60)
 *   [0x3A]: request counter hi (from DAT_10314a64)
 *
 * param_3 (piVar11)  : Envelope state
 *   [0x01]: body data ptr     [0x03]: body length
 *   [0x06]: envelope header   [0x0B]: query data ptr
 *   [0x0D]: query length      [0x10]: SnakeOil key ptr (8 bytes)
 *
 * local_c (iVar3)    : Credential object (from provider vtable[6])
 *   +0x10: Code_lo    +0x14: Code_hi    (stored in wire header)
 *   +0x1C: Secret_lo  +0x20: Secret_hi  (SnakeOil key for BOTH query and body)
 *
 * Key derivation:
 *   if credential==NULL or mode==RANDOM:
 *     key = xorshift(time64())          // random per-request key
 *   else (DEVICE mode):
 *     key = Secret from credential      // persistent device key
 *
 * CRITICAL: Both SnakeOil calls use the SAME key from envelope[0x10].
 * Wire traffic shows query decrypts with tb_code and body with different key.
 * This contradiction is UNRESOLVED — see spec for details.
 */""",

    "NngineStart": """/* NngineStart — Initialize and start the Nngine engine
 * Export ordinal: 10 (0xf600)
 *
 * void NngineStart(undefined4 config_handle)
 *
 * Creates engine singleton at DAT_103143d0 via FUN_1000ee00.
 * Checks if engine is already running via FUN_10118d80/FUN_10118d40.
 */""",

    "NngineStop": """/* NngineStop — Shut down the Nngine engine
 * Export ordinal: 11 (0xf6f0)
 *
 * Waits for engine to finish (busy-wait with sleep).
 * Uses QueryPerformanceCounter for precise timing.
 */""",

    "NngineIsRunning": """/* NngineIsRunning — Check if engine is currently running
 * Export ordinal: 7 (0xfb10)
 * Returns: 1 if running, 0 if stopped
 */""",

    "NngineAttachConfig": """/* NngineAttachConfig — Attach configuration from file path
 * Export ordinal: 1 (0xfdb0)
 *
 * undefined4 NngineAttachConfig(int config_index, undefined4 *config_data)
 *
 * config_index selects from 5 config slots at DAT_1030b064.
 * Creates 0x14-byte config object with vtable PTR_FUN_102af81c.
 * Returns 0 on success, 1 if config slot already occupied.
 */""",

    "FUN_10157d40": """/* MD5 hash — Standard MD5 with optional salt parameter
 *
 * void __cdecl MD5(int data, int len, uint32_t result[4], int salt)
 *
 * When salt=0: standard MD5 (init constants: 0x67452301, etc.)
 * When salt!=0: modified init constants (adds salt * multiplier)
 *
 * Internal: FUN_10157820 = MD5_Update, FUN_101578e0 = MD5_Final
 * Validated in Unicorn against known test vectors.
 */""",

    "FUN_10158410": """/* XOR-CBC decrypt — Block cipher for .lyc credential files
 *
 * undefined4* __thiscall (int *this, int buffer_obj)
 *
 * this: Credential data object
 *   [2..5]: XOR-CBC key (4 x uint32 = 16 bytes)
 *   [6..9]: MD5 hash for validation
 *   [10]:   flags
 *
 * buffer_obj:
 *   +0x04: data pointer    +0x08: data size
 *
 * Algorithm (per 16-byte block):
 *   output[i] = input[i] ^ key[i]
 *   key[i] ^= output[i]           // CBC feedback
 *
 * First validates MD5(data) == this[6..9].
 * Magic: first uint32 of decrypted data must be 0x36c8b267.
 */""",

    "FUN_10154b40": """/* RSA PKCS#1 v1.5 — Decrypt/verify with padding check
 *
 * int (int key_obj, int mode, int *out_len, undefined4 input, undefined4 output)
 *
 * mode=0: public key (verify), mode=1: private key (decrypt)
 * Key size: 0x10 to 0x200 bytes (128 to 4096 bits)
 *
 * Calls FUN_10154860 (public modexp) or FUN_10154920 (private CRT).
 * Strips PKCS#1 type 2 padding: 00 02 [random] 00 [payload]
 * Returns payload length via out_len.
 */""",

    "FUN_10154860": """/* RSA modexp (public key) — m = c^e mod n
 *
 * uint (int key_obj, undefined4 input, undefined4 output)
 *
 * Uses Montgomery multiplication via FUN_1015bcc0.
 * Key object fields: +0x08 modulus, +0x14 exponent, +0x68 Montgomery ctx
 * Returns 0 on success.
 */""",

    "FUN_101a9930": """/* serializer_invoke — Top-level igo-binary serializer
 *
 * undefined4 __thiscall (int *body_obj, int output_stream, undefined4 *version)
 *
 * 1. Gets descriptor via vtable[1] on body_obj
 * 2. Processes version info via FUN_101b3f20
 * 3. Calls vtable[7] (prepare) on descriptor
 * 4. Calls vtable[2] (compound_serialize) on descriptor
 * 5. Returns 1 on success, 0 on failure
 *
 * output_stream+0x12: error flag (checked after serialize)
 */""",

    "FUN_101a8e80": """/* compound_serializer — Iterates fields, writes presence bits + values
 *
 * undefined4 __fastcall (int descriptor)
 *
 * Delegates to FUN_101a9da0 (field_iterator) if descriptor has fields.
 * NOTE: Ghidra shows this as very short — the real logic is in
 * FUN_101a9da0 and the ~90 unreachable blocks that follow suggest
 * heavy compiler optimization/inlining.
 */""",

    "FUN_10091bf0": """/* envelope_writer — Serializes QUERY or BODY section
 *
 * void (undefined4 output, int data, undefined4 request, int format)
 *
 * format=0: binary serialization (for wire protocol)
 * format=1: text/string serialization
 *
 * Dispatches to:
 *   FUN_101b30f0 (XML text serializer) — for http_dump log
 *   FUN_101b2c30 (binary serializer)   — for actual wire data
 *
 * Uses global object manager at DAT_10326d38 for buffer allocation.
 */""",

    "FUN_100b1670": """/* credential_copier — Copies credential from source to 0x9C-byte object
 *
 * undefined4* __thiscall (undefined4 *dest, int source)
 *
 * Copies 0x22 uint32s (0x88 bytes) from source+0x10 to dest+0x10.
 * Sets vtables: PTR_FUN_102baf20, PTR_FUN_102baf34, PTR_FUN_102baf48
 * Also copies source+0x98 and source+0xA0 to dest+0x98/0xA0.
 *
 * Source is the credential at param_1+0x84 in the session object.
 */""",

    "FUN_100b10c0": """/* credential_source — Creates connection objects with credentials
 *
 * void __thiscall (int this, undefined4 param_2)
 *
 * Manages a pool of 0xE4-byte connection objects (max 5 in free pool).
 * Each object gets credentials copied from this+0x84 via FUN_100b1670.
 * Uses doubly-linked list with -1 (0xFFFFFFFF) as null sentinel.
 *
 * References: "network", "communicating_on_udp"
 */""",

    "FUN_10044c60": """/* device_nng_reader — Reads device.nng from USB drive
 *
 * undefined4 __thiscall (int this, undefined4 param_2, int *file_obj)
 *
 * 1. Builds path via FUN_101c0860 ("license" + "device.nng")
 * 2. Searches for file via file_obj->vtable[11] (offset 0x2C)
 * 3. Calls *(*(this+8)+0x6c) — file system manager vtable[27]
 *    This is a PATH BUILDER, not credential derivation.
 * 4. Processes result via FUN_101b8300
 *
 * String refs: "license", "device.nng" (at PTR_u_device_nng_1030b108)
 */""",

    "FUN_100ea130": """/* nnge_parser — Reads .nng files, searches for NNGE block
 *
 * bool __thiscall (int *this, int *output_buf, int *version_out)
 *
 * Search strategy:
 *   1. If cached (this[5]!=0), return cached data
 *   2. Load NNGE key "m0$7j0n4(0n73n71I)" from DAT_102c11e4
 *   3. Load template "ZXXXXXXXXXXXXXXXXXXZ" from DAT_102c11f8
 *   4. Open file via vtable[23] (offset 0x5C)
 *   5. Read first 512 bytes, search for magic 0x460
 *   6. Seek to end-24, read 20 bytes, check for "NNGE" header
 *   7. If found: store via FUN_100ea610, copy to output
 *   8. If not found: try template fallback
 *
 * NNGE block: 20 bytes = "NNGE" + 16 bytes data
 * Returns true if NNGE block found, false otherwise.
 *
 * FAILS for device.nng (268 bytes): offset 244 has no "NNGE" marker.
 */""",

    "FUN_100bed80": """/* license_file_loader — Iterates .lic/.lyc files, loads licenses
 *
 * void __fastcall (int this)
 *
 * Searches for *.lic and *.lyc files in the license directory.
 * For each file:
 *   1. Allocates 0x70-byte license object
 *   2. Calls FUN_10101e80 to validate (RSA + XOR-CBC)
 *   3. On failure: logs "License file '%s' cannot be loaded!"
 *   4. On success: appends to vector at this+8
 */""",

    "FUN_100be3c0": """/* credential_provider_constructor — Creates credential provider
 *
 * undefined4* __thiscall (undefined4 *this, int *cred_sources, int *rsa_keys)
 *
 * Sets vtable to PTR_FUN_102bbbf4 (credential provider).
 * Creates RSA context objects via FUN_101585f0 for each key.
 * Loads license files via FUN_100bed80.
 * Registers credential sources from cred_sources vector.
 */""",

    "FUN_100bd380": """/* nnge_vtable2_speedx — Formats "SPEEDx%sCAM", computes MD5
 *
 * void __thiscall (int *this, undefined4 param_2)
 *
 * Gets hardware ID via vtable[6] (offset 0x18).
 * Formats as "SPEEDx{hwid}CAM" via sprintf.
 * Computes MD5 hash of the formatted string via FUN_10157d40.
 * Used for SWID (Software ID) generation.
 */""",

    "FUN_101aa050": """/* credential_constructor — Creates 0x58-byte delegated credential
 *
 * undefined4* (undefined4 *param_1_code, undefined4 *param_2_secret)
 *
 * param_1: pointer to Code (hu_code, 8 bytes)
 * param_2: pointer to Secret (hu_secret, 8 bytes) — used for HMAC key
 *
 * Creates credential with:
 *   Code = *param_1 (hu_code)
 *   Secret = from device manager singleton (DAT_1031445c)
 *   Name = HMAC-MD5(hu_secret_BE, serialized_data)
 *
 * Device manager chain for Secret:
 *   FUN_10011dd0 -> vtable[6] -> FUN_100a4bb0
 *   -> *(*(device_obj+0x3C)+0x1C)+0x10
 *
 * HMAC-MD5 for Name:
 *   key = hu_secret bytes in big-endian order (8 bytes)
 *   data = igo-binary serialized via FUN_101a9930
 *   result = 16-byte name (ad35bcc12654b893f7b5596a8057190c)
 */""",

    "FUN_10094510": """/* device_object_constructor — Creates 0x54-byte device object
 *
 * undefined4* __thiscall (undefined4 *this, undefined4 name)
 *
 * Vtable: PTR_FUN_102b9688
 * Fields 7-0x11 initialized to 0 (populated during registration).
 * Creates two tree structures at this[0x10] and this[0x13].
 *
 * Key field: this[0xF] (offset 0x3C) = inner credential object ptr
 *   Set during registration via FUN_10055c70.
 *   Contains Code/Secret at inner[7]+0x10/0x1C.
 */""",

    "FUN_1001fc00": """/* credential_copy_constructor — Deep copy of credential object
 *
 * undefined4* __thiscall (undefined4 *dest, int source)
 *
 * Copies all credential fields from source to dest:
 *   source+0x10 -> dest[4..5]  = Code (8 bytes)
 *   source+0x18 -> dest[6]     = unknown field
 *   source+0x1C -> dest[7..8]  = Secret (8 bytes)
 *   source+0x24 -> dest[9]     = unknown field
 *   source+0x28 -> dest[10..11]= unknown (8 bytes)
 *   source+0x30 -> dest[12]    = unknown field
 *   source+0x34 -> dest[13..14]= unknown (8 bytes)
 *   source+0x3C -> dest[15]    = inner object ptr
 *   source+0x40 -> dest[16]    = flags (2 bytes)
 */""",

    "FUN_10056ad0": """/* buf_write — Write N bytes to growable buffer
 *
 * undefined4 __thiscall (int *this, undefined4 data, int length)
 *
 * this: buffer object
 *   [0]: data pointer    [2]: current size
 *   [3]: capacity        +0x11: growable flag
 *   +0x12: error flag
 *
 * Grows buffer (2x + length) if needed via FUN_1027ea51 (realloc).
 * Copies data via FUN_1027fa10 (memcpy).
 */""",

    "FUN_100eab30": """/* nnge_lb_process — Parses _lb_ license block strings
 *
 * void __fastcall (undefined4 *this)
 *
 * Splits string by delimiter (DAT_102b51d8).
 * For each 0x1A-length block: calls FUN_10155c10 (Base32 decode).
 * Inserts 16-byte decoded results into linked list at this[0x1A].
 * Used for license key decoding from NNGE metadata.
 */""",

    "FUN_10155c10": """/* base32_decode — Decodes 26 Base32 chars to 16 bytes
 *
 * uint (int input, uint input_len, int *output)
 *
 * Crockford-style Base32 (no padding, case-insensitive).
 * Used for license key format: CK-XXXX-XXXX-XXXX-XXXX
 */""",

    "FUN_10158610": """/* provider_decrypt — Block-level decryption for .lyc files
 *
 * undefined4* __thiscall (int *this, int buffer_obj)
 *
 * Reads block size via vtable[3] (offset 0x0C).
 * Loops calling vtable[2] (offset 0x08) to decrypt each block.
 * Wraps result in 0x18-byte object with vtable PTR_FUN_102b5f64.
 */""",

    "FUN_10158710": """/* rsa_validate — Thin wrapper for RSA PKCS#1 verify
 *
 * bool __thiscall (int this, undefined4 p2, undefined4 p3, undefined4 p4)
 *
 * Calls FUN_10154b40(this+4, 0, p2, p4, p3).
 * The 0 selects public-key (verify) mode.
 * Returns true if RSA verify succeeds (result == 0).
 */""",

    "FUN_100b4600": """/* debug_dump — Writes request data to http_dump log
 *
 * void (uint32 counter_lo, uint32 counter_hi, undefined4 *name,
 *       undefined4 data_ptr, undefined4 data_len)
 *
 * Formats filename as: "{counter:016X}-{name}-{type}.bin"
 * Writes raw binary data to the http_dump directory.
 * Used for debugging serialized request/response bodies.
 */""",

    "FUN_100ba130": """/* login_arg_factory — Builds LOGIN request argument struct
 *
 * undefined4* __thiscall (undefined4 *this, int param_2)
 *
 * Creates 76-byte LOGIN arg with vtable and field descriptors.
 * Fields: OperatingSystemName, OperatingSystemVersion,
 *         OperatingSystemBuildVersion, AgentVersion,
 *         AgentAliases, Language, AgentType
 */""",

    "FUN_101b41b0": """/* serializer_lookup — Binary search in global serializer registry
 *
 * void (undefined4 *result, int registry, undefined4 service_name, undefined4 arg_type)
 *
 * Global registry singleton at DAT_10314964.
 * Searches by (service_name, arg_type) pair.
 * Uses FUN_101b45a0 as comparison function.
 * Services: MARKET, TB, MOTA, MOCA, etc. (table at RVA 0x2D8A70)
 */""",

    "FUN_101a9e80": """/* write_1bit_lsb — Writes single bit to bitstream (LSB-first)
 *
 * undefined4 __thiscall (int *stream, byte bit_value)
 *
 * stream: BitStream object
 *   +0x00: buffer ptr    +0x04: bit position
 *   +0x08: byte position +0x10: MSB/LSB flag
 *   +0x12: error flag    +0x14: capacity
 *
 * Used for presence bits in igo-binary format.
 */""",

    "FUN_101a8150": """/* write_nbits_msb — Writes N bits MSB-first to bitstream
 *
 * undefined1 __thiscall (int *stream, uint value, uint num_bits)
 *
 * Writes value in num_bits bits, MSB-first per byte.
 * Used for field values when stream+0x10 flag is zero.
 */""",

    "FUN_101a8310": """/* write_nbits_lsb — Writes N bits LSB-first to bitstream
 *
 * undefined1 __thiscall (int *stream, uint value, uint num_bits)
 *
 * Writes value in num_bits bits, LSB-first per byte.
 * Used for field values when stream+0x10 flag is non-zero.
 */""",

    "FUN_100b3100": """/* session_bind — Binds HTTP connection to session
 *
 * undefined4* __thiscall (undefined4 *this, undefined4 session_id, undefined4 *connection)
 */""",

    "FUN_100a4bb0": """/* inner_object_accessor — Returns value at this+0x1C
 *
 * undefined4 __fastcall (int this)
 *
 * Simple accessor: return *(this + 0x1C)
 * In the Secret3 pointer chain: returns the inner credential object
 * from which Code (+0x10) and Secret (+0x1C) are read.
 */""",

    "FUN_10011dd0": """/* device_manager_lookup — Finds device in credential store tree
 *
 * void (uint *tree, undefined4 key, int flags)
 *
 * Searches the "NAVIEXTRAS_UNIQUE_DEVICE__ID" credential store.
 * Returns device object via tree output parameter.
 */""",

    "FUN_10096700": """/* singleton_constructor — Creates device manager singleton
 *
 * undefined4* __fastcall (undefined4 *this)
 *
 * Lazy-initialized singleton stored at DAT_1031445c.
 * Thread-safe via LOCK/UNLOCK with DAT_103144ac as init flag.
 */""",

    "FUN_101b2c30": """/* binary_serializer — Produces D8..D9 credential block
 *
 * void __thiscall (int *this, int *data, int param_3, undefined1 param_4)
 *
 * Serializes credential data into binary wire format.
 * Uses vtable at PTR_FUN_102d8d68 for type-specific writers.
 * Produces the encrypted credential block in the query section.
 */""",

    "FUN_101b30f0": """/* xml_text_serializer — Produces XML for http_dump log
 *
 * void __thiscall (int *this, int *data, int param_3, undefined1 param_4)
 *
 * Generates human-readable XML representation of request data.
 * Output goes to http_dump directory for debugging.
 * Fields logged: <Key>, <Crypt>, <State>, etc.
 */""",

    "FUN_100ea960": """/* lyc_provider_reader — Reads .lyc file, decrypts via provider
 *
 * void __fastcall (int this)
 *
 * Reads .lyc file contents.
 * Calls provider vtable to decrypt (RSA + XOR-CBC).
 * Validates magic 0x36c8b267 in decrypted header.
 * Validates decrypted size == 0x28 (40 bytes).
 */""",

    "FUN_100ea670": """/* credential_provider_find — Iterates providers at +0x54..0x58
 *
 * bool __thiscall (int this, undefined4 param_2)
 *
 * Walks provider objects, calls vtable[1] to get credential data.
 */""",

    "FUN_100ea610": """/* nnge_block_store — Stores 20-byte NNGE block
 *
 * void __thiscall (int this, int nnge_data)
 *
 * Copies 20-byte NNGE block (4-byte "NNGE" + 16 bytes data)
 * into the parser's internal storage.
 */""",

    "FUN_10055c70": """/* device_obj_set_inner — Sets inner credential object pointer
 *
 * undefined4* __thiscall (undefined4 *this, undefined4 inner_ptr)
 *
 * Sets this[0xF] (offset 0x3C) = inner_ptr.
 * Called from 23 locations during registration flow.
 * The inner object contains Code/Secret for the device credential.
 */""",

    "FUN_10056830": """/* device_obj_copy_globals — Copies credential from global data
 *
 * void (undefined4 *dest)
 *
 * Copies credential data from globals at DAT_103147d4 area
 * into the device object. Called during service manager init.
 */""",

    "FUN_1005ffe0": """/* credential_provider_factory — Creates credential provider
 *
 * undefined1 (int *param_1, int *******param_2, undefined4 param_3)
 *
 * Factory function that creates the credential provider via FUN_100be3c0.
 * Connects RSA keys, license files, and registration data.
 */""",

    "FUN_100b0b50": """/* session_protocol_dispatch — Dispatches protocol request
 *
 * void __thiscall (int this, int param_2)
 *
 * Calls protocol_envelope_builder (FUN_100b3a60).
 * Handles connection setup and credential selection.
 */""",

    "FUN_10062240": """/* credential_entry_parser — Parses comma-delimited credential string
 *
 * int __thiscall (int this, int entry_data, int entry_type)
 *
 * For type 1 entries: parses "field1, field2, field3, ..."
 * Delimiter: ", " (comma-space) at DAT_102b3260
 * Builds credential with Code/Secret from parsed fields.
 */""",

    "FUN_10062a20": """/* credential_entry_iterator — Iterates credential entries
 *
 * void (int entries, int count, int stride, char type_filter)
 *
 * Walks credential entries (stride 0x80) with sub-entries (stride 0x20).
 * Sub-entry type 1 -> FUN_10062240 (credential parser)
 * Sub-entry type 2/4 -> FUN_100623f0 (license credentials)
 */""",

    "FUN_1005fb70": """/* device_manager_credential_handler — Handles device credentials
 *
 * int __thiscall (int this, int param_2, undefined4 param_3, undefined4 param_4)
 *
 * Called from FUN_1005fca9 during device manager initialization.
 * Processes credential data for the device manager singleton.
 */""",

    "FUN_101585f0": """/* rsa_provider_wrapper — Wraps RSA key in provider object
 *
 * undefined4* __thiscall (undefined4 *this, undefined4 rsa_key)
 *
 * Creates provider with vtable PTR_FUN_102c76b0:
 *   [0] destructor  [1] chunk_decrypt  [2] rsa_validate
 *   [3] get_value   [4] get_adjusted
 */""",

    "FUN_10101120": """/* rsa_key1_init — Loads RSA Key1 from static DLL data
 *
 * undefined4 (undefined4 *output)
 *
 * Key1: 2048-bit RSA, exponent=65537 (0x10001)
 * Modulus at RVA 0x30B588 (64 uint32 words = 256 bytes)
 * Exponent at RVA 0x30B580
 * Used for .lyc file signature verification.
 */""",
}

# ============================================================
# INLINE COMMENTS - (pattern_to_match, comment_to_add) per function
# ============================================================
INLINE_COMMENTS = {
    "FUN_100b3a60": [
        ("**(int **)(param_1 + 0x1c) + 0x18", "/* credential_provider->vtable[6]: get_credential */"),
        ("piVar8[0xf] == 3", "/* mode == DEVICE (not RANDOM) */"),
        ("piVar8[0xf] == 2", "/* mode == RANDOM */"),
        ("FUN_100935c0(param_3 + 1)", "/* copy envelope header data */"),
        ("FUN_101a9930(piVar1 + 0xb,&local_1c)", "/* serialize envelope header (igo-binary) */"),
        ("FUN_101a9930(param_3 + 6,&local_1c)", "/* serialize envelope body (igo-binary) */"),
        ("FUN_100b4a30()", "/* construct body object */"),
        ("DAT_10314964", "/* global serializer registry singleton */"),
        ("FUN_101b41b0", "/* lookup serializer by (service_name, arg_type) */"),
        ("__time64", "/* get current time for random key seed */"),
        ("uVar13 << 0x15 ^ uVar13", "/* xorshift PRNG step for random key */"),
        ("FUN_1027e4f5(8)", "/* allocate 8-byte SnakeOil key */"),
        ("*(iVar3 + 0x1c)", "/* Secret_lo from credential */"),
        ("*(iVar3 + 0x20)", "/* Secret_hi from credential */"),
        ("*(iVar3 + 0x10)", "/* Code_lo from credential (stored in wire header) */"),
        ("*(iVar3 + 0x18)", "/* unknown credential field */"),
        ("DAT_10314a60", "/* global request counter */"),
        ("DAT_10314a50", "/* global timestamp */"),
        ("piVar8[0x39]", "/* request counter lo */"),
        ("piVar8[0x3a]", "/* request counter hi */"),
        ('"name: %s\\ncode: %lld\\nsecret: %lld"', "/* DEBUG LOG: credential values */"),
        ("FUN_101bae20(L\"credentials\")", "/* log section: credentials */"),
        ("FUN_101bae20(L\"decoded_request_body\")", "/* log section: decoded body */"),
        ("FUN_101bae20(L\"decoded_request_q\")", "/* log section: decoded query */"),
        ("FUN_101b3e10(piVar11[0xb]", "/* SnakeOil encrypt QUERY section */"),
        ("FUN_101b3e10(piVar11[1]", "/* SnakeOil encrypt BODY section */"),
        ("piVar11[0x10]", "/* SnakeOil key pointer (8 bytes: [lo, hi]) */"),
        ("FUN_10091bf0(piVar1,local_16c", "/* serialize QUERY (credential block) */"),
        ("FUN_10091bf0(piVar1,&local_f8", "/* serialize BODY (request args) */"),
        ("local_13c = 2", "/* mode = RANDOM */"),
        ("local_13c = 3", "/* mode = DEVICE */"),
        ("FUN_100b4600(piVar8[0x39]", "/* write to http_dump log */"),
    ],
    "FUN_101b3e10": [
        ("param_5 << 0x15 | param_4 >> 0xb", "/* PRNG step 1: hi = (hi<<21 | lo>>11) ^ hi */"),
        ("param_4 << 0x15 ^ param_4 ^ param_5 >> 3", "/* PRNG step 2: lo = (lo<<21)^lo ^ (hi>>3) */"),
        ("param_5 << 4 | param_4 >> 0x1c", "/* PRNG step 3: hi = (hi<<4 | lo>>28) ^ hi */"),
        ("param_4 << 4 ^ param_4", "/* PRNG step 4: lo = (lo<<4) ^ lo */"),
        ("param_4 >> 0x17", "/* extract keystream byte: (lo >> 23) & 0xFF */"),
    ],
    "FUN_101aa050": [
        ('"NAVIEXTRAS_UNIQUE_DEVICE__ID"', "/* device manager singleton name */"),
        ("DAT_1031445c", "/* device manager singleton pointer */"),
        ("FUN_10096700()", "/* create device manager singleton */"),
        ("FUN_10011dd0(&local_24,&local_28,0)", "/* lookup device in credential store */"),
        ("(**(code **)(*local_24 + 0x18))()", "/* device_obj->vtable[6]: get inner credential */"),
        ("FUN_1027e4f5(0x58)", "/* allocate 0x58-byte credential object */"),
        ("PTR_FUN_102b9590", "/* credential vtable 1 */"),
        ("PTR_FUN_102b9580", "/* credential vtable 2 */"),
        ("PTR_FUN_102b9588", "/* credential vtable 3 */"),
        ("puVar9[6] = uVar6", "/* Code_lo = *param_1 (hu_code lo) */"),
        ("puVar9[7] = uVar1", "/* Code_hi = param_1[1] (hu_code hi) */"),
        ("*(iVar5 + 0x10)", "/* Secret from device manager: *(inner+0x10) */"),
        ("*(iVar5 + 0x18)", "/* unknown field from device manager */"),
        ("FUN_101d2630()", "/* get current timestamp */"),
        ("puVar9[0x10] = 3", "/* mode = DEVICE */"),
        ("FUN_101a9930(&local_44,0)", "/* serialize credential data (igo-binary) */"),
        ("FUN_101aa3a0(local_1c,&local_30,8,local_44,local_3c)", "/* HMAC-MD5: key=hu_secret(8B BE), data=serialized */"),
    ],
    "FUN_10158410": [
        ("FUN_10157d40(*(undefined4 *)(param_2 + 4),*(undefined4 *)(param_2 + 8),local_38,0)", "/* MD5(input_data) for validation */"),
        ("param_1 + 6", "/* this[6..9] = expected MD5 hash */"),
        ("*piVar9 != *piVar11", "/* compare computed MD5 vs expected */"),
        ("(**(code **)(*param_1 + 0xc))()", "/* vtable[3]: get block size (returns 0x10) */"),
        ("(**(code **)(*param_1 + 0x10))()", "/* vtable[4]: get output multiplier */"),
        ("FUN_1027e4f5(0x18)", "/* allocate output buffer object */"),
        ("PTR_FUN_102b5f64", "/* output buffer vtable */"),
        ("param_1[2]", "/* XOR-CBC key word 0 */"),
        ("param_1[3]", "/* XOR-CBC key word 1 */"),
        ("param_1[4]", "/* XOR-CBC key word 2 */"),
        ("param_1[5]", "/* XOR-CBC key word 3 */"),
        ("*puVar12 ^ local_3c", "/* XOR-CBC: output = input ^ key */"),
        ("local_3c = local_3c ^ uVar5", "/* XOR-CBC: key feedback */"),
    ],
    "FUN_100ea130": [
        ("_DAT_102c11e4", "/* NNGE key: \"m0$7j0n4(0n73n71I)\" (19 bytes) */"),
        ("s_ZXXXXXXXXXXXXXXXXXXZ_102c11f8", "/* NNGE template: \"ZXXXXXXXXXXXXXXXXXXZ\" */"),
        ("_strncmp(local_30,\"NNGE\",4)", "/* check for NNGE magic header */"),
        ("_strncmp((char *)&uStack_244,\"NNGE\",4)", "/* check if template starts with NNGE */"),
        ("0x460", "/* magic marker in .nng file header */"),
        ("FUN_100ea610(local_30)", "/* store 20-byte NNGE block */"),
        ("FUN_100fc970(param_1 + 1)", "/* copy NNGE data to output buffer */"),
        ("_fseek(_File,iVar2,_Origin)", "/* seek to NNGE block position */"),
        ("_fread(local_30,1,0x14,_File)", "/* read 20-byte NNGE block */"),
        ("_fread(local_230,4,0x80,_File)", "/* read first 512 bytes of .nng file */"),
    ],
    "FUN_10091bf0": [
        ("FUN_101b30f0(param_2,0,0)", "/* XML text serializer (for http_dump log) */"),
        ("FUN_101b2c30(param_2,0,0)", "/* binary serializer (for wire protocol) */"),
        ("FUN_101b2910(0,1)", "/* set binary serializer vtable */"),
        ("DAT_10326d38", "/* global object manager */"),
        ("param_4 == 0", "/* format: binary */"),
        ("param_4 == 1", "/* format: text/string */"),
    ],
    "FUN_10157d40": [
        ("0x67452301", "/* MD5 init constant A */"),
        ("-0x10325477", "/* MD5 init constant B (0xEFCDAB89) */"),
        ("-0x67452302", "/* MD5 init constant C (0x98BADCFE) */"),
        ("DAT_10325476", "/* MD5 init constant D base (0x10325476) */"),
        ("param_4 * 0xb", "/* salt modifier for constant A */"),
        ("param_4 * 0x47", "/* salt modifier for constant B */"),
        ("param_4 * 0x25", "/* salt modifier for constant C */"),
        ("param_4 * 0x61", "/* salt modifier for constant D */"),
        ("FUN_10157820", "/* MD5_Update */"),
        ("FUN_101578e0", "/* MD5_Final */"),
    ],
    "FUN_10094510": [
        ("PTR_FUN_102b9688", "/* device object main vtable */"),
        ("PTR_LAB_102b96d0", "/* device object sub-vtable 1 */"),
        ("PTR_LAB_102b96d8", "/* device object sub-vtable 2 */"),
        ("FUN_1027e4f5(0xc)", "/* allocate 12-byte callback object */"),
        ("FUN_10091a20", "/* callback function pointer */"),
        ("param_1[0xf] = 0", "/* inner credential ptr (set during registration) */"),
        ("param_1[0x10]", "/* credential tree 1 */"),
        ("param_1[0x13]", "/* credential tree 2 */"),
    ],
    "FUN_1001fc00": [
        ("*(param_2 + 0x10)", "/* source Code_lo */"),
        ("*(param_2 + 0x14)", "/* source Code_hi */"),
        ("*(param_2 + 0x18)", "/* source unknown field */"),
        ("*(param_2 + 0x1c)", "/* source Secret_lo */"),
        ("*(param_2 + 0x20)", "/* source Secret_hi (missing in Ghidra output) */"),
        ("*(param_2 + 0x24)", "/* source unknown field 2 */"),
        ("*(param_2 + 0x28)", "/* source unknown (8 bytes) */"),
        ("*(param_2 + 0x3c)", "/* source inner object ptr */"),
        ("*(param_2 + 0x40)", "/* source flags (2 bytes) */"),
    ],
}

# ============================================================
# DAT_ COMMENTS - annotate global data references
# ============================================================
DAT_COMMENTS = {
    "DAT_10314964": "global serializer registry singleton",
    "DAT_10314968": "serializer registry init flag",
    "DAT_10326d38": "global object manager (null until DllMain)",
    "DAT_1031497c": "global request counter",
    "DAT_10314a60": "request counter lo",
    "DAT_10314a64": "request counter hi (timestamp-based)",
    "DAT_10314a50": "global timestamp",
    "DAT_10314a58": "timestamp init flag",
    "DAT_103143d0": "Nngine engine singleton",
    "DAT_1031445c": "device manager singleton (NAVIEXTRAS_UNIQUE_DEVICE__ID)",
    "DAT_103144ac": "device manager init flag",
    "DAT_10316b58": "network manager ptr",
    "DAT_10316b18": "service manager ptr",
    "DAT_10314978": "request logger callback ptr",
    "DAT_10312f6c": "stack cookie (GS security)",
    "DAT_10316970": "RSA key store (global linked list)",
}
