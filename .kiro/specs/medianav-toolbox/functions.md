# Annotated Function Reference — nngine.dll

> Functions identified through Ghidra decompilation and cross-referencing with
> protocol traces, mitmproxy captures, and decrypted http_dump XML files.

## Protocol & Envelope

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_100b3a60` | 152038 | **ProtocolEnvelopeRO builder** | Builds the binary envelope header. Generates SnakeOil key (RANDOM or DEVICE mode). Calls `FUN_101a9930` to serialize, then `FUN_101b3e10` to encrypt. |
| `FUN_101a9930` | 371550 | **igo-binary serializer (write)** | Generic serializer wrapper. Calls vtable functions to write typed fields. |
| `FUN_101a99b0` | 371590 | **igo-binary deserializer (read)** | Generic deserializer wrapper. Calls vtable functions to read typed fields. |
| `FUN_100b4570` | 152568 | **Request serializer** | Serializes request envelope + body to igo-binary. Calls HTTP log assistant. |
| `FUN_100b46a0` | 152625 | **Response deserializer** | Deserializes response from igo-binary. |
| `FUN_100b05f0` | 149176 | **HTTP request builder** | Constructs HTTP POST request with headers. Calls serializer and sends. |

## SnakeOil Cipher

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_101b3e10` | 382511 | **SnakeOil encrypt** | XOR-shift128 PRNG stream cipher. Params: `(plaintext, length, output, key_lo, key_hi)`. Uses `shrd` for 64-bit output byte extraction. |
| `FUN_101b3e80` | 382540 | **SnakeOil decrypt** | Same PRNG, symmetric XOR. Params: `(key_state*, ciphertext_ptr, length, output)`. |

### SnakeOil PRNG Algorithm (from disassembly at 0x101b3e30)

```asm
; eax = key_lo, esi = key_hi (state)
; Loop per byte:
  mov  ecx, eax              ; save key_lo
  mov  edx, esi              ; save key_hi
  shld edx, ecx, 0x15        ; edx = (key_hi << 21) | (key_lo >> 11)
  xor  edx, esi              ; edx ^= key_hi
  shl  ecx, 0x15             ; ecx = key_lo << 21
  xor  ecx, eax              ; ecx ^= key_lo
  mov  eax, edx              ; 
  shr  eax, 3                ; eax = new_hi >> 3
  xor  ecx, eax              ; ecx ^= (new_hi >> 3)
  mov  esi, edx              ; esi = new_hi
  mov  eax, ecx              ; eax = new_lo
  shld esi, eax, 4           ; esi = (new_hi << 4) | (new_lo >> 28)
  xor  esi, edx              ; esi ^= new_hi
  shl  eax, 4                ; eax = new_lo << 4
  xor  eax, ecx              ; eax ^= new_lo
  ; State: eax = final_lo, esi = final_hi
  mov  ecx, esi
  mov  edx, eax
  shrd edx, ecx, 0x17        ; edx = (key_hi << 9) | (key_lo >> 23)  [64-bit shift]
  xor  dl, [plaintext + i]   ; output byte = low_byte(edx) ^ plaintext[i]
```

**Status**: FULLY REVERSED AND VERIFIED. Decrypts boot response (service URLs visible), device registration response (credentials visible), and model list response (all model names visible). Response header is 4 bytes (`01 00 C2 XX`), request header is 16 bytes.

## HTTP & Network

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_1008ebb0` | 119171 | **SendPostRequest** | HTTP POST with auth. Logs `"SendPostRequest(aServiceName = '%s', %s)"`. |
| `FUN_1008e840` | 119021 | **HTTP request handler** | Manages HTTP connections. |
| `FUN_10093010` | 123012 | **HTTP request object** | Creates request with URL, headers, body. |

## Device & Registration

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_100bd450` | 159534 | **Get drive serial** | Opens `\\.\PhysicalDrive0` via IOCTL, falls back to `GetVolumeInformationW("C:\\")`. |
| `FUN_100bd380` | 159493 | **SWID part hasher** | Wraps drive serial in `"SPEEDx%sCAM"`, computes MD5. |
| `FUN_1009c960` | 131620 | **SWID builder** | Reads `swid_prefix` config, joins MD5 parts with `"-"`. |
| `FUN_100bd300` | 159464 | **Get device key data** | Vtable[6] of device.nng reader. Calls `FUN_100bd450`. |
| `FUN_100bd310` | 159475 | **Get volume serial** | `GetVolumeInformationW("C:\\")` → volume serial as DWORD. |
| `FUN_100ea4e0` | — | **Device fingerprint** | Computes MD5 of device data, formats as `%02X` hex string. |
| `FUN_100a4d50` | 139093 | **RegisterDeviceTaskRO builder** | Copies 30 fields from device info to registration arg struct. |
| `FUN_1009c650` | 131438 | **Device info populator** | Reads device.nng data into device info structure. |
| `FUN_1009be10` | 130922 | **Device info constructor** | Creates device info object, calls `FUN_1009c650` and `FUN_1009c960`. |

## Device Recognition

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_1005ffe0` | 77546 | **Model matcher** | Matches device against model list. Uses `"filter_factory_sku"`. |
| `FUN_100be390` | 160247 | **Matcher factory** | Creates device matcher object with vtable `PTR_FUN_102bbbf4`. |
| `FUN_100be920` | 160577 | **Match function** | Vtable[3] of matcher. Iterates models, checks APPCID. |

## Encryption & Crypto

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_10157d40` | 299296 | **MD5 hash** | Standard MD5 with optional salt via `param_4`. |
| `FUN_10157820` | — | **MD5 update** | Feeds data into MD5 state. |
| `FUN_101578e0` | — | **MD5 finalize** | Produces 16-byte digest. |
| `FUN_101b54f0` | 384260 | **Blowfish encrypt wrapper** | Calls Blowfish vtable. Used for http_dump XML encryption. |
| `FUN_101b5510` | 384278 | **Blowfish singleton init** | Creates Blowfish cipher with key at `DAT_102af9e8` (16 bytes). |

## NNGE (device.nng)

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_100bde70` | — | **UTF-16 to UTF-8 converter** | Converts device data for hashing. |
| `FUN_100be060` | — | **Device config reader** | Reads `device_code_param`, `device_id_ioctl`, `content_code_param`. |
| `FUN_100be2a0` | — | **Decoder plugin** | Constructs `"toolbox_" + brand` for fingerprint. |

## String & Memory Utilities

| Function | Line | Role | Notes |
|----------|------|------|-------|
| `FUN_101b74e0` | — | **sprintf wrapper** | `sprintf(buf, fmt, ...)` |
| `FUN_101baa50` | — | **String copy** | Copies string data. |
| `FUN_101babb0` | — | **String init** | Initializes empty string. |
| `FUN_101bae20` | — | **Wide string init** | Initializes from wide string literal. |
| `FUN_101baea0` | — | **String empty check** | Returns true if string is empty. |
| `FUN_101bad00` | — | **String clear** | Clears string content. |
| `FUN_101bad80` | — | **String set** | Sets string from char*. |
| `FUN_101bd8d0` | — | **Get string length** | Returns string length. |
| `FUN_101bd970` | — | **Get string data pointer** | Returns pointer to string data. |
| `FUN_101bdf30` | — | **Debug log enabled check** | Returns true if debug logging is on. |
| `FUN_1000d160` | — | **Debug log write** | Writes formatted debug message. |
| `FUN_1027e4f5` | — | **malloc** | Allocates memory. |
| `FUN_1027dfe8` | — | **free** | Frees memory. |

## Key Data Addresses

| Address | Type | Value | Notes |
|---------|------|-------|-------|
| `0x102af9e8` | 16 bytes | `b0caba3d f8a23194 f2a22f59 cd0b39ab` | Blowfish key for http_dump |
| `0x102c11e4` | 18 bytes | `m0$7j0n4(0n73n71I)` | NNGE encryption key |
| `0x102c11f8` | 20 bytes | `ZXXXXXXXXXXXXXXXXXXZ` | NNGE key template |
| `DAT_10314458` | ptr | — | Blowfish singleton instance |
| `DAT_10314964` | ptr | — | SnakeOil key state |

## Vtables

| Address | Interface | Key Methods |
|---------|-----------|-------------|
| `PTR_FUN_102bba98` | Device.nng reader | [6]=GetDeviceKey, [8]=HashSWIDPart, [9]=GetFingerprint |
| `PTR_FUN_102bbbf4` | Device matcher | [3]=Match, [4]=GetResults |
| `PTR_FUN_102b5294` | GetDeviceModelList request | [1]=Serialize |
| `PTR_FUN_102b5274` | GetDeviceDescriptorList request | [1]=Serialize |
