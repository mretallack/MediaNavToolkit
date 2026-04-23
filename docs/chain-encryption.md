# Delegated Request Wire Format

> Source of truth for constructing delegated senddevicestatus requests.
> All claims verified by `tests/test_dynamic_wire.py` (24 tests).

## How to Construct the Payload

### Inputs

| Input | Type | Source |
|-------|------|--------|
| `hu_code` | uint64 | Delegator response `.code` |
| `hu_secret` | uint64 | Delegator response `.secret` |
| `tb_code` | uint64 | Registration response `.code` |
| `session_key` | uint64 | `creds.secret` (toolbox Secret from registration) |
| `body` | bytes | `build_senddevicestatus_body()` or `build_live_senddevicestatus()` |
| `timestamp` | uint32 | `int(time.time()) & 0xFFFFFFFF` |

### Step 1: Build the credential data (21 bytes)

```python
cred_data = b"\xC4" + struct.pack(">Q", hu_code) + struct.pack(">Q", tb_code) + struct.pack(">I", timestamp)
```

### Step 2: Compute the HMAC (16 bytes)

```python
hmac_key = struct.pack(">Q", hu_secret)
hmac_result = hmac.new(hmac_key, cred_data, hashlib.md5).digest()
```

**Key is `hu_secret`, data contains `hu_code`.** These are different values.

### Step 3: Build the query (41 bytes)

```python
query = bytes([0x08, 0x80]) + cred_data + b"\x30\x10" + hmac_result
```

For 58B variant (with tb_name): `bytes([0x48, 0x80]) + tb_name[:16] + b"\x80" + cred_data + b"\x30\x10" + hmac_result`

### Step 4: Build the header (16 bytes)

```python
header = struct.pack(">BBBB Q B HB", 0x01, 0xC2, 0xC2, 0x30, tb_code, 0x19, 0x0000, session_id)
```

### Step 5: Encrypt and assemble

```python
prefix = snakeoil(b"\xE9", session_key)           # 1 byte
encrypted_query = snakeoil(query, session_key)     # 41 bytes
encrypted_body = snakeoil(body, session_key)       # len(body) bytes
wire = header + prefix + encrypted_query + encrypted_body
```

Each `snakeoil()` call resets the PRNG from `session_key` independently.

### Implementation

```python
from medianav_toolbox.protocol import build_dynamic_request

wire = build_dynamic_request(
    counter=0, body=body,
    hu_code=hu_code, tb_code=tb_code, hu_secret=hu_secret,
    session_key=creds.secret,  # toolbox Secret from registration
)
```

## Wire Format

```
[16B header][1B prefix][snakeoil(query, key)][snakeoil(body, key)]
```

| Offset | Size | Content |
|--------|------|---------|
| 0-15 | 16B | Header: `01 C2 C2 30` + tb_code(8B BE) + `19 00 00` + session_id |
| 16 | 1B | Prefix: `snakeoil(0xE9, session_key)` = `0x55` |
| 17-57 | 41B | `snakeoil(query, session_key)` |
| 58+ | var | `snakeoil(body, session_key)` |

Total: `16 + 1 + 41 + len(body)` bytes.

## Query Format (41B, no name)

| Offset | Size | Content |
|--------|------|---------|
| 0 | 1B | Flags: `0x08` (bit 3 set, no name) |
| 1 | 1B | Format: `0x80` |
| 2 | 1B | Credential type: `0xC4` |
| 3-10 | 8B | `hu_code` (big-endian) |
| 11-18 | 8B | `tb_code` (big-endian) |
| 19-22 | 4B | `timestamp` (big-endian) |
| 23-24 | 2B | Separator: `0x30 0x10` |
| 25-40 | 16B | HMAC-MD5 |

## HMAC Computation

```
Key:  hu_secret as 8 bytes big-endian
Data: 0xC4 || hu_code(8B BE) || tb_code(8B BE) || timestamp(4B BE)
Algo: HMAC-MD5
```

### Test Vectors (from run25 HMAC log)

| # | Timestamp | HMAC Output |
|---|-----------|-------------|
| 1 | `69E8FC9B` | `D21F264DF9CE422164E1B278ED8DC08B` |
| 2 | `69E8FC9D` | `ABA5982D0773B8028BD369373FB55EA2` |

Key for both: `000EE87C16B1E812`. Data prefix: `C4000BF28569BACB7C000D4EA65D36B98E`.

## Session Key — SOLVED

The session key is **`creds.secret`** — the toolbox Secret from device registration.

Confirmed by Ghidra analysis of `FUN_100b3a60` (envelope builder): in DEVICE mode
(mode 3), the SnakeOil key is read from `credential_obj[0x1c:0x24]`, which is the
Secret field. For delegated requests, this is the toolbox credential's Secret.

Verified: `creds.secret = 0x000ACAB6C9FB66F8` matches the session key observed in
all captured SnakeOil calls (run25: 48 calls, run32: 54 calls).

No hardcoding needed — every device gets its own `creds.secret` at registration.

## Credentials

| Name | Value | Source |
|------|-------|--------|
| `hu_code` | `0x000BF28569BACB7C` | `get_delegator_credentials().code` |
| `hu_secret` | `0x000EE87C16B1E812` | `get_delegator_credentials().secret` |
| `tb_code` | `0x000D4EA65D36B98E` | Registration `.code` |
| `session_key` | `0x000ACAB6C9FB66F8` | `creds.secret` (toolbox Secret) |

## How the Old Replay Worked

`build_0x68_request()` used `snakeoil(query + chain_body, tb_code)`. This worked because:

1. `chain_body` was extracted as `snakeoil(wire[16:], tb_code)[25:]`
2. Re-encrypting: `snakeoil(new_query + chain_body, tb_code)` = `(new_query ⊕ ks[:25]) + wire[41:]`
3. XOR self-cancellation replayed the body bytes verbatim

The server received identical encrypted body bytes as the original request.

## No Remaining Unknowns

All cryptographic parameters for constructing delegated requests are now known
and derived from credentials obtained during the normal session flow.

## Files

| File | Purpose |
|------|---------|
| `medianav_toolbox/protocol.py` | `build_dynamic_request()` |
| `tests/test_dynamic_wire.py` | 24 tests verifying all claims in this doc |
| `analysis/using-win32/run25_ssl/ssl_write_14_2218.bin` | Ground truth wire capture |
| `analysis/using-win32/hmac_log_run25_ssl.txt` | SnakeOil + HMAC log |
