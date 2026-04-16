# Design: MediaNav Toolbox Python Library

> **Reverse engineering reference:** See [toolbox.md](toolbox.md) for protocol details, encryption keys, and data source locations.
> **Function reference:** See [functions.md](functions.md) for annotated Ghidra function map.

---

## 1. Library Architecture

Existing modules (✓) and planned modules (○):

```
┌──────────────────────────────────────────────────────────────┐
│                      CLI ✓ (cli.py)                          │
│  detect │ register │ catalog │ download │ install │ sync     │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│              medianav_toolbox (public API) ✓ (__init__.py)    │
│                                                              │
│  Toolbox(usb_path)                                           │
│    .detect_device() → DeviceInfo                             │
│    .boot()          → ServiceEndpoints                       │
│    .register()      → Credentials                            │
│    .login()         → Session                                │
│    .catalog()       → list[ContentItem]                      │
│    .download()      → list[Path]                             │
│    .install()       → InstallResult                          │
│    .sync()          → SyncResult  (full pipeline)            │
└──────────────────────┬───────────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────────┐
│                    Internal Modules                           │
│                                                              │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────────────────┐│
│  │ device.py ✓ │ │ protocol.py ○│ │ api/ ✓                 ││
│  │ device.nng  │ │ SnakeOil     │ │  client.py ✓           ││
│  │ brand.txt   │ │ Envelope     │ │  boot.py ✓ (needs redo)││
│  │ APPCID      │ │              │ │  register.py ✓ (stubs) ││
│  │ XOR decode  │ │ crypto.py ○  │ │  market.py ✓ (stubs)   ││
│  └─────────────┘ │ SnakeOil     │ │  catalog.py ✓ (stubs)  ││
│  ┌─────────────┐ │ Blowfish     │ │  igo_binary.py ✓       ││
│  │ config.py ✓ │ │ NNGE / MD5   │ └────────────────────────┘│
│  │ models.py ✓ │ └──────────────┘ ┌────────────────────────┐│
│  │ auth.py ✓   │ ┌──────────────┐ │ installer.py ✓ (stub)  ││
│  └─────────────┘ │ download.py ✓│ │ USB layout             ││
│  ┌─────────────┐ │ (stub)       │ │ .lyc/.stm/.md5         ││
│  │fingerprint  │ │ Cache        │ └────────────────────────┘│
│  │  .py ✓      │ │ Resume       │                           │
│  │ Read/build  │ │ MD5 verify   │                           │
│  └─────────────┘ └──────────────┘                           │
└──────────────────────────────────────────────────────────────┘
```

**Status**: `protocol.py` and `crypto.py` are implemented and tested. Query and body are encrypted as separate SnakeOil streams (DEVICE mode: Code for query, Secret for body). The `api/` modules have working boot (v2 JSON + v3 wire), device registration (wire protocol returning DeviceCredentials), and market login (wire protocol). Request bodies use a simple length-prefixed format (`wire_codec.py`), verified byte-for-byte against captured traffic.

**CRITICAL**: Wire protocol requests must NOT include a `Content-Type` HTTP header — the server returns HTTP 500 if it's present. Only `User-Agent` (format: `DaciaAutomotive-Toolbox-{version}`) is required. Header byte 15 is a random per-session nonce, not a fixed value.

**End-to-end session flow** (`session.py`): boot → register (cached creds from `.medianav_creds.json`) → login → sendfingerprint → getprocess. Login and getprocess confirmed working against live API. Market calls go to `https://dacia-ulc.naviextras.com/rest/1/` (brand-specific URL), not the index URL from boot. Credentials (Code/Secret) are permanent and stored in `service_register_v1.sav` by the Windows Toolbox.

---

## 2. Protocol Layer (`protocol.py`)

### Envelope

```python
@dataclass
class ProtocolEnvelope:
    version: int = 1                    # always 1
    auth_mode: int = 0x20               # 0x20=unauthenticated, 0x30=authenticated
    snakeoil_key: int = 0               # 8-byte key (random or Credentials.Code)
    service_minor: int = 0              # 1=index, 14=register, 25=market

    def serialize_request_header(self) -> bytes:
        """Build the 16-byte request header."""
        return struct.pack('>BBBBx Q B HB',
            self.version,               # 0x01
            0xC2, 0xC2,                 # envelope marker
            self.auth_mode,             # 0x20 or 0x30
            self.snakeoil_key,          # 8-byte key (Code for DEVICE, random for RANDOM)
            self.service_minor,         # service version
            0x0000,                     # padding
            0x3F                        # end marker
        )

    @staticmethod
    def parse_response_header(data: bytes) -> tuple[int, bytes]:
        """Parse 4-byte response header. Returns (mode_byte, encrypted_payload)."""
        assert data[0] == 0x01 and data[1] == 0x00 and data[2] == 0xC2
        return data[3], data[4:]
```

### SnakeOil Cipher (FULLY REVERSED)

```python
class SnakeOil:
    """xorshift128 PRNG stream cipher.

    Reversed from FUN_101b3e10 in nngine.dll.
    Symmetric: encrypt and decrypt are the same XOR operation.

    Key management (split query/body encryption):
    - RANDOM mode: query and body both use random seed, but as SEPARATE SnakeOil streams
    - DEVICE mode: query seed = Code, body seed = Secret (response also uses Secret)
    """
    M = 0xFFFFFFFF

    def __init__(self, seed: int):
        """seed: uint64 PRNG seed (the Secret for DEVICE mode, or the random key for RANDOM)."""
        self.key_lo = seed & self.M
        self.key_hi = (seed >> 32) & self.M

    def process(self, data: bytes) -> bytes:
        """Encrypt or decrypt (symmetric XOR)."""
        M = self.M
        result = bytearray(len(data))
        eax, esi = self.key_lo, self.key_hi
        for i in range(len(data)):
            edx = (((esi << 21) | (eax >> 11)) ^ esi) & M
            ecx = (((eax << 21) & M) ^ eax) & M
            ecx = (ecx ^ (edx >> 3)) & M
            esi = ((((edx << 4) | (ecx >> 28)) & M) ^ edx) & M
            eax = (((ecx << 4) & M) ^ ecx) & M
            result[i] = data[i] ^ (((esi << 32) | eax) >> 23) & 0xFF
        return bytes(result)
```

### igo-binary Serialization

| Tag | Type | Encoding |
|-----|------|----------|
| 0x01 | int32 | `<Bi` (tag + LE int32) |
| 0x02 | byte/bool | `BB` (tag + byte) |
| 0x03 | int16 | `<Bh` (tag + LE int16) |
| 0x04 | int64 | `<Bq` (tag + LE int64) |
| 0x05 | string | tag + UTF-8 bytes + 0x00 |
| 0x80 0x00 | envelope | start of message |

---

## 3. Device Detection (`device.py`)

```python
@dataclass
class DeviceInfo:
    brand: str              # from NaviSync/content/brand.txt ("dacia")
    brand_md5: str          # MD5 of brand.txt content
    appcid: int             # from device.nng NNGE header offset 0x5C
    device_nng_path: Path

def detect_device(usb_path: Path) -> DeviceInfo:
    brand = (usb_path / "NaviSync/content/brand.txt").read_text().strip()
    device_nng = (usb_path / "NaviSync/license/device.nng").read_bytes()
    appcid = struct.unpack_from('<I', device_nng, 0x5C)[0]
    brand_md5 = hashlib.md5(brand.encode()).hexdigest()
    return DeviceInfo(brand=brand, brand_md5=brand_md5, appcid=appcid, ...)
```

---

## 4. SWID Generation (`swid.py`)

```python
def compute_swid() -> str:
    """CK-XXXX-XXXX-XXXX-XXXX from PC drive serial."""
    serial = get_drive_serial()
    salted = f"SPEEDx{serial}CAM"
    md5 = hashlib.md5(salted.encode()).digest()
    return format_swid(md5)
```

---

## 5. API Client (`api/`)

### Boot (`api/boot.py`)

```python
def boot(session: Session) -> dict[str, str]:
    """POST /services/index/rest/3/boot → service URL map
    Uses RANDOM mode SnakeOil."""
```

### Register (`api/register.py`)

```python
@dataclass
class Credentials:
    name: str       # "FB86ACD6EBA8F54A93C4286CE077D06C"
    code: int       # 3745651132643726 (goes in wire header for DEVICE mode)
    secret: int     # 3037636188661496 (PRNG seed for DEVICE mode)

def register_device(session: Session, device: DeviceInfo, swid: str) -> Credentials:
    """POST /services/register/rest/1/device
    Uses RANDOM mode SnakeOil.
    Sends: BrandName, ModelName, Swid, Imei, IgoVersion, FirstUse, Appcid, UniqId
    Returns: Credentials (Name, Code, Secret)
    """
```

### Market Login (`api/market.py`)

```python
def login(session: Session, credentials: Credentials) -> MarketSession:
    """POST /rest/1/login (on dacia-ulc.naviextras.com)
    Uses DEVICE mode SnakeOil (Code in header AND as request seed, Secret for response)."""
```

---

## 6. Crypto Utilities (`crypto.py`)

```python
# SnakeOil — fully reversed
def snakeoil(data: bytes, seed: int) -> bytes:
    """xorshift128 PRNG stream cipher. Symmetric encrypt/decrypt."""
    ...

# Blowfish for http_dump decryption
BLOWFISH_KEY = bytes.fromhex('b0caba3df8a23194f2a22f59cd0b39ab')

def decrypt_http_dump(path: Path) -> bytes:
    cipher = Blowfish.new(BLOWFISH_KEY, Blowfish.MODE_ECB)
    return cipher.decrypt(path.read_bytes())

# NNGE decryption (device.nng) — not yet reversed
NNGE_KEY = b'm0$7j0n4(0n73n71I)'
NNGE_TEMPLATE = b'ZXXXXXXXXXXXXXXXXXXZ'
```

---

## 7. Implementation Priority

### Phase 1: Offline tools (no server communication)
1. `device.py` — parse USB drive, extract APPCID, brand
2. `crypto.py` — SnakeOil cipher, Blowfish http_dump decryption
3. `swid.py` — SWID computation
4. `protocol.py` — envelope serialization, igo-binary parser

### Phase 2: Server communication
5. `api/boot.py` — service URL discovery (RANDOM mode)
6. `api/register.py` — device registration (RANDOM mode → get Credentials)
7. `api/market.py` — login, fingerprint, catalog (DEVICE mode)

### Phase 3: Full update pipeline
8. `download.py` — content download with resume and MD5 verify
9. `installer.py` — write updates to USB drive (.lyc, .stm, .md5 files)

---

## 8. Remaining Work

1. ~~**igo-binary parser**~~ — **DONE**: Parser implemented for boot, register, and model list responses.

2. ~~**DEVICE mode request encryption**~~ — **SOLVED**: Request seed = Code, response seed = Secret. Verified against live server.

3. ~~**igo-binary request body encoder**~~ — **SOLVED**: Request bodies use the same igo-binary tagged format as responses. The body was encrypted separately from the query (DEVICE mode: query with Code, body with Secret; RANDOM mode: both with random seed, separate PRNG state). No custom bitstream serializer needed.

4. **NNGE decryption** — device.nng uses key `m0$7j0n4(0n73n71I)` with template `ZXXXXXXXXXXXXXXXXXXZ`. Not yet reversed.

5. ~~**SWID format_swid()**~~ — **SOLVED**: Crockford base32 encoding of first 10 bytes of MD5("SPEEDx{serial}CAM"). Implemented in `swid.py`.

6. **Credential block XOR key universality** — Unknown whether `IGO_CREDENTIAL_KEY` is the same for all devices. Needs testing with a second device.

7. **Content download and installation** — Download manager and USB installer are stubs.
