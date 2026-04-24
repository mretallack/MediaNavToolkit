# Tasks: MediaNav Toolbox Python Library

> Design: [design.md](design.md) | Docs: `docs/chain-encryption.md`, `docs/serializer.md`, `docs/reverse-engineering.md`

## Status Summary

**The delegated wire protocol is fully solved.** All cryptographic parameters are derived
from credentials obtained during the normal session flow. No captured data or hardcoded
values needed.

- Wire format: `[header][prefix][snakeoil(query, creds.secret)][snakeoil(body, creds.secret)]`
- Session key = `creds.secret` (toolbox Secret from registration)
- HMAC = `HMAC-MD5(hu_secret_BE, C4 + hu_code_BE + tb_code_BE + timestamp_BE)`
- Implementation: `build_dynamic_request()` in `protocol.py`
- Verified byte-exact against captured wire data (25 tests in `test_dynamic_wire.py`)
- 321+ unit tests passing

## Done ✅

- Full protocol reverse engineering (SnakeOil, wire format, credential encoding)
- `build_dynamic_request()` — generates delegated requests from scratch
- `session.py` — uses `build_dynamic_request` (no more captured chain bodies)
- USB drive detection, device.nng parsing, fingerprint management
- Device registration, authentication flow (boot → login → fingerprint → delegator)
- Catalog browsing (38 items), free content purchase, license installation
- CLI commands: detect, register, login, catalog, updates, licenses

## Remaining ❌

- [ ] **Map data file download** — sync handles selection + confirmation + license install,
  but actual map data download not implemented (getprocess polling + file transfer + .stm writing).
  Server only offers downloads when device reports older map versions.

## Key Files

| File | Purpose |
|------|---------|
| `medianav_toolbox/protocol.py` | `build_request()`, `build_dynamic_request()` |
| `medianav_toolbox/session.py` | End-to-end session flow |
| `medianav_toolbox/crypto.py` | SnakeOil xorshift128 cipher |
| `tests/test_dynamic_wire.py` | 25 tests verifying wire format |
| `docs/chain-encryption.md` | Source of truth for payload construction |
| `docs/serializer.md` | DLL serializer internals reference |
| `docs/reverse-engineering.md` | Full project documentation |
