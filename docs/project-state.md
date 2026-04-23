# MediaNavToolbox Project State — 2026-04-24T00:18

## OBJECTIVE
Reverse-engineer and reimplement the MediaNav Toolbox wire protocol to dynamically generate delegated senddevicestatus requests without captured data.

## STATUS: DELEGATED WIRE FORMAT FULLY SOLVED

`build_dynamic_request()` in `protocol.py` generates complete wire requests from scratch. Verified byte-exact against captured run25 wire data. 24 tests in `test_dynamic_wire.py`.

## WIRE FORMAT (verified)
```
[16B header][1B prefix][snakeoil(query, session_key)][snakeoil(body, session_key)]
```
- Each snakeoil() call resets PRNG independently
- Body is standard plaintext format (NOT bitstream-encoded)
- Session key: `0x000ACAB6C9FB66F8` (fixed across runs, derivation unknown)

## CREDENTIALS
| Name | Value | Source |
|------|-------|--------|
| hu_code | 0x000BF28569BACB7C | get_delegator_credentials().code |
| hu_secret | 0x000EE87C16B1E812 | get_delegator_credentials().secret |
| tb_code | 0x000D4EA65D36B98E | Registration .code |
| session_key | 0x000ACAB6C9FB66F8 | Fixed (derivation unknown) |

## TEST STATUS
320 passed, 3 failed (integration/network only)

## REMAINING
1. Session key derivation (hardcoded)
2. session.py integration (still uses replay)
3. Live server 409s (server-side issue)
