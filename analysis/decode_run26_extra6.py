"""Decrypt run26 ssl_write files to extract extra_6 bytes from queries."""
import struct, sys, os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from medianav_toolbox.crypto import snakeoil

data_dir = Path("analysis/using-win32/run26_envelopes")

results = []
for f in sorted(data_dir.glob("ssl_write_*.bin")):
    raw = f.read_bytes()
    if len(raw) < 20 or raw[:4] != b'\x01\xC2\xC2\x30':
        continue
    key = struct.unpack(">Q", raw[4:12])[0]
    svc_minor = raw[12]
    payload = snakeoil(raw[16:], key)
    
    if len(payload) < 2:
        continue
    
    counter = payload[0]
    flags = payload[1]
    
    # Only interested in queries with extra_6 (flags 0x68 or 0x28)
    if flags not in (0x68, 0x28) or len(payload) < 25:
        continue
    
    extra_6 = payload[19:25]
    body_size = len(payload) - 25
    body_first4 = payload[25:29].hex() if len(payload) > 28 else "?"
    
    results.append({
        'file': f.name,
        'flags': flags,
        'counter': counter,
        'extra_6': extra_6.hex(),
        'body_size': body_size,
        'body_first4': body_first4,
        'key': key,
        'wire_size': len(raw),
    })

print(f"Found {len(results)} delegated queries")
print()
print(f"{'File':<30} {'Fl':>4} {'Cnt':>4} {'Extra6':<14} {'BodySz':>7} {'Body[0:4]':<10}")
print("-" * 80)
for r in results:
    print(f"{r['file']:<30} 0x{r['flags']:02X} 0x{r['counter']:02X} {r['extra_6']} {r['body_size']:>7} {r['body_first4']}")

# Check if extra_6 varies across requests with same flags
print()
by_flags = {}
for r in results:
    by_flags.setdefault(r['flags'], []).append(r)

for flags, group in sorted(by_flags.items()):
    extras = [r['extra_6'] for r in group]
    unique = set(extras)
    print(f"Flags 0x{flags:02X}: {len(group)} requests, {len(unique)} unique extra_6 values")
    for e in sorted(unique):
        count = extras.count(e)
        print(f"  {e} (×{count})")
