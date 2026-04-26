"""Decode gap area using the NNG tagged record format from DLL analysis.

Based on FUN_10240e80 switch cases:
  type = byte & 0x7F
  flag = byte >> 7
  Case 0: END
  Case 1: read 4 bytes (int32)
  Case 2: read 8 bytes (coord pair: lon + lat as int32)
  Case 3: read 1 byte (length?), then variable data
  Case 4: read 1 byte (length?), then variable data  
  Case 5: read 8 bytes (raw data)
  Case 6,8: call FUN_10242060 — reads uint32 count, then count*8 bytes of pairs
  Case 7,0x12: read uint32 count, then count nested records (recursive)

FUN_10242060 reads: uint32 count, then for each: call FUN_10240e80 (nested record)
FUN_10242e10 reads: 4 bytes from stream (uint32)
FUN_10242e60 reads: 1 byte from stream
"""
import struct
import sys
from pathlib import Path

XOR_TABLE_PATH = "analysis/xor_table_normal.bin"
SCALE = 2**23


class Stream:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    
    def read_bytes(self, n):
        if self.pos + n > len(self.data):
            return None
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result
    
    def read_u8(self):
        b = self.read_bytes(1)
        return b[0] if b else None
    
    def read_u16(self):
        b = self.read_bytes(2)
        return struct.unpack('<H', b)[0] if b else None
    
    def read_u32(self):
        b = self.read_bytes(4)
        return struct.unpack('<I', b)[0] if b else None
    
    def read_i32(self):
        b = self.read_bytes(4)
        return struct.unpack('<i', b)[0] if b else None
    
    @property
    def remaining(self):
        return len(self.data) - self.pos


def read_record(stream, depth=0):
    """Read one tagged record from the stream."""
    if stream.remaining < 1:
        return None
    
    byte = stream.read_u8()
    rtype = byte & 0x7F
    flag = byte >> 7
    indent = "  " * depth
    start_pos = stream.pos - 1
    
    if rtype == 0:
        return {'type': 'END', 'flag': flag, 'pos': start_pos}
    
    elif rtype == 1:
        val = stream.read_i32()
        if val is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        return {'type': 'INT32', 'flag': flag, 'value': val, 'pos': start_pos}
    
    elif rtype == 2:
        lon = stream.read_i32()
        lat = stream.read_i32()
        if lon is None or lat is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        return {'type': 'COORD', 'flag': flag, 'lon': lon, 'lat': lat,
                'lon_deg': lon / SCALE, 'lat_deg': lat / SCALE, 'pos': start_pos}
    
    elif rtype in (3, 4):
        length_byte = stream.read_u8()
        if length_byte is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        return {'type': f'VAR{rtype}', 'flag': flag, 'length': length_byte, 'pos': start_pos}
    
    elif rtype == 5:
        raw = stream.read_bytes(8)
        if raw is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        return {'type': 'RAW8', 'flag': flag, 'data': raw, 'pos': start_pos}
    
    elif rtype in (6, 8):
        # FUN_10242060: read uint32 count, then count records
        count = stream.read_u32()
        if count is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        children = []
        for i in range(min(count, 1000)):
            child = read_record(stream, depth + 1)
            if child is None or child['type'] == 'END':
                break
            children.append(child)
        return {'type': f'ARRAY{rtype}', 'flag': flag, 'count': count,
                'children': children, 'pos': start_pos}
    
    elif rtype in (7, 0x12):
        count = stream.read_u32()
        if count is None:
            return {'type': 'TRUNCATED', 'pos': start_pos}
        children = []
        for i in range(min(count, 1000)):
            # Read key-value pair (two records per entry)
            key = read_record(stream, depth + 1)
            if key is None or key['type'] == 'END':
                break
            val = read_record(stream, depth + 1)
            if val is None or val['type'] == 'END':
                children.append(key)
                break
            children.append({'key': key, 'value': val})
        return {'type': f'GROUP{rtype}', 'flag': flag, 'count': count,
                'children': children, 'pos': start_pos}
    
    else:
        return {'type': f'UNKNOWN_{rtype}', 'flag': flag, 'byte': byte, 'pos': start_pos}


def print_record(rec, depth=0):
    indent = "  " * depth
    pos = rec.get('pos', '?')
    flag = rec.get('flag', 0)
    
    if rec['type'] == 'END':
        print(f"{indent}[@{pos:4d}] END")
    elif rec['type'] == 'INT32':
        print(f"{indent}[@{pos:4d}] INT32 flag={flag}: {rec['value']} (0x{rec['value'] & 0xFFFFFFFF:08x})")
    elif rec['type'] == 'COORD':
        print(f"{indent}[@{pos:4d}] COORD flag={flag}: ({rec['lon_deg']:.6f}, {rec['lat_deg']:.6f})")
    elif rec['type'] == 'RAW8':
        print(f"{indent}[@{pos:4d}] RAW8  flag={flag}: {rec['data'].hex(' ')}")
    elif rec['type'].startswith('VAR'):
        print(f"{indent}[@{pos:4d}] {rec['type']} flag={flag}: length={rec['length']}")
    elif rec['type'].startswith('ARRAY') or rec['type'].startswith('GROUP'):
        print(f"{indent}[@{pos:4d}] {rec['type']} flag={flag}: count={rec['count']}")
        for child in rec.get('children', []):
            if isinstance(child, dict) and 'key' in child:
                print_record(child['key'], depth + 1)
                print_record(child['value'], depth + 1)
            else:
                print_record(child, depth + 1)
    elif rec['type'].startswith('UNKNOWN'):
        print(f"{indent}[@{pos:4d}] {rec['type']} flag={flag} byte=0x{rec['byte']:02x}")
    elif rec['type'] == 'TRUNCATED':
        print(f"{indent}[@{pos:4d}] TRUNCATED")


def decrypt_fbl(fbl_path):
    xor_table = Path(XOR_TABLE_PATH).read_bytes()
    data = Path(fbl_path).read_bytes()
    return bytes(data[i] ^ xor_table[i % len(xor_table)] for i in range(len(data)))


def main():
    fbl_path = sys.argv[1] if len(sys.argv) > 1 else "tools/maps/testdata/Vatican_osm.fbl"
    
    dec = decrypt_fbl(fbl_path)
    sec0 = struct.unpack_from('<I', dec, 0x048E)[0]
    
    # Try different start positions in the gap area
    starts = []
    
    # 1. Start of bitstream (after 000 separator)
    for off in range(0x0580, min(0x0600, sec0)):
        if dec[off] == 0 and dec[off+1] == 0 and dec[off+2] == 0 and dec[off+3] != 0:
            window = dec[off+3:off+19]
            if len(set(window)) > 10:
                starts.append(('bitstream', off + 3))
                break
    
    # 2. Start of gap area
    starts.append(('gap_start', 0x04DE))
    
    # 3. After the fixed header
    starts.append(('after_header', 0x0565))
    
    # 4. After the count field
    starts.append(('after_count', 0x0565))
    
    # 5. After the 4D marker
    gap = dec[0x04DE:sec0]
    for i in range(len(gap)-5):
        if gap[i] == 0x4D and gap[i+1] == 0 and gap[i+2] == 0 and gap[i+3] == 0 and gap[i+4] == 3:
            starts.append(('after_4D', 0x04DE + i + 7))
            break
    
    print(f"=== NNG Tagged Record Decoder ===")
    print(f"File: {fbl_path}")
    print(f"Gap: 0x04DE to 0x{sec0:04x} ({sec0 - 0x04DE} bytes)")
    
    for label, start_off in starts:
        data = dec[start_off:sec0]
        stream = Stream(data)
        
        print(f"\n{'='*60}")
        print(f"Starting from 0x{start_off:04x} ({label}), {len(data)} bytes")
        print(f"First 8 bytes: {data[:8].hex(' ')}")
        print(f"{'='*60}")
        
        records = []
        unknown_count = 0
        for i in range(30):
            if stream.remaining < 1:
                break
            rec = read_record(stream)
            if rec is None:
                break
            records.append(rec)
            print_record(rec)
            
            if rec['type'] == 'END':
                break
            if rec['type'].startswith('UNKNOWN'):
                unknown_count += 1
                if unknown_count > 5:
                    print("  (too many unknowns, stopping)")
                    break
        
        consumed = stream.pos
        print(f"\n  Records: {len(records)}, Consumed: {consumed}/{len(data)} bytes")
        
        # Count valid vs unknown
        valid = sum(1 for r in records if not r['type'].startswith('UNKNOWN'))
        print(f"  Valid: {valid}, Unknown: {len(records) - valid}")


if __name__ == "__main__":
    main()
