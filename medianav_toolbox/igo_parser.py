"""igo-binary parser for NaviExtras wire protocol payloads.

The igo-binary format uses length-prefixed strings and structured markers.
Reversed from decrypted mitmproxy captures and http_dump XML files.

Ref: toolbox.md §2 (wire protocol), functions.md (serializer functions)
"""

import struct
from dataclasses import dataclass, field


@dataclass
class IgoBinaryReader:
    """Streaming reader for igo-binary data."""

    data: bytes
    pos: int = 0

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def peek_byte(self) -> int:
        return self.data[self.pos]

    def read_bytes(self, n: int) -> bytes:
        result = self.data[self.pos : self.pos + n]
        self.pos += n
        return result

    def read_uint16_be(self) -> int:
        val = struct.unpack_from(">H", self.data, self.pos)[0]
        self.pos += 2
        return val

    def read_uint32_be(self) -> int:
        val = struct.unpack_from(">I", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_int32_le(self) -> int:
        val = struct.unpack_from("<i", self.data, self.pos)[0]
        self.pos += 4
        return val

    def read_uint64_be(self) -> int:
        val = struct.unpack_from(">Q", self.data, self.pos)[0]
        self.pos += 8
        return val

    def read_string(self) -> str:
        """Read a length-prefixed, null-terminated string."""
        length = self.read_byte()
        raw = self.read_bytes(length)
        text = raw.decode("utf-8", errors="replace")
        if self.pos < len(self.data) and self.data[self.pos] == 0x00:
            self.pos += 1  # skip null terminator
        return text

    def expect(self, byte_val: int) -> None:
        actual = self.read_byte()
        if actual != byte_val:
            raise ValueError(
                f"Expected 0x{byte_val:02x} at offset {self.pos - 1}, got 0x{actual:02x}"
            )


def parse_boot_response(data: bytes) -> dict[str, str]:
    """Parse a boot response into a service name → URL map.

    Args:
        data: decrypted igo-binary payload (after SnakeOil decryption)

    Returns:
        Dict mapping service names to URLs, e.g. {"index": "https://...", "register": "https://..."}
    """
    r = IgoBinaryReader(data)
    r.expect(0x80)  # outer envelope

    # Skip header bytes (flags, timestamps) until the service list envelope at 0x80
    # The structure is: 80 [header bytes...] 80 [count] [type] [entries...]
    # Skip past the first 0x80 and any non-0x80 bytes, then find the NEXT 0x80
    found = False
    while r.remaining() > 2:
        b = r.peek_byte()
        if b == 0x80 and not found:
            # This might be a nested 0x80 flag — skip it and look for the real one
            r.read_byte()
            found = True
            continue
        if b == 0x80 and found:
            break
        r.read_byte()

    services = {}
    if r.remaining() > 2 and r.peek_byte() == 0x80:
        r.read_byte()  # service list envelope marker
        count = r.read_byte()
        entry_type = r.read_byte()

        for _ in range(count):
            if r.remaining() < 3:
                break
            name = r.read_string()
            if r.remaining() < 2:
                break
            url = r.read_string()
            services[name] = url

    return services


def parse_register_response(data: bytes) -> dict:
    """Parse a registration response to extract credentials.

    Args:
        data: decrypted igo-binary payload

    Returns:
        Dict with 'name' (str), 'code' (int), 'secret' (int), 'max_age' (int)
    """
    r = IgoBinaryReader(data)
    r.expect(0x80)  # envelope

    # The registration response contains:
    # [0xE0] [16 bytes Name] [8 bytes Code BE] [8 bytes Secret BE] [4 bytes MaxAge BE] ...
    marker = r.read_byte()

    # Name is 16 raw bytes, displayed as hex
    name_bytes = r.read_bytes(16)
    name = name_bytes.hex().upper()

    # Code and Secret as big-endian uint64
    code = r.read_uint64_be()
    secret = r.read_uint64_be()

    # MaxAge as big-endian uint32 (preceded by a null byte)
    if r.remaining() > 0 and r.peek_byte() == 0x00:
        r.read_byte()  # skip null separator
    max_age = r.read_uint32_be() if r.remaining() >= 4 else 0

    return {"name": name, "code": code, "secret": secret, "max_age": max_age}


def parse_model_list_response(data: bytes) -> list[dict]:
    """Parse a model list response to extract device models.

    Args:
        data: decrypted igo-binary payload

    Returns:
        List of dicts with 'name', 'display_name', 'brand_name' keys
    """
    r = IgoBinaryReader(data)
    r.expect(0x80)  # envelope
    r.expect(0x00)  # separator

    # Version string (e.g. "3.857")
    version = r.read_string()

    models = []
    while r.remaining() > 10:
        # Look for model entries — they start with 0xE9 marker
        if r.peek_byte() == 0x1E or r.peek_byte() == 0x22:
            # Skip the length/marker bytes before E9
            pass

        # Try to find the next string that looks like a model name
        # Model entries have: [marker bytes] [name_string] [display_name_string] [brand_string]
        try:
            # Scan for E9 marker
            while r.remaining() > 0 and r.peek_byte() != 0xE9:
                r.read_byte()
            if r.remaining() < 5:
                break
            r.read_byte()  # E9

            # Skip timestamp/version bytes
            r.read_bytes(4)  # 00 69 XX XX (timestamp)

            # Skip header bytes until we find string-like data
            while r.remaining() > 0:
                b = r.peek_byte()
                if 0x01 <= b <= 0x7F:
                    # Could be a string length — check if followed by printable chars
                    if r.pos + 1 + b <= len(r.data):
                        candidate = r.data[r.pos + 1 : r.pos + 1 + b]
                        if all(32 <= c < 127 for c in candidate):
                            break
                r.read_byte()

            if r.remaining() < 3:
                break

            # Skip any remaining non-string bytes
            while r.remaining() > 0 and r.peek_byte() == 0x00:
                r.read_byte()

            # Read model name, display name, brand name
            name = r.read_string()
            display_name = r.read_string()
            brand_name = r.read_string()

            if name and display_name:
                models.append(
                    {
                        "name": name,
                        "display_name": display_name,
                        "brand_name": brand_name,
                    }
                )
        except (IndexError, ValueError):
            break

    return models
