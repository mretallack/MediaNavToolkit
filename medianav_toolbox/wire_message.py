"""Decode and encode complete delegated wire messages.

Provides WireMessage — a structured representation of every field in a
delegated senddevicestatus wire message. Can decode captured wire bytes
and re-encode from structured fields, enabling golden-test verification.

Usage:
    msg = WireMessage.decode(wire_bytes, session_key)
    assert msg.header.tb_code == 0x000D4EA65D36B98E
    assert msg.query.hmac_valid

    # Re-encode with different timestamp
    msg.query.timestamp = int(time.time())
    msg.query.recompute_hmac()
    new_wire = msg.encode()
"""

import hashlib
import hmac as hmac_mod
import struct
from dataclasses import dataclass, field

from medianav_toolbox.crypto import snakeoil


@dataclass
class Header:
    version: int = 0x01
    magic: bytes = b"\xC2\xC2"
    auth_mode: int = 0x30
    tb_code: int = 0
    svc_minor: int = 0x19
    reserved: int = 0
    session_id: int = 0

    def encode(self) -> bytes:
        return struct.pack(
            ">BBBB Q B HB",
            self.version, self.magic[0], self.magic[1], self.auth_mode,
            self.tb_code, self.svc_minor, self.reserved, self.session_id,
        )

    @classmethod
    def decode(cls, data: bytes) -> "Header":
        v, m1, m2, am = data[0], data[1], data[2], data[3]
        code = struct.unpack(">Q", data[4:12])[0]
        svc = data[12]
        res = struct.unpack(">H", data[13:15])[0]
        sid = data[15]
        return cls(v, bytes([m1, m2]), am, code, svc, res, sid)


@dataclass
class Query:
    flags: int = 0x08
    format: int = 0x80
    cred_type: int = 0xC4
    hu_code: int = 0
    tb_code: int = 0
    timestamp: int = 0
    separator: bytes = b"\x30\x10"
    hmac: bytes = b""
    tb_name: bytes | None = None  # 16B, present when flags & 0x40

    # For HMAC verification
    hu_secret: int = 0

    @property
    def credential_data(self) -> bytes:
        return (
            bytes([self.cred_type])
            + struct.pack(">Q", self.hu_code)
            + struct.pack(">Q", self.tb_code)
            + struct.pack(">I", self.timestamp)
        )

    @property
    def hmac_valid(self) -> bool:
        if not self.hu_secret:
            return False
        expected = hmac_mod.new(
            struct.pack(">Q", self.hu_secret),
            self.credential_data, hashlib.md5,
        ).digest()
        return self.hmac == expected

    def recompute_hmac(self):
        self.hmac = hmac_mod.new(
            struct.pack(">Q", self.hu_secret),
            self.credential_data, hashlib.md5,
        ).digest()

    def encode(self) -> bytes:
        parts = [bytes([self.flags, self.format])]
        if self.tb_name is not None:
            parts.append(self.tb_name[:16])
            parts.append(b"\x80")
        parts.append(self.credential_data)
        parts.append(self.separator)
        parts.append(self.hmac)
        return b"".join(parts)

    @classmethod
    def decode(cls, data: bytes) -> "Query":
        q = cls()
        q.flags = data[0]
        q.format = data[1]
        pos = 2
        if q.flags & 0x40:
            q.tb_name = data[pos:pos + 16]
            pos += 17  # 16B name + 0x80 separator
        q.cred_type = data[pos]
        q.hu_code = struct.unpack(">Q", data[pos + 1:pos + 9])[0]
        q.tb_code = struct.unpack(">Q", data[pos + 9:pos + 17])[0]
        q.timestamp = struct.unpack(">I", data[pos + 17:pos + 21])[0]
        q.separator = data[pos + 21:pos + 23]
        q.hmac = data[pos + 23:pos + 39]
        return q


@dataclass
class BodyField:
    """A single field from the body."""
    name: str
    value: object
    raw: bytes  # original bytes for this field


@dataclass
class Body:
    marker: int = 0xD8
    variant: int = 0x03
    bitmask: bytes = b"\x1E\x40"
    brand_name: str = ""
    model_name: str = ""
    swid: str = ""
    imei: str = ""
    igo_version: str = ""
    first_use: int = 0
    padding_4b: bytes = b"\x00\x00\x00\x00"
    appcid: int = 0
    serial: str = ""
    raw: bytes = b""  # full raw body for passthrough

    @classmethod
    def decode(cls, data: bytes) -> "Body":
        b = cls()
        b.raw = data
        b.marker = data[0]
        b.variant = data[1]
        b.bitmask = data[2:4]
        pos = 4

        def read_str(p):
            length = data[p]
            return data[p + 1:p + 1 + length].decode("ascii", errors="replace"), p + 1 + length

        b.brand_name, pos = read_str(pos)
        b.model_name, pos = read_str(pos)
        b.swid, pos = read_str(pos)
        b.imei, pos = read_str(pos)
        b.igo_version, pos = read_str(pos)
        b.first_use = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        b.padding_4b = data[pos:pos + 4]
        pos += 4
        b.appcid = struct.unpack(">I", data[pos:pos + 4])[0]
        pos += 4
        b.serial, pos = read_str(pos)
        return b

    def encode(self) -> bytes:
        """Re-encode from raw bytes (passthrough)."""
        return self.raw


@dataclass
class WireMessage:
    header: Header = field(default_factory=Header)
    prefix_plain: int = 0xE9
    query: Query = field(default_factory=Query)
    body: Body = field(default_factory=Body)
    session_key: int = 0
    body_raw: bytes = b""  # raw plaintext body for re-encoding

    def encode(self) -> bytes:
        """Encode to wire bytes."""
        h = self.header.encode()
        prefix = snakeoil(bytes([self.prefix_plain]), self.session_key)
        eq = snakeoil(self.query.encode(), self.session_key)
        eb = snakeoil(self.body_raw, self.session_key)
        return h + prefix + eq + eb

    @classmethod
    def decode(cls, wire: bytes, session_key: int, hu_secret: int = 0) -> "WireMessage":
        msg = cls()
        msg.session_key = session_key
        msg.header = Header.decode(wire[:16])
        msg.prefix_plain = snakeoil(wire[16:17], session_key)[0]

        # Determine query size from prefix
        query_size = 41
        query_plain = snakeoil(wire[17:17 + query_size], session_key)
        if query_plain[0] & 0x40:  # name present
            query_size = 58
            query_plain = snakeoil(wire[17:17 + query_size], session_key)

        msg.query = Query.decode(query_plain)
        msg.query.hu_secret = hu_secret

        body_start = 16 + 1 + query_size
        msg.body_raw = snakeoil(wire[body_start:], session_key)
        msg.body = Body.decode(msg.body_raw)
        return msg

    def summary(self) -> str:
        lines = [
            "=== Wire Message ===",
            f"Header: version=0x{self.header.version:02X} mode=0x{self.header.auth_mode:02X} "
            f"tb_code=0x{self.header.tb_code:016X} svc=0x{self.header.svc_minor:02X} "
            f"sid=0x{self.header.session_id:02X}",
            f"Prefix: 0x{self.prefix_plain:02X}",
            f"Query: flags=0x{self.query.flags:02X} format=0x{self.query.format:02X} "
            f"name={'yes' if self.query.tb_name else 'no'}",
            f"  hu_code=0x{self.query.hu_code:016X}",
            f"  tb_code=0x{self.query.tb_code:016X}",
            f"  timestamp=0x{self.query.timestamp:08X} ({self.query.timestamp})",
            f"  separator={self.query.separator.hex()}",
            f"  hmac={self.query.hmac.hex()}",
            f"  hmac_valid={self.query.hmac_valid}",
            f"Body: {len(self.body_raw)}B marker=0x{self.body.marker:02X} "
            f"variant=0x{self.body.variant:02X} bitmask={self.body.bitmask.hex()}",
            f"  brand={self.body.brand_name}",
            f"  model={self.body.model_name}",
            f"  swid={self.body.swid}",
            f"  imei={self.body.imei}",
            f"  version={self.body.igo_version}",
            f"  first_use=0x{self.body.first_use:08X}",
            f"  appcid=0x{self.body.appcid:08X}",
            f"  serial={self.body.serial}",
        ]
        return "\n".join(lines)
