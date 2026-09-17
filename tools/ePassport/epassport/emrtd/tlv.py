"""Minimal BER-TLV reader for eMRTD data groups.

Deliberately dependency-free: eMRTD LDS files are plain BER-TLV and the
structures we care about are shallow.  Anything malformed degrades to a
partial parse rather than an exception, because real dumps are sometimes
truncated when a card is pulled out of the field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Sequence


class TlvError(ValueError):
    """Raised when a buffer cannot be parsed as BER-TLV at all."""


@dataclass
class Tlv:
    """One BER-TLV node.

    ``tag`` keeps the full encoded tag as an int (``0x5F1F`` stays 0x5F1F).
    Constructed nodes carry ``children``; primitive nodes carry ``value``.
    """

    tag: int
    value: bytes
    constructed: bool
    children: list["Tlv"] = field(default_factory=list)
    offset: int = 0

    @property
    def tag_hex(self) -> str:
        n = self.tag
        width = 2
        while n >= 1 << (width * 4):
            width += 2
        return f"{n:0{width}X}"

    def find(self, tag: int) -> "Tlv | None":
        """Depth-first search for the first node with ``tag``."""
        for node in self.walk():
            if node.tag == tag:
                return node
        return None

    def find_all(self, tag: int) -> list["Tlv"]:
        return [node for node in self.walk() if node.tag == tag]

    def walk(self) -> Iterator["Tlv"]:
        yield self
        for child in self.children:
            yield from child.walk()

    def dump(self, indent: int = 0) -> str:
        pad = "  " * indent
        if self.constructed:
            head = f"{pad}{self.tag_hex} [{len(self.value)}] {{"
            body = "\n".join(c.dump(indent + 1) for c in self.children)
            return f"{head}\n{body}\n{pad}}}" if body else f"{head}}}"
        preview = self.value[:24].hex().upper()
        if len(self.value) > 24:
            preview += "..."
        return f"{pad}{self.tag_hex} [{len(self.value)}] {preview}"


def _read_tag(buf: bytes, pos: int) -> tuple[int, bool, int]:
    """Return ``(tag, constructed, new_pos)``."""
    if pos >= len(buf):
        raise TlvError("truncated tag")
    first = buf[pos]
    tag = first
    pos += 1
    constructed = bool(first & 0x20)
    if first & 0x1F == 0x1F:  # multi-byte tag
        while True:
            if pos >= len(buf):
                raise TlvError("truncated multi-byte tag")
            b = buf[pos]
            tag = (tag << 8) | b
            pos += 1
            if not b & 0x80:
                break
            if tag > 0xFFFFFFFF:
                raise TlvError("tag too long")
    return tag, constructed, pos


def _read_length(buf: bytes, pos: int) -> tuple[int, int]:
    """Return ``(length, new_pos)``.  Indefinite length is rejected."""
    if pos >= len(buf):
        raise TlvError("truncated length")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    n = first & 0x7F
    if n == 0:
        raise TlvError("indefinite length not supported")
    if n > 4:
        raise TlvError(f"length field of {n} bytes is unreasonable")
    if pos + n > len(buf):
        raise TlvError("truncated long-form length")
    length = int.from_bytes(buf[pos : pos + n], "big")
    return length, pos + n


def parse(buf: bytes | bytearray, *, strict: bool = False) -> list[Tlv]:
    """Parse a whole buffer into a list of top-level TLV nodes.

    With ``strict=False`` (the default) a trailing garbage/truncation stops
    the parse and returns what was decoded so far.
    """
    data = bytes(buf)
    out: list[Tlv] = []
    pos = 0
    while pos < len(data):
        # Skip 0x00 / 0xFF padding between objects.
        if data[pos] in (0x00, 0xFF):
            pos += 1
            continue
        start = pos
        try:
            tag, constructed, pos = _read_tag(data, pos)
            length, pos = _read_length(data, pos)
        except TlvError:
            if strict:
                raise
            break
        end = pos + length
        if end > len(data):
            if strict:
                raise TlvError(
                    f"tag {tag:X} claims {length} bytes, buffer has {len(data) - pos}"
                )
            end = len(data)
        value = data[pos:end]
        node = Tlv(tag=tag, value=value, constructed=constructed, offset=start)
        if constructed:
            node.children = parse(value, strict=strict)
        out.append(node)
        pos = end
    return out


def parse_one(buf: bytes | bytearray, *, strict: bool = False) -> Tlv:
    """Parse and return the single expected top-level node."""
    nodes = parse(buf, strict=strict)
    if not nodes:
        raise TlvError("empty TLV buffer")
    return nodes[0]


def find(nodes: Sequence[Tlv], tag: int) -> Tlv | None:
    for node in nodes:
        hit = node.find(tag)
        if hit is not None:
            return hit
    return None


def find_value(nodes: Sequence[Tlv], tag: int) -> bytes | None:
    hit = find(nodes, tag)
    return None if hit is None else hit.value


def text(value: bytes | None) -> str:
    """Decode an LDS text field.  Falls back to latin-1, never raises."""
    if not value:
        return ""
    try:
        return value.decode("utf-8").rstrip("\x00").strip()
    except UnicodeDecodeError:
        return value.decode("latin-1").rstrip("\x00").strip()


def encode_tag(tag: int) -> bytes:
    length = 1
    while tag >= 1 << (length * 8):
        length += 1
    return tag.to_bytes(length, "big")


def encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def encode(tag: int, value: bytes) -> bytes:
    """Build a TLV.  Used by the sample-dump generator and the tests."""
    return encode_tag(tag) + encode_length(len(value)) + value
