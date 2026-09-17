"""BER-TLV reader: nesting, long-form lengths, multi-byte tags, damage."""

from __future__ import annotations

import pytest

from epassport.emrtd import tlv


def test_primitive_short_form() -> None:
    node = tlv.parse_one(bytes([0x5F, 0x1F, 0x03]) + b"ABC")
    assert node.tag == 0x5F1F
    assert node.tag_hex == "5F1F"
    assert not node.constructed
    assert node.value == b"ABC"


def test_constructed_nesting() -> None:
    inner = tlv.encode(0x5F1F, b"P<UTO")
    node = tlv.parse_one(tlv.encode(0x61, inner))
    assert node.constructed
    assert node.tag == 0x61
    assert [c.tag for c in node.children] == [0x5F1F]
    assert node.find(0x5F1F).value == b"P<UTO"
    assert node.find(0xDEAD) is None


def test_long_form_length() -> None:
    payload = b"\xab" * 300
    node = tlv.parse_one(tlv.encode(0x75, payload))
    assert len(node.value) == 300


def test_encode_length_boundaries() -> None:
    assert tlv.encode_length(0x7F) == b"\x7f"
    assert tlv.encode_length(0x80) == b"\x81\x80"
    assert tlv.encode_length(300) == b"\x82\x01\x2c"


def test_multiple_top_level_objects() -> None:
    buf = tlv.encode(0x5C, b"\x61\x75") + tlv.encode(0x5F01, b"0107")
    nodes = tlv.parse(buf)
    assert [n.tag for n in nodes] == [0x5C, 0x5F01]
    assert tlv.find_value(nodes, 0x5F01) == b"0107"


def test_padding_between_objects_is_skipped() -> None:
    buf = b"\x00\x00" + tlv.encode(0x5F1F, b"X") + b"\xff\xff"
    assert [n.tag for n in tlv.parse(buf)] == [0x5F1F]


def test_truncated_value_is_tolerated_by_default() -> None:
    buf = bytes([0x61, 0x20]) + b"\x5f\x1f\x03ABC"  # claims 32 bytes, has 7
    node = tlv.parse_one(buf)
    assert node.tag == 0x61
    assert node.find(0x5F1F).value == b"ABC"


def test_truncated_value_raises_in_strict_mode() -> None:
    with pytest.raises(tlv.TlvError):
        tlv.parse(bytes([0x61, 0x20]) + b"\x5f\x1f\x03ABC", strict=True)


def test_indefinite_length_rejected() -> None:
    with pytest.raises(tlv.TlvError):
        tlv.parse(b"\x61\x80\x00\x00", strict=True)


def test_empty_buffer() -> None:
    assert tlv.parse(b"") == []
    with pytest.raises(tlv.TlvError):
        tlv.parse_one(b"")


def test_text_decoding_never_raises() -> None:
    assert tlv.text(b"ANNA\x00") == "ANNA"
    assert tlv.text(b"\xff\xfe") == "ÿþ"
    assert tlv.text(None) == ""
    assert tlv.text(b"M\xc3\xbcller") == "Müller"


def test_walk_and_dump() -> None:
    buf = tlv.encode(0x6B, tlv.encode(0x5C, b"\x5f\x0e") + tlv.encode(0x5F0E, b"ANNA"))
    node = tlv.parse_one(buf)
    assert [n.tag for n in node.walk()] == [0x6B, 0x5C, 0x5F0E]
    assert "5F0E" in node.dump()
    assert len(node.find_all(0x5F0E)) == 1
