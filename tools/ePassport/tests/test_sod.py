"""EF_SOD structure decoding, including the shapes real documents use."""

from __future__ import annotations

from pathlib import Path

import pytest

from epassport.emrtd import dg
from epassport.emrtd.sod import parse_sod


def _raw(directory: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for name, _tag, _note, _eac in dg.DG_FILES:
        _path, data = dg.read_dump_file(directory, name)
        if data:
            out[name] = data
    return out


def test_data_group_hash_values_is_a_sequence_of_not_a_set_of(td3: Path) -> None:
    """ICAO 9303 part 10 says SEQUENCE OF.

    Decoding it as SET OF makes every real EF_SOD fail with "tag should have
    been 17, but 16 was found", while a synthetic file encoded the same wrong
    way still parses - so this is asserted against the raw DER.
    """
    from asn1crypto import cms

    from epassport.emrtd import tlv

    data = (td3 / "EF_SOD.bin").read_bytes()
    payload = tlv.parse(data)[0].value
    lds_der = cms.ContentInfo.load(payload)["content"]["encap_content_info"][
        "content"
    ].native

    # Walk the outer SEQUENCE to the third element and check its tag byte.
    assert lds_der[0] == 0x30, "LDSSecurityObject is a SEQUENCE"
    offset = 2 if lds_der[1] < 0x80 else 2 + (lds_der[1] & 0x7F)
    offset += 3  # version: 02 01 xx
    assert lds_der[offset] == 0x30, "hashAlgorithm is a SEQUENCE"
    offset += 2 + lds_der[offset + 1]
    assert lds_der[offset] == 0x30, "dataGroupHashValues must be tagged SEQUENCE (0x30)"


def test_sod_reports_every_data_group_hash(td3: Path) -> None:
    raw = _raw(td3)
    info = parse_sod(raw["EF_SOD"], raw)
    assert info.available, info.message
    assert info.message == ""
    assert [h.dg for h in info.hashes] == [1, 2, 7, 11, 12, 14, 15]
    assert all(h.status == "match" for h in info.hashes)


def test_a_data_group_absent_from_the_dump_is_not_checked(td3: Path) -> None:
    raw = _raw(td3)
    raw.pop("EF_DG7")
    info = parse_sod(raw["EF_SOD"], raw)
    statuses = {h.dg: h.status for h in info.hashes}
    assert statuses[7] == "not checked"
    assert statuses[1] == "match"
    assert info.mismatches == []


def test_missing_sod_is_reported_not_crashed() -> None:
    info = parse_sod(b"", {})
    assert not info.available
    assert "not dumped" in info.message


def test_garbage_sod_is_reported_not_crashed() -> None:
    info = parse_sod(b"\x77\x05\x01\x02\x03\x04\x05", {})
    assert not info.available
    assert info.message
