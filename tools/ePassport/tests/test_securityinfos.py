"""SecurityInfos - the protocol list in EF_DG14, EF_CardAccess, EF_CardSecurity.

The OID arcs are the ones the client uses in client/src/emrtd/emrtd_pace.c:
PACE is 0.4.0.127.0.7.2.2.4.x.y, and 0.4.0.127.0.7.2.2.1.2 is the Chip
Authentication public key the client calls oid_pk_ecdh. The viewer used to
label the second one as PACE, so a PACE passport had its CA key announced as
PACE while its actual PACE protocol went unlabelled.
"""

from __future__ import annotations

from epassport.emrtd import securityinfos as si

#: A real EF_CardAccess: PACE ECDH generic mapping, 3DES, NIST P-256.
CARD_ACCESS = bytes.fromhex("31143012060A04007F0007020204020102010202010C")


def test_the_public_key_oid_is_not_pace() -> None:
    name = si.describe("0.4.0.127.0.7.2.2.1.2")
    assert "PACE" not in name
    assert "Chip Authentication" in name


def test_the_chip_authentication_oid_is_not_terminal_authentication() -> None:
    name = si.describe("0.4.0.127.0.7.2.2.3.2.1")
    assert "Terminal Authentication" not in name
    assert "Chip Authentication" in name


def test_pace_is_the_arc_the_client_uses() -> None:
    assert "PACE" in si.describe("0.4.0.127.0.7.2.2.4.2.1")
    assert "ECDH" in si.describe("0.4.0.127.0.7.2.2.4.2.1")


def test_terminal_authentication_has_its_own_arc() -> None:
    assert "Terminal Authentication" in si.describe("0.4.0.127.0.7.2.2.2")


def test_an_unknown_oid_comes_back_as_itself() -> None:
    assert si.describe("1.2.840.10045.2.1") == "1.2.840.10045.2.1"


def test_card_access_decodes_to_protocol_version_and_curve() -> None:
    (entry,) = si.parse(CARD_ACCESS)
    assert entry.oid == "0.4.0.127.0.7.2.2.4.2.1"
    assert "PACE" in entry.name
    assert entry.version == 2
    assert entry.parameter_id == 12
    assert entry.curve == "NIST P-256 (secp256r1)"


def test_the_display_line_names_the_protocol_and_the_curve() -> None:
    (entry,) = si.parse(CARD_ACCESS)
    assert "PACE" in entry.text
    assert "NIST P-256 (secp256r1)" in entry.text


def test_parsing_rubbish_yields_nothing_rather_than_raising() -> None:
    assert si.parse(b"") == []
    assert si.parse(b"\xff\xff\xff") == []


def test_domain_parameters_match_the_client_table() -> None:
    assert si.DOMAIN_PARAMETERS[12] == "NIST P-256 (secp256r1)"
    assert si.DOMAIN_PARAMETERS[13] == "BrainpoolP256r1"
    assert 3 not in si.DOMAIN_PARAMETERS  # 3..7 are not assigned


def test_the_icao_active_authentication_oid_is_named() -> None:
    assert si.describe("2.23.136.1.1.5") == "Active Authentication"


def _der(tag: int, value: bytes) -> bytes:
    from epassport.emrtd import tlv

    return tlv.encode(tag, value)


def _public_key_info() -> bytes:
    """A ChipAuthenticationPublicKeyInfo carrying a P-256 point."""
    algorithm = _der(
        0x30,
        _der(0x06, bytes.fromhex("2A8648CE3D0201"))
        + _der(0x06, bytes.fromhex("2A8648CE3D0101")),
    )
    key = _der(0x30, algorithm + _der(0x03, b"\x00\x04" + bytes(64)))
    info = _der(0x30, _der(0x06, bytes.fromhex("04007F000702020102")) + key)
    return _der(0x31, info)


def test_nested_algorithm_oids_are_not_listed_as_protocols() -> None:
    """SecurityInfos is a SET OF SecurityInfo - only its members count.

    Walking every nested SEQUENCE also picked up the X9.62 identifiers inside
    the public key, which are not protocols the chip supports.
    """
    entries = si.parse(_public_key_info())
    assert [e.oid for e in entries] == ["0.4.0.127.0.7.2.2.1.2"]


def test_a_public_key_entry_reports_its_size() -> None:
    (entry,) = si.parse(_public_key_info())
    assert entry.key_bits == 256
    assert "256" in entry.text
