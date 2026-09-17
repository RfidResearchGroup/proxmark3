"""EF_DG13 - optional details, whatever the issuing state chose to put there.

ICAO assigns DG13 no meaning, so it is read as tagged values and nothing is
inferred from a tag on its own.  Poland is the exception worth naming: it
carries the PESEL, its national identity number, in tag 5F70, and a Polish
passport that ships no DG11 has no other place to put it.
"""

from __future__ import annotations

from epassport.emrtd import dg, tlv


def _dg13(*elements: bytes) -> bytes:
    return tlv.encode(0x6D, b"".join(elements))


def _pesel(digits: str) -> bytes:
    """A DG13 shaped like Poland's: a 5C tag list then the number."""
    return _dg13(tlv.encode(0x5C, b"\x5f\x70"), tlv.encode(0x5F70, digits.encode()))


#: Checksum-valid, born 2010-03-09, male.  Not anybody's: built for the test.
VALID = "10030912345"


def test_the_tag_list_is_not_content() -> None:
    """5C enumerates the tags that follow; showing it as a field is noise."""
    details = dg.parse_dg13(_pesel(VALID))
    assert [tag for tag, _ in details.fields] == ["5F70"]


def test_fields_come_back_as_tag_and_text() -> None:
    details = dg.parse_dg13(_pesel(VALID))
    assert details.fields == [("5F70", VALID)]


def test_an_unknown_tag_is_carried_without_being_named() -> None:
    details = dg.parse_dg13(_dg13(tlv.encode(0x5F71, b"whatever")))
    assert details.fields == [("5F71", "whatever")]


def test_rubbish_yields_no_fields_rather_than_raising() -> None:
    assert dg.parse_dg13(b"").fields == []
    assert dg.parse_dg13(b"\xff\xff\xff").fields == []


# ------------------------------------------------------ the PESEL in tag 5F70
def test_a_valid_pesel_is_recognised() -> None:
    assert dg.is_pesel(VALID)


def test_the_checksum_has_to_hold() -> None:
    wrong = VALID[:10] + str((int(VALID[10]) + 1) % 10)
    assert not dg.is_pesel(wrong)


def test_length_and_digits_are_required() -> None:
    assert not dg.is_pesel("1003091234")
    assert not dg.is_pesel("1003091234A")
    assert not dg.is_pesel("")


# ------------------------------------------- what the PERSONAL tab ends up with
from epassport.emrtd.model import PassportRecord  # noqa: E402
from epassport.emrtd.mrz import Checked, Mrz  # noqa: E402


def _record(nationality: str, dg13: bytes, optional_data: str = "") -> PassportRecord:
    """Use the real Mrz dataclass: a hand-rolled stub can disagree with it."""
    record = PassportRecord()
    blank = Checked("")
    record.mrz = Mrz(
        kind="TD3",
        lines=[],
        document_number=blank,
        date_of_birth=blank,
        date_of_expiry=blank,
        composite=blank,
        nationality=nationality,
        optional_data=Checked(optional_data),
    )
    record.optional = dg.parse_dg13(dg13)
    return record


def test_a_polish_document_with_no_dg11_still_has_a_personal_number() -> None:
    """DG11 absent and the MRZ optional field empty - DG13 is all there is."""
    record = _record("POL", _pesel(VALID))
    assert record.personal_number == VALID
    assert record.personal_number_source == "DG13"


def test_the_same_tag_elsewhere_is_not_claimed_as_a_personal_number() -> None:
    """DG13 means whatever the issuer decided, so 5F70 is Polish only."""
    record = _record("DEU", _pesel(VALID))
    assert record.personal_number != VALID
    assert record.personal_number_source != "DG13"


def test_a_number_that_fails_the_checksum_is_not_used() -> None:
    wrong = VALID[:10] + str((int(VALID[10]) + 1) % 10)
    assert _record("POL", _pesel(wrong)).personal_number != wrong


def test_the_mrz_optional_field_still_wins_over_dg13() -> None:
    """Sweden and others put it there; that is the more direct source."""
    record = _record("POL", _pesel(VALID), optional_data="654321")
    assert record.personal_number == "654321"
    assert record.personal_number_source == "MRZ"
