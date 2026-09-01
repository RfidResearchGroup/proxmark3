"""The personal number taken from the MRZ optional-data field.

ICAO 9303 Part 4, positions 29 to 42: "Any special characters, including
spaces, in the personal identification number ... shall be replaced by the
filler character (<). The number shall be followed by the filler character
(<) repeated up to position 42."

So the trailing run is padding, and a filler inside the number stands for a
space or a special character that was substituted on the way in.  Printing it
raw put a '<' in the middle of the number.
"""

from __future__ import annotations

from epassport.emrtd.model import PassportRecord
from epassport.emrtd.mrz import Checked, Mrz


def _record(optional: str) -> PassportRecord:
    record = PassportRecord()
    blank = Checked("")
    record.mrz = Mrz(
        kind="TD3",
        lines=[],
        document_number=blank,
        date_of_birth=blank,
        date_of_expiry=blank,
        composite=blank,
        nationality="USA",
        optional_data=Checked(optional),
    )
    return record


def test_a_filler_inside_the_number_stands_for_a_space() -> None:
    assert _record("123456789<0123").personal_number == "123456789 0123"


def test_trailing_padding_never_reaches_the_value() -> None:
    assert _record("ZE184226B").personal_number == "ZE184226B"
    assert _record("ZE184226B<<<<<").personal_number == "ZE184226B"


def test_a_plain_number_is_untouched() -> None:
    assert _record("6512168").personal_number == "6512168"


def test_an_empty_field_yields_no_number() -> None:
    assert _record("").personal_number_source == ""


def test_the_source_is_still_reported_as_the_mrz() -> None:
    assert _record("123456789<0123").personal_number_source == "MRZ"
