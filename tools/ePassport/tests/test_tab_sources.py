"""Which files each detail tab actually drew from.

The tab headers named their files as fixed text - "Additional personal
details  ·  EF_DG11" - so a document without DG11 was told its details came
from a file it does not carry, and the SECURITY header listed EF_DG15 whether
or not it was there.
"""

from __future__ import annotations

from pathlib import Path

from epassport.emrtd import dg, tlv
from epassport.emrtd.model import PassportRecord
from epassport.emrtd.mrz import Checked, Mrz


def _pesel_dg13(digits: str = "10030912345") -> bytes:
    return tlv.encode(
        0x6D, tlv.encode(0x5C, b"\x5f\x70") + tlv.encode(0x5F70, digits.encode())
    )


def _polish_record() -> PassportRecord:
    """DG13 and no DG11, the shape that exposed this."""
    record = PassportRecord()
    blank = Checked("")
    record.mrz = Mrz(
        kind="TD3",
        lines=[],
        document_number=blank,
        date_of_birth=blank,
        date_of_expiry=blank,
        composite=blank,
        nationality="POL",
        optional_data=Checked(""),
    )
    record.optional = dg.parse_dg13(_pesel_dg13())
    return record


def test_personal_names_dg11_when_the_document_carries_it(td3: Path) -> None:
    assert "EF_DG11" in dg.load_dump(td3).personal_files


def test_personal_names_dg13_when_that_is_where_the_number_came_from() -> None:
    record = _polish_record()
    assert record.personal_files == ["EF_DG13"]
    assert "EF_DG11" not in record.personal_files


def test_personal_names_nothing_when_nothing_fed_it(tmp_path: Path) -> None:
    assert dg.load_dump(tmp_path).personal_files == []


def test_document_follows_dg12(td3: Path, td1: Path) -> None:
    assert dg.load_dump(td3).document_files == ["EF_DG12"]
    assert dg.load_dump(td1).document_files == []


def test_security_lists_only_the_files_that_are_there(td3: Path) -> None:
    files = dg.load_dump(td3).security_files
    assert "EF_SOD" in files
    assert files == [f for f in ("EF_SOD", "EF_DG14", "EF_DG15") if f in files]


def test_security_drops_a_missing_dg15(tmp_path: Path, td3: Path) -> None:
    import shutil

    for name in ("EF_SOD.bin", "EF_DG14.bin"):
        shutil.copy(td3 / name, tmp_path / name)
    files = dg.load_dump(tmp_path).security_files
    assert "EF_DG15" not in files
    assert "EF_DG14" in files
