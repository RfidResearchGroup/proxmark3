"""The dumps directory listing that answers "where did my read go?"."""

from __future__ import annotations

from pathlib import Path

from epassport import config


def _dump(root: Path, name: str, files: int) -> Path:
    directory = root / "ePassport" / "dumps" / name
    directory.mkdir(parents=True)
    for index in range(files):
        (directory / f"EF_DG{index + 1}.bin").write_bytes(b"\x61\x02\xab\xcd")
    return directory


def test_listing_is_newest_first(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    older = _dump(tmp_path, "20260101T000000Z", 2)
    newer = _dump(tmp_path, "20260102T000000Z", 3)
    import os

    os.utime(older, (1_700_000_000, 1_700_000_000))
    os.utime(newer, (1_800_000_000, 1_800_000_000))
    entries = config.list_dumps()
    assert [e.name for e in entries] == [newer.name, older.name]
    assert entries[0].files == 3


def test_timestamp_is_rendered_readably(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _dump(tmp_path, "20260821T194657Z", 1)
    assert config.list_dumps()[0].when == "2026-08-21 19:46:57 UTC"


def test_a_directory_with_an_odd_name_still_lists(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _dump(tmp_path, "handmade", 1)
    assert config.list_dumps()[0].when == "handmade"


def test_empty_dumps_are_flagged_and_prunable(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _dump(tmp_path, "20260101T000000Z", 0)
    kept = _dump(tmp_path, "20260102T000000Z", 2)
    entries = config.list_dumps()
    assert sum(1 for e in entries if e.is_empty) == 1
    assert "did not complete" in [e.summary for e in entries if e.is_empty][0]

    assert config.prune_empty_dumps() == 1
    remaining = config.list_dumps()
    assert [e.name for e in remaining] == [kept.name]
    assert config.prune_empty_dumps() == 0


def test_summary_reports_size(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _dump(tmp_path, "20260101T000000Z", 2)
    assert "2 files" in config.list_dumps()[0].summary


def test_no_dumps_yet(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert config.list_dumps() == []


def test_window_size_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = config.Settings(window_width=900, window_height=600)
    settings.save(path)
    assert config.Settings.load(path).window_width == 900
    assert config.Settings.load(path).window_height == 600


# ------------------------------------------------------------ deleting one
def test_deleting_one_dump_leaves_the_others(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    doomed = _dump(tmp_path, "20260101T000000Z", 3)
    kept = _dump(tmp_path, "20260102T000000Z", 2)

    import shutil

    shutil.rmtree(doomed)
    assert [e.name for e in config.list_dumps()] == [kept.name]
    assert not doomed.exists()
    assert kept.exists()


def test_a_deleted_dump_takes_its_files_with_it(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    doomed = _dump(tmp_path, "20260101T000000Z", 3)
    assert len(list(doomed.iterdir())) == 3

    import shutil

    shutil.rmtree(doomed)
    assert not doomed.exists()
    assert config.list_dumps() == []


# ---------------------------------------------------- surviving the rename
def test_a_legacy_data_directory_is_adopted(monkeypatch, tmp_path: Path) -> None:
    """Dumps are not reproducible without the document in hand.

    Renaming the app must carry the old directory across, never quietly start
    an empty one and orphan somebody's reads.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    legacy = tmp_path / "pm3-passport" / "dumps" / "20260101T000000Z"
    legacy.mkdir(parents=True)
    (legacy / "EF_DG1.bin").write_bytes(b"\x61\x02\xab\xcd")

    entries = config.list_dumps()
    assert [e.name for e in entries] == ["20260101T000000Z"]
    assert config.data_dir() == tmp_path / config.APP_NAME
    assert not (tmp_path / "pm3-passport").exists()


def test_an_existing_new_directory_wins_over_a_legacy_one(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    (tmp_path / config.APP_NAME / "dumps" / "new").mkdir(parents=True)
    (tmp_path / "pm3-passport" / "dumps" / "old").mkdir(parents=True)

    assert [e.name for e in config.list_dumps()] == ["new"]
    # The legacy directory is left alone rather than merged or deleted.
    assert (tmp_path / "pm3-passport" / "dumps" / "old").exists()


def test_no_legacy_directory_is_harmless(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert config.list_dumps() == []
    assert config.data_dir().is_dir()


def test_every_test_here_redirects_the_data_directory() -> None:
    """A test that forgets to redirect XDG_DATA_HOME would operate on the
    user's real dumps - which hold a live portrait and MRZ and cannot be
    recreated without the document."""
    import inspect

    import tests.test_dumps as module

    for name, func in vars(module).items():
        if (
            not name.startswith("test_")
            or name == "test_every_test_here_redirects_the_data_directory"
        ):
            continue
        source = inspect.getsource(func)
        if any(
            token in source
            for token in ("config.list_dumps", "config.data_dir", "prune_empty")
        ):
            assert "XDG_DATA_HOME" in source, f"{name} must redirect XDG_DATA_HOME"


def _failed_read(root: Path, name: str = "20260101T000000Z") -> Path:
    """A read that dumped nothing but left its client log behind."""
    directory = root / "ePassport" / "dumps" / name
    directory.mkdir(parents=True)
    (directory / config.DUMP_LOG_NAME).write_text("# pm3 dump, exit 0\n[!] failed\n")
    return directory


def test_a_directory_holding_only_the_log_still_reads_as_empty(
    monkeypatch, tmp_path: Path
) -> None:
    """The log is evidence about the read, not a file off the chip.

    Counting it would hide a failed read behind "1 files" and take it out of
    reach of the empty-dump cleanup.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    _failed_read(tmp_path)
    (entry,) = config.list_dumps()
    assert entry.is_empty
    assert "did not complete" in entry.summary


def test_pruning_clears_a_failed_read_along_with_its_log(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    directory = _failed_read(tmp_path)
    assert config.prune_empty_dumps() == 1
    assert not directory.exists()


def test_pruning_leaves_a_directory_holding_real_files(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    directory = _dump(tmp_path, "20260101T000000Z", 2)
    (directory / config.DUMP_LOG_NAME).write_text("# pm3 dump, exit 0\n")
    assert config.prune_empty_dumps() == 0
    assert directory.exists()
