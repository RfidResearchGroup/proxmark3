"""Settings persistence, and the promise that BAC data is not kept by default."""

from __future__ import annotations

import json
from pathlib import Path

from epassport.config import Settings, new_dump_dir


def test_defaults_do_not_remember_credentials() -> None:
    settings = Settings()
    assert settings.remember_bac is False
    assert settings.last_document_number == ""


def test_saving_without_remember_strips_the_bac_fields(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    settings = Settings(
        last_document_number="L898902C3",
        last_date_of_birth="740812",
        last_date_of_expiry="120415",
        remember_bac=False,
    )
    settings.save(path)
    raw = json.loads(path.read_text())
    assert raw["last_document_number"] == ""
    assert raw["last_date_of_birth"] == ""
    assert raw["last_date_of_expiry"] == ""


def test_saving_with_remember_keeps_them(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    Settings(last_document_number="L898902C3", remember_bac=True).save(path)
    assert json.loads(path.read_text())["last_document_number"] == "L898902C3"
    assert Settings.load(path).last_document_number == "L898902C3"


def test_settings_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    Settings().save(path)
    assert path.stat().st_mode & 0o077 == 0


def test_corrupt_settings_file_falls_back_to_defaults(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text("{ this is not json")
    assert Settings.load(path).timeout_seconds == 120.0


def test_unknown_keys_are_ignored(tmp_path: Path) -> None:
    path = tmp_path / "settings.json"
    path.write_text(json.dumps({"camera_index": 2, "from_the_future": True}))
    assert Settings.load(path).camera_index == 2


def test_dump_dirs_are_unique_and_owner_only(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    first = new_dump_dir()
    second = new_dump_dir()
    assert first != second
    assert first.stat().st_mode & 0o077 == 0
    assert first.parent.stat().st_mode & 0o077 == 0
