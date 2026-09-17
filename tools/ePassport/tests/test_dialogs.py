"""Popup wiring.

These are plain-Python checks of the parts that do not need a window, because
the bugs worth catching here are wiring mistakes, not pixels.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from epassport.ui import dialogs


def test_confirm_callback_is_not_named_with_an_on_prefix() -> None:
    """Kivy binds any ``on_*`` constructor keyword as an event observer.

    Naming the callback property ``on_confirm`` meant ``ConfirmPopup(
    on_confirm=fn)`` silently bound an observer and left the property None,
    so confirming a deletion did nothing at all.
    """
    names = [n for n in vars(dialogs.ConfirmPopup) if not n.startswith("__")]
    assert "confirm_action" in names
    assert not any(
        n.startswith("on_")
        and n not in ("on_touch_down", "on_touch_move", "on_touch_up")
        for n in names
    ), "a callback property must not start with on_"


def test_confirm_runs_the_action() -> None:
    calls: list[int] = []
    popup = dialogs.ConfirmPopup.__new__(dialogs.ConfirmPopup)
    popup.confirm_action = lambda: calls.append(1)
    popup.dismiss = lambda *a, **k: None
    dialogs.ConfirmPopup.confirm(popup)
    assert calls == [1]


def test_confirm_without_an_action_is_harmless() -> None:
    popup = dialogs.ConfirmPopup.__new__(dialogs.ConfirmPopup)
    popup.confirm_action = None
    popup.dismiss = lambda *a, **k: None
    dialogs.ConfirmPopup.confirm(popup)  # must not raise


def test_dump_rows_expose_both_actions() -> None:
    assert "on_open" in dialogs.DumpRow.__events__
    assert "on_delete" in dialogs.DumpRow.__events__


def test_deleting_asks_before_it_removes_anything() -> None:
    source = inspect.getsource(dialogs.DumpsPopup.confirm_delete)
    assert "ConfirmPopup" in source, "deletion must be confirmed, never immediate"
    assert "cannot be undone" in source


# ------------------------------------------------------------- quick jumps
def test_shortcuts_offer_the_places_dumps_actually_live(monkeypatch, tmp_path) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(config, "samples_dir", lambda: None)
    labels = [label for label, _path in dialogs.ChooseDirPopup.shortcuts()]
    assert "Dumps" in labels
    assert "Home" in labels
    assert "Samples" not in labels, "not offered until the samples are generated"


def test_samples_appear_once_generated(monkeypatch, tmp_path) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    generated = tmp_path / "samples"
    generated.mkdir()
    monkeypatch.setattr(config, "samples_dir", lambda: generated)
    entries = dict(dialogs.ChooseDirPopup.shortcuts())
    assert entries["Samples"] == generated.resolve()


def test_shortcuts_are_all_real_directories(monkeypatch, tmp_path) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(config, "samples_dir", lambda: tmp_path / "does-not-exist")
    for label, path in dialogs.ChooseDirPopup.shortcuts():
        assert path.is_dir(), f"{label} points at {path}"


def test_duplicate_shortcuts_are_collapsed(monkeypatch, tmp_path) -> None:
    """Launched from the project root, 'Working dir' and 'Samples' can be the
    same place; offering it twice is just noise."""
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    monkeypatch.setattr(config, "samples_dir", lambda: Path.cwd())
    paths = [path for _label, path in dialogs.ChooseDirPopup.shortcuts()]
    assert len(paths) == len(set(paths))


def test_samples_dir_is_none_until_generated(tmp_path, monkeypatch) -> None:
    from epassport import config

    monkeypatch.setattr(config, "project_root", lambda: tmp_path)
    assert config.samples_dir() is None
    (tmp_path / "samples").mkdir()
    assert config.samples_dir() == tmp_path / "samples"


# --------------------------------------------------- remembering where you were
def test_the_picker_reopens_beside_the_last_dump(tmp_path, monkeypatch) -> None:
    """A dump was picked *inside* some folder; offer that folder again.

    Opening the app's own dumps directory every time meant navigating back to
    wherever your dumps actually live on every single trip through the picker.
    """
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    elsewhere = tmp_path / "captures" / "20260101T000000Z"
    elsewhere.mkdir(parents=True)
    assert config.browse_start(str(elsewhere)) == elsewhere.parent


def test_no_history_falls_back_to_the_app_dumps(tmp_path, monkeypatch) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert config.browse_start("") == config.dumps_dir()


def test_a_dump_that_has_been_deleted_falls_back(tmp_path, monkeypatch) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    gone = tmp_path / "gone" / "also-gone"
    assert config.browse_start(str(gone)) == config.dumps_dir()


def test_a_deleted_dump_whose_parent_survives_offers_the_parent(
    tmp_path, monkeypatch
) -> None:
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    parent = tmp_path / "captures"
    parent.mkdir()
    assert config.browse_start(str(parent / "removed")) == parent


def test_the_start_is_absolute(tmp_path, monkeypatch) -> None:
    """The chooser is handed this path directly; a relative one is fragile."""
    from epassport import config

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    nested = tmp_path / "rel" / "dump"
    nested.mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    assert config.browse_start("rel/dump").is_absolute()


def test_recent_is_offered_as_a_shortcut() -> None:
    import inspect

    source = inspect.getsource(dialogs.ChooseDirPopup.shortcuts)
    assert '"Recent"' in source
    assert "browse_start" in source
