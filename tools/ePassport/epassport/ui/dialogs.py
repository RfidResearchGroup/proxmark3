"""Small popups: pick a directory, confirm a destructive action.

Kivy's FileChooser is used rather than a native dialog so the app has no
desktop-portal dependency and stays entirely self-contained.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from kivy.app import App
from kivy.metrics import dp, sp
from kivy.properties import BooleanProperty, ObjectProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.popup import Popup


class ChooseDirPopup(Popup):
    """Directory picker.  Calls ``on_choice(Path)`` with the chosen folder.

    Navigating to a dump by hand is tedious, so the places one actually keeps
    them are one click away, and the path is typeable for everything else.
    """

    start = StringProperty("")
    selection = StringProperty("")

    def __init__(
        self, *, start: str, on_choice: Callable[[Path], None], **kwargs
    ) -> None:
        self.start = start if Path(start).is_dir() else str(Path.home())
        self.selection = self.start
        self._on_choice = on_choice
        super().__init__(**kwargs)

    # -- quick jumps -------------------------------------------------------
    @staticmethod
    def shortcuts() -> list[tuple[str, Path]]:
        """``(label, path)`` for every shortcut that actually exists."""
        from kivy.app import App

        from ..config import browse_start, dumps_dir, samples_dir

        app = App.get_running_app()
        last = getattr(getattr(app, "settings", None), "last_dump_dir", "")
        candidates: list[tuple[str, Path | None]] = [
            ("Recent", browse_start(last) if last else None),
            ("Dumps", dumps_dir()),
            ("Samples", samples_dir()),
            ("Working dir", Path.cwd()),
            ("Home", Path.home()),
        ]
        seen: set[Path] = set()
        out: list[tuple[str, Path]] = []
        for label, path in candidates:
            if path is None or not path.is_dir():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue  # e.g. launched from the project root
            seen.add(resolved)
            out.append((label, resolved))
        return out

    def build_shortcuts(self) -> None:
        from kivy.uix.button import Button

        box = self.ids.get("shortcuts")
        if box is None:
            return
        box.clear_widgets()
        for label, path in self.shortcuts():
            button = Button(
                text=label, font_size=sp(11), size_hint_x=None, width=dp(96)
            )
            button.bind(on_release=lambda _w, p=path: self.jump(p))
            box.add_widget(button)

    def jump(self, path: Path) -> None:
        """Point the chooser at ``path``."""
        chooser = self.ids.get("chooser")
        if chooser is not None and path.is_dir():
            chooser.path = str(path)
        self.selection = str(path)

    def go_to_typed(self, text: str) -> None:
        """Accept a typed or pasted path."""
        target = Path(text.strip()).expanduser()
        if target.is_dir():
            self.jump(target)
        elif target.parent.is_dir():
            self.jump(target.parent)

    # -- selection ---------------------------------------------------------
    def choose(self) -> None:
        target = Path(self.selection or self.start)
        self.dismiss()
        if target.is_dir():
            self._on_choice(target)

    def on_chooser_selection(self, paths: list[str]) -> None:
        """A file selection means 'this file's folder'."""
        if not paths:
            return
        chosen = Path(paths[0])
        self.selection = str(chosen if chosen.is_dir() else chosen.parent)


class DumpRow(BoxLayout):
    """One dump in the browser: when it was read, and what it holds."""

    __events__ = ("on_open", "on_delete")

    when = StringProperty("")
    summary = StringProperty("")
    path = StringProperty("")
    empty = BooleanProperty(False)
    palette = ObjectProperty(None)

    def on_open(self, *_args) -> None:
        """Default handler; the browser binds over this."""

    def on_delete(self, *_args) -> None:
        """Default handler; the browser binds over this."""


class DumpsPopup(Popup):
    """Browse the app's own dump directory.

    "Where did my read go?" should never need a file manager, so this lists
    every dump with its timestamp and contents, and can open the folder.
    """

    status = StringProperty("")

    def __init__(self, *, on_choice: Callable[[Path], None], **kwargs) -> None:
        self._on_choice = on_choice
        super().__init__(**kwargs)
        self.refresh()

    def refresh(self) -> None:
        from ..config import dumps_dir, list_dumps
        from .. import ui  # noqa: F401  (kv rules are already loaded)

        entries = list_dumps()
        box = self.ids.get("rows")
        if box is None:
            return
        box.clear_widgets()
        app = App.get_running_app()
        palette = getattr(app, "palette", None)
        for entry in entries:
            row = DumpRow(
                when=entry.when,
                summary=entry.summary,
                path=str(entry.path),
                empty=entry.is_empty,
                palette=palette,
            )
            row.bind(on_open=lambda widget: self.choose(widget.path))
            row.bind(on_delete=lambda widget: self.confirm_delete(widget.path))
            box.add_widget(row)
        self.status = f"{len(entries)} dump(s) in {dumps_dir()}"
        if not entries:
            self.status = f"No dumps yet. They will appear in {dumps_dir()}"

    def choose(self, path: str) -> None:
        self.dismiss()
        self._on_choice(Path(path))

    def confirm_delete(self, path: str) -> None:
        """Ask first: a dump holds the live personal data of a real document."""
        target = Path(path)
        ConfirmPopup(
            title_text="Delete this dump?",
            message=(
                f"{target}\n\n"
                "This permanently removes the dumped files, including the "
                "portrait and the MRZ. It cannot be undone."
            ),
            confirm_text="Delete",
            confirm_action=lambda: self.delete(target),
        ).open()

    def delete(self, target: Path) -> None:
        import shutil

        try:
            shutil.rmtree(target)
        except OSError as exc:
            self.status = f"Could not delete {target.name}: {exc}"
            return
        app = App.get_running_app()
        if app is not None and getattr(app, "status_dump_dir", "") == str(target):
            app.forget_current_dump()
        self.refresh()
        self.status = f"Deleted {target.name}"

    @property
    def has_samples(self) -> bool:
        from ..config import samples_dir

        return samples_dir() is not None

    def open_folder(self) -> None:
        from ..config import dumps_dir

        _open_in_file_manager(dumps_dir())

    def prune(self) -> None:
        from ..config import prune_empty_dumps

        removed = prune_empty_dumps()
        self.refresh()
        if removed:
            self.status = f"Removed {removed} empty dump(s)."


def _open_in_file_manager(path) -> None:
    import subprocess

    try:
        subprocess.Popen(["xdg-open", str(path)], start_new_session=True)
    except OSError:
        pass


class ConfirmPopup(Popup):
    """Yes/no confirmation for anything destructive."""

    title_text = StringProperty("")
    message = StringProperty("")
    confirm_text = StringProperty("Delete")
    #: Deliberately NOT named ``on_confirm``: Kivy treats any constructor
    #: keyword starting with ``on_`` as an event binding, so passing
    #: ``on_confirm=callback`` silently binds an observer and leaves the
    #: property None - the dialog then confirms and does nothing.
    confirm_action = ObjectProperty(None)

    def confirm(self) -> None:
        self.dismiss()
        if callable(self.confirm_action):
            self.confirm_action()
