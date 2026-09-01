"""ePassport: an ePassport (eMRTD) viewer.

Everything runs offline.  The only coupling to proxmark3 is the ``pm3`` CLI.

Run it with the ``ePassport`` script in the project root::

    ./ePassport
    ./ePassport --dump samples/td3_utopia
    ./ePassport --dry-run <a recorded pm3 log> --dump <a dump dir>
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import threading
from pathlib import Path

os.environ.setdefault("KIVY_NO_ARGS", "1")

# Quieten the noisy libraries BEFORE importing them.  Kivy 2.3 takes its log
# level from ~/.kivy/config.ini, which is shared with every other Kivy app on
# the machine and is not ours to rewrite - so drop its console handler instead
# and re-install our own for warnings and above (see _install_kivy_logging).
# OpenCV and its V4L2 backend read their verbosity from the environment.
_VERBOSE = any(flag in sys.argv for flag in ("-v", "--verbose"))
if not _VERBOSE:
    os.environ.setdefault("KIVY_NO_CONSOLELOG", "1")
os.environ.setdefault("OPENCV_LOG_LEVEL", "DEBUG" if _VERBOSE else "ERROR")
os.environ.setdefault("OPENCV_VIDEOIO_DEBUG", "1" if _VERBOSE else "0")

from kivy.app import App  # noqa: E402
from kivy.clock import Clock  # noqa: E402
from kivy.core.window import Window  # noqa: E402
from kivy.properties import (  # noqa: E402
    BooleanProperty,
    DictProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.boxlayout import BoxLayout  # noqa: E402
from kivy.uix.screenmanager import NoTransition, Screen, ScreenManager  # noqa: E402

from .config import Settings, dumps_dir, new_dump_dir  # noqa: E402
from .emrtd.dg import load_dump  # noqa: E402
from .emrtd.model import PassportRecord  # noqa: E402
from .ocr.camera import opencv_available  # noqa: E402
from .ocr.mrz_ocr import tesseract_available  # noqa: E402
from .pm3 import errors  # noqa: E402
from .pm3.client import BacInput, Pm3Client, Pm3Result  # noqa: E402
from .ui import load_kv, theme  # noqa: E402

log = logging.getLogger("epassport")

#: What the window manager shows.
APP_TITLE = "ePassport"

#: The smallest window the passport page stays readable in.
MIN_WINDOW_SIZE = (760, 520)

#: How many files a full dump writes, for the progress bar's denominator when
#: EF_COM has not been read yet.
DEFAULT_EXPECTED_FILES = 9


def apply_minimum_window_size(window) -> None:
    """Constrain the window, once it exists.

    Setting this through Config instead makes Kivy apply it inside
    create_window(), where the resize recurses until the stack gives out.
    """
    minimum_width, minimum_height = MIN_WINDOW_SIZE
    window.size = (
        max(window.width, minimum_width),
        max(window.height, minimum_height),
    )
    window.minimum_width = minimum_width
    window.minimum_height = minimum_height


class Root(BoxLayout):
    """The window: screen manager plus the status bar."""


class ViewerScreen(Screen):
    """The passport book: tab strip, page area, progress and error panel."""


class Pm3PassportApp(App):
    """The application object.  Owns the record, the client and the threads."""

    record = ObjectProperty(None, allownone=True, rebind=True)
    palette = DictProperty(theme.LIGHT)
    dark = BooleanProperty(False)

    busy = BooleanProperty(False)
    progress = NumericProperty(0.0)
    progress_text = StringProperty("")
    status_connection = StringProperty("idle")
    status_bac = StringProperty("-")
    status_auth = StringProperty("None")
    status_dump_dir = StringProperty("")

    scale_mode = StringProperty("fit")
    camera_available = BooleanProperty(False)
    ocr_available = BooleanProperty(False)
    ocr_reason = StringProperty("")

    def __init__(self, args: argparse.Namespace, **kwargs) -> None:
        super().__init__(**kwargs)
        self.args = args
        self.settings = Settings.load()
        if args.pm3_binary:
            self.settings.pm3_binary = args.pm3_binary
        self.client = Pm3Client(
            self.settings.pm3_binary or None,
            timeout=self.settings.timeout_seconds,
            dry_run_log=args.dry_run,
        )
        self._worker: threading.Thread | None = None
        self._tab_pages: dict[int, object] = {}

    # ------------------------------------------------------------ build
    def build(self):
        # ``App.title`` is a StringProperty: setting it as a class attribute
        # shadows the property and the window keeps Kivy's default name.
        self.title = APP_TITLE
        Window.set_title(APP_TITLE)
        load_kv()
        self.dark = self.settings.dark_chrome
        self.scale_mode = self.settings.page_scale_mode
        self.palette = theme.palette(self.dark)
        self.record = PassportRecord()
        self.camera_available = opencv_available()
        self.ocr_available, self.ocr_reason = tesseract_available()
        self._restore_window_size()
        root = Root()
        self.root_widget = root
        Clock.schedule_once(self._post_build, 0)
        return root

    def _restore_window_size(self) -> None:
        """Reopen at the size the user last left, not a size we insist on."""
        width, height = self.settings.window_width, self.settings.window_height
        minimum_width, minimum_height = MIN_WINDOW_SIZE
        if width >= minimum_width and height >= minimum_height:
            Window.size = (width, height)
        apply_minimum_window_size(Window)
        Window.bind(on_resize=self._remember_window_size)

    def _remember_window_size(self, _window, width: int, height: int) -> None:
        if width < 100 or height < 100:  # a minimise, not a resize
            return
        self.settings.window_width = int(width)
        self.settings.window_height = int(height)
        self._window_size_dirty = True

    def _post_build(self, *_args) -> None:
        entry = self.screen("entry")
        if entry is not None and self.settings.remember_bac:
            entry.remember = True
            entry.fill(
                self.settings.last_document_number,
                self.settings.last_date_of_birth,
                self.settings.last_date_of_expiry,
            )
        scan = self.screen("scan")
        if scan is not None:
            scan.on_accept = self._on_mrz_scanned
            scan.on_camera_change = self._remember_camera
            scan.camera_index = self.settings.camera_index
        self.status_connection = "pm3: " + (
            str(self.client.binary) if self.client.binary else "not found"
        )
        if self.args.dry_run:
            self.status_connection = f"dry run: {self.args.dry_run}"
        self.select_tab(0)
        if self.args.dump and not self.args.dry_run:
            self.load_dump_dir(Path(self.args.dump))

    # ---------------------------------------------------------- helpers
    @property
    def manager(self) -> ScreenManager | None:
        return self.root_widget.ids.get("sm") if hasattr(self, "root_widget") else None

    def screen(self, name: str):
        manager = self.manager
        if manager is None:
            return None
        return manager.get_screen(name) if manager.has_screen(name) else None

    def goto(self, name: str) -> None:
        manager = self.manager
        if manager is not None and manager.has_screen(name):
            manager.transition = NoTransition()
            manager.current = name

    def goto_entry(self) -> None:
        scan = self.screen("scan")
        if scan is not None:
            scan.stop()
        self.goto("entry")

    def goto_scan(self) -> None:
        scan = self.screen("scan")
        if scan is None:
            return
        self.goto("scan")
        scan.camera_index = self.settings.camera_index
        scan.start()

    def goto_viewer(self) -> None:
        self.goto("viewer")

    # ------------------------------------------------------- tab handling
    def select_tab(self, index: int) -> None:
        viewer = self.screen("viewer")
        if viewer is None:
            return
        strip = viewer.ids.get("tabs")
        turner = viewer.ids.get("pages")
        if strip is None or turner is None:
            return
        strip.active_index = index
        for tab in strip.children:
            tab.active = tab.index == index
        page = self._page_for(index)
        if page is not None:
            turner.show(page)

    def _page_for(self, index: int):
        """Build a tab's page on first use, then reuse it."""
        if index in self._tab_pages:
            page = self._tab_pages[index]
        else:
            from .ui.passport import AspectBox, PassportPage
            from .ui.tabs.pages import (
                FilesPage,
                IssuerPage,
                LogPage,
                PersonalPage,
                SecurityPage,
            )

            if index == 0:
                from .ui.passport import PagePlate

                box = AspectBox()
                page = box
                self._passport_page = PassportPage()
                from .ui.passport import PX_PER_MM

                reference = (
                    theme.REFERENCE_PAGE_MM[0] * PX_PER_MM,
                    theme.REFERENCE_PAGE_MM[1] * PX_PER_MM,
                )
                plate = PagePlate(size=reference)
                plate.add_widget(self._passport_page)
                box.add_widget(plate)
            else:
                cls, title = {
                    # The files are appended by the page itself, from what
                    # the document actually turned out to carry.
                    1: (PersonalPage, "Additional personal details"),
                    2: (IssuerPage, "Additional document details"),
                    3: (SecurityPage, "Document security"),
                    4: (FilesPage, "Dumped files"),
                    5: (LogPage, "pm3 client output"),
                }[index]
                page = cls(title=title, palette=self.palette)
            self._tab_pages[index] = page
            if index == 0:
                self._apply_scale_mode()
        self._apply_record_to(page)
        return page

    def _apply_record_to(self, page) -> None:
        if page is None:
            return
        if hasattr(page, "record"):
            page.record = self.record
        if hasattr(self, "_passport_page") and page is self._tab_pages.get(0):
            self._passport_page.record = self.record
        if hasattr(page, "refresh"):
            page.refresh()

    def on_record(self, *_args) -> None:
        for page in self._tab_pages.values():
            self._apply_record_to(page)

    # --------------------------------------------------------------- log
    @property
    def log_pane(self):
        page = self._tab_pages.get(5)
        return page.ids.get("logpane") if page is not None else None

    def append_log(self, line: str) -> None:
        """Thread-safe: LogPane queues and flushes on the Kivy clock."""
        pane = self.log_pane
        if pane is None:
            self._page_for(5)
            pane = self.log_pane
        if pane is not None:
            pane.append(line)

    def clear_log(self) -> None:
        pane = self.log_pane
        if pane is not None:
            pane.clear()

    # --------------------------------------------------------- reading
    def start_read(self) -> None:
        """Kick off a dump on a worker thread.  Never blocks the UI."""
        if self.busy:
            return
        entry = self.screen("entry")
        if entry is None:
            return
        bac, problem = entry.validated_input()
        if bac is None:
            self.show_error(errors.MissingBacInputError(), detail=problem)
            return
        if self.client.binary is None and not self.args.dry_run:
            self.show_error(errors.Pm3NotFound())
            return

        if entry.remember:
            self.settings.remember_bac = True
            self.settings.last_document_number = entry.document_number
            self.settings.last_date_of_birth = entry.date_of_birth
            self.settings.last_date_of_expiry = entry.date_of_expiry
        else:
            self.settings.remember_bac = False
            self.settings.forget_bac()
        self.settings.save()

        directory = new_dump_dir()
        self.hide_error()
        self.busy = True
        self.progress = 0.0
        self.progress_text = "starting pm3…"
        self.status_bac = "attempting…"
        self.status_auth = bac.mechanism
        self.status_dump_dir = str(directory)
        self.select_tab(5)
        self.goto_viewer()

        command = Pm3Client.build_command("dump", bac, directory)
        self.append_log(f'[=] pm3 -c "{command}"')
        self._worker = threading.Thread(
            target=self._read_worker,
            args=(command, directory),
            name="ePassport-read",
            daemon=True,
        )
        self._worker.start()

    def _read_worker(self, command: str, directory: Path) -> None:
        """Runs off the UI thread: pm3, then parsing, then a single UI hop."""
        result = self.client.run(
            command,
            on_line=self.append_log,
            on_progress=self._on_progress,
            dump_dir=directory,
            expected_files=DEFAULT_EXPECTED_FILES,
        )
        # In dry-run mode the log is replayed but no files are written, so
        # --dump doubles as "the dump this log would have produced".
        source = (
            Path(self.args.dump)
            if (self.args.dry_run and self.args.dump)
            else directory
        )
        record: PassportRecord | None = None
        if result.error is None:
            try:
                record = load_dump(source)
            except Exception as exc:  # a bad dump must not crash the app
                log.exception("parsing the dump failed")
                self.append_log(f"[!!] could not parse the dump: {exc}")
        Clock.schedule_once(lambda *_: self._read_finished(result, record), 0)

    def _on_progress(self, done: int, total: int, name: str) -> None:
        total = total or DEFAULT_EXPECTED_FILES
        Clock.schedule_once(lambda *_: self._set_progress(done, total, name), 0)

    def _set_progress(self, done: int, total: int, name: str) -> None:
        self.progress = min(1.0, done / total) if total else 0.0
        self.progress_text = f"{name}  ({done}/{total})"

    def _read_finished(self, result: Pm3Result, record: PassportRecord | None) -> None:
        self.busy = False
        self.progress = 1.0 if result.ok else 0.0
        self.progress_text = ""
        if result.error is not None:
            self.status_bac = "failed"
            self.status_auth = "None"
            self.show_error(result.error)
            self.select_tab(5)
            return
        if record is not None and record.is_empty:
            # Nothing the classifier recognises went wrong, but no file was
            # written.  Calling that a success drops you on an empty page.
            self.status_bac = "failed"
            self.status_auth = "None"
            self.show_error(
                errors.NothingReadError(),
                detail=str(result.log_path or record.source_dir or ""),
            )
            self.select_tab(5)
            return
        self.status_bac = "success"
        mechanism = errors.detect_mechanism(result.lines)
        if mechanism:
            self.status_auth = mechanism
        if record is not None:
            self.record = record
            self.status_dump_dir = str(record.source_dir or "")
            self.select_tab(0)
            for warning in record.warnings:
                self.append_log(f"[!] {warning}")

    def cancel_read(self) -> None:
        """Kill the pm3 process.  The app stays fully usable afterwards."""
        if not self.busy:
            return
        self.append_log("[!] cancelling…")
        self.client.cancel()

    # ------------------------------------------------------- saved dumps
    def load_dump_dir(self, directory: Path) -> None:
        """Open an existing dump - no hardware needed."""
        directory = Path(directory).expanduser()
        if not directory.is_dir():
            self.show_error(errors.Pm3Error("not a directory"), detail=str(directory))
            return
        self.append_log(f"[=] opening saved dump {directory}")
        self.status_connection = "offline dump"
        self.status_auth = "None (offline)"

        def work() -> None:
            try:
                record = load_dump(directory)
            except Exception as exc:
                log.exception("parsing the dump failed")
                Clock.schedule_once(lambda *_: self.append_log(f"[!!] {exc}"), 0)
                return
            Clock.schedule_once(lambda *_: self._dump_loaded(record), 0)

        threading.Thread(target=work, name="ePassport-open", daemon=True).start()

    def _dump_loaded(self, record: PassportRecord) -> None:
        self.record = record
        self.status_bac = "n/a (offline)"
        self.status_dump_dir = str(record.source_dir or "")
        self.settings.last_dump_dir = str(record.source_dir or "")
        self.settings.save()
        self.hide_error()
        self.select_tab(0)
        self.goto_viewer()
        for warning in record.warnings:
            self.append_log(f"[!] {warning}")

    def open_dumps_browser(self) -> None:
        """List the app's own dumps.  Answers "where did my read go?"."""
        from .ui.dialogs import DumpsPopup

        DumpsPopup(on_choice=self.load_dump_dir).open()

    def open_dump_dialog(self, start: str | None = None) -> None:
        from .config import browse_start
        from .ui.dialogs import ChooseDirPopup

        # Reopen where the last dump was picked from, so browsing to a second
        # dump beside the first does not mean navigating there again.
        ChooseDirPopup(
            start=start or str(browse_start(self.settings.last_dump_dir)),
            on_choice=self.load_dump_dir,
        ).open()

    def open_samples_dialog(self) -> None:
        """Jump straight to the generated sample dumps."""
        from .config import samples_dir

        directory = samples_dir()
        if directory is None:
            self.append_log("[!] no samples yet - generate them with: make samples")
            return
        self.open_dump_dialog(str(directory))

    def export_file(self) -> None:
        from .ui.dialogs import ChooseDirPopup

        page = self._tab_pages.get(4)
        if page is None:
            return

        def chosen(directory: Path) -> None:
            page.status = page.export_selected(str(directory))

        ChooseDirPopup(start=str(Path.home()), on_choice=chosen).open()

    def open_dump_dir(self) -> None:
        """Open the dump directory in the desktop file manager."""
        directory = self.status_dump_dir
        if not directory:
            return
        try:
            subprocess.Popen(["xdg-open", directory], start_new_session=True)
        except OSError as exc:
            self.append_log(f"[!] could not open {directory}: {exc}")

    def forget_current_dump(self) -> None:
        """The loaded dump has just been deleted from under us."""
        self.status_dump_dir = ""
        self.record = PassportRecord()
        self.append_log("[=] the loaded dump was deleted")

    def delete_dump(self) -> None:
        from .ui.dialogs import ConfirmPopup

        directory = self.status_dump_dir
        if not directory:
            return

        def do_delete() -> None:
            import shutil

            try:
                shutil.rmtree(directory)
            except OSError as exc:
                self.append_log(f"[!] could not delete {directory}: {exc}")
                return
            self.append_log(f"[=] deleted {directory}")
            self.forget_current_dump()

        ConfirmPopup(
            title_text="Delete this dump?",
            message=f"{directory}\n\nThis permanently removes the dumped personal data.",
            confirm_action=do_delete,
        ).open()

    # -------------------------------------------------------------- misc
    def _on_mrz_scanned(self, parsed) -> None:
        entry = self.screen("entry")
        if entry is not None:
            entry.set_line2(parsed.mrz_line2)
            entry.fill(
                parsed.bac_document_number,
                parsed.date_of_birth.value,
                parsed.date_of_expiry.value,
            )
        Clock.schedule_once(lambda *_: self.goto("entry"), 0.35)

    def _remember_camera(self, index: int) -> None:
        """Persist the camera the user picked (or that we fell back to)."""
        if self.settings.camera_index == index:
            return
        self.settings.camera_index = index
        self.settings.save()

    def toggle_scale_mode(self) -> None:
        """Swap between filling the window and true relative size.

        A card's MRZ is proportionally larger than a passport's, so a document
        cannot both fill the window and print its MRZ at the same size as
        another format.  This picks which of the two you want.
        """
        from .ui.passport import FIT_TO_WINDOW, TRUE_SCALE

        self.scale_mode = (
            TRUE_SCALE if self.scale_mode == FIT_TO_WINDOW else FIT_TO_WINDOW
        )
        self.settings.page_scale_mode = self.scale_mode
        self.settings.save()
        self._apply_scale_mode()

    def _apply_scale_mode(self) -> None:
        box = self._tab_pages.get(0)
        if box is not None and hasattr(box, "scale_mode"):
            box.scale_mode = self.scale_mode

    def toggle_dark(self) -> None:
        self.dark = not self.dark
        self.palette = theme.palette(self.dark)
        self.settings.dark_chrome = self.dark
        self.settings.save()
        for page in self._tab_pages.values():
            if hasattr(page, "palette"):
                page.palette = self.palette
            if hasattr(page, "refresh"):
                page.refresh()

    def show_error(self, error: errors.Pm3Error, *, detail: str = "") -> None:
        for name in ("entry", "viewer"):
            screen = self.screen(name)
            panel = screen.ids.get("error_panel") if screen is not None else None
            if panel is not None:
                panel.title = error.title
                panel.detail = detail or getattr(error, "detail", "")
                panel.remedy = error.remedy
                panel.visible = True

    def hide_error(self) -> None:
        for name in ("entry", "viewer"):
            screen = self.screen(name)
            panel = screen.ids.get("error_panel") if screen is not None else None
            if panel is not None:
                panel.visible = False

    def on_stop(self) -> None:
        if getattr(self, "_window_size_dirty", False):
            self.settings.save()
        self.client.cancel()
        scan = self.screen("scan")
        if scan is not None:
            scan.stop()


USAGE = """\
An ePassport (eMRTD) viewer for the Proxmark3.

Reads a passport chip over the pm3 CLI and renders it as a data page.
Everything runs offline; nothing is ever uploaded.

Examples:
  ePassport                          read a passport (needs a Proxmark3)
  ePassport --dump DIR               open a saved dump, no hardware needed
  ePassport --dry-run LOG --dump DIR replay a pm3 log you recorded yourself
"""


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ePassport",
        description=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--dump", metavar="DIR", help="open a saved dump directory at startup"
    )
    parser.add_argument(
        "--dry-run",
        metavar="LOG",
        help="replay a recorded pm3 log instead of running pm3",
    )
    parser.add_argument("--pm3-binary", metavar="PATH", help="path to the pm3 client")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    return parser.parse_args(argv)


class _KivyNoise(logging.Filter):
    """Drop Kivy messages that only report a missing optional helper.

    The clipboard cut-buffer probe logs a CRITICAL plus a full traceback when
    xclip and xsel are absent, which is a dozen lines of alarming noise about
    something the app never uses.
    """

    NOISE = (
        "Cutbuffer",
        "Unable to find any valuable Cutbuffer provider",
        "Both Window.minimum_width and Window.minimum_height",
    )

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        return not any(token in message for token in self.NOISE)


def _install_kivy_logging(verbose: bool) -> None:
    """Give Kivy a handler of ours, since its own console one is disabled."""
    from kivy.logger import Logger

    if verbose:
        return  # Kivy kept its own console handler
    if sys.__stderr__ is None:
        return  # pythonw and some frozen builds have no stderr
    # Not sys.stderr: Kivy replaces it with a stream that feeds writes back
    # in as warnings, so a handler on its own logger would loop.
    handler = logging.StreamHandler(sys.__stderr__)
    handler.setFormatter(logging.Formatter("%(levelname)s kivy: %(message)s"))
    handler.addFilter(_KivyNoise())
    Logger.addHandler(handler)
    Logger.setLevel(logging.WARNING)


def quieten_libraries(verbose: bool) -> None:
    """Stop third-party libraries logging into our console.

    pytesseract logs the whole tesseract command line - including the temp
    file path - at DEBUG for every single frame, which at several frames a
    second buries everything else.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    for name in ("pytesseract", "PIL", "matplotlib", "kivy", "glymur", "asn1crypto"):
        logging.getLogger(name).setLevel(level)
    try:
        import cv2

        cv2.setLogLevel(4 if verbose else 1)  # 4 = DEBUG, 1 = FATAL/silent
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    quieten_libraries(args.verbose)
    _install_kivy_logging(args.verbose)
    Pm3PassportApp(args).run()
    return 0
