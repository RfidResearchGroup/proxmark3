"""The Scan screen: live preview, guide rectangle, OCR at ~4 fps off-thread."""

from __future__ import annotations

import threading
import time

from kivy.clock import Clock
from kivy.graphics import Color, Line, Rectangle
from kivy.properties import (
    BooleanProperty,
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.image import Image as KivyImage
from kivy.uix.screenmanager import Screen
from kivy.uix.widget import Widget

from ..ocr import mrz_ocr
from ..ocr.camera import (
    CameraDevice,
    CameraThread,
    frame_to_texture,
    list_cameras,
    opencv_available,
)
from . import theme

#: The guide rectangle as fractions of the CAMERA FRAME, roughly the MRZ
#: aspect.  The overlay is drawn over the letterboxed image rather than the
#: widget, so these same fractions describe both what the user sees and what
#: :func:`mrz_ocr.crop_to_guide` cuts out.
GUIDE = (0.06, 0.60, 0.88, 0.26)

#: Target period between OCR attempts.  The loop subtracts however long the
#: last attempt took, so this paces the work instead of adding to it.
OCR_INTERVAL = 0.12


class GuideOverlay(Widget):
    """The framing rectangle drawn over the live preview.

    The overlay fills the same area as the preview widget, but draws against
    :attr:`image_rect` - the letterboxed picture inside it.  Anything else and
    the box the user frames stops matching the region actually cropped, which
    is the whole point of having a guide.
    """

    guide = ListProperty(list(GUIDE))
    ok = BooleanProperty(False)
    #: ``(x, y, w, h)`` of the displayed image in window coordinates.  Set as
    #: one expression, never as separate pos/size bindings - those are applied
    #: in an order that can compute a position from a stale size.
    image_rect = ListProperty([0, 0, 0, 0])

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.bind(image_rect=self._redraw, guide=self._redraw, ok=self._redraw)

    def _redraw(self, *_args) -> None:
        self.canvas.after.clear()
        rx, ry, rw, rh = self.image_rect
        if rw < 8 or rh < 8:
            return
        fx, fy, fw, fh = self.guide
        x = rx + fx * rw
        # The guide is expressed top-down; Kivy's origin is bottom-left.
        y = ry + (1.0 - fy - fh) * rh
        w, h = fw * rw, fh * rh
        with self.canvas.after:
            self._draw_scrim(rx, ry, rw, rh, x, y, w, h)
            Color(*(theme.OK if self.ok else (1, 1, 1, 0.9)))
            Line(rectangle=(x, y, w, h), width=2.0)
            corner = min(w, h) * 0.18
            for cx, cy, dx, dy in (
                (x, y, 1, 1),
                (x + w, y, -1, 1),
                (x, y + h, 1, -1),
                (x + w, y + h, -1, -1),
            ):
                Line(
                    points=[cx, cy + dy * corner, cx, cy, cx + dx * corner, cy],
                    width=3.0,
                )

    def _draw_scrim(self, rx, ry, rw, rh, x, y, w, h) -> None:
        """Dim everything outside the box, so the target area is unmistakable."""
        Color(0, 0, 0, 0.45)
        Rectangle(pos=(rx, y + h), size=(rw, ry + rh - (y + h)))  # above
        Rectangle(pos=(rx, ry), size=(rw, y - ry))  # below
        Rectangle(pos=(rx, y), size=(x - rx, h))  # left
        Rectangle(pos=(x + w, y), size=(rx + rw - (x + w), h))  # right


class ScanScreen(Screen):
    """Camera preview plus the OCR worker.  Always optional."""

    status = StringProperty("")
    detail = StringProperty("")
    accepted = BooleanProperty(False)
    frozen = BooleanProperty(False)
    camera_index = NumericProperty(0)
    camera_choices = ListProperty([])
    camera_label = StringProperty("")
    #: 0 means "no camera on this machine" - the Scan screen then exists only
    #: to tell the user so and offer a rescan.
    camera_count = NumericProperty(0)
    has_cameras = BooleanProperty(False)
    palette = ObjectProperty(theme.LIGHT)

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._camera: CameraThread | None = None
        self._acceptor = mrz_ocr.Acceptor()
        self._latest = None
        self._frame_counter = 0
        self._latest_lock = threading.Lock()
        self._ocr_thread: threading.Thread | None = None
        #: One event per run.  Re-entering the screen must not resurrect the
        #: previous run's worker, which is what a single shared event did.
        self._stop_ocr = threading.Event()
        self._stop_ocr.set()
        self._devices: list[CameraDevice] = []
        self._probe_thread: threading.Thread | None = None
        #: The dropdown writes back into :attr:`camera_label`, so setting that
        #: label in code would re-enter :meth:`select_camera` and restart the
        #: camera mid-open.  Suppress the echo instead.
        self._setting_label = False
        self.on_accept = None  # set by the app: callable(mrz)
        self.on_camera_change = None  # set by the app: callable(index)

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        if not opencv_available():
            self.status = "OpenCV is not installed"
            self.detail = "pip install opencv-python-headless"
            return
        available, reason = mrz_ocr.tesseract_available()
        if not available:
            self.status = "OCR unavailable"
            self.detail = reason + "  -  you can still type the MRZ manually."
        else:
            self.status = (
                "Lay the data page flat and fill the box with the two bottom lines"
            )
            self.detail = ""
        self.stop()  # never leave a previous camera or worker running
        self.refresh_cameras()  # names only - probing would fight for the device
        if not self._devices:
            self.status = "No camera found"
            self.detail = (
                "Connect a camera and press Rescan, or use Enter manually - "
                "typing the MRZ works just as well."
            )
            return
        self.accepted = False
        self.frozen = False
        self._acceptor.reset()
        mrz_ocr.use_private_tempdir()
        self._camera = CameraThread(
            index=int(self.camera_index),
            on_frame=self._on_frame,
            on_error=lambda msg: Clock.schedule_once(
                lambda *_: self._show_error(msg), 0
            ),
        )
        self._camera.start()
        if available:
            # One event per run: re-entering the screen must not resurrect the
            # previous run's worker, which a single shared event allowed.
            stop = threading.Event()
            self._stop_ocr = stop
            self._ocr_thread = threading.Thread(
                target=self._ocr_loop,
                args=(stop,),
                name="ePassport-ocr",
                daemon=True,
            )
            self._ocr_thread.start()

    # -- device list -------------------------------------------------------
    def refresh_cameras(self, *, probe: bool = False) -> None:
        """Populate the dropdown.

        Names come from sysfs without opening anything.  Probing which device
        actually delivers frames means opening every one of them, which fights
        with the capture thread for the device - so it only happens on an
        explicit Rescan, with the preview stopped first.
        """
        self._apply_devices(list_cameras())
        if not probe:
            return

        was_running = self._camera is not None
        self.stop()

        def work() -> None:
            devices = list_cameras(probe=True)
            Clock.schedule_once(
                lambda *_: self._probe_finished(devices, was_running), 0
            )

        self._probe_thread = threading.Thread(
            target=work, name="ePassport-camlist", daemon=True
        )
        self._probe_thread.start()

    def _probe_finished(self, devices: list[CameraDevice], restart: bool) -> None:
        self._apply_devices(devices)
        working = [d for d in devices if d.works]
        if working and self._device_for(int(self.camera_index)) not in working:
            self.camera_index = working[0].index
            self._set_label(working[0].label)
            if callable(self.on_camera_change):
                self.on_camera_change(working[0].index)
        self.status = (
            f"{len(working)} working camera(s) found"
            if working
            else "No camera delivered a frame - check permissions"
        )
        if restart:
            self.start()

    def _apply_devices(self, devices: list[CameraDevice]) -> None:
        # Keep any "works" verdict we already established.
        known = {d.index: d.works for d in self._devices if d.works is not None}
        for device in devices:
            if device.works is None and device.index in known:
                device.works = known[device.index]
        self._devices = devices
        self.camera_choices = [d.label for d in devices]
        self.camera_count = len(devices)
        self.has_cameras = bool(devices)
        current = self._device_for(int(self.camera_index))
        if current is not None:
            self._set_label(current.label)
        elif self.camera_choices:
            self._set_label(self.camera_choices[0])
        else:
            self._set_label("")

    def _set_label(self, label: str) -> None:
        """Set the dropdown's text without it echoing back as a selection."""
        if label == self.camera_label:
            return
        self._setting_label = True
        try:
            self.camera_label = label
        finally:
            self._setting_label = False

    def _device_for(self, index: int) -> CameraDevice | None:
        for device in self._devices:
            if device.index == index:
                return device
        return None

    def select_camera(self, label: str) -> None:
        """Switch to the device the user picked and restart the preview."""
        if self._setting_label or not label:
            return  # our own update echoing back, not a user choice
        for device in self._devices:
            if device.label != label:
                continue
            if device.index == int(self.camera_index) and self._camera is not None:
                return
            self.camera_index = device.index
            self.camera_label = label
            if callable(self.on_camera_change):
                self.on_camera_change(device.index)
            self.start()
            return

    def _sync_label_to_camera(self) -> None:
        """Frames are arriving, so record which device actually works - and
        follow along if the capture thread fell back to another index."""
        camera = self._camera
        if camera is None:
            return
        device = self._device_for(camera.index)
        if device is not None and device.works is not True:
            device.works = True
            self.camera_choices = [d.label for d in self._devices]
        if int(self.camera_index) != camera.index:
            self.camera_index = camera.index
            if device is not None:
                self._set_label(device.label)
            if callable(self.on_camera_change):
                self.on_camera_change(camera.index)

    def stop(self) -> None:
        """Release the camera and the OCR worker.  Idempotent."""
        self._stop_ocr.set()
        mrz_ocr.clear_private_tempdir()
        thread, self._ocr_thread = self._ocr_thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)
        camera, self._camera = self._camera, None
        if camera is not None:
            camera.stop()
        probe, self._probe_thread = self._probe_thread, None
        if probe is not None and probe.is_alive():
            probe.join(timeout=5.0)

    def on_leave(self, *_args) -> None:
        self.stop()

    # -- capture thread ----------------------------------------------------
    def _on_frame(self, frame) -> None:
        if self.frozen:
            return
        with self._latest_lock:
            self._latest = frame
            self._frame_counter += 1
        Clock.schedule_once(lambda *_: self._blit(frame), 0)

    def _blit(self, frame) -> None:
        if self.frozen:
            return
        self._sync_label_to_camera()
        preview: KivyImage | None = self.ids.get("preview")
        if preview is None:
            return
        try:
            preview.texture = frame_to_texture(frame)
        except Exception:
            pass

    # -- OCR thread --------------------------------------------------------
    def _ocr_loop(self, stop: threading.Event) -> None:
        seen = 0
        while not stop.is_set():
            started = time.monotonic()
            frame = None
            if not self.frozen:
                with self._latest_lock:
                    frame = self._latest
                    counter = self._frame_counter
                # Re-reading a frame we already processed cannot tell us
                # anything new, and OCR is the most expensive thing here.
                if frame is not None and counter == seen:
                    frame = None
                else:
                    seen = counter
            if frame is not None:
                result = mrz_ocr.read_frame(frame.array, guide=GUIDE)
                if stop.is_set():
                    return
                result = self._acceptor.offer(result)
                Clock.schedule_once(lambda *_, r=result: self._on_result(r), 0)
            # Pace the loop: sleep only the remainder of the interval, so a
            # slow OCR pass does not have a full sleep added on top of it.
            elapsed = time.monotonic() - started
            if elapsed < OCR_INTERVAL:
                stop.wait(OCR_INTERVAL - elapsed)

    def _on_result(self, result: mrz_ocr.OcrResult) -> None:
        overlay: GuideOverlay | None = self.ids.get("overlay")
        if overlay is not None:
            overlay.ok = result.checks_ok
        if result.mrz is not None:
            self.detail = "  ".join(result.lines)
        self.status = result.reason or "scanning…"
        if result.accepted and not self.accepted:
            self._accept(result)

    def _accept(self, result: mrz_ocr.OcrResult) -> None:
        """Freeze, flash green, release the camera, hand the MRZ to the app."""
        self.accepted = True
        self.frozen = True
        self.status = (
            "Line 2 captured - that is everything BAC needs"
            if result.line2_only
            else "MRZ captured"
        )
        blind = result.unverifiable_characters
        if blind:
            self.detail = (
                "Check the document number: the MRZ check digits cannot tell "
                f"{', '.join(blind)} apart from their look-alikes."
            )
        self.stop()
        if callable(self.on_accept):
            self.on_accept(result.mrz)

    def _show_error(self, message: str) -> None:
        self.status = "Camera error"
        self.detail = message
