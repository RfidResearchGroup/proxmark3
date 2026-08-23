"""Render the passport data page to a PNG, headless-ish, for eyeballing.

python3 tools_render_page.py samples/td3_utopia out.png
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("KIVY_NO_ARGS", "1")
os.environ.setdefault("KIVY_NO_CONSOLELOG", "1")

from kivy.app import App  # noqa: E402
from kivy.clock import Clock  # noqa: E402
from kivy.config import Config  # noqa: E402

Config.set("graphics", "width", "1280")
Config.set("graphics", "height", "860")

from epassport.emrtd.dg import load_dump  # noqa: E402
from epassport.ui import load_kv  # noqa: E402


class RenderApp(App):
    def __init__(self, dump: Path, out: Path, **kwargs) -> None:
        super().__init__(**kwargs)
        self.dump = dump
        self.out = out

    def build(self):
        load_kv()
        from epassport.ui.passport import AspectBox, PassportPage

        box = AspectBox()
        page = PassportPage()
        page.record = load_dump(self.dump)
        box.add_widget(page)
        return box

    def on_start(self) -> None:
        Clock.schedule_once(self._shoot, 1.2)

    def _shoot(self, *_a) -> None:
        from kivy.core.window import Window

        Window.screenshot(name=str(self.out))
        self.stop()


if __name__ == "__main__":
    dump = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/td3_utopia")
    out = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/page.png")
    RenderApp(dump, out).run()
    print("wrote", out)
