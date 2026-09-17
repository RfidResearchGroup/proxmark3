"""Drive the running app and screenshot every tab, for eyeballing a build.

python3 tools_screenshot.py samples/td3_utopia /tmp/shots
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("KIVY_NO_ARGS", "1")

from kivy.clock import Clock  # noqa: E402

from epassport.__main__ import Pm3PassportApp, parse_args  # noqa: E402


def main() -> int:
    dump = sys.argv[1] if len(sys.argv) > 1 else "samples/td3_utopia"
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else "/tmp/shots")
    outdir.mkdir(parents=True, exist_ok=True)

    args = parse_args(["--dump", dump])
    app = Pm3PassportApp(args)
    steps: list[tuple[str, object]] = []

    def shoot(name: str):
        from kivy.core.window import Window

        Window.screenshot(name=str(outdir / f"{name}.png"))

    def script(*_a) -> None:
        if not steps:
            app.stop()
            return
        name, action = steps.pop(0)
        if callable(action):
            action()
        Clock.schedule_once(
            lambda *_: (shoot(name), Clock.schedule_once(script, 0.6)), 0.8
        )

    for index, label in enumerate(
        ("datapage", "personal", "issuer", "security", "files", "log")
    ):
        steps.append((f"{index}_{label}", lambda i=index: app.select_tab(i)))
    steps.append(("6_entry", app.goto_entry))
    steps.append(("7_dark", app.toggle_dark))

    original = app.on_start

    def on_start() -> None:
        original()
        Clock.schedule_once(script, 1.5)

    app.on_start = on_start
    app.run()
    print("shots in", outdir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
