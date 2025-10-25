# pm3-gui

Lightweight GUI wrapper for the Proxmark3 client.

This is a minimal starter GUI that can be installed with pip (from the `gui/` folder) and used to run simple non-interactive commands against a built `pm3` client binary.

Quick start (Linux):

1. Build the `pm3` client from the repository root (see top-level README). Make sure `./pm3` exists or install the built `pm3` into your PATH.

2. From this `gui/` folder install the GUI package:

```bash
cd gui
pip install --upgrade .
```

3. Run the GUI (or get version non-interactively):

```bash
pm3-gui --version
# or launch the graphical UI
pm3-gui
```

New features added:

- Device autodetect: detect serial devices from the GUI or CLI (`--detect-devices`).
- Interactive flashing: the GUI will run `pm3-flash` (or other flash scripts) inside a PTY so the script can prompt and show progress. A small input box lets you type responses to prompts while the flash is running.
- Confirmation safeguard: flashing requires an explicit typed confirmation (type FLASH) before proceeding.
- udev helpers: the GUI shows a udev rules template and can copy it to clipboard. There's a "Install udev (pkexec)" button that attempts to run the provided install script using `pkexec` or `sudo` (you will be prompted for credentials by your desktop environment or terminal).
- Packaging & CI: the repository includes a lightweight GitHub Actions workflow that runs tests and builds a wheel for the GUI package.

Notes & safety:

- Always review the udev rules and the install script before running them as root.
- Flashing is destructive by design — use the confirmation dialog and ensure the device path and script are correct.
- The PTY-based console is a simple text passthrough (no full terminal emulation). For full terminal behavior we can integrate a terminal widget (QTermWidget) in a future iteration.

## AppImage packaging (optional)

I included a minimal AppImage skeleton and a local helper script in `gui/packaging` and `gui/scripts/build-appimage.sh`.
To build an AppImage locally:

```bash
pip install appimage-builder
./gui/scripts/build-appimage.sh
```

This is intentionally a local helper. CI-level AppImage builds require more setup (tooling, caching, signing) and can be added to the repository's GitHub Actions if you want — say the word and I'll add a CI job that produces an AppImage artifact per release.


## Notes and next steps

- Current implementation is Linux-first and lightweight. It wraps the `pm3` executable and lets you run single commands and see the output.

- Next steps: support interactive terminal bridging, packaging (deb/AppImage), advanced device-management UI, Mac/Windows wrappers.
