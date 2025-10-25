import argparse
import os
import shutil
import subprocess
import sys

from . import __version__


def find_pm3(pm3_path=None):
    # If pm3_path provided, use that. Otherwise check cwd ./pm3 then PATH.
    if pm3_path:
        if os.path.isfile(pm3_path) and os.access(pm3_path, os.X_OK):
            return pm3_path
        raise FileNotFoundError(f"pm3 binary not found or not executable: {pm3_path}")

    cwd_path = os.path.join(os.getcwd(), "pm3")
    if os.path.isfile(cwd_path) and os.access(cwd_path, os.X_OK):
        return cwd_path

    which_pm3 = shutil.which("pm3")
    if which_pm3:
        return which_pm3

    raise FileNotFoundError("pm3 binary not found. Build it from the repository root or place it in PATH.")


def run_pm3_command(pm3_path, command):
    # Run a single command non-interactively using the pm3 binary.
    # For now we run pm3 with the provided command as a single argument.
    # This is intentionally conservative - if pm3 supports a -c/--cmd flag in future,
    # update this to use that to avoid shell interpretation.
    proc = subprocess.run([pm3_path, command], capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout + proc.stderr


def main(argv=None):
    parser = argparse.ArgumentParser(prog="pm3-gui")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    parser.add_argument("--pm3-path", help="path to pm3 binary (executable)")
    parser.add_argument("--nogui", action="store_true", help="do not launch GUI; useful for CI/tests")
    parser.add_argument("--test-cmd", help="run a simple pm3 command non-interactively and exit")
    parser.add_argument("--detect-devices", action="store_true", help="list candidate serial devices and exit")
    parser.add_argument("--flash", nargs="?", const="pm3-flash", help="run a flash script non-interactively (script name or blank for default pm3-flash)")
    parser.add_argument("--flash-device", help="device path to pass to flash script (if required)")

    args = parser.parse_args(argv)

    if args.version:
        print(__version__)
        return 0

    try:
        pm3_path = find_pm3(args.pm3_path)
    except FileNotFoundError as e:
        print(str(e), file=sys.stderr)
        return 2

    if args.nogui:
        print(f"Found pm3 binary: {pm3_path}")
        # Non-GUI convenience operations
        if args.detect_devices:
            try:
                from .devices import list_serial_ports
            except Exception:
                print("pyserial not available; falling back to naive detection")
                from .devices import list_serial_ports

            ports = list_serial_ports()
            if not ports:
                print("No serial ports found")
            else:
                for dev, desc in ports:
                    print(f"{dev}\t{desc}")
            return 0

        if args.flash:
            # Run flash script (search repo root or PATH)
            from .devices import find_flash_script
            script = args.flash
            # if user passed no arg, args.flash is 'pm3-flash' due to const
            # allow user to specify a different script filename
            candidate = find_flash_script([script]) or find_flash_script()
            if not candidate:
                print("No flash script found (tried pm3-flash and variants). Build tools are in the repo root.")
                return 4
            # build command
            cmd = [candidate]
            if args.flash_device:
                cmd.append(args.flash_device)
            print(f"Running: {' '.join(cmd)}")
            try:
                proc = __import__('subprocess').run(cmd, capture_output=True, text=True)
                print(proc.stdout)
                print(proc.stderr, file=sys.stderr)
                return proc.returncode
            except Exception as e:
                print(f"Failed to run flash script: {e}", file=sys.stderr)
                return 5

        if args.test_cmd:
            rc, out = run_pm3_command(pm3_path, args.test_cmd)
            print(out)
            return rc
        return 0

    # Lazily import the UI so --nogui or --version doesn't require PySide6
    try:
        from .ui import PM3GuiApp
    except Exception as e:
        print("Failed to import GUI dependencies (PySide6).\nInstall PySide6 or run with --nogui.", file=sys.stderr)
        print("Import error:", e, file=sys.stderr)
        return 3

    # Launch the graphical application
    app = PM3GuiApp(pm3_path=pm3_path)
    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())
