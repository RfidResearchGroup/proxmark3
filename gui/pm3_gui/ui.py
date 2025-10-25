"""Simple PySide6-based GUI for pm3 (minimal starter).

This module is intentionally small: it provides a main window that allows the user
to run one-off pm3 commands and view output. Interactive shell bridging is left
for a follow-up iteration.
"""

from typing import Optional
import subprocess
import sys
import os

from PySide6 import QtWidgets, QtCore
from PySide6.QtCore import QProcess
from PySide6.QtGui import QKeySequence

from .devices import list_serial_ports, find_flash_script

# Optional richer terminal widget: prefer QTermWidget if available (native terminal widget),
# otherwise fall back to pyte-based TerminalWidget. If neither available, use plain text.
TerminalWidget = None
QTermWidget = None
try:
    # qtermwidget Python bindings (if installed in environment)
    from qtermwidget import QTermWidget
    QTermWidget = QTermWidget
except Exception:
    QTermWidget = None

try:
    from .terminal import TerminalWidget as PyteTerminalWidget
except Exception:
    PyteTerminalWidget = None

if QTermWidget is not None:
    TerminalWidget = QTermWidget
elif PyteTerminalWidget is not None:
    TerminalWidget = PyteTerminalWidget
else:
    TerminalWidget = None


class HistoryLineEdit(QtWidgets.QLineEdit):
    """QLineEdit with simple up/down history navigation backed by a list."""
    def __init__(self, history: list, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._history = history
        self._hist_idx = len(history)

    def keyPressEvent(self, event):
        key = event.key()
        if key == QtCore.Qt.Key_Up:
            if self._history and self._hist_idx > 0:
                self._hist_idx -= 1
                self.setText(self._history[self._hist_idx])
                return
        elif key == QtCore.Qt.Key_Down:
            if self._history and self._hist_idx < len(self._history) - 1:
                self._hist_idx += 1
                self.setText(self._history[self._hist_idx])
                return
            else:
                self._hist_idx = len(self._history)
                self.clear()
                return
        super().keyPressEvent(event)


class PM3GuiApp:
    def __init__(self, pm3_path: str):
        self.pm3_path = pm3_path
        self._qt_app = QtWidgets.QApplication(sys.argv)
        self._main = QtWidgets.QMainWindow()
        self._main.setWindowTitle("pm3 GUI (minimal)")
        self._main.resize(900, 700)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        # Presets and command input (with history)
        run_row = QtWidgets.QHBoxLayout()
        self.preset_combo = QtWidgets.QComboBox()
        self.preset_combo.addItem("-- presets --")
        for p in ("hf search", "hf 14a list", "lf sniff", "hf mf chk", "hf 14a trace"):
            self.preset_combo.addItem(p)
        self.preset_combo.currentIndexChanged.connect(self._on_preset)
        run_row.addWidget(self.preset_combo)

        self.cmd_input = HistoryLineEdit(history=[], parent=None)
        self.cmd_input.setPlaceholderText("Enter a single pm3 command (e.g. 'hf search')")
        run_row.addWidget(self.cmd_input, 1)

        run_btn = QtWidgets.QPushButton("Run")
        run_btn.clicked.connect(self._on_run)
        run_row.addWidget(run_btn)

        layout.addLayout(run_row)

        # Device detection row
        dev_row = QtWidgets.QHBoxLayout()
        self.dev_combo = QtWidgets.QComboBox()
        self.dev_combo.setEditable(False)
        self.dev_combo.currentIndexChanged.connect(self._on_device_selected)
        dev_row.addWidget(self.dev_combo, 1)
        detect_btn = QtWidgets.QPushButton("Detect Devices")
        detect_btn.clicked.connect(self._on_detect)
        dev_row.addWidget(detect_btn)
        layout.addLayout(dev_row)

        # Terminal output area (better rendering for PTY output when pyte available)
        if TerminalWidget is not None:
            self.terminal = TerminalWidget(cols=100, rows=40, parent=self._main)
            layout.addWidget(self.terminal, 1)
        else:
            self.terminal = QtWidgets.QPlainTextEdit()
            self.terminal.setReadOnly(True)
            layout.addWidget(self.terminal, 1)

        # Flash / udev area
        flash_row = QtWidgets.QHBoxLayout()
        self.flash_button = QtWidgets.QPushButton("Flash (pm3-flash)")
        self.flash_button.clicked.connect(self._on_flash)
        self.flash_button.setEnabled(False)
        flash_row.addWidget(self.flash_button)

        self.udev_btn = QtWidgets.QPushButton("udev rules & install")
        self.udev_btn.clicked.connect(self._on_udev)
        flash_row.addWidget(self.udev_btn)

        self.pkexec_btn = QtWidgets.QPushButton("Install udev (pkexec)")
        self.pkexec_btn.clicked.connect(self._on_pkexec_install)
        flash_row.addWidget(self.pkexec_btn)

        layout.addLayout(flash_row)

        # PTY interactive input (send to running PTY session)
        pty_row = QtWidgets.QHBoxLayout()
        self.pty_input = QtWidgets.QLineEdit()
        self.pty_input.setPlaceholderText("Type to send to interactive flash / pm3 session")
        self.pty_input.returnPressed.connect(self._on_send_input)
        self.pty_input.setEnabled(False)
        pty_row.addWidget(self.pty_input, 1)
        send_btn = QtWidgets.QPushButton("Send")
        send_btn.clicked.connect(self._on_send_input)
        pty_row.addWidget(send_btn)
        layout.addLayout(pty_row)

        # Simple status bar
        status = QtWidgets.QStatusBar()
        self._main.setStatusBar(status)

        self._main.setCentralWidget(central)

        # internal state
        self.history = []
        self.input_history = []

    def _append(self, text: str):
        # Append to terminal if possible, otherwise to the raw text widget
        if hasattr(self, 'terminal') and TerminalWidget is not None:
            try:
                # We use append_plain to avoid pyte parsing for log lines
                self.terminal.append_plain(text)
                return
            except Exception:
                pass
        if hasattr(self, 'terminal'):
            self.terminal.appendPlainText(text)

    def _on_run(self):
        cmd = self.cmd_input.text().strip()
        if not cmd:
            self._append("No command entered.")
            return

        self._append(f"> {cmd}")
        QtCore.QCoreApplication.processEvents()
        try:
            proc = subprocess.run([self.pm3_path, cmd], capture_output=True, text=True, timeout=120)
            out = proc.stdout + proc.stderr
            self._append(out)
        except Exception as e:
            self._append(f"Failed to run pm3: {e}")
        # Save to history
        try:
            self.history.append(cmd)
            # update HistoryLineEdit backing list and reset index
            if isinstance(self.cmd_input, HistoryLineEdit):
                self.cmd_input._history = self.history
                self.cmd_input._hist_idx = len(self.history)
        except Exception:
            pass

    def _on_detect(self):
        self.dev_combo.clear()
        ports = list_serial_ports()
        if not ports:
            self._append("No serial ports detected.")
            return
        for dev, desc in ports:
            self.dev_combo.addItem(f"{dev} — {desc}", dev)
        self._append(f"Detected {len(ports)} ports")
        # enable flash button if at least one device present
        self.flash_button.setEnabled(self.dev_combo.count() > 0)

    def _on_device_selected(self, idx: int):
        self.flash_button.setEnabled(idx >= 0)

    def _on_preset(self, idx: int):
        if idx <= 0:
            return
        text = self.preset_combo.currentText()
        self.cmd_input.setText(text)

    def _on_udev(self):
        # Show udev rules file contents and offer to copy to clipboard
        rules_path = os.path.join(os.path.dirname(__file__), '..', 'scripts', 'udev_rules.txt')
        rules_path = os.path.abspath(rules_path)
        try:
            with open(rules_path, 'r') as f:
                data = f.read()
        except Exception:
            data = "(udev rules template not found)"

        dlg = QtWidgets.QMessageBox(self._main)
        dlg.setWindowTitle("udev rules and install")
        dlg.setText("udev rules template (you may need sudo to install).\n\nCopy to clipboard or run the install script as root.")
        dlg.setDetailedText(data)
        copy_btn = dlg.addButton("Copy to clipboard", QtWidgets.QMessageBox.ActionRole)
        show_cmd_btn = dlg.addButton("Show install command", QtWidgets.QMessageBox.ActionRole)
        dlg.addButton(QtWidgets.QMessageBox.Close)
        dlg.exec()

        if dlg.clickedButton() == copy_btn:
            QtWidgets.QApplication.clipboard().setText(data)
            self._append("udev rules copied to clipboard")
        elif dlg.clickedButton() == show_cmd_btn:
            cmd = f"sudo {os.path.join(os.path.dirname(__file__), '..', 'scripts', 'install-udev.sh')}"
            QtWidgets.QMessageBox.information(self._main, "Install command", cmd)

    def _on_pkexec_install(self):
        # Try to run the install script using pkexec; fall back to showing command
        script = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts', 'install-udev.sh'))
        if not os.path.exists(script):
            QtWidgets.QMessageBox.warning(self._main, "Install udev", f"Install script not found: {script}")
            return
        # Confirmation
        ok = QtWidgets.QMessageBox.question(self._main, "Run install as root?", "This will run an install script as root to install udev rules. Continue?",
                                            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        if ok != QtWidgets.QMessageBox.Yes:
            return
        # Attempt pkexec
        try:
            import shutil
            pk = shutil.which('pkexec')
            if pk:
                subprocess.run([pk, 'bash', script], check=True)
                self._append('udev install completed via pkexec')
                return
            # fallback to sudo (will prompt in terminal)
            su = shutil.which('sudo')
            if su:
                subprocess.run([su, 'bash', script], check=True)
                self._append('udev install attempted via sudo')
                return
        except Exception as e:
            self._append(f'Failed to run install script: {e}')
            QtWidgets.QMessageBox.warning(self._main, "Install failed", str(e))

    def _confirm_flash(self) -> bool:
        dlg = QtWidgets.QDialog(self._main)
        dlg.setWindowTitle("Confirm flash")
        v = QtWidgets.QVBoxLayout(dlg)
        v.addWidget(QtWidgets.QLabel("Flashing will overwrite device firmware. This is potentially destructive."))
        v.addWidget(QtWidgets.QLabel("Type FLASH in the box below to confirm and press Confirm."))
        edit = QtWidgets.QLineEdit()
        v.addWidget(edit)
        btns = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Ok)
        v.addWidget(btns)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        res = dlg.exec()
        if res == QtWidgets.QDialog.Accepted and edit.text().strip() == "FLASH":
            return True
        return False

    def _on_flash(self):
        # Find flash script
        script = find_flash_script()
        if not script:
            self._append("No flash script found in repo root or PATH.")
            return

        # Determine device arg from combo box if available
        device = None
        if self.dev_combo.count() > 0:
            device = self.dev_combo.currentData()

        args = [script]
        if device:
            args.append(device)

        self._append(f"Running flash: {' '.join(args)}")

        # Confirm destructive action
        if not self._confirm_flash():
            self._append("Flash cancelled by user.")
            return

        # Use PTY runner to handle interactive prompts; fall back to QProcess
        try:
            from .ptyrunner import PTYProcess
        except Exception:
            PTYProcess = None

        if PTYProcess:
            self._append("Starting interactive flash via PTY...")
            argv = args
            self._pty = PTYProcess(argv)
            self._pty.start()
            # Start a QTimer to poll output
            if not hasattr(self, '_pty_timer'):
                self._pty_timer = QtCore.QTimer(self._main)
                self._pty_timer.setInterval(150)
                self._pty_timer.timeout.connect(self._poll_pty)
                self._pty_timer.start()
            # enable input field
            self.pty_input.setEnabled(True)
        else:
            # Fallback to QProcess
            self._append("PTY runner unavailable; using QProcess fallback")
            self._qproc = QProcess(self._main)
            self._qproc.setProgram(script)
            self._qproc.setArguments(args[1:])
            self._qproc.readyReadStandardOutput.connect(self._flash_stdout)
            self._qproc.readyReadStandardError.connect(self._flash_stderr)
            self._qproc.finished.connect(self._flash_finished)
            self._qproc.start()

    def _on_send_input(self):
        txt = self.pty_input.text()
        if not txt:
            return
        # send to PTY if running
        if hasattr(self, '_pty') and self._pty is not None:
            try:
                self._pty.write(txt + '\n')
                self._append(f"<sent> {txt}")
            except Exception as e:
                self._append(f"Failed to send to PTY: {e}")
        elif hasattr(self, '_qproc') and self._qproc is not None:
            # QProcess fallback: write to stdin if supported
            try:
                self._qproc.write((txt + '\n').encode('utf-8'))
                self._append(f"<sent> {txt}")
            except Exception as e:
                self._append(f"Failed to write to process stdin: {e}")
        else:
            self._append("No running process to send input to.")
        # add to history
        self.input_history.append(txt)
        self.pty_input.clear()

    def _flash_stdout(self):
        out = bytes(self._qproc.readAllStandardOutput()).decode('utf-8', errors='replace')
        # If we have a TerminalWidget, feed bytes to pyte for rendering
        if hasattr(self, 'terminal') and TerminalWidget is not None:
            try:
                self.terminal.feed(out.encode('utf-8'))
                return
            except Exception:
                pass
        self._append(out)

    def _flash_stderr(self):
        out = bytes(self._qproc.readAllStandardError()).decode('utf-8', errors='replace')
        if hasattr(self, 'terminal') and TerminalWidget is not None:
            try:
                self.terminal.feed(out.encode('utf-8'))
                return
            except Exception:
                pass
        self._append(out)

    def _flash_finished(self, exitCode, exitStatus):
        self._append(f"Flash finished with code {exitCode}")

    def _poll_pty(self):
        if not hasattr(self, '_pty') or self._pty is None:
            return
        while True:
            item = self._pty.read_nowait()
            if item is None:
                break
            is_eof, text = item
            if is_eof:
                self._append("[PTY finished]")
                # disable input
                self.pty_input.setEnabled(False)
                return
            if text:
                # feed to TerminalWidget if available else append
                if hasattr(self, 'terminal') and TerminalWidget is not None:
                    try:
                        self.terminal.feed(text.encode('utf-8'))
                        continue
                    except Exception:
                        pass
                self._append(text)

    def run(self) -> int:
        self._main.show()
        return self._qt_app.exec()
