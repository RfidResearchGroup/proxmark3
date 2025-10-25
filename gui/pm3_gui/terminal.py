"""Simple terminal widget using pyte for basic VT100 rendering.

This is a lightweight solution that renders most text-based output (prompts,
line output) and is not a full-featured terminal emulator. It improves readability
of PTY output compared to raw text passthrough.
"""
from PySide6 import QtWidgets, QtCore
import pyte


class TerminalWidget(QtWidgets.QWidget):
    def __init__(self, cols=80, rows=24, parent=None):
        super().__init__(parent)
        self._text = QtWidgets.QPlainTextEdit()
        self._text.setReadOnly(True)
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._text)

        self.screen = pyte.Screen(cols, rows)
        self.stream = pyte.Stream(self.screen)

    def feed(self, data: bytes):
        try:
            text = data.decode('utf-8', errors='replace')
        except Exception:
            text = str(data)
        # feed to pyte stream; pyte mutates screen
        self.stream.feed(text)
        self._render()

    def _render(self):
        # Render screen lines to a single string
        lines = []
        for y in range(self.screen.lines):
            line = self.screen.display[y]
            lines.append(line.rstrip())
        out = "\n".join(lines).rstrip() + "\n"
        # Replace the widget content efficiently
        self._text.setPlainText(out)
        # scroll to bottom
        cursor = self._text.textCursor()
        cursor.movePosition(cursor.End)
        self._text.setTextCursor(cursor)

    def append_plain(self, text: str):
        # convenience to append simple lines without pyte parsing
        self._text.appendPlainText(text)
