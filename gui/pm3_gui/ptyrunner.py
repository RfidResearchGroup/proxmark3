"""Simple PTY-based process runner for interactive flashing and pm3 sessions.

This module provides PTYProcess which runs a subprocess attached to a pty.
It exposes a thread-safe output queue and a write() method to send input.
The GUI can poll the output queue periodically to display live output.
"""
import os
import pty
import threading
import subprocess
import queue
import select
import errno
from typing import List, Optional


class PTYProcess:
    def __init__(self, argv: List[str], cwd: Optional[str] = None, env=None):
        self.argv = argv
        self.cwd = cwd
        self.env = env
        self.master_fd = None
        self.pid = None
        self._out_q = queue.Queue()
        self._stop = threading.Event()
        self._read_thread = None

    def start(self):
        if self.pid is not None:
            raise RuntimeError("Process already started")

        self.pid, self.master_fd = pty.fork()
        if self.pid == 0:
            # Child
            try:
                if self.cwd:
                    os.chdir(self.cwd)
                if self.env is not None:
                    os.execvpe(self.argv[0], self.argv, self.env)
                else:
                    os.execvp(self.argv[0], self.argv)
            except Exception as e:
                # If exec fails in child, write to stderr and exit
                print(f"Exec failed: {e}", flush=True)
                os._exit(1)

        # Parent: spawn reader thread
        self._read_thread = threading.Thread(target=self._reader, daemon=True)
        self._read_thread.start()

    def _reader(self):
        fd = self.master_fd
        try:
            while not self._stop.is_set():
                r, _, _ = select.select([fd], [], [], 0.1)
                if fd in r:
                    try:
                        data = os.read(fd, 4096)
                        if not data:
                            break
                        # decode as utf-8 with replacement
                        text = data.decode('utf-8', errors='replace')
                        self._out_q.put((False, text))
                    except OSError as e:
                        if e.errno == errno.EIO:
                            # EOF on some platforms
                            break
                        raise
        finally:
            # put an EOF sentinel (tuple with True flag)
            self._out_q.put((True, ''))

    def read_nowait(self):
        """Return next tuple (is_eof:bool, text:str) or None if no data yet."""
        try:
            item = self._out_q.get_nowait()
            return item
        except queue.Empty:
            return None

    def write(self, data: str):
        if self.master_fd is None:
            raise RuntimeError("Process not started")
        os.write(self.master_fd, data.encode('utf-8'))

    def terminate(self):
        self._stop.set()
        try:
            if self.master_fd:
                os.close(self.master_fd)
        except Exception:
            pass
