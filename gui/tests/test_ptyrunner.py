import os
import stat
import subprocess
import time
from pm3_gui.ptyrunner import PTYProcess


def test_ptyrunner_echo(tmp_path):
    # create a small script that echos a prompt and reads a line
    script = tmp_path / "echo_prompt.sh"
    script.write_text("#!/bin/sh\nprintf 'PROMPT: ' >&1\nread line\necho GOT:$line\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)

    p = PTYProcess([str(script)])
    p.start()

    # read until prompt appears
    got_prompt = False
    deadline = time.time() + 5
    while time.time() < deadline:
        item = p.read_nowait()
        if item is None:
            time.sleep(0.05)
            continue
        is_eof, text = item
        if text and 'PROMPT:' in text:
            got_prompt = True
            break

    assert got_prompt

    # send input
    p.write('hello\n')

    # read response
    got = ''
    deadline = time.time() + 5
    while time.time() < deadline:
        item = p.read_nowait()
        if item is None:
            time.sleep(0.05)
            continue
        is_eof, text = item
        if text:
            got += text
        if is_eof:
            break

    assert 'GOT:hello' in got