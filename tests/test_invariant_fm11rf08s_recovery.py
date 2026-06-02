import pytest
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent.parent / "pyscripts"))
import fm11rf08s_recovery


@pytest.mark.parametrize("malicious_uid", [
    "123456789ABCDEF; rm -rf /",  # Command injection with semicolon
    "123456789ABCDEF$(whoami)",    # Command substitution
    "123456789ABCDEF`id`",         # Backtick command substitution
    "123456789ABCDEF| cat /etc/passwd",  # Pipe injection
    "123456789ABCDEF",             # Valid UID (baseline)
])
def test_shell_injection_prevention(malicious_uid):
    """Invariant: Shell metacharacters in card UIDs never reach unescaped shell execution"""
    
    # Mock the subprocess.run to capture what command would be executed
    captured_commands = []
    
    def mock_run(cmd, *args, **kwargs):
        captured_commands.append(cmd)
        result = MagicMock()
        result.stdout = ""
        result.returncode = 0
        return result
    
    with patch("subprocess.run", side_effect=mock_run):
        with patch("fm11rf08s_recovery.detect_reader", return_value=True):
            with patch("fm11rf08s_recovery.select_card", return_value=True):
                # Attempt to trigger command construction with malicious UID
                try:
                    fm11rf08s_recovery.recover_card(malicious_uid)
                except Exception:
                    pass  # We only care about command construction, not execution
    
    # Assert: if commands were captured, they must be lists (not shell-injectable strings)
    # or if strings, must not contain unescaped metacharacters from the payload
    for cmd in captured_commands:
        if isinstance(cmd, str):
            # If cmd is a string, it should not contain raw shell metacharacters
            # from the malicious payload (they should be escaped or rejected)
            dangerous_chars = ["; rm", "$(", "`", "| cat"]
            for char_seq in dangerous_chars:
                assert char_seq not in cmd, \
                    f"Unescaped shell metacharacter '{char_seq}' found in command: {cmd}"
        else:
            # Commands passed as lists are safe from shell injection
            assert isinstance(cmd, list), \
                f"Command must be list or properly escaped string, got: {type(cmd)}"