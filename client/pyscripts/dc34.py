#!/usr/bin/env python3

# See https://dc34.rfid.wtf/

import subprocess
import time
import sys
import os
import re
from enum import Enum
from dataclasses import dataclass
import struct
from collections.abc import Sequence
from typing import List, Optional
import logging

# This try block allows send_proxmark_command() to work both
# from within the proxmark3 client environment (where pm3.py is available)
# and from outside (where it must call the proxmark3 binary via subprocess).
try:
    import pm3  # Used when inside the pm3 environment
    PM3_AVAILABLE = True
    p = pm3.pm3()
except ImportError:
    PM3_AVAILABLE = False  # Use subprocess instead

required_version = (3, 10)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    sys.exit(1)



if True:  # Logging helper
    LOG = logging.getLogger(__name__)
    LOG_HF14 = logging.getLogger("HF14")
    LOG_PROXMARK = logging.getLogger("PROXMARK_COMMANDS")
    LOG_PM_DEVICE = logging.getLogger("PM_DEVICE")

    LOG_HF14.parent = LOG
    LOG_PROXMARK.parent = LOG
    LOG_PM_DEVICE.parent = LOG

    if len(LOG.handlers) < 1:
        LOG.addHandler(logging.StreamHandler(sys.stdout))
    # LOG_HF14.addHandler(logging.StreamHandler(sys.stdout))
    # LOG_PROXMARK.addHandler(logging.StreamHandler(sys.stdout))
    # LOG_PM_DEVICE.addHandler(logging.StreamHandler(sys.stdout))
    LOG.setLevel(logging.DEBUG)
    LOG_HF14.setLevel(logging.ERROR)
    LOG_PROXMARK.setLevel(logging.ERROR)
    LOG_PM_DEVICE.setLevel(logging.ERROR)

if True:  # Enumerations

    class Status_HF14a(Enum):
        InvalidDataLength    = 0x6700
        InsNotSupported      = 0x6D00
        ClaNotSupported      = 0x6E00
        Success              = 0x9000

    class Status_Hangman(Enum):
        InvalidDataLength    = Status_HF14a.InvalidDataLength.value
        InsNotSupported      = Status_HF14a.InsNotSupported.value
        ClaNotSupported      = Status_HF14a.ClaNotSupported.value
        Success              = Status_HF14a.Success.value
        NoActiveGame         = 0x6985 # No Active Game (send NEW GAME command first)
        GameFinished         = 0x6986 # Same result, win or lose
        InvalidLetterInput   = 0x6A80 # Must be in range [A-Z] (0x41..0x5A)
        LetterAlreadyGuessed = 0x6A86

    class Status_TicTacToe(Enum):
        InvalidDataLength    = Status_HF14a.InvalidDataLength.value
        InsNotSupported      = Status_HF14a.InsNotSupported.value
        ClaNotSupported      = Status_HF14a.ClaNotSupported.value
        Success              = Status_HF14a.Success.value
        NoActiveGame         = 0x6985 # No Active Game (send NEW GAME command first)
        GameFinished         = 0x6986 # Game already finished
        CellAlreadyOccupied  = 0x6A80 # Cell already occupied
        InvalidParameters    = 0x6A86 # Row must be [0..2], Column must be [0..2]

    class Status_GuessKey(Enum):
        InvalidDataLength    = Status_HF14a.InvalidDataLength.value
        InsNotSupported      = Status_HF14a.InsNotSupported.value
        ClaNotSupported      = Status_HF14a.ClaNotSupported.value
        Success              = Status_HF14a.Success.value
        GameFinished         = 0x6986 # This is a one-time game ... can only play once
        IncorrectGuess       = 0x6A80 # The guess was not the correct key

    class TicTacToe_CellValue(Enum):
        _ = 0
        X = 1
        O = 2

        def __str__(self):
            if self == TicTacToe_CellValue._:
                return " "
            elif self == TicTacToe_CellValue.X:
                return "X"
            elif self == TicTacToe_CellValue.O:
                return "O"
            else:
                return "?"

    class TicTacToe_GameStatus(Enum):
        InProgress = 0
        User_Wins  = 1
        Card_Wins  = 2
        Draw       = 3

    class Hangman_GameStatus(Enum):
        InProgress = 0
        PlayerWon  = 1
        PlayerLost = 2
        NoActiveGame = 0xFF

if True:  # Data classes

    @dataclass
    class HF14aCommandResult:
        # This is simply a way to return both a status code and a data buffer from the HF14a command.
        status: int
        cmd:    bytes
        data:   bytes

        @property
        def IsSuccess(self) -> bool:
            return self.status == 0x9000

    class GuessKey_Statistics:
        # Class for serializing / deserializing the GuessKey command response data.
        _FORMAT = ">HB"
        _SIZE   = struct.calcsize(_FORMAT)

        @classmethod
        def _validate_uint16(cls, value: int) -> int:
            if not isinstance(value, int):
                raise ValueError("value must be an integer.")
            if not (0 <= value <= 0xFFFF):
                raise ValueError(f"value must be in range [0x0000 .. 0xFFFF], got 0x{value:04x}.")
            return value
        @classmethod
        def _validate_bool(cls, value: bool | int) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, int) and value in (0, 1):
                return bool(value)
            raise ValueError("value must be True, False, 0, or 1.")

        def __init__(self, guess_count: int, is_solved: bool):
            self.guess_count = self._validate_uint16(guess_count)
            self.is_solved = self._validate_bool(is_solved)

        def pack(self) -> bytes:
            return struct.pack(
                self._FORMAT,
                self.guess_count,
                int(self.is_solved)
            )

        @classmethod
        def unpack(cls, data: bytes | bytearray) -> "GuessKey_Statistics":
            """Deserialize from bytes/bytearray into a Packet object."""
            try:
                if len(data) != cls._SIZE:
                    raise ValueError(f"Invalid data length: expected {cls._SIZE}, got {len(data)}")
                raw_guess_count, raw_is_solved = struct.unpack(cls._FORMAT, data)
                guess_count = cls._validate_uint16(raw_guess_count)
                is_solved   = cls._validate_bool(raw_is_solved)
                return cls(guess_count = guess_count, is_solved = is_solved)
            except struct.error as e:
                raise ValueError(f"Deserialization error: {e}")

        def __repr__(self):
            return f"{self.__class__.__name__}(guess_count={self.guess_count}, is_solved={self.is_solved})"

    class TicTacToe_BoardState:
        # Class for serializing / deserializing the GuessKey command response data.
        _FORMAT = ">9BB"
        _SIZE   = struct.calcsize(_FORMAT)

        # Bytes 0-8:  Board cells, row-major order (row0col0, row0col1, ..., row2col2)
        # Byte 9:     Game status

        @classmethod
        def _validate_cell(cls, value: int) -> TicTacToe_CellValue:
            if not isinstance(value, int):
                raise ValueError("cell value must be an integer.")
            result = TicTacToe_CellValue._value2member_map_.get(value)
            if result is None:
                raise ValueError(f"cell value must be one of {list(TicTacToe_CellValue._value2member_map_.keys())}, got 0x{value:02x}.")
            return TicTacToe_CellValue(value)

        @classmethod
        def _validate_game_status(cls, value: int) -> TicTacToe_GameStatus:
            if not isinstance(value, int):
                raise ValueError("game status must be an integer.")
            result = TicTacToe_GameStatus._value2member_map_.get(value)
            if result is None:
                raise ValueError(f"game status must be one of {list(TicTacToe_GameStatus._value2member_map_.keys())}, got 0x{value:02x}.")
            return TicTacToe_GameStatus(value)

        def __init__(self, cells : bytes | bytearray, game_status : int):
            if len(cells) != 9:
                raise ValueError(f"cells must be exactly 9 bytes, got {len(cells)}.")
            self.cells = [self._validate_cell(c) for c in cells]
            self.game_status = self._validate_game_status(game_status)

        def pack(self) -> bytes:
            return struct.pack(
                self._FORMAT,
                *(c.value for c in self.cells),
                self.game_status.value
            )

        @classmethod
        def unpack(cls, data: bytes | bytearray) -> "TicTacToe_BoardState":
            """Deserialize from bytes/bytearray into a Packet object."""
            try:
                if len(data) != cls._SIZE:
                    raise ValueError(f"Invalid data length: expected {cls._SIZE}, got {len(data)}")
                # Pack/Unpack are overkill here, since it's just a 9-element byte array and a single byte
                cells = data[:9]
                return cls(cells=cells, game_status=data[9])
            except struct.error as e:
                raise ValueError(f"Deserialization error: {e}")

        def __repr__(self):
            return f"{self.__class__.__name__}(cells={self.cells}, game_status={self.game_status})"

    class Hangman_State:
        # Class for serializing / deserializing the GuessKey command response data.

        # Bytes 0-7:   Word mask (up to 8 letters; revealed letters as ASCII, hidden as 5F ('_'), padding as 00)
        # Byte 8:      Wrong guess count (0-6)
        # Bytes 9-12:  Guessed-letter bitmask (4 bytes, 26 bits for A-Z, byte 9 bits 0-7 == A..H, byte 10 bits 0-7 == I..P, ...)
        # Byte 13:     Game status

        _FORMAT = "<8sBIB"

        _SIZE   = struct.calcsize(_FORMAT)
        _GUESSED_LETTER_MASK : int = (1 << 26) - 1 # 0x03FFFFFF
        _ALL_AVAILABLE_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

        @classmethod
        def guessed_letter_bitmask_to_remaining_letters(cls, bitmask: int) -> str:
            letters = list(cls._ALL_AVAILABLE_LETTERS)
            for i in range(26):
                if bitmask & (1 << i):
                    letters[i] = ' '
            return ''.join(letters)

        @classmethod
        def guessed_letter_bitmask_to_already_guessed_letters(cls, bitmask: int) -> str:
            letters = list(cls._ALL_AVAILABLE_LETTERS)
            for i in range(26):
                if not (bitmask & (1 << i)):
                    letters[i] = ' '
            return ''.join(letters)

        @classmethod
        def _validate_wordmask(cls, value: bytes | bytearray | str) -> str:
            if not isinstance(value, (bytes, bytearray, str)):
                raise ValueError("word mask must be bytes, bytearray, or str.")

            if isinstance(value, (bytes, bytearray)):
                if len(value) != 8:
                    raise ValueError(f"word mask must be exactly 8 bytes, got {len(value)}.")
                # Remove any trailing null bytes first....
                value = value.rstrip(b'\x00')
                # then convert to ASCII string for validation
                value = value.decode("ascii")

            # match regex r"^[A-Z_]{0,8}$" or raise exception
            if not re.fullmatch(r"^[A-Z_]{0,8}$", value):
                raise ValueError(f"word mask string must match regex r'^[A-Z_]{{0,8}}$', got '{value}'.")
            return value

        @classmethod
        def _validate_guessed_letter_bitmask(cls, value: bytes | bytearray | int) -> int:
            if not isinstance(value, (bytes, bytearray, int)):
                raise ValueError("guessed letter bitmask must be int, bytes or bytearray.")
            if isinstance(value, int):
                result = value
            else:
                if len(value) != 4:
                    raise ValueError(f"guessed letter bitmask must be an int or exactly 4 bytes, got {len(value)} bytes.")
                result = int.from_bytes(value, byteorder="little")
            if (result & cls._GUESSED_LETTER_MASK) != result:
                raise ValueError(f"guessed letter bitmask must only have bits 0-25 set, got 0x{result:08x}.")
            return result

        @classmethod
        def _validate_wrong_guess_count(cls, value: int) -> int:
            if not isinstance(value, int):
                raise ValueError("wrong guess count must be an integer.")
            if not (0 <= value <= 6):
                raise ValueError(f"wrong guess count must be in range [0..6], got {value}.")
            return value

        @classmethod
        def _validate_game_status(cls, value: int | Hangman_GameStatus) -> Hangman_GameStatus:
            if isinstance(value, Hangman_GameStatus):
                return value
            if not isinstance(value, int):
                raise ValueError("game status must be an integer or Hangman_GameStatus.")
            result = Hangman_GameStatus._value2member_map_.get(value)
            if result is None:
                raise ValueError(f"game status must be one of {list(Hangman_GameStatus._value2member_map_.keys())}, got 0x{value:02x}.")
            return Hangman_GameStatus(value)

        def __init__(self, wordmask : bytes | bytearray | str, wrong_guess_count : int, guessed_letter_bitmask : bytes | bytearray | int, game_status : int):
            self.wordmask = self._validate_wordmask(wordmask)
            self.wrong_guess_count = self._validate_wrong_guess_count(wrong_guess_count)
            self.guessed_letter_bitmask = self._validate_guessed_letter_bitmask(guessed_letter_bitmask)
            self.game_status = self._validate_game_status(game_status)

        def pack(self) -> bytes:
            return struct.pack(
                self._FORMAT,
                self.wordmask.encode("ascii"),
                self.wrong_guess_count,
                self.guessed_letter_bitmask,
                self.game_status.value
            )

        @classmethod
        def unpack(cls, data: bytes | bytearray) -> "Hangman_State":
            """Deserialize from bytes/bytearray into a Packet object."""
            try:
                if len(data) != cls._SIZE:
                    raise ValueError(f"Invalid data length: expected {cls._SIZE}, got {len(data)}")
                wordmask, wrong_guess_count, guessed_letter_bitmask, game_status = struct.unpack(cls._FORMAT, data)
                return cls(
                    wordmask=wordmask,
                    wrong_guess_count=wrong_guess_count,
                    guessed_letter_bitmask=guessed_letter_bitmask,
                    game_status=game_status
                )
            except struct.error as e:
                raise ValueError(f"Deserialization error: {e}")

        def __repr__(self):
            return f"{self.__class__.__name__}(wordmask={self.wordmask}, wrong_guess_count={self.wrong_guess_count}, guessed_letter_bitmask={self.guessed_letter_bitmask}, game_status={self.game_status})"

    class Hangman_GuessResult(Hangman_State):
        # This class is represented by a single WasGuessCorrect byte (0x00 == wrong, 0x01 == correct),
        # followed by the Hangman_State packed structure.

        _FORMAT = "<B8sBIB"
        _SIZE   = struct.calcsize(_FORMAT)

        #     B s s s s s s s s B I I I I b ____
        #      B s s s s s s s s B I I I I b____
        # <<< 005f5f5f5f5f5f00000100400000009000 == 00 40 00 00  Letters: O
        # <<< 015f5f5f5f455f00000110400000009000 == 10 40 00 00  Letters: O, E(4)

        # ABCD EFGH IJKL MNOP QRST UVWX YZ.. ....
        # 0000 0000 0000 0010 0000 0000 0000 0000 == 00 02 00 00 == WRONG
        # 0000 1000 0000 0010 0000 0000 0000 0000 == 08 02 00 00 == WRONG
        #
        # .... ..ZY XWVU TSRQ PONM LKJI HGFE DCBA
        # 0000 0000 0000 0000 0100 0000 0000 0000 == 00 00 40 00 == stored little-endian
        # 0000 0000 0000 0000 0100 0000 0001 0000 == 00 00 40 10 == stored little-endian

        @classmethod
        def _validate_was_guess_correct(cls, value: int | bool) -> bool:
            if not isinstance(value, (int, bool)):
                raise ValueError("WasGuessCorrect must be an integer or boolean.")
            if isinstance(value, bool):
                return value
            if value not in (0, 1):
                raise ValueError(f"WasGuessCorrect must be 0 or 1, got {value}.")
            return bool(value)

        def __init__(self, was_guess_correct : int | bool, wordmask : bytes | bytearray | str, wrong_guess_count : int, guessed_letter_bitmask : bytes | bytearray | int, game_status : int):
            super().__init__(wordmask=wordmask, wrong_guess_count=wrong_guess_count, guessed_letter_bitmask=guessed_letter_bitmask, game_status=game_status)
            self.was_guess_correct = self._validate_was_guess_correct(was_guess_correct)

        def pack(self) -> bytes:
            return struct.pack(
                self._FORMAT,
                self.was_guess_correct,
                self.wordmask.encode("ascii"),
                self.wrong_guess_count,
                self.guessed_letter_bitmask,
                self.game_status.value
            )

        @classmethod
        def unpack(cls, data: bytes | bytearray) -> "Hangman_GuessResult":
            """Deserialize from bytes/bytearray into a Packet object."""
            try:
                if len(data) != cls._SIZE:
                    raise ValueError(f"Invalid data length: expected {cls._SIZE}, got {len(data)}")
                was_guess_correct, wordmask, wrong_guess_count, guessed_letter_bitmask, game_status = struct.unpack(cls._FORMAT, data)
                return cls(
                    was_guess_correct=was_guess_correct,
                    wordmask=wordmask,
                    wrong_guess_count=wrong_guess_count,
                    guessed_letter_bitmask=guessed_letter_bitmask,
                    game_status=game_status
                )
            except struct.error as e:
                raise ValueError(f"Deserialization error: {e}")

        def __repr__(self):
            return f"{self.__class__.__name__}(was_guess_correct={self.was_guess_correct}, wordmask={self.wordmask}, wrong_guess_count={self.wrong_guess_count}, guessed_letter_bitmask={self.guessed_letter_bitmask}, game_status={self.game_status})"

if True:  # Commands ... HF14CommandBase and SelectApplet classes

    class Cmd_DropField:
        def __init__(self):
            pass
        def generate_proxmark_cmd_string(self) -> str:
            return "hf 14a reader --drop"

    # Define a base class for the HF 14a commands.
    # CLA, INS, P1, P2, optional length of data buffer to send (default = 0, -1 for variable), optional length of data to receive (default = 0, -1 for variable)
    class HF14aCommandBase :

        _REGEX_COMMAND = re.compile( r">>> (?P<cmd>(([A-Fa-f0-9][A-Fa-f0-9])+))" )
        _REGEX_DATA   = re.compile( r"<<< (?P<data>(([A-Fa-f0-9][A-Fa-f0-9]){2,}))")

        def __init__(self, cla: int, ins: int, p1: int = 0, p2: int = 0, send_buffer: bytes | bytearray | None = None, expect_data_length: int = 0) -> None:
            if not (0 <= cla <= 0xFF):
                raise ValueError(f"CLA must be in range [0x00 .. 0xFF], got 0x{cla:02X}.")
            if not (0 <= ins <= 0xFF):
                raise ValueError(f"INS must be in range [0x00 .. 0xFF], got 0x{ins:02X}.")
            if not (0 <= p1 <= 0xFF):
                raise ValueError(f"P1  must be in range [0x00 .. 0xFF], got 0x{p1:02X}.")
            if not (0 <= p2 <= 0xFF):
                raise ValueError(f"P2  must be in range [0x00 .. 0xFF], got 0x{p2:02X}.")
            if send_buffer is not None and len(send_buffer) > 255:
                raise ValueError(f"extended send buffer length (>0xFF) is not tested/supported, got {len(send_buffer)}.")
            if expect_data_length > 255:
                raise ValueError(f"extended expected data length (>0xFF) is not tested/supported, got {expect_data_length}.")

            self.cla: int = cla
            self.ins: int = ins
            self.p1: int = p1
            self.p2: int = p2
            self.send_buffer : bytes | bytearray | None = send_buffer
            self.expect_data_length : int = expect_data_length

        def generate_proxmark_cmd_string(self, select_card : bool = False, keep_field : bool = True) -> str:
            cmdString : str = "hf 14a apdu "
            if select_card:
                cmdString += "--select "
            if keep_field:
                cmdString += "--keep "
            cmdString += f"-m {self.cla:02X}{self.ins:02x}{self.p1:02x}{self.p2:02x} "
            if self.send_buffer is None or len(self.send_buffer) < 1:
                cmdString += "-d \"\" "
            else:
                cmdString += f"-d {self.send_buffer.hex()} "
            if self.expect_data_length > 256:
                cmdString += "--extended"
            cmdString += f"-l {self.expect_data_length:d}"
            return cmdString

        @classmethod
        def parse_proxmark_response(cls, multiline_response : Optional[Sequence[str]]) -> HF14aCommandResult:
            cmd     : bytearray = bytearray()
            data    : bytearray = bytearray()
            if multiline_response is not None and len(multiline_response) > 0:
                # First pass: append all the data
                for line in multiline_response:
                    matchC = cls._REGEX_COMMAND.search(line)
                    if matchC:
                        raw_cmd = matchC.group("cmd")
                        if raw_cmd is not None and len(raw_cmd) > 0:
                            cmd.extend(bytes.fromhex(raw_cmd))
                    matchD = cls._REGEX_DATA.search(line)
                    if matchD:
                        raw_data        = matchD.group("data")
                        if raw_data is not None and len(raw_data) > 0:
                            data.extend(bytes.fromhex(raw_data))

            if len(cmd) < 1:
                msg = "!!! Could not find any command."
                LOG_HF14.fatal(msg)
                raise RuntimeError(msg)
            if len(data) < 2:
                msg = f"!!! Could not find response to cmd {cmd.hex()}."
                LOG_HF14.fatal(msg)
                raise RuntimeError(msg)

            LOG_HF14.debug(f">>> {cmd.hex()}")
            LOG_HF14.debug(f"<<< {data.hex()}")

            # the last two bytes of data are the status code
            status = int.from_bytes(data[-2:], byteorder="big")
            data = data[:-2]
            return HF14aCommandResult(status = status, cmd = bytes(cmd), data = bytes(data))

    # Classes to select a different applet on the card.

    class Cmd_SelectApplet_Base(HF14aCommandBase):
        def __init__(self, applet_id : bytes | bytearray):
            if len(applet_id) < 5 or len(applet_id) > 16:
                raise ValueError(f"applet_id must be between 5 and 16 bytes, got {len(applet_id)}.")
            super().__init__(cla = 0x00, ins = 0xA4, p1 = 0x04, p2 = 0x00, send_buffer = applet_id, expect_data_length = 0)

    class Cmd_SelectApplet_GuessKey(Cmd_SelectApplet_Base):
        def __init__(self):
            applet_id : bytes = bytes([0xf0, 0x43, 0x42, 0x47, 0x4B, 0x01])
            super().__init__(applet_id)

    class Cmd_SelectApplet_Hangman(Cmd_SelectApplet_Base):
        def __init__(self):
            applet_id : bytes = bytes([0xf0, 0x43, 0x42, 0x48, 0x4D, 0x4E, 0x01])
            super().__init__(applet_id)

    class Cmd_SelectApplet_TicTacToe(Cmd_SelectApplet_Base):
        def __init__(self):
            applet_id : bytes = bytes([0xf0, 0x43, 0x42, 0x54, 0x54, 0x54, 0x01])
            super().__init__(applet_id)

if True:  # GuessKey applet commands

    class Cmd_GuessKey_Base(HF14aCommandBase):
        def __init__(self, ins : int, send_buffer : bytes | bytearray | None = None, expect_data_length : int = 0):
            super().__init__(cla = 0x80, ins = ins, p1 = 0x00, p2 = 0x00, send_buffer = send_buffer, expect_data_length = expect_data_length)

    class Cmd_GuessKey_Guess(Cmd_GuessKey_Base):
        def __init__(self, value : int):
            if (value < 0 or value > 0xFFFFFF):
                raise ValueError(f"Value must be between 0 and 0xFFFFFF, was {value:06x}.")
            to_send = value.to_bytes(3, 'big') # 3 bytes, big-endian
            super().__init__(ins = 0x02, send_buffer = to_send)

    class Cmd_GuessKey_GetStatistics(Cmd_GuessKey_Base):
        def __init__(self):
            super().__init__(ins = 0x04, send_buffer = None, expect_data_length = 3)

if True:  # TicTacToe applet commands

    class Cmd_TicTacToe_Base(HF14aCommandBase):
        def __init__(self, ins : int, p1 : int = 0x00, p2 : int = 0x00, expect_data_length : int = 0):
            super().__init__(cla = 0x80, ins = ins, p1 = p1, p2 = p2, send_buffer = None, expect_data_length = expect_data_length)

    class Cmd_TicTacToe_NewGame(Cmd_TicTacToe_Base):
        def __init__(self, card_moves_first : bool = False):
            p1 = 0x01 if card_moves_first else 0x00
            super().__init__(ins = 0x02, p1 = p1, p2 = 0x00, expect_data_length = 10)

    class Cmd_TicTacToe_PlayMove(Cmd_TicTacToe_Base):
        def __init__(self, row : int, col : int):
            if (row < 0 or row > 2):
                raise ValueError(f"Row must be in range [0..2], was {row:02x}.")
            if (col < 0 or col > 2):
                raise ValueError(f"Column must be in range [0..2], was {col:02x}.")
            super().__init__(ins = 0x04, p1 = row, p2 = col, expect_data_length = 10)

    class Cmd_TicTacToe_GetBoard(Cmd_TicTacToe_Base):
        def __init__(self):
            super().__init__(ins = 0x06, p1 = 0x00, p2 = 0x00, expect_data_length = 10)

    class Cmd_TicTacToe_GetGameCount(Cmd_TicTacToe_Base):
        def __init__(self):
            super().__init__(ins = 0x08, p1 = 0x00, p2 = 0x00, expect_data_length = 2)

if True:  # Hangman applet commands

    class Cmd_Hangman_Base(HF14aCommandBase):
        def __init__(self, ins : int, p1 : int = 0x00, expect_data_length : int = 0):
            super().__init__(cla = 0x80, ins = ins, p1 = p1, p2 = 0x00, send_buffer = None, expect_data_length = expect_data_length)

    class Cmd_Hangman_NewGame(Cmd_Hangman_Base):
        def __init__(self):
            super().__init__(ins = 0x02, expect_data_length = 14)

    class Cmd_Hangman_GuessLetter(Cmd_Hangman_Base):
        def __init__(self, letter : str):
            if not isinstance(letter, str):
                raise ValueError(f"Letter must be a string, got {type(letter).__name__}.")
            if len(letter) != 1:
                raise ValueError(f"Letter must be a single character, got '{letter}'.")
            # require regex match against r"^[A-Z]$" (single uppercase letter)
            if not re.match(r"^[A-Z]$", letter):
                raise ValueError(f"Letter must be a single uppercase alphabetic character [A-Z], got '{letter}'.")
            letter_byte = ord(letter)
            super().__init__(ins = 0x04, p1 = letter_byte, expect_data_length = 15)

    class Cmd_Hangman_GetState(Cmd_Hangman_Base):
        def __init__(self):
            super().__init__(ins = 0x06, expect_data_length = 14)

    class Cmd_Hangman_GetGameCount(Cmd_Hangman_Base):
        def __init__(self):
            super().__init__(ins = 0x08, expect_data_length = 2)

# Hangman string UI, index by count of incorrect guesses (0..6).
# Each string is a 6-line ASCII art representation of the hangman state,
# with the gallows and the (partially drawn) hangman figure.
hangman_character_art = (

    "  ____  \n"
    " |    | \n"
    " |      \n"
    " |      \n"
    " |      \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |      \n"
    " |      \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |    | \n"
    " |      \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |   /| \n"
    " |      \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |   /|\\\n"
    " |      \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |   /|\\\n"
    " |   /  \n"
    "_|_     \n",


    "  ____  \n"
    " |    | \n"
    " |    O \n"
    " |   /|\\\n"
    " |   / \\\n"
    "_|_     \n",
)


if True:  # Proxmark3 abstraction layer
    def detect_proxmark_device():

        # Detect the Proxmark3 connection type (USB, Bluetooth, or TCP).
        try:
            # Try running `pm3 --list` to detect available Proxmark devices
            result = subprocess.run(["pm3", "--list"], capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()

            for line in lines:
                if ":" in line:  # Expected format: "1: /dev/ttyACM0" or "1: bt:xx:xx:xx:xx:xx"
                    device = line.split(": ", 1)[1].strip()
                    LOG_PM_DEVICE.info(f"✅ Using Proxmark device: {device}")
                    return device
        except Exception:
            LOG_PM_DEVICE.info("⚠️ `pm3 --list` failed, falling back to manual detection.")

        # If `pm3 --list` doesn't work, check manually (Android or fallback mode)
        usb_devices = ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0", "/dev/ttyUSB1"]
        for dev in usb_devices:
            if os.path.exists(dev):
                LOG_PM_DEVICE.info(f"✅ Using USB device: {dev}")
                return dev

        # Default to TCP mode for Android Termux
        TCP_PORT = 4444
        LOG_PM_DEVICE.info(f"⚠️ No USB or Bluetooth device found, defaulting to TCP (localhost:{TCP_PORT})")
        return f"tcp:localhost:{TCP_PORT}"

    CACHED_PROXMARK_DEVICE : Optional[str] = None

    def send_proxmark_command(command : str) -> Sequence[str]:

        LOG_PROXMARK.info(f">>> {command}")

        if PM3_AVAILABLE:
            p.console(command)
            multiline_response = p.grabbed_output.strip()
            lines = multiline_response.splitlines()
        else:
            full_command = f"{command}\n"
            global CACHED_PROXMARK_DEVICE
            if CACHED_PROXMARK_DEVICE is None:
                CACHED_PROXMARK_DEVICE = detect_proxmark_device()
            host_device = CACHED_PROXMARK_DEVICE
            process = subprocess.Popen(
                ["./pm3", "-p", host_device],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            output, error = process.communicate(full_command)
            time.sleep(0.2)  # Small delay to let Proxmark process fully
            # Combine stdout and stderr
            response_lines = (output or "").splitlines() + (error or "").splitlines()
            # this creates a generator ... not the final sequence
            lines : List[str] = [ line.strip() for line in response_lines if "STDIN unexpected end" not in line ]

        if LOG_PROXMARK.isEnabledFor(logging.INFO):
            for line in lines:
                LOG_PROXMARK.info(f"<<< {line}")
        return lines

    def send_HF14a_command(cmd : HF14aCommandBase, select_card : bool = False, keep_field : bool = True) -> HF14aCommandResult:
        cmd_string : str = cmd.generate_proxmark_cmd_string(select_card = select_card, keep_field = keep_field)
        response_lines : Sequence[str] = send_proxmark_command(cmd_string)
        cmdResult : HF14aCommandResult = HF14aCommandBase.parse_proxmark_response(response_lines)
        return cmdResult

    def select_game(cmd : Cmd_SelectApplet_Base) -> HF14aCommandResult:
        if True: # Drop the field first, to reset the card to a known-good state
            # TODO: Selection of game: Turn off field, delay, select applet w/field kept on
            dropField : str = Cmd_DropField().generate_proxmark_cmd_string()
            send_proxmark_command(dropField)
            time.sleep(0.2)
            # NOTE: dropping the field has zero output from client
        return send_HF14a_command(cmd, select_card = True, keep_field = True)

if True:  # TicTacToe interactive UI

    def dc34_PlayTicTacToe_start_new_game(card_moves_first : bool) -> TicTacToe_BoardState:
        # Start a new TicTacToe game
        newGameCmd = Cmd_TicTacToe_NewGame(card_moves_first = card_moves_first)
        newGameResult = send_HF14a_command(newGameCmd)
        if newGameResult is None:
            msg = "Error: No HF14a response when starting new TicTacToe game."
            LOG.fatal(msg)
            raise RuntimeError(msg)
        if not newGameResult.IsSuccess:
            status = Status_TicTacToe(newGameResult.status)
            msg = f"Error: Failed to start new TicTacToe game, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        if len(newGameResult.data) == 0:
            msg = "Error: No data returned when starting new TicTacToe game."
            LOG.fatal(msg)
            raise RuntimeError(msg)
        board : TicTacToe_BoardState = TicTacToe_BoardState.unpack(newGameResult.data)
        return board

    def dc34_PlayTicTacToe_play_move(board_index : int) -> TicTacToe_BoardState:
        # Send the move to the card
        playMoveCmd = Cmd_TicTacToe_PlayMove(row=board_index // 3, col=board_index % 3)
        playMoveResult = send_HF14a_command(playMoveCmd)
        if not playMoveResult.IsSuccess:
            status = Status_TicTacToe(playMoveResult.status)
            msg = f"Error: Failed to play move, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        board = TicTacToe_BoardState.unpack(playMoveResult.data)
        return board

    def dc34_PlayTicTacToe_print_board(board : TicTacToe_BoardState):
            print(" {0} | {1} | {2}      1 | 2 | 3".format(board.cells[0], board.cells[1], board.cells[2]))
            print("---+---+---    ---+---+---")
            print(" {0} | {1} | {2}      4 | 5 | 6".format(board.cells[3], board.cells[4], board.cells[5]))
            print("---+---+---    ---+---+---")
            print(" {0} | {1} | {2}      7 | 8 | 9".format(board.cells[6], board.cells[7], board.cells[8]))

    def dc34_PlayTicTacToe():
        cmdResult = select_game(Cmd_SelectApplet_TicTacToe())
        if not cmdResult.IsSuccess:
            status = Status_HF14a(cmdResult.status)
            msg = f"Error: Failed to select TicTacToe applet, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        LOG.debug("TicTacToe applet selected successfully.")

        # Ask if the user wants to go first or let the card go first
        while True:
            first_choice = input("Do you want to go first? (Y/N): ").strip().upper()
            if first_choice in ['Y', 'N']:
                break
            print("Invalid choice. Please enter 'Y' or 'N'.")
        card_first = (first_choice == 'N')

        board = dc34_PlayTicTacToe_start_new_game(card_moves_first = card_first)
        while True:
            # Print the board to the screen
            print()
            dc34_PlayTicTacToe_print_board(board)
            print()

            # Check if game was won/lost
            if board.game_status == TicTacToe_GameStatus.User_Wins:
                print("Congratulations! You won the game!")
                return # End of game, so exit function
            if board.game_status == TicTacToe_GameStatus.Card_Wins:
                print("The card won the game. Better luck next time!")
                return # End of game, so exit function
            if board.game_status == TicTacToe_GameStatus.Draw:
                print("The game ended in a draw.")
                return # End of game, so exit function
            if board.game_status != TicTacToe_GameStatus.InProgress:
                msg = f"Error: Unknown game status {board.game_status} (0x{board.game_status.value:02X})."
                LOG.fatal(msg)
                raise RuntimeError(msg)
            # Prompt user for their move
            user_input = input("Enter your move (1-9): ").strip()
            if not user_input.isdigit():
                print("Invalid input. Please enter a number between 1 and 9.")
                continue
            if not ( 1 <= int(user_input) <= 9 ):
                print("Invalid input. Please enter a number between 1 and 9.")
                continue
            move_index = int(user_input) - 1
            if board.cells[move_index] != TicTacToe_CellValue._:
                print("Invalid move: Cell is already occupied. Please choose another cell.")
                continue
            board = dc34_PlayTicTacToe_play_move(move_index)

        # End of while loop ... don't think this should ever be reached.
        LOG.critical("Unexpectedly exiting the while loop in dc34_PlayTicTacToe().  This should never happen.")

if True:  # Hangman interactive UI

    def dc34_PlayHangman_start_new_game() -> Hangman_State:
        newGameCmd = Cmd_Hangman_NewGame()
        newGameResult = send_HF14a_command(newGameCmd)
        if not newGameResult.IsSuccess:
            status = Status_HF14a(newGameResult.status)
            msg = f"Error: Failed to start new Hangman game, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        return Hangman_State.unpack(newGameResult.data)

    def dc34_PlayHangman_guess_letter(letter : str, state : Hangman_State) -> Hangman_GuessResult:
        guessCmd = Cmd_Hangman_GuessLetter(letter)
        guessResult = send_HF14a_command(guessCmd)
        if not guessResult.IsSuccess:
            status = Status_HF14a(guessResult.status)
            msg = f"Error: Failed to guess letter '{letter}', status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        return Hangman_GuessResult.unpack(guessResult.data)

    def dc34_PlayHangman_print_state(state : Hangman_State) -> None:
        print(hangman_character_art[state.wrong_guess_count])
        print()
        print(f"Word: {state.wordmask}")
        print()
        print(f"{Hangman_State.guessed_letter_bitmask_to_remaining_letters(state.guessed_letter_bitmask)}")

    def dc34_PlayHangman_validate_user_input(user_input : str, state : Hangman_State) -> Optional[str]:
        user_input = user_input.strip().upper()
        if len(user_input) != 1:
            return None
        if not re.match(r"^[A-Z]$", user_input):
            return None
        letter_index = ord(user_input) - ord('A')
        if (state.guessed_letter_bitmask & (1 << letter_index)) != 0:
            return None
        return user_input

    def dc34_PlayHangman():
        cmdResult = select_game(Cmd_SelectApplet_Hangman())
        if not cmdResult.IsSuccess:
            status = Status_HF14a(cmdResult.status)
            msg = f"Error: Failed to select Hangman applet, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        LOG.debug("Hangman applet selected successfully.")

        state : Hangman_State | Hangman_GuessResult = dc34_PlayHangman_start_new_game()

        while True:
            print()
            dc34_PlayHangman_print_state(state)
            print()
            if state.game_status == Hangman_GameStatus.PlayerWon:
                print("Congratulations! You won the game!")
                return # End of game, so exit function
            if state.game_status == Hangman_GameStatus.PlayerLost:
                print("Sorry, word not guessed. Better luck next time!")
                return # End of game, so exit function
            if state.game_status != Hangman_GameStatus.InProgress:
                msg = f"Error: Unknown game status {state.game_status} (0x{state.game_status.value:02X})."
                LOG.fatal(msg)
                raise RuntimeError(msg)

            user_input = input("Guess Letter: ")
            user_input = dc34_PlayHangman_validate_user_input(user_input, state)
            if user_input is not None:
                state = dc34_PlayHangman_guess_letter(user_input, state)
            else:
                print("Invalid input. Please enter a single letter that you haven't guessed yet.")

        # End of while loop ... don't think this should ever be reached.
        LOG.critical("Unexpectedly exiting the while loop in dc34_PlayHangman().  This should never happen.")

if True:  # GuessKey interactive UI

    def dc34_PlayGuessKey_get_statistics() -> GuessKey_Statistics:
        statsResult = send_HF14a_command(Cmd_GuessKey_GetStatistics())
        if not statsResult.IsSuccess:
            status = Status_HF14a(statsResult.status)
            msg = f"Error: Failed to get GuessKey statistics, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        return GuessKey_Statistics.unpack(statsResult.data)

    def dc34_PlayGuessKey_guess_key(value : int) -> bool:
        guessCmd = Cmd_GuessKey_Guess(value)
        guessResult = send_HF14a_command(guessCmd)
        status = Status_GuessKey(guessResult.status)
        if status not in (Status_GuessKey.Success, Status_GuessKey.IncorrectGuess):
            msg = f"Error: Failed to send guess '{value:06X}', status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        return status == Status_GuessKey.Success

    def dc34_PlayGuessKey():
        cmdResult = select_game(Cmd_SelectApplet_GuessKey())
        if not cmdResult.IsSuccess:
            status = Status_HF14a(cmdResult.status)
            msg = f"Error: Failed to select GuessKey applet, status code: {status} (0x{status.value:04X})"
            LOG.fatal(msg)
            raise RuntimeError(msg)
        LOG.debug("GuessKey applet selected successfully.")

        while True:
            # Get state (# of guesses already attempted, if already solved, etc.)
            stats = dc34_PlayGuessKey_get_statistics()
            if stats.is_solved:
                print(f"Congratulations!  The key was guessed in {stats.guess_count} (0x{stats.guess_count:04X}) attempts.")
                return

            print(f"Current Guess Count: {stats.guess_count:5d} (0x{stats.guess_count:04X})")
            user_input = input("Enter six hex character guess (000000-FFFFFF) or 'exit' to return to main menu: ").strip()
            if user_input.lower() == 'exit':
                print("Returning to main menu.")
                return
            if not (len(user_input) == 6 and all(c in "0123456789ABCDEFabcdef" for c in user_input)):
                print("Invalid input. Please enter six hex characters (000000-FFFFFF).")
                continue
            guess_value = int(user_input, 16)

            if dc34_PlayGuessKey_guess_key(guess_value):
                print(f"Correct guess! The key was {guess_value:06X}.")
            else:
                print(f"Incorrect; Try again.")

def dc34_main_menu():
    invalid_choice_count : int = 0
    while True:
        print()
        print("DC34 Proxmark3 Game Applet Client")
        print("================================")
        print("1 / G. GuessKey")
        print("2 / T. TicTacToe")
        print("3 / H. Hangman")
        print("4 / X. Exit")
        choice = input("Select an option [1234GTHXgthx]: ")

        if choice in ['1', 'G', 'g']:
            invalid_choice_count = 0
            dc34_PlayGuessKey()
        elif choice in ['2', 'T', 't']:
            invalid_choice_count = 0
            dc34_PlayTicTacToe()
        elif choice in ['3', 'H', 'h']:
            invalid_choice_count = 0
            dc34_PlayHangman()
        elif choice in ['4', 'X', 'x']:
            LOG.info("Exiting...")
            break # out of the while loop
        elif invalid_choice_count > 3:
            # allows five times: 0,1,2,3,4
            LOG.fatal("Repeated invalid choices detected.  Exiting.")
            break # out of the while loop
        else:
            invalid_choice_count += 1
            print(f"Invalid choice ({invalid_choice_count}): {choice}")
    # End of main menu loop, aka exiting
    pass

if __name__ == '__main__':
    dc34_main_menu()
