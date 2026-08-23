"""Manual BAC entry: the three fields, or a full MRZ line 2 that wins."""

from __future__ import annotations

import re
from dataclasses import dataclass

from kivy.properties import BooleanProperty, ObjectProperty, StringProperty
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.screenmanager import Screen

from ..emrtd import mrz as mrzlib
from ..pm3.client import AUTH_AUTO, AUTH_BAC, AUTH_PACE, BacInput, ValidationError
from . import theme

_DIGITS = re.compile(r"[^0-9]")
_MRZ_CHARS = re.compile(r"[^0-9A-Z<]")


def sanitize_docnum(text: str) -> str:
    return _MRZ_CHARS.sub("", text.upper())[:9]


def sanitize_date(text: str) -> str:
    return _DIGITS.sub("", text)[:6]


def sanitize_line2(text: str) -> str:
    return _MRZ_CHARS.sub("", text.upper())[:44]


def sanitize_can(text: str) -> str:
    return _DIGITS.sub("", text)[:14]


#: Labels for the authentication picker, in the order they are offered.
AUTH_LABELS: dict[str, str] = {
    AUTH_AUTO: "Automatic (PACE, then BAC)",
    AUTH_PACE: "PACE only",
    AUTH_BAC: "BAC only",
}
AUTH_BY_LABEL: dict[str, str] = {label: mode for mode, label in AUTH_LABELS.items()}


def date_problem(text: str) -> str:
    """Live validation message for a YYMMDD field, or "" when it is fine."""
    if len(text) < 6:
        return "YYMMDD"
    month, day = int(text[2:4]), int(text[4:6])
    if not 1 <= month <= 12:
        return "month must be 01-12"
    days = (31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    if not 1 <= day <= days:
        return f"day must be 01-{days:02d}"
    return ""


@dataclass
class FormState:
    """The outcome of validating the entry form.

    Kept free of Kivy so it can be tested directly - the version of this logic
    that lived only inside the widget shipped a bug where entering a CAN left
    the MRZ field markers set, which kept the Read button disabled on a form
    that was perfectly valid.
    """

    docnum_error: str = ""
    dob_error: str = ""
    expiry_error: str = ""
    line2_error: str = ""
    can_error: str = ""
    note: str = ""
    valid: bool = False

    @property
    def fields_ok(self) -> bool:
        return not (
            self.docnum_error
            or self.dob_error
            or self.expiry_error
            or self.line2_error
            or self.can_error
        )


def auth_hint(mode: str, can: str) -> str:
    """One line describing what pressing Read will actually attempt."""
    if can and len(can) != 6:
        return (
            f"A CAN is usually 6 digits; yours is {len(can)}. It will still be tried."
        )
    if can:
        return "PACE with the Card Access Number printed on the data page."
    if mode == AUTH_BAC:
        return "Forcing BAC - PACE will not be attempted."
    if mode == AUTH_PACE:
        return "Forcing PACE with the MRZ - no BAC fallback if it fails."
    return "PACE is tried first, then BAC."


def validate_form(
    *,
    document_number: str = "",
    date_of_birth: str = "",
    date_of_expiry: str = "",
    mrz_line2: str = "",
    can: str = "",
    mode: str = AUTH_AUTO,
) -> FormState:
    """Validate the entry form.

    A CAN alone is enough, and it *replaces* the MRZ - so entering one must
    clear the MRZ field markers rather than leaving "required" behind.
    """
    state = FormState()
    using_can = bool(can)
    # A complete line 2 already carries the document number and both dates,
    # so it stands on its own - the three boxes are then just a convenience.
    line2_complete = bool(mrz_line2) and len(mrz_line2) in (36, 44)

    if using_can:
        if not 1 <= len(can) <= 14:
            state.can_error = "1-14 digits"
        elif document_number or date_of_birth or date_of_expiry or mrz_line2:
            state.can_error = "clear the MRZ fields - the CAN replaces them"
    elif line2_complete:
        pass  # nothing else is required
    else:
        state.docnum_error = "" if document_number else "required"
        state.dob_error = date_problem(date_of_birth)
        state.expiry_error = date_problem(date_of_expiry)
        if mrz_line2:
            state.line2_error = f"{len(mrz_line2)}/44 characters"

    untouched = not (
        using_can or document_number or date_of_birth or date_of_expiry or mrz_line2
    )
    try:
        build_input(
            document_number=document_number,
            date_of_birth=date_of_birth,
            date_of_expiry=date_of_expiry,
            mrz_line2=mrz_line2,
            can=can,
            mode=mode,
        ).validated()
    except ValidationError as exc:
        # An untouched form is not an error; the field markers already say
        # what is still needed.
        state.note = "" if untouched else str(exc)
        state.valid = False
        return state

    # A field-level problem is the reason Read is disabled, so say that rather
    # than describing an attempt that is not going to happen.
    state.note = state.can_error if state.can_error else auth_hint(mode, can)
    state.valid = state.fields_ok
    return state


def build_input(
    *,
    document_number: str = "",
    date_of_birth: str = "",
    date_of_expiry: str = "",
    mrz_line2: str = "",
    can: str = "",
    mode: str = AUTH_AUTO,
) -> BacInput:
    """Assemble the key material, preferring the least error-prone form."""
    if can:
        return BacInput(can=can, mode=mode)
    if mrz_line2 and len(mrz_line2) in (36, 44):
        # A whole line 2 avoids field-splitting mistakes entirely.
        return BacInput(mrz_line2=mrz_line2, mode=mode)
    return BacInput(
        document_number=document_number,
        date_of_birth=date_of_birth,
        date_of_expiry=date_of_expiry,
        mode=mode,
    )


class EntryScreen(Screen):
    """The manual-entry form.  ``Read`` stays disabled until inputs validate."""

    document_number = StringProperty("")
    date_of_birth = StringProperty("")
    date_of_expiry = StringProperty("")
    mrz_line2 = StringProperty("")
    can = StringProperty("")
    auth_label = StringProperty(AUTH_LABELS[AUTH_AUTO])
    remember = BooleanProperty(False)

    docnum_error = StringProperty("")
    dob_error = StringProperty("")
    expiry_error = StringProperty("")
    line2_error = StringProperty("")
    can_error = StringProperty("")
    valid = BooleanProperty(False)
    derived_note = StringProperty("")
    auth_note = StringProperty("")

    palette = ObjectProperty(theme.LIGHT)

    # -- live validation ---------------------------------------------------
    def on_document_number(self, *_args) -> None:
        self._validate()

    def on_date_of_birth(self, *_args) -> None:
        self._validate()

    def on_date_of_expiry(self, *_args) -> None:
        self._validate()

    def on_mrz_line2(self, *_args) -> None:
        self._autofill_from_line2()
        self._validate()

    def on_can(self, *_args) -> None:
        self._validate()

    def on_auth_label(self, *_args) -> None:
        self._validate()

    @property
    def auth_mode(self) -> str:
        return AUTH_BY_LABEL.get(self.auth_label, AUTH_AUTO)

    def _autofill_from_line2(self) -> None:
        """A clean line 2 populates the three boxes and takes precedence."""
        line = self.mrz_line2
        self.derived_note = ""
        if len(line) not in (36, 44):
            return
        head = "P<UTO" + "<" * (39 if len(line) == 44 else 31)
        try:
            parsed = mrzlib.parse([head, line])
        except mrzlib.MrzError:
            return
        self.set_field("docnum", parsed.bac_document_number)
        self.set_field("dob", parsed.date_of_birth.value)
        self.set_field("expiry", parsed.date_of_expiry.value)
        bad = parsed.failed_checks()
        if bad:
            self.derived_note = (
                "Filled from MRZ line 2 - check digits failed: " + ", ".join(bad)
            )
            return
        blind = mrzlib.ambiguous_positions(parsed.document_number.value)
        if blind:
            self.derived_note = (
                "Filled from MRZ line 2 - check digits valid. Still worth a glance: the "
                "7-3-1 checksum cannot distinguish L/1, S/8, G/6 or Z/5 in the document number."
            )
        else:
            self.derived_note = "Filled from MRZ line 2 - check digits valid."

    def revalidate(self, *_args) -> None:
        """Validate once the widget tree exists and its bindings have settled,
        so the guidance line is never blank on first show."""
        from kivy.clock import Clock

        Clock.schedule_once(lambda *_: self._validate(), 0)

    def _validate(self) -> None:
        state = validate_form(
            document_number=self.document_number,
            date_of_birth=self.date_of_birth,
            date_of_expiry=self.date_of_expiry,
            mrz_line2=self.mrz_line2,
            can=self.can,
            mode=self.auth_mode,
        )
        self.docnum_error = state.docnum_error
        self.dob_error = state.dob_error
        self.expiry_error = state.expiry_error
        self.line2_error = state.line2_error
        self.can_error = state.can_error
        self.auth_note = state.note
        self.valid = state.valid

    # -- what the app asks for --------------------------------------------
    def bac_input(self) -> BacInput:
        return build_input(
            document_number=self.document_number,
            date_of_birth=self.date_of_birth,
            date_of_expiry=self.date_of_expiry,
            mrz_line2=self.mrz_line2,
            can=self.can,
            mode=self.auth_mode,
        )

    def validated_input(self) -> tuple[BacInput | None, str]:
        try:
            return self.bac_input().validated(), ""
        except ValidationError as exc:
            return None, str(exc)

    def set_field(self, field_id: str, text: str) -> None:
        """Write into a text box.  Values flow box -> field -> screen, so this
        is the only correct way to fill the form programmatically."""
        field = self.ids.get(field_id)
        if field is not None and "box" in field.ids:
            field.ids.box.text = text

    def fill(self, document_number: str, dob: str, expiry: str) -> None:
        self.set_field("docnum", sanitize_docnum(document_number))
        self.set_field("dob", sanitize_date(dob))
        self.set_field("expiry", sanitize_date(expiry))

    def set_line2(self, text: str) -> None:
        self.set_field("line2", sanitize_line2(text))


class ErrorPanel(BoxLayout):
    """The BAC-failed / no-card / no-device panel: title, cause, remedy."""

    title = StringProperty("")
    detail = StringProperty("")
    remedy = StringProperty("")
    visible = BooleanProperty(False)
    palette = ObjectProperty(theme.LIGHT)
