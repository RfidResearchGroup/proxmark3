"""The five non-passport tabs: PERSONAL, ISSUER, SECURITY, FILES and LOG."""

from __future__ import annotations

import shutil
from pathlib import Path

from kivy.clock import Clock
from kivy.properties import (
    ListProperty,
    NumericProperty,
    ObjectProperty,
    StringProperty,
)
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label

from ...emrtd.model import FileState, PassportRecord
from .. import theme
from .tabs import TabPage


class KeyValueRow(BoxLayout):
    """One ``label: value`` line in a detail tab."""

    key = StringProperty("")
    value = StringProperty("")
    palette = ObjectProperty(theme.LIGHT)


class DetailPage(TabPage):
    """A scrolling list of key/value rows."""

    rows = ListProperty([])
    empty_text = StringProperty("Nothing to show.")

    def set_rows(self, pairs: list[tuple[str, str]]) -> None:
        self.rows = [(k, v) for k, v in pairs if v]

    def on_rows(self, *_args) -> None:
        Clock.schedule_once(self._rebuild, 0)

    def _rebuild(self, *_args) -> None:
        box = self.ids.get("rows_box")
        if box is None:
            return
        box.clear_widgets()
        for key, value in self.rows:
            box.add_widget(KeyValueRow(key=key, value=value, palette=self.palette))


def _personal_number_label(record) -> str:
    """Name the source when it is not DG11, so the row is not misread.

    Without the "from" it fits the caption column: dp(190) holds 167px of
    "Personal number (DG13)" but not the 203px the longer wording needs, and
    a caption that wraps drops the source onto a line of its own.
    """
    source = record.personal_number_source
    if source in ("MRZ", "DG13"):
        return f"Personal number ({source})"
    return "Personal number"


class PersonalPage(DetailPage):
    """EF_DG11 - additional personal details."""

    def refresh(self) -> None:
        record: PassportRecord | None = self.record
        if record is None:
            self.set_rows([])
            return
        p = record.personal
        self.set_rows(
            [
                ("Full name", p.full_name),
                ("Other names", ", ".join(p.other_names)),
                (
                    _personal_number_label(record),
                    # The rest of this tab drops absent fields rather than
                    # labelling them, and the placeholder would stand out.
                    (
                        ""
                        if record.is_missing(record.personal_number)
                        else record.personal_number
                    ),
                ),
                (
                    "Full date of birth",
                    record.full_date_of_birth if p.full_date_of_birth else "",
                ),
                ("Place of birth", p.place_of_birth),
                ("Address", p.address),
                ("Telephone", p.telephone),
                ("Profession", p.profession),
                ("Title", p.title),
                ("Personal summary", p.personal_summary),
                ("Custody information", p.custody_information),
            ]
        )
        self.empty_text = (
            "EF_DG11 is not present on this document."
            if not record.has_dg(11)
            else "EF_DG11 is present but held no readable fields."
        )


class IssuerPage(DetailPage):
    """EF_DG12 - additional document details."""

    def refresh(self) -> None:
        record: PassportRecord | None = self.record
        if record is None:
            self.set_rows([])
            return
        d = record.document
        self.set_rows(
            [
                ("Issuing authority", d.issuing_authority),
                ("Date of issue", record.date_of_issue),
                ("Endorsements / observations", d.endorsements),
                ("Tax / exit requirements", d.tax_exit_requirements),
                ("Other persons", ", ".join(d.other_persons)),
                ("Personalization time", d.personalization_time),
                ("Personalization device", d.personalization_device),
                ("LDS version", record.com.lds_version),
                ("Unicode version", record.com.unicode_version),
                (
                    "Data groups announced",
                    ", ".join(f"DG{n}" for n in record.com.present_dgs),
                ),
            ]
        )
        self.empty_text = (
            "EF_DG12 is not present on this document."
            if not record.has_dg(12)
            else "EF_DG12 is present but held no readable fields."
        )


class HashRow(BoxLayout):
    """One row of the EF_SOD data-group hash table."""

    dg = StringProperty("")
    status = StringProperty("")
    digest = StringProperty("")
    palette = ObjectProperty(theme.LIGHT)

    @property
    def status_color(self):
        return {
            "match": theme.OK,
            "MISMATCH": theme.BAD,
        }.get(self.status, theme.WARN)


class SecurityPage(TabPage):
    """EF_SOD signer summary, the DG hash table and DG14/DG15."""

    rows = ListProperty([])
    hashes = ListProperty([])
    headline = StringProperty("")
    headline_color = ObjectProperty(theme.WARN)

    def on_rows(self, *_args) -> None:
        Clock.schedule_once(self._rebuild, 0)

    def on_hashes(self, *_args) -> None:
        Clock.schedule_once(self._rebuild, 0)

    def _rebuild(self, *_args) -> None:
        box = self.ids.get("rows_box")
        if box is None:
            return
        box.clear_widgets()
        if self.hashes:
            box.add_widget(
                KeyValueRow(key="Data group hashes", value="", palette=self.palette)
            )
            for dg, status, digest in self.hashes:
                box.add_widget(
                    HashRow(dg=dg, status=status, digest=digest, palette=self.palette)
                )
            box.add_widget(KeyValueRow(key="", value="", palette=self.palette))
        for key, value in self.rows:
            box.add_widget(KeyValueRow(key=key, value=value, palette=self.palette))

    def refresh(self) -> None:
        record: PassportRecord | None = self.record
        if record is None:
            self.rows, self.hashes = [], []
            self.headline = "No document loaded."
            return
        sod = record.sod
        if not sod.available:
            self.headline = sod.message or "EF_SOD could not be inspected."
            self.headline_color = theme.WARN
            self.hashes = []
        else:
            mismatches = sod.mismatches
            unchecked = [h for h in sod.hashes if h.status == "not checked"]
            if mismatches:
                self.headline = f"{len(mismatches)} data group hash MISMATCH - contents do not match the signature"
                self.headline_color = theme.BAD
            elif not sod.hashes:
                self.headline = "EF_SOD carries no data-group hash table."
                self.headline_color = theme.WARN
            elif unchecked:
                self.headline = f"{len(sod.hashes) - len(unchecked)} of {len(sod.hashes)} data groups hash-matched"
                self.headline_color = theme.WARN
            else:
                self.headline = f"All {len(sod.hashes)} data groups hash-matched"
                self.headline_color = theme.OK
            self.hashes = [(f"DG{h.dg}", h.status, h.expected) for h in sod.hashes]

        sec = record.security
        self.rows = [
            (k, v)
            for k, v in (
                ("Hash algorithm", sod.hash_algorithm),
                ("Signature algorithm", sod.signature_algorithm),
                ("LDS security object version", sod.ldsversion),
                ("Signer subject", sod.signer_subject),
                ("Signer issuer", sod.signer_issuer),
                ("Signer serial", sod.signer_serial),
                ("Certificate valid from", sod.valid_from),
                ("Certificate valid to", sod.valid_to),
                ("PACE  ·  EF_CardAccess", "\n".join(sec.pace)),
                ("DG14 protocols", "\n".join(sec.protocols)),
                ("DG15 AA public key", f"{sec.aa_algorithm} {sec.aa_key_size}".strip()),
            )
            if v
        ]
        if not record.has_dg(14) and not record.has_dg(15):
            self.rows.append(("DG14 / DG15", "not present on this document"))
        # A note about the signature itself: we verify hashes, not the chain.
        if sod.available:
            self.rows.append(
                (
                    "Note",
                    "Hashes are checked against the dumped files. The signer certificate "
                    "chain is NOT validated - that needs the issuing country's CSCA.",
                )
            )


class FileRow(ButtonBehavior, BoxLayout):
    """One row of the FILES table."""

    name = StringProperty("")
    size_text = StringProperty("")
    state = StringProperty("")
    selected = ObjectProperty(False)
    palette = ObjectProperty(theme.LIGHT)

    @property
    def state_color(self):
        return {
            FileState.PRESENT: theme.OK,
            FileState.PROTECTED: theme.WARN,
            FileState.UNREADABLE: theme.BAD,
        }.get(self.state, theme.LIGHT["text_dim"])


class FilesPage(TabPage):
    """Every dumped file, with a hex viewer and an Export button."""

    files = ListProperty([])
    selected_name = StringProperty("")
    selected_data = ObjectProperty(b"")
    selected_image = ObjectProperty(b"")
    status = StringProperty("")
    dump_dir = StringProperty("")

    def refresh(self) -> None:
        record: PassportRecord | None = self.record
        if record is None:
            self.files = []
            self.selected_data = b""
            self.selected_image = b""
            return
        self.dump_dir = str(record.source_dir or "")
        self.files = [
            (f.name, _size_text(f), f.state, f.note)
            for f in record.files
            if f.state != FileState.ABSENT or f.size
        ]
        present = [f for f in record.files if f.state == FileState.PRESENT]
        if present:
            Clock.schedule_once(lambda *_: self.select(present[0].name), 0)
        else:
            self.selected_name = ""
            self.selected_data = b""
            self.selected_image = b""

    def on_files(self, *_args) -> None:
        Clock.schedule_once(self._rebuild, 0)

    def _rebuild(self, *_args) -> None:
        box = self.ids.get("files_box")
        if box is None:
            return
        box.clear_widgets()
        for name, size_text, state, note in self.files:
            row = FileRow(
                name=name,
                size_text=size_text,
                state=state,
                palette=self.palette,
                selected=name == self.selected_name,
            )
            row.bind(on_release=lambda widget: self.select(widget.name))
            box.add_widget(row)

    def on_selected_name(self, *_args) -> None:
        for row in (
            self.ids.get("files_box").children if self.ids.get("files_box") else []
        ):
            row.selected = row.name == self.selected_name

    def select(self, name: str) -> None:
        record: PassportRecord | None = self.record
        if record is None:
            return
        entry = record.file(name)
        self.selected_name = name
        self.selected_data = entry.data if entry else b""
        self.selected_image = record.image_for(name)

    def export_selected(self, destination: str) -> str:
        """Copy the selected file elsewhere.  Returns a status message."""
        record: PassportRecord | None = self.record
        if record is None or not self.selected_name:
            return "Nothing selected."
        entry = record.file(self.selected_name)
        if entry is None or entry.path is None:
            return f"{self.selected_name} has no file on disk."
        target = Path(destination).expanduser() / entry.path.name
        try:
            shutil.copy2(entry.path, target)
        except OSError as exc:
            return f"Export failed: {exc}"
        return f"Exported to {target}"


def _size_text(entry) -> str:
    if entry.state == FileState.PRESENT:
        return f"{entry.size:,} B"
    return "-"


class LogPage(TabPage):
    """The live pm3 output.  Owns no state; the app pushes lines into it."""

    line_count = NumericProperty(0)


class LabelValue(Label):
    """Selectable-looking value label used across the detail tabs."""
