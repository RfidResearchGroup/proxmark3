"""Parse a dump directory and print the resulting PassportRecord.

    python3 -m epassport.emrtd samples/td3_utopia

This is the headless half of the app: no Kivy, no hardware.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .dg import load_dump
from .model import PassportRecord


def render(record: PassportRecord) -> str:
    out: list[str] = []
    add = out.append
    add(f"source        : {record.source_dir}")
    m = record.mrz
    if m:
        add(f"MRZ kind      : {m.kind}")
        add(f"document type : {m.document_type} ({m.document_code})")
        add(f"issuing state : {m.issuing_state} - {m.issuing_state_name}")
        add(f"surname       : {m.surname}")
        add(f"given names   : {m.given_names}")
        add(f"doc number    : {m.document_number.value} [{m.document_number.badge}]")
        add(f"nationality   : {m.nationality} - {m.nationality_name}")
        add(f"date of birth : {m.dob_text} [{m.date_of_birth.badge}]")
        add(f"sex           : {m.sex_label}")
        add(f"date of expiry: {m.expiry_text} [{m.date_of_expiry.badge}]")
        add(f"composite     : [{m.composite.badge}]")
        add(
            f"check digits  : {'all valid' if m.all_checks_ok else 'FAILED: ' + ', '.join(m.failed_checks())}"
        )
        for line in m.lines:
            add(f"    {line}")
    else:
        add("MRZ           : (none)")

    add("")
    add(
        f"EF_COM        : LDS {record.com.lds_version}  Unicode {record.com.unicode_version}"
    )
    add(f"  announced DG: {record.com.present_dgs}")

    p = record.personal
    if not p.is_empty():
        add("")
        add("DG11 personal :")
        for key, value in vars(p).items():
            if value:
                add(f"  {key:<20}: {value}")

    d = record.document
    if not d.is_empty():
        add("")
        add("DG12 document :")
        for key, value in vars(d).items():
            if value and not key.startswith("image_"):
                add(f"  {key:<20}: {value}")

    s = record.security
    if s.pace:
        add("")
        add("EF_CardAccess :")
        for proto in s.pace:
            add(f"  protocol            : {proto}")
    if s.protocols or s.aa_algorithm:
        add("")
        add("DG14/15       :")
        for proto in s.protocols:
            add(f"  protocol            : {proto}")
        if s.aa_algorithm:
            add(f"  AA public key       : {s.aa_algorithm} {s.aa_key_size}")

    add("")
    add("EF_SOD        :")
    if not record.sod.available:
        add(f"  {record.sod.message}")
    else:
        add(f"  hash algorithm      : {record.sod.hash_algorithm}")
        add(f"  signature algorithm : {record.sod.signature_algorithm}")
        add(f"  signer subject      : {record.sod.signer_subject}")
        add(f"  signer issuer       : {record.sod.signer_issuer}")
        add(f"  valid               : {record.sod.valid_from} .. {record.sod.valid_to}")
        for row in record.sod.hashes:
            add(f"  DG{row.dg:<2} {row.status:<12} {row.expected[:32]}...")

    add("")
    add("images        :")
    add(f"  DG2 portrait        : {len(record.portrait_png)} bytes PNG")
    add(f"  DG5 portrait        : {len(record.displayed_portrait_png)} bytes PNG")
    add(f"  DG7 signature       : {len(record.signature_png)} bytes PNG")

    add("")
    add("files         :")
    for f in record.files:
        if f.state == "absent" and not f.size:
            continue
        add(f"  {f.name:<16} {f.size:>7}  {f.state_label}")

    if record.warnings:
        add("")
        add("warnings      :")
        for w in record.warnings:
            add(f"  - {w}")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    directory = Path(argv[1])
    if not directory.is_dir():
        print(f"not a directory: {directory}", file=sys.stderr)
        return 1
    print(render(load_dump(directory)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
