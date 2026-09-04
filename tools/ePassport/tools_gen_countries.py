"""One-shot generator for ``epassport/emrtd/countries.py``.

Country *names* come from the proxmark3 client's own ISO-3166 table
(``client/src/cmdlffdxb.c``, ``fdxbCountryMapping``), which is keyed by
ISO-3166 numeric.  MRZ uses alpha-3, so the numeric -> alpha-3 bridge is
resolved here at generation time via pycountry; the emitted module is a plain
dict with no runtime dependency.

Run:  python3 tools_gen_countries.py ../../client/src/cmdlffdxb.c
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pycountry

# ICAO 9303 codes that are not ISO-3166 country codes.
ICAO_EXTRA: dict[str, str] = {
    "D": "Germany",
    "GBD": "British Overseas Territories Citizen",
    "GBN": "British National (Overseas)",
    "GBO": "British Overseas Citizen",
    "GBP": "British Protected Person",
    "GBS": "British Subject",
    "EUE": "European Union",
    "RKS": "Kosovo",
    "UNO": "United Nations Organization",
    "UNA": "United Nations Specialized Agency",
    "UNK": "Kosovo (UNMIK)",
    "XBA": "African Development Bank",
    "XIM": "African Export-Import Bank",
    "XCC": "Caribbean Community",
    "XCO": "Common Market for Eastern and Southern Africa",
    "XEC": "Economic Community of West African States",
    "XPO": "International Criminal Police Organization",
    "XOM": "Sovereign Military Order of Malta",
    "XDC": "Southern African Development Community",
    "XXA": "Stateless person",
    "XXB": "Refugee",
    "XXC": "Refugee (other)",
    "XXX": "Unspecified nationality",
    "UTO": "Utopia",
    "ZZZ": "Unknown",
}

ROW = re.compile(r"\{\s*(\d+)\s*,\s*\"([^\"]+)\"\s*\}")


def main(source: Path, out: Path) -> None:
    text = source.read_text(encoding="utf-8", errors="replace")
    start = text.index("fdxbCountryMapping[]")
    end = text.index("};", start)
    table = {int(num): name for num, name in ROW.findall(text[start:end])}

    mapping: dict[str, str] = {}
    unmatched: list[tuple[int, str]] = []
    for numeric, name in sorted(table.items()):
        try:
            entry = pycountry.countries.get(numeric=f"{numeric:03d}")
        except (KeyError, LookupError):
            entry = None
        if entry is None:
            unmatched.append((numeric, name))
            continue
        mapping[entry.alpha_3] = name

    # ICAO codes win over anything the numeric bridge produced.
    mapping.update(ICAO_EXTRA)

    lines = [
        '"""ICAO / ISO-3166 alpha-3 code -> country name.',
        "",
        "GENERATED FILE - do not edit by hand.  Regenerate with::",
        "",
        "    python3 tools_gen_countries.py <proxmark3>/client/src/cmdlffdxb.c",
        "",
        "Names are taken verbatim from the proxmark3 client's own ISO-3166 table",
        "(``fdxbCountryMapping`` in ``client/src/cmdlffdxb.c``); the numeric ->",
        "alpha-3 bridge and the ICAO-specific non-ISO codes are applied by the",
        "generator.  No runtime dependencies.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "COUNTRIES: dict[str, str] = {",
    ]
    for code in sorted(mapping):
        lines.append(f'    "{code}": "{mapping[code]}",')
    lines += [
        "}",
        "",
        "",
        "def country_name(code: str) -> str:",
        '    """Full country name for an MRZ alpha-3 code, or the code itself."""',
        "    if not code:",
        '        return ""',
        '    key = code.strip().upper().rstrip("<")',
        "    return COUNTRIES.get(key, key)",
        "",
    ]
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out} with {len(mapping)} codes")
    if unmatched:
        print(f"no alpha-3 for {len(unmatched)} numeric entries: {unmatched}")


if __name__ == "__main__":
    src = (
        Path(sys.argv[1]) if len(sys.argv) > 1 else Path("../../client/src/cmdlffdxb.c")
    )
    main(src, Path("epassport/emrtd/countries.py"))
