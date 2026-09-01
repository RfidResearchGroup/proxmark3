"""SecurityInfos: what EF_DG14, EF_CardAccess and EF_CardSecurity advertise.

The OID arcs and the names come from the client's own tables in
``client/src/emrtd/emrtd_pace.c``, so the two agree on what a chip announces.
PACE lives under ``0.4.0.127.0.7.2.2.4``; the neighbouring arcs are the public
key, terminal authentication and chip authentication.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import tlv

_BSI = "0.4.0.127.0.7.2.2"

#: Protocol families, by OID prefix.  Used when the exact leaf is unknown.
FAMILIES: dict[str, str] = {
    f"{_BSI}.1": "Chip Authentication public key",
    f"{_BSI}.2": "Terminal Authentication",
    f"{_BSI}.3": "Chip Authentication",
    f"{_BSI}.4": "PACE",
    f"{_BSI}.5": "Restricted Identification",
}

_CIPHERS = ("3DES-CBC-CBC", "AES-CMAC-128", "AES-CMAC-192", "AES-CMAC-256")
_PACE_MAPPINGS = {
    1: "DH, Generic Mapping",
    2: "ECDH, Generic Mapping",
    3: "DH, Integrated Mapping",
    4: "ECDH, Integrated Mapping",
    6: "ECDH, CA Mapping",
}

PROTOCOLS: dict[str, str] = {
    f"{_BSI}.1.1": "Chip Authentication public key (DH)",
    f"{_BSI}.1.2": "Chip Authentication public key (ECDH)",
    **{
        f"{_BSI}.4.{mapping}.{n}": f"PACE {name}, {cipher}"
        for mapping, name in _PACE_MAPPINGS.items()
        for n, cipher in enumerate(_CIPHERS, start=1)
    },
    **{
        f"{_BSI}.3.{arc}.{n}": f"Chip Authentication {agreement}, {cipher}"
        for arc, agreement in ((1, "DH"), (2, "ECDH"))
        for n, cipher in enumerate(_CIPHERS, start=1)
    },
}

#: ICAO Doc 9303 security object OIDs, which sit outside the BSI arcs.
PROTOCOLS.update(
    {
        "2.23.136.1.1.1": "LDS Security Object",
        "2.23.136.1.1.5": "Active Authentication",
    }
)

#: Standardised domain parameters, from the client's ``pacesdp_table``.
DOMAIN_PARAMETERS: dict[int, str] = {
    0: "1024-bit MODP Group with 160-bit Prime Order Subgroup",
    1: "2048-bit MODP Group with 224-bit Prime Order Subgroup",
    2: "2048-bit MODP Group with 256-bit Prime Order Subgroup",
    8: "NIST P-192 (secp192r1)",
    9: "BrainpoolP192r1",
    10: "NIST P-224 (secp224r1)",
    11: "BrainpoolP224r1",
    12: "NIST P-256 (secp256r1)",
    13: "BrainpoolP256r1",
    14: "BrainpoolP320r1",
    15: "NIST P-384 (secp384r1)",
    16: "BrainpoolP384r1",
    17: "BrainpoolP512r1",
    18: "NIST P-521 (secp521r1)",
}

_OID_TAG = 0x06
_INTEGER_TAG = 0x02
_BIT_STRING_TAG = 0x03
_SEQUENCE_TAG = 0x30
_SET_TAG = 0x31


def describe(oid: str) -> str:
    """The friendliest name for ``oid``: exact, then family, then the OID."""
    if oid in PROTOCOLS:
        return PROTOCOLS[oid]
    for prefix in sorted(FAMILIES, key=len, reverse=True):
        if oid == prefix or oid.startswith(prefix + "."):
            return FAMILIES[prefix]
    return oid


@dataclass
class Protocol:
    """One SecurityInfo entry."""

    oid: str
    name: str
    version: int | None = None
    parameter_id: int | None = None
    curve: str = ""
    key_bits: int | None = None

    @property
    def text(self) -> str:
        """One line for the SECURITY tab."""
        parts = [self.name]
        if self.curve:
            parts.append(self.curve)
        elif self.parameter_id is not None:
            parts.append(f"domain parameter {self.parameter_id}")
        if self.key_bits:
            parts.append(f"{self.key_bits}-bit key")
        return "  ·  ".join(parts)


def parse(data: bytes) -> list[Protocol]:
    """Every SecurityInfo in ``data``, best effort - never raises."""
    out: list[Protocol] = []
    for node in _sequences(data):
        oid = next(
            (decode_oid(c.value) for c in node.children if c.tag == _OID_TAG), ""
        )
        if not oid:
            continue
        numbers = [
            int.from_bytes(c.value, "big")
            for c in node.children
            if c.tag == _INTEGER_TAG and c.value
        ]
        entry = Protocol(oid=oid, name=describe(oid))
        if numbers:
            entry.version = numbers[0]
        if len(numbers) > 1:
            entry.parameter_id = numbers[1]
            entry.curve = DOMAIN_PARAMETERS.get(entry.parameter_id, "")
        entry.key_bits = _key_bits(node)
        out.append(entry)
    return out


def _sequences(data: bytes) -> list[tlv.Tlv]:
    """The members of the SET, which is what a SecurityInfo actually is.

    Descending further would also collect the algorithm identifiers nested
    inside a public key, which are not protocols the chip supports.
    """
    if not data:
        return []
    try:
        nodes = tlv.parse(data)
    except Exception:
        return []
    # EF_CardAccess is the bare SET; DG14 wraps it in the 0x6E data-group tag.
    sets = [found for node in nodes for found in node.walk() if found.tag == _SET_TAG]
    members = sets[0].children if sets else nodes
    return [
        m
        for m in members
        if m.tag == _SEQUENCE_TAG and any(c.tag == _OID_TAG for c in m.children)
    ]


def _key_bits(node: tlv.Tlv) -> int | None:
    """Field size of an EC point carried in this entry's public key."""
    for candidate in node.walk():
        if candidate.tag != _BIT_STRING_TAG or len(candidate.value) < 4:
            continue
        point = candidate.value[1:]  # drop the unused-bits count
        if point[0] == 0x04 and len(point) % 2 == 1:
            return (len(point) - 1) // 2 * 8
    return None


def decode_oid(value: bytes) -> str:
    """Dotted form of a DER OBJECT IDENTIFIER body."""
    if not value:
        return ""
    first = value[0]
    parts = [str(first // 40), str(first % 40)]
    number = 0
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(number))
            number = 0
    return ".".join(parts)
