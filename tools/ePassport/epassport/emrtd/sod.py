"""EF_SOD inspection: signer summary plus the data-group hash table.

Entirely optional.  When ``asn1crypto`` is not installed the module returns a
:class:`SodInfo` that tells the user what to install, rather than nothing.
"""

from __future__ import annotations

import hashlib
import logging

from . import tlv
from .model import SodHash, SodInfo

log = logging.getLogger(__name__)

#: OID -> hashlib name, for the digest algorithm named inside the LDS object.
_HASH_OIDS = {
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
}

_DG_FILE = {n: f"EF_DG{n}" for n in range(1, 17)}


def parse_sod(data: bytes, raw_files: dict[str, bytes] | None = None) -> SodInfo:
    """Decode EF_SOD and cross-check the DG hashes against the dumped files."""
    if not data:
        return SodInfo(available=False, message="EF_SOD was not dumped.")

    try:
        from asn1crypto import cms
    except ImportError:
        return SodInfo(
            available=False,
            message="Install 'asn1crypto' (and 'cryptography') to inspect EF_SOD.",
        )

    # EF_SOD wraps the CMS ContentInfo in an application tag 0x77.
    nodes = tlv.parse(data)
    payload = nodes[0].value if nodes and nodes[0].tag == 0x77 else data

    try:
        content = cms.ContentInfo.load(payload)
        signed: "cms.SignedData" = content["content"]
    except Exception as exc:
        return SodInfo(
            available=False, message=f"EF_SOD is not decodable CMS SignedData: {exc}"
        )

    info = SodInfo(available=True)
    try:
        _fill_signer(signed, info)
    except Exception as exc:  # never let a weird cert kill the whole tab
        log.info("could not summarise SOD signer: %s", exc)
        info.message = f"signer details unavailable ({exc.__class__.__name__})"

    try:
        _fill_hashes(signed, info, raw_files or {})
    except Exception as exc:
        log.info("could not read the SOD hash table: %s", exc)
        info.message = (
            info.message + "; " if info.message else ""
        ) + "DG hash table unreadable"

    return info


def _fill_signer(signed, info: SodInfo) -> None:
    algos = signed["digest_algorithms"]
    if len(algos):
        info.hash_algorithm = _algo_name(algos[0]["algorithm"].dotted)

    signers = signed["signer_infos"]
    if len(signers):
        signer = signers[0]
        info.signature_algorithm = signer["signature_algorithm"]["algorithm"].native

    certs = signed["certificates"]
    if certs is None or not len(certs):
        info.signer_subject = "(no document signer certificate in EF_SOD)"
        return
    cert = certs[0].chosen
    info.signer_subject = cert.subject.human_friendly
    info.signer_issuer = cert.issuer.human_friendly
    info.signer_serial = format(cert.serial_number, "X")
    validity = cert["tbs_certificate"]["validity"]
    info.valid_from = str(validity["not_before"].native)
    info.valid_to = str(validity["not_after"].native)


def _fill_hashes(signed, info: SodInfo, raw_files: dict[str, bytes]) -> None:
    from asn1crypto.core import (
        Any,
        Integer,
        ObjectIdentifier,
        OctetString,
        PrintableString,
        Sequence,
        SequenceOf,
    )

    encap = signed["encap_content_info"]
    lds_der = encap["content"].native
    if not lds_der:
        return

    class DataGroupHash(Sequence):
        _fields = [("dataGroupNumber", Integer), ("dataGroupHashValue", OctetString)]

    class DataGroupHashValues(SequenceOf):
        # ICAO 9303 part 10 defines this as a SEQUENCE OF, not a SET OF.  Get
        # that wrong and every real EF_SOD fails with "tag should have been
        # 17, but 16 was found".
        _child_spec = DataGroupHash

    class AlgorithmIdentifier(Sequence):
        _fields = [
            ("algorithm", ObjectIdentifier),
            ("parameters", Any, {"optional": True}),
        ]

    class LDSVersionInfo(Sequence):
        _fields = [
            ("ldsVersion", PrintableString),
            ("unicodeVersion", PrintableString),
        ]

    class LDSSecurityObject(Sequence):
        _fields = [
            ("version", Integer),
            ("hashAlgorithm", AlgorithmIdentifier),
            ("dataGroupHashValues", DataGroupHashValues),
            # Present when version is v1; absent from v0 documents.
            ("ldsVersionInfo", LDSVersionInfo, {"optional": True}),
        ]

    lds = LDSSecurityObject.load(lds_der)
    info.ldsversion = str(lds["version"].native)
    oid = lds["hashAlgorithm"]["algorithm"].dotted
    info.hash_algorithm = _algo_name(oid)
    hashlib_name = _HASH_OIDS.get(oid, "")

    rows: list[SodHash] = []
    for entry in lds["dataGroupHashValues"]:
        number = int(entry["dataGroupNumber"].native)
        expected = bytes(entry["dataGroupHashValue"].native)
        row = SodHash(dg=number, expected=expected.hex().upper())
        blob = raw_files.get(_DG_FILE.get(number, ""), b"")
        if blob and hashlib_name:
            actual = hashlib.new(hashlib_name, blob).digest()
            row.actual = actual.hex().upper()
            row.status = "match" if actual == expected else "MISMATCH"
        elif not blob:
            row.status = "not checked"
        else:
            row.status = "not checked"
        rows.append(row)
    info.hashes = sorted(rows, key=lambda r: r.dg)


def _algo_name(oid: str) -> str:
    return {
        "1.3.14.3.2.26": "SHA-1",
        "2.16.840.1.101.3.4.2.1": "SHA-256",
        "2.16.840.1.101.3.4.2.2": "SHA-384",
        "2.16.840.1.101.3.4.2.3": "SHA-512",
        "2.16.840.1.101.3.4.2.4": "SHA-224",
    }.get(oid, oid)
