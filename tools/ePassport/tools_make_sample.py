"""Generate the synthetic dumps under ``samples/``.

These are entirely fabricated documents for the fictional ICAO specimen state
"Utopia".  No real personal data, no real security print, no real key material
of any consequence - the SOD signing key is generated fresh and thrown away.

Run:  python3 tools_make_sample.py
"""

from __future__ import annotations

import datetime as dt
import io
from pathlib import Path

from epassport.emrtd import mrz
from epassport.emrtd.tlv import encode

#: Default output directory when this file is run as a script.  Nothing is
#: checked in: the dumps are generated on demand, and the tests build their own
#: copy into a temporary directory.
SAMPLES = Path(__file__).parent / "samples"


def portrait_png(seed: int, width: int = 240, height: int = 320) -> bytes:
    """A flat synthetic 'photo' - deliberately not a real face."""
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (width, height), (207, 205, 198))
    d = ImageDraw.Draw(img)
    skin = (214, 178 - seed % 30, 150 - seed % 20)
    d.ellipse((width * 0.28, height * 0.14, width * 0.72, height * 0.52), fill=skin)
    d.ellipse(
        (width * 0.12, height * 0.50, width * 0.88, height * 1.10), fill=(48, 60, 92)
    )
    d.ellipse((width * 0.32, height * 0.53, width * 0.68, height * 0.78), fill=skin)
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=88)
    return out.getvalue()


def signature_png() -> bytes:
    from PIL import Image, ImageDraw

    img = Image.new("RGB", (320, 96), (255, 255, 255))
    d = ImageDraw.Draw(img)
    pts = [
        (20, 70),
        (50, 30),
        (70, 72),
        (95, 34),
        (125, 68),
        (160, 40),
        (200, 66),
        (250, 36),
        (300, 60),
    ]
    d.line(pts, fill=(20, 24, 60), width=3, joint="curve")
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=85)
    return out.getvalue()


def cbeff_wrap(image: bytes, biometric_type: int = 0x02) -> bytes:
    """Wrap an image the way DG2 does: 7F61 { 02 count, 7F60 { A1 hdr, 5F2E img } }."""
    header = (
        encode(0x81, bytes([biometric_type]))
        + encode(0x82, b"\x00")
        + encode(0x87, b"\x01\x01")
    )
    bit = encode(0xA1, header) + encode(0x5F2E, b"\x00" * 46 + image)
    return encode(0x7F61, encode(0x02, b"\x01") + encode(0x7F60, bit))


def build_dg1(line1: str, line2: str) -> bytes:
    return encode(0x61, encode(0x5F1F, (line1 + line2).encode("ascii")))


def build_com(dgs: list[int]) -> bytes:
    tag_of = {
        1: 0x61,
        2: 0x75,
        3: 0x63,
        5: 0x65,
        7: 0x67,
        11: 0x6B,
        12: 0x6C,
        14: 0x6E,
        15: 0x6F,
    }
    taglist = bytes(tag_of[n] for n in dgs if n in tag_of)
    body = encode(0x5F01, b"0107") + encode(0x5F36, b"040000") + encode(0x5C, taglist)
    return encode(0x60, body)


def build_dg11(**fields: str) -> bytes:
    tags = {
        "full_name": 0x5F0E,
        "personal_number": 0x5F10,
        "place_of_birth": 0x5F11,
        "full_date_of_birth": 0x5F2B,
        "address": 0x5F42,
        "telephone": 0x5F12,
        "profession": 0x5F13,
    }
    present = [tags[k] for k in fields if k in tags]
    body = encode(0x5C, b"".join(t.to_bytes(2, "big") for t in present))
    for key, value in fields.items():
        body += encode(tags[key], value.encode("utf-8"))
    return encode(0x6B, body)


def build_dg12(**fields: str) -> bytes:
    tags = {
        "issuing_authority": 0x5F19,
        "date_of_issue": 0x5F26,
        "endorsements": 0x5F1B,
    }
    present = [tags[k] for k in fields if k in tags]
    body = encode(0x5C, b"".join(t.to_bytes(2, "big") for t in present))
    for key, value in fields.items():
        body += encode(tags[key], value.encode("utf-8"))
    return encode(0x6C, body)


def build_dg15() -> bytes:
    """A real (throwaway) RSA public key in SubjectPublicKeyInfo form."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    spki = key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return encode(0x6F, spki)


def build_dg14() -> bytes:
    """SecurityInfos announcing Chip Authentication + Active Authentication."""
    from asn1crypto.core import ObjectIdentifier

    def secinfo(oid: str, version: int) -> bytes:
        body = ObjectIdentifier(oid).dump() + encode(0x02, bytes([version]))
        return encode(0x30, body)

    infos = secinfo("0.4.0.127.0.7.2.2.1.2", 1) + secinfo("2.23.136.1.1.5", 1)
    return encode(0x6E, encode(0x31, infos))


def build_sod(dg_hashes: dict[int, bytes], subject: str) -> bytes:
    """A genuine CMS SignedData over a real LDSSecurityObject, self-signed."""
    import hashlib

    from asn1crypto import algos, cms, core, x509 as a_x509
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    class DataGroupHash(core.Sequence):
        _fields = [
            ("dataGroupNumber", core.Integer),
            ("dataGroupHashValue", core.OctetString),
        ]

    class DataGroupHashValues(core.SequenceOf):
        # ICAO 9303 part 10: SEQUENCE OF, not SET OF.
        _child_spec = DataGroupHash

    class LDSSecurityObject(core.Sequence):
        _fields = [
            ("version", core.Integer),
            ("hashAlgorithm", algos.DigestAlgorithm),
            ("dataGroupHashValues", DataGroupHashValues),
        ]

    lds = LDSSecurityObject(
        {
            "version": 0,
            "hashAlgorithm": {"algorithm": "sha256"},
            "dataGroupHashValues": [
                {"dataGroupNumber": n, "dataGroupHashValue": h}
                for n, h in sorted(dg_hashes.items())
            ],
        }
    )
    lds_der = lds.dump()

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "UT"),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, "Utopia Ministry of the Interior"
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, subject),
        ]
    )
    now = dt.datetime(2020, 4, 1, tzinfo=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x5A17C0DE)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)

    digest = hashlib.sha256(lds_der).digest()
    signed_attrs = cms.CMSAttributes(
        [
            cms.CMSAttribute(
                {"type": "content_type", "values": ["1.2.840.10008.5.1.4.1.1.1"]}
            ),
            cms.CMSAttribute({"type": "message_digest", "values": [digest]}),
        ]
    )
    signature = key.sign(
        signed_attrs.dump(),
        __import__(
            "cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]
        ).PKCS1v15(),
        hashes.SHA256(),
    )

    signed_data = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": "sha256"}],
            "encap_content_info": {
                "content_type": "1.2.840.10008.5.1.4.1.1.1",
                "content": lds_der,
            },
            "certificates": [a_x509.Certificate.load(cert_der)],
            "signer_infos": [
                {
                    "version": "v1",
                    "sid": cms.SignerIdentifier(
                        {
                            "issuer_and_serial_number": {
                                "issuer": a_x509.Certificate.load(cert_der).issuer,
                                "serial_number": 0x5A17C0DE,
                            }
                        }
                    ),
                    "digest_algorithm": {"algorithm": "sha256"},
                    "signed_attrs": signed_attrs,
                    "signature_algorithm": {"algorithm": "rsassa_pkcs1v15"},
                    "signature": signature,
                }
            ],
        }
    )
    content = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return encode(0x77, content.dump())


def write_dump(directory: Path, files: dict[str, bytes]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (directory / f"{name}.bin").write_bytes(data)
    # pm3 also side-saves the carved portrait next to the .bin files.
    if "EF_DG2" in files:
        blob = files["EF_DG2"]
        idx = blob.find(b"\xff\xd8\xff")
        if idx >= 0:
            (directory / "EF_DG2.jpg").write_bytes(blob[idx:])
    print(f"wrote {directory} ({len(files)} files)")


def sample_td3(root: Path) -> None:
    import hashlib

    line1 = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<"
    line2 = mrz.build_td3_line2(
        "L898902C3",
        "740812",
        "120415",
        nationality="UTO",
        sex="F",
        optional="ZE184226B",
    )
    files = {
        "EF_DG1": build_dg1(line1, line2),
        "EF_DG2": encode(0x75, cbeff_wrap(portrait_png(3))),
        "EF_DG7": encode(0x67, cbeff_wrap(signature_png(), biometric_type=0x08)),
        "EF_DG11": build_dg11(
            full_name="ERIKSSON<<ANNA<MARIA",
            personal_number="19740812-1234",
            place_of_birth="STOCKHOLM<SWEDEN",
            full_date_of_birth="19740812",
            address="STORGATAN<12<<11122<STOCKHOLM",
            profession="ENGINEER",
        ),
        "EF_DG12": build_dg12(
            issuing_authority="UTOPIA PASSPORT AGENCY",
            date_of_issue="20200401",
            endorsements="NONE",
        ),
        "EF_DG14": build_dg14(),
        "EF_DG15": build_dg15(),
    }
    files["EF_COM"] = build_com([1, 2, 7, 11, 12, 14, 15])
    hashes = {
        n: hashlib.sha256(files[f"EF_DG{n}"]).digest()
        for n in (1, 2, 7, 11, 12, 14, 15)
    }
    files["EF_SOD"] = build_sod(hashes, "Utopia Document Signer 01")
    write_dump(root / "td3_utopia", files)


def sample_td3_tampered(root: Path) -> None:
    """Same document, but DG2 is altered after signing - SOD must flag it."""
    import hashlib
    import shutil

    src = root / "td3_utopia"
    dst = root / "td3_utopia_tampered"
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    swapped = encode(0x75, cbeff_wrap(portrait_png(21)))
    (dst / "EF_DG2.bin").write_bytes(swapped)
    idx = swapped.find(b"\xff\xd8\xff")
    (dst / "EF_DG2.jpg").write_bytes(swapped[idx:])
    print(f"wrote {dst} (DG2 replaced after signing)")
    del hashlib


def sample_td1(root: Path) -> None:
    """An ID card: TD1 geometry, no DG11/DG12, no SOD."""
    l1 = "I<UTOD231458907<<<<<<<<<<<<<<<"
    l2 = "7408122F1204159UTO<<<<<<<<<<<6"
    l3 = "ERIKSSON<<ANNA<MARIA<<<<<<<<<<"
    files = {
        "EF_DG1": encode(0x61, encode(0x5F1F, (l1 + l2 + l3).encode("ascii"))),
        "EF_DG2": encode(0x75, cbeff_wrap(portrait_png(11))),
    }
    files["EF_COM"] = build_com([1, 2, 3])
    write_dump(root / "td1_utopia_idcard", files)


def build_all(root: Path) -> Path:
    """Generate every sample dump under ``root``.  Returns ``root``."""
    root.mkdir(parents=True, exist_ok=True)
    sample_td3(root)
    sample_td3_tampered(root)
    sample_td1(root)
    return root


if __name__ == "__main__":
    import sys

    build_all(Path(sys.argv[1]) if len(sys.argv) > 1 else SAMPLES)
