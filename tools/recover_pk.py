#!/usr/bin/env python3
# MIT License
# Copyright (c) 2020 @doegox

import binascii
import sys

debug = False

#######################################################################
# Using external sslcrypto library:
# import sslcrypto
# ... sslcrypto.ecc.get_curve()
# But to get this script autonomous, i.e. for CI, we embedded the
# code snippets we needed:
#######################################################################
# code snippets from JacobianCurve:
# This code is public domain. Everyone has the right to do whatever they want with it for any purpose.
# Copyright (c) 2013 Vitalik Buterin

class JacobianCurve:
    def __init__(self, p, n, a, b, g):
        self.p = p
        self.n = n
        self.a = a
        self.b = b
        self.g = g
        self.n_length = len(bin(self.n).replace("0b", ""))


    def to_jacobian(self, p):
        return p[0], p[1], 1


    def jacobian_double(self, p):
        if not p[1]:
            return 0, 0, 0
        ysq = (p[1] ** 2) % self.p
        s = (4 * p[0] * ysq) % self.p
        m = (3 * p[0] ** 2 + self.a * p[2] ** 4) % self.p
        nx = (m ** 2 - 2 * s) % self.p
        ny = (m * (s - nx) - 8 * ysq ** 2) % self.p
        nz = (2 * p[1] * p[2]) % self.p
        return nx, ny, nz


    def jacobian_add(self, p, q):
        if not p[1]:
            return q
        if not q[1]:
            return p
        u1 = (p[0] * q[2] ** 2) % self.p
        u2 = (q[0] * p[2] ** 2) % self.p
        s1 = (p[1] * q[2] ** 3) % self.p
        s2 = (q[1] * p[2] ** 3) % self.p
        if u1 == u2:
            if s1 != s2:
                return (0, 0, 1)
            return self.jacobian_double(p)
        h = u2 - u1
        r = s2 - s1
        h2 = (h * h) % self.p
        h3 = (h * h2) % self.p
        u1h2 = (u1 * h2) % self.p
        nx = (r ** 2 - h3 - 2 * u1h2) % self.p
        ny = (r * (u1h2 - nx) - s1 * h3) % self.p
        nz = (h * p[2] * q[2]) % self.p
        return (nx, ny, nz)


    def from_jacobian(self, p):
        z = inverse(p[2], self.p)
        return (p[0] * z ** 2) % self.p, (p[1] * z ** 3) % self.p


    def jacobian_shamir(self, a, n, b, m):
        ab = self.jacobian_add(a, b)
        if n < 0 or n >= self.n:
            n %= self.n
        if m < 0 or m >= self.n:
            m %= self.n
        res = 0, 0, 1  # point on infinity
        for i in range(self.n_length - 1, -1, -1):
            res = self.jacobian_double(res)
            has_n = n & (1 << i)
            has_m = m & (1 << i)
            if has_n:
                if has_m == 0:
                    res = self.jacobian_add(res, a)
                if has_m != 0:
                    res = self.jacobian_add(res, ab)
            else:
                if has_m == 0:
                    res = self.jacobian_add(res, (0, 0, 1))  # Try not to leak
                if has_m != 0:
                    res = self.jacobian_add(res, b)
        return res

    def fast_shamir(self, a, n, b, m):
        return self.from_jacobian(self.jacobian_shamir(self.to_jacobian(a), n, self.to_jacobian(b), m))

#######################################################################
# code snippets from sslcrypto
# MIT License
# Copyright (c) 2019 Ivan Machugovskiy

import hmac
import os
import hashlib
import struct

def int_to_bytes(raw, length):
    data = []
    for _ in range(length):
        data.append(raw % 256)
        raw //= 256
    return bytes(data[::-1])


def bytes_to_int(data):
    raw = 0
    for byte in data:
        raw = raw * 256 + byte
    return raw

def legendre(a, p):
    res = pow(a, (p - 1) // 2, p)
    if res == p - 1:
        return -1
    else:
        return res

def inverse(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def square_root_mod_prime(n, p):
    if n == 0:
        return 0
    if p == 2:
        return n  # We should never get here but it might be useful
    if legendre(n, p) != 1:
        raise ValueError("No square root")
    # Optimizations
    if p % 4 == 3:
        return pow(n, (p + 1) // 4, p)
    # 1. By factoring out powers of 2, find Q and S such that p - 1 =
    # Q * 2 ** S with Q odd
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    # 2. Search for z in Z/pZ which is a quadratic non-residue
    z = 1
    while legendre(z, p) != -1:
        z += 1
    m, c, t, r = s, pow(z, q, p), pow(n, q, p), pow(n, (q + 1) // 2, p)
    while True:
        if t == 0:
            return 0
        elif t == 1:
            return r
        # Use repeated squaring to find the least i, 0 < i < M, such
        # that t ** (2 ** i) = 1
        t_sq = t
        i = 0
        for i in range(1, m):
            t_sq = t_sq * t_sq % p
            if t_sq == 1:
                break
        else:
            raise ValueError("Should never get here")
        # Let b = c ** (2 ** (m - i - 1))
        b = pow(c, 2 ** (m - i - 1), p)
        m = i
        c = b * b % p
        t = t * b * b % p
        r = r * b % p
    return r

# name: (nid, p, n, a, b, (Gx, Gy)),
CURVES = {
    "secp128r1": (
        706,
        0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFE0000000075A30D1B9038A115,
        0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC,
        0xE87579C11079F43DD824993C2CEE5ED3,
        (
            0x161FF7528B899B2D0C28607CA52C5B86,
            0xCF5AC8395BAFEB13C02DA292DDED7A83
        )
    ),
    # ! h=4, how to handle that?
    "secp128r2": (
        707,
        0xFFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF,
        0x3FFFFFFF7FFFFFFFBE0024720613B5A3,
        0xD6031998D1B3BBFEBF59CC9BBFF9AEE1,
        0x5EEEFCA380D02919DC2C6558BB6D8A5D,
        (
            0x7B6AA5D85E572983E6FB32A7CDEBC140,
            0x27B6916A894D3AEE7106FE805FC34B44
        )
    ),
    "secp192k1": (
        711,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37,
        0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D,
        0x000000000000000000000000000000000000000000000000,
        0x000000000000000000000000000000000000000000000003,
        (
            0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D,
            0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D
        )
    ),
    # p192
    "secp192r1": (
        409,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC,
        0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1,
        (
            0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
            0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
        )
    ),
    "secp224k1": (
        712,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D,
        0x10000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7,
        0x00000000000000000000000000000000000000000000000000000000,
        0x00000000000000000000000000000000000000000000000000000005,
        (
            0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C,
            0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5
        )
    ),
    # p224
    "secp224r1": (
        713,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE,
        0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4,
        (
            0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21,
            0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34
        )
    ),
    "secp256k1": (
        714,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
        0x0000000000000000000000000000000000000000000000000000000000000000,
        0x0000000000000000000000000000000000000000000000000000000000000007,
        (
            0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
            0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        )
    ),
    # p256, openssl uses the name: prime256v1.
    "secp256r1": (
        415,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
        0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        0x5AC635D8AA3A93E7B3EbBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        (
            0x6B17D1F2E12c4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
            0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
        )
    ),
    # p384
    "secp384r1": (
        715,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        (
            0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
            0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F
        )
    ),
    "secp521r1": (
        716,
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,
        0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,
        0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,
        (
            0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
            0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650
        )
    )
}

def get_curve(name):
    if name not in CURVES:
        raise ValueError("Unknown curve {}".format(name))
    nid, p, n, a, b, g = CURVES[name]
    params = {"p": p, "n": n, "a": a, "b": b, "g": g}
    return EllipticCurve(nid, p, n, a, b, g)

class EllipticCurve:
    def __init__(self, nid, p, n, a, b, g):
        self.p, self.n, self.a, self.b, self.g = p, n, a, b, g
        self.jacobian = JacobianCurve(self.p, self.n, self.a, self.b, self.g)
        self.public_key_length = (len(bin(p).replace("0b", "")) + 7) // 8
        self.order_bitlength = len(bin(n).replace("0b", ""))


    def _int_to_bytes(self, raw, len=None):
        return int_to_bytes(raw, len or self.public_key_length)


    def _subject_to_int(self, subject):
        return bytes_to_int(subject[:(self.order_bitlength + 7) // 8])


    def recover(self, signature, data, hash="sha256"):
        # Sanity check: is this signature recoverable?
        if len(signature) != 1 + 2 * self.public_key_length:
            raise ValueError("Cannot recover an unrecoverable signature")
        subject = self._digest(data, hash)
        z = self._subject_to_int(subject)

        recid = signature[0] - 27 if signature[0] < 31 else signature[0] - 31
        r = bytes_to_int(signature[1:self.public_key_length + 1])
        s = bytes_to_int(signature[self.public_key_length + 1:])

        # Verify bounds
        if not 0 <= recid < 2 * (self.p // self.n + 1):
            raise ValueError("Invalid recovery ID")
        if r >= self.n:
            raise ValueError("r is out of bounds")
        if s >= self.n:
            raise ValueError("s is out of bounds")

        rinv = inverse(r, self.n)
        u1 = (-z * rinv) % self.n
        u2 = (s * rinv) % self.n

        # Recover R
        rx = r + (recid // 2) * self.n
        if rx >= self.p:
            raise ValueError("Rx is out of bounds")

        # Almost copied from decompress_point
        ry_square = (pow(rx, 3, self.p) + self.a * rx + self.b) % self.p
        try:
            ry = square_root_mod_prime(ry_square, self.p)
        except Exception:
            raise ValueError("Invalid recovered public key") from None

        # Ensure the point is correct
        if ry % 2 != recid % 2:
            # Fix Ry sign
            ry = self.p - ry

        x, y = self.jacobian.fast_shamir(self.g, u1, (rx, ry), u2)
        x, y = self._int_to_bytes(x), self._int_to_bytes(y)

        is_compressed = signature[0] >= 31
        if is_compressed:
            return bytes([0x02 + (y[-1] % 2)]) + x
        else:
            return bytes([0x04]) + x + y

    def _digest(self, data, hash):
        if hash is None:
            return data
        elif callable(hash):
            return hash(data)
        elif hash == "md5":
            return hashlib.md5(data).digest()
        elif hash == "sha1":
            return hashlib.sha1(data).digest()
        elif hash == "sha256":
            return hashlib.sha256(data).digest()
        elif hash == "sha512":
            return hashlib.sha512(data).digest()
        else:
            raise ValueError("Unknown hash/derivation method")

#######################################################################

def guess_curvename(signature):
    l = (len(signature) // 2) & 0xfe
    if   l == 32 :
        curves = [ "secp128r1", "secp128r2" ]
    elif l == 48:
        curves = [ "secp192k1", "secp192r1" ]
    elif l == 56:
        curves = [ "secp224k1", "secp224r1" ]
    elif l == 64:
        curves = [ "secp256k1", "secp256r1" ]
    elif l == 96:
        curves = [ "secp384r1" ]
    elif l == 132:
        curves = [ "secp521r1" ]
    else:
        raise ValueError("Unsupported signature size %i" % len(signature))
    return curves

def recover(data, signature, curvename, alghash=None):
    recovered = set()
    curve = get_curve(curvename)
    recoverable = len(signature) % 1 == 1
    if (recoverable):
        try:
            pk = curve.recover(signature, data, hash=alghash)
            recovered.add(pk)
            if debug:
                print("Possible Pk:    ", binascii.hexlify(pk))
        except:
            pass
    else:
        for i in range(2):
            # Brute force RECID
            recid = bytes([27+i])
            try:
                pk = curve.recover(recid + signature, data, hash=alghash)
                recovered.add(pk)
                if debug:
                    print("Possible Pk:    ", binascii.hexlify(pk))
            except:
                pass
    return recovered

def recover_multiple(uids, sigs, curvename, alghash=None):
    recovered = set()
    assert len(uids) == len(sigs)
    for i in range(len(uids)):
        data = binascii.unhexlify(uids[i])
        if debug:
            print("UID       (%2i): " %  len(data), binascii.hexlify(data))
        signature = binascii.unhexlify(sigs[i])
        if debug:
            print("Signature (%2i): " % len(signature), binascii.hexlify(signature))
        recovered_tmp = recover(data, signature, curvename, alghash)
        if i == 0:
            if recovered_tmp == set():
                break
            else:
                recovered = recovered_tmp
        else:
            recovered &= recovered_tmp
    return recovered

def selftests():
    tests = [
        {'name': "Mifare Ultralight EV1",
         'samples': ["04C1285A373080", "CEA2EB0B3C95D0844A95B824A7553703B3702378033BF0987899DB70151A19E7",
                     "04C2285A373080", "A561506723D422D29ED9F93E60D20B9ED1E05CC1BF81DA19FE500CA0B81CC0ED"],
         'pk': "0490933BDCD6E99B4E255E3DA55389A827564E11718E017292FAF23226A96614B8" },
        {'name': "NTAG21x",
         'samples': ["04E10CDA993C80", "8B76052EE42F5567BEB53238B3E3F9950707C0DCC956B5C5EFCFDB709B2D82B3",
                     "04DB0BDA993C80", "6048EFD9417CD10F6B7F1818D471A7FE5B46868D2EABDC6307A1E0AAE139D8D0"],
         'pk': "04494E1A386D3D3CFE3DC10E5DE68A499B1C202DB5B132393E89ED19FE5BE8BC61" },
        {'name': "Mifare Classic EV1",
         'samples': ["0433619AB35780", "B9FAE369EC21C980650D87ED9AE9B1610E859131B4B8699C647548AB68D249BB",
                     "524374E2",       "F8758CE30A58553A9985C458FB9C7D340FCFB04847B928A0667939272BC58B5E",
                     "53424B8A",       "B4F533E8C06C021E242EFE8558C1672ED7022E5AE4E7AA2D46113B0AB6928AFC"],
         'pk': "044F6D3F294DEA5737F0F46FFEE88A356EED95695DD7E0C27A591E6F6F65962BAF" },
        {'name': "DESFire Light",
         'samples': ["0439556ACB6480", "D5BD0978106E1E38B513642335966AB21E9F950DCFCFAB45FF13D0DC3CA4C2AE7E0D671DF1240937D040DAC4601C5F66ED62C546EE03ED08",
                     "043B156ACB6480", "76B46932BF2FCF4931A24C755F5CB1686B914F1856177686B864BDAD58EFA6A7493E5C2232F3ADDAA434EA4647BFD1D385BDA6115E77D74C"],
         'pk': "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D" },
        {'name': "DESFire EV2",
         'samples': ["042A41CAE45380", "B2769F8DDB575AEA2A680ADCA8FFED4FAB81A1E9908E2B82FE0FABB697BBD9B23835C416970E75768F12902ACA491349E94E6589EAF4F508",
                     "045640CAE45380", "D34B53A8C2C100D700DEA1C4C0D0DE4409F3A418CD8D57C4F41F146E42AD9A55F014199ABBF5CA259C7799DB0AE20D5E77D4950AC7E95D33"],
         'pk': "04B304DC4C615F5326FE9383DDEC9AA892DF3A57FA7FFB3276192BC0EAA252ED45A865E3B093A3D0DCE5BE29E92F1392CE7DE321E3E5C52B3A" },
        {'name': "DESFire EV3",
         'samples': ["04448BD2DB6B80", "5CBB5632795C8F15263FEFB095B51C7B541AFD914A1AE44EF6FB8AF605EDF13DBFEE6C3A2DB372245E671DFE0D42CB1F0D0B8FE67A89D2F6",
                     "04445DD2DB6B80", "166BFD9F9BFAA451172566101580DF9894F582C4A4E258C15037AD2F35A475CF1D7FB817618623A6569F991931AFB2766984E21A18512A6D"],
         'pk': "041DB46C145D0A36539C6544BD6D9B0AA62FF91EC48CBC6ABAE36E0089A46F0D08C8A715EA40A63313B92E90DDC1730230E0458A33276FB743" },
# TODO one more Mifare Plus EV1...
        {'name': "Mifare Plus EV1",
         'samples': ["042A2B221C5080", "BAC40CD88E9193C58ADA5055350C4F648EB5A7AEC4FCF9BD4CDD7B1C558DE5F59C6636F26286ED48622AAA2331D4DF1CEE23B57B94BDA631"],
         'pk': "044409ADC42F91A8394066BA83D872FB1D16803734E911170412DDF8BAD1A4DADFD0416291AFE1C748253925DA39A5F39A1C557FFACD34C62E" },
        {'name': "NTAG413DNA",
         'samples': ["042468222F5C80", "B9211E320F321BD1D0E158E10FF15109B389638BAE15D9909D7725BF1250ED236D66F1AF75C94D60330E4E92535F5E6997675281A5687173",
                     "042938222F5C80", "18B642797D1FD71806146A7A6EC778D3FDD04F39C4A3B36A592BD1A114DC44E5528380FA766C0B7EA32B284AFBE84300B620369F0686D8CC"],
         'pk': "04bb5d514f7050025c7d0f397310360eec91eaf792e96fc7e0f496cb4e669d414f877b7b27901fe67c2e3b33cd39d1c797715189ac951c2add" },
        {'name': "NTAG424DNA",
         'samples': ["0463474AA26A80", "27E9A50E6CA4BA9037C02F7D20A80D0284D0C1D83C67F5A5AC1D8A4EF86C9508417E4E9C6F85AA7920F0ABDED984CAF20467D66EA54BBF08",
                     "04C46C222A6380", "344A806EBF704C05C19215D2F840529CE365AAD2D08A469A95896D75D477D9FAB02A0C827E9F215BD8EB0E56A3A9A008FB75D706AABBD4DA"],
         'pk': "048A9B380AF2EE1B98DC417FECC263F8449C7625CECE82D9B916C992DA209D68422B81EC20B65A66B5102A61596AF3379200599316A00A1410" },
        {'name': "Vivokey Spark1",
# ! tag signature bytes output by pm3 must be read right to left: echo $sig |sed 's/\(..\)/\1\n/g'|tac|tr -d '\n'  (and it uses a SHA256)
         'samples': ["E0040118009C870C", "4B4E03E1211952EF6A5F9D84AB218CD4D7549D0CDF8CA8779F9AD16C9A9CBF3B",
                     "E0040118009B4D62", "25CF13747C3389EC7889DE916E3747584978511CC78B51CFB1883B494CBED7AB"],
         'pk': "04d64bb732c0d214e7ec580736acf847284b502c25c0f7f2fa86aace1dada4387a" },
# ! tag UID is considered inversed: E0040118009B5FEE => EE5F9B00180104E0
# TODO one more ICODE-DNA...
        {'name': "ICODE DNA, ICODE SLIX2",
         'samples': ["EE5F9B00180104E0", "32D9E7579CD77E6F1FA11419231E874826984C5F189FDE1421684563A9663377"],
         'pk': "048878A2A2D3EEC336B4F261A082BD71F9BE11C4E2E896648B32EFA59CEA6E59F0" },
#  uses secp256r1?, SHA-256,
#        {'name': "Minecraft Earth",
#         'samples': ["aa", "DF0E506DFF8FCFC4B7B979D917644445F1230D2C7CDC342AFA842CA240C210BE7275F62073A9670F2DCEFC602CBEE771C2B4CD4A04F3D1EA11F49ABDF7E8B721"],
#         'pk': "" },
    ]
    succeeded = True
    for t in tests:
        print("Testing %-25s" % (t['name']+":"), end="")
        curvenames = guess_curvename(t['samples'][1])
        recovered = set()
        for c in curvenames:
            for h in [None, "md5", "sha1", "sha256", "sha512"]:
                recovered |= recover_multiple(t['samples'][::2], t['samples'][1::2], c, alghash=h)
        if (len(recovered) == 1):
            pk = recovered.pop()
            pk = binascii.hexlify(pk).decode('utf8')
            if pk.lower() == t['pk'].lower():
                print("[OK]")
            else:
                succeeded = False
                print("[FAIL], got %s" % pk.lower())
        elif len(t['samples'])//2 == 1:
            pks = [binascii.hexlify(pk).decode('utf8').lower() for pk in list(recovered)]
            if t['pk'].lower() in pks:
                print("[OK] (partial)")
            else:
                succeeded = False
                print("[FAIL], got %s" % pks)
        else:
            succeeded = False
            print("[FAIL]")
    print("Tests:                           [%s]" % ["FAIL", "OK"][succeeded])

if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] == "selftests":
        selftests()
        exit(0)
    if len(sys.argv) < 3 or len(sys.argv) % 2 == 0:
        print("Usage:   \n%s UID SIGN [UID SIGN] [...]" % sys.argv[0])
        print("Example: \n%s 04ee45daa34084 ebb6102bff74b087d18a57a54bc375159a04ea9bc61080b7f4a85afe1587d73b" % sys.argv[0])
        exit(1)
    uids, sigs = sys.argv[1:][::2], sys.argv[1:][1::2]
    curvenames = guess_curvename(sigs[0])
    for c in curvenames:
        print("\nAssuming curve=%s" % c)
        print("========================")
        for h in [None, "md5", "sha1", "sha256", "sha512"]:
            print("Assuming hash=%s" % h)
            recovered = recover_multiple(uids, sigs, c, alghash=h)
            if recovered:
                print("Possible uncompressed Pk(s):")
                for pk in list(recovered):
                    print(binascii.hexlify(pk).decode('utf8'))
