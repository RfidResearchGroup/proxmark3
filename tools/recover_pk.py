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
        elif hash == "sha1":
            return hashlib.sha1(data).digest()
        elif hash == "sha256":
            return hashlib.sha256(data).digest()
        elif hash == "sha512":
            return hashlib.sha512(data).digest()
        else:
            raise ValueError("Unknown hash/derivation method")

#######################################################################

def recover(data, signature, alghash=None):
    recovered = set()
    if len(signature) == 32:
        curve = get_curve("secp128r1")
        recoverable = False
    elif len(signature) == 33:
        curve = get_curve("secp128r1")
        recoverable = True
    elif len(signature) == 56:
        curve = get_curve("secp224r1")
        recoverable = False
    elif len(signature) == 57:
        curve = get_curve("secp224r1")
        recoverable = True
    else:
        print("Unsupported signature size %i" % len(signature))
        exit(1)

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

def recover_multiple(uids, sigs, alghash=None):
    recovered = set()
    assert len(uids) == len(sigs)
    for i in range(len(uids)):
        data = binascii.unhexlify(uids[i])
        if debug:
            print("UID       (%2i): " %  len(data), binascii.hexlify(data))
        signature = binascii.unhexlify(sigs[i])
        if debug:
            print("Signature (%2i): " % len(signature), binascii.hexlify(signature))
        recovered_tmp = recover(data, signature, alghash)
        if i == 0:
            if recovered_tmp == set():
                break
            else:
                recovered = recovered_tmp
        else:
            recovered &= recovered_tmp
    return recovered

if len(sys.argv) < 3 or len(sys.argv) % 2 == 0:
    print("Usage:   \n%s UID SIGN [UID SIGN] [...]" % sys.argv[0])
    print("Example: \n%s 04ee45daa34084 ebb6102bff74b087d18a57a54bc375159a04ea9bc61080b7f4a85afe1587d73b" % sys.argv[0])
    exit(1)

print("Assuming no hash was used in the signature generation:")
recovered = recover_multiple(sys.argv[1:][::2], sys.argv[1:][1::2])
print("Possible uncompressed Pk(s):")
for pk in list(recovered):
    print(binascii.hexlify(pk).decode('utf8'))
print("Assuming SHA-256 was used in the signature generation:")
recovered = recover_multiple(sys.argv[1:][::2], sys.argv[1:][1::2], alghash="sha256")
print("Possible uncompressed Pk(s):")
for pk in list(recovered):
    print(binascii.hexlify(pk).decode('utf8'))
