from hashlib import sha1
from ecdsa import curves, VerifyingKey, ecdsa, ellipticcurve
from ecdsa.numbertheory import square_root_mod_prime
from ecdsa.util import string_to_number, number_to_string
from six import b

__author__ = 'Matt David'

# ecdsa to_sec / from_sec functions (to be removed when https://github.com/warner/python-ecdsa/pull/54 is finally merged into the library

def from_sec(string, curve=curves.SECP256k1, hashfunc=sha1, validate_point=True):
    """Convert a public key in SEC binary format to a verifying key."""
    # based on code from https://github.com/richardkiss/pycoin
    if string.startswith(b('\x04')):
        # uncompressed
        return VerifyingKey.from_string(string[1:], curve, hashfunc, validate_point)
    elif string.startswith(b('\x02')) or string.startswith(b('\x03')):
        # compressed
        is_even = string.startswith(b('\x02'))
        x = string_to_number(string[1:])
        order = curve.order
        p = curve.curve.p()
        alpha = (pow(x, 3, p) + (curve.curve.a() * x) + curve.curve.b()) % p
        beta = square_root_mod_prime(alpha, p)
        if is_even == bool(beta & 1):
            y = p - beta
        else:
            y = beta
        if validate_point:
            assert ecdsa.point_is_valid(curve.generator, x, y)
        point = ellipticcurve.Point(curve.curve, x, y, order)
        return VerifyingKey.from_public_point(point, curve, hashfunc)


def to_sec(vk, compressed=True):
    """Convert verifying key to the SEC binary format (as used by OpenSSL)."""
    # based on code from https://github.com/richardkiss/pycoin
    order = vk.pubkey.order
    x_str = number_to_string(vk.pubkey.point.x(), order)
    if compressed:
        if vk.pubkey.point.y() & 1:
            return b('\x03') + x_str
        else:
            return b('\x02') + x_str
    else:
        y_str = number_to_string(vk.pubkey.point.y(), order)
        return b('\x04') + x_str + y_str