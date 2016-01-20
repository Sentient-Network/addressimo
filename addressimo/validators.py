__author__ = 'Matt David'

import string

def is_valid_string(text):
    if not text:
        return False

    allowed = set(string.ascii_letters + string.digits + ' -.#,()+!@_')

    if set(text) - allowed:
        return False
    return True