from operator import xor
import sys

if sys.version_info >= (3, 0):
    def op_xor(a, b):
        """XOR two bytes-like objects."""
        return bytes(map(xor, a, b))
else:
    from itertools import imap

    def op_xor(a, b):
        """XOR two bytes-like objects."""
        return bytes(bytearray(imap(xor, bytearray(a), bytearray(b))))
