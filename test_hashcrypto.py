from __future__ import print_function, unicode_literals

import unittest
import hashcrypto
from os import urandom

def ba(*args):
    return bytes(bytearray(*args))

class TestUtilFunctions(unittest.TestCase):

    def test_b_xor(self):
        b = ba(range(32))
        self.assertEqual(ba(32), ba(hashcrypto.b_xor(b, b)))
        self.assertEqual(b, ba(hashcrypto.b_xor(b, ba(32))))

if __name__ == '__main__':
    unittest.main()
