from __future__ import print_function, unicode_literals

import unittest
import hashcrypto
from os import urandom


class TestUtilFunctions(unittest.TestCase):

    def test_b_xor(self):
        b = bytes(range(32))
        unittest.assertEqual(bytes(32), hashcrypto.b_xor(b, b))
        unittest.assertEqual(b, hashcrypto.b_xor(b, bytes(32)))
