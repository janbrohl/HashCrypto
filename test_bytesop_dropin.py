import unittest
import bytesop_dropin

def ba(*args):
    return bytes(bytearray(*args))

class TestUtilFunctions(unittest.TestCase):

    def test_b_xor(self):
        b = ba(range(32))
        self.assertEqual(ba(32), ba(bytesop_dropin.op_xor(b, b)))
        self.assertEqual(b, ba(bytesop_dropin.op_xor(b, ba(32))))

if __name__ == '__main__':
    unittest.main()
