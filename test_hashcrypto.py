from __future__ import print_function, unicode_literals

import unittest
import hashcrypto
import io

def notrandom(n,start=0):
    return bytearray(0xff&i for i in range(start,start+n))

class TestCipherModes(unittest.TestCase):
    def setUp(self):
        self.inbytes=notrandom(1000)
        self.key=notrandom(20)

    def roundtrip_stream(self,cls):
        infile=io.BytesIO(self.inbytes)
        cryptfile=io.BytesIO()
        outfile=io.BytesIO()
        crypt=cls(self.key)
        crypt.encrypt_stream(infile,cryptfile)
        cryptfile.seek(0)
        crypt.decrypt_stream(cryptfile,outfile)
        self.assertEqual(infile.getvalue(),outfile.getvalue())

    def roundtrip_file(self,cls):
        infile=io.BytesIO(self.inbytes)
        cryptfile=io.BytesIO()
        outfile=io.BytesIO()
        crypt=cls(self.key)
        crypt.encrypt_file(infile,cryptfile)
        cryptfile.seek(0)
        hashcrypto.decrypt_file(cryptfile,outfile,self.key)
        self.assertEqual(infile.getvalue(),outfile.getvalue())
        
    def test_CTR_roundtrip_stream(self):
        self.roundtrip_stream(hashcrypto.CTR)
        
    def test_CFB_roundtrip_stream(self):
        self.roundtrip_stream(hashcrypto.CFB)

    def test_OFB_roundtrip_stream(self):
        self.roundtrip_stream(hashcrypto.OFB)

    def test_CTR_roundtrip_file(self):
        self.roundtrip_file(hashcrypto.CTR)
        
    def test_CFB_roundtrip_file(self):
        self.roundtrip_file(hashcrypto.CFB)

    def test_OFB_roundtrip_file(self):
        self.roundtrip_file(hashcrypto.OFB)


if __name__ == '__main__':
    unittest.main()
