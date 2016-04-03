from __future__ import print_function, unicode_literals

import hashlib
from os import urandom
from operator import xor
from struct import Struct
try:
    from bytesop import op_xor as b_xor
except ImportError:
    def b_xor(a, b):
        return bytes(map(xor, a, b))


Q = Struct("<Q")


def read_file(infile, block_size):
    b = infile.read(block_size)
    while b:
        yield b
        b = infile.read(block_size)


class HashCrypt(object):

    def __init__(self, key, hash_constructor=hashlib.sha512):
        self.hash = hash_constructor
        self.key = key
        self.block_size = hash_constructor().digest_size

    def block(self, iv):
        return self.hash(self.key + iv).digest()

    def encrypt_file(self, infile, outfile, *args, **kwargs):
        for block in self.encrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    def decrypt_file(self, infile, outfile, *args, **kwargs):
        for block in self.decrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    @classmethod
    def suggest_key_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size


class CTR(HashCrypt):

    def __init__(self, key, hash_constructor=hashlib.sha512, nonce=None):
        super().__init__(key, hash_constructor)
        if nonce is None:
            nonce = self.make_nonce(hash_constructor)
        self.nonce = nonce

    def keystream(self, counter_start):
        counter = counter_start
        while True:
            yield self.block(self.nonce + Q.pack(counter))
            counter += 1

    def encrypt(self, plain_blocks, counter_start=0):
        return map(b_xor, plain_blocks, self.keystream(counter_start))

    decrypt = encrypt

    def encrypt_block(self, b, counter):
        if len(b) != self.block_size:
            raise ValueError("Wrong size for input", len(b))
        d = self.self.block(self.nonce + Q.pack(counter))
        return b_xor(b, d)

    decrypt_block = encrypt_block

    @classmethod
    def suggest_nonce_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size - Q.size

    @classmethod
    def make_nonce(cls, hash_constructor=hashlib.sha512):
        return urandom(cls.suggest_nonce_size(hash_constructor))


class OFB(HashCrypt):

    def keystream(self, iv):
        while True:
            iv = self.block(iv)
            return iv

    def encrypt(self, plain_blocks, iv):
        return map(b_xor, plain_blocks, self.keystream(iv))

    decrypt = encrypt

    @classmethod
    def suggest_iv_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size

    @classmethod
    def make_iv(cls, hash_constructor=hashlib.sha512):
        return urandom(cls.suggest_iv_size(cls, hash_constructor))


class CFB(HashCrypt):

    def encrypt(self, plain_blocks, iv):
        for b in plain_blocks:
            d = self.block(iv)
            iv = b_xor(b, d)
            yield iv

    def decrypt(self, cipher_blocks, iv):
        for b in cipher_blocks:
            d = self.block(iv)
            yield b_xor(b, d)
            iv = b

    def decrypt_block(self, b, iv):
        d = self.block(iv)
        return b_xor(b, d)

    @classmethod
    def suggest_iv_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size
