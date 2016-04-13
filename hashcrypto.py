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

try:
    unicode()
except NameError:
    unicode=str


__version__="0.1"


Q = Struct("<Q")
B = Struct("<B")

def pack_pascal(b):
    if isinstance(b,unicode):
        b=b.encode("ascii")
    return B.pack(len(b))+b

def unpack_pascal(b):
    size=B.unpack(b[0])[0]
    return b[1:size+1]

def read_pascal(f):
    size=B.unpack(f.read(1))[0]
    return f.read(size)

class IVError(ValueError):
    pass


    
    
    

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

    def encrypt_file(self, infile, outfile, write_header=False, *args, **kwargs ):
        outfile.write(self.header())
        for block in self.encrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    def decrypt_file(self, infile, outfile, *args, **kwargs):
        for block in self.decrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    def header(self):
        return b"HASHCRYPT"+(b"".join(map(pack_pascal,(__version__,self.__class__.__name__,self.hash_name))))
    
    def hash_name(self):
        return self.hash().name
    
    @classmethod
    def suggest_key_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size


class WithIV(HashCrypt):
    def __init__(self, key, hash_constructor=hashlib.sha512, start_iv=None):
        super().__init__(key, hash_constructor)
        self.start_iv=start_iv
    def header(self):
        return super().header()+pack_pascal(self.start_iv)

    @classmethod
    def suggest_iv_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size

    @classmethod
    def make_iv(cls, hash_constructor=hashlib.sha512):
        return urandom(cls.suggest_iv_size(cls, hash_constructor))
    

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

    def header(self):
        return super().header()+pack_pascal(self.nonce)

    @classmethod
    def suggest_nonce_size(cls, hash_constructor=hashlib.sha512):
        return hash_constructor().block_size - Q.size

    @classmethod
    def make_nonce(cls, hash_constructor=hashlib.sha512):
        return urandom(cls.suggest_nonce_size(hash_constructor))



class OFB(WithIV):

    def keystream(self, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        while True:
            iv = self.block(iv)
            return iv

    def encrypt(self, plain_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        return map(b_xor, plain_blocks, self.keystream(iv))

    decrypt = encrypt




class CFB(WithIV):

    def encrypt(self, plain_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        for b in plain_blocks:
            d = self.block(iv)
            iv = b_xor(b, d)
            yield iv

    def decrypt(self, cipher_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        for b in cipher_blocks:
            d = self.block(iv)
            yield b_xor(b, d)
            iv = b

    def decrypt_block(self, b, iv):
        d = self.block(iv)
        return b_xor(b, d)

MODES={"CTR":CTR,"OFB":OFB,"CFB":CFB}
 

def decrypt_file(infile,outfile,key):
    if infile.read(9)!=b"HASHCRYPT":
        raise ValueError("Bad Header")
    ver=read_pascal(infile).decode("ascii")
    mode=read_pascal(infile).decode("ascii")
    h=read_pascal(infile).decode("ascii")
    iv_nonce=read_pascal(infile)
    obj=MODES[mode](key,hashlib.new(h).copy,iv_nonce)
    obj.decrypt_file(infile,outfile)
    
