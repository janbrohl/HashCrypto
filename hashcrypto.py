from __future__ import print_function, unicode_literals

import hashlib
from os import urandom
import sys
from struct import Struct

if sys.version_info>=(3,0):
    unicode=str
    short_map=map
else:
    from itertools import imap as short_map

try:
    from bytesop import op_xor
except ImportError:
    from bytesop_dropin import op_xor


    



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

fast_lookup={"md5":hashlib.md5, "sha1":hashlib.sha1, "sha224":hashlib.sha224, "sha256":hashlib.sha256, "sha384":hashlib.sha384, "sha512":hashlib.sha512}  
    
    

def read_file(infile, block_size):
    b = infile.read(block_size)
    while b:
        yield b
        b = infile.read(block_size)


class HashCrypt(object):

    def __init__(self, key, hash_constructor=hashlib.sha512):
        if isinstance(hash_constructor,(unicode,bytes)):
            h=hash_constructor
            n=hashlib.new
            hash_constructor=fast_lookup.get(h,(lambda b:n(h,b)))
        self.hash = hash_constructor
        self.key = key
        self.block_size = hash_constructor().digest_size

    def block(self, b):
        return self.hash(self.key + b).digest()

    def encrypt_file(self, infile, outfile, *args, **kwargs):
        outfile.write(self.header())
        self.encrypt_stream(infile, outfile, *args, **kwargs)


    def encrypt_stream(self, infile, outfile, *args, **kwargs):        
        for block in self.encrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    def decrypt_stream(self, infile, outfile, *args, **kwargs):
        for block in self.decrypt(read_file(infile, self.block_size), *args, **kwargs):
            outfile.write(block)

    def header(self):
        return b"HASHCRYPT"+(b"".join(short_map(pack_pascal,(__version__,self.__class__.__name__,self.hash_name()))))
    
    def hash_name(self):
        return self.hash().name
    
    @classmethod
    def suggest_key_size(cls, hash_constructor):
        return max(hash_constructor().block_size,32)


class WithIV(HashCrypt):
    def __init__(self, key, hash_constructor=hashlib.sha512, start_iv=None):
        super(WithIV,self).__init__(key, hash_constructor)
        if start_iv is None:
            start_iv = self.make_iv(hash_constructor)
        self.start_iv=start_iv

    def header(self):
        return super(WithIV,self).header()+pack_pascal(self.start_iv)

    @classmethod
    def suggest_iv_size(cls, hash_constructor):
        return max(hash_constructor().block_size,32)

    @classmethod
    def make_iv(cls, hash_constructor):
        return urandom(cls.suggest_iv_size( hash_constructor))
    
class WithNonce(HashCrypt):
    def __init__(self, key, hash_constructor=hashlib.sha512, nonce=None):
        super(WithNonce,self).__init__(key, hash_constructor)
        if nonce is None:
            nonce = self.make_nonce(hash_constructor)
        self.nonce = nonce

    def header(self):
        return super(WithNonce,self).header()+pack_pascal(self.nonce)
    
    @classmethod
    def make_nonce(cls, hash_constructor=hashlib.sha512):
        return urandom(cls.suggest_nonce_size(hash_constructor))

class CTR(WithNonce):   

    def keystream(self, counter_start):
        counter = counter_start
        while True:
            yield self.block(self.nonce + Q.pack(counter))
            counter += 1

    def encrypt(self, plain_blocks, counter_start=0):
        return short_map(op_xor, plain_blocks, self.keystream(counter_start))

    decrypt = encrypt

    def encrypt_block(self, b, counter):
        if len(b) != self.block_size:
            raise ValueError("Wrong size for input", len(b))
        d = self.block(self.nonce + Q.pack(counter))
        return op_xor(b, d)

    decrypt_block = encrypt_block   

    @classmethod
    def suggest_nonce_size(cls, hash_constructor):
        return max(hash_constructor().block_size - Q.size,32)

    



class OFB(WithIV):

    def keystream(self, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        while True:
            iv = self.block(iv)
            yield iv

    def encrypt(self, plain_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        return short_map(op_xor, plain_blocks, self.keystream(iv))

    decrypt = encrypt




class CFB(WithIV):

    def encrypt(self, plain_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        for b in plain_blocks:
            d = self.block(iv)
            iv = op_xor(b, d)
            yield iv

    def decrypt(self, cipher_blocks, iv=None):
        if iv is None:
            iv=self.start_iv
        if iv is None:
            raise IVError("If iv is omitted or None, self.start_iv must be set.")
        
        for b in cipher_blocks:
            d = self.block(iv)
            yield op_xor(b, d)
            iv = b

    def decrypt_block(self, b, iv):
        d = self.block(iv)
        return op_xor(b, d)

MODES={"CTR":CTR,"OFB":OFB,"CFB":CFB}
 

def decrypt_file(infile,outfile,key):
    if infile.read(9)!=b"HASHCRYPT":
        raise ValueError("Bad Header")
    ver=read_pascal(infile).decode("ascii")
    mode=read_pascal(infile).decode("ascii")
    h=read_pascal(infile).decode("ascii")
    iv_nonce=read_pascal(infile)
    obj=MODES[mode](key,h,iv_nonce)
    obj.decrypt_stream(infile,outfile)
    

