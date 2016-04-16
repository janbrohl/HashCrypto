#! python
from __future__ import print_function, unicode_literals, absolute_import

import hashcrypto
import argparse
import sys
import binascii


def plain_ascii(s):
    return s.encode("ascii")

encodings = {"hex": binascii.a2b_hex,
             "base64": binascii.a2b_base64, "ascii": plain_ascii}

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=hashcrypto.MODES.keys(),
                    help="Cipher mode.")
parser.add_argument("hash", choices=hashcrypto.fast_lookup,
                    help="Hashing algorithm.")
parser.add_argument(
    "key", help="Hex-encoded encryption/decryption key.", type=binascii.a2b_hex)
group3 = parser.add_mutually_exclusive_group()
group3.add_argument(
    "--iv", help="Initialization vector. Defaults to random bytes.")
group3.add_argument("--nonce", help="Nonce. Defaults to random bytes.")
parser.add_argument("--infile", "-i", type=argparse.FileType("rb"),
                    default=sys.stdin, help="Input file. Defaults to stdin.")
parser.add_argument("--outfile", "-o", type=argparse.FileType("rb"),
                    default=sys.stdout, help="Input file. Defaults to stdout.")
parser.add_argument("--verbose", "-v", action='store_true',
                    default=False, help="Verbose mode. Print more stuff to stderr.")
parser.add_argument("--encoding", "-e", choice=encodings, default=plain_ascii,
                    help="Encoding for provided key, IV, nonce. Defaults to none.")


def main():
    ns = parser.parse_args()
    e = ns.encoding
    cls = hashcrypto.MODES[ns.mode]
    if hasattr(ns, "iv"):
        if issubclass(cls, hashcrypto.WithIV):
            crypt = cls(e(ns.key), ns.algorithm, e(ns.iv))
        else:
            parser.error(
                "Initializaion vector was provided but is not supported by cipher mode.")
    elif hasattr(ns, "nonce"):
        if issubclass(cls, hashcrypto.WithNonce):
            crypt = cls(e(ns.key), ns.algorithm, e(ns.nonce))
        else:
            parser.error(
                "Nonce was provided but is not supported by cipher mode.")
    else:
        crypt = cls(e(ns.key), ns.algorithm)
        if ns.verbose:
            if isinstance(crypt, hashcrypto.WithIV):
                print("IV:", binascii.b2a_hex(crypt.start_iv), file=sys.stderr)
            elif isinstance(crypt, hashcrypto.WithNonce):
                print("Nonce:", binascii.b2a_hex(crypt.nonce), file=sys.stderr)
    crypt.encrypt_file(ns.infile, ns.outfile, write_header=True)
    parser.exit()

if __name__ == "__main__":
    main()
