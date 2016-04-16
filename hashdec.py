#! python
from __future__ import print_function, unicode_literals

import hashcrypto
import argparse
import sys
import binascii


def plain_ascii(s):
    return s.encode("ascii")

encodings = {"hex": binascii.a2b_hex,
             "base64": binascii.a2b_base64, "ascii": plain_ascii}

parser = argparse.ArgumentParser()
parser.add_argument(
    "key", help="Hex-encoded encryption/decryption key.", type=binascii.a2b_hex)
parser.add_argument("--infile", "-i", type=argparse.FileType("rb"),
                    default=sys.stdin, help="Input file. Defaults to stdin.")
parser.add_argument("--outfile", "-o", type=argparse.FileType("rb"),
                    default=sys.stdout, help="Input file. Defaults to stdout.")
parser.add_argument("--encoding", "-e", choice=encodings, default=plain_ascii,
                    help="Encoding for provided key. Defaults to ascii.")


ns = parser.parse_args()
hashcrypto.decrypt_file(ns.infile, ns.outfile, ns.encoding(ns.key))
parser.exit()
