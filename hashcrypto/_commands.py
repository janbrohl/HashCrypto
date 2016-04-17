from __future__ import print_function, unicode_literals, absolute_import

import hashcrypto
import argparse
import sys
import binascii


def plain_ascii(s):
    return s.encode("ascii")

encodings_in = {"hex": binascii.a2b_hex,
                "base64": binascii.a2b_base64, "ascii": plain_ascii}

encodings_out = {"hex": binascii.b2a_hex, "base64": binascii.b2a_base64}


def add_enc_args(parser=argparse.ArgumentParser()):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=hashcrypto.MODES.keys(),
                        help="Cipher mode.")
    parser.add_argument("hash", choices=hashcrypto.fast_lookup,
                        help="Hashing algorithm.")
    parser.add_argument("key", help="Encryption/decryption key.")
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
    parser.add_argument("--encoding", "-e", choices=encodings_in, default=encodings_in["hex"],
                        help="Encoding for provided key, IV, nonce. Defaults to hex.")
    return parser


def enc(namespace, error_func, exit_func):
    ns = namespace
    e = ns.encoding
    cls = hashcrypto.MODES[ns.mode]
    key = e(ns.key)
    if hasattr(ns, "iv"):
        if issubclass(cls, hashcrypto.WithIV):
            start_iv = e(ns.iv)
            crypt = cls(key, ns.algorithm, start_iv)
        else:
            error_func(
                "Initializaion vector was provided but is not supported by cipher mode.")
            return
    elif hasattr(ns, "nonce"):
        if issubclass(cls, hashcrypto.WithNonce):
            nonce = e(ns.nonce)
            crypt = cls(key, ns.algorithm, nonce)
        else:
            error_func(
                "Nonce was provided but is not supported by cipher mode.")
            return
    else:
        crypt = cls(key, ns.algorithm)
        if ns.verbose:
            if isinstance(crypt, hashcrypto.WithIV):
                print("IV:", file=sys.stderr)
                for n, f in encodings_out.items():
                    print(n, f(crypt.start_iv), file=sys.stderr)
            elif isinstance(crypt, hashcrypto.WithNonce):
                print("Nonce:", file=sys.stderr)
                for n, f in encodings_out.items():
                    print(n, f(crypt.nonce), file=sys.stderr)
    crypt.encrypt_file(ns.infile, ns.outfile, write_header=True)
    exit_func()


def enc_main():
    parser = add_enc_args()
    enc(parser.parse_args(), parser.error, parser.exit)


def add_dec_args(parser=argparse.ArgumentParser()):
    parser.add_argument("key", help="Encryption/decryption key.")
    parser.add_argument("--infile", "-i", type=argparse.FileType("rb"),
                        default=sys.stdin, help="Input file. Defaults to stdin.")
    parser.add_argument("--outfile", "-o", type=argparse.FileType("rb"),
                        default=sys.stdout, help="Input file. Defaults to stdout.")
    parser.add_argument("--encoding", "-e", choices=encodings_in, default=encodings_in["hex"],
                        help="Encoding for provided key. Defaults to hex.")
    return parser


def dec(namespace, error_func, exit_func):
    ns = namespace
    ns = parser.parse_args()
    key = ns.encoding(ns.key)
    hashcrypto.decrypt_file(ns.infile, ns.outfile, key)
    exit_func()


def dec_main():
    parser = add_dec_args()
    dec(parser.parse_args(), parser.error, parser.exit)


def main():
    if len(sys.argv) > 1:
        ed = sys.argv.pop(1).lower()
        if ed == "enc":
            enc_main()
        elif ed == "dec":
            dec_main()
    # quite hacky
    pe = add_enc_args()
    pe.parse_args(["--help"])
    pd = add_dec_args()
    pd.parse_args(["--help"])

if __name__ == "__main__":
    main()
