from setuptools import setup
import hashcrypto

setup(name="HashCrypto",
      version=hashcrypto.__version__,
      description="Encryption/decryption via hashlib hash-functions",
      author="Jan Brohl",
      author_email="janbrohl@t-online.de",
      url="https://github.com/janbrohl/HashCrypto",
      test_suite="tests",
      packages=["hashcrypto"],
      scripts=["hashenc.py", "hashdec.py"],
      classifiers=[
          "Intended Audience :: Developers",
          "License :: OSI Approved :: BSD License",
          "Operating System :: OS Independent",
          "Programming Language :: Python",
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.2",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
      ]
      )
