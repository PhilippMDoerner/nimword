# Nimword
#### A mini password hashing collection

[![Run Tests](https://github.com/PhilippMDoerner/nimword/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/PhilippMDoerner/nimword/actions/workflows/tests.yml)

[![github pages](https://github.com/PhilippMDoerner/nimword/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/PhilippMDoerner/nimword/actions/workflows/docs.yml)

- [API index](https://philippmdoerner.github.io/nimword/nimword.html)

This package is a collection of functions for password hashing implemented by other packages, presented with a unified interface.
It is currently only tested for Linux, but *should* work for Windows as well assuming the same libraries are installed.

Currently available hashing algorithms:
- PBKDF2 - HMAC with SHA256 from [openssl](https://nim-lang.org/docs/openssl.html)
- PBKDF2 - HMAC with SHA512 from [openssl](https://nim-lang.org/docs/openssl.html)
- Argon2 from [libsodium](https://github.com/FedericoCeratto/nim-libsodium)

## Installation
Install Nimword with [Nimble](https://github.com/nim-lang/nimble):

    $ nimble install -y nimword

Add Nimword to your .nimble file:

    requires "nimword"


If you want to use argon2, ensure you have [libsodium](https://doc.libsodium.org/installation) installed. 

If you want to use pbkdf2, ensure you have OpenSSL version 1 or 3 installed

## Basic usage
The following will work for every module:
```nim
let password: string = "my-super-secret-password"
let iterations: int = 3 # For Argon2 this is sensible, for pbkdf2 consider a number above 100.000
let encodedHash: string = hashEncodePassword(password, iterations)

assert password.isValidPassword(encodedHash) == true
```

## Core-API
The core module of nimword provides the simple api of `hashEncodePassword` and `isValidPassword`:
- `hashEncodePassword`:
  Proc to create base64 encoded hashes and further encodes them in a specific format that can be stored in e.g. a database and used with `isValidPassword`.
  Always takes the plain-text password, the algorithm to use for hashing and a number of iterations for the algorithm. Any further values needed by the algorithm will use sensible defaults. The salts for hashing will be generated and returned as part of the encoded string.
- `isValidPassword`:
  Proc to validate if a given password is identical to the one that was used to create an encoded hash. 

These core procs are also available in the individual modules for each algorithm, there `hashEncodePassword` may expose further options depending on the algorithm.

The individual algorithm-modules further provide 2 procs in case some customization is needed:
- `hashPassword`:
  Proc to create unencoded raw hashes like `hashEncodePassword`, but returns the hash-bytes directly from there without turning it into a specific format like `hashEncodePassword` does.
- `encodeHash`:
  Proc to generate strings of the format that `hashEncodePassword` outputs, but without doing any of the hashing itself. The output can be used with `isValidPassword`.

## Running tests
You can run the tests either locally or in a container:
- `nimble test`
- `nimble containerTest` - This assumes you have docker and docker-compose installed