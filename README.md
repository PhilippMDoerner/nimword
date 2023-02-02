# Nimword
#### A mini password hashing collection

[![Run Tests](https://github.com/PhilippMDoerner/nimword/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/PhilippMDoerner/nimword/actions/workflows/tests.yml)

[![github pages](https://github.com/PhilippMDoerner/nimword/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/PhilippMDoerner/nimword/actions/workflows/docs.yml)

<h1> NOT YET FINISHED PACKAGE </h1>

- [API index](https://philippmdoerner.github.io/nimword/)

This package is a collection of functions for password hashing implemented by other packages, presented with a unified interface.

Currently available hashing algorithms:
- PBKDF2 - HMAC with SHA256 using [openssl](https://nim-lang.org/docs/openssl.html)
- PBKDF2 - HMAC with SHA512 using [openssl](https://nim-lang.org/docs/openssl.html)
- Argon2 using [libsodium](https://github.com/FedericoCeratto/nim-libsodium)

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
  Proc to create base 64 encoded hashes like `hashEncodePassword`, but returns the hash directly from there without turning it into a specific format like `hashEncodePassword` does.
- `encodeHash`:
  Proc to generate strings of the format that `hashEncodePassword` outputs, but without doing any of the hashing itself. The output can be used with `isValidPassword`.

## Running tests
You can run the tests either locally or in a container:
- `nimble test`
- `nimble containerTest` - This assumes you have docker and docker-compose installed