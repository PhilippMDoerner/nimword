# Nimword
#### A mini password hashing collection

<h1> NOT YET FINISHED PACKAGE </h1>

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
Every algorithm is provided in its own module.
Every module will provide `hashEncodePassword` and `isValidPassword`:
- `hashEncodePassword`:
  Proc to create base64 encoded hashes and further encodes them in a specific format that can be stored in e.g. a database.
  Always takes the plain-text password and a number of iterations for the algorithm. May take additional parameter depending on the algorithm, though those will have sensible default values. The salts for hashing will be generated.
- `isValidPassword`:
  Proc to validate if a given password is identical to the one that was used to create an encoded hash. 

In case something custom must be built, all modules further provide:
- `hashPassword`:
  Proc to create base 64 encoded hashes like `hashEncodePassword`, but returns the hash directly from there without turning it into a specific format like `hashEncodePassword` does.
- `encodeHash`:
  Proc to generate strings of the format that `hashEncodePassword` outputs, but without doing any of the hashing itself.
