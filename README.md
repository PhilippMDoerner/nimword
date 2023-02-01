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

## Structure
Every algorithm is provided in its own module.
Every module will provide a `hashEncodePassword` proc to create encoded hashes that can be stored in a database, and `isValidPassword` to validate a password against the encoded hash. "Encoded hashes" in this context mean strings containing the password-hash as well as all data required to replicate the hash operation.

In case you want to build your own validation and encoding, every module also provides a `hashPassword` proc to solely generate the hash as well as `encodeHash` to generate an encoded hash string like `hashEncodePassword` does.