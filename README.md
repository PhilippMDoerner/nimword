# Nimword
#### A mini password hashing collection

<h1> NOT YET FINISHED PACKAGE </h1>

This package is a collection of functions for password hashing implemented by other packages, presented with a unified interface.

The algorithms can either be used directly, or through a central location

Further proc parameters are avilable, but use sensible default values if that's all that's needed.

Currently available hashing algorithms:
- PBKDF2 - HMAC with SHA256 using [openssl](https://nim-lang.org/docs/openssl.html)
- PBKDF2 - HMAC with SHA512 using [openssl](https://nim-lang.org/docs/openssl.html)
- Argon2 using [libsodium](https://github.com/FedericoCeratto/nim-libsodium)


## Structure
Every algorithm is provided in its own module.
Every module will provide 4 procs:
- hashEncodePassword:
  Turns a password together with a salt (will be generated if not provided) and a number of iterations into a hash in an encoded string. Extra options for customization may be available depending on the algorithm, but will have sensible default values.
  The encoded string will contain the base64 encoded hash itself, as well as the salt, iterations and extra options used.
  It can be used to validate plain text passwords with `verifyPassword`.
- verifyPassword:
  Validates a password against a hash in an encoded string as provided by `hashEncodePassword` or `encodeHash`.
  It extracts the values required from that encoded string, hashes the given plain-text password and compares the hashes
- encodeHash:
  Encodes a hash and the values used to generate it into a string that can be used with `verifyPassword`.
  This proc is mostly intended for users that need to build a custom solution for their authentication.
- hashPassword:
  Turns a password together with a salt (will be generated if not provided) and a number of iterations into a hash.
  It will not encode the string as `hashEncodePassword` does.
  This proc is mostly intended for users that need to build a custom solution for their authentication.

