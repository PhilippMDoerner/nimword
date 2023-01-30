# Nimword
#### A mini password hashing collection

<h1> NOT YET FINISHED PACKAGE </h1>

This package is a collection of functions for password hashing implemented by other packages, presented with a unified interface.
Any hashing proc will require `password`, `salt` and number of `iterations` to calculate the hash.

Further proc parameters are avilable, but use sensible default values if that's all that's needed.

Currently implemented hashing procs:
- PBKDF2 - HMAC with SHA256 using [openssl](https://nim-lang.org/docs/openssl.html)
- PBKDF2 - HMAC with SHA512 using [openssl](https://nim-lang.org/docs/openssl.html)
- Argon2 using [argon_bind](https://github.com/D-Nice/argon2_bind)