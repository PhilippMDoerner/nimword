import nimword/[argon2, pbkdf2_sha256, pbkdf2_sha512]
import std/[strutils]

type NimwordHashingAlgorithm* = enum
  nhaPbkdf2Sha256 = "pbkdf2_sha256"
  nhaPbkdf2Sha512 = "pbkdf2_sha512"
  nhaArgon2i = "argon2i"
  nhaArgon2id = "argon2id"
  nhaDefault

proc hashEncodePassword*(
  password: string,
  iterations: int,
  algorithm: NimwordHashingAlgorithm = nhaDefault
): string =
  ## Hashes and encodes the given password using the argon2 algorithm from libsodium.
  ## 
  ## Returns the hash as part of a larger string containing hash, iterations, algorithm, 
  ## salt and any further values used to calculate the hash. The pattern depends on the
  ## algorithm chosen.
  ## 
  ## The return value can be used with `isValidPassword<#isValidPassword>`_ .
  ## 
  ## The salt is randomly generated during the process.
  ## 
  ## For guidance on choosing values for `iterations` consult the
  ## `libsodium-documentation<https://doc.libsodium.org/password_hashing/default_phf#guidelines-for-choosing-the-parameters>`_
  result = case algorithm:
  of nhaPbkdf2Sha256:
    pbkdf2_sha256.hashEncodePassword(password, iterations)
  of nhaPbkdf2Sha512:
    pbkdf2_sha512.hashEncodePassword(password, iterations)
  of nhaArgon2i:
    argon2.hashEncodePassword(password, iterations, PasswordHashingAlgorithm.phaArgon2i13)
  of nhaArgon2id:
    argon2.hashEncodePassword(password, iterations, PasswordHashingAlgorithm.phaArgon2id13)
  of nhaDefault:
    argon2.hashEncodePassword(password, iterations, PasswordHashingAlgorithm.phaDefault)
  

proc isValidPassword*(
  password: string,
  encodedHash: string
): bool =
  let algorithmStr: string = encodedHash.split("$")[1]
  let algorithm = parseEnum[NimwordHashingAlgorithm](algorithmStr)
  case algorithm:
  of nhaPbkdf2Sha256:
    result = pbkdf2_sha256.isValidPassword(password, encodedHash)
  of nhaPbkdf2Sha512:
    result = pbkdf2_sha512.isValidPassword(password, encodedHash)
  of nhaArgon2i, nhaArgon2id, nhaDefault:
    result = argon2.isValidPassword(password, encodedHash)