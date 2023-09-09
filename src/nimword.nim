import nimword/[argon2, pbkdf2_sha256, pbkdf2_sha512]
import std/[strutils, strformat]

export argon2.SodiumError
export pbkdf2_sha256.Pbkdf2Error
export Password
export toPassword
export Hash

type NimwordHashingAlgorithm* = enum
  ## The number of different hashing algorithms nimword supports
  nhaPbkdf2Sha256 = "pbkdf2_sha256"
  nhaPbkdf2Sha512 = "pbkdf2_sha512"
  nhaArgon2i = "argon2i"
  nhaArgon2id = "argon2id"
  nhaDefault

type UnknownAlgorithmError = object of ValueError

proc hashEncodePassword*(
  password: Password,
  iterations: int,
  algorithm: NimwordHashingAlgorithm = nhaDefault
): string =
  ## Hashes and encodes the given password using the argon2 algorithm from libsodium.
  ## 
  ## Returns the hash as part of a larger string containing hash, iterations, algorithm, 
  ## salt and any further values used to calculate the hash. The pattern depends on the
  ## algorithm chosen.
  ## 
  ## The return value can be used with `isValidPassword<#isValidPassword%2Cstring%2Cstring>`_ .
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
  password: Password,
  encodedHash: string
): bool {.raises: {UnknownAlgorithmError, ValueError, Pbkdf2Error, SodiumError, Exception}.} =
  ## Verifies that a given plain-text password can be used to generate
  ## the hash contained in `encodedHash` with the parameters provided in `encodedHash`.
  ## 
  ## `encodedHash` must be a string with the kind of pattern that `encodeHash` procs or
  ## and `hashEncodePassword<#hashEncodePassword%2Cstring%2Cint>`_ generate. 
  ## 
  ## Raises UnknownAlgorithmError if the encoded hash string is for an algorithm not 
  ## supported by nimword.
  var algorithm: NimwordHashingAlgorithm
  let algorithmStr: string = encodedHash.split("$")[1]
  try:
    algorithm = parseEnum[NimwordHashingAlgorithm](algorithmStr)
  except ValueError as e:
    raise newException(UnknownAlgorithmError, fmt"'{algorithmStr}' is not an algorithm supported by nimword. Consult the NimwordHashingAlgorithm to see which algorithm options are supported.")
  
  case algorithm:
  of nhaPbkdf2Sha256:
    result = pbkdf2_sha256.isValidPassword(password, encodedHash)
  of nhaPbkdf2Sha512:
    result = pbkdf2_sha512.isValidPassword(password, encodedHash)
  of nhaArgon2i, nhaArgon2id, nhaDefault:
    result = argon2.isValidPassword(password, encodedHash)