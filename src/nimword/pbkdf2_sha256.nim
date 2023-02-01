import std/[strformat, strutils, base64, sysrand]
from std/openssl import DLLSSLName, EVP_MD, DLLUtilName
import ./private/pbkdf2_utils

## Imports that sometimes break when importing from std/openssl - START
proc EVP_sha256_fixed(): EVP_MD    {.cdecl, dynlib: DLLUtilName, importc: "EVP_sha256".}
## Imports that sometimes break when importing from std/openssl - END

proc `$`(s: seq[byte]): string =
  result = cast[ptr string](unsafeAddr s)[]

proc encodeHash*(
  hash: string, 
  salt: string, 
  iterations: SomeInteger, 
): string =
  result = encodeHash(hash, salt, iterations, Pbkdf2Algorithm.pbkdf2_sha256)

proc hashPassword*(password: string, salt: string, iterations: int): string {.gcsafe.} =
  ## Hashes the given password with an HMAC using the SHA256 hashing function 
  ## and the PBKDF2 function to derive a key as a "hash" from the password.
  ## This is using openSSL.
  ## The returned hash is always 44 characters long.
  let digestFunction: EVP_MD = EVP_sha256_fixed()

  result = hashPbkdf2(password, salt, iterations, digestFunction)

proc hashEncodePassword*(password: string, iterations: int): string {.gcsafe.} =
  ## Hashes the given password with an HMAC using the SHA256 hashing function 
  ## and the PBKDF2 function to derive a key as a "hash" from the password.
  ## This is using openSSL.
  ## The hash is returned in a string together with the algorithm, salt and 
  ## number of iterations used to generate it, following this pattern:
  ## "<algorithm>$<iterations>$<salt>$<hash>" 
  let salt = $urandom(16)
  let hash = hashPassword(password, salt, iterations)
  result = hash.encodeHash(salt, iterations, Pbkdf2Algorithm.pbkdf2_sha256)

proc isValidPassword*(password: string, encodedHash: string): bool =
  try:
    let hashPieces: seq[string] = encodedHash.split('$')[1..^1]
    let iterations: int = parseInt(hashPieces[1])
    let salt: string = hashPieces[2].decode()

    let passwordHash: string = password.hashPassword(salt, iterations)
    
    let hash: string = hashPieces[3]
    result = passwordHash == hash
  
  except CatchableError as e:
    raise newException(
      Pbkdf2Error, 
      fmt"Could not calculate password hash from the data encoded in '{encodedHash}'. Expected pattern of 'pbkdf2_sha256$<iterations>$<salt>$<hash>'", 
      e
    )