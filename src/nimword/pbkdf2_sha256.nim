import std/[strformat, strutils, sysrand]
from std/openssl import DLLSSLName, EVP_MD, DLLUtilName
import ./private/[base64_utils, pbkdf2_utils]

export pbkdf2_utils.Pbkdf2Error
export Password
export toPassword
export Hash

# Imports that sometimes break when importing from std/openssl - START
proc EVP_sha256_fixed(): EVP_MD    {.cdecl, dynlib: DLLUtilName, importc: "EVP_sha256".}
# Imports that sometimes break when importing from std/openssl - END

proc encodeHash*(
  hash: Hash, 
  salt: seq[byte], 
  iterations: SomeInteger, 
): string =
  ## Convenience proc to encode all relevant data for a password hash 
  ## using pbkdf2_sha256 into a string.
  ##  
  ## The returned string can be used with `isValidPassword<#isValidPassword%2Cstring%2Cstring>`_ .
  ## 
  ## For further information, see `encodeHash<private/pbkdf2_utils.html#encodeHash%2Cstring%2Cseq[byte]%2CSomeInteger>`_

  result = encodeHash(hash, salt, iterations, Pbkdf2Algorithm.pbkdf2_sha256)

proc hashPassword*(password: Password, salt: seq[byte], iterations: int): Hash {.gcsafe.} =
  ## Hashes the given plain-text password with the PBKDF2 using an HMAC 
  ## with the SHA256 hashing algorithm from openssl.
  ## 
  ## Returns the hash as Hash type.
  ## 
  ## Salt can be of any size, but is recommended to be at least 16 bytes long.
  ## 
  ## Iterations is the number of times the argon-algorithm is applied during hashing.
  ## Set the number of iterations to be as high as you can as long as hashing 
  ## times remain acceptable for your application.
  ## For online use (e.g. logging in on a website), a 1 second computation is likely to be the acceptable maximum.
  ## For interactive use (e.g. a desktop application), a 5 second pause after having entered a password is acceptable if the password doesn't need to be entered more than once per session.
  ## For non-interactive and infrequent use (e.g. restoring an encrypted backup), an even slower computation can be an option.
  let digestFunction: EVP_MD = EVP_sha256_fixed()
  result = hashPbkdf2(password, salt, iterations, digestFunction)

proc hashEncodePassword*(password: Password, iterations: int): string {.gcsafe.} =
  ## Hashes and encodes the given password with the PBKDF2 using an HMAC 
  ## with the SHA256 hashing algorithm from openssl.
  ## 
  ## Returns the hash in an encoded form as part of a larger string containing it, iterations and salt. 
  ## For information about the pattern see `encodeHash<#encodeHash%2Cstring%2Cseq[byte]%2CSomeInteger>`_
  ## 
  ## The return value can be used with `isValidPassword<#isValidPassword%2Cstring%2Cstring>`_ .
  ## 
  ## For guidance on choosing values for `iterations`, `algorithm`and `memorylimitKibiBytes`
  ## see `hashPassword<#hashPassword%2Cstring%2Cseq[byte]%2Cint>`_ .
  ## 
  ## The salt used for the hash is randomly generated during the process.
  let salt = urandom(16)
  let hash: Hash = hashPassword(password, salt, iterations)
  result = hash.encodeHash(salt, iterations)

proc isValidPassword*(password: Password, encodedHash: string): bool {.raises: {Pbkdf2Error, Exception} .} =
  ## Verifies that a given plain-text password can be used to generate
  ## the hash contained in `encodedHash` with the parameters provided in `encodedHash`.
  ## 
  ## `encodedHash` must be a string with the kind of pattern that `encodeHash<#encodeHash%2Cstring%2Cseq[byte]%2CSomeInteger>`_
  ## and `hashEncodePassword<#hashEncodePassword%2Cstring%2Cint>`_ generate. 
  ##
  ## Raises Pbkdf2Error if an error happens during the process.

  try:
    let hashPieces: seq[string] = encodedHash.split('$')[1..^1]
    let iterations: int = parseInt(hashPieces[1])
    let salt: seq[byte] = hashPieces[2].decode()

    let passwordHash: Hash = password.hashPassword(salt, iterations)
    
    let hash: Hash = hashPieces[3].decode()
    result = passwordHash == hash
  
  except CatchableError as e:
    raise newException(
      Pbkdf2Error, 
      fmt"Could not calculate password hash from the encoded Hash string", 
      e
    )