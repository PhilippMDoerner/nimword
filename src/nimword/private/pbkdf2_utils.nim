from std/openssl import DLLSSLName, EVP_MD, DLLUtilName
import std/[strformat, strutils, base64]

type Pbkdf2Error* = object of ValueError

type Pbkdf2Algorithm* = enum
  pbkdf2_sha256
  pbkdf2_sha512

## Imports that sometimes break when importing from std/openssl - START
proc EVP_MD_size_fixed*(md: EVP_MD): cint {.cdecl, dynlib: DLLUtilName, importc: "EVP_MD_get_size".} 
## Imports that sometimes break when importing from std/openssl - END

func encodeHash*(
  hash: string, 
  salt: string, 
  iterations: SomeInteger, 
  algorithm: Pbkdf2Algorithm,
): string =
  ## Encodes all relevant data for a password hash in a string
  ## with the pattern "<algorithm>$<iterations>$<salt>$<hash>"
  result = fmt"{algorithm}${iterations}${salt}${hash}"

proc PKCS5_PBKDF2_HMAC(
  pass: cstring,
  passLen: cint,
  salt: cstring,
  saltLen: cint,
  iter: cint,
  digest: EVP_MD,
  keylen: cint,
  output: cstring
): cint {.cdecl, dynlib: DLLSSLName, importc: "PKCS5_PBKDF2_HMAC".} ##
## Documentation as per : https://www.openssl.org/docs/manmaster/man3/PKCS5_PBKDF2_HMAC.html
## PKCS5_PBKDF2_HMAC() derives a key from a password using a salt and iteration count.
## 
## pass is the password used in the derivation of length passlen. pass is an optional 
## parameter and can be NULL. 
## If passlen is -1, then the function will calculate the length of pass using strlen().
## 
## salt is the salt used in the derivation of length saltlen. 
## If the salt is NULL, then saltlen must be 0. 
## The function will not attempt to calculate the length of the salt because it is not assumed to be NULL terminated.
## 
## iter is the iteration count and its value should be greater than or equal to 1. 
## Any iter less than 1 is treated as a single iteration.
## 
## digest is the message digest function used in the derivation. 
## 
## The derived key will be written to out. 
## The size of the out buffer is specified via keylen.


proc hashPbkdf2*(password: string, salt: string, iterations: int, digestFunction: EVP_MD): string {.gcsafe.} =
  ## Hashes the given password with a SHA256 digest and the PBKDF2 hashing function
  ## from openSSL. This will execute the PBKDF2.
  ## HMAC = Hash based message authentication code
  let hasTooManyIterations = iterations > cint.high
  if hasTooManyIterations: 
    raise newException(ValueError, fmt"You can not have more iterations than a c integer can carry. Choose a number below {cint.high}")

  let hashLength: cint = EVP_MD_size_fixed(digestFunction)
  let output = newString(hashLength)
  let outputStartingpoint: cstring = cast[cstring](output[0].unsafeAddr)

  let hashOperationReturnCode = PKCS5_PBKDF2_HMAC(
    password.cstring,
    -1,
    salt.cstring,
    len(salt).cint,
    iterations.cint,
    digestFunction,
    hashLength,
    outputStartingpoint
  )
  
  let wasHashSuccessful = hashOperationReturnCode == 1
  doAssert wasHashSuccessful

  result = encode(output)