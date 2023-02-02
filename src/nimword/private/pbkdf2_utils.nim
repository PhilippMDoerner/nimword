from std/openssl import DLLSSLName, EVP_MD, DLLUtilName, getOpenSSLVersion
import std/[strformat, strutils, dynlib]
import ./base64_utils

type Pbkdf2Error* = object of ValueError

type Pbkdf2Algorithm* = enum
  pbkdf2_sha256
  pbkdf2_sha512


## Imports that sometimes break when importing from std/openssl - START
type DigestSizeProc = proc(md: EVP_MD): cint {.cdecl, gcsafe.}

let lib = loadLibPattern(DLLUtilName)
assert lib != nil, fmt"Could not find lib {DLLUtilName}"

proc getOpenSSLMajorVersion(): uint =
  ## Returns the major version of openssl
  result = (getOpenSSLVersion() shr 28) and 0xF

proc EVP_MD_size_fixed*(md: EVP_MD): cint =
  assert md != nil, "Tried to get the hash size for a digest function but the digest function was nil!"
  let sizeProc: DigestSizeProc =
    if getOpenSSLMajorVersion() == 3:
      cast[DigestSizeProc](lib.symAddr("EVP_MD_get_size"))
    
    elif getOpenSSLMajorVersion() == 1:
      cast[DigestSizeProc](lib.symAddr("EVP_MD_size"))

    else:
      raise newException(ValueError, fmt"This library supports only openssl 1 and 3. The openssl version we found was {getOpenSSLMajorVersion()}")
  
  assert sizeProc != nil, "Failed to load hash size for digest function"
  result = sizeProc(md)


## Imports that sometimes break when importing from std/openssl - END



proc `$`(s: seq[byte]): string =
  ## Casts a 
  result = cast[ptr string](unsafeAddr s)[]

proc encodeHash*(
  hash: string, 
  salt: seq[byte], 
  iterations: SomeInteger, 
  algorithm: Pbkdf2Algorithm,
): string =
  ## Encodes all relevant data for a password hash in a string.
  ## 
  ## Hash is assumed to be a base64 encoded strings.
  ## Salt gets turned into a base64 encoded string with all padding suffix character of "=" removed.
  ## Algorithm is either "pbkdf2_sha256" or "pbkdf2_sha512"
  ## 
  ## The pattern is:
  ## $<algorithm>$<iterations>$<salt>$<hash>
  var encodedSalt = salt.encode()
  encodedSalt.removeSuffix('=')
  result = fmt"${algorithm}${iterations}${encodedSalt}${hash}"

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


proc hashPbkdf2*(password: string, salt: seq[byte], iterations: int, digestFunction: EVP_MD): string {.gcsafe.} =
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
    ($salt).cstring,
    len(salt).cint,
    iterations.cint,
    digestFunction,
    hashLength,
    outputStartingpoint
  )
  
  let wasHashSuccessful = hashOperationReturnCode == 1
  doAssert wasHashSuccessful

  result = encode(output)
  result.removeSuffix("=")
