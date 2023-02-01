import std/[strformat, base64, strutils]
import libsodium/[sodium, sodium_sizes]

export sodium.PasswordHashingAlgorithm

proc encodeHash*(
  hash: string, 
  salt: seq[byte], 
  iterations: int, 
  algorithm: PasswordHashingAlgorithm;
  memoryLimitKibiBytes: int;
): string =
  ## Encodes all relevant data for a password hash in a string.
  ## 
  ## The returned string can be used with `isValidPassword<#isValidPassword>`_ .
  ## 
  ## Hash is assumed to be a base64 encoded strings.
  ## Salt gets turned into a base64 encoded string with all padding suffix character of "=" removed.
  ## memoryLimitKibiBytes is the number of KiB used for the hashing process.
  ## algorithm is either "argon2id" or "argon2i".
  ## 
  ## The pattern is:
  ## $<algorithm>$v=19$m=<memoryLimit>,t=<iterations>,p=1$<salt>$<hash>
  var encodedSalt = salt.encode()
  encodedSalt.removeSuffix('=')

  let algorithmStr = case algorithm:
    of phaDefault, phaArgon2id13:
      "argon2id"
    of phaArgon2i13:
      "argon2i"

  result = fmt"${algorithmStr}$v=19$m={memoryLimitKibiBytes},t={iterations},p=1${encodedSalt}${hash}"



proc hashPassword*(
  password: string, 
  salt: seq[byte], 
  iterations: int = crypto_pwhash_opslimit_moderate().int,
  hashLength: int = 32,
  algorithm: PasswordHashingAlgorithm = phaDefault,
  memoryLimitKibiBytes: int = (crypto_pwhash_memlimit_moderate().int / 1024).int
): string =
  ## Hashes the given password using the argon2 algorithm from libsodium.
  ## Returns the hash as a base64 encoded string with any padding "=" suffix
  ## character removed.
  ## 
  ## Salt must be exactly 16 bytes long.
  ## 
  ## Iterations is the number of times the argon-algorithm is applied during hashing.
  ## For guidance on how to choose a number for this value, consult the
  ## `libsodium-documentation<https://doc.libsodium.org/password_hashing/default_phf#guidelines-for-choosing-the-parameters>`_
  ## for the `opslimit` value.
  ## 
  ## hashLength is the number of characters that the hash should be long.
  ## For guidance on how to choose a number for this value, consult the
  ## `libsodium-documentation<https://doc.libsodium.org/password_hashing/default_phf#key-derivation>`_ 
  ## for the `outlen` value.
  ## 
  ## The algorithm defaults to the default of libsodium. For guidance on which Argon variant to choose,
  ## consult the `argon readme<https://github.com/P-H-C/phc-winner-argon2>`_ . Do note that libsodium
  ## and thus this package does not provide a way to call Argon2D.
  ## 
  ## The memoryLimit must be provided in KibiBytes aka KiB, it designates the 
  ## amount of memory used during hashing.
  ## For guidance on how to choose a number for this value, consult the 
  ## `libsodium-documentation<https://doc.libsodium.org/password_hashing/default_phf#key-derivation>`_
  ## for the `memlimit` value.
  let memoryLimitBytes = memoryLimitKibiBytes * 1024
  let hashBytes = crypto_pwhash(
    password, 
    salt, 
    hashLength, 
    algorithm, 
    iterations.csize_t, 
    memoryLimitBytes.csize_t
  )
  result = hashBytes.encode()
  result.removeSuffix("=")

proc hashEncodePassword*(
  password: string, 
  iterations: int = crypto_pwhash_opslimit_moderate().int,
  algorithm: PasswordHashingAlgorithm = phaDefault,
  memoryLimitKibiBytes: int = (crypto_pwhash_memlimit_moderate().int / 1024).int
): string =
  ## Hashes and encodes the given password using the argon2 algorithm from libsodium.
  ## 
  ## Returns the hash as part of a larger string containing hash, iterations, algorithm, 
  ## memoryLimitKibiBytes and salt. For information about the pattern see `encodeHash<#encodeHash>`_
  ## 
  ## The return value can be used with `isValidPassword<#isValidPassword>`_ .
  ## 
  ## The salt is randomly generated during the process.
  ## 
  ## For guidance on choosing values for `iterations`, `algorithm`and `memorylimitKibiBytes`
  ## see `hashPassword<#hashPassword>`_ .
  let memoryLimitBytes: int = memoryLimitKibiBytes * 1024
  result = crypto_pwhash_str(
    password, 
    algorithm, 
    iterations.csize_t, 
    memoryLimitBytes.csize_t
  )

proc isValidPassword*(password: string, encodedHash: string): bool =
  ## Verifies that a given plain-text password can be used to generate
  ## the hash contained in `encodedHash` with the parameters provided in `encodedHash`.
  ## 
  ## `encodedHash` must be a string with the kind of pattern that `encodeHash<#encodeHash>`_
  ## and `hashEncodePassword<#hashEncodePassword>`_ generate. 
  ## 
  ## Raises SodiumError if an error happens during the process.
  result = crypto_pwhash_str_verify(encodedHash, password) 