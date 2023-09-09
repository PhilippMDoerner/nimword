import std/[strformat, osproc, strutils]
import unittest
import libsodium/[sodium_sizes]
import nimword/argon2
import nimword/private/base64_utils

const password = "lala"
let saltStr = "1234567812345678"
let salt: seq[byte] = saltStr.toBytes()
const hashLength = 32
let iterations = 1

let memoryLimitBytes = crypto_pwhash_memlimit_moderate().int
let memoryLimitInKiB = (memoryLimitBytes / 1024).int

suite "nimword-basics":
  test """
    Given a password and its hash
    When calculating the hash with hashPassword using a different salt
    It should produce an different hash from the initial one 
  """:
    # Given
    let differentSalt: seq[byte] = "1234123412341234".toBytes()
    let initialHash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      differentSalt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )

    # Then
    check initialHash != differentHash


  test """
    Given a password and its hash
    When calculating the hash with hashPassword using a different number of iterations
    It should produce an different hash from the initial one 
  """:
    # Given
    let differentIterations = iterations + 1
    let initialHash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      salt, 
      differentIterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )

    # Then
    check initialHash != differentHash


  test """
    Given a password, its hash and all parameters used to calculate the hash,
    When encoding the hash with `encodeHash`
    Then it should produce a string that is identical to one produced by `hashEncodePassword`
  """:
    # Given
    let expectedEncodedHash: string = hashEncodePassword(password, iterations, phaArgon2id13, memoryLimitInKiB)
    let encodedSalt: string = expectedEncodedHash.split("$")[^2]
    let salt: seq[byte] = encodedSalt.decode()
    let hash: Hash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )

    # When
    let encodedHash: string = encodeHash(
      hash, 
      salt, 
      iterations, 
      phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )
    
    # Then
    check expectedEncodedHash == encodedHash


  test """
    Given a password and its encoded hash
    When verifying that the password can be turned into the encoded hash with "isValidPassword"
    Then return true
  """:
    # Given
    let encodedHash = hashEncodePassword(password, iterations, phaArgon2id13, memoryLimitInKiB)

    # When
    let isValid = password.isValidPassword(encodedHash)

    # Then
    check isValid == true


  test """
    Given a password and an encoded hash from a different password
    When verifying that the password can be turned into the encoded hash with "isValidPassword"
    Then return false
  """:
    # Given
    let encodedHash = hashEncodePassword(password, iterations, phaArgon2id13, memoryLimitInKiB)
    let differentPassword = fmt"{password}andmore"
    
    # When
    let isValid = differentPassword.isValidPassword(encodedHash)

    # Then
    check isValid == false


suite "Argon2 specific":
  test """
    Given a password, a salt and a number of iterations,
    When calculating a hash with hashPassword
    It should produce an identical hash to calling the argon cli command 
    `echo -n lala | argon2 1234567812345678 -v 13 -id -p 1 -k 262144.0 -t 3 -l 32 -e`
  """:
    # Given
    let argonCommand = fmt"echo -n {password} | argon2 {saltStr} -v 13 -id -p 1 -k {memoryLimitInKiB} -t {iterations} -l {hashLength} -e"
    let cliResult = execCmdEx(argonCommand)
    doAssert cliResult.exitCode == 0
    let cliEncodedHash = cliResult.output
    
    echo cliEncodedHash.split('$') # TODO: Remove
    var cliHash: Hash = cliEncodedHash.split('$')[^1].decode()

    # When
    let libHash: Hash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimitKibiBytes = memoryLimitInKiB
    )

    # Then
    check cliHash == libHash
