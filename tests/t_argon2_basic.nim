# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest
import std/[strformat, osproc, strutils, base64]
import nimword/argon2
import libsodium/[sodium_sizes]

const password = "lala"
const salt = "1234567812345678"
const hashLength = 32
let iterations = crypto_pwhash_opslimit_moderate().int

let memoryLimitBytes = crypto_pwhash_memlimit_moderate().int
let memoryLimitInKb = memoryLimitBytes/1024

suite "Argon2 ":
  test """
    Given a password, a salt and a number of iterations,
    When calculating a hash with hashPassword
    It should produce an identical hash to calling the argon cli command 
    `echo -n lala | argon2 1234567812345678 -v 13 -id -p 1 -k 262144.0 -t 3 -l 32 -e`
  """:
    # Given
    let argonCommand = fmt"echo -n {password} | argon2 {salt} -v 13 -id -p 1 -k {memoryLimitInKb} -t {iterations} -l {hashLength} -e"
    let cliEncodedHash = execCmdEx(argonCommand).output
    var cliHash: string = cliEncodedHash.split('$')[^1]
    cliHash.removeSuffix("\n")

    # When
    let libHash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )

    # Then
    check cliHash == libHash


  test """
    Given a password and its hash
    When calculating the hash with hashPassword using a different salt
    It should produce an different hash from the initial one 
  """:
    # Given
    let differentSalt = "1234123412341234"
    let initialHash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      differentSalt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )

    # Then
    check initialHash != differentHash


  test """
    Given a password and its hash
    When calculating the hash with hashPassword using a different number of iterations
    It should produce an different hash from the initial one 
  """:
    # Given
    let differentIterations = iterations - 1
    let initialHash = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      salt, 
      differentIterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )

    # Then
    check initialHash != differentHash


  test """
    Given a password, its hash and all parameters used to calculate the hash,
    When encoding the hash with `encodeHash`
    Then it should produce a string that is identical to one produced by `hashEncodePassword`
  """:
    # Given
    let expectedEncodedHash: string = hashEncodePassword(password, phaArgon2id13, iterations, memoryLimitBytes)
    let encodedSalt: string = expectedEncodedHash.split("$")[^2]
    let salt: string = encodedSalt.decode()
    let hash: string = hashPassword(
      password, 
      salt, 
      iterations, 
      hashLength, 
      algorithm = phaArgon2id13, 
      memoryLimit = memoryLimitBytes
    )

    # When
    let encodedHash: string = encodeHash(
      hash, 
      salt, 
      iterations, 
      phaArgon2id13, 
      memoryLimitBytes
    )
    
    # Then
    check expectedEncodedHash == encodedHash


  test """
    Given a password and its encoded hash
    When verifying that the password can be turned into the encoded hash with "isValidPassword"
    Then return true
  """:
    # Given
    let encodedHash = hashEncodePassword(password, phaArgon2id13, iterations, memoryLimitBytes)

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
    let encodedHash = hashEncodePassword(password, phaArgon2id13, iterations, memoryLimitBytes)
    let differentPassword = fmt"{password}andmore"
    # When
    let isValid = differentPassword.isValidPassword(encodedHash)

    # Then
    check isValid == false
