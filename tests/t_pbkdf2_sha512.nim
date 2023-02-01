# This is just an example to get you started. You may wish to put all of your
# tests into a single file, or separate them into multiple `test1`, `test2`
# etc. files (better names are recommended, just make sure the name starts with
# the letter 't').
#
# To run these tests, simply execute `nimble test`.

import unittest
import std/[strformat, osproc, strutils, base64]
import nimword/pbkdf2_sha512

const password = "lala"
const salt = "1234567812345678"
const hashLength = 32
let iterations = 1000


suite "PBKDF2-HMAC-SHA512":
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
      iterations
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      differentSalt, 
      iterations
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
      iterations
    )
    
    # When
    let differentHash = hashPassword(
      password, 
      salt, 
      differentIterations
    )

    # Then
    check initialHash != differentHash


  test """
    Given a password, its hash and all parameters used to calculate the hash,
    When encoding the hash with `encodeHash`
    Then it should produce a string that is identical to one produced by `hashEncodePassword`
  """:
    # Given
    let expectedEncodedHash: string = hashEncodePassword(password, iterations)
    let encodedSalt: string = expectedEncodedHash.split("$")[^2]
    let salt: string = encodedSalt.decode()
    let hash: string = hashPassword(
      password, 
      salt, 
      iterations
    )

    # When
    let encodedHash: string = encodeHash(
      hash, 
      encodedSalt, 
      iterations,
    )
    
    # Then
    check expectedEncodedHash == encodedHash


  test """
    Given a password and its encoded hash
    When verifying that the password can be turned into the encoded hash with "isValidPassword"
    Then return true
  """:
    # Given
    let encodedHash = hashEncodePassword(password, iterations)

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
    let encodedHash = hashEncodePassword(password, iterations)
    let differentPassword = fmt"{password}andmore"
    # When
    let isValid = differentPassword.isValidPassword(encodedHash)

    # Then
    check isValid == false
