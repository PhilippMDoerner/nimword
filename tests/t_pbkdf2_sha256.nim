import unittest
import std/[strformat, strutils]
import nimword/pbkdf2_sha256
import nimword/private/base64_utils

const password = "lala"
const hashLength = 32
let salt = "1234567812345678".toBytes()
let iterations = 1000


suite "PBKDF2-HMAC-SHA256":
  test """
    Given a password and its hash
    When calculating the hash with hashPassword using a different salt
    It should produce an different hash from the initial one 
  """:
    # Given
    let differentSalt = "1234123412341234".toBytes()
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
    let salt: seq[byte] = encodedSalt.decode()
    let hash: Hash = hashPassword(
      password, 
      salt, 
      iterations
    )

    # When
    let encodedHash: string = encodeHash(
      hash, 
      salt, 
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
