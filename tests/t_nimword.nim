import unittest
import std/[strformat]
import nimword
import nimword/private/base64_utils

const password = "lala"
const hashLength = 32
let salt = "1234567812345678".toBytes()
let iterations = 3

template testSuite(algorithm: NimwordHashingAlgorithm) =
  suite "Nimword isValidPassword and hashEncodePassword - " & $algorithm :
    test """
      Given a password and its encoded hash
      When verifying that the password can be turned into the encoded hash with "isValidPassword"
      Then return true
    """:
      for algorithm in NimwordHashingAlgorithm:
        # Given
        let encodedHash = hashEncodePassword(password, iterations, algorithm)

        # When
        let isValid = password.isValidPassword(encodedHash)

        # Then
        check isValid == true


    test """
      Given a password and an encoded hash from a different password
      When verifying that the password can be turned into the encoded hash with "isValidPassword"
      Then return false
    """:
      for algorithm in NimwordHashingAlgorithm:
        # Given
        let encodedHash = hashEncodePassword(password, iterations, algorithm)
        let differentPassword = fmt"{password}andmore"
        # When
        let isValid = differentPassword.isValidPassword(encodedHash)

        # Then
        check isValid == false

for algorithm in NimwordHashingAlgorithm:
  testSuite(algorithm)