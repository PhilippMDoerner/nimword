import argon2_bind
import std/base64

func hashEncode(
  hash: string, 
  salt: string, 
  iterations: uint32, 
  memoryCostK: uint32;
  parallelism: uint32;
  hashLen: uint32;
  algoType: Argon2Type;
  version: Argon2Version
): string =
  ## Encodes all relevant data for a password hash in a string
  ## with the pattern "<algoType>$<version>$<iterations>$<salt>$<memoryCostK>$<parallelism>$<hashLen>$<hash>"
  result = fmt"{algoType}${version}${iterations}${salt}${memoryCostK}${parallelism}${hashLen}${hash}"


proc hashArgon2*(
  password: string, 
  salt: string, 
  iterations: static uint32,
  memoryCostK: static uint32 = Argon2DefaultParams.memoryCostK;
  parallelism: static uint32 = Argon2DefaultParams.parallelism;
  hashLen: static uint32 = Argon2DefaultParams.hashLen;
  algoType: static Argon2Type = Argon2DefaultParams.algoType;
  version: static Argon2Version = Argon2DefaultParams.version
): string {.gcsafe, raises: [Argon2Error].} =
  const params = setupArgon2Params(
    timeCost = iterations,
    memoryCostK,
    parallelism,
    hashLen,
    algoType,
    version
  )

  let res: Argon2Output = password.getOutput(salt, params)
  result = res.hash.encode()

proc hashEncodeArgon2*(
  password: string, 
  salt: string, 
  iterations: static uint32,
  memoryCostK: static uint32 = Argon2DefaultParams.memoryCostK;
  parallelism: static uint32 = Argon2DefaultParams.parallelism;
  hashLen: static uint32 = Argon2DefaultParams.hashLen;
  algoType: static Argon2Type = Argon2DefaultParams.algoType;
  version: static Argon2Version = Argon2DefaultParams.version
): string {.gcsafe, raises: [Argon2Error].} =
  