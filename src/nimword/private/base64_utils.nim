import std/base64

export base64.encode

proc toBytes*(s: string): seq[byte] =
  ## Simply casts a string into a byte-sequence without modifying it
  result = cast[ptr seq[byte]](unsafeAddr s)[]

proc decode*(s: string): seq[byte] =
  ## Decodes a base64 encoded string and returns it as a byte-sequence
  let decodedStr: string = base64.decode(s)
  result = decodedStr.toBytes()
