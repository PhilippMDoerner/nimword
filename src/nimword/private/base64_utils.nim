import std/base64

export base64.encode

proc toBytes*(s: string): seq[byte] =
  result = cast[ptr seq[byte]](unsafeAddr s)[]

proc `$`*(s: seq[byte]): string =
  result = cast[ptr string](unsafeAddr s)[]

proc decode*(s: string): seq[byte] =
  let decodedStr: string = base64.decode(s)
  result = decodedStr.toBytes()
