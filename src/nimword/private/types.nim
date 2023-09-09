type Password* = distinct string ## A special type for plain-text password string to prevent performing normal string operations with them. They are security critical and should not be accidentally logged or the like.

converter toPassword*(str: string): Password = str.Password ## Converter that implicitly converts any string to a `Password` type. Makes it easier to use procs with strings.

type Hash* = seq[byte] ## A convenience type to better express hashes.