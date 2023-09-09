type Password* = distinct string

converter toPassword*(str: string): Password = str.Password

type Hash* = seq[byte]