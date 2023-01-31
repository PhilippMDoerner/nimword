import nimword/[argon2, pbkdf2_sha256, pbkdf2_sha512]

## TODO:
## Implement here an overarching password hashing manager
## It shall provide the procs:
## - verifyPassword:  Given a password and a hash-string, check if it is valid and return a boolean
##  Use the hash-string to figure out which algorithm/module to use
##  Use that module's "verifyPassword" function for the boolean
## - hashPassword: Given a password and an algorithm-variable, turn it into a hash-string. Could maybe also eat a Table for options of the individual parameters
##  Use the algorithm variable to determine which module to use
##  Use that module's "hashEncodePassword" function
## 
## TODO2:
## Ensure that every module for every algorithm implements 4 procs:
## - encodeHash: Given all data used for a password-hashing, generate a string that can be used with "verifyPassword"
##  That function is mostly for the user if they want to do their own thing
## - verifyPassword: Given a hashEncode-string and a password, verify that the password can be turned into the hash in hashEncode
## proc verifyPassword(password: string, encodedHash: string): bool
## - hashPassword: Given a password, salt and a number of iterations (and maybe other options), create and return a hash
## - hashEncodePassword: Given a password, salt, and a number of iterations (and maybe other options), create a hash and turn it into a hash-string
##  That function is mostly for the user if they want to do their own thing