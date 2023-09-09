# Package

version       = "1.0.0"
author        = "Philipp Doerner"
description   = "A simple library with a simple interface to do password hashing and validation with different algorithms"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.10"
requires "libsodium >= 0.7.1"

task apis, "docs only for api":
  exec "nim doc --verbosity:0 --warnings:off --project --index:on " &
    "--git.url:https://github.com/PhilippMDoerner/nimword " &
    "--git.commit:main " &
    "-o:docs/apidocs " &
    "src/nimword.nim"
  
  exec "nim buildIndex -o:docs/apidocs/index.html docs/apidocs"

task containerTests, "Runs the tests within a docker container":
  echo staticExec "sudo docker image rm nimword"
  exec "sudo docker-compose run --rm tests"