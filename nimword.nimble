# Package

version       = "0.1.0"
author        = "Philipp Doerner"
description   = "A new awesome nimble package"
license       = "MIT"
srcDir        = "src"


# Dependencies

requires "nim >= 1.6.10"
requires "libsodium >= 0.7.1"

task apis, "docs only for api":
  exec "nim doc --verbosity:0 --warnings:off --project --index:on -d:sqlite " &
    "--git.url:https://github.com/PhilippMDoerner/nimword " &
    "--git.commit:main " &
    "-o:docs " &
    "src/nimword.nim"
  
task containerTests, "Runs the tests within a docker container":
  echo staticExec "sudo docker image rm nimword"
  exec "sudo docker-compose run --rm tests"