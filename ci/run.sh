#!/bin/bash

set -xeu
set -o pipefail

# Only build the unittest binary, but don't run it
# We want to run it ourselves to catch any bug / set timeout, etc...
dub build -b unittest-cov -c unittest --skip-registry=all --compiler=${DC}

dchatty=1
timeout -s SEGV 8m ./build/agora-unittests
