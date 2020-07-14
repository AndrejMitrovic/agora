#!/bin/bash

set -xeu
set -o pipefail

# echo dub build -c unittest -b unittest-cov --skip-registry=all --compiler=ldc2
dub build -c unittest -b unittest-cov --skip-registry=all --compiler=ldc2
rdmd --build-only -of./runner --compiler=${DC} ./ci/unittest_runner.d
sudo ./runner
