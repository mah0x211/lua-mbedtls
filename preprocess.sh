#!/bin/sh

set -e
set -x

cd deps/mbedtls/
make
make check
programs/test/selftest
