#!/bin/bash

CURDIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
TARGET=${CURDIR}/fuzz
PREFIX=third_party/move

while test $# -gt 0; do
    case "$1" in
        -b)
            # clean up
            cargo +fuzz clean
            rm -rf ${TARGET}

            # build and run the test
            PAFL=${TARGET}/build PAFL_TARGET_PREFIX=${PREFIX} \
            cargo +fuzz test -j 1 \
                regression_tests::fuzz::miri_path_fuzz -- \
                --exact
            ;;
        -r)
            # run the fuzzer
            PAFL=${TARGET}/build PAFL_TARGET_PREFIX=${PREFIX} \
            cargo +fuzz miri test \
                regression_tests::fuzz::miri_path_fuzz -- \
                --exact
            ;;
        *)
            echo "invalid argument $1"
            exit 1
            ;;
    esac
    shift
done
