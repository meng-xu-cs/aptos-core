#!/bin/bash

PREFIX=third_party/move

while test $# -gt 0; do
    case "$1" in
        -b)
            cargo +fuzz clean

            PAFL=1 PAFL_TARGET_PREFIX=${PREFIX} \
            cargo +fuzz test \
                regression_tests::fuzz::miri_path_fuzz -- \
                --exact
            ;;
        -r)
            PAFL=1 PAFL_TARGET_PREFIX=${PREFIX} \
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
