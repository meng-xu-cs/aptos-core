#!/bin/bash

cargo +fuzz miri test \
    regression_tests::fuzz::miri_path_fuzz -- \
    --exact
