#!/bin/bash

# checks the formatting of the project.
# This script doesn't check vendored files.
# Every new file belonging to our code should be included into this one for formatting purposes.

clang-format --dry-run --Werror src/main.c src/gb.h src/gba.h src/arm7.h src/ios_support.h src/localization.c src/localization.h src/nds.h  
