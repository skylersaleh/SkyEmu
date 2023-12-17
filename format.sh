#!/bin/bash

# formats the project.
# This is a script as to not accidentally format vendored files.
# Every new file belonging to our code should be included into this one for formatting purposes.

clang-format -i src/main.c src/gb.h src/gba.h src/arm7.h src/gba_bios.h src/ios_support.h src/lcd_shaders.h src/localization.c src/localization.h src/nds.h src/nds_rom_database.h 
