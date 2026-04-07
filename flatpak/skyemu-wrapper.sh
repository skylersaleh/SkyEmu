#!/bin/bash
# Define the target directory inside the sandbox
DATA_DIR="$XDG_DATA_HOME/Sky/SkyEmu"

# Create the directory if it doesn't exist
mkdir -p "$DATA_DIR"
mkdir -p "$DATA_DIR/saves"
mkdir -p "$DATA_DIR/cheats"
mkdir -p "$DATA_DIR/bios"

# Copy the modified default config file if it's not already there
if [ ! -f "$DATA_DIR/search_paths.bin" ]; then
    cp /app/share/skyemu/search_paths.bin "$DATA_DIR/search_paths.bin"
fi

if [ ! -f "$DATA_DIR/user_settings.bin" ]; then
    cp /app/share/skyemu/user_settings.bin "$DATA_DIR/user_settings.bin"
fi

# Launch the actual program
exec /app/bin/SkyEmu "$@"
