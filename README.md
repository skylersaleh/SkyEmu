<img width="90" align="left" alt="SkyEmu App Screenshot" src="https://user-images.githubusercontent.com/7118296/175430950-1d969fa8-e192-4e0d-a585-521b4b286725.png">

# SkyEmu

SkyEmu is a low level GameBoy, GameBoy Color and Game Boy Advance emulator. Its primary focus is to provide a good user experience through a good mixture of tradeoffs of accuracy, performance, features and usability.

<img width="1015" alt="SkyEmu App Screenshot" src="https://user-images.githubusercontent.com/7118296/175430669-20c8079a-bf5c-44b6-b7da-270aca51f216.png">

# Features

- Highly accurate Game Boy Advanced emulation
- Game Boy and Game Boy Color Emulation 
- Experimental Nintendo DS support (only capable of running homebrew currently)
- Cross Platform: Windows, MacOS, Linux, Web App (with touch screen controls for iOS and Android)
- Game Controller and Rumble Support with configureable keybinds
- 4x Save Slots with screenshot preview
- Game fastforward and rewind support (supporting [very long rewind times](https://www.youtube.com/watch?v=Sfc_1NKbiKg))
- Support for emulating the Real Time Clock
- CPU, MMIO, and Memory Debuggers
- Dark and Light Themes
- Support for loading official BIOSs dumps

## Web App Based Build (Desktop/iOS/Android)

The latest version of the emulator can be played at the following address as a progressive web app:

https://web.skyemu.app/

On Mobile platforms it is recommended to add to the home screen and launch from there. This will prevent the web browser from auto deleting save files and will remove the browsers UI. 

Nightly native builds can be downloaded at the following links: 

- [Windows](https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_win/main/WindowsRelease.zip)
- [macOS](https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_mac/main/MacOSRelease.zip)
- [Linux](https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_linux/main/LinuxRelease.zip)

Drag and drop a rom in to load it or click on the Load .GB/.GBC/.GBA button to open a menu to select a rom. 

Note: A GBA BIOS is not required as SkyEmu bundles an open source replacement BIOS. However, a dump of an official GBA BIOS should be used if you want to maximize accuracy or you like seeing the GBA intro.

## Default Controls:

- WASD: D-Pad
- J: A button
- K: B button
- ': Select button
- Enter: Start button
- U: L shoulder
- I: R shoulder

On mobile platforms an onscreen touch screen controller is provided. 

## Loading save files and BIOSs

On web builds save files and the BIOS can be loaded by dragging them onto the page or loading them using the ROM file picker. The GBA BIOS must be named `gba_bios.bin` for the emulator to pick it up. Save files must be named the name of the rom file with the extension `.sav`. So for example if the ROM was `MyRomFile.gba` the save file must be called `MyRomFile.sav`. 

On native builds the above naming convention still applies, but the save/BIOS files must be instead located in the same folder as the ROM file, instead of being dragged or loaded in the emulator itself.

## Native Build Instructions

Native builds are experimental currently but can be built using the following commands:

```
mkdir build
cd build
cmake .. 
cmake --build . 
```

The output binaries should be in the build/bin folder

Native builds support loading roms through the command line by specifying the path to the ROM as the first argument: 

```
./SkyEmu path/to/rom.gba
```

## Accuracy/Compatibility

SkyEmu has been tested on 100s of ROMs and most common games should be playable with no to minor bugs currently. However, the GBA emulation is significantly more accurate than the GB/GBC emulation. 

**GBA**:
- Per Pixel PPU Implementation capable of both scan line and mid scan line effects (SkyEmu is the only GBA emulator released to support this) 
- Passes the AGS Aging Test ROM (SkyEmu is the second SW based GBA emulator to ever pass this)
- Can run difficult to emulate GBA games such as the NES Classics Series, Golden Sun and Hello Kitty Miracle Fashion Maker
- 100% Passes all ArmWrestler Tests
- 100% Passes all FuzzARM tests
- 100% Passes arm.gba and thumb.gba
- Passes 2020/2020 GBA Suite timing tests when utilizing the official Nintendo GBA BIOS (SkyEmu is one of the few emulators capable of passing this test).
- Full instruction pipeline and prefetch emulation

**GB**: 
- Passes all of Blargg's CPU instruction tests
- Passes DMG and GBC acid2 PPU conformance tests
- Passes MBCtest
- Scan line based PPU implementation
- Anti-aliased audio synthesis with support for APU changes per sample (supports Pikachu's voice in Pokemon Yellow/Pokemon Pinball)
