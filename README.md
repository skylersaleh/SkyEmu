<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_win/dev/WindowsRelease.zip" rel="Download Windows">![Windows Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_win.yml/badge.svg)</a>
<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_mac/dev/MacOSRelease.zip" rel="Download macOS">![Mac Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_mac.yml/badge.svg)
<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_linux/dev/LinuxRelease.zip" rel="Download Linux">![Linux Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_linux.yml/badge.svg)
<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_android/dev/AndroidRelease.zip" rel="Download Android">![Android Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_android.yml/badge.svg)
<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_ios/dev/iOSRelease.zip" rel="Download iOS">![iOS Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_ios.yml/badge.svg)
<a href="https://nightly.link/skylersaleh/SkyEmu/workflows/deploy_freebsd/dev/FreeBSDRelease.zip" rel="Download FreeBSD">![FreeBSD Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_freebsd.yml/badge.svg)
<a href="https://web.skyemu.app/branch/dev" rel="Web Build">![Web Build](https://github.com/skylersaleh/SkyEmu/actions/workflows/deploy_web.yml/badge.svg)
<a href="https://discord.gg/tnUEtmJgA5" rel="Join Discord Server">![Discord Shield](https://discordapp.com/api/guilds/1131322341645893783/widget.png?style=shield) 

<img width="90" align="left" alt="SkyEmu App Screenshot" src="https://user-images.githubusercontent.com/7118296/175430950-1d969fa8-e192-4e0d-a585-521b4b286725.png">

# SkyEmu

SkyEmu is a low level GameBoy, GameBoy Color, Game Boy Advance, and Nintendo DS emulator. Its primary focus is to provide a good user experience through a good mixture of tradeoffs of accuracy, performance, features and usability.

<img width="1015" alt="SkyEmu App Screenshot" src="https://user-images.githubusercontent.com/7118296/197385606-b12439ca-48d4-46f2-b0d5-311037430f94.png">

# Features

- [Highly accurate Game Boy Advance emulation](docs/Accuracy.md)
- Game Boy and Game Boy Color Emulation
- Nintendo DS Emulation (Beta Quality)
- High Quality Upscaling Shaders, Color Correction, and Screen Ghosting
- Cross Platform: Windows, MacOS, Linux, FreeBSD, iOS, Android, and Web
- Game Controller and Rumble Support with configureable keybinds
- 4x Persistent Save State Slots with screenshot preview
- Game fastforward and rewind support (supporting [very long rewind times](https://www.youtube.com/watch?v=Sfc_1NKbiKg))
- Action Replay Cheat Code Engine 
- Localization in Armenian, Chinese, Danish, Dutch, English, German, Greek, Italian, and Russian
- Support for emulating the Real Time Clock and Solar Sensor
- CPU, MMIO, and Memory Debuggers
- Support for loading official BIOS and Boot ROM dumps
- Support for loading roms compressed in .zip archives
- [REST-like API for asynchronous scripting and other automation](docs/HTTP_CONTROL_SERVER.md)

## Download / Usage

Native builds can be downloaded at: https://github.com/skylersaleh/SkyEmu/releases

The latest version of the emulator can also be played without installing at the following address as a progressive web app:

https://web.skyemu.app/

On Mobile platforms it is recommended to add this to the home screen and launch from there. This will prevent the web browser from auto deleting save files and will make the app full screen. 

Drag and drop a rom in to load it or click on the Load .GB/.GBC/.GBA button to open a menu to select a rom. 

Note: Platform BIOS/Firmware files are not required as SkyEmu bundles open source replacement BIOS/stubs. However, it is strongly recommended to dump official BIOS/firmware as the open source replacements lack many of the features of the native firmware/BIOS (such as colorizing GB games and the startup splashes) and are not as accurate. 
=======
- Dark and Light Themes
- Support for loading official BIOS and Boot ROM dumps
- Support for loading roms compressed in .zip archives

## Download / Usage

Native builds can be downloaded at: https://github.com/skylersaleh/SkyEmu/releases

The latest version of the emulator can also be played without installing at the following address as a progressive web app:

https://web.skyemu.app/

On Mobile platforms it is recommended to add this to the home screen and launch from there. This will prevent the web browser from auto deleting save files and will make the app full screen. 

## Discord Server

<a href="https://discord.gg/tnUEtmJgA5" rel="Join Discord Server">![Discord Banner 2](https://discordapp.com/api/guilds/1131322341645893783/widget.png?style=banner2)</a>

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
- Per Pixel PPU Implementation capable of both scan line and mid scan line effects (SkyEmu and NanoBoyAdvance are the only GBA emulators released to support this) 
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
- Dotclk based PPU implementation
- Anti-aliased audio synthesis with support for APU changes per sample (supports Pikachu's voice in Pokemon Yellow/Pokemon Pinball)

## Birds of a Feather
- [**Pokemon Bot**](https://github.com/OFFTKP/pokemon-bot): A discord bot that can connect to SkyEmu to allow your discord users to play GB/GBC/GBA/NDS games. 
- [**Panda3DS**](https://github.com/wheremyfoodat/Panda3DS): Panda themed HLE Nintendo 3DS emulator
- [**NanoBoyAdvance**](https://github.com/nba-emu/NanoBoyAdvance): A Game Boy Advance emulator focusing on hardware research and cycle-accurate emulation
- [**Dust**](https://github.com/kelpsyberry/dust): Nintendo DS emulator for desktop devices and the web
- [**Kaizen**](https://github.com/SimoneN64/Kaizen): Experimental work-in-progress low-level N64 emulator
