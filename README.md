# SkyEmu

SkyEmu is low level cycle accurate GameBoy, GameBoy Color and Game Boy Advance emulator that I have been developing in my spare time. Its primary focus is to provide a good user experience through a good mixture of tradeoffs of accuracy, performance, features and usability. It is still fairly early in development and should be considered as beta quality. 

<img width="851" alt="image" src="https://user-images.githubusercontent.com/7118296/141718823-5f5251de-b60a-412d-9624-751173d56c45.png">

## Web App Based Build (Desktop/iOS/Android)

The latest version of the emulator can be played at the following address as a progressive web app:

https://skylersaleh.github.io/SkyEmu/

On Mobile platforms it is recommended to add to the home screen and launch from there. This will prevent the web browser from auto deleting save files and will remove the browsers UI. 

Drag and drop a rom in to load it or click on the Load .GB/.GBC/.GBA button to open a menu to select a rom. 

Note: A GBA BIOS is not required as SkyEmu bundles an open source replacement BIOS. 

Controls:

- WASD: D-Pad
- J: A button
- K: B button
- ': Select button
- Enter: Start button
- U: L shoulder
- I: R shoulder

On mobile platforms an onscreen touch screen controller is provided. 

## Native Build Instructions

Native builds are experimental currently but can be built using the following commands:

```
mkdir build
cd build
cmake .. 
cmake --build . 
```

The output binaries should be in the build/bin folder

Native builds should work for the following platforms although they are currently not well tested:

- Windows
- Mac OS X
- Linux
- iOS
- Android

## Accuracy/Compatibility

SkyEmu has been tested on 100s of ROMs and most common games should be playable with no to minor bugs currently. However, the GBA emulation is significantly more accurate than the GB/GBC emulation. 

**GBA**:
- Per Pixel PPU Implementation capable of both scan line and mid scan line effects (SkyEmu is the only GBA emulator released to support this) 
- Passes the AGS Aging Test ROM (SkyEmu is the second SW based GBA emulator to ever pass this)
- Can run difficult to emulate GBA games such as the NES Classics Series, Golden Sun and Hello Kitty Miracle Fashion Maker
- 100% Passes all ArmWrestler Tests
- 100% Passes all FuzzARM tests
- 100% Passes arm.gba and thumb.gba
- Passes 1860/1920 GBA Suite timing tests (for reference mGBA 0.9.2 passes 1696/1920 and VBA-M 2.1.4 passes 994/1920)
- Full instruction pipeline and prefetch emulation

**GB**: 
- Passes all of Blargg's CPU instruction tests
- Passes DMG and GBC acid2 PPU conformance tests
- Passes MBCtest
- Scan line based PPU implementation
- Anti-aliased audio synthesis with support for APU changes per sample (supports Pikachu's voice in Pokemon Yellow/Pokemon Pinball)
