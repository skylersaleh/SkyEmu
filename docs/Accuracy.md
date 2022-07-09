
# Accuracy on Difficult to Emulate Games

Testname                                                | SkyEmu 1.0  | NanoBoyAdvance 1.5                                 | mGBA 0.9.3 | VBA-M 2.1.4 | Notes
--------------------------------------------------------|-------------|----------------------------------------------------|------------|-------------|------
AGS Aging Cartridge                                     | Pass        | Pass                                               | [Fail](accuracy_screenshots/mGBA/AGS.png)           | [Fail](accuracy_screenshots/VBA-M/AGS.png) | MGBA/VBA-M Do not pass all tests
Classic NES Series - The Legend of Zelda (USA, Europe)  | Pass        | Pass                                               | Pass                                                | Pass | 
Digimon Racing (Europe)                                 | [Fail](accuracy_screenshots/SkyEmu/digimon.png) | Pass           | Pass                                                | [Fail](accuracy_screenshots/VBA-M/digimon.png) | SkyEmu has rendering corruption. VBA-M locks up before title screen.
Hello Kitty Collection - Miracle Fashion Maker (Japan)  | Pass        | Pass                                               | Pass                                                | [Fail](accuracy_screenshots/VBA-M/hello-kitty.png) | VBA-M fails to boot.
Iridion 3D                                              | Pass        | [Fail](accuracy_screenshots/NBA/Iridion.png)       | [Fail](accuracy_screenshots/mGBA/Iridion.png)       | [Fail](accuracy_screenshots/VBA-M/Iridion.png) | NBA/mGBA/VBA-M have rendering corruption
James Pond - Codename Robocod                           | Pass        | Pass                                               | Pass                                                | Pass | 
Lufia - The Ruins of Lore (USA)                         | Pass        | Pass                                               | Pass                                                | [Fail](accuracy_screenshots/VBA-M/Lufia.png) | VBA-M has rendering corruption
Pinball Tycoon                                          | Fail        | Pass                                               | Pass                                                | [Fail](accuracy_screenshots/VBA-M/PinballTycoon.png) | SkyEmu has choppy audio. VBA-M has rendering corruption.
Sennen Kazoku                                           | Pass        | Pass ([staging build only](https://github.com/nba-emu/NanoBoyAdvance/commit/7e09229fc441aa730883b5567d9ee9944c9aac0a))        | Pass                                                | [Fail](accuracy_screenshots/VBA-M/Sennen.png) | VBA-M fail to boot
Star Wars - Episode II - Attack of the Clones (USA)     | Pass        | [Fail](accuracy_screenshots/NBA/StarWars.png)      | [Fail](accuracy_screenshots/mGBA/StarWars.png)      | [Fail](accuracy_screenshots/VBA-M/StarWars.png) | NBA/mGBA/VBA-M have rendering corruption
**Games Passed / Total Games**                          | 8/10        | 8/10                                               | 7/10                                                | 2/10     
------------------------------------------------------------------------------------------------------------------

# Accuracy on Test Roms

Testname                                              | SkyEmu 1.0  | NanoBoyAdvance 1.5  | mGBA 0.9.3         | VBA-M 2.1.4 |
------------------------------------------------------|-------------|---------------------|--------------------|-------------|
GBA Suite Memory                                      | Pass        | Pass                | Pass               | Fail (1338/1552) | 
GBA Suite IO                                          | Pass        | Pass                | Fail (114/123)     | Fail (100/123)   | 
GBA Suite Timing                                      | Pass        | Pass                | Fail (1708/2020)   | Fail (751/2020)  | 
GBA Suite DMA                                         | Pass        | Pass                | Fail (1232/1256)   | Fail (1032/1256) | 
Armwrestler                                           | Pass        | Pass                | Pass               | Pass | 
FuzzArm                                               | Pass        | Pass                | Pass               | Pass | 
------------------------------------------------------------------------------------------------------------------