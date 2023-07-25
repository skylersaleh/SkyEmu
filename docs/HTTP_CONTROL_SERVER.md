# HTTP Control Server

SkyEmu contains a web server that implements a REST-like API that can be used to control SkyEmu from other programs and scripts.

This interface provides access to the following functionality:
- Loading arbitrary ROM files
- Retrieving the emulated screen's image
- Reading/Writing arbitrary memory addresses in the emulated system
- Stepping the emulator a controlled number of frames
- Controlling user inputs for the emulator and emulated console

To enable the server check the "Enable HTTP Control Server" option in the advanced settings and configure the port. 

Additionally, SkyEmu can be launched in a mode optimized for headless display using the following commandline parameters:

``` ./SkyEmu http_server <Server Port> <Path To ROM file> ```

When running using these parameters, SkyEmu won't render the UI and will run without sleeping to synchronize with real time. 

# Overview of API commands

A description of each of the supported API commands is shown below. You can test each command using a standard web browser by visiting a link like below:

```http://localhost:<port>/cmd?Param=Value```

# /ping command
Returns the word 'pong' used to check if the server is up. 

**Example:**

```http://localhost:8080/ping```

**Result:**

```pong```

# /step command

Steps the emulator forward one or more frames. A frames parameter can be optionally provided to step the emulator a fixed number of frames.
Otherwise, the emulator steps a single frame. Returns "ok" on completion. 

**Example:**

```http://localhost:8080/step```

**Result:**

The emulator is stepped ahead 1 frame. 

```ok```

**Example:**

```http://localhost:8080/step?frames=100```

**Result:**

The emulator is stepped ahead 100 frames. 

```ok```

# /run command

The emulator is un-paused and runs at 1x speed. Returns "ok" on completion. 

**Example:**

```http://localhost:8080/run```

**Result:**

The emulator is playing at 1x speed. 

```ok```

# /screen command

Returns a png image of the current screen of the emulated system. The parameter embed_state can be set to 1 to embed the emulation save state similar to the /save commands output on emulators that support it (ie. SkyEmu). The default keeps embed_state set to 0. 

The paramater format specifies which image format to use. It can be set to png, jpg, or bmp. If not specified, png is used by default. 

**Example:**

```http://localhost:8080/screen```

**Result:**

```<png image of screen>```

**Example:**

```http://localhost:8080/screen?format=jpg```

**Result:**

```<jpg image of screen>```

**Example:**

```http://localhost:8080/screen?embed_state=1```

**Result:**

```<much larger png image of screen with save state embedded>```

# /read_byte command

Reads one or multiple bytes of data from the emulated system at addresses provided using parameters. The addr parameter can be repeated an arbitrary amount of times to read an arbitrary amount of bytes. 

The paramater map can be used to specify different address maps. This is currently only used in the NDS core where address map 7 is used for the ARM7 address map and 0 and 9 are used for the ARM9 address map. The default address map is 0. The map command only effects bytes read after the parameter and does not persist across API calls. 

**Example (Read a single byte):**

```http://localhost:8080/read_byte?addr=02000004```

**Result:**

1 byte of data is returned in hexadecimal

```f0```

**Example (Read multiple bytes):**

```http://localhost:8080/read_byte?addr=02000004&addr=02000005&addr=02000006```

**Result:**

3 bytes of data are returned in hexadecimal (in the order mem[0x02000004], mem[0x02000005], mem[0x02000006])

```f0bf01```

**Example (Read multiple bytes from different address spaces ):**

```http://localhost:8080/read_byte?addr=02000004&map=7&addr=02000005&addr=02000006```

**Result:**

3 bytes of data are returned in hexadecimal (in the order mem_map0[0x02000004], mem_map7[0x02000005], mem_map7[0x02000006] of map 7)

```f0bf01```

# /write_byte command

Writes one or multiple bytes of data from the emulated system at addresses provided using parameters. Multiple addresses can be written to in a single command. Returns "ok" on completion

The paramater map can be used to specify different address maps. This is currently only used in the NDS core where address map 7 is used for the ARM7 address map and 0 and 9 are used for the ARM9 address map. The default address map is 0. The map command only effects bytes read after the parameter and does not persist across API calls. 

**Example (Write a single byte):**

```http://localhost:8080/write_byte?02000000=ff```

**Result:**

mem[0x02000000] = 0xff; 

```okay```

**Example (Write multiple bytes):**

```http://localhost:8080/write_byte?02000000=ff&02000001=ee&02000002=cc```

**Result:**

mem[0x02000000] = 0xff; 

mem[0x02000001] = 0xee; 

mem[0x02000002] = 0xcc; 

```ok```

**Example (Write multiple bytes from different maps ):**

```http://localhost:8080/write_byte?02000000=ff&map=7&02000001=ee&02000002=cc```

**Result:**

mem_map0[0x02000000] = 0xff; 

mem_map7[0x02000001] = 0xee; 

mem_map7[0x02000002] = 0xcc; 

```ok```

# /input command

Sends an input to the emulated system which will stay until a different input command assigns a new value. The parameters specify the input to set and the value to set it to. In general all inputs that have keybinds in the GUI can be set using this command. A full list of the valid input names and their current state is viewable with the /status command. An arbitrary number of inputs can be set using this command. Returns "ok" on completion. 

**Example (Sends a sequence of commands)**

All buttons start released. 

```http://localhost:8080/input?A=1&Up=1```

A and Up are now being pressed. 

```http://localhost:8080/input?B=1&Up=0```

A and B are now being pressed (and Up was released)

```http://localhost:8080/input?B=0```

A is being pressed (and B was released)

```http://localhost:8080/input?A=0```

No button is being pressed (A was released)

```http://localhost:8080/input?A=0```

*Example (Send a special command to capture a save state slot)*

```http://localhost:8080/input?Capture State 0=1```

Hot key for capturing save state 0 is being pressed. 

```http://localhost:8080/step```

Emulation is stepped, completing the capture into save state 1

```http://localhost:8080/input?Capture State 0=0```

Hot key is released.

# /status command

Returns info about the current state of the emulator and the state of the HTTP Control Server Inputs that are being fed into the emulator. 

**Example**

```http://localhost:8080/status```

**Result:**

```
SkyEmu (737bc7722193891cd6aa375f0a6fcdb183476356)
MODE: PAUSE
ROM Loaded: true
ROM Path: /Users/skylersaleh/Documents/roms/gba/Pokemon - Emerald Version (U).gba
Save Path: /Users/skylersaleh/Documents/roms/gba/Pokemon - Emerald Version (U).sav
Inputs: 
- A: 1.000000
- B: 0.000000
- X: 0.000000
- Y: 0.000000
- Up: 1.000000
- Down: 0.000000
- Left: 0.000000
- Right: 0.000000
- L: 0.000000
- R: 0.000000
- Start: 0.000000
- Select: 0.000000
- Fold Screen (NDS): 0.000000
- Tap Screen (NDS): 0.000000
- Emulator ïŒ/ï‹: 0.000000
- Emulator ïŠ: 0.000000
- Emulator ïŽ: 0.000000
- Emulator ï: 0.000000
- Capture State 0: 1.000000
- Restore State 0: 0.000000
- Capture State 1: 0.000000
- Restore State 1: 0.000000
- Capture State 2: 0.000000
- Restore State 2: 0.000000
- Capture State 3: 0.000000
- Restore State 3: 0.000000
- Reset Game: 0.000000
- Turbo A: 0.000000
- Turbo B: 0.000000
- Turbo X: 0.000000
- Turbo Y: 0.000000
- Turbo L: 0.000000
- Turbo R: 0.000000
- Solar Sensor+: 0.000000
- Solar Sensor-: 0.000000
- Toggle Full Screen: 0.000000
```

# /save command

Saves a save state to a parameter specified "path" on the server.  Returns "ok" on success and "failed" on error. 

**Example**

```http://localhost:8080/save?path=/tmp/save.png```

**Result:**

A save state is created on the server in /tmp/save.png

```ok```

# /load command

Loads a save state from a parameter specified "path" on the server.  Returns "ok" on success and "failed" on error. 

**Example**

```http://localhost:8080/load?path=/tmp/save.png```

**Result:**

The state of the emulator is restored to where it was at the time the /tmp/save.png save state was taken. 

```ok```

# /load_rom command

Loads a rom from a parameter specified "path" on the server. Can be initially paused by setting the "pause" parameter. Returns "ok" on success.

**Example**

```http://localhost:8080/load?path=/tmp/rom.gba&pause=1```

**Result:**

Loads the rom at /tmp/rom.gba and pauses the emulator.

```ok```

# /cheats command

Lists the current cheats and their status

**Example**
```http://localhost:8080/cheats```

**Result:**

```
0 - My first cheat: 12345678 AABBCCDD (enabled)
1 - My second cheat: 12345678 90ABCDEF (disabled)
```