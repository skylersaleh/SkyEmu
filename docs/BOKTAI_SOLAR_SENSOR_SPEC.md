# Real Solar Sensor for Boktai on Android — Implementation Spec

**Target repo:** fork of `skylersaleh/SkyEmu` (branch `dev`)
**Goal:** Drive SkyEmu's existing GBA solar sensor emulation from the Android device's
physical ambient light sensor, so the Boktai games respond to actual sunlight.
**Non-goal:** Writing any emulator internals. The GPIO/ADC emulation already works and is correct.

---

## 0. Context for the agent

SkyEmu already emulates the Boktai cartridge's solar sensor correctly at the hardware level.
It is driven by a manual slider and two hotkeys. This project replaces that input source with
`Sensor.TYPE_LIGHT` readings from the phone, and — separately — corrects the mapping curve so
the in-game sun gauge tracks real light the way the original cartridge did.

Nothing in this project requires modifying the ARM core, PPU, APU, or GPIO state machine.
If you find yourself editing `gba_process_solar_sensor()`, stop and re-read this document.

---

## 1. Setup

```bash
# Fork skylersaleh/SkyEmu on GitHub first, then:
git clone --depth 1 -b dev https://github.com/<YOUR_USER>/SkyEmu.git
cd SkyEmu
git remote add upstream https://github.com/skylersaleh/SkyEmu.git
git checkout -b feature/real-solar-sensor
```

License is MIT, so there are no redistribution obligations beyond keeping the notice.

**Build paths:**
- Android app project: `tools/android_project/`
- CI workflow that produces an APK: `.github/workflows/deploy_android.yml`
  (useful for a first build without a local NDK; too slow for iteration)
- Native desktop build for logic testing: `mkdir build && cd build && cmake .. && cmake --build .`

Develop the mapping math on desktop where you can iterate in seconds. Only move to the
device once the curve is implemented and unit-tested.

---

## 2. How the real hardware worked

Source: GBATEK "GBA Cart Solar Sensor"; chip ID by Drakodan via the TideGear/BoktaiSensor project.

**The sensor:** a Hamamatsu Photonics **G5842** GaAsP photodiode. Spectral range roughly
260–400 nm, centred near 370 nm — i.e. **UV-A dominant**, not visible light. This is the single
most important fact in this document and Section 6 deals with its consequences.

**The ADC:** the cartridge has no real ADC chip. It uses a self-made digital-ramp converter:
a **74LV4040** 12-bit binary counter (only the low 8 bits used), clocked by the CPU over the
GPIO port, feeding a resistor-ladder DAC that produces a linearly rising voltage, compared
against the photodiode output by a **TLV272** comparator.

**The protocol** (already implemented in SkyEmu, listed for understanding only):
- GPIO bit 0 = CLK, bit 1 = RST, bit 2 = chip select, bit 3 = FLG (cart → GBA)
- Game pulses RST to zero the counter, then clocks CLK repeatedly
- FLG goes high when the counter reaches the trip point
- The game counts how many clocks that took — **that count is the sensor reading**

**The reading is inverted.** More light = lower count.

| Condition | Raw 8-bit value |
|---|---|
| Darkness | ~`0xE8` (232) |
| Max sun gauge reached | ~`0x5C`–`0x50` (92–80) |
| Extreme / saturated | `0x00` |

Note from GBATEK: the manual claims the sensor only works in sunlight, but in practice a strong
light source at very close range (a 100 W bulb at 1–2 cm) will drive it. The real cartridge was
*not* perfectly sun-exclusive. Keep this in mind before over-engineering an anti-cheat curve.

---

## 3. How the game converted the reading to bars — VERIFIED

This is the part that was actually reverse-engineered by the Boktai speedrunning community
(Raphi, https://raphi.xyz/~raphi/boktai/sensor_graph/) and is used by TASVideos-accepted runs.

### 3.1 The pipeline

```
photodiode → 8-bit trip count (0xE8 dark … 0x00 blazing)
           → game applies its stored calibration
           → "calibrated value", clamped to 0..140 inclusive
           → threshold table → sun gauge bars
```

The calibration is **game-side, stored in the save file**. It is effectively
`calibrated = dark_baseline - raw_count`, with the baseline established when the sensor is
covered. This is why the standard community advice is *"recalibrate with the sensor blocked
first"* when the gauge misbehaves. Model it as `calibrated = 232 - raw_byte`.

Only `calibrated == 0` yields 0 bars, and only `calibrated == 140` (after clamping) yields max bars.

### 3.2 The threshold table (exclusive upper bounds)

| Bars | Boktai 1 | Boktai 2 & 3 |
|---:|---:|---:|
| 0 | 1 | 1 |
| 1 | 7 | 6 |
| 2 | 16 | 13 |
| 3 | 28 | 23 |
| 4 | 44 | 35 |
| 5 | 67 | 50 |
| 6 | 98 | 67 |
| 7 | 140 | 87 |
| 8 | (max) | 110 |
| 9 | — | 140 |
| 10 | — | (max) |

Read as: you get N bars when `threshold[N-1] <= calibrated < threshold[N]`.

**The curve is geometric, not linear.** Each successive bar needs roughly 1.3–1.5× the light of
the previous one. Bars 0–3 come easily; bar 9→10 requires nearly a third of the entire range.
This is the whole feel of the game and any mapping you build must preserve it.

### 3.3 Cross-check against mGBA (do this, it validates the model)

mGBA's `GBA_LUX_LEVELS[10] = { 5, 11, 18, 27, 42, 62, 84, 109, 139, 183 }`
(`src/gba/cart/gpio.c`), with a base offset of `0x16` and `readLuminance()` returning
`0xFF - luxLevel`.

Running mGBA's 11 levels through `calibrated = 232 - byte` and then the table above:

| mGBA level | byte | calibrated | Boktai 1 bars | Boktai 2/3 bars |
|---:|---:|---:|---:|---:|
| 0 | 0xE9 | 0 | 0 | 0 |
| 1 | 0xE4 | 4 | 1 | 1 |
| 2 | 0xDE | 10 | 2 | 2 |
| 3 | 0xD7 | 17 | 3 | 3 |
| 4 | 0xCE | 26 | **3** | 4 |
| 5 | 0xBF | 41 | 4 | 5 |
| 6 | 0xAB | 61 | 5 | 6 |
| 7 | 0x95 | 83 | 6 | 7 |
| 8 | 0x7C | 108 | 7 | 8 |
| 9 | 0x5E | 138 | **7** | 9 |
| 10 | 0x32 | 182→140 | 8 | 10 |

Perfect 1:1 for Boktai 2/3 — mGBA's table was reverse-engineered to land exactly one value in
each band. **And it independently reproduces the bug in mgba-emu/mgba#523**: on Boktai 1, levels
3 and 4 both give 3 bars, and levels 8 and 9 both give 7 bars, so the gauge appears "stuck".
The root cause is applying a 10-level table designed for the 8-bar game's siblings. Our design
avoids this by computing bars from the calibrated value per-game rather than using fixed levels.

### 3.4 Anchoring to real-world UV

The TideGear/BoktaiSensor project tuned a real UV sensor against a real Boktai 3 cartridge
and landed on: **calibrated 1 at UV Index 1.0, calibrated 140 at UV Index 13.1**, linear between.

That gives `calibrated ≈ 11.5 × UVI − 10.5`, i.e. the calibrated value is **linear in UV
irradiance** while the bar thresholds are geometric. Notable consequence: at UVI 10 (a very
sunny summer noon at mid-latitude) you get about 104 → **8 bars, not 10**. Maxing the gauge
genuinely required exceptional UV. Preserve this; do not "fix" it.

---

## 4. Where SkyEmu's code lives

All paths relative to repo root. Line numbers are from `dev` at time of writing — locate by
symbol, not by line.

| What | Location |
|---|---|
| Sensor state struct `gba_solar_sensor_t` | `src/gba.h` ~797 |
| GPIO state machine `gba_process_solar_sensor()` | `src/gba.h` ~1156 — **do not modify** |
| **Float → byte conversion (the injection point)** | `src/gba.h` ~3767 |
| `float solar_sensor;` in joypad state | `src/sb_types.h` ~123 |
| `SE_KEY_SOLAR_P` / `SE_KEY_SOLAR_M` | `src/sb_types.h` ~101 |
| Hotkey integrator `se_update_solar_sensor()` | `src/main.c` ~4237 |
| Called once per frame | `src/main.c` ~5335 |
| Settings slider | `src/main.c` ~6517 |
| Default value `0.5` | `src/main.c` ~508 |
| **JNI bridge pattern to copy** — `se_android_get_display_dpi_scale()` | `src/main.c` ~4487 |
| Java activity | `tools/android_project/app/src/main/java/com/sky/SkyEmu/EnhancedNativeActivity.java` |
| Manifest | `tools/android_project/app/src/main/AndroidManifest.xml` |
| Localization string table | `src/localization.c` (has "Solar Sensor" entries already) |

Current conversion in `src/gba.h`:

```c
float solar_value = emu->joy.solar_sensor;
if(!(solar_value <1.00))solar_value=1.00;
if(!(solar_value >0.00))solar_value=0.00;
gba->solar_sensor.value = 0xE7-solar_value*(0xE7-0x32);
```

---

## 5. Two bugs in the existing code — fix these first

Fixing these is worth doing on its own and gives you a way to validate your understanding
before any Android work.

**Bug 1: the slider at 0.0 does not give 0 bars.**
`0xE7` = 231, so `calibrated = 232 − 231 = 1`, which lands in the 1-bar band. Minimum should be
`0xE8` (or higher) so calibrated reaches 0. Fix the low end of the range.

**Bug 2: the slider is badly non-linear in the wrong direction.**
Because the byte is linear and the bar thresholds are geometric, the slider is extremely
top-heavy. Measured behaviour on Boktai 2/3:

| Slider | calibrated | bars |
|---:|---:|---:|
| 0.00 | 1 | 1 |
| 0.10 | 19 | 3 |
| 0.25 | 46 | 5 |
| 0.50 | 92 | 8 |
| 0.75 | 137 | 9 |
| 1.00 | 182 | 10 |

Half the slider travel covers bars 8–10. Reframe the slider as **"0.0–1.0 maps linearly onto
calibrated 0–140"**, then `byte = 0xE8 − calibrated`. Same top and bottom, sane middle.

---

## 6. The core design problem: lux is not UV

The phone's `Sensor.TYPE_LIGHT` reports **illuminance in lux** — a photometric, visible-light
measurement weighted to human eye response. The cartridge measured **UV-A irradiance**.
These correlate well outdoors under sunlight and **not at all indoors**, because incandescent
and LED lighting emit essentially no UV-A.

This is a feature, not a problem: it means a lux-based estimate with an indoor floor subtracted
is a decent proxy, and the failure mode (a bright lamp registering as sun) is exactly what the
floor is there to prevent.

### 6.1 Reference light levels

| Condition | Illuminance | Real UVI |
|---|---:|---:|
| Dim indoor room | 50–200 lux | ~0 |
| Bright office / kitchen | 300–800 lux | ~0 |
| Very bright indoor / near window | 1,000–3,000 lux | ~0–0.5 |
| Overcast daylight outdoors | 5,000–20,000 lux | 1–3 |
| Full daylight, shade | 10,000–25,000 lux | 2–5 |
| Direct sun, mid-latitude noon | 60,000–100,000 lux | 6–10 |
| Direct sun, tropics / high altitude | 100,000–130,000 lux | 10–14 |

### 6.2 Mapping (implement this)

```
lux_smoothed = EMA(raw_lux, alpha)
uvi_est      = max(0, (lux_smoothed - LUX_FLOOR) / LUX_PER_UVI)
calibrated   = clamp(round(11.5 * uvi_est - 10.5 + 11.5), 0, 140)   // see note
byte         = 0xE8 - calibrated
```

Note on the constant: TideGear's anchor is `calibrated = 1` at UVI 1.0. Since we already
subtract the indoor floor, apply the linear UVI→calibrated relation directly as
`calibrated = 140 * uvi_est / UVI_SATURATION` with `UVI_SATURATION = 13.1`. That is the same
line, expressed without the double offset. Prefer this form.

Starting constants — **these are guesses and must be tuned on the actual device**:

```c
#define SOLAR_LUX_FLOOR        1500.0f   // below this, calibrated = 0
#define SOLAR_LUX_PER_UVI      9000.0f   // lux per unit of UV index in daylight
#define SOLAR_UVI_SATURATION   13.1f     // UVI at which the gauge maxes
#define SOLAR_EMA_ALPHA        0.15f     // per-sample smoothing
#define SOLAR_BAR_HYSTERESIS   3         // calibrated units of deadband
```

### 6.3 Two-point user calibration (strongly recommended)

Hardcoded constants will be wrong on most devices. Ship a calibration flow that mirrors what
the cartridge itself did:

1. **"Cover the sensor"** → record `lux_dark`, becomes `LUX_FLOOR`
2. **"Point at open sky in full sun"** → record `lux_max`, becomes the saturation point
3. Persist both in SkyEmu's existing settings/config store
4. Linear-interpolate calibrated 0..140 between them

Offer a "Reset to defaults" and expose both raw values in the debug readout.

---

## 7. Critical unknown: measure the ALS ceiling FIRST

Many Android devices clamp `TYPE_LIGHT` reporting at around 10,000 lux; others report
100,000+. If your device clamps at 10k, a saturation point of 100k means you can never exceed
about 1 bar and the entire feature is dead.

**Task zero, before writing any mapping code:** build a throwaway diagnostic that logs
`sensor.getMaximumRange()` plus live lux, and record readings in five conditions —
dark room, lit room, next to a window, outdoor shade, direct sun. Write the numbers into
`docs/solar_sensor_calibration.md` in the fork. Every constant in Section 6 follows from them.

Also note: the ALS sits near the top of the front face, so when you hold the phone to play it
faces up and toward you rather than at the sun. Readings will be lower than a skyward-facing
sensor. Calibrate in the actual playing posture.

---

## 8. Implementation phases

### Phase 0 — Diagnostic (do first)
- Build and run stock SkyEmu on the target device; confirm Boktai boots and the slider moves the gauge
- Log ALS max range and live lux across the five conditions above
- Record results in `docs/solar_sensor_calibration.md`

### Phase 1 — Correct the existing curve (desktop, no Android)
- Add `se_solar_calibrated_to_byte()` and `se_solar_float_to_calibrated()` helpers
- Fix Bugs 1 and 2 from Section 5
- Add a small host-side test (or a `--selftest` path) asserting the Section 3.3 table:
  each of the 11 calibrated reference values must produce the expected Boktai 2/3 bar count
- Verify by hand in-game on desktop before proceeding

### Phase 2 — Java sensor layer
In `EnhancedNativeActivity.java`:
- Fields: `SensorManager`, `Sensor lightSensor`, `volatile float lastLux`, `volatile boolean luxValid`
- Implement `SensorEventListener`; register in `onResume`, unregister in `onPause`
- Public methods callable from JNI:
  - `public float getAmbientLux()` — returns last reading, or `-1.0f` if unavailable
  - `public boolean hasLightSensor()`
  - `public float getLightSensorMaxRange()`
- Use `SENSOR_DELAY_NORMAL`; the game polls infrequently and battery matters
- **No manifest permission is required for `TYPE_LIGHT`.** Do not add one.

### Phase 3 — JNI bridge
In `src/main.c`, copy `se_android_get_display_dpi_scale()` verbatim and adapt:
- `se_android_get_ambient_lux()` → `"getAmbientLux"`, signature `"()F"`
- `se_android_has_light_sensor()` → `"hasLightSensor"`, signature `"()Z"`, `CallBooleanMethod`
- Guard all of it with `#ifdef __ANDROID__` and provide no-op stubs returning `-1.0f` / `false`
  for desktop, iOS, web, and libretro builds so nothing else breaks

### Phase 4 — Wire it up
- Add `bool solar_use_light_sensor` plus calibration floats to the persisted settings struct
- In `se_update_solar_sensor()`: if the toggle is on and the sensor is present, compute from lux;
  otherwise fall through to the existing hotkey/slider path unchanged
- Apply EMA smoothing and hysteresis in the C layer, not Java
- Never let sensor mode silently override a user who is dragging the slider

### Phase 5 — UI
- Toggle: "Use device light sensor" in the existing settings panel, near the solar slider
- Grey it out with an explanatory line when `hasLightSensor()` is false
- Debug readout (can be behind an "advanced" flag): raw lux, smoothed lux, estimated UVI,
  calibrated 0–140, resulting byte, and inferred bar count
- Calibration flow from Section 6.3
- Add new UI strings to `src/localization.c` following the existing "Solar Sensor" entries
  (English only is fine; leave other languages as the English fallback)

### Phase 6 — Tune outdoors
Take the phone outside with all three games. Adjust `LUX_FLOOR`, saturation, and smoothing
until stepping into shade visibly drains the gauge and direct sun charges it within a few
seconds. Log final values in `docs/solar_sensor_calibration.md`.

---

## 9. Test plan

**Unit / desktop:**
- Each of the 11 reference calibrated values from Section 3.3 → correct Boktai 2/3 bar count
- Slider 0.0 → calibrated 0 → 0 bars (regression test for Bug 1)
- Slider 1.0 → calibrated 140 → max bars
- `lux < LUX_FLOOR` → calibrated 0 for any floor value
- Monotonicity: increasing lux never decreases calibrated

**On-device, in-game (all three titles):**
- Dark room → gauge empty, sunlight-gated abilities unusable
- Bright indoor room under a lamp → gauge stays at 0 or 1 bar (this is the acceptance test
  for the whole feature)
- Outdoor shade → mid-range bars
- Direct sun → high bars, ideally 8+
- Cover the sensor with a thumb mid-game → gauge drains within ~2 s
- Background the app and return → sensor re-registers, no stale reading, no crash
- Toggle sensor mode off mid-game → slider resumes control cleanly
- Save state / load state → no sensor-related corruption
- **Boktai 1 specifically:** sweep slowly through the full range and confirm all 9 gauge states
  (0–8 bars) are reachable with no stuck values — this is the mgba#523 regression test

**Devices without an ALS:** confirm graceful fallback, no crash, toggle disabled with explanation.

---

## 10. Traps

- **Do not apply Prof9's solar sensor patches to the ROM.** They exist to remove the sensor
  dependency. Use clean No-Intro dumps.
- **Do not modify `gba_process_solar_sensor()`.** The GPIO state machine is correct.
- **Beware integer overflow in the naive cube-root mapping.** mGBA's Switch port uses
  `luxLevel = cbrtf(lux) * 8` into a `uint8_t`, which overflows above ~32,768 lux. Don't copy
  that pattern. Clamp before narrowing.
- **Boktai 1 has 8 bars, Boktai 2 and 3 have 10.** Do not hardcode a level count.
- The GBA runs at 59.7275 Hz; don't tie sensor sampling to frame count. Use wall-clock time,
  as the existing `se_update_solar_sensor()` already does with `se_time()`.
- Java `getAmbientLux()` is called from the emulator thread. Keep `lastLux` `volatile`.
  Do not allocate or take locks in the JNI path.
- SkyEmu builds for seven platforms. Every `__ANDROID__` block needs a working stub elsewhere.

---

## 11. Optional stretch: actual UV via the camera

The honest ceiling of the lux approach is that it cannot distinguish a very bright artificial
source from sunlight. If Phase 6 shows this matters in practice, the rear camera's white
balance metadata gives colour temperature, and daylight sits around 5,500–6,500 K where
household bulbs do not. Gate the lux reading on a plausible daylight colour temperature.

Cost: a camera permission, meaningful battery drain, and significant complexity. Only pursue
this if the simple version genuinely disappoints. Note also that the real cartridge could be
fooled by a bulb at close range, so perfect discrimination is arguably *less* authentic.

---

## 12. Upstreaming

`mgba-emu/mgba#2524` is an open request for exactly this feature. If the SkyEmu implementation
works well, it is a strong candidate for an upstream PR to SkyEmu, and the mapping tables in
Section 3 are directly reusable by mGBA. Keep the calibration constants in one header and the
mapping functions free of Android dependencies to make that easy.

---

## 13. References

| Source | URL |
|---|---|
| Reverse-engineered bar thresholds (primary source) | https://raphi.xyz/~raphi/boktai/sensor_graph/ |
| GBATEK — GBA Cart Solar Sensor | http://problemkaputt.de/gbatek-gba-cart-solar-sensor.htm |
| GBATEK — GBA Cart I/O Port (GPIO) | http://problemkaputt.de/gbatek-gba-cart-i-o-port-gpio.htm |
| TideGear/BoktaiSensor — real UV sensor hardware, chip ID, UVI anchors | https://github.com/TideGear/BoktaiSensor |
| mGBA `GBA_LUX_LEVELS` table | `src/gba/cart/gpio.c` in https://github.com/mgba-emu/mgba |
| mGBA #523 — Boktai 1 8-bar vs 10-level bug | https://github.com/mgba-emu/mgba/issues/523 |
| mGBA #2524 — ambient light sensor feature request | https://github.com/mgba-emu/mgba/issues/2524 |
| Prof9 solar sensor patches (reference only — do not apply) | https://github.com/Prof9/Boktai-Solar-Sensor-Patches |
| Android `Sensor.TYPE_LIGHT` | https://developer.android.com/reference/android/hardware/Sensor#TYPE_LIGHT |

Sensor chip: Hamamatsu Photonics G5842, GaAsP photodiode, ~260–400 nm, peak ~370 nm.
Counter: 74LV4040 12-bit binary counter (low 8 bits used). Comparator: TLV272.
