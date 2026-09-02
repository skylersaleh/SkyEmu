# Testing the Boktai Real Solar Sensor

How to build/install this fork on an Android phone and verify the light-sensor
feature with the actual games. Desktop builds are for the unit test only — the
sensor feature is Android-only.

> **ROMs:** use clean **No-Intro** dumps of Boktai 1/2/3. **Do NOT** apply Prof9's
> solar-sensor patches — those *remove* the sensor dependency and would defeat the
> whole test (spec §10). Bring your own legally-dumped ROMs.

---

## 1. Get the app

### Option A — download the APK from CI (no toolchain needed)
Every push to the branch builds an Android APK as a CI artifact.

```bash
gh run list --branch feature/real-solar-sensor --workflow "Build Android"
gh run download <run-id> -n AndroidRelease
```

That drops `com.sky.SkyEmu-*-release.apk` in the current folder.

> If the **release** APK refuses to install (unsigned), build a debug APK locally
> instead (Option B with `assembleDebug`) — debug APKs are always self-signed.

### Option B — build locally
Needs Android SDK + NDK (Android Studio, or command-line tools) and JDK 17.

```bash
cd tools/android_project
./gradlew assembleDebug     # -> app/build/outputs/apk/debug/*.apk  (installable)
# or ./gradlew assembleRelease for the CI-style build
```

## 2. Install & launch
```bash
adb install -r com.sky.SkyEmu-*.apk
```
Or copy the APK to the phone and tap it (allow "install from unknown sources").
Launch SkyEmu; confirm it boots to the menu.

## 3. Load a Boktai ROM
Menu → open file → pick your `.gba`. Let it get to the in-game sun gauge (the
bars at the top of the screen). Booting each of the three games at least once is
worth it — Boktai 1 has 8 bars, Boktai 2 & 3 have 10.

---

## 4. Smoke test — the slider fix (Phase 1, works on any build)
Settings → **Advanced → Solar Sensor** slider.

- Drag it fully **down** → the in-game gauge should read **empty (0 bars)**. (Before this fix it stuck at 1 bar — that's the bug we fixed.)
- Drag it up slowly → bars fill, geometrically (early bars easy, top bars need lots).
- **Boktai 1 specifically:** sweep slowly end-to-end and confirm **all 9 states (0–8 bars)** appear with none stuck/skipped (the mgba#523 regression).

## 5. Turn on the light sensor (Phases 2–5)
Settings → Advanced → **"Use device light sensor"**.

- If the phone has no ALS you'll see *"No ambient light sensor on this device…"* and the slider stays in charge. (Most phones have one.)
- Enable **"Show Debug Tools"** (same Advanced page) to reveal a live readout under the toggle:
  `lux raw/smooth/UVI`, `calibrated 0–140`, `byte`, `bars (B1)/(B2-3)`, and `[active]/[waiting]`.

### Calibrate (do this once, in your normal playing posture)
Three buttons appear under **Light Calibration**:

1. **Set dark** — cover the sensor (top-front of the phone) with a thumb, then tap. Records your indoor/dark floor.
2. **Set full sun** — outdoors, point the phone at open sky in full sun, then tap. Records the "gauge full" point.
3. **Reset** — restores the built-in defaults.

Calibration persists in settings. Recalibrating with the sensor covered first is the same trick the real cartridge used.

---

## 6. Acceptance test plan (spec §9 — do on all three games)

| Test | Expected |
|---|---|
| Dark room | gauge empty; sunlight-gated abilities unusable |
| **Bright indoor room under a lamp** | **gauge stays at 0–1 bar** — this is the key acceptance test (lux ≠ UV; a bulb must not read as sun) |
| Outdoor shade | mid-range bars |
| Direct sun | high bars, ideally 8+ |
| Cover the sensor with a thumb mid-game | gauge drains within ~2 s |
| Background the app and return | sensor re-registers, no stale reading, no crash |
| Toggle sensor mode off mid-game | slider resumes control cleanly |
| Save state / load state | no sensor-related corruption |

If direct sun can't get past ~1 bar, your device's ALS likely **clamps low** (some
cap at ~10,000 lux). Check the `sensor ceiling` value in the debug readout and, if
low, lower `Set full sun` accordingly (or see Phase 0 in the calibration doc).

## 7. Record results & tune
Write your ALS ceiling, the five-condition lux readings, and final tuned numbers
into `docs/solar_sensor_calibration.md`. If the feel is off, adjust the constants
in `src/se_solar_sensor.h` (`SOLAR_LUX_FLOOR`, saturation, `SOLAR_EMA_ALPHA`,
`SOLAR_BAR_HYSTERESIS`), push, and re-test.

## 8. Troubleshooting
- **Gauge never moves in sensor mode:** confirm the toggle is on and the debug readout shows `[active]` with a non-zero `lux smooth`. `[waiting]` means no reading yet — give it a second after resume.
- **Gauge maxes indoors:** floor set too high or saturation too low — recalibrate, "Set dark" indoors.
- **Release APK won't install:** use a debug build (§1 Option B).
- **Gauge behaves like it's stuck:** in-game, recalibrate the game's own sensor with the phone sensor covered (Boktai's built-in calibration), then retry.
