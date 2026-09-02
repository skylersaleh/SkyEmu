# Boktai Real Solar Sensor — Implementation Log

Living status doc for the "drive SkyEmu's GBA solar sensor from the phone's
ambient light sensor" feature. **If you are a fresh Claude Code instance picking
this up, read this file first, then `BOKTAI_SOLAR_SENSOR_SPEC.md` (the design
spec this work follows).** Update the status table and the log as you go.

- **Repo/branch:** `anujyadav140/SkyEmu-Sun`, branch `feature/real-solar-sensor` (forked from `skylersaleh/SkyEmu` `dev`).
- **Validation:** this dev machine has **no C toolchain** (no gcc/clang/cl/cmake, no WSL; only Node.js). We validate by **pushing and reading GitHub Actions** — every workflow triggers on `push`, building all seven platforms + libretro, and a dedicated `Test Solar Sensor` job compiles and runs the unit test. Read results with `gh run list --branch feature/real-solar-sensor` and `gh run view <id> --log-failed`.
- **Golden rule (spec §10):** do **not** touch `gba_process_solar_sensor()` — the GPIO/ADC state machine is correct. We only change the *input source* and the *float→byte mapping*.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | On-device ALS diagnostic (measure lux ceiling + 5 conditions) | ⬜ **needs device** — template in `docs/solar_sensor_calibration.md` |
| 1 | Fix slider curve; pure mapping header + self-test | ✅ done, **self-test green in CI** |
| 2 | Java `Sensor.TYPE_LIGHT` layer + 3 JNI getters | ✅ done (Android build compiles it) |
| 3 | JNI bridge in `main.c` (+ non-Android stubs) | ✅ done |
| 4 | Persisted settings + wire-up in `se_update_solar_sensor` (EMA + hysteresis) | ✅ done |
| 5 | Settings UI: toggle, 2-point calibration, debug readout | ✅ done |
| 6 | Outdoor tuning of the lux constants | ⬜ **needs device** |

"needs device" = only the user can do it (physical phone + Boktai carts/ROMs). All code phases are implemented; what remains is real-world calibration and the in-game acceptance tests in `docs/testing_boktai_solar_sensor.md`.

## File map (what changed and why)

| File | Role |
|---|---|
| `src/se_solar_sensor.h` | **The whole mapping, dependency-free.** Constants + `float↔calibrated↔byte`, the per-game bar threshold tables, and `lux→calibrated`. No Android/emulator deps so it unit-tests on desktop and is upstream-friendly (spec §12). |
| `src/gba.h` | Includes the header; `gba_tick()` now sets `solar_sensor.value = se_solar_float_to_byte(joy.solar_sensor)`. GPIO state machine untouched. |
| `tests/solar_sensor_selftest.c` | Standalone unit test: §3.3 reference table (both games, incl. mgba#523 stuck-bar points), bug-1/bug-2 regressions, monotonicity, reachability, and the lux mapping. |
| `.github/workflows/test_solar_sensor.yml` | CI job that compiles + runs the self-test on every push. |
| `tools/.../EnhancedNativeActivity.java` | `implements SensorEventListener`; samples `TYPE_LIGHT`, registers in `onResume`/unregisters in `onPause`; exposes `getAmbientLux()`, `hasLightSensor()`, `getLightSensorMaxRange()`. No manifest permission needed. |
| `src/main.c` | JNI bridge (`se_android_get_ambient_lux` etc. + non-Android stubs); `persistent_settings_t` gains `solar_use_light_sensor` / `solar_lux_floor` / `solar_lux_saturation`; settings version bumped 3→4; `se_solar_runtime_t` telemetry; `se_update_solar_sensor()` rewritten with poll-throttle + EMA + hysteresis; settings UI toggle + calibration + debug readout. |
| `docs/solar_sensor_calibration.md` | On-device calibration log (Phase 0 / Phase 6). |
| `docs/testing_boktai_solar_sensor.md` | How to build/install/test the fork and the games. |

## Key decisions & deviations from the spec (read before editing)

1. **Guard macro is `SE_PLATFORM_ANDROID`, not `__ANDROID__`.** The spec says `#ifdef __ANDROID__`; the actual codebase uses `SE_PLATFORM_ANDROID` everywhere. We follow the codebase. All JNI code is guarded with it, with `static inline` no-op stubs for the other six platforms so everything links.
2. **Calibration is stored as two lux points** (`solar_lux_floor`, `solar_lux_saturation`), not as separate `LUX_PER_UVI`/`UVI_SATURATION` fields. This is algebraically the spec §6.2 line (`lux_saturation == floor + LUX_PER_UVI*UVI_SATURATION`) and maps directly onto the two-point calibration flow (§6.3). `SOLAR_EMA_ALPHA` and `SOLAR_BAR_HYSTERESIS` stay compile-time constants.
3. **Localization untouched.** `se_localize()` returns the input string on a miss, so new English UI strings render via fallback. Editing ~24 language tables was judged not worth it (spec explicitly allows "English only"). If translations are wanted later, add pairs in `src/localization.c`.
4. **`solar_sensor` normalized value is the single channel.** Sensor mode writes `joy.solar_sensor = calibrated/140`; `gba_tick()` maps it back through the same range, so it round-trips to the exact byte. Hotkeys still override in sensor mode; the settings slider is the manual fallback when the toggle is off.
5. **Defaults are guesses.** `SOLAR_LUX_FLOOR=1500`, saturation ≈119400 lux. These MUST be tuned on-device (Phase 0/6). The in-app 2-point calibration is the real path.

## Verified vs unverified

- ✅ **Verified in CI:** the mapping math (self-test green — real C compiled by gcc + all assertions pass), and cross-platform compilation of the C changes (desktop + libretro; Android build compiles the Java + JNI).
- ⬜ **Unverified (needs device):** actual lux readings, the ALS ceiling, in-game gauge behavior, calibration feel, background/resume, save-state interaction. See the testing guide.

## How to continue

- Watch CI after any push; fix `gh run view <id> --log-failed` before moving on.
- For device work, follow `docs/testing_boktai_solar_sensor.md`, then record numbers in `docs/solar_sensor_calibration.md` and tune the constants in `src/se_solar_sensor.h`.
- Upstreaming (spec §12): the mapping header + tables are reusable by mGBA and are a candidate SkyEmu PR. Keep constants in the one header and mapping functions free of Android deps (already the case).

## Changelog

- Phase 1 — commit `541dc88`: curve fix, mapping header, self-test, CI job, calibration doc.
- Phase 2 — commit `de0adcf`: Android light-sensor Java layer.
- Phases 3–5 — this batch: JNI bridge + stubs, settings persistence + wire-up (EMA/hysteresis), settings UI, lux mapping + tests, these two docs.
