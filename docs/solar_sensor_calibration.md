# Boktai Solar Sensor — Device Calibration Log

This file is the on-device companion to `src/se_solar_sensor.h`. Fill in the
tables as you run the diagnostic (spec Phase 0) and tune outdoors (Phase 6).
Every lux constant in the light-sensor path is derived from the numbers here.

## 1. Ambient Light Sensor (ALS) ceiling — measure FIRST

Many Android devices clamp `Sensor.TYPE_LIGHT` at ~10,000 lux; others report
100,000+. If yours clamps at 10k, a 100k saturation point means you can never
exceed ~1 bar and the feature is dead. Measure before writing any mapping code.

- Device: _`<model>`_
- `sensor.getMaximumRange()`: _`<lux>`_
- ALS location on device (front-top is typical; it faces up/toward you while playing): _`<notes>`_

## 2. Live lux in five conditions

Hold the phone in the actual playing posture (screen toward you), not sensor-to-sky.

| Condition | Measured lux | Notes |
|---|---:|---|
| Dark room (sensor covered) | | this becomes `LUX_FLOOR` |
| Lit indoor room | | should stay at 0–1 bar |
| Next to a window | | |
| Outdoor shade | | target: mid-range bars |
| Direct sun | | target: 8+ bars; becomes saturation point |

## 3. Tuned constants (Phase 6)

Starting guesses live in `src/se_solar_sensor.h` (added in Phase 4). Record the
final tuned values here once stepping into shade visibly drains the gauge and
direct sun charges it within a few seconds.

| Constant | Default | Tuned |
|---|---:|---:|
| `SOLAR_LUX_FLOOR` | 1500 | |
| `SOLAR_LUX_PER_UVI` | 9000 | |
| `SOLAR_UVI_SATURATION` | 13.1 | |
| `SOLAR_EMA_ALPHA` | 0.15 | |
| `SOLAR_BAR_HYSTERESIS` | 3 | |

## 4. Two-point user calibration results (optional)

If using the in-app "cover the sensor" / "point at open sky" flow, record the
captured raw values for reference:

- `lux_dark`: _____
- `lux_max`: _____

---

## Reference: verified mapping (already implemented, spec §3)

The calibrated → bars mapping below is fixed hardware/game behavior and is unit
tested in `tests/solar_sensor_selftest.c`. It does not need device tuning; only
the lux → calibrated estimate does.

- calibrated = 232 − trip_byte, clamped 0..140
- Boktai 1 bar thresholds (excl. upper bounds): 1, 7, 16, 28, 44, 67, 98, 140 (8 bars)
- Boktai 2 & 3 bar thresholds: 1, 6, 13, 23, 35, 50, 67, 87, 110, 140 (10 bars)
- Anchor: calibrated 1 at UVI 1.0, calibrated 140 at UVI 13.1 (linear in UV)
