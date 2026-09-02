# Boktai Solar Sensor — Device Calibration Log

This file is the on-device companion to `src/se_solar_sensor.h`. Fill in the
tables as you run the diagnostic (spec Phase 0) and tune outdoors (Phase 6).
Every lux constant in the light-sensor path is derived from the numbers here.

## 1. Ambient Light Sensor (ALS) ceiling — measure FIRST

Many Android devices clamp `Sensor.TYPE_LIGHT` at ~10,000 lux; others report
100,000+. If yours clamps at 10k, a 100k saturation point means you can never
exceed ~1 bar and the feature is dead. Measure before writing any mapping code.

- Device: _`<model>`_
- `sensor.getMaximumRange()`: _`<lux>`_ — **read this from the debug readout line
  ending `sensor ceiling ... lux`.** If it comes back as a suspiciously round
  100000 or 65535, that is a driver clamp, and saturation must be set below it.
- ALS location on device (front-top is typical; it faces up/toward you while playing): _`<notes>`_

### Observed so far (Boktai 1, Los Angeles, September)

With the shipped defaults (floor 1500, saturation 119400) the gauge pinned at
**7 of 8 bars** with the phone held flat and unshadowed in direct sun. Working
backwards through the Boktai 1 ladder, 7 bars means calibrated landed in
[98,139], i.e. the ALS was reporting roughly **84,000–118,000 lux**. So the
sensor is reporting real, uncapped sunlight — there is no 10k clamp on this
device. The gauge could not fill because 119,400 lux (the UVI 13.1 anchor, which
was tuned for a UV sensor aimed at open tropical sky) is not reachable at 34°N,
and because Boktai's top bar requires calibrated to hit exactly 140.

**Posture matters and must be recorded separately.** Laid flat and unshadowed is
not how the game is played: held normally the screen tilts toward your face, your
head shades the top bezel, and illuminance falls off with the cosine of the angle
to the sun. A 40–60% drop between the two postures is normal. Calibrate against
the *playing* posture — the original cartridge's sensor sat proud of the GBA's
top edge pointing up and away from the player, so compensating for the phone's
worse geometry restores parity rather than making the game easier.

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
| `SOLAR_SATURATION_HEADROOM` | 0.85 | |

### Why saturation needs headroom

Boktai's top bar is a **clamp-only state**: after clamping, only calibrated == 140
reports max bars. If saturation equals the brightest lux ever measured, calibrated
touches 140 at exactly one input value, so the top bar is unreachable in practice
and oscillates against the hysteresis deadband. Setting saturation to ~0.85x the
observed playing-posture peak creates a plateau you can sit on — which is what the
cartridge did, since its UV photodiode saturated hard and stayed pinned.

The `Set full sun` button now applies this factor automatically and samples the
smoothed lux rather than a raw instantaneous spike.

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
