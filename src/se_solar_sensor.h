#ifndef SE_SOLAR_SENSOR_H
#define SE_SOLAR_SENSOR_H 1
/*
  Boktai solar-sensor mapping -- pure, platform-independent.

  This header is intentionally free of Android / emulator dependencies so it can
  be unit-tested on the desktop and shared with an upstream PR (see spec S12).
  It does NOT touch the GPIO/ADC state machine (gba_process_solar_sensor()); it
  only produces the 8-bit trip count that state machine already consumes.

  Model (spec S2-3):
    - The cartridge reports an INVERTED 8-bit trip count: ~0xE8 in darkness,
      decreasing as light increases.
    - The game computes  calibrated = 232 - byte,  clamped to 0..140.
    - "calibrated" maps to sun-gauge bars through a GEOMETRIC threshold table
      (below). Boktai 1 has 8 bars; Boktai 2 & 3 have 10.

  Because the bar thresholds are geometric but the byte is linear, anything that
  wants a perceptually even control (the settings slider today, the phone light
  sensor later) must work in "calibrated" units, not raw bytes. That is the whole
  reason these helpers exist.
*/

/* Trip count written under full cover -> game calibrated == 0 (empty gauge). */
#define SE_SOLAR_DARK_BYTE       0xE8   /* 232 */
/* calibrated value that fills the gauge (both games clamp here). */
#define SE_SOLAR_CALIBRATED_MAX  140

/* Normalized brightness [0,1] -> calibrated [0,140], LINEAR.
   Fixes spec Bug 2: the old path was linear in the byte, which made the slider
   wildly top-heavy (half its travel covered bars 8-10). */
static inline int se_solar_float_to_calibrated(float norm){
  if(norm<0.0f) norm=0.0f;
  if(norm>1.0f) norm=1.0f;
  int calibrated = (int)(norm*(float)SE_SOLAR_CALIBRATED_MAX + 0.5f); /* round-to-nearest */
  if(calibrated<0) calibrated=0;
  if(calibrated>SE_SOLAR_CALIBRATED_MAX) calibrated=SE_SOLAR_CALIBRATED_MAX;
  return calibrated;
}

/* calibrated [0,140] -> 8-bit trip count for the emulated sensor.
   byte = 0xE8 - calibrated, so the game's (232 - byte) recovers calibrated.
   Fixes spec Bug 1: the old low end was 0xE7, leaving calibrated at 1 (one bar)
   when the slider was fully down, instead of 0 (empty gauge). */
static inline int se_solar_calibrated_to_byte(int calibrated){
  if(calibrated<0) calibrated=0;
  if(calibrated>SE_SOLAR_CALIBRATED_MAX) calibrated=SE_SOLAR_CALIBRATED_MAX;
  return SE_SOLAR_DARK_BYTE - calibrated;
}

/* Convenience: normalized brightness [0,1] straight to the emulated trip count. */
static inline int se_solar_float_to_byte(float norm){
  return se_solar_calibrated_to_byte(se_solar_float_to_calibrated(norm));
}

/* calibrated [0,140] -> sun-gauge bars. Exclusive upper bounds: you get N bars
   when thresh[N-1] <= calibrated < thresh[N]. Used by the self-test and the
   debug readout; the emulator core itself never needs this. */
static inline int se_solar_calibrated_to_bars(int calibrated, const int* thresh, int nbars){
  int bars=0;
  for(int i=0;i<nbars;i++){
    if(calibrated>=thresh[i]) bars=i+1;
    else break;
  }
  return bars;
}
static inline int se_solar_calibrated_to_bars_boktai1(int calibrated){
  static const int thresh[8]  = {1,7,16,28,44,67,98,140};        /* 8-bar gauge  */
  return se_solar_calibrated_to_bars(calibrated, thresh, 8);
}
static inline int se_solar_calibrated_to_bars_boktai23(int calibrated){
  static const int thresh[10] = {1,6,13,23,35,50,67,87,110,140}; /* 10-bar gauge */
  return se_solar_calibrated_to_bars(calibrated, thresh, 10);
}

/* --- Light-sensor path: lux -> calibrated (spec S6) -------------------------
   The phone's Sensor.TYPE_LIGHT reports illuminance in LUX (visible light);
   the cartridge measured UV-A irradiance. They correlate well outdoors and not
   at all indoors (bulbs/LEDs emit ~no UV-A), so we subtract an indoor floor and
   scale up to a saturation point. Both points are user-calibratable (spec S6.3);
   the constants below are only starting DEFAULTS and MUST be tuned on-device
   (spec S7) -- do not treat them as correct for any particular phone. */
#define SOLAR_LUX_FLOOR        1500.0f  /* below this, calibrated = 0            */
#define SOLAR_LUX_PER_UVI      9000.0f  /* lux per unit of UV index in daylight  */
#define SOLAR_UVI_SATURATION   13.1f    /* UVI at which the gauge maxes          */
#define SOLAR_EMA_ALPHA        0.15f    /* per-sample smoothing (applied in C)   */
#define SOLAR_BAR_HYSTERESIS   3        /* calibrated-unit deadband (applied in C)*/
/* Default lux at which the gauge maxes: floor + the full UV span (~119k lux,
   i.e. direct tropical/high-altitude sun -- see the spec S6.1 reference table). */
#define SOLAR_LUX_SATURATION_DEFAULT (SOLAR_LUX_FLOOR + SOLAR_LUX_PER_UVI*SOLAR_UVI_SATURATION)

/* Two-point linear map: lux in [lux_floor, lux_saturation] -> calibrated [0,140].
   This is the two-point-calibration form of spec S6.2 (the UVI intermediate is
   algebraically folded in: lux_saturation == floor + LUX_PER_UVI*UVI_SATURATION). */
static inline int se_solar_lux_to_calibrated(float lux, float lux_floor, float lux_saturation){
  if(lux_saturation < lux_floor + 1.0f) lux_saturation = lux_floor + 1.0f; /* guard /0 */
  float t = (lux - lux_floor) / (lux_saturation - lux_floor);
  if(t<0.0f) t=0.0f;
  if(t>1.0f) t=1.0f;
  int calibrated = (int)(t*(float)SE_SOLAR_CALIBRATED_MAX + 0.5f);
  if(calibrated<0) calibrated=0;
  if(calibrated>SE_SOLAR_CALIBRATED_MAX) calibrated=SE_SOLAR_CALIBRATED_MAX;
  return calibrated;
}

#endif /* SE_SOLAR_SENSOR_H */
