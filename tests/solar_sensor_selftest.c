/*
  Standalone host-side self-test for the Boktai solar-sensor mapping.
  No emulator or Android dependencies -- pure C, builds with any compiler.

  Build & run:
    cc -std=c99 -Wall -Wextra -o solar_selftest tests/solar_sensor_selftest.c && ./solar_selftest
    clang -std=c99 -Wall -Wextra -o solar_selftest tests/solar_sensor_selftest.c && ./solar_selftest
    cl /W3 /Fe:solar_selftest.exe tests\solar_sensor_selftest.c && solar_selftest.exe

  Exit code 0 = all pass, 1 = at least one failure.

  Validates:
    - reference table (11 mGBA-derived calibrated values, both games),
      including the two documented mgba#523 "stuck bar" points on Boktai 1
    - endpoint contract: slider 0.0 -> byte 0xE8 -> calibrated 0 -> 0 bars
    - slider 1.0 -> byte 0x5C -> calibrated 140 -> max bars
    - the curve pinned at literal intermediate points (rejects sqrt/x^2/x^4)
    - no top-end dead zone (the old 181-into-140 saturation regression)
    - monotonicity of the whole slider sweep
    - every gauge state is reachable across the sweep (mgba#523 regression)
*/
#include <stdio.h>
#include "../src/se_solar_sensor.h"

static int g_failures = 0;
#define CHECK(cond, ...) do{ if(!(cond)){ g_failures++; printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } }while(0)

int main(void){
  /* --- reference table: calibrated -> bars, both games ------------------- */
  /* {calibrated, boktai1 bars, boktai2/3 bars} */
  struct { int calibrated, b1, b23; } ref[] = {
    {   0, 0,  0},
    {   4, 1,  1},
    {  10, 2,  2},
    {  17, 3,  3},
    {  26, 3,  4},   /* Boktai 1 sticks at 3 here (mgba#523); 2/3 advances */
    {  41, 4,  5},
    {  61, 5,  6},
    {  83, 6,  7},
    { 108, 7,  8},
    { 138, 7,  9},   /* Boktai 1 sticks at 7 here (mgba#523) */
    { 140, 8, 10},   /* clamped max */
  };
  int n = (int)(sizeof(ref)/sizeof(ref[0]));
  for(int i=0;i<n;i++){
    int b1  = se_solar_calibrated_to_bars_boktai1(ref[i].calibrated);
    int b23 = se_solar_calibrated_to_bars_boktai23(ref[i].calibrated);
    CHECK(b1==ref[i].b1,   "Boktai1   calibrated=%d expected %d bars, got %d", ref[i].calibrated, ref[i].b1, b1);
    CHECK(b23==ref[i].b23, "Boktai2/3 calibrated=%d expected %d bars, got %d", ref[i].calibrated, ref[i].b23, b23);
  }

  /* --- endpoint + curve contract ----------------------------------------
     These assertions deliberately hard-code the GAME's constant (232) and the
     expected bytes as literals rather than deriving them via
     SE_SOLAR_DARK_BYTE. Recovering calibrated with the same constant the
     implementation uses would be circular: both sides would shift together and
     an incorrect dark byte would still pass. */
  #define GAME_RECOVERS(byte) (232 - (byte))

  /* slider 0.0 -> empty gauge (previously produced 0xE7 -> one lit bar) */
  int byte0 = se_solar_float_to_byte(0.0f);
  CHECK(byte0==0xE8, "slider 0.0 should give byte 0xE8, got 0x%02X", byte0);
  CHECK(GAME_RECOVERS(byte0)==0, "slider 0.0 should give calibrated 0, got %d", GAME_RECOVERS(byte0));
  CHECK(se_solar_calibrated_to_bars_boktai23(GAME_RECOVERS(byte0))==0, "slider 0.0 should give 0 bars (Boktai2/3)");
  CHECK(se_solar_calibrated_to_bars_boktai1(GAME_RECOVERS(byte0))==0,  "slider 0.0 should give 0 bars (Boktai1)");

  /* slider 1.0 -> exactly the clamp -> max bars */
  int byte1 = se_solar_float_to_byte(1.0f);
  CHECK(byte1==0x5C, "slider 1.0 should give byte 0x5C, got 0x%02X", byte1);
  CHECK(GAME_RECOVERS(byte1)==140, "slider 1.0 should give calibrated 140, got %d", GAME_RECOVERS(byte1));
  CHECK(se_solar_calibrated_to_bars_boktai23(GAME_RECOVERS(byte1))==10, "slider 1.0 should give 10 bars (Boktai2/3)");
  CHECK(se_solar_calibrated_to_bars_boktai1(GAME_RECOVERS(byte1))==8,   "slider 1.0 should give 8 bars (Boktai1)");

  /* The curve itself, pinned at literal points. Endpoint-only checks are
     satisfied by ANY monotone map through (0,0) and (1,140) -- sqrt, x^2, x^4
     all pass those -- so pin the intermediate values too. */
  struct { float norm; int calibrated, byte; } curve[] = {
    { 0.00f,   0, 0xE8 },
    { 0.25f,  35, 0xC5 },
    { 0.50f,  70, 0xA2 },
    { 0.75f, 105, 0x7F },
    { 1.00f, 140, 0x5C },
  };
  for(int i=0;i<(int)(sizeof(curve)/sizeof(curve[0]));i++){
    int c = se_solar_float_to_calibrated(curve[i].norm);
    int b = se_solar_float_to_byte(curve[i].norm);
    CHECK(c==curve[i].calibrated, "norm %.2f expected calibrated %d, got %d", curve[i].norm, curve[i].calibrated, c);
    CHECK(b==curve[i].byte,       "norm %.2f expected byte 0x%02X, got 0x%02X", curve[i].norm, curve[i].byte, b);
  }

  /* No top-end dead zone. The previous mapping emitted a 181-count span into a
     140-count window, so it saturated from norm ~0.77 upward and the top ~23%
     of slider travel did nothing. Under the corrected range norm 0.90 must NOT
     already be clamped -- this check fails if that regression ever returns. */
  CHECK(se_solar_float_to_calibrated(0.90f)==126,
    "norm 0.90 should give calibrated 126, got %d (top-end saturation regression?)",
    se_solar_float_to_calibrated(0.90f));
  CHECK(se_solar_float_to_calibrated(0.90f) < SE_SOLAR_CALIBRATED_MAX,
    "norm 0.90 must not already be clamped at the maximum");

  /* --- monotonicity across the slider sweep ------------------------------ */
  /* calibrated must never decrease; the byte is inverted so it must never
     increase; and the byte must stay inside [0x5C, 0xE8]. */
  int prev_cal=-1, prev_byte=0x100;
  for(int i=0;i<=1000;i++){
    float norm=(float)i/1000.0f;
    int cal  = se_solar_float_to_calibrated(norm);
    int byte = se_solar_calibrated_to_byte(cal);
    CHECK(cal>=prev_cal,   "calibrated not monotonic at norm=%.3f (%d < %d)", norm, cal, prev_cal);
    CHECK(byte<=prev_byte, "byte not monotonic(inverted) at norm=%.3f (0x%02X > 0x%02X)", norm, byte, prev_byte);
    CHECK(byte>=0x5C && byte<=0xE8, "byte out of range at norm=%.3f: 0x%02X", norm, byte);
    prev_cal=cal; prev_byte=byte;
  }

  /* --- reachability: every gauge state hit across the sweep -------------- */
  /* Boktai 1: all 9 states (0..8). This is the mgba#523 regression -- our
     per-game mapping must not skip or stick on any bar. */
  int seen1[9]={0};
  for(int i=0;i<=1000;i++){
    int b = se_solar_calibrated_to_bars_boktai1(se_solar_float_to_calibrated((float)i/1000.0f));
    if(b>=0 && b<=8) seen1[b]=1;
  }
  for(int b=0;b<=8;b++) CHECK(seen1[b], "Boktai1 bar state %d unreachable via slider (mgba#523 regression)", b);

  /* Boktai 2/3: all 11 states (0..10). */
  int seen23[11]={0};
  for(int i=0;i<=1000;i++){
    int b = se_solar_calibrated_to_bars_boktai23(se_solar_float_to_calibrated((float)i/1000.0f));
    if(b>=0 && b<=10) seen23[b]=1;
  }
  for(int b=0;b<=10;b++) CHECK(seen23[b], "Boktai2/3 bar state %d unreachable via slider", b);

  /* --- lux -> calibrated (Android light-sensor path) --------------------- */
  {
    float lfloor = SOLAR_LUX_FLOOR, lsat = SOLAR_LUX_SATURATION_DEFAULT;
    CHECK(se_solar_lux_to_calibrated(0.0f, lfloor, lsat)==0,           "lux 0 -> calibrated 0");
    CHECK(se_solar_lux_to_calibrated(lfloor, lfloor, lsat)==0,         "lux at floor -> calibrated 0");
    CHECK(se_solar_lux_to_calibrated(lfloor-500.0f, lfloor, lsat)==0,  "lux below floor -> calibrated 0");
    CHECK(se_solar_lux_to_calibrated(lsat, lfloor, lsat)==140,         "lux at saturation -> calibrated 140");
    CHECK(se_solar_lux_to_calibrated(lsat*2.0f, lfloor, lsat)==140,    "lux above saturation -> clamped 140");
    int mid = se_solar_lux_to_calibrated((lfloor+lsat)*0.5f, lfloor, lsat);
    CHECK(mid==70, "lux at midpoint -> calibrated ~70, got %d", mid);
    /* degenerate calibration (saturation <= floor) must not divide by zero */
    CHECK(se_solar_lux_to_calibrated(5000.0f, 1000.0f, 1000.0f)>=0,    "degenerate calibration guarded");
    /* monotonic in lux */
    int plux=-1;
    for(int l=0;l<=140000;l+=1000){
      int c=se_solar_lux_to_calibrated((float)l, lfloor, lsat);
      CHECK(c>=plux, "lux->calibrated not monotonic at %d lux", l);
      plux=c;
    }
  }

  /* --- calibrated -> lux (inverse map, used by the debug bar ladder) ------- */
  {
    float lfloor = SOLAR_LUX_FLOOR, lsat = SOLAR_LUX_SATURATION_DEFAULT;
    CHECK(se_solar_calibrated_to_lux(0,lfloor,lsat)==lfloor,   "calibrated 0 -> floor lux");
    CHECK(se_solar_calibrated_to_lux(140,lfloor,lsat)==lsat,   "calibrated 140 -> saturation lux");
    /* round-trips with the forward map at every Boktai 1 bar threshold */
    for(int i=0;i<8;i++){
      int t = SE_SOLAR_BOKTAI1_THRESH[i];
      float lux = se_solar_calibrated_to_lux(t,lfloor,lsat);
      int back = se_solar_lux_to_calibrated(lux,lfloor,lsat);
      CHECK(back==t, "bar ladder round-trip failed at threshold %d (got %d)", t, back);
    }
  }

  /* --- saturation headroom: the top bar must have a usable plateau ---------
     This is the bug that pinned Boktai 1 at 7/8 bars: with saturation set to the
     exact observed peak, calibrated only reaches 140 at that single lux value. */
  {
    float peak = 100000.0f, lfloor = 1500.0f;
    int no_headroom = se_solar_lux_to_calibrated(peak*0.97f, lfloor, peak);
    CHECK(no_headroom < 140, "without headroom, 3%% below peak should miss max (got %d)", no_headroom);
    float lsat = peak*SOLAR_SATURATION_HEADROOM;
    CHECK(se_solar_lux_to_calibrated(peak, lfloor, lsat)==140,       "with headroom, peak -> 140");
    CHECK(se_solar_lux_to_calibrated(peak*0.90f, lfloor, lsat)==140, "with headroom, 10%% below peak still 140");
    CHECK(se_solar_calibrated_to_bars_boktai1(
            se_solar_lux_to_calibrated(peak*0.90f,lfloor,lsat))==8,  "with headroom, Boktai 1 reaches 8 bars");
    /* and the low end must not become trivially reachable indoors */
    CHECK(se_solar_lux_to_calibrated(800.0f, lfloor, lsat)==0,       "lit indoor room stays at calibrated 0");
  }

  if(g_failures){ printf("\n%d CHECK(s) FAILED\n", g_failures); return 1; }
  printf("All solar-sensor self-tests passed (%d reference points, both games).\n", n);
  return 0;
}
