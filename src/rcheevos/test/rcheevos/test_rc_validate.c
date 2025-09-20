#include "rc_validate.h"

#include "rc_consoles.h"

#include "../rc_compat.h"
#include "../test_framework.h"

#include <stdlib.h>
#include <string.h>

int validate_trigger(const char* trigger, char result[], const size_t result_size, uint32_t max_address) {
  char* buffer;
  rc_trigger_t* compiled;
  int success = 0;

  int ret = rc_trigger_size(trigger);
  if (ret < 0) {
    snprintf(result, result_size, "%s", rc_error_str(ret));
    return 0;
  }

  buffer = (char*)malloc(ret + 4);
  memset(buffer + ret, 0xCD, 4);
  compiled = rc_parse_trigger(buffer, trigger, NULL, 0);
  if (compiled == NULL) {
    snprintf(result, result_size, "parse failed");
  }
  else if (*(uint32_t*)&buffer[ret] != 0xCDCDCDCD) {
    snprintf(result, result_size, "write past end of buffer");
  }
  else if (rc_validate_trigger(compiled, result, result_size, max_address)) {
    success = 1;
  }

  free(buffer);
  return success;
}

static void test_validate_trigger_max_address(const char* trigger, const char* expected_error, uint32_t max_address) {
  char buffer[512];
  int valid = validate_trigger(trigger, buffer, sizeof(buffer), max_address);

  if (*expected_error) {
    ASSERT_STR_EQUALS(buffer, expected_error);
    ASSERT_NUM_EQUALS(valid, 0);
  }
  else {
    ASSERT_STR_EQUALS(buffer, "");
    ASSERT_NUM_EQUALS(valid, 1);
  }
}

static void test_validate_trigger(const char* trigger, const char* expected_error) {
  test_validate_trigger_max_address(trigger, expected_error, 0xFFFFFFFF);
}

static void test_validate_trigger_64k(const char* trigger, const char* expected_error) {
  test_validate_trigger_max_address(trigger, expected_error, 0xFFFF);
}

static void test_validate_trigger_128k(const char* trigger, const char* expected_error) {
  test_validate_trigger_max_address(trigger, expected_error, 0x1FFFF);
}

int validate_trigger_for_console(const char* trigger, char result[], const size_t result_size, uint32_t console_id) {
  char* buffer;
  rc_trigger_t* compiled;
  int success = 0;

  int ret = rc_trigger_size(trigger);
  if (ret < 0) {
    snprintf(result, result_size, "%s", rc_error_str(ret));
    return 0;
  }

  buffer = (char*)malloc(ret + 4);
  memset(buffer + ret, 0xCD, 4);
  compiled = rc_parse_trigger(buffer, trigger, NULL, 0);
  if (compiled == NULL) {
    snprintf(result, result_size, "parse failed");
  }
  else if (*(unsigned*)&buffer[ret] != 0xCDCDCDCD) {
    snprintf(result, result_size, "write past end of buffer");
  }
  else if (rc_validate_trigger_for_console(compiled, result, result_size, console_id)) {
    success = 1;
  }

  free(buffer);
  return success;
}

static void test_validate_trigger_console(const char* trigger, const char* expected_error, uint32_t console_id) {
  char buffer[512];
  int valid = validate_trigger_for_console(trigger, buffer, sizeof(buffer), console_id);

  if (*expected_error) {
    ASSERT_STR_EQUALS(buffer, expected_error);
    ASSERT_NUM_EQUALS(valid, 0);
  }
  else {
    ASSERT_STR_EQUALS(buffer, "");
    ASSERT_NUM_EQUALS(valid, 1);
  }
}

static void test_combining_conditions_at_end_of_definition() {
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_A:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_B:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_C:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_D:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_N:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_O:0xH2345=2", "Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_Z:0xH2345=2", "Final condition type expects another condition to follow");

  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_A:0xH2345=2S0x3456=1", "Core Final condition type expects another condition to follow");
  TEST_PARAMS2(test_validate_trigger, "0x3456=1S0xH1234=1_A:0xH2345=2", "Alt1 Final condition type expects another condition to follow");

  /* combining conditions not at end of definition */
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234=1_0xH2345=2", "");
  TEST_PARAMS2(test_validate_trigger, "B:0xH1234=1_0xH2345=2", "");
  TEST_PARAMS2(test_validate_trigger, "N:0xH1234=1_0xH2345=2", "");
  TEST_PARAMS2(test_validate_trigger, "O:0xH1234=1_0xH2345=2", "");
  TEST_PARAMS2(test_validate_trigger, "Z:0xH1234=1_0xH2345=2", "");
}

static void test_addhits_chain_without_target() {
  TEST_PARAMS2(test_validate_trigger, "C:0xH1234=1_0xH2345=2", "Condition 2: Final condition in AddHits chain must have a hit target");
  TEST_PARAMS2(test_validate_trigger, "D:0xH1234=1_0xH2345=2", "Condition 2: Final condition in AddHits chain must have a hit target");
  TEST_PARAMS2(test_validate_trigger, "C:0xH1234=1_0xH2345=2.1.", "");
  TEST_PARAMS2(test_validate_trigger, "D:0xH1234=1_0xH2345=2.1.", "");
}

static void test_range_comparisons() {
  TEST_PARAMS2(test_validate_trigger, "0xH1234>1", "");

  TEST_PARAMS2(test_validate_trigger, "0xH1234=255", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234!=255", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>255", "Condition 1: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>=255", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234<255", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234<=255", "Condition 1: Comparison is always true");

  /* while a BCD value shouldn't exceed 99, it can reach 165: 0xFF => 15*10+15 */
  TEST_PARAMS2(test_validate_trigger, "b0xH1234<165", "");
  TEST_PARAMS2(test_validate_trigger, "b0xH1234<=165", "Condition 1: Comparison is always true");

  TEST_PARAMS2(test_validate_trigger, "R:0xH1234<255", "");
  TEST_PARAMS2(test_validate_trigger, "R:0xH1234<=255", "Condition 1: Comparison is always true");

  TEST_PARAMS2(test_validate_trigger, "0xH1234=256", "Condition 1: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234!=256", "Condition 1: Comparison is always true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>256", "Condition 1: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>=256", "Condition 1: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234<256", "Condition 1: Comparison is always true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234<=256", "Condition 1: Comparison is always true");

  TEST_PARAMS2(test_validate_trigger, "0x 1234>=65535", "");
  TEST_PARAMS2(test_validate_trigger, "0x 1234>=65536", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "b0x 1234>=16665", "");
  TEST_PARAMS2(test_validate_trigger, "b0x 1234>=16666", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "0xW1234>=16777215", "");
  TEST_PARAMS2(test_validate_trigger, "0xW1234>=16777216", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "b0xW1234>=1666665", "");
  TEST_PARAMS2(test_validate_trigger, "b0xW1234>=1666666", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "0xX1234>=4294967295", "");
  TEST_PARAMS2(test_validate_trigger, "0xX1234>4294967295", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "b0xX1234>=166666665", "");
  TEST_PARAMS2(test_validate_trigger, "b0xX1234>=166666666", "Condition 1: Comparison is never true");

  TEST_PARAMS2(test_validate_trigger, "0xT1234>=1", "");
  TEST_PARAMS2(test_validate_trigger, "0xT1234>1", "Condition 1: Comparison is never true");

  /* max for AddSource is the sum of all parts (255+255=510) */
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0<255", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0<=255", "Condition 2: Comparison is always true");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0xH1235<510", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0xH1235<=510", "Condition 2: Comparison is always true");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234*10_0xH1235>=2805", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234*10_0xH1235>2805", "Condition 2: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234/10_0xH1235>=280", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234/10_0xH1235>280", "Condition 2: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234&10_0xH1235>=265", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234&10_0xH1235>265", "Condition 2: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "A:b0xH1234*100_b0xH1235>=16665", "");
  TEST_PARAMS2(test_validate_trigger, "A:b0xH1234*100_b0xH1235>16665", "Condition 2: Comparison is never true");

  /* max for SubSource is always 0xFFFFFFFF */
  TEST_PARAMS2(test_validate_trigger, "B:0xH1234_0xH1235<510", "");
  TEST_PARAMS2(test_validate_trigger, "B:0xH1234_0xH1235<=510", "");
}

void test_size_comparisons() {
  TEST_PARAMS2(test_validate_trigger, "0xH1234>0xH1235", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>0x 1235", "Condition 1: Comparing different memory sizes");

  /* AddSource chain may compare different sizes without warning as the chain changes the
   * size of the final result. */
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0xH1235=0xH2345", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xH1234_0xH1235=0x 2345", "");
}

void test_address_range() {
  /* basic checks for each side */
  TEST_PARAMS2(test_validate_trigger_64k, "0xH1234>0xH1235", "");
  TEST_PARAMS2(test_validate_trigger_64k, "0xH12345>0xH1235", "Condition 1: Address 12345 out of range (max FFFF)");
  TEST_PARAMS2(test_validate_trigger_64k, "0xH1234>0xH12345", "Condition 1: Address 12345 out of range (max FFFF)");
  TEST_PARAMS2(test_validate_trigger_64k, "0xH12345>0xH12345", "Condition 1: Address 12345 out of range (max FFFF)");
  TEST_PARAMS2(test_validate_trigger_64k, "0xX1234>h12345", "");

  /* support for multiple memory blocks and edge addresses */
  TEST_PARAMS2(test_validate_trigger_128k, "0xH1234>0xH1235", "");
  TEST_PARAMS2(test_validate_trigger_128k, "0xH12345>0xH1235", "");
  TEST_PARAMS2(test_validate_trigger_128k, "0xH0000>5", "");
  TEST_PARAMS2(test_validate_trigger_128k, "0xH1FFFF>5", "");
  TEST_PARAMS2(test_validate_trigger_128k, "0xH20000>5", "Condition 1: Address 20000 out of range (max 1FFFF)");

  /* AddAddress can use really big values for negative offsets, don't flag them. */
  TEST_PARAMS2(test_validate_trigger_128k, "I:0xX1234_0xHFFFFFF00>5", "");
  TEST_PARAMS2(test_validate_trigger_128k, "I:0xX1234_0xH1234>5_0xHFFFFFF00>5", "Condition 3: Address FFFFFF00 out of range (max 1FFFF)");

  /* console-specific warnings */
  TEST_PARAMS3(test_validate_trigger_console, "0xH0123>23", "", RC_CONSOLE_NINTENDO);
  TEST_PARAMS3(test_validate_trigger_console, "0xH07FF>23", "", RC_CONSOLE_NINTENDO);
  TEST_PARAMS3(test_validate_trigger_console, "0xH0800>23", "Condition 1: Mirror RAM may not be exposed by emulator (address 0800)", RC_CONSOLE_NINTENDO);
  TEST_PARAMS3(test_validate_trigger_console, "0xH1FFF>23", "Condition 1: Mirror RAM may not be exposed by emulator (address 1FFF)", RC_CONSOLE_NINTENDO);
  TEST_PARAMS3(test_validate_trigger_console, "0xH2000>23", "", RC_CONSOLE_NINTENDO);
  TEST_PARAMS3(test_validate_trigger_console, "0xH0123>0xH1000", "Condition 1: Mirror RAM may not be exposed by emulator (address 1000)", RC_CONSOLE_NINTENDO);

  TEST_PARAMS3(test_validate_trigger_console, "0xHC123>23", "", RC_CONSOLE_GAMEBOY);
  TEST_PARAMS3(test_validate_trigger_console, "0xHDFFF>23", "", RC_CONSOLE_GAMEBOY);
  TEST_PARAMS3(test_validate_trigger_console, "0xHE000>23", "Condition 1: Echo RAM may not be exposed by emulator (address E000)", RC_CONSOLE_GAMEBOY);
  TEST_PARAMS3(test_validate_trigger_console, "0xHFDFF>23", "Condition 1: Echo RAM may not be exposed by emulator (address FDFF)", RC_CONSOLE_GAMEBOY);
  TEST_PARAMS3(test_validate_trigger_console, "0xHFE00>23", "", RC_CONSOLE_GAMEBOY);

  TEST_PARAMS3(test_validate_trigger_console, "0xHC123>23", "", RC_CONSOLE_GAMEBOY_COLOR);
  TEST_PARAMS3(test_validate_trigger_console, "0xHDFFF>23", "", RC_CONSOLE_GAMEBOY_COLOR);
  TEST_PARAMS3(test_validate_trigger_console, "0xHE000>23", "Condition 1: Echo RAM may not be exposed by emulator (address E000)", RC_CONSOLE_GAMEBOY_COLOR);
  TEST_PARAMS3(test_validate_trigger_console, "0xHFDFF>23", "Condition 1: Echo RAM may not be exposed by emulator (address FDFF)", RC_CONSOLE_GAMEBOY_COLOR);
  TEST_PARAMS3(test_validate_trigger_console, "0xHFE00>23", "", RC_CONSOLE_GAMEBOY_COLOR);

  TEST_PARAMS3(test_validate_trigger_console, "0xH9E20=68", "Condition 1: Kernel RAM may not be initialized without real BIOS (address 9E20)", RC_CONSOLE_PLAYSTATION);
  TEST_PARAMS3(test_validate_trigger_console, "0xHB8BE=68", "Condition 1: Kernel RAM may not be initialized without real BIOS (address B8BE)", RC_CONSOLE_PLAYSTATION);
  TEST_PARAMS3(test_validate_trigger_console, "0xHFFFF=68", "Condition 1: Kernel RAM may not be initialized without real BIOS (address FFFF)", RC_CONSOLE_PLAYSTATION);
  TEST_PARAMS3(test_validate_trigger_console, "0xH10000=68", "", RC_CONSOLE_PLAYSTATION);
}

void test_delta_pointers() {
  TEST_PARAMS2(test_validate_trigger, "I:0xX1234_0xH0000=1", "");
  TEST_PARAMS2(test_validate_trigger, "I:d0xX1234_0xH0000=1", "Condition 1: Using pointer from previous frame");
  TEST_PARAMS2(test_validate_trigger, "I:p0xX1234_0xH0000=1", "Condition 1: Using pointer from previous frame");
  TEST_PARAMS2(test_validate_trigger, "I:0xX1234_d0xH0000=1", "");
  TEST_PARAMS2(test_validate_trigger, "I:d0xX1234_I:d0xH0010_0xH0000=1", "Condition 1: Using pointer from previous frame");
  TEST_PARAMS2(test_validate_trigger, "I:d0xX1234_I:0xH0010_0xH0000=1", "Condition 1: Using pointer from previous frame");
  TEST_PARAMS2(test_validate_trigger, "I:0xX1234_I:d0xH0010_0xH0000=1", "Condition 2: Using pointer from previous frame");
  TEST_PARAMS2(test_validate_trigger, "I:0xX1234_I:0xH0010_0xH0000=1", "");
}

void test_float_comparisons() {
  TEST_PARAMS2(test_validate_trigger, "fF1234=f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "fM1234=f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "fF1234=2", "");
  TEST_PARAMS2(test_validate_trigger, "0xX1234=2", "");
  TEST_PARAMS2(test_validate_trigger, "0xX1234=f2.3", "Condition 1: Comparison is never true"); /* non integral comparison */
  TEST_PARAMS2(test_validate_trigger, "0xX1234!=f2.3", "Condition 1: Comparison is always true"); /* non integral comparison */
  TEST_PARAMS2(test_validate_trigger, "0xX1234<f2.3", ""); /* will be converted to < 3 */
  TEST_PARAMS2(test_validate_trigger, "0xX1234<=f2.3", ""); /* will be converted to <= 2 */
  TEST_PARAMS2(test_validate_trigger, "0xX1234>f2.3", ""); /* will be converted to > 2 */
  TEST_PARAMS2(test_validate_trigger, "0xX1234>=f2.3", ""); /* will be converted to >= 3 */
  TEST_PARAMS2(test_validate_trigger, "0xX1234=f2.0", ""); /* float can be converted to int without loss of data*/
  TEST_PARAMS2(test_validate_trigger, "0xH1234=f2.3", "Condition 1: Comparison is never true");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=f300.0", "Condition 1: Comparison is never true"); /* value out of range */
  TEST_PARAMS2(test_validate_trigger, "f2.3=fF1234", "");
  TEST_PARAMS2(test_validate_trigger, "f2.3=0xX1234", "Condition 1: Comparison is never true"); /* non integral comparison */
  TEST_PARAMS2(test_validate_trigger, "f2.0=0xX1234", "");
  TEST_PARAMS2(test_validate_trigger, "A:Ff2345_fF1234=f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "A:0xX2345_fF1234=f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "A:Ff2345_0x1234=f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "fM1234>f2.3", "");
  TEST_PARAMS2(test_validate_trigger, "fM1234>f-2.3", "");
  TEST_PARAMS2(test_validate_trigger, "I:0xX2345_fM1234>f1.0", "");
  TEST_PARAMS2(test_validate_trigger, "I:0xX2345_fM1234>f-1.0", "");
  TEST_PARAMS2(test_validate_trigger, "fF1234>=f0.0", ""); /* explicit float comparison can be negative */
  TEST_PARAMS2(test_validate_trigger, "fM1234>=f0.0", "");
  TEST_PARAMS2(test_validate_trigger, "fB1234>=f0.0", "");
  TEST_PARAMS2(test_validate_trigger, "fF1234>=0", ""); /* implicit float comparison can be negative */
  TEST_PARAMS2(test_validate_trigger, "fM1234>=0", "");
  TEST_PARAMS2(test_validate_trigger, "fB1234>=0", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234>=f0.1", ""); /* 0 can be less than 0.1 */
  TEST_PARAMS2(test_validate_trigger, "0xH1234>=f255.1", "Condition 1: Comparison is never true"); /* 255 cannot be >= 255.1 */
  TEST_PARAMS2(test_validate_trigger, "f0.1<=0xH1234", ""); /* 0 can be less than 0.1 */
  TEST_PARAMS2(test_validate_trigger, "f255.1<=0xH1234", "Condition 1: Comparison is never true"); /* 255 cannot be >= 255.1 */
}

void test_conflicting_conditions() {
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1_0xH0000=2", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0xH0000>5", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0xH0000=5", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0xH0001=5", ""); /* ignore differing address */
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0x 0000=5", ""); /* ignore differing size */
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_d0xH0000=5", ""); /* ignore differing type */
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0xH0000=5.1.", ""); /* ignore anything with a hit target */
  TEST_PARAMS2(test_validate_trigger, "O:0xH0000<5_0xH0000=5", ""); /* ignore combining conditions */
  TEST_PARAMS2(test_validate_trigger, "A:0xH0000<5_0xH0000=5", ""); /* ignore combining conditions */
  TEST_PARAMS2(test_validate_trigger, "N:0xH0000<5_R:0xH0001=8_T:0xH0000=0", ""); /* ignore combining conditions */
  TEST_PARAMS2(test_validate_trigger, "0xH0000<=5_0xH0000>=5", "");
  TEST_PARAMS2(test_validate_trigger, "0xH0000>1_0xH0000<3", "");
  TEST_PARAMS2(test_validate_trigger, "1=1S0xH0000=1S0xH0000=2", "");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1S0xH0000=2", "Alt1 Condition 1: Conflicts with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000=1S0xH0000=1", "Alt1 Condition 1: Conflicts with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1SR:0xH0000=1", "Alt1 Condition 1: Conflicts with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1_0xH0000=1", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1S0xH0000=1", "");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1SP:0xH0000!=1", "Alt1 Condition 1: Conflicts with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1_P:0xH0000!=1", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1_R:0xH0000=1", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1SP:0xH0000=5", "");
  TEST_PARAMS2(test_validate_trigger, "M:0xH0000=5_Q:0xH0000=255", "Condition 2: Conflicts with Condition 1");

  /* PauseIf prevents hits from incrementing. ResetIf clears all hits. If both exist and are conflicting, the group
   * will only ever be paused or reset, and therefore will never be true */
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1_R:0xH0000!=1", "Condition 2: Conflicts with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000!=1_P:0xH0000=1", "Condition 2: Conflicts with Condition 1");
  /* if the PauseIf is less restrictive than the ResetIf, it's just a guard. ignore it*/
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1_R:0xH0000!=6", "");
  /* PauseIf in alternate group does not affect the ResetIf*/
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1SR:0xH0000!=1", "");
}

void test_redundant_conditions() {
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1_0xH0000=1", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000<3_0xH0000<5", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000<5_0xH0000<3", "Condition 1: Redundant with Condition 2");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1S0xH0000=1", "Alt1 Condition 1: Redundant with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000=1_0xH0000!=1", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000=1_0xH0000=2", "");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000=1_T:0xH0000=2", "");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1_R:0xH0000!=1", "Condition 1: Redundant with Condition 2");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000=1S0xH0000!=1", "Alt1 Condition 1: Redundant with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1SR:0xH0000!=1", "Core Condition 1: Redundant with Alt1 Condition 1");
  TEST_PARAMS2(test_validate_trigger, "P:0xH0000=1SP:0xH0000=1", ""); /* same pauseif can appear in different groups */
  TEST_PARAMS2(test_validate_trigger, "0xH0000=4.1._0xH0000=5_P:0xH0000<4", "");
  TEST_PARAMS2(test_validate_trigger, "Q:0xH0000=5_Q:0xH0000!=255", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "M:0xH0000=5_Q:0xH0000!=255", ""); /* measuredif not redundant measured */
  TEST_PARAMS2(test_validate_trigger, "Q:0xH0000=1_0xH0000=1", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "Q:0xH0000=1_Q:0xH0000=1", "Condition 2: Redundant with Condition 1");
  TEST_PARAMS2(test_validate_trigger, "Q:0xH0000=1SQ:0xH0000=1", ""); /* same measuredif can appear in different groups */
  TEST_PARAMS2(test_validate_trigger, "T:0xH0000!=0_T:0xH0000=6", "Condition 1: Redundant with Condition 2");
  TEST_PARAMS2(test_validate_trigger, "0xH0000!=0_T:0xH0000=6", ""); /* trigger not redundant with non-trigger */
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1_Q:0xH0000=1", "Condition 1: Redundant with Condition 2");
  TEST_PARAMS2(test_validate_trigger, "0xH0000=1S0xH0000!=0S0xH0001=2", "Alt1 Condition 1: Redundant with Core Condition 1");
  TEST_PARAMS2(test_validate_trigger, "0xH0000!=0S0xH0000=1S0xH0001=2", ""); /* more restrictive alt 1 is not redundant with core */
  TEST_PARAMS2(test_validate_trigger, "0xH0000!=0S0xH0000!=0S0xH0001=2", "Alt1 Condition 1: Redundant with Core Condition 1");
}

void test_redundant_hitcounts() {
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000!=0", "");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000!=0.1.", "Condition 1: Hit target of 1 is redundant on ResetIf");
  TEST_PARAMS2(test_validate_trigger, "R:0xH0000!=0.2.", "");
}

void test_rc_validate(void) {
  TEST_SUITE_BEGIN();

  /* positive baseline test cases */
  TEST_PARAMS2(test_validate_trigger, "", "");
  TEST_PARAMS2(test_validate_trigger, "0xH1234=1_0xH2345=2S0xH3456=1S0xH3456=2", "");

  test_combining_conditions_at_end_of_definition();
  test_addhits_chain_without_target();
  test_range_comparisons();
  test_size_comparisons();
  test_address_range();
  test_delta_pointers();
  test_float_comparisons();
  test_conflicting_conditions();
  test_redundant_conditions();
  test_redundant_hitcounts();

  TEST_SUITE_END();
}
