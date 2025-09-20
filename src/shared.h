#ifndef SKYEMU_SHARED
#define SKYEMU_SHARED

#include<stdint.h>
#include<stdbool.h>

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_TRANSPARENT_BG_ALPHA 0.9

#define SE_NUM_CHEATS 32
#define SE_MAX_CHEAT_NAME_SIZE 32
#define SE_MAX_CHEAT_CODE_SIZE 256

typedef struct{
  char name[SE_MAX_CHEAT_NAME_SIZE];
  uint32_t buffer[SE_MAX_CHEAT_CODE_SIZE];
  uint32_t size; //In 32bit words
  int32_t state; //-1: invalid, 0: inactive, 1: active
}se_cheat_t;

extern se_cheat_t cheats[SE_NUM_CHEATS];
typedef bool(*se_cheat_fn)(const uint32_t* buffer, uint32_t size);

void se_run_all_ar_cheats(se_cheat_fn fn);
void se_load_cheats(const char * filename);
void se_save_cheats(const char* filename);
void se_convert_cheat_code(const char * text_code, int cheat_index);
void se_enable_cheat(int cheat_index);
void se_disable_cheat(int cheat_index);
void se_reset_cheats(void);

#endif
