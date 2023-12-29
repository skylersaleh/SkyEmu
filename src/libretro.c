#include "mutex.h"
#include <stdint.h>
#include <stdbool.h>

// include core headers

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_REBIND_TIMER_LENGTH 5.0

#define SE_TRANSPARENT_BG_ALPHA

#include "gba.h"
#include "nds.h"
#include "gb.h"

// common SE implementations

bool se_load_bios_file(
    const char* name,
    const char* base_path,
    const char* file_name,
    uint8_t* data, size_t data_size
) {

  return true;
}                   

// global emu state

static struct lr_emu_state_t {
  void* rom_data;
  int32_t screen_width;
  int32_t screen_height;
  int32_t screen_width_max;
  int32_t screen_height_max;
} emu_state;

// Retro Arch implementation

#include "libretro.h"

void retro_set_environment(retro_environment_t _env){}

void retro_set_video_refresh(retro_video_refresh_t _refresh){}

void retro_set_audio_sample(retro_audio_sample_t _sample) {}

void retro_set_audio_sample_batch(retro_audio_sample_batch_t _batch) {}

void retro_set_input_poll(retro_input_poll_t _poll) {}

void retro_set_input_state(retro_input_state_t _state) {}

void retro_init(void) {
  emu_state.screen_height_max = 1080;
  emu_state.screen_width_max = 1920;
}

void retro_deinit(void) {}

unsigned retro_api_version(void) {
  return RETRO_API_VERSION;
}

void retro_get_system_info(struct retro_system_info* info){
    static const char* name = "SkyEmu"; 
    info->library_name = name;
    info->library_version = "tmp";
    info->block_extract = false;
    info->need_fullpath = false;
    info->valid_extensions = NULL;
}

void retro_get_system_av_info(struct retro_system_av_info* info) {
  info->geometry = (struct retro_game_geometry){
    .aspect_ratio = 1.0, 
    .base_height = emu_state.screen_height_max, 
    .base_width = emu_state.screen_width_max,
    .max_height = emu_state.screen_height_max, 
    .max_width = emu_state.screen_width_max
  };
  info->timing = (struct retro_system_timing){.fps = 60, .sample_rate = 60};
}

void retro_set_controller_port_device(unsigned port, unsigned device) {}

void retro_reset(void) {}

void retro_run(void) {}

size_t retro_serialize_size(void) {
  return 0;
}

bool retro_serialize(void* _data, size_t _size) {
  return true;
}

bool retro_unserialize(const void* _data, size_t _size) {
  return true;
}

void retro_cheat_reset(void) {}

void retro_cheat_set(unsigned _index, bool _enabled, const char* _code) {}

bool retro_load_game(const struct retro_game_info* _game) {
  return true;
}

bool retro_load_game_special(unsigned game_type, const struct retro_game_info* _info, size_t _num_info) {
  return true;
}

void retro_unload_game(void) {}

unsigned retro_get_region(void) {
  return 0;
}

void* retro_get_memory_data(unsigned _id) {
  return 0;
}

size_t retro_get_memory_size(unsigned _id) {
  return 0;
}
