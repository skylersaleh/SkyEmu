#include "libretro_common.h"

#include <cstdint>
#include <stdbool.h>
#include <assert.h>

// include core headers

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_REBIND_TIMER_LENGTH 5.0

#define SE_TRANSPARENT_BG_ALPHA

// global emu state

sb_emu_state_t emu_state;

// SE implementations

bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t* data, size_t data_size) {
  return false;
}

// Retro Arch implementation

retro_video_refresh_t video_refresh_cb = NULL;
retro_input_poll_t input_poll_cb = NULL;
retro_input_state_t input_state_cb = NULL;
retro_audio_sample_t audio_sample_cb = NULL;

void retro_set_environment(retro_environment_t env) {
  enum retro_pixel_format pixel_format = RETRO_PIXEL_FORMAT_XRGB8888;
  env(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &pixel_format);
}

void retro_set_video_refresh(retro_video_refresh_t refresh) {
  video_refresh_cb = refresh;
}

void retro_set_audio_sample(retro_audio_sample_t sample) {
  audio_sample_cb = sample;
}

void retro_set_audio_sample_batch(retro_audio_sample_batch_t _batch) {}

void retro_set_input_poll(retro_input_poll_t poll) {
  input_poll_cb = poll;
}

void retro_set_input_state(retro_input_state_t state) {
  input_state_cb = state;
}

void retro_init(void) {
  impl_init();
  emu_state.render_frame = true;
}

void retro_deinit(void) {
  if (emu_state.rom_loaded) {
    free(emu_state.rom_data);
  }
}

unsigned retro_api_version(void) {
  return RETRO_API_VERSION;
}

void retro_get_system_info(struct retro_system_info* info){
    info->library_name = impl_library_name();
    info->library_version = impl_library_version();
    info->block_extract = false;
    info->need_fullpath = false;
    info->valid_extensions = NULL;
}

void retro_get_system_av_info(struct retro_system_av_info* info) {
  impl_get_system_av_info(info);
}

void retro_set_controller_port_device(unsigned port, unsigned device) {}

void retro_reset(void) {
  impl_reset(&emu_state);
}

void retro_run(void) {
  input_poll_cb();

  impl_input_poll(&emu_state, input_state_cb);

  impl_tick(&emu_state);
    
  uint32_t width, height;
  void* data = impl_frame(&width, &height);
  int pitch = width * 4;
  video_refresh_cb(data, width, height, pitch);

  for (uint32_t audio_buffer_size; audio_buffer_size = sb_ring_buffer_size(&emu_state.audio_ring_buff), audio_buffer_size > 2;) {
    uint32_t read0 = emu_state.audio_ring_buff.read_ptr++ % SB_AUDIO_RING_BUFFER_SIZE;
    uint32_t read1 = emu_state.audio_ring_buff.read_ptr++ % SB_AUDIO_RING_BUFFER_SIZE;
    int16_t sample0 = emu_state.audio_ring_buff.data[read0];
    int16_t sample1 = emu_state.audio_ring_buff.data[read1];
    audio_sample_cb(sample0, sample1);
  }
}

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

bool retro_load_game(const struct retro_game_info* game) {  
  if (lr_state.emu_state.rom_loaded) {
    free(lr_state.emu_state.rom_data);
  }
  lr_state.emu_state.rom_loaded = true;
  strncpy(lr_state.emu_state.rom_path, game->path, SB_FILE_PATH_SIZE);
  lr_state.emu_state.rom_data = malloc(game->size);
  memcpy(lr_state.emu_state.rom_data, game->data, game->size);
  lr_state.emu_state.rom_size = game->size;
  
  if (sb_load_rom(&lr_state.emu_state, &lr_state.gb_state, &lr_state.scratch.gb)) {
    lr_state.emu_state.system = SYSTEM_GB;
    return true;
  }

  lr_state.emu_state.rom_loaded = false;
  free(lr_state.emu_state.rom_data);
  return false;
}

bool retro_load_game_special(unsigned game_type, const struct retro_game_info* _info, size_t _num_info) {
  return false;
}

void retro_unload_game(void) {
  lr_state.emu_state.system = SYSTEM_NONE;
}

unsigned retro_get_region(void) {
  return 0;
}

void* retro_get_memory_data(unsigned _id) {
  return 0;
}

size_t retro_get_memory_size(unsigned _id) {
  return 0;
}
