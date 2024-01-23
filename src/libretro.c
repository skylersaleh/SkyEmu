#include "SDL2/include/SDL_joystick.h"
#include "SDL2/include/SDL_video.h"
#include "mutex.h"
#include "sb_types.h"
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

// include core headers

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_REBIND_TIMER_LENGTH 5.0

#define SE_TRANSPARENT_BG_ALPHA

#include "gba.h"
#include "nds.h"
#include "gb.h"

// global emu state

struct lr_scratch_t {
  gb_scratch_t gb;
};

static struct lr_state_t {  
  struct lr_scratch_t scratch;
  sb_emu_state_t emu_state;
  sb_gb_t gb_state;
} lr_state;

// SE implementations

bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t* data, size_t data_size) {
  return false;
}

// Retro Arch implementation

#include "libretro.h"

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
  lr_state.gb_state.dmg_palette[0] = 0xff;
  lr_state.gb_state.dmg_palette[1] = 0xcc;
  lr_state.gb_state.dmg_palette[2] = 0x66;
  lr_state.gb_state.dmg_palette[3] = 0x00;
  lr_state.gb_state.dmg_palette[4] = 0xff;
  lr_state.gb_state.dmg_palette[5] = 0xcc;
  lr_state.gb_state.dmg_palette[6] = 0x66;
  lr_state.gb_state.dmg_palette[7] = 0x00;
  lr_state.gb_state.dmg_palette[8] = 0xff;
  lr_state.gb_state.dmg_palette[9] = 0xcc;
  lr_state.gb_state.dmg_palette[10] = 0x66;
  lr_state.gb_state.dmg_palette[11] = 0x00;

  lr_state.emu_state.render_frame = true;
}

void retro_deinit(void) {
  if (lr_state.emu_state.rom_loaded) {
    free(lr_state.emu_state.rom_data);
  }
}

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
  switch (lr_state.emu_state.system) {
  case SYSTEM_GB:
    info->geometry.aspect_ratio = 0.0;
    info->geometry.max_height = SB_LCD_H;
    info->geometry.max_width = SB_LCD_W;
    info->geometry.base_height = info->geometry.max_height;
    info->geometry.base_width = info->geometry.max_width;
    info->timing.fps = 60;
    info->timing.sample_rate = 44100; // TODO: set to something more appropriate?
    break;

  case SYSTEM_GBA: assert(false); // TODO: add GBA core
  case SYSTEM_NDS: assert(false); // TODO: add NDS core
    
  default: assert(false); // should never happen?
  }
}

void retro_set_controller_port_device(unsigned port, unsigned device) {}

void retro_reset(void) {
  switch (lr_state.emu_state.system) {
  case SYSTEM_GB:
    sb_load_rom(&lr_state.emu_state, &lr_state.gb_state, &lr_state.scratch.gb);
    break;

  case SYSTEM_NONE:
  default:;
  }

}

void retro_run(void) {
  input_poll_cb();

  lr_state.emu_state.joy.inputs[SE_KEY_A] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_a);
  lr_state.emu_state.joy.inputs[SE_KEY_B] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_b);
  lr_state.emu_state.joy.inputs[SE_KEY_L] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_l);
  lr_state.emu_state.joy.inputs[SE_KEY_R] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_r);
  lr_state.emu_state.joy.inputs[SE_KEY_DOWN] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_DOWN);
  lr_state.emu_state.joy.inputs[SE_KEY_RIGHT] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RIGHT);
  lr_state.emu_state.joy.inputs[SE_KEY_LEFT] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_LEFT);
  lr_state.emu_state.joy.inputs[SE_KEY_UP] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_UP);
  lr_state.emu_state.joy.inputs[SE_KEY_X] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_x);
  lr_state.emu_state.joy.inputs[SE_KEY_Y] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_y);
  lr_state.emu_state.joy.inputs[SE_KEY_SELECT] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RETURN);
  lr_state.emu_state.joy.inputs[SE_KEY_START] = input_state_cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_ESCAPE);

    
  switch (lr_state.emu_state.system) {
  case SYSTEM_GB:
    sb_tick(&lr_state.emu_state, &lr_state.gb_state, &lr_state.scratch.gb);  
    break;

  case SYSTEM_NONE:
  default:;
  }

  do {
    // video
    void* data;
    int width, height;
    
    switch (lr_state.emu_state.system) {
    case SYSTEM_GB:
      data = lr_state.scratch.gb.framebuffer;      
      width = SB_LCD_W;
      height = SB_LCD_H;
      break;    

    default: break;
    }

    int pitch = width * 4;
    video_refresh_cb(data, width, height, pitch);
  } while (false);
  
  for (uint32_t audio_buffer_size; audio_buffer_size = sb_ring_buffer_size(&lr_state.emu_state.audio_ring_buff), audio_buffer_size > 2;) {
    uint32_t read0 = lr_state.emu_state.audio_ring_buff.read_ptr++ % SB_AUDIO_RING_BUFFER_SIZE;
    uint32_t read1 = lr_state.emu_state.audio_ring_buff.read_ptr++ % SB_AUDIO_RING_BUFFER_SIZE;
    int16_t sample0 = lr_state.emu_state.audio_ring_buff.data[read0];
    int16_t sample1 = lr_state.emu_state.audio_ring_buff.data[read1];
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
