#include "libretro.h"
#include "libretro_common.h"

#include "sb_types.h"
#include "gba.h"

static gba_scratch_t gba_scratch;
static gba_t gba;

void impl_init(sb_emu_state_t* emu_state) {
  emu_state->system = SYSTEM_GBA;
}

bool impl_load_rom(sb_emu_state_t* emu_state) {
  return gba_load_rom(emu_state, &gba, &gba_scratch);
}

void impl_get_system_av_info(struct retro_system_av_info* info) {
  info->geometry.aspect_ratio = 1.0;
  info->geometry.max_width = GBA_LCD_W;
  info->geometry.max_height = GBA_LCD_H;
  info->geometry.base_width = info->geometry.max_width;
  info->geometry.base_height = info->geometry.max_height; 
  info->timing.fps = 60;
  info->timing.sample_rate = SE_AUDIO_SAMPLE_RATE;
}

int impl_get_pixel_format() {
  return RETRO_PIXEL_FORMAT_XRGB8888;
}

void impl_reset(sb_emu_state_t* emu_state) {
  gba_load_rom(emu_state, &gba, &gba_scratch);
}

void impl_input_poll(sb_emu_state_t* emu_state, retro_input_state_t cb) {
    emu_state->joy.inputs[SE_KEY_A] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_a);
    emu_state->joy.inputs[SE_KEY_B] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_b);
    emu_state->joy.inputs[SE_KEY_SELECT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RETURN);
    emu_state->joy.inputs[SE_KEY_START] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_ESCAPE);
    emu_state->joy.inputs[SE_KEY_RIGHT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RIGHT);
    emu_state->joy.inputs[SE_KEY_LEFT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_LEFT);
    emu_state->joy.inputs[SE_KEY_UP] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_UP);
    emu_state->joy.inputs[SE_KEY_DOWN] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_DOWN);
    emu_state->joy.inputs[SE_KEY_R] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_r);
    emu_state->joy.inputs[SE_KEY_L] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_l);
}

void impl_tick(sb_emu_state_t* emu_state) {
  gba_tick(emu_state, &gba, &gba_scratch);
}

static uint8_t flipped_frame[sizeof gba_scratch.framebuffer];

void* impl_frame(uint32_t* width, uint32_t* height) {
  *width = GBA_LCD_W;
  *height = GBA_LCD_H;
  for (int i = 0; i < sizeof(flipped_frame); i += 4) {
    // NOTE: assume little endian
    flipped_frame[i + 0] = gba_scratch.framebuffer[i + 2]; // blue
    flipped_frame[i + 1] = gba_scratch.framebuffer[i + 1]; // green
    flipped_frame[i + 2] = gba_scratch.framebuffer[i + 0]; // red
    flipped_frame[i + 3] = 0; // ignored
  }
  return flipped_frame;
}

const char* impl_library_name() {  
  return "SkyEmuGba";
}

const char* impl_library_version() {
  return SKYEMO_LIBRETRO_VERSION;
}

