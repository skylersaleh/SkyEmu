#include "libretro_common.h"
#include "sb_types.h"

// these headers are necessary for gb.h
#include <time.h>
#include <math.h>

#include "gb.h"

gb_scratch_t gb_scratch;
sb_gb_t gb;

void impl_init(sb_emu_state_t* emu_state){
  emu_state->system = SYSTEM_GB;

  uint8_t palette[4*3] = { 0xff,0xff,0xff,0xAA,0xAA,0xAA,0x55,0x55,0x55,0x00,0x00,0x00 };
  for(int i = 0; i < 12; ++i) gb.dmg_palette[0] = palette[i];
}

bool impl_load_rom(sb_emu_state_t* emu_state){
  return sb_load_rom(emu_state, &gb, &gb_scratch);
}

void impl_get_system_av_info(struct retro_system_av_info* info) {  
    info->geometry.aspect_ratio = 0.0;
    info->geometry.max_height = SB_LCD_H;
    info->geometry.max_width = SB_LCD_W;
    info->geometry.base_height = info->geometry.max_height;
    info->geometry.base_width = info->geometry.max_width;
    info->timing.fps = 60;
    info->timing.sample_rate = 44100; // TODO: set to something more appropriate?
}

void reset(sb_emu_state_t* emu_state) {  
    sb_load_rom(emu_state, &gb, &gb_scratch);
}

void impl_input_poll(sb_emu_state_t* emu_state, retro_input_state_t cb) {
  emu_state->joy.inputs[SE_KEY_A] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_a);
  emu_state->joy.inputs[SE_KEY_B] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_b);
  emu_state->joy.inputs[SE_KEY_L] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_l);
  emu_state->joy.inputs[SE_KEY_R] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_r);
  emu_state->joy.inputs[SE_KEY_DOWN] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_DOWN);
  emu_state->joy.inputs[SE_KEY_RIGHT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RIGHT);
  emu_state->joy.inputs[SE_KEY_LEFT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_LEFT);
  emu_state->joy.inputs[SE_KEY_UP] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_UP);
  emu_state->joy.inputs[SE_KEY_X] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_x);
  emu_state->joy.inputs[SE_KEY_Y] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_y);
  emu_state->joy.inputs[SE_KEY_SELECT] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_RETURN);
  emu_state->joy.inputs[SE_KEY_START] = cb(0, RETRO_DEVICE_KEYBOARD, 0, RETROK_ESCAPE);
}

void impl_tick(sb_emu_state_t* emu_state) {
    sb_tick(emu_state, &gb, &gb_scratch);  
}

void* impl_frame(uint32_t* width, uint32_t* height){  
      *width = SB_LCD_W;
      *height = SB_LCD_H;
      return gb_scratch.framebuffer;      
}

const char* impl_library_name() {
  return "SkyEmuGb";
}

const char* impl_library_version() {
  return "TODO";
}
