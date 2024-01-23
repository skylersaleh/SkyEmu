#ifndef LIBRETRO_COMMON
#define LIBRETRO_COMMON 

#include "libretro.h"
#include "sb_types.h"

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_REBIND_TIMER_LENGTH 5.0

#define SE_TRANSPARENT_BG_ALPHA

void impl_init(sb_emu_state_t* emu_state);

bool impl_load_rom(sb_emu_state_t* emu_state);

void impl_get_system_av_info(struct retro_system_av_info* info);

void impl_reset(sb_emu_state_t* emu_state);

void impl_input_poll(sb_emu_state_t* emu_state, retro_input_state_t cb);

void impl_tick(sb_emu_state_t* emu_state);

void* impl_frame(uint32_t* width, uint32_t* height);

const char* impl_library_name();

const char* impl_library_version();

#endif
