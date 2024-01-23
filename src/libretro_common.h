#ifndef LIBRETRO_COMMON
#define LIBRETRO_COMMON 

#include "libretro.h"
#include "sb_types.h"
#include <cstdint>

void impl_init();

void impl_get_system_av_info(struct retro_system_av_info* info);

void impl_reset(sb_emu_state_t* emu_state);

void impl_input_poll(sb_emu_state_t* emu_state, retro_input_state_t cb);

void impl_tick(sb_emu_state_t* emu_state);

void* impl_frame(uint32_t* width, uint32_t* height);

const char* impl_library_name();

const char* impl_library_version();

#endif
