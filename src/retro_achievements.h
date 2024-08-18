
// Purpose of retro_achievements.h and .cpp files:
// - interact with https.hpp/cpp, which is the callback based API for asynchronous HTTPS requests we also use for drive support
// - have access to std::vector and std::unordered_map for the atlas and the image cache

// The rest of the retro achievements related work is in main.c

#ifndef RETRO_ACHIEVEMENTS
#define RETRO_ACHIEVEMENTS
#include <stdint.h>
#include <stdbool.h>
#include "atlas.h"

#define SE_RC_BUFFER_SIZE (256*1024)

#ifdef ENABLE_RETRO_ACHIEVEMENTS

void retro_achievements_initialize(void* emu_state, bool hardcore);

void retro_achievements_shutdown();

bool retro_achievements_load_game();

void retro_achievements_frame();

void retro_achievements_draw_panel();

struct atlas_tile_t* retro_achievements_get_game_image();

struct atlas_tile_t* retro_achievements_get_user_image();

void retro_achievements_login(const char* username, const char* password);

bool retro_achievements_is_pending_login();

struct rc_client_t* retro_achievements_get_client();

const char* retro_achievements_get_login_error();

void retro_achievements_keep_alive();

void retro_achievements_draw_notifications(float left, float top, float screen_width, bool only_one_notification);

void retro_achievements_draw_progress_indicator(float right, float top, float screen_width);

void retro_achievements_draw_leaderboard_trackers(float left, float bottom);

void retro_achievements_draw_challenge_indicators(float right, float bottom, float screen_width);

void retro_achievements_capture_state(uint8_t* buffer);

void retro_achievements_restore_state(const uint8_t* buffer);

bool retro_achievements_has_game_loaded(); 

#endif

#endif