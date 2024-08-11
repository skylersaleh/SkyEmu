
// Purpose of retro_achievements.h and .cpp files:
// - interact with https.hpp/cpp, which is the callback based API for asynchronous HTTPS requests we also use for drive support
// - have access to std::vector and std::unordered_map for the atlas and the image cache

// The rest of the retro achievements related work is in main.c

#ifndef RETRO_ACHIEVEMENTS
#define RETRO_ACHIEVEMENTS
#include <stdint.h>
#include <stdbool.h>

#define SE_RC_BUFFER_SIZE 32768

#ifdef ENABLE_RETRO_ACHIEVEMENTS

typedef struct {
    uint32_t atlas_id;
    uint32_t width, height;
    float x1, y1;
    float x2, y2;
} atlas_tile_t;

void retro_achievements_initialize(void* emu_state, bool hardcore, bool is_mobile);

void retro_achievements_shutdown();

bool retro_achievements_load_game();

void retro_achievements_frame();

void retro_achievements_draw_panel(int win_w, uint32_t* draw_checkboxes[5]);

void retro_achievements_update_atlases();

void retro_achievements_keep_alive();

void retro_achievements_draw_notifications(float left, float top);

void retro_achievements_draw_progress_indicator(float right, float top);

void retro_achievements_draw_leaderboard_trackers(float left, float bottom);

void retro_achievements_draw_challenge_indicators(float right, float bottom);

void retro_achievements_capture_state(uint8_t* buffer);

void retro_achievements_restore_state(const uint8_t* buffer);
#endif

#endif