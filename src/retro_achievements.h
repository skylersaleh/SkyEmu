#ifndef RETRO_ACHIEVEMENTS
#define RETRO_ACHIEVEMENTS
#include "rc_client.h"
#include "mutex.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

extern const int atlas_pixel_stride;
extern const int atlas_tile_size;

struct rc_client_t;
typedef struct rc_client_t rc_client_t;

typedef uint32_t (*rc_client_read_memory_func_t)(uint32_t address, uint8_t* buffer, uint32_t num_bytes, rc_client_t* client);
typedef void (*rc_client_callback_t)(int result, const char* error_message, rc_client_t* client, void* user_data);

typedef void (*ra_download_callback_t)(const uint8_t* data, size_t data_size, void* user_data);

// REMOVE most of these
void ra_initialize_client(rc_client_read_memory_func_t memory_read_func);
void ra_load_game(const uint8_t* rom, size_t rom_size, int console_id, rc_client_callback_t callback);
void ra_get_image(const char* url, ra_download_callback_t callback, void* user_data);
void ra_run_pending_callbacks();
void ra_unset_pending_login();
rc_client_t* ra_get_client();
rc_client_achievement_list_t* ra_get_achievements();
void ra_invalidate_achievements();
mutex_t ra_get_mutex();
#endif