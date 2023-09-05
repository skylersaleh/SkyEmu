#ifndef RETRO_ACHIEVEMENTS
#define RETRO_ACHIEVEMENTS
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct rc_client_t;
typedef struct rc_client_t rc_client_t;

typedef uint32_t (*rc_client_read_memory_func_t)(uint32_t address, uint8_t* buffer, uint32_t num_bytes, rc_client_t* client);
typedef void (*rc_client_callback_t)(int result, const char* error_message, rc_client_t* client, void* userdata);
typedef void(*get_image_callback_t)(const uint8_t* buffer, size_t buffer_size, int width, int height, void* userdata);

bool ra_is_logged_in();
void ra_initialize_client(rc_client_read_memory_func_t memory_read_func);
void ra_login_credentials(const char* username, const char* password, rc_client_callback_t login_callback);
void ra_login_token(const char* username, const char* token, rc_client_callback_t login_callback);
void ra_poll_requests();
void ra_shutdown_client();
void ra_logout();
void ra_load_game(const uint8_t* rom, size_t rom_size, int console_id, rc_client_callback_t callback);
int ra_get_game_id();
void ra_get_game_title(char* buffer, size_t buffer_size);
void ra_get_image(const char* url, get_image_callback_t callback, void* userdata);
rc_client_t* ra_get_client();
#endif