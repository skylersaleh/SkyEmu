
// Purpose of retro_achievements.h and .cpp files:
// - interact with https.hpp/cpp, which is the callback based API for asynchronous HTTPS requests we also use for drive support
// - have access to std::vector and std::unordered_map for the atlas and the image cache

// The rest of the retro achievements related work is in main.c

#ifndef RETRO_ACHIEVEMENTS
#define RETRO_ACHIEVEMENTS
#include "rc_client.h"
#include "mutex.h"
#include <stdint.h>

// All the retro achievements images are placed in separate atlases
// This is because there's a lot of them and they are of similar sizes
typedef struct {
    uint32_t atlas_id;
    float x1, y1;
    float x2, y2;
} atlas_tile_t;

void ra_server_callback(const rc_api_request_t* request,
    rc_client_server_callback_t callback, void* callback_data, rc_client_t* client);
void ra_log_callback(const char* message, const rc_client_t* client);

// Either finds the image in the atlas, sets out_image to it and immediately returns, or starts a download
// and creates a pending callback so out_image is set on the UI thread
void ra_get_image(const char* url, atlas_tile_t* out_image);
void ra_run_pending_callbacks();
void ra_reset();
void ra_cleanup();
void ra_update_atlases();
mutex_t ra_get_mutex(); // TODO: can we delete this and only lock mutex stuff from .cpp file
void ra_dump_atlases();

#endif