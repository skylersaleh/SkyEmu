#ifndef SE_ATLAS_H
#define SE_ATLAS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

typedef struct atlas_uvs_t {
    float x1, y1, x2, y2;
}atlas_uvs_t;
struct atlas_tile_t;
typedef struct atlas_tile_t atlas_tile_t;
struct atlas_map_t;

struct atlas_map_t* atlas_create_map();

void atlas_destroy_map(struct atlas_map_t* map);

// Downloads an image from the url and adds it to the atlas map
// TODO: add hint of atlas total size, so that we can tell it to allocate a bigger atlas or a smaller one if we expect less tiles
struct atlas_tile_t* atlas_add_tile_from_url(struct atlas_map_t* map, const char* url);

// Loads an image from a path and adds it to the atlas map
struct atlas_tile_t* atlas_add_tile_from_path(struct atlas_map_t* map, const char* path);

// Called from the main thread at the end of the frame to update the atlases if needed, for example if there's a need to resize
// or if there are new tiles to add, or if some atlases need to be cleaned up
void atlas_upload_all();

uint32_t atlas_get_tile_id(struct atlas_tile_t* tile);
struct atlas_uvs_t atlas_get_tile_uvs(struct atlas_tile_t* tile);

#ifdef __cplusplus
}
#endif

#endif