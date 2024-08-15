#include "atlas.h"
#include "https.hpp"
#include "sokol_gfx.h"
#include "stb_image.h"
#include <algorithm>
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

[[noreturn]] void atlas_error(const char* message) {
    fprintf(stderr, "Atlas error: %s\n", message);
    exit(1);
}

struct cached_image_t {
    const uint8_t* data = nullptr;
    uint32_t width, height;
};

struct atlas_tile_t {
    std::atomic_uint32_t atlas_id;
    std::atomic<float> x1, y1, x2, y2;
};

std::mutex image_cache_mutex;
std::unordered_map<std::string, cached_image_t*> image_cache;

std::mutex atlas_maps_mutex;
std::vector<atlas_map_t*> atlas_maps;

std::mutex to_delete_mutex;
std::vector<sg_image> images_to_delete;

struct atlas_t {
    atlas_t(atlas_map_t* map, uint32_t tile_width, uint32_t tile_height);
    ~atlas_t();

    void add_tile(const std::string& url, atlas_tile_t* tile, cached_image_t* cached_image);
    void upload();

private:
    void copy_to_data(atlas_tile_t* tile, cached_image_t* image);

    atlas_map_t* map;
    const uint32_t tile_width, tile_height;

    std::mutex mutex;
    sg_image atlas_image;
    uint32_t atlas_dimension;
    uint32_t offset_x, offset_y;
    std::vector<uint8_t> data;
    std::vector<std::string> image_urls;
    bool dirty;   // new data needs to be uploaded to the GPU
    bool resized; // atlas needs to be destroyed and created at new size

    constexpr static uint32_t padding = 4;
};

struct atlas_map_t {
    ~atlas_map_t() {
        for (auto& pair : atlases) {
            delete pair.second;
        }

        for (auto& pair : total_tiles) {
            delete pair.second;
        }
    }

    atlas_tile_t* add_tile_from_url(const char* url);
    atlas_tile_t* add_tile_from_path(const char* path);
    void wait_all();
    void upload_all();

    std::mutex atlases_mutex;
    std::atomic_int requests = {0};

    // When downloading images we don't know what size they will be until they are downloaded, so we don't know what atlas to put them in
    // This means we need to map urls->atlas_tile_t before we have the image data
    // Creating an atlas_tile_t without mapping it here would mean that if two threads tried to download the same image
    // at the same time, they would both create a new atlas_tile_t and map it later and it would result in a race.
    // With this, the second thread will see that the tile already exists and return that instead.
    std::unordered_map<std::string, atlas_tile_t*> total_tiles;

private:
    atlas_t* get_atlas(uint32_t tile_width, uint32_t tile_height) {
        uint32_t key = tile_width << 16 | tile_height;

        atlas_t* atlas = atlases[key];

        if (atlas == nullptr) {
            atlas = new atlas_t(this, tile_width, tile_height);
            atlases[key] = atlas;
        }

        return atlas;
    }

    std::unordered_map<uint32_t, atlas_t*> atlases;
};

atlas_t::atlas_t(atlas_map_t* map, uint32_t tile_width, uint32_t tile_height) : map(map), tile_width(tile_width), tile_height(tile_height) {
    atlas_image.id = SG_INVALID_ID;
    offset_x = 0;
    offset_y = 0;
    dirty = false;
    resized = false;
    atlas_dimension = 16;
    uint32_t minimum_width = tile_width + padding;
    uint32_t minimum_height = tile_height + padding;
    while (atlas_dimension < minimum_width || atlas_dimension < minimum_height) {
        atlas_dimension *= 2;
    }

    data.resize(atlas_dimension * atlas_dimension * 4);
}

atlas_t::~atlas_t() {
    std::unique_lock<std::mutex> lock(to_delete_mutex);
    images_to_delete.push_back(atlas_image);
}

void atlas_t::copy_to_data(atlas_tile_t* tile, cached_image_t* cached_image) {
    if (tile == nullptr) {
        atlas_error("Tile is null");
    }

    if (cached_image->data == nullptr) {
        atlas_error("Cached image data is null");
    }

    if (cached_image->width != tile_width || cached_image->height != tile_height) {
        atlas_error("Image dimensions do not match atlas tile dimensions");
    }

    dirty = true;

    uint32_t tile_offset_x = offset_x;
    uint32_t tile_offset_y = offset_y;

    offset_x += tile_width + padding;
    if (offset_x + tile_width > atlas_dimension) {
        offset_x = 0;
        offset_y += tile_height + padding;
    }

    for (int y = 0; y < tile_height; y++) {
        for (int x = 0; x < tile_width; x++) {
            uint32_t atlas_offset = ((tile_offset_x + x) * 4) + (((tile_offset_y + y) * atlas_dimension) * 4);
            uint32_t tile_offset = x * 4 + (y * 4 * tile_width);

            data[atlas_offset + 0] = cached_image->data[tile_offset + 0];
            data[atlas_offset + 1] = cached_image->data[tile_offset + 1];
            data[atlas_offset + 2] = cached_image->data[tile_offset + 2];
            data[atlas_offset + 3] = cached_image->data[tile_offset + 3];
        }
    }

    tile->atlas_id = atlas_image.id;
    tile->x1 = (float)tile_offset_x / atlas_dimension;
    tile->y1 = (float)tile_offset_y / atlas_dimension;
    tile->x2 = (float)(tile_offset_x + tile_width) / atlas_dimension;
    tile->y2 = (float)(tile_offset_y + tile_height) / atlas_dimension;
}

void atlas_t::add_tile(const std::string& url, atlas_tile_t* tile, cached_image_t* cached_image) {
    std::unique_lock<std::mutex> lock(mutex);

    if (std::find(image_urls.begin(), image_urls.end(), url) != image_urls.end()) {
        atlas_error("Image already added to atlas");
    }

    image_urls.push_back(url);

    // These are the dimensions that would occur after adding a tile
    uint32_t minimum_x = offset_x + tile_width + padding;
    uint32_t minimum_y = offset_y + tile_height + padding;

    // If the atlas is too small, resize it
    if (minimum_x > atlas_dimension || minimum_y > atlas_dimension) {
        resized = true;
        atlas_dimension *= 2;

        std::vector<uint8_t> new_data;
        new_data.resize(atlas_dimension * atlas_dimension * 4);
        data.swap(new_data);

        offset_x = 0;
        offset_y = 0;

        std::unique_lock<std::mutex> lock(image_cache_mutex);
        for (auto& image_url : image_urls) {
            atlas_tile_t* old_tile = map->total_tiles[image_url];
            cached_image_t* old_cached_image = image_cache[image_url];
            copy_to_data(old_tile, old_cached_image);
        }
    }

    float current_x = offset_x;
    float current_y = offset_y;

    copy_to_data(tile, cached_image);
}

void atlas_t::upload() {
    std::unique_lock<std::mutex> lock(mutex);
    if (resized) {
        sg_destroy_image(atlas_image);
        atlas_image.id = SG_INVALID_ID;
        resized = false;
    }

    if (atlas_image.id == SG_INVALID_ID) {
        sg_image_desc desc = {0};
        desc.type = SG_IMAGETYPE_2D;
        desc.render_target = false;
        desc.width = atlas_dimension;
        desc.height = atlas_dimension;
        desc.num_slices = 1;
        desc.num_mipmaps = 1;
        desc.usage = SG_USAGE_DYNAMIC;
        desc.pixel_format = SG_PIXELFORMAT_RGBA8;
        desc.sample_count = 1;
        desc.min_filter = SG_FILTER_LINEAR;
        desc.mag_filter = SG_FILTER_LINEAR;
        desc.wrap_u = SG_WRAP_CLAMP_TO_EDGE;
        desc.wrap_v = SG_WRAP_CLAMP_TO_EDGE;
        desc.wrap_w = SG_WRAP_CLAMP_TO_EDGE;
        desc.border_color = SG_BORDERCOLOR_TRANSPARENT_BLACK;
        desc.max_anisotropy = 1;
        desc.min_lod = 0.0f;
        desc.max_lod = 1e9f;

        atlas_image = sg_make_image(desc);

        for (auto& image_url : image_urls) {
            atlas_tile_t* tile = map->total_tiles[image_url];
            tile->atlas_id = atlas_image.id;
        }
    }

    if (dirty) {
        sg_image_data sg_data = {0};
        sg_data.subimage[0][0].ptr = data.data();
        sg_data.subimage[0][0].size = data.size();
        sg_update_image(atlas_image, sg_data);
        dirty = false;
    }
}

atlas_tile_t* atlas_map_t::add_tile_from_url(const char* url) {
    std::unique_lock<std::mutex> lock(atlases_mutex);
    const std::string url_str(url);

    // same image can be requested multiple times, so we need to check if it's already in *some* atlas
    if (total_tiles.find(url_str) != total_tiles.end()) {
        return total_tiles[url_str];
    }

    {
        std::unique_lock<std::mutex> lock(image_cache_mutex);
        if (image_cache.find(url_str) != image_cache.end()) {
            cached_image_t* cached_image = image_cache[url_str];
            lock.unlock();

            // If this is reached, the image is in our download cache but not in any atlas
            // This can happen if you restart a game for example, so we add it to an atlas
            // We know the dimensions of the image, so we can add it to the correct atlas immediately 
            atlas_t* atlas = get_atlas(cached_image->width, cached_image->height);
            atlas_tile_t* tile = new atlas_tile_t();
            total_tiles[url_str] = tile;
            atlas->add_tile(url_str, tile, cached_image);
            return tile;
        }
    }

    atlas_tile_t* tile = new atlas_tile_t();
    total_tiles[url_str] = tile;

    requests++;
    https_request(http_request_e::GET, url_str, {}, {}, [this, url_str, tile] (const std::vector<uint8_t>& result) {
        if (result.empty()) {
            printf("Failed to download image for atlas\n");
            requests--;
            return;
        }

        cached_image_t* cached_image = new cached_image_t();
        int width, height;
        cached_image->data = stbi_load_from_memory(result.data(), result.size(), &width, &height, NULL, 4);
        cached_image->width = width;
        cached_image->height = height;

        if (!cached_image->data)
        {
            printf("Failed to load image for atlas\n");
            delete cached_image;
        } else {
            {
                std::unique_lock<std::mutex> lock(image_cache_mutex);
                image_cache[url_str] = cached_image;
            }

            std::unique_lock<std::mutex> lock(atlases_mutex);
            atlas_t* atlas = get_atlas(cached_image->width, cached_image->height);
            atlas->add_tile(url_str, tile, cached_image);
        }

        requests--;
    });

    return tile;
}

atlas_tile_t* atlas_map_t::add_tile_from_path(const char* path) {
    std::unique_lock<std::mutex> lock(atlases_mutex);
    atlas_error("Not implemented");
    return nullptr;
}

void atlas_map_t::wait_all() {
    std::unique_lock<std::mutex> lock(atlases_mutex);
    while (requests > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(15));
    }
}

void atlas_map_t::upload_all() {
    std::unique_lock<std::mutex> lock(atlases_mutex);
    for (auto& pair : atlases) {
        pair.second->upload();
    }
}

atlas_map_t* atlas_create_map() {
    atlas_map_t* map = new atlas_map_t();
    {
        std::unique_lock<std::mutex> lock(atlas_maps_mutex);
        atlas_maps.push_back(map);
    }
    return map;
}

void atlas_destroy_map(atlas_map_t* map) {
    {
        std::unique_lock<std::mutex> lock(atlas_maps_mutex);
        auto it = std::find(atlas_maps.begin(), atlas_maps.end(), map);
        if (it != atlas_maps.end()) {
            atlas_maps.erase(it);
        }
    }

    std::thread delete_thread([map] {
        map->wait_all();
        delete map;
    });
    delete_thread.detach();
}

atlas_tile_t* atlas_add_tile_from_url(atlas_map_t* map, const char* url) {
    if (map == nullptr) {
        atlas_error("Map is null");
    }

    return map->add_tile_from_url(url);
}

atlas_tile_t* atlas_add_tile_from_path(atlas_map_t* map, const char* path) {
    atlas_error("Not implemented");
    return nullptr;
}

void atlas_upload_all() {
    std::unique_lock<std::mutex> lock(atlas_maps_mutex);
    for (atlas_map_t* map : atlas_maps) {
        if (map->requests > 0) {
            continue; // probably a lot of outstanding requests and we don't wanna update too often
        }

        map->upload_all();
    }
    lock.unlock();

    std::unique_lock<std::mutex> dlock(to_delete_mutex);
    for (sg_image image : images_to_delete) {
        sg_destroy_image(image);
    }
    images_to_delete.clear();       
}

uint32_t atlas_get_tile_id(atlas_tile_t* tile) {
    if (tile == nullptr) {
        return 0;
    }

    return tile->atlas_id;
}

atlas_uvs_t atlas_get_tile_uvs(atlas_tile_t* tile) {
    return {tile->x1, tile->y1, tile->x2, tile->y2};
}