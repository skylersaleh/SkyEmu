#include "mutex.h"
#include "sokol_gfx.h"
#include <cstdint>
extern "C" {
  #include "retro_achievements.h"
}
#include "https.hpp"
#include <mutex>
#include <cstring>
#include <thread>
#include <stdio.h>
#include <memory>
#include <regex>
#include <map>
#include <vector>
#define STBI_ONLY_PNG
#include "stb_image.h"

// Access to some parts such as the atlas and the pending callbacks can happen from multiple threads
// so we need to synchronize access to them
std::mutex* synchronization_mutex = new std::mutex();

static const int atlas_spacing = 4; // leaving some space between tiles to avoid bleeding

// Atlases are always square and power of two
// This always starts as a single tile image, but if a new tile needs to be added, it's resized
// to the next power of two
struct atlas_t {
  atlas_t(uint32_t tile_width, uint32_t tile_height) : tile_width(tile_width), tile_height(tile_height) {}
  ~atlas_t() = default;
  atlas_t(const atlas_t&) = delete;
  atlas_t& operator=(const atlas_t&) = delete;
  atlas_t(atlas_t&&) = default;
  atlas_t& operator=(atlas_t&&) = default;

  sg_image image = {};
  std::vector<uint8_t> data; // we construct the atlas here before uploading it to the GPU
  int pixel_stride = 0;
  int offset_x = 0, offset_y = 0; // to keep track of where next tile needs to be placed, in pixels
  int tile_width, tile_height;
  bool resized = false;
  bool dirty = false; // needs the data to be reuploaded to the GPU
};

struct downloaded_image_t {
  uint8_t* data; // always RGBA
  int width;
  int height;
};

// We store the atlases we have for the current game so we can expand them if needed
static std::vector<atlas_t*> atlases;

// Caches downloads of images so we don't have to redownload them if the game is reloaded
static std::map<std::string, downloaded_image_t*> image_cache;

// Some stuff needs to run on the UI thread, such as sg_make_image, so we queue it up
static std::vector<std::function<void()>> pending_callbacks;

// Used by rcheevos to make http requests
extern "C" void ra_server_callback(const rc_api_request_t* request,
    rc_client_server_callback_t callback, void* callback_data, rc_client_t* client)
{
  std::string url = request->url;
  std::string content_type = request->content_type;
  std::string post_data = request->post_data;
  http_request_e type;

  if (post_data.empty())
  {
    type = http_request_e::GET;
  } else {
    type = http_request_e::POST;
  }
  url += "?" + post_data;

#ifndef EMSCRIPTEN
std::thread thread([type, url, post_data, callback, callback_data](){ // TODO: remove this thread?
#endif
  std::vector<std::pair<std::string, std::string>> headers;
  #ifndef EMSCRIPTEN
  // TODO(paris): When setting User-Agent from browser side, it sends a CORS preflight request
  // which is makes the request fail.
  headers.push_back({"User-Agent", "SkyEmu/4.0"});
  #endif
  https_request(type, url, {}, headers, [callback, callback_data](const std::vector<uint8_t>& result) {
    if (result.empty())
    {
      printf("[rcheevos]: empty response\n");
      return;
    }

    // Heavy work (http request) is done, do rest of the work in the ui thread to avoid
    // potential synchronization issues
    std::unique_lock<std::mutex> lock(*synchronization_mutex);
    pending_callbacks.push_back([result, callback, callback_data]() { // TODO: std::move?
      rc_api_server_response_t response;
      response.body = (const char*)result.data();
      response.body_length = result.size();
      response.http_status_code = 200;
      callback(&response, callback_data);
    });
  });
#ifndef EMSCRIPTEN
});
thread.detach();
#endif
}

extern "C" void ra_log_callback(const char* message, const rc_client_t* client)
{
  printf("[rcheevos - internal]: %s\n", message);
}

// We got some data (either by downloading it, or from the cache), let's handle it
void handle_downloaded_image(downloaded_image_t* image, atlas_tile_t* out_image) {
  printf("[rcheevos]: handling downloaded image\n");
  atlas_t* atlas = nullptr;

  // Check if we already have an atlas for this exact tile size
  for (atlas_t* a : atlases) {
    if (a->tile_width == image->width && a->tile_height == image->height) {
      atlas = a;
      break;
    }
  }

  if (!atlas) {
    atlas_t* new_atlas = new atlas_t(image->width, image->height);
    atlases.push_back(new_atlas);
    atlas = new_atlas;
  }

  // Check if we need to resize the atlas
  uint32_t minimum_width = atlas->offset_x + atlas->tile_width + atlas_spacing;
  uint32_t minimum_height = atlas->offset_y + atlas->tile_height + atlas_spacing;
  if (minimum_width > atlas->pixel_stride || minimum_height > atlas->pixel_stride) {
    // We need to resize and upload the atlas later
    atlas->resized = true;

    // Find a sufficient power of two
    uint32_t power = 2048; // TODO: reduce to 256x256
    uint32_t max = std::max(minimum_width, minimum_height);
    while (power < max) {
      power *= 2;

      if (power > 4096) {
        printf("[rcheevos]: making atlas too big (%dx%d), this shouldn't happen\n", power, power);
      }
    }

    uint32_t old_stride = atlas->pixel_stride;
    atlas->pixel_stride = power;

    // Copy the old images to the new atlas
    uint32_t old_offset_x = atlas->offset_x;
    uint32_t old_offset_y = atlas->offset_y;

    atlas->offset_x = 0;
    atlas->offset_y = 0;

    std::vector<uint8_t> new_data;
    new_data.resize(power * power * 4);

    // Copying the old data isn't enough, they also need to be placed to appropriate
    // places in the new atlas since the width of the atlas has been changed
    for (uint32_t y = 0; y < old_offset_y; y += atlas->tile_height + atlas_spacing) {
      for (uint32_t x = 0; x < old_offset_x; x += atlas->tile_width + atlas_spacing) {
        uint32_t old_offset = (x * 4) + (y * old_stride * 4);
        uint32_t new_offset = (atlas->offset_x * 4) + (atlas->offset_y * atlas->pixel_stride * 4);
        new_data[new_offset + 0] = atlas->data[old_offset + 0];
        new_data[new_offset + 1] = atlas->data[old_offset + 1];
        new_data[new_offset + 2] = atlas->data[old_offset + 2];
        new_data[new_offset + 3] = atlas->data[old_offset + 3];

        atlas->offset_x += atlas->tile_width + atlas_spacing;
        if (atlas->offset_x + atlas->tile_width > atlas->pixel_stride) {
          atlas->offset_x = 0;
          atlas->offset_y += atlas->tile_height + atlas_spacing;
        }
      }
    }

    atlas->data.swap(new_data);
  }

  // At this point we should have an atlas that has enough room for our incoming tile

  int offset_x = atlas->offset_x;
  int offset_y = atlas->offset_y;

  // Prepare offsets for next tile
  atlas->offset_x += atlas->tile_width + atlas_spacing;
  if (atlas->offset_x + atlas->tile_width > atlas->pixel_stride) {
    atlas->offset_x = 0;
    atlas->offset_y += atlas->tile_width + atlas_spacing;
  }

  printf("atlas size: %dx%d\n", atlas->pixel_stride, atlas->pixel_stride);

  // Copy tile to atlas
  for (int y = 0; y < atlas->tile_height; y++) {
    for (int x = 0; x < atlas->tile_width; x++) {
      uint32_t atlas_offset = ((offset_x + x) * 4) + (((offset_y + y) * atlas->pixel_stride) * 4);
      atlas->data[atlas_offset + 0] = image->data[x * 4 + (y * 4 * atlas->tile_width) + 0];
      atlas->data[atlas_offset + 1] = image->data[x * 4 + (y * 4 * atlas->tile_width) + 1];
      atlas->data[atlas_offset + 2] = image->data[x * 4 + (y * 4 * atlas->tile_width) + 2];
      atlas->data[atlas_offset + 3] = image->data[x * 4 + (y * 4 * atlas->tile_width) + 3];
    }
  }

  out_image->x1 = (float)offset_x/ atlas->pixel_stride;
  out_image->y1 = (float)offset_y / atlas->pixel_stride;
  out_image->x2 = (float)(offset_x + image->width) / atlas->pixel_stride;
  out_image->y2 = (float)(offset_y + image->height) / atlas->pixel_stride;

  printf("%d %d %d %d\n", atlas->offset_x, atlas->offset_y, image->width, image->height);
  printf("atlas tile: %f %f %f %f\n", out_image->x1, out_image->y1, out_image->x2, out_image->y2);

  // Note: at this point atlas->dirty might be true and we can't be certain we are on the UI thread
  // (this might be called from the UI thread if the image is cached,
  // but it might also be called from a worker thread if the image is being downloaded)
  // Pending callbacks are always ran from the UI thread and only after the atlases have been updated
  // so we push it there
  pending_callbacks.push_back([out_image, atlas](){
    out_image->atlas_id = atlas->image.id;
  });
}

// This should be getting called from the UI thread only, either from the load game callback
// or from the retro achievements event handler
void ra_get_image(const char* url, atlas_tile_t* out_image)
{
  std::unique_lock<std::mutex> lock(*synchronization_mutex);

  if (image_cache.find(url) != image_cache.end())
  {
    // Great, image was already downloaded in the past and is in the cache
    // let's just handle it immediately from this current thread as it is the UI thread
    handle_downloaded_image(image_cache[url], out_image);
    return;
  }

  // When this function returns, the const char* will be invalid, so we need to copy the contents
  std::string url_str = url;
  https_request(http_request_e::GET, url_str, {}, {}, [out_image, url_str](const std::vector<uint8_t>& result) {
      printf("downloaded: %s\n", url_str.c_str());
      std::unique_lock<std::mutex> lock(*synchronization_mutex);
      rc_api_server_response_t response;
      response.body = (const char*)result.data();
      response.body_length = result.size();
      response.http_status_code = 200;

      downloaded_image_t* image = new downloaded_image_t();
      image->data = stbi_load_from_memory((const uint8_t*)response.body, response.body_length, &image->width, &image->height, NULL, 4);
      if (!image->data) {
        printf("[rcheevos]: failed to load image from memory\n");
        return;
      }
      image_cache[url_str] = image;

      pending_callbacks.push_back([image, out_image](){
        handle_downloaded_image(image, out_image);
      });
  });
}

void ra_run_pending_callbacks()
{
  // Pending callbacks is always added to from non-UI threads, so before we run them
  // we need to lock the mutex
  std::unique_lock<std::mutex> lock(*synchronization_mutex);
  if(pending_callbacks.empty())
    return;
  std::vector<std::function<void()>> callbacks;
  callbacks.swap(pending_callbacks);
  lock.unlock();

  for (auto& callback : callbacks)
  {
    callback();
  }
}

void ra_reset() {
  std::unique_lock<std::mutex> lock(*synchronization_mutex);
  for (auto& atlas : atlases) {
    if (atlas->image.id != SG_INVALID_ID) {
      sg_destroy_image(atlas->image);
    }
    delete atlas;
  }
  atlases.clear();
  pending_callbacks.clear();
}

void ra_update_atlases() {
  std::unique_lock<std::mutex> lock(*synchronization_mutex);
  for (atlas_t* atlas : atlases) {
    if (atlas->resized) {
      if (atlas->image.id != SG_INVALID_ID) {
        sg_destroy_image(atlas->image);
      }
      atlas->image.id = SG_INVALID_ID;
    }

    if (atlas->image.id == SG_INVALID_ID) {
      sg_image_data im_data = {0};
      im_data.subimage[0][0].ptr = atlas->data.data();
      im_data.subimage[0][0].size = atlas->data.size();

      sg_image_desc desc = {
        .type=              SG_IMAGETYPE_2D,
        .render_target=     false,
        .width=             atlas->pixel_stride,
        .height=            atlas->pixel_stride,
        .num_slices=        1,
        .num_mipmaps=       1,
        .usage=             SG_USAGE_IMMUTABLE,
        .pixel_format=      SG_PIXELFORMAT_RGBA8,
        .sample_count=      1,
        .min_filter=        SG_FILTER_LINEAR,
        .mag_filter=        SG_FILTER_LINEAR,
        .wrap_u=            SG_WRAP_CLAMP_TO_EDGE,
        .wrap_v=            SG_WRAP_CLAMP_TO_EDGE,
        .wrap_w=            SG_WRAP_CLAMP_TO_EDGE,
        .border_color=      SG_BORDERCOLOR_TRANSPARENT_BLACK,
        .max_anisotropy=    1,
        .min_lod=           0.0f,
        .max_lod=           1e9f,
        .data=              im_data,
      };

      atlas->image = sg_make_image(&desc);
    } else if (atlas->dirty) {
      sg_image_data data = {0};
      data.subimage[0][0].ptr = atlas->data.data();
      data.subimage[0][0].size = atlas->data.size();
      sg_update_image(atlas->image, data);
    }

    atlas->dirty = false;
    atlas->resized = false;
  }
}

mutex_t ra_get_mutex() {
  return synchronization_mutex;
}

void ra_cleanup() {
  ra_reset();
  delete synchronization_mutex;
  for (auto& image : image_cache) {
    stbi_image_free(image.second->data);
    delete image.second;
  }
  image_cache.clear();
}

void ra_dump_atlases() {
  printf("todo\n");
}