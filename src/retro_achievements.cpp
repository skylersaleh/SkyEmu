#include "mutex.h"
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

#include <fstream>

const int atlas_pixel_stride = 2048;
const int atlas_tile_size = 64; // all images in the atlas will be 64x64
std::mutex* synchronization_mutex = new std::mutex();

static rc_client_t* ra_client = nullptr;
static rc_client_achievement_list_t* achievements = nullptr;
static bool atlas_needs_update = false;

static std::vector<uint8_t> atlas_data;
static const int atlas_spacing = 4;
static int atlas_offset_x = 0; // to keep track of where next tile needs to be placed, in pixels
static int atlas_offset_y = 0;
static std::map<std::string, std::vector<uint8_t>> image_cache; // TODO: cache of ra_image is bad - refactor to use data only
static std::vector<std::function<void()>> pending_callbacks;

static void server_callback(const rc_api_request_t* request,
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
std::thread thread([type, url, post_data, callback, callback_data](){
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
    std::lock_guard<std::mutex> lock(*synchronization_mutex);
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

static void log_message(const char* message, const rc_client_t* client)
{
  printf("[rcheevos - internal]: %s\n", message);
}

void ra_initialize_client(rc_client_read_memory_func_t memory_read_func)
{
  if(ra_client)
  {
    printf("[rcheevos]: client already initialized\n");
  }
  else
  {
    ra_client = rc_client_create(memory_read_func, server_callback);
    // RetroAchievements doesn't enable CORS, so we use a reverse proxy
    rc_api_set_host("https://api.achieve.skyemoo.pandasemi.co");
    rc_api_set_image_host("https://media.retroachievements.org");
    #ifndef NDEBUG
    rc_client_enable_logging(ra_client, RC_CLIENT_LOG_LEVEL_VERBOSE, log_message);
    #endif
    // TODO: should probably be an option after we're finished testing
    rc_client_set_hardcore_enabled(ra_client, 0);
  }
}

void ra_add_image(ra_image image, ra_image* out_image) {
  sg_image_data im_data = {0};
  im_data.subimage[0][0].ptr = image.pixel_data;
  im_data.subimage[0][0].size = image.width * image.height * 4;
  sg_image_desc desc={
    .type=              SG_IMAGETYPE_2D,
    .render_target=     false,
    .width=             image.width,
    .height=            image.height,
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

  image.id = sg_make_image(&desc).id;
  stbi_image_free(image.pixel_data);
  image.pixel_data = nullptr;

  *out_image = image;
}

void ra_load_game(const uint8_t *rom, size_t rom_size, int console_id, rc_client_callback_t callback)
{
  // Make a copy of the ROM as the original may be destroyed before the thread finishes
  std::vector<uint8_t> rom_copy(rom, rom + rom_size);
#ifndef EMSCRIPTEN
  std::thread load_thread([rom_copy, console_id, callback](){
#endif
  rc_client_begin_identify_and_load_game(ra_client, console_id, 
    NULL, rom_copy.data(), rom_copy.size(), callback, NULL);
#ifndef EMSCRIPTEN
  });
  load_thread.detach();
#endif
}

void ra_get_image(const char* url, ra_image* out_image)
{
  std::lock_guard<std::mutex> lock(*synchronization_mutex);
  if (image_cache.find(url) != image_cache.end())
  {
    auto& image = image_cache[url];
    pending_callbacks.push_back([out_image, image](){
      // callback(image, user_data);
    });
    return;
  }

  std::string url_str = url;
  #ifndef EMSCRIPTEN
  std::thread thread([url_str, out_image](){
  #endif
  https_request(http_request_e::GET, url_str, {}, {}, [out_image, url_str](const std::vector<uint8_t>& result) {
      std::lock_guard<std::mutex> lock(*synchronization_mutex);
      rc_api_server_response_t response;
      response.body = (const char*)result.data();
      response.body_length = result.size();
      response.http_status_code = 200;
      auto& image = image_cache[url_str];
      image.pixel_data = stbi_load_from_memory((const uint8_t*)response.body, response.body_length, &image.width, &image.height, NULL, 4);

      bool is_atlas_tile = image.width == atlas_tile_size && image.height == atlas_tile_size;
      if (is_atlas_tile) {
        image.offset_x = atlas_offset_x;
        image.offset_y = atlas_offset_y;

        // Prepare offsets for next tile
        atlas_offset_x += atlas_tile_size + atlas_spacing;
        if (atlas_offset_x + atlas_tile_size > atlas_pixel_stride) {
          atlas_offset_x = 0;
          atlas_offset_y += atlas_tile_size + atlas_spacing;
        }

        image.id = atlas.id;
        int offset_x = image.offset_x;
        int offset_y = image.offset_y;

        if (atlas_data.empty()) {
          atlas_data.resize(atlas_pixel_stride * atlas_pixel_stride * 4);
        }

        // Copy tile to atlas
        for (int y = 0; y < atlas_tile_size; y++) {
          for (int x = 0; x < atlas_tile_size; x++) {
            uint32_t atlas_offset = ((offset_x + x) * 4) + (((offset_y + y) * atlas_pixel_stride) * 4);
            atlas_data[atlas_offset + 0] = image.pixel_data[x * 4 + (y * 4 * atlas_tile_size) + 0];
            atlas_data[atlas_offset + 1] = image.pixel_data[x * 4 + (y * 4 * atlas_tile_size) + 1];
            atlas_data[atlas_offset + 2] = image.pixel_data[x * 4 + (y * 4 * atlas_tile_size) + 2];
            atlas_data[atlas_offset + 3] = image.pixel_data[x * 4 + (y * 4 * atlas_tile_size) + 3];
          }
        }
        std::ofstream file("atlas_data.bin", std::ios::binary);
        file.write((const char*)atlas_data.data(), atlas_data.size());
        file.close();
        stbi_image_free(image.pixel_data);
        image.pixel_data = nullptr;
        atlas_needs_update = true;
        *out_image = image;
      } else {
        // pending_callbacks.push_back([callback, user_data, image](){
        //   ra_add_image(image, callback, user_data);
        // });
      }
  });
  #ifndef EMSCRIPTEN
  });
  thread.detach();
  #endif
}

void ra_run_pending_callbacks()
{
  // std::lock_guard<std::mutex> lock(image_cache_mutex);
  // if(pending_callbacks.empty())
  //   return;

  // for (auto& callback : pending_callbacks)
  // {
  //   callback();
  // }
  // pending_callbacks.clear();
}

rc_client_t* ra_get_client()
{
  return ra_client;
}

rc_client_achievement_list_t* ra_get_achievements()
{
  return achievements;
}

void ra_invalidate_achievements()
{
  if(achievements)
  {
    rc_client_destroy_achievement_list(achievements);
  }
  achievements = rc_client_create_achievement_list(ra_client,
    RC_CLIENT_ACHIEVEMENT_CATEGORY_CORE_AND_UNOFFICIAL,
    RC_CLIENT_ACHIEVEMENT_LIST_GROUPING_PROGRESS);
}

int ra_get_atlas_size() {
  return atlas_pixel_stride;
}

void ra_update_atlas() { // TODO: move to main
  std::lock_guard<std::mutex> lock(*synchronization_mutex);
  if (atlas_needs_update) {
      if (atlas.id == SG_INVALID_ID) {
        printf("[rcheevos]: atlas not created\n");
        return;
      }
      sg_image_data data = {0};
      data.subimage[0][0].ptr = atlas_data.data();
      data.subimage[0][0].size = atlas_data.size();
      sg_update_image(atlas, data);
      atlas_needs_update = false;
  }
}

mutex_t ra_get_mutex() {
  return synchronization_mutex;
}