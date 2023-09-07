extern "C" {
  #include "retro_achievements.h"
}
#include "rcheevos/include/rc_client.h"
#include "httplib.h"
#include <stdio.h>
#include <future>
#include <memory>
#include <regex>
#include <unordered_map>
#include <vector>
#define STBI_ONLY_PNG
#include "stb_image.h"

rc_client_t* ra_client = NULL;

struct Image
{
  int width = 0, height = 0;
  std::vector<uint8_t> pixel_data;
};

std::unordered_map<std::string, Image> image_cache;

// httplib doesn't have a way to make async requests, so we need to do it ourselves
struct AsyncRequest
{
  std::unique_ptr<httplib::Client> client;
  std::future<httplib::Result> result_future;
  rc_client_server_callback_t callback;
  void* callback_data;
};

struct ImageCallbackData
{
  get_image_callback_t callback;
  void* userdata;
  std::string url;
};

std::vector<AsyncRequest> async_requests;
std::vector<AsyncRequest> async_requests_to_be_added;
std::recursive_mutex async_requests_mutex;

std::pair<std::string, std::string> split_url(const std::string& url)
{
  // Unfortunately request->url gives us the full URL, so we need to extract the GET query
  // to pass to httplib
  // TODO: switch to SSLClient and https, needs OpenSSL
  std::regex path_regex("https://(.*?)(/.*)");
  std::string host = "http://", query;
  std::smatch match;
  if (std::regex_search(url, match, path_regex) && match.size() == 3)
  {
    host += match[1];
    query = match[2];
  }
  else
  {
    printf("[rcheevos]: failed to parse URL: %s\n", url.c_str());
  }
  return std::make_pair(host, query);
}

static void server_callback(const rc_api_request_t* request,
    rc_client_server_callback_t callback, void* callback_data, rc_client_t* client)
{
  std::unique_lock<std::recursive_mutex> lock(async_requests_mutex);
  // RetroAchievements may not allow hardcore unlocks if we don't properly identify ourselves.
  const char* user_agent = "SkyEmu/4.0";

  // TODO: with C++17 we can use structured bindings
  auto pair = split_url(request->url);
  std::string host = pair.first;
  std::string query = pair.second;

  AsyncRequest async_request;
  async_request.client.reset(new httplib::Client(host));

  // Copy it as the request is destroyed as soon as we return
  std::string content_type = request->content_type;
  std::string post_data = request->post_data;
  if(request->post_data)
  {
    httplib::Result (httplib::Client::*gf)(const std::string&, const std::string&, const std::string&) = &httplib::Client::Post;
    async_request.result_future = std::async(std::launch::async, gf, async_request.client.get(), query, post_data, content_type);
  }
  else
  {
    httplib::Result (httplib::Client::*gf)(const std::string&) = &httplib::Client::Get;
    async_request.result_future = std::async(std::launch::async, gf, async_request.client.get(), query);
  }
  async_request.callback = callback;
  async_request.callback_data = callback_data;
  async_requests_to_be_added.push_back(std::move(async_request));
}

static void log_message(const char* message, const rc_client_t* client)
{
  printf("[rcheevos]: %s\n", message);
}

void ra_initialize_client(rc_client_read_memory_func_t memory_read_func)
{
  if(ra_client)
  {
    printf("[rcheevos]: client already initialized!\n");
  }
  else
  {
    ra_client = rc_client_create(memory_read_func, server_callback);
    #ifndef NDEBUG
    rc_client_enable_logging(ra_client, RC_CLIENT_LOG_LEVEL_VERBOSE, log_message);
    #endif
    // TODO: should probably be an option after we're finished testing
    rc_client_set_hardcore_enabled(ra_client, 0);
  }
}

void ra_shutdown_client()
{
  if(ra_client)
  {
    rc_client_destroy(ra_client);
    ra_client = nullptr;
  }
}

bool ra_is_logged_in()
{
  return rc_client_get_user_info(ra_client) != NULL;
}

void ra_login_credentials(const char* username, const char* password, rc_client_callback_t login_callback)
{
  rc_client_begin_login_with_password(ra_client, username, password, login_callback, NULL);
}

void ra_poll_requests()
{
  std::unique_lock<std::recursive_mutex> lock(async_requests_mutex);
  // Check if any of our asynchronous requests have finished, and if so, call the callback
  auto it = async_requests.begin();
  while(it != async_requests.end())
  {
    AsyncRequest& request = *it;
    if (!request.result_future.valid()) {
      it = async_requests.erase(it);
      continue;
    }
    if (request.result_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
    {
      httplib::Result result = request.result_future.get();
      if(result.error() == httplib::Error::Success)
      {
        rc_api_server_response_t response;
        response.body = result->body.c_str();
        response.body_length = result->body.length();
        response.http_status_code = result->status;
        request.callback(&response, request.callback_data);
      }
      else
      {
        printf("[rcheevos]: http request failed: %s\n", to_string(result.error()).c_str());
      }
    }
    ++it;
  }

  // Add any new requests at the end as to not invalidate the iterator
  async_requests.insert(async_requests.end(), std::make_move_iterator(async_requests_to_be_added.begin()), std::make_move_iterator(async_requests_to_be_added.end()));
}

void ra_login_token(const char* username, const char* token, rc_client_callback_t login_callback)
{
  std::string username_str = username;
  std::string token_str = token;
  std::thread login_thread([=](){
    rc_client_begin_login_with_token(ra_client, username_str.c_str(), token_str.c_str(), login_callback, NULL);
  });
  login_thread.detach();
}

void ra_logout()
{
  rc_client_logout(ra_client);
}

void ra_load_game(const uint8_t *rom, size_t rom_size, int console_id, rc_client_callback_t callback)
{
  rc_client_begin_identify_and_load_game(ra_client, console_id, 
      NULL, rom, rom_size, callback, NULL);
}

int ra_get_game_id()
{
  const rc_client_game_t* game = rc_client_get_game_info(ra_client);
  return game->id;
}

void ra_get_game_title(char* buffer, size_t buffer_size)
{
  const rc_client_game_t* game = rc_client_get_game_info(ra_client);
  strncpy(buffer, game->title, buffer_size);
}

static void ra_get_image_callback(const rc_api_server_response_t* server_response, void* callback_data)
{
  ImageCallbackData* data = (ImageCallbackData*)callback_data;

  if(server_response->http_status_code == 200)
  {
    auto& image = image_cache[data->url];
    uint8_t* pixel_data = stbi_load_from_memory((const uint8_t*)server_response->body, server_response->body_length, &image.width, &image.height, NULL, 4);
    image.pixel_data.resize(image.width * image.height * 4);
    memcpy(image.pixel_data.data(), pixel_data, image.pixel_data.size());
    data->callback(image.pixel_data.data(), image.pixel_data.size(), image.width, image.height, data->userdata);
    stbi_image_free(pixel_data);
  }
  else
  {
    printf("[rcheevos]: failed to get image: %s\n", data->url.c_str());
  }

  delete data;
}

void ra_get_image(const char* url, get_image_callback_t callback, void* userdata)
{
  std::unique_lock<std::recursive_mutex> lock(async_requests_mutex);
  auto pair = split_url(url);
  std::string host = pair.first;
  std::string query = pair.second;

  ImageCallbackData* image_callback_data = new ImageCallbackData;
  image_callback_data->callback = callback;
  image_callback_data->userdata = userdata;
  image_callback_data->url = url;

  if (image_cache.find(url) != image_cache.end())
  {
    auto& image = image_cache[url];
    image_callback_data->callback(image.pixel_data.data(), image.pixel_data.size(), image.width, image.height, image_callback_data->userdata);
    delete image_callback_data;
    return;
  }

  AsyncRequest async_request;
  async_request.client.reset(new httplib::Client(host));

  httplib::Result (httplib::Client::*gf)(const std::string&) = &httplib::Client::Get;
  async_request.result_future = std::async(std::launch::async, gf, async_request.client.get(), query);

  async_request.callback = ra_get_image_callback;
  async_request.callback_data = image_callback_data;
  async_requests_to_be_added.push_back(std::move(async_request));
}

rc_client_t* ra_get_client()
{
  return ra_client;
}