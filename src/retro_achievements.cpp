extern "C" {
  #include "retro_achievements.h"
}
#include "rcheevos/include/rc_client.h"
#include "httplib.h"
#include <stdio.h>
#include <future>
#include <memory>
#include <regex>

rc_client_t* ra_client = NULL;

// httplib doesn't have a way to make async requests, so we need to do it ourselves
struct AsyncRequest
{
  std::unique_ptr<httplib::Client> client;
  std::future<httplib::Result> result_future;
  rc_client_server_callback_t callback;
  void* callback_data;
};

std::vector<AsyncRequest*> async_requests;

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
  // RetroAchievements may not allow hardcore unlocks if we don't properly identify ourselves.
  const char* user_agent = "SkyEmu/4.0";

  // TODO: with C++17 we can use structured bindings
  auto pair = split_url(request->url);
  std::string host = pair.first;
  std::string query = pair.second;

  AsyncRequest* async_request = new AsyncRequest;
  async_request->client.reset(new httplib::Client(host));

  // Copy it as the request is destroyed as soon as we return
  std::string content_type = request->content_type;
  std::string post_data = request->post_data;
  if(request->post_data)
  {
    httplib::Result (httplib::Client::*gf)(const std::string&, const std::string&, const std::string&) = &httplib::Client::Post;
    async_request->result_future = std::async(std::launch::async, gf, async_request->client.get(), query, post_data, content_type);
  }
  else
  {
    httplib::Result (httplib::Client::*gf)(const std::string&) = &httplib::Client::Get;
    async_request->result_future = std::async(std::launch::async, gf, async_request->client.get(), query);
  }
  async_request->callback = callback;
  async_request->callback_data = callback_data;
  async_requests.push_back(async_request);
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
  // Check if any of our asynchronous requests have finished, and if so, call the callback
  auto it = async_requests.begin();
  while(it != async_requests.end())
  {
    AsyncRequest* request = *it;
    if (request->result_future.wait_for(std::chrono::seconds(0)) == std::future_status::ready)
    {
      httplib::Result result = request->result_future.get();
      it = async_requests.erase(it);
      if(result.error() == httplib::Error::Success)
      {
        rc_api_server_response_t response;
        response.body = result->body.c_str();
        response.body_length = result->body.length();
        response.http_status_code = result->status;
        request->callback(&response, request->callback_data);
      }
      else
      {
        printf("[rcheevos]: http request failed: %s\n", to_string(result.error()).c_str());
      }
      delete request;
    }
    else
    {
      ++it;
    }
  }
}

void ra_login_token(const char* username, const char* token, rc_client_callback_t login_callback)
{
  rc_client_begin_login_with_token(ra_client, username, token, login_callback, NULL);
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

void ra_get_game_image(uint8_t** buffer, size_t* buffer_size)
{
  *buffer = nullptr;
  *buffer_size = 0;

  std::array<char, 128> url;
  const rc_client_game_t* game = rc_client_get_game_info(ra_client);
  if (rc_client_game_get_image_url(game, url.data(), url.size()) != RC_OK)
  {
    printf("[rcheevos]: could not get game image URL\n");
    return;
  }

  auto pair = split_url(url.data());
  std::string host = pair.first;
  std::string query = pair.second;

  httplib::Client client(host);
  httplib::Result result = client.Get(query);

  if(result.error() == httplib::Error::Success)
  {
    std::string image_data = result->body;
    uint8_t* image = (uint8_t*)malloc(image_data.length());
    memcpy(image, image_data.data(), image_data.length());
    *buffer = image;
    *buffer_size = image_data.length();
  }
  else
  {
    printf("[rcheevos]: http request failed: %s\n", to_string(result.error()).c_str());
  }
}

rc_client_t* ra_get_client()
{
  return ra_client;
}