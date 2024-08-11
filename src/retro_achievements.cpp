// TODO: use some tool to simulate slow internet connection and try this

#include "sokol_gfx.h"

extern "C" {
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
const char* se_get_pref_path();
void se_push_disabled();
void se_pop_disabled();
void se_text(const char* fmt, ...);
void se_boxed_image_dual_label(const char* title, const char* description, const char* icon,
                               sg_image image, int flags, ImVec2 uv0, ImVec2 uv1);
bool se_button(const char* label, ImVec2 size);
const char* se_localize_and_cache(const char* input_str);
ImFont* se_get_mono_font();
void se_emscripten_flush_fs();
double se_time();
#include "retro_achievements.h"
}

#include "https.hpp"
#include "IconsForkAwesome.h"
#include "rc_client.h"
#include "rc_consoles.h"
#include "sb_types.h"
#include "sokol_time.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#define STBI_ONLY_PNG
#include "stb_image.h"
#include "stb_image_write.h"

const float notification_start_seconds = 0.75f;
const float notification_start_secondary_text_seconds = notification_start_seconds + 3.0f;
const float notification_end_seconds = 6.0f;
const float notification_fade_seconds = notification_end_seconds - notification_start_seconds;
bool only_one_notification = false;
const int atlas_spacing = 4; // leaving some space between tiles to avoid bleeding
const float padding = 7;

// atlases -> the currently existing atlases, each serving a different image
// width/height combo image_cache -> a mapping of image urls to their atlas and
// the coordinates within the atlas download_cache -> a cache of downloaded
// images, so we don't download the same image multiple times

// download_cache has the lifetime of the program
// atlases and image_cache are reset every time the user loads a *different*
// game

struct atlas_t;
struct ra_game_state_t;

using ra_game_state_ptr = std::shared_ptr<ra_game_state_t>;

struct downloaded_image_t
{
    uint8_t* data; // always RGBA
    int width;
    int height;
};

struct ra_achievement_t
{
    atlas_tile_t* tile = nullptr;
    uint32_t id;
    std::string title;
    std::string description;
};

struct ra_bucket_t
{
    uint8_t bucket_id;
    std::string label;
    std::vector<std::unique_ptr<ra_achievement_t>> achievements;
};

struct ra_achievement_list_t
{
    void initialize(ra_game_state_ptr game_state, rc_client_achievement_list_t* list);

    std::vector<ra_bucket_t> buckets{};
};

struct ra_leaderboard_tracker_t
{
    char display[24] = {0};
};

struct ra_challenge_indicator_t
{
    atlas_tile_t* tile = nullptr;
};

struct ra_progress_indicator_t
{
    atlas_tile_t* tile = nullptr;
    std::string title{};
    std::string measured_progress{};
    bool show = false;
};

struct ra_notification_t
{
    atlas_tile_t* tile = nullptr;
    std::string title{};
    std::string submessage{};
    std::string submessage2{};
    float start_time = 0;
};

static std::mutex global_cache_mutex;
static std::unordered_map<std::string, downloaded_image_t*> download_cache;
static std::vector<sg_image> images_to_destroy;

struct ra_game_state_t
{
    ~ra_game_state_t();

    atlas_tile_t* game_image;
    std::vector<atlas_t*> atlases{};
    std::unordered_map<std::string, atlas_tile_t> image_cache{};
    ra_achievement_list_t achievement_list;
    std::unordered_map<uint32_t, ra_leaderboard_tracker_t> leaderboard_trackers;
    std::unordered_map<uint32_t, ra_challenge_indicator_t> challenges;
    ra_progress_indicator_t progress_indicator;
    std::vector<ra_notification_t> notifications;
    std::atomic_int outstanding_requests;
    std::mutex mutex;

    void inc()
    {
        outstanding_requests++;
    }

    void dec()
    {
        outstanding_requests--;
    }
};

struct ra_state_t
{
    explicit ra_state_t(sb_emu_state_t* state) : emu_state(state) {}

    ra_state_t(const ra_state_t&) = delete;
    ra_state_t& operator=(const ra_state_t&) = delete;
    ra_state_t(ra_state_t&&) = delete;
    ra_state_t& operator=(ra_state_t&&) = delete;

    std::string username;
    std::atomic<const char*> error_message = { nullptr };
    sb_emu_state_t* emu_state = nullptr;
    rc_client_t* rc_client = nullptr;

    bool pending_login = false;

    // Game state is a shared_ptr. This is because there's a lot of asynchronous http requests
    // referring to it so every time we need to create such a request, we make a copy of the
    // shared_ptr and pass it to the callback. The data will then go to that state. This way, if
    // before the callback is called the state is destroyed, the data will go to a valid place
    // before the game state is destroyed after the last reference to it is gone. Having a single
    // state that exists for the entirety of the programs lifetime doesn't work. Imagine you load a
    // game, an http request is fired to download the games image, you then load a different game,
    // another http request is fired and finishes earlier, when the first request finishes, the game
    // icon will be that of the old game. For this reason, multiple states need to exist and a
    // global state solution is not viable.
    ra_game_state_ptr game_state;

    void download(ra_game_state_ptr game_state, const std::string& url,
                  const std::function<void()>& callback);
    void handle_downloaded(ra_game_state_ptr game_state, const std::string& url);
    void rebuild_achievement_list(ra_game_state_ptr game_state);
};

static ra_state_t* ra_state = nullptr;

// Atlases are always square and power of two
// This always starts as a single tile image, but if a new tile needs to be
// added, it's resized to the next power of two
struct atlas_t
{
    atlas_t(uint32_t tile_width, uint32_t tile_height)
        : tile_width(tile_width), tile_height(tile_height)
    {
        image.id = SG_INVALID_ID;
    }

    ~atlas_t() = default;
    atlas_t(const atlas_t&) = delete;
    atlas_t& operator=(const atlas_t&) = delete;
    atlas_t(atlas_t&&) = default;
    atlas_t& operator=(atlas_t&&) = default;

    std::vector<uint8_t> data; // we construct the atlas here before uploading it to the GPU
    sg_image image = {};
    int pixel_stride = 0;
    int offset_x = 0,
        offset_y = 0; // to keep track of where next tile needs to be placed, in pixels
    int tile_width, tile_height;
    bool resized = false;
    bool dirty = false; // needs the data to be reuploaded to the GPU

    void copy_image(downloaded_image_t* image)
    {
        dirty = true;

        uint32_t tile_offset_x = offset_x;
        uint32_t tile_offset_y = offset_y;

        offset_x += tile_width + atlas_spacing;
        if (offset_x + tile_width > pixel_stride)
        {
            offset_x = 0;
            offset_y += tile_width + atlas_spacing;
        }

        assert(image->width == tile_width);

        for (int y = 0; y < tile_height; y++)
        {
            for (int x = 0; x < tile_width; x++)
            {
                uint32_t atlas_offset =
                    ((tile_offset_x + x) * 4) + (((tile_offset_y + y) * pixel_stride) * 4);
                uint32_t tile_offset = x * 4 + (y * 4 * tile_width);

                assert(atlas_offset + 3 < data.size());
                assert(tile_offset + 3 < tile_width * tile_height * 4);

                data[atlas_offset + 0] = image->data[tile_offset + 0];
                data[atlas_offset + 1] = image->data[tile_offset + 1];
                data[atlas_offset + 2] = image->data[tile_offset + 2];
                data[atlas_offset + 3] = image->data[tile_offset + 3];
            }
        }
    }
};

namespace
{
    void retro_achievements_game_image_loaded(ra_game_state_ptr game_state)
    {
        const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
        rc_client_user_game_summary_t summary;
        rc_client_get_user_game_summary(ra_state->rc_client, &summary);

        ra_notification_t notification;
        notification.title = "Loaded " + std::string(game->title) + "!";

        int achievement_count = summary.num_core_achievements + summary.num_unofficial_achievements;

        if (achievement_count == 0)
        {
            notification.submessage = "This game has no achievements";
        }
        else
        {
            notification.submessage = std::to_string(achievement_count) + " achievements, " +
                                      std::to_string(summary.points_core) + " points";
            notification.submessage2 = "You have earned " +
                                       std::to_string(summary.num_unlocked_achievements) +
                                       " achievements";
        }

        notification.tile = game_state->game_image;
        notification.start_time = se_time();

        game_state->notifications.push_back(notification);
    }

    ra_achievement_t* retro_achievements_move_bucket(ra_game_state_ptr game_state, uint32_t id,
                                                     uint8_t bucket_id)
    {
        // We need to move the achievement from one bucket to another
        // Unfortunately we don't know which bucket the achievement is in
        // so we need to find it
        // This is preferable to reconstructing the entire list
        ra_achievement_t* achievement_ptr = nullptr;
        for (int i = 0; i < game_state->achievement_list.buckets.size(); i++)
        {
            ra_bucket_t* bucket = &game_state->achievement_list.buckets[i];
            for (int j = 0; j < bucket->achievements.size(); j++)
            {
                if (bucket->achievements[j]->id == id)
                {
                    std::unique_ptr<ra_achievement_t> achievement =
                        std::move(bucket->achievements[j]);
                    bucket->achievements.erase(bucket->achievements.begin() + j);
                    achievement_ptr = achievement.get();

                    // Find correct bucket and place the achievement there
                    bool bucket_found = false;
                    for (int k = 0; k < game_state->achievement_list.buckets.size(); k++)
                    {
                        if (game_state->achievement_list.buckets[k].bucket_id == bucket_id)
                        {
                            game_state->achievement_list.buckets[k].achievements.push_back(
                                std::move(achievement));
                            bucket_found = true;
                            break;
                        }
                    }

                    if (!bucket_found)
                    {
                        ra_bucket_t bucket;
                        bucket.bucket_id = bucket_id;

                        switch (bucket.bucket_id)
                        {
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_LOCKED:
                                bucket.label = "Locked";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNLOCKED:
                                bucket.label = "Unlocked";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNSUPPORTED:
                                bucket.label = "Unsupported";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNOFFICIAL:
                                bucket.label = "Unofficial";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_RECENTLY_UNLOCKED:
                                bucket.label = "Recently Unlocked";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_ACTIVE_CHALLENGE:
                                bucket.label = "Active Challenges";
                                break;
                            case RC_CLIENT_ACHIEVEMENT_BUCKET_ALMOST_THERE:
                                bucket.label = "Almost There";
                                break;
                            default:
                                bucket.label = "Unknown";
                                break;
                        }

                        bucket.achievements.push_back(std::move(achievement));
                        game_state->achievement_list.buckets.emplace(
                            game_state->achievement_list.buckets.begin(), std::move(bucket));
                    }
                    break;
                }
            }
        }

        return achievement_ptr;
    }

    void retro_achievements_achievement_triggered(ra_game_state_ptr game_state,
                                                  const rc_client_achievement_t* rc_achievement)
    {
        // Need a shared_ptr because otherwise it will go out of scope during download
        // With a shared_ptr it won't go out of scope because it will be copied in the callback
        // functor
        std::shared_ptr<ra_notification_t> notification = std::make_shared<ra_notification_t>();

        if (rc_achievement->category == RC_CLIENT_ACHIEVEMENT_CATEGORY_UNOFFICIAL)
        {
            notification->title = "Unofficial achievement unlocked!";
        }
        else
        {
            notification->title = "Achievement unlocked!";
        }

        notification->submessage = rc_achievement->title;
        notification->submessage2 = rc_achievement->description;

        std::string url;
        url.resize(256);
        if (rc_client_achievement_get_image_url(
                rc_achievement, RC_CLIENT_ACHIEVEMENT_STATE_UNLOCKED, &url[0], url.size()) == RC_OK)
        {
            notification->tile = &game_state->image_cache[url];
            uint32_t id = rc_achievement->id;
            uint8_t bucket = rc_achievement->bucket;
            std::unique_lock<std::mutex> lock(game_state->mutex);
            ra_achievement_t* achievement = retro_achievements_move_bucket(game_state, id, bucket);
            game_state->notifications.push_back(*notification);
            ra_state->download(game_state, url, [game_state, notification, url, id, bucket, achievement]() {
                if (achievement)
                {
                    achievement->tile = &game_state->image_cache[url];
                    notification->tile = achievement->tile;
                }
            });
        }
    }

    void
    retro_achievements_progress_indicator_updated(ra_game_state_ptr game_state,
                                                  const rc_client_achievement_t* rc_achievement)
    {
        game_state->progress_indicator.title = std::string("Progress: ") + rc_achievement->title;
        game_state->progress_indicator.measured_progress = rc_achievement->measured_progress;

        std::string url;
        url.resize(256);
        if (rc_client_achievement_get_image_url(rc_achievement, RC_CLIENT_ACHIEVEMENT_STATE_ACTIVE,
                                                &url[0], url.size()) == RC_OK)
        {
            std::unique_lock<std::mutex> lock(game_state->mutex);
            ra_state->download(game_state, url, [game_state, url]() {
                game_state->progress_indicator.tile = &game_state->image_cache[url];
            });
        }
    }

    std::string category_to_icon(uint8_t id)
    {
        switch (id)
        {
            case RC_CLIENT_ACHIEVEMENT_BUCKET_LOCKED:
                return ICON_FK_LOCK;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNLOCKED:
                return ICON_FK_STAR;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNSUPPORTED:
                return ICON_FK_UNLOCK_ALT;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_UNOFFICIAL:
                return ICON_FK_UNLOCK_ALT;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_RECENTLY_UNLOCKED:
                return ICON_FK_UNLOCK;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_ACTIVE_CHALLENGE:
                return ICON_FK_EXCLAMATION;
            case RC_CLIENT_ACHIEVEMENT_BUCKET_ALMOST_THERE:
                return ICON_FK_STAR_HALF;
            default:
                return ICON_FK_QUESTION;
        }
    }

    void retro_achievements_load_game_callback(int result, const char* error_message,
                                               rc_client_t* client, void* userdata)
    {
        ra_game_state_ptr* game_state_ptr = (ra_game_state_ptr*)userdata;
        ra_game_state_ptr game_state = *game_state_ptr;

        if (result != RC_OK)
        {
            // TODO: notification error message?
            printf("[rcheevos]: failed to load game: %s\n", error_message);
        }
        else
        {
            std::string url;
            url.resize(256);
            const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
            if (rc_client_game_get_image_url(game, &url[0], url.size()) == RC_OK)
            {
                std::unique_lock<std::mutex> lock(game_state->mutex);
                ra_state->download(game_state, url, [game_state, url]() {
                    game_state->game_image = &game_state->image_cache[url];
                    retro_achievements_game_image_loaded(game_state);
                });
            }

            ra_state->rebuild_achievement_list(game_state);
        }

        game_state->dec();

        delete game_state_ptr; // delete the pointer that was allocated to pass through ffi
    }

    void retro_achievements_login_callback(int result, const char* error_message,
                                           rc_client_t* client, void* userdata)
    {
        static char buffer[256];
        // TODO: show cool "logged in" banner or something
        ra_state_t* state = (ra_state_t*)userdata;
        const rc_client_user_t* user = rc_client_get_user_info(client);

        if (user)
        {
            printf("[rcheevos]: logged in as %s (score: %d)\n", user->display_name, user->score);

            std::string data;
            data = state->username + "\n" + user->token + "\n";

            std::string path = se_get_pref_path();
            path += "ra_token.txt";

            sb_save_file_data(path.c_str(), (const uint8_t*)data.data(), data.size());
            retro_achievements_load_game();
            se_emscripten_flush_fs();
            ra_state->error_message.store(nullptr);
        } else {
            snprintf(buffer, sizeof(buffer), "Login failed: %s", error_message);
            ra_state->error_message.store(buffer);
        }

        state->pending_login = false;
    }

    void retro_achievements_event_handler(const rc_client_event_t* event, rc_client_t* client)
    {
        switch (event->type)
        {
            case RC_CLIENT_EVENT_ACHIEVEMENT_TRIGGERED:
            {
                ra_game_state_ptr game_state = ra_state->game_state;
                retro_achievements_achievement_triggered(game_state, event->achievement);
                break;
            }
            case RC_CLIENT_EVENT_LEADERBOARD_STARTED:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                ra_notification_t notification;
                notification.title =
                    std::string("Leaderboard attempt started: ") + event->leaderboard->title;
                notification.submessage = event->leaderboard->description;
                notification.tile = game_state->game_image;
                game_state->notifications.push_back(notification);
                break;
            }
            case RC_CLIENT_EVENT_LEADERBOARD_FAILED:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                ra_notification_t notification;
                notification.title =
                    std::string("Leaderboard attempt failed: ") + event->leaderboard->title;
                notification.submessage = event->leaderboard->description;
                notification.tile = game_state->game_image;
                game_state->notifications.push_back(notification);
                break;
            }
            case RC_CLIENT_EVENT_LEADERBOARD_SUBMITTED:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                ra_notification_t notification;
                notification.title = "Leaderboard attempt submitted!";
                notification.submessage = std::string(event->leaderboard->tracker_value) + " for " +
                                          event->leaderboard->title;
                notification.tile = game_state->game_image;
                game_state->notifications.push_back(notification);
                break;
            }
            case RC_CLIENT_EVENT_LEADERBOARD_TRACKER_UPDATE:
            case RC_CLIENT_EVENT_LEADERBOARD_TRACKER_SHOW:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                ra_leaderboard_tracker_t tracker;
                memcpy(tracker.display, event->leaderboard_tracker->display,
                       sizeof(tracker.display));
                game_state->leaderboard_trackers[event->leaderboard_tracker->id] = tracker;
                break;
            }
            case RC_CLIENT_EVENT_LEADERBOARD_TRACKER_HIDE:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                game_state->leaderboard_trackers.erase(event->leaderboard_tracker->id);
                break;
            }
            case RC_CLIENT_EVENT_ACHIEVEMENT_CHALLENGE_INDICATOR_SHOW:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                uint32_t id = event->achievement->id;
                retro_achievements_move_bucket(game_state, event->achievement->id,
                                               event->achievement->bucket);
                ra_challenge_indicator_t indicator;
                game_state->challenges[id] = indicator;
                lock.unlock();

                std::string url;
                url.resize(256);
                if (rc_client_achievement_get_image_url(event->achievement,
                                                        RC_CLIENT_ACHIEVEMENT_STATE_UNLOCKED,
                                                        &url[0], url.size()) == RC_OK)
                {
                    std::unique_lock<std::mutex> lock(game_state->mutex);
                    ra_state->download(game_state, url, [game_state, url, id]() {
                        game_state->challenges[id].tile = &game_state->image_cache[url];
                    });
                }
                break;
            }
            case RC_CLIENT_EVENT_ACHIEVEMENT_CHALLENGE_INDICATOR_HIDE:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                retro_achievements_move_bucket(game_state, event->achievement->id,
                                               RC_CLIENT_ACHIEVEMENT_BUCKET_LOCKED);
                game_state->challenges.erase(event->achievement->id);
                break;
            }
            case RC_CLIENT_EVENT_ACHIEVEMENT_PROGRESS_INDICATOR_SHOW:
            {
                ra_game_state_ptr game_state = ra_state->game_state;
                game_state->progress_indicator.show = true;
                retro_achievements_progress_indicator_updated(game_state, event->achievement);
            }
            case RC_CLIENT_EVENT_ACHIEVEMENT_PROGRESS_INDICATOR_UPDATE:
            {
                retro_achievements_progress_indicator_updated(ra_state->game_state,
                                                              event->achievement);
                break;
            }
            case RC_CLIENT_EVENT_ACHIEVEMENT_PROGRESS_INDICATOR_HIDE:
            {
                ra_game_state_ptr game_state = ra_state->game_state;
                game_state->progress_indicator.show = false;
                break;
            }
            case RC_CLIENT_EVENT_GAME_COMPLETED:
            {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);
                std::string completed =
                    rc_client_get_hardcore_enabled(ra_state->rc_client) ? "Mastered" : "Completed";
                const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
                rc_client_user_game_summary_t summary;
                rc_client_get_user_game_summary(ra_state->rc_client, &summary);
                ra_notification_t notification;
                notification.title = completed + " " + game->title + "!";
                notification.submessage = std::string("All ") +
                                          std::to_string(summary.num_core_achievements) +
                                          " achievements unlocked";
                notification.tile = game_state->game_image;
                game_state->notifications.push_back(notification);
                break;
            }
            case RC_CLIENT_EVENT_RESET:
                ra_state->emu_state->run_mode = SB_MODE_RESET;
                break;
            case RC_CLIENT_EVENT_SERVER_ERROR:
                printf("[rcheevos]: Server error: %s %s\n", event->server_error->api,
                       event->server_error->error_message);
                break;
            default:
                printf("Unhandled event %d\n", event->type);
                break;
        }
    }

    // Used by rcheevos to make http requests
    void retro_achievements_server_callback(const rc_api_request_t* request,
                                            rc_client_server_callback_t callback,
                                            void* callback_data, rc_client_t* client)
    {
        std::string url = request->url;
        std::string post_data = request->post_data;
        http_request_e type;

        if (post_data.empty())
        {
            type = http_request_e::GET;
        }
        else
        {
            type = http_request_e::POST;
        }

        url += "?" + post_data;
        std::vector<std::pair<std::string, std::string>> headers;
#ifndef EMSCRIPTEN
        // TODO(paris): When setting User-Agent from browser side, it sends a CORS
        // preflight request which is makes the request fail.
        headers.push_back({"User-Agent", "SkyEmu/4.0"});
#endif

        https_request(type, url, {}, headers,
                      [callback, callback_data](const std::vector<uint8_t>& result) {
                          if (result.empty())
                          {
                              rc_api_server_response_t response;
                              response.body = nullptr;
                              response.body_length = 0;
                              response.http_status_code = 500; // set it to some server error code to indicate failure
                              callback(&response, callback_data);
                          }
                          else
                          {
                              // Heavy work (http request) is done, do rest of the work in
                              // the ui thread to avoid potential synchronization issues
                              rc_api_server_response_t response;
                              response.body = (const char*)result.data();
                              response.body_length = result.size();
                              response.http_status_code = 200;
                              callback(&response, callback_data);
                          }
                      });
    }

    void retro_achievements_log_callback(const char* message, const rc_client_t* client)
    {
        printf("[rcheevos - internal]: %s\n", message);
    }

    void retro_achievements_draw_achievements()
    {
        if (!ra_state->game_state)
            return;

        std::unique_lock<std::mutex> lock(ra_state->game_state->mutex);
        for (int i = 0; i < ra_state->game_state->achievement_list.buckets.size(); i++)
        {
            if (ra_state->game_state->achievement_list.buckets[i].achievements.empty())
                continue;

            ra_bucket_t* bucket = &ra_state->game_state->achievement_list.buckets[i];
            std::string label = category_to_icon(bucket->bucket_id) + " " +
                                se_localize_and_cache(bucket->label.c_str());
            se_text("%s", label.c_str());
            for (int j = 0; j < bucket->achievements.size(); j++)
            {
                sg_image image = {SG_INVALID_ID};
                ImVec2 uv0, uv1;
                if (bucket->achievements[j]->tile)
                {
                    atlas_tile_t* tile = bucket->achievements[j]->tile;
                    uv0 = ImVec2{tile->x1, tile->y1};
                    uv1 = ImVec2{tile->x2, tile->y2};
                    image.id = tile->atlas_id;
                }

                const auto& achievement = bucket->achievements[j];
                se_boxed_image_dual_label(achievement->title.c_str(),
                                          achievement->description.c_str(), ICON_FK_SPINNER, image,
                                          0, uv0, uv1);
            }
        }
    }
} // namespace

void ra_achievement_list_t::initialize(ra_game_state_ptr game_state,
                                       rc_client_achievement_list_t* list)
{
    std::unique_lock<std::mutex> lock(game_state->mutex);

    buckets.clear();

    buckets.resize(list->num_buckets);

    for (int i = 0; i < list->num_buckets; i++)
    {
        buckets[i].bucket_id = list->buckets[i].bucket_type;
        buckets[i].label = list->buckets[i].label;
        buckets[i].achievements.resize(list->buckets[i].num_achievements);
    }

    for (int i = 0; i < list->num_buckets; i++)
    {
        for (int j = 0; j < list->buckets[i].num_achievements; j++)
        {
            std::string url;
            url.resize(512);

            buckets[i].achievements[j].reset(new ra_achievement_t());
            buckets[i].achievements[j]->id = list->buckets[i].achievements[j]->id;
            buckets[i].achievements[j]->title = list->buckets[i].achievements[j]->title;
            buckets[i].achievements[j]->description = list->buckets[i].achievements[j]->description;

            const rc_client_achievement_t* achievement = list->buckets[i].achievements[j];
            if (rc_client_achievement_get_image_url(achievement, achievement->state, &url[0],
                                                    url.size()) == RC_OK)
            {
                uint32_t id = achievement->id;
                ra_achievement_t* achievement_ptr = buckets[i].achievements[j].get();
                ra_state->download(game_state, url, [game_state, url, achievement_ptr]() {
                    atlas_tile_t* tile = &game_state->image_cache[url];
                    achievement_ptr->tile = tile;
                });
            }

            printf("[rcheevos]: Achievement %s, ", achievement->title);
            if (achievement->id == RC_CLIENT_ACHIEVEMENT_BUCKET_UNSUPPORTED)
                printf("unsupported\n");
            else if (achievement->unlocked)
                printf("unlocked\n");
            else if (achievement->measured_percent)
                printf("progress: %f%%\n", achievement->measured_percent);
            else
                printf("locked\n");
        }
    }

    rc_client_destroy_achievement_list(list);
}

void ra_state_t::download(ra_game_state_ptr game_state, const std::string& url,
                          const std::function<void()>& callback)
{
    std::unique_lock<std::mutex> lock(global_cache_mutex);

    if (download_cache.find(url) != download_cache.end())
    {
        // Great, image was already downloaded in the past and is in the cache
        // First, let's see if there's already an atlas for this image
        if (game_state->image_cache.find(url) != game_state->image_cache.end())
        {
            callback();
            return;
        }
        else
        {
            // We have the image downloaded, but we need to create an atlas for it
            handle_downloaded(game_state, url);
            callback();
            return;
        }
    }
    lock.unlock();

    game_state->inc();
    // The image is not already downloaded, let's download it
    https_request(http_request_e::GET, url, {}, {},
                  [url, game_state, callback](const std::vector<uint8_t>& result) {
                      if (result.empty())
                      {
                          printf("[rcheevos]: empty response from: %s\n", url.c_str());
                          game_state->dec();
                          return;
                      }

                      rc_api_server_response_t response;
                      response.body = (const char*)result.data();
                      response.body_length = result.size();
                      response.http_status_code = 200;

                      downloaded_image_t* image = new downloaded_image_t();
                      image->data =
                          stbi_load_from_memory((const uint8_t*)response.body, response.body_length,
                                                &image->width, &image->height, NULL, 4);

                      if (!image->data)
                      {
                          printf("[rcheevos]: failed to load image from memory\n");
                      }
                      else
                      {
                          std::unique_lock<std::mutex> glock(game_state->mutex);
                          std::unique_lock<std::mutex> lock(global_cache_mutex);
                          download_cache[url] = image;
                          ra_state->handle_downloaded(game_state, url);
                          callback();
                      }

                      game_state->dec();
                  });
}

void ra_state_t::handle_downloaded(ra_game_state_ptr game_state, const std::string& url)
{
    downloaded_image_t* image = download_cache[url];
    atlas_t* atlas = nullptr;

    // Check if we already have an atlas for this exact tile size
    for (atlas_t* a : game_state->atlases)
    {
        if (a->tile_width == image->width && a->tile_height == image->height)
        {
            atlas = a;
            break;
        }
    }

    // Otherwise, create a new atlas
    if (!atlas)
    {
        atlas_t* new_atlas = new atlas_t(image->width, image->height);
        game_state->atlases.push_back(new_atlas);
        atlas = new_atlas;
    }

    // Check if we need to resize the atlas
    uint32_t minimum_width = atlas->offset_x + atlas->tile_width + atlas_spacing;
    uint32_t minimum_height = atlas->offset_y + atlas->tile_height + atlas_spacing;

    if (minimum_width > atlas->pixel_stride || minimum_height > atlas->pixel_stride)
    {
        // We need to resize and upload the atlas later
        atlas->resized = true;

        // Find a sufficient power of two
        uint32_t power = 2;
        uint32_t max = std::max(minimum_width, minimum_height);
        while (power < max)
        {
            power *= 2;

            if (power > 4096)
            {
                printf("Atlas too large\n");
                exit(1);
            }
        }

        uint32_t old_stride = atlas->pixel_stride;
        atlas->pixel_stride = power;
        atlas->offset_x = 0;
        atlas->offset_y = 0;

        std::vector<uint8_t> new_data;
        new_data.resize(power * power * 4);
        atlas->data.swap(new_data);

        // Copy every existing downloaded image of this size
        for (auto& cached_image : game_state->image_cache)
        {
            if (cached_image.second.width == image->width &&
                cached_image.second.height == image->height)
            {
                auto& tile = game_state->image_cache[cached_image.first];
                uint32_t tile_offset_x = atlas->offset_x;
                uint32_t tile_offset_y = atlas->offset_y;
                tile.x1 = (float)tile_offset_x / atlas->pixel_stride;
                tile.y1 = (float)tile_offset_y / atlas->pixel_stride;
                tile.x2 = (float)(tile_offset_x + cached_image.second.width) / atlas->pixel_stride;
                tile.y2 = (float)(tile_offset_y + cached_image.second.height) / atlas->pixel_stride;

                atlas->copy_image(download_cache[cached_image.first]);
            }
        }
    }

    // At this point we should have an atlas that has enough room for our incoming
    // tile
    int offset_x = atlas->offset_x;
    int offset_y = atlas->offset_y;

    atlas->copy_image(image);

    atlas_tile_t* tile = &game_state->image_cache[url];

    tile->atlas_id = atlas->image.id;
    tile->width = image->width;
    tile->height = image->height;
    tile->x1 = (float)offset_x / atlas->pixel_stride;
    tile->y1 = (float)offset_y / atlas->pixel_stride;
    tile->x2 = (float)(offset_x + image->width) / atlas->pixel_stride;
    tile->y2 = (float)(offset_y + image->height) / atlas->pixel_stride;
}

void ra_state_t::rebuild_achievement_list(ra_game_state_ptr game_state)
{
    game_state->achievement_list.initialize(
        game_state,
        rc_client_create_achievement_list(
            rc_client,
            RC_CLIENT_ACHIEVEMENT_CATEGORY_CORE, // TODO: option for _AND_UNOFFICIAL achievements?
            RC_CLIENT_ACHIEVEMENT_LIST_GROUPING_PROGRESS));
}

ra_game_state_t::~ra_game_state_t()
{
    std::unique_lock<std::mutex> lock(global_cache_mutex);
    for (auto& atlas : atlases)
    {
        images_to_destroy.push_back(atlas->image);
        delete atlas;
    }
}

extern "C" uint32_t retro_achievements_read_memory_callback(uint32_t address, uint8_t* buffer,
                                                            uint32_t num_bytes,
                                                            rc_client_t* client);

void retro_achievements_initialize(void* state, bool hardcore, bool is_mobile)
{
    if (is_mobile)
        only_one_notification = true;

    ra_state = new ra_state_t((sb_emu_state_t*)state);
    ra_state->rc_client = rc_client_create(retro_achievements_read_memory_callback,
                                           retro_achievements_server_callback);

    rc_client_enable_logging(ra_state->rc_client, RC_CLIENT_LOG_LEVEL_VERBOSE,
                             retro_achievements_log_callback);

    rc_client_set_hardcore_enabled(ra_state->rc_client, hardcore);
    rc_client_set_event_handler(ra_state->rc_client, retro_achievements_event_handler);

    // RetroAchievements doesn't enable CORS, so we use a reverse proxy
#ifdef SE_PLATFORM_WEB
    rc_api_set_host("https://api.achieve.skyemoo.pandasemi.co");
    rc_api_set_image_host("https://api.achieve.skyemoo.pandasemi.co");
#endif

    std::string path = se_get_pref_path();
    path += "ra_token.txt";

    // Check if we have a token saved
    if (sb_file_exists(path.c_str()))
    {
        size_t size;
        uint8_t* data = sb_load_file_data(path.c_str(), &size);
        if (data)
        {
            std::string text = std::string(data, data + size);

            auto result = std::vector<std::string>{};
            auto ss = std::stringstream{text};

            for (std::string line; std::getline(ss, line, '\n');)
                result.push_back(line);

            ra_state->username = result[0];
            std::string token = result[1];

            if (!ra_state->username.empty() && !token.empty())
            {
                ra_state->pending_login = true;
                rc_client_begin_login_with_token(ra_state->rc_client, ra_state->username.c_str(),
                                                 token.c_str(), retro_achievements_login_callback,
                                                 ra_state);
            }

            free(data);
        }
    }
}

void retro_achievements_shutdown()
{
    // TODO: better way to handle this
    if (ra_state->game_state)
    {
        if (ra_state->game_state.use_count() != 1)
        {
            printf("Waiting for RetroAchievements requests to finish to clean up\n");
            while (ra_state->game_state.use_count() != 1)
            {
                // Wait for all threads to finish and stop owning game_state
#ifndef SE_PLATFORM_WEB
                std::this_thread::sleep_for(std::chrono::milliseconds(0));
#endif
            }
        }
    }

    rc_client_destroy(ra_state->rc_client);

    for (auto& image : images_to_destroy)
    {
        sg_destroy_image(image);
    }

    ra_state->game_state.reset();

    delete ra_state;

    for (auto& download : download_cache)
    {
        stbi_image_free(download.second->data);
        delete download.second;
    }
}

bool retro_achievements_load_game()
{
    if (!ra_state->emu_state->rom_loaded)
        return true;

    const rc_client_user_t* user = rc_client_get_user_info(ra_state->rc_client);
    if (!user)
        return true; // not logged in or login in progress, in which case the game will be loaded
                     // when the login is done

    if (ra_state->game_state && ra_state->game_state->outstanding_requests.load() != 0)
        return false;

    // the old one will be destroyed when the last reference is gone
    ra_state->game_state.reset(new ra_game_state_t());

    // We need to create a shared_ptr*, so we can pass it to the C api.
    ra_game_state_ptr* game_state = new ra_game_state_ptr(ra_state->game_state);

    switch (ra_state->emu_state->system)
    {
        case SYSTEM_GB:
            (*game_state)->inc();
            rc_client_begin_identify_and_load_game(
                ra_state->rc_client, RC_CONSOLE_GAMEBOY, NULL, ra_state->emu_state->rom_data,
                ra_state->emu_state->rom_size, retro_achievements_load_game_callback, game_state);
            break;
        case SYSTEM_GBA:
            (*game_state)->inc();
            rc_client_begin_identify_and_load_game(
                ra_state->rc_client, RC_CONSOLE_GAMEBOY_ADVANCE, NULL,
                ra_state->emu_state->rom_data, ra_state->emu_state->rom_size,
                retro_achievements_load_game_callback, game_state);
            break;
        case SYSTEM_NDS:
            (*game_state)->inc();
            rc_client_begin_identify_and_load_game(
                ra_state->rc_client, RC_CONSOLE_NINTENDO_DS, NULL, ra_state->emu_state->rom_data,
                ra_state->emu_state->rom_size, retro_achievements_load_game_callback, game_state);
            break;
    }

    return true;
}

void retro_achievements_frame()
{
    rc_client_do_frame(ra_state->rc_client);
}

void retro_achievements_login(const char* username, const char* password)
{
    ra_state->pending_login = true;
    ra_state->username = username;
    rc_client_begin_login_with_password(ra_state->rc_client, username, password,
                                        retro_achievements_login_callback, ra_state);
}

void retro_achievements_keep_alive()
{
    static uint64_t last_time = 0;
    if (last_time == 0)
        last_time = stm_now();
    if (ra_state->emu_state->run_mode == SB_MODE_PAUSE)
    {
        if (stm_sec(stm_diff(stm_now(), last_time)) > 1.0)
        {
            last_time = stm_now();
            // Needs to be called once every few seconds if the emulator is paused
            // to keep the session alive or retrying failed unlocks
            rc_client_idle(ra_state->rc_client);
        }
    }
}

atlas_tile_t* retro_achievements_get_game_image()
{
    if (!ra_state->game_state)
        return nullptr;

    return ra_state->game_state->game_image;
}

void retro_achievements_update_atlases()
{
    if (!ra_state->game_state)
        return;

    if (ra_state->game_state->outstanding_requests.load() != 0)
        return; // probably a lot of outstanding requests hold the mutex, let's wait for them to
                // finish before we try to lock ourselves to prevent stuttering

    {
        std::unique_lock<std::mutex> lock(global_cache_mutex);
        for (auto& image : images_to_destroy)
        {
            sg_destroy_image(image);
        }
    }

    std::unique_lock<std::mutex> lock(ra_state->game_state->mutex);

    for (atlas_t* atlas : ra_state->game_state->atlases)
    {
        if (atlas->resized)
        {
            if (atlas->image.id != SG_INVALID_ID)
            {
                sg_destroy_image(atlas->image);
            }
            atlas->image.id = SG_INVALID_ID;
        }

        if (atlas->image.id == SG_INVALID_ID)
        {
            sg_image_desc desc = {0};
            desc.type = SG_IMAGETYPE_2D, desc.render_target = false,
            desc.width = atlas->pixel_stride, desc.height = atlas->pixel_stride,
            desc.num_slices = 1, desc.num_mipmaps = 1, desc.usage = SG_USAGE_DYNAMIC,
            desc.pixel_format = SG_PIXELFORMAT_RGBA8, desc.sample_count = 1,
            desc.min_filter = SG_FILTER_LINEAR, desc.mag_filter = SG_FILTER_LINEAR,
            desc.wrap_u = SG_WRAP_CLAMP_TO_EDGE, desc.wrap_v = SG_WRAP_CLAMP_TO_EDGE,
            desc.wrap_w = SG_WRAP_CLAMP_TO_EDGE,
            desc.border_color = SG_BORDERCOLOR_TRANSPARENT_BLACK, desc.max_anisotropy = 1,
            desc.min_lod = 0.0f, desc.max_lod = 1e9f,

            atlas->image = sg_make_image(&desc);

            if (atlas->resized)
            {
                for (auto& image : ra_state->game_state->image_cache)
                {
                    // Update the images to point to the new atlas instead
                    if (image.second.width == atlas->tile_width &&
                        image.second.height == atlas->tile_height)
                    {
                        image.second.atlas_id = atlas->image.id;
                    }
                }
            }
        }

        if (atlas->dirty)
        {
            sg_image_data data = {0};
            data.subimage[0][0].ptr = atlas->data.data();
            data.subimage[0][0].size = atlas->data.size();
            sg_update_image(atlas->image, data);
        }

        atlas->dirty = false;
        atlas->resized = false;
    }
}

void retro_achievements_draw_panel(int win_w, uint32_t* draw_checkboxes[5])
{
    const rc_client_user_t* user = rc_client_get_user_info(ra_state->rc_client);
    igPushIDStr("RetroAchievements");
    if (!user)
    {
        static char username[256] = {0};
        static char password[256] = {0};
        bool pending_login = ra_state->pending_login;
        se_text("Username");
        igSameLine(win_w - 150, 0);
        if (pending_login)
            se_push_disabled();
        bool enter = igInputText("##Username", username, sizeof(username),
                                 ImGuiInputTextFlags_EnterReturnsTrue, NULL, NULL);
        if (pending_login)
            se_pop_disabled();
        se_text("Password");
        igSameLine(win_w - 150, 0);
        if (pending_login)
            se_push_disabled();
        enter |= igInputText("##Password", password, sizeof(password),
                             ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue,
                             NULL, NULL);
        const char* error_message = ra_state->error_message.load();
        if (error_message) {
            igPushStyleColorVec4(ImGuiCol_Text, ImVec4{1.0f, 0.0f, 0.0f, 1.0f});
            se_text("%s", error_message);
            igPopStyleColor(1);
        }
        if (se_button(ICON_FK_SIGN_IN " Login", ImVec2{0, 0}) || enter)
        {
            retro_achievements_login(username, password);
        }
        if (pending_login)
            se_pop_disabled();
    }
    else
    {
        const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
        ImVec2 pos;
        sg_image image = {SG_INVALID_ID};
        ImVec2 offset1 = {0, 0};
        ImVec2 offset2 = {1, 1};
        const char* play_string = "No Game Loaded";
        char line1[256];
        char line2[256];
        snprintf(line1, 256, se_localize_and_cache("Logged in as %s"), user->display_name);
        atlas_tile_t* game_image = retro_achievements_get_game_image();
        if (game && game_image)
        {
            image.id = game_image->atlas_id;
            offset1 = ImVec2{game_image->x1, game_image->y1};
            offset2 = ImVec2{game_image->x2, game_image->y2};
            snprintf(line2, 256, se_localize_and_cache("Playing: %s"), game->title);
        }
        else
            snprintf(line2, 256, "%s", se_localize_and_cache("No Game Loaded"));
        se_boxed_image_dual_label(line1, line2, ICON_FK_TROPHY, image, 0, offset1, offset2);
        if (se_button(ICON_FK_SIGN_OUT " Logout", ImVec2{0, 0}))
        {
            std::string path = se_get_pref_path();
            path += "ra_token.txt";
            
            ::remove(path.c_str());
            rc_client_logout(ra_state->rc_client);
        }

        std::string settings = ICON_FK_WRENCH " " + std::string(se_localize_and_cache("Settings"));
        se_text(settings.c_str());

        // This is done this way to be able to only use uint32_t on persistent_settings_t, while also using
        // bool for imgui stuff since that's what it needs and not resorting to type punning
        bool draw_checkboxes_bool[5];
        for (int i = 0; i < 5; i++)
        {
            draw_checkboxes_bool[i] = *draw_checkboxes[i];
        }

        if (igCheckbox(se_localize_and_cache("Enable Hardcore Mode"), &draw_checkboxes_bool[0]))
        {
            rc_client_set_hardcore_enabled(ra_state->rc_client, draw_checkboxes_bool[0]);
        }

        igCheckbox(se_localize_and_cache("Enable Notifications"), &draw_checkboxes_bool[1]);
        igCheckbox(se_localize_and_cache("Enable Progress Indicators"),
                   &draw_checkboxes_bool[2]);
        igCheckbox(se_localize_and_cache("Enable Leaderboard Trackers"),
                   &draw_checkboxes_bool[3]);
        igCheckbox(se_localize_and_cache("Enable Challenge Indicators"),
                   &draw_checkboxes_bool[4]);

        for (int i = 0; i < 5; i++)
        {
            *draw_checkboxes[i] = draw_checkboxes_bool[i];
        }

        retro_achievements_draw_achievements();
    }
    igPopID();
}

// https://easings.net/#easeOutBack
float easeOutBack(float t) {
    const float c1 = 1.30158;
    const float c3 = c1 + 1;
    const float t1 = t - 1;
    return 1 + c3 * (t1 * t1 * t1) + c1 * (t1 * t1);
}

void retro_achievements_draw_notifications(float left, float top)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    std::unique_lock<std::mutex> lock(game_state->mutex);

    if (game_state->notifications.empty())
        return;

    float x = left;
    float y = top;

    auto it = game_state->notifications.begin();

    while (it != game_state->notifications.end())
    {
        ra_notification_t& notification = *it;

        float time = se_time() - notification.start_time;

        if (time >= notification_end_seconds)
        {
            it = game_state->notifications.erase(it);
            continue;
        }
        else
        {
            ++it;
        }

        float multiplier = 1.0f;
        if (time > notification_fade_seconds)
        {
            multiplier = (1.0f - (time - notification_fade_seconds) /
                                     (notification_end_seconds - notification_fade_seconds));
        }
        else if (time < notification_start_seconds)
        {
            multiplier = time / notification_start_seconds;
        }

        float easing = easeOutBack(multiplier);
        if (easing < 0.97f)
            continue;

        float padding_adj = padding * easing;

#define ALPHA(x) ((uint32_t)(multiplier * x) << 24)

        float image_width = 64 * easing;
        float image_height = 64 * easing;
        float placard_width =
            padding_adj + 300 * easing + padding_adj; // notifications that have the same width are more appealing
        float wrap_width = placard_width - padding_adj * 2 - image_width;

        float title_height = 0, submessage_height = 0;

        ImVec2 out;
        ImFont* font = igGetFont();
        ImFont_CalcTextSizeA(&out, font, 22.0f * easing, std::numeric_limits<float>::max(), wrap_width,
                             notification.submessage.c_str(), NULL, NULL);
        title_height = out.y;

        ImFont_CalcTextSizeA(&out, font, 18.0f * easing, std::numeric_limits<float>::max(), wrap_width,
                             notification.submessage2.c_str(), NULL, NULL);
        submessage_height = out.y;

        float all_text_height = padding_adj + title_height + padding_adj + submessage_height + padding_adj;
        float image_height_with_padding = padding_adj + image_height + padding_adj;

        float placard_height = std::max(all_text_height, image_height_with_padding);

        auto ig = igGetWindowDrawList();

        // Main box
        ImVec2 top_left = {x, y};
        ImVec2 bottom_right = {x + placard_width, y + placard_height};
        float width = bottom_right.x - top_left.x;
        float height = bottom_right.y - top_left.y;
        top_left.x += (width / 2) * (1 - easing);
        bottom_right.x -= (width / 2) * (1 - easing);
        top_left.y += (height / 2) * (1 - easing);
        bottom_right.y -= (height / 2) * (1 - easing);
        ImDrawList_AddRectFilled(ig, top_left, bottom_right, 0x515151 | ALPHA(180), 8.0f, ImDrawCornerFlags_All);

        // Border
        ImDrawList_AddRect(ig, top_left, bottom_right, 0xffffff | ALPHA(180), 8.0f, ImDrawCornerFlags_All, 2.0f);

        // Image, or a gray square if it's still loading
        ImVec2 img_top_left = {top_left.x + padding_adj, top_left.y + padding_adj};
        ImVec2 img_bottom_right = {img_top_left.x + image_width - padding_adj, img_top_left.y + image_height - padding_adj};
        if (notification.tile && notification.tile->atlas_id != SG_INVALID_ID)
        {
            ImVec2 uv0 = {notification.tile->x1, notification.tile->y1};
            ImVec2 uv1 = {notification.tile->x2, notification.tile->y2};
            ImDrawList_AddImageRounded(ig, (ImTextureID)(intptr_t)notification.tile->atlas_id, img_top_left, img_bottom_right, uv0, uv1, 0xffffff | ALPHA(255), 8.0f, ImDrawCornerFlags_All);
        }
        else
        {
            ImDrawList_AddRectFilled(ig, img_top_left, img_bottom_right, 0x242424 | ALPHA(255), 8.0f, ImDrawCornerFlags_All);
        }

        if (time > notification_start_secondary_text_seconds) 
        {
            float text_time = time - notification_start_secondary_text_seconds;
            float text_half_time = (notification_end_seconds - notification_start_secondary_text_seconds) / 2.0f;
            float text_alpha = 255;
            if (text_time < text_half_time)
            {
                text_alpha = (255 * text_time) / text_half_time;
            }
            text_alpha *= easing;

            ImDrawList_AddTextFontPtr(
                ig, igGetFont(), 22.0f * easing,
                ImVec2{top_left.x + padding_adj + image_width + padding_adj, top_left.y + padding_adj},
                0xffffff | ALPHA(text_alpha), notification.submessage.c_str(), NULL, wrap_width, NULL);
            ImDrawList_AddTextFontPtr(
                ig, igGetFont(), 18.0f * easing,
                ImVec2{top_left.x + padding_adj + image_width + padding_adj, top_left.y + padding_adj + title_height + padding_adj},
                0xc0c0c0 | ALPHA(text_alpha), notification.submessage2.c_str(), NULL, wrap_width, NULL);
        } else {
            float text_time = notification_start_secondary_text_seconds - time;
            float text_half_time = (notification_start_secondary_text_seconds - notification_start_seconds) / 2.0f;
            float text_alpha = 255;
            if (text_time < text_half_time)
            {
                text_alpha = (255 * text_time) / text_half_time;
            }
            text_alpha *= easing;
            ImFont_CalcTextSizeA(&out, font, 22.0f * easing, std::numeric_limits<float>::max(), wrap_width,
                             notification.title.c_str(), NULL, NULL);
            title_height = out.y;
            ImDrawList_AddTextFontPtr(ig, igGetFont(), 22.0f * easing,
                ImVec2{top_left.x + padding_adj + image_width + padding_adj, top_left.y + image_height / 2 - title_height / 2},
                0xffffff | ALPHA(text_alpha), notification.title.c_str(), NULL,
                wrap_width, NULL);
        }

        y += placard_height + padding;

        if (only_one_notification)
            break;
    }
}

void retro_achievements_draw_progress_indicator(float right, float top)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    if (!game_state->progress_indicator.show)
        return;

    ra_progress_indicator_t& indicator = game_state->progress_indicator;

    float image_width = 64;
    float image_height = 64;
    float wrap_width = 200;
    float placard_width = padding + image_width + padding + wrap_width + padding;
    float x = right - placard_width;
    float y = top;

    ImVec2 out;
    ImFont* font = igGetFont();
    ImFont_CalcTextSizeA(&out, font, 22.0f, std::numeric_limits<float>::max(), wrap_width,
                         indicator.measured_progress.c_str(), NULL, NULL);
    float title_height = out.y;
    ImFont_CalcTextSizeA(&out, font, 18.0f, std::numeric_limits<float>::max(), wrap_width,
                         indicator.measured_progress.c_str(), NULL, NULL);
    float progress_height = out.y;

    float placard_height = std::max(padding + title_height + padding + progress_height + padding,
                                    padding + image_height + padding);

    ImDrawList_AddRectFilled(igGetWindowDrawList(), ImVec2{x, y},
                             ImVec2{x + placard_width, y + placard_height}, 0x80515151, 8.0f,
                             ImDrawCornerFlags_All);

    ImDrawList_AddRect(
        igGetWindowDrawList(), ImVec2{x + (padding / 2), y + (padding / 2)},
        ImVec2{x + placard_width - (padding / 2), y + placard_height - (padding / 2)}, 0x80000000,
        8.0f, ImDrawCornerFlags_All, 2.0f);

    if (indicator.tile && indicator.tile->atlas_id != SG_INVALID_ID)
    {
        ImVec2 uv0 = {indicator.tile->x1, indicator.tile->y1};
        ImVec2 uv1 = {indicator.tile->x2, indicator.tile->y2};
        ImDrawList_AddImageRounded(igGetWindowDrawList(),
                                   (ImTextureID)(intptr_t)indicator.tile->atlas_id,
                                   ImVec2{x + padding, y + padding},
                                   ImVec2{x + padding + image_width, y + padding + image_height},
                                   uv0, uv1, 0x80ffffff, 8.0f, ImDrawCornerFlags_All);
    }
    else
    {
        ImDrawList_AddRectFilled(igGetWindowDrawList(), ImVec2{x + 15, y + 15},
                                 ImVec2{x + padding + image_width, y + padding + image_height},
                                 0x80242424, 8.0f, ImDrawCornerFlags_All);
    }

    ImDrawList_AddTextFontPtr(igGetWindowDrawList(), igGetFont(), 22.0f,
                              ImVec2{x + padding + image_width + padding, y + padding}, 0xffffffff,
                              indicator.title.c_str(), NULL, wrap_width, NULL);

    ImDrawList_AddTextFontPtr(
        igGetWindowDrawList(), igGetFont(), 18.0f,
        ImVec2{x + padding + image_width + padding, y + placard_height - padding - progress_height},
        0xff00aaaa, indicator.measured_progress.c_str(), NULL, wrap_width, NULL);
}

void retro_achievements_draw_leaderboard_trackers(float left, float bottom)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    std::unique_lock<std::mutex> lock(game_state->mutex);

    if (game_state->leaderboard_trackers.empty())
        return;

    ImVec2 out;
    float max_text_width;
    float text_height;
    ImFont* font = se_get_mono_font();
    ImFont_CalcTextSizeA(&out, font, 12.0f, std::numeric_limits<float>::max(), 0, "A", NULL, NULL);
    text_height = out.y;

    float x = left;
    float y = bottom - text_height * 3 - padding * 6 - padding * 2;
    int i = 0;

    igPushFont(font);
    for (auto& tracker : game_state->leaderboard_trackers)
    {
        ImFont_CalcTextSizeA(&out, font, 12.0f, std::numeric_limits<float>::max(), 0,
                             tracker.second.display, NULL, NULL);
        float max_text_width = out.x;

        ImDrawList_AddRectFilled(
            igGetWindowDrawList(), ImVec2{x, y},
            ImVec2{x + max_text_width + padding * 2, y + text_height + padding * 2}, 0x80515151, 0,
            0);

        ImDrawList_AddTextFontPtr(
            igGetWindowDrawList(), igGetFont(), 12.0f, ImVec2{x + padding, y + padding}, 0xffffffff,
            tracker.second.display, NULL, std::numeric_limits<float>::max(), NULL);

        if (i++ % 3 != 2)
        {
            x += max_text_width + padding * 3;
        }
        else
        {
            x = left;
            y += text_height + padding * 3;
        }

        if (i == 9)
            break; // show up to 9 trackers
    }
    igPopFont();
}

void retro_achievements_draw_challenge_indicators(float right, float bottom)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    std::unique_lock<std::mutex> lock(game_state->mutex);

    if (game_state->challenges.empty())
        return;

    float x = right - 32 * 3 - padding * 2;
    float y = bottom - 32 * 3 - padding * 2;
    int i = 0;

    for (const auto& item : game_state->challenges)
    {
        const ra_challenge_indicator_t& challenge = item.second;

        if (challenge.tile && challenge.tile->atlas_id != SG_INVALID_ID)
        {
            ImDrawList_AddImage(igGetWindowDrawList(),
                                (ImTextureID)(intptr_t)challenge.tile->atlas_id, ImVec2{x, y},
                                ImVec2{x + 32, y + 32},
                                ImVec2{challenge.tile->x1, challenge.tile->y1},
                                ImVec2{challenge.tile->x2, challenge.tile->y2}, 0x80ffffff);
        }

        if (i++ % 3 != 2)
        {
            x += 32 + padding;
        }
        else
        {
            x = right - 32 * 3 - padding * 2;
            y += 32 + padding;
        }

        if (i == 9)
            break; // show up to 9 trackers
    }
}

void retro_achievements_capture_state(uint8_t *buffer)
{
    if (!ra_state->rc_client)
        return;

    if (!rc_client_get_user_info(ra_state->rc_client))
        return;

    uint32_t buffer_size = (uint32_t)rc_client_progress_size(ra_state->rc_client);
    
    if (buffer_size + 8 > SE_RC_BUFFER_SIZE) {
        printf("RetroAchievements state buffer too small. Need %d bytes\n", buffer_size);
        return;
    }

    if (rc_client_serialize_progress(ra_state->rc_client, buffer + 8) == RC_OK) {
        memcpy(buffer, "RCHV", 4);
        memcpy(buffer + 4, &buffer_size, 4);
    } else {
        printf("Failed to serialize RetroAchievements state\n");
    }
}

void retro_achievements_restore_state(const uint8_t *buffer)
{
    if (!ra_state->rc_client)
        return;

    if (!rc_client_get_user_info(ra_state->rc_client))
        return;

    if (memcmp(buffer, "RCHV", 4) != 0) {
        // When loading a save state that does not have runtime state information,
        // rc_client_deserialize_progress should be called with NULL to reset the runtime state.
        rc_client_deserialize_progress(ra_state->rc_client, NULL);
        return;
    }

    uint32_t buffer_size;
    memcpy(&buffer_size, buffer + 4, 4);

    if (buffer_size + 8 > SE_RC_BUFFER_SIZE) {
        printf("RetroAchievements state buffer too small. Need %d bytes\n", buffer_size);
        return;
    }

    if (rc_client_deserialize_progress(ra_state->rc_client, (const uint8_t*)(buffer + 8)) != RC_OK) {
        printf("Failed to deserialize RetroAchievements state\n");
    }
}