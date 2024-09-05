#include "sokol_gfx.h"

extern "C" {
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "retro_achievements.h"

const char* se_get_pref_path();
void se_push_disabled();
void se_pop_disabled();
void se_boxed_image_triple_label(const char* first_label, const char* second_label, const char* third_label, uint32_t third_label_color, const char* box, atlas_tile_t* atlas, bool glow);

void se_section(const char* label,...);
const char* se_localize_and_cache(const char* input_str);
ImFont* se_get_mono_font();
void se_emscripten_flush_fs();
double se_time();
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
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
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
const float notification_start_secondary_text_seconds = notification_start_seconds + 1.25f;
const float notification_end_seconds = 4.0f;
const float notification_fade_seconds = notification_end_seconds - notification_start_seconds;
const float padding = 7;

struct atlas_t;
struct ra_game_state_t;

using ra_game_state_ptr = std::shared_ptr<ra_game_state_t>;

std::atomic_bool loading_game = { false };

struct ra_achievement_t
{
    atlas_tile_t* tile = nullptr;
    uint32_t id;
    std::string title;
    std::string description;
    float percentage;
    float rarity;
    float rarity_hardcore;
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
    float measured_percent = 0;
    bool show = false;
};

struct ra_notification_t
{
    atlas_tile_t* tile = nullptr;
    std::string title{};
    std::string submessage{};
    std::string submessage2{};
    float start_time = 0;
    uint32_t leaderboard_id = 0;
    uint32_t leaderboard_format = NUM_RC_CLIENT_LEADERBOARD_FORMATS;
};

struct ra_game_state_t
{
    ra_game_state_t() {
        atlas_map = atlas_create_map();
        game_image = nullptr;
    }

    ~ra_game_state_t() {
        atlas_destroy_map(atlas_map);
    }

    std::mutex mutex;
    atlas_map_t* atlas_map;
    atlas_tile_t* game_image;
    ra_achievement_list_t achievement_list;
    std::unordered_map<uint32_t, ra_leaderboard_tracker_t> leaderboard_trackers;
    std::unordered_map<uint32_t, ra_challenge_indicator_t> challenges;
    ra_progress_indicator_t progress_indicator;
    std::vector<ra_notification_t> notifications;
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
    atlas_map_t* user_image_atlas = nullptr;
    atlas_tile_t* user_image = nullptr;

    std::atomic_bool pending_login = { false };

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

    void rebuild_achievement_list(ra_game_state_ptr game_state);
};

static ra_state_t* ra_state = nullptr;

namespace
{
    void retro_achievements_game_image_loaded(ra_game_state_ptr game_state)
    {
        const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
        rc_client_user_game_summary_t summary;
        rc_client_get_user_game_summary(ra_state->rc_client, &summary);

        ra_notification_t notification;
        notification.title = game->title;

        bool unofficial_enabled = rc_client_get_unofficial_enabled(ra_state->rc_client);
        int achievement_count = summary.num_core_achievements;
        int unlocked_achievement_count = summary.num_unlocked_achievements;

        if (achievement_count == 0)
        {
            notification.submessage = "This game has no achievements";
        }
        else
        {
            notification.submessage = "You have " + std::to_string(unlocked_achievement_count) + " of " + std::to_string(achievement_count) + " achievements unlocked.";
            notification.submessage2 = "Points: " + std::to_string(summary.points_unlocked) + "/" + std::to_string(summary.points_core);
        }

        notification.tile = game_state->game_image;

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
            uint32_t id = rc_achievement->id;
            uint8_t bucket = rc_achievement->bucket;
            std::unique_lock<std::mutex> lock(game_state->mutex);
            ra_achievement_t* achievement = retro_achievements_move_bucket(game_state, id, bucket);
            notification->tile = atlas_add_tile_from_url(game_state->atlas_map, url.c_str());
            achievement->tile = notification->tile;
            game_state->notifications.push_back(*notification);
        }
    }

    void
    retro_achievements_progress_indicator_updated(ra_game_state_ptr game_state,
                                                  const rc_client_achievement_t* rc_achievement)
    {
        game_state->progress_indicator.title = std::string("Progress: ") + rc_achievement->title;
        game_state->progress_indicator.measured_progress = rc_achievement->measured_progress;
        game_state->progress_indicator.measured_percent = rc_achievement->measured_percent;

        std::string url;
        url.resize(256);
        if (rc_client_achievement_get_image_url(rc_achievement, RC_CLIENT_ACHIEVEMENT_STATE_ACTIVE,
                                                &url[0], url.size()) == RC_OK)
        {
            std::unique_lock<std::mutex> lock(game_state->mutex);
            game_state->progress_indicator.tile = atlas_add_tile_from_url(game_state->atlas_map, url.c_str());
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
                game_state->game_image = atlas_add_tile_from_url(game_state->atlas_map, url.c_str());
                retro_achievements_game_image_loaded(game_state);
            }

            ra_state->rebuild_achievement_list(game_state);
        }

        delete game_state_ptr; // delete the pointer that was allocated to pass through ffi
        loading_game = false;
    }

    void retro_achievements_login_callback(int result, const char* error_message,
                                           rc_client_t* client, void* userdata)
    {
        static char buffer[256];
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
            se_emscripten_flush_fs();
            ra_state->error_message.store(nullptr);

            std::string url;
            url.resize(256);
            if (rc_client_user_get_image_url(user, &url[0], url.size()) == RC_OK)
            {
                ra_state->user_image = atlas_add_tile_from_url(ra_state->user_image_atlas, url.c_str());
            }
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
            case RC_CLIENT_EVENT_LEADERBOARD_SCOREBOARD: {
                ra_game_state_ptr game_state = ra_state->game_state;

                std::unique_lock<std::mutex> lock(game_state->mutex);

                // Find the existing notification from leaderboard_submitted and modify it
                // leaderboard_scoreboard event was added later down the line to provide more
                // information about the leaderboard submission so this is why we have to do it this way
                ra_notification_t* current_notification = nullptr;
                for (auto& notification : game_state->notifications)
                {
                    if (notification.leaderboard_id == event->leaderboard_scoreboard->leaderboard_id)
                    {
                        current_notification = &notification;
                        break;
                    }
                }

                if (current_notification)
                {
                    std::string score_type = "score";
                    std::string score_type_caps = "Score";
                    switch (current_notification->leaderboard_format)
                    {
                        case RC_CLIENT_LEADERBOARD_FORMAT_VALUE:
                        case RC_CLIENT_LEADERBOARD_FORMAT_SCORE: {
                            score_type = "score";
                            score_type_caps = "Score";
                            break;
                        }

                        case RC_CLIENT_LEADERBOARD_FORMAT_TIME: {
                            score_type = "time";
                            score_type_caps = "Time";
                            break;
                        }
                    }

                    current_notification->submessage = score_type_caps + ": " +
                        std::string(event->leaderboard_scoreboard->submitted_score) + "\nYour best " + score_type + ": " +
                        std::string(event->leaderboard_scoreboard->best_score);
                    current_notification->submessage2 = ICON_FK_TROPHY " Ranked " +
                        std::to_string(event->leaderboard_scoreboard->new_rank) + " out of " +
                        std::to_string(event->leaderboard_scoreboard->num_entries);
                }
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
                notification.title = std::string("Leaderboard attempt submitted: ") + event->leaderboard->title;
                notification.submessage = std::string(event->leaderboard->tracker_value) + " for " +
                                          event->leaderboard->title;
                notification.tile = game_state->game_image;
                notification.leaderboard_id = event->leaderboard->id;
                notification.leaderboard_format = event->leaderboard->format;
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
                    game_state->challenges[id].tile = atlas_add_tile_from_url(game_state->atlas_map, url.c_str());
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
                break;
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

        std::vector<std::pair<std::string, std::string>> headers;
#ifndef EMSCRIPTEN
        // TODO(paris): When setting User-Agent from browser side, it sends a CORS
        // preflight request which is makes the request fail.
        headers.push_back({"User-Agent", "SkyEmu/4.0"});
#endif
        headers.push_back({"Content-Type", "application/x-www-form-urlencoded"});
        headers.push_back({"Content-Length", std::to_string(post_data.size())});

        https_request(type, url, post_data, headers,
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
                      }, false);
    }

    void retro_achievements_log_callback(const char* message, const rc_client_t* client)
    {
        printf("[rcheevos - internal]: %s\n", message);
    }

    void retro_achievements_draw_achievements()
    {
        ra_game_state_ptr game_state = ra_state->game_state;
        if (!game_state)
            return;

        std::unique_lock<std::mutex> lock(game_state->mutex);
        const rc_client_game_t* game = rc_client_get_game_info(ra_state->rc_client);
        if (game)
        {
            rc_client_user_game_summary_t summary;
            rc_client_get_user_game_summary(ra_state->rc_client, &summary);
            auto title = std::string("Playing ") + game->title;
            auto description = std::to_string(summary.points_unlocked) + "/" +
                            std::to_string(summary.points_core) + " points, " +
                            std::to_string(summary.num_unlocked_achievements) + "/" +
                            std::to_string(summary.num_core_achievements) + " achievements";
            bool hardcore = rc_client_get_hardcore_enabled(ra_state->rc_client);
            bool encore = rc_client_get_encore_mode_enabled(ra_state->rc_client);
            auto hardcore_str = hardcore ? "Hardcore mode" : "Softcore mode";
            uint32_t hardcore_color = hardcore ? 0xff0000ff : 0xff00ff00; // TODO: make me nicer
            if (encore)
            {
                hardcore_str = "Encore mode";
                hardcore_color = 0xff00ffff;
            }
            se_boxed_image_triple_label(title.c_str(), description.c_str(), hardcore_str,hardcore_color,ICON_FK_GAMEPAD, game_state->game_image, false);
        }
        for (int i = 0; i < game_state->achievement_list.buckets.size(); i++)
        {
            if (game_state->achievement_list.buckets[i].achievements.empty())
                continue;

            ra_bucket_t* bucket = &game_state->achievement_list.buckets[i];
            std::string label = category_to_icon(bucket->bucket_id) + " " +
                                se_localize_and_cache(bucket->label.c_str());
            se_section("%s", label.c_str());
            for (int j = 0; j < bucket->achievements.size(); j++)
            {
                const auto& achievement = bucket->achievements[j];
                float rarity = rc_client_get_hardcore_enabled(ra_state->rc_client)
                                   ? achievement->rarity_hardcore
                                   : achievement->rarity;
                bool unlocked = bucket->bucket_id == RC_CLIENT_ACHIEVEMENT_BUCKET_RECENTLY_UNLOCKED ||
                                bucket->bucket_id == RC_CLIENT_ACHIEVEMENT_BUCKET_UNLOCKED;
                bool glow = rarity < 5.0f && unlocked; // glow if less than 5% of players have it and you have it too
                std::stringstream stream;
                stream << std::fixed << std::setprecision(2) << rarity;
                std::string players = stream.str() + "% of players";

                uint32_t color;
                if (rarity > 30.0f) {
                    color = 0xff8fdba4;
                } else if (rarity > 20.0f) {
                    color = 0xffd49a8a;
                } else if (rarity > 5.0f) {
                    color = 0xffcc85bb;
                } else if (rarity > 1.5f) {
                    color = 0xff71b0e3;
                } else {
                    color = 0xff000000; // rainbow
                }

                se_boxed_image_triple_label(achievement->title.c_str(),
                                          achievement->description.c_str(), players.c_str(), color, ICON_FK_SPINNER, bucket->achievements[j]->tile, glow);
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
            buckets[i].achievements[j]->percentage = list->buckets[i].achievements[j]->measured_percent;
            buckets[i].achievements[j]->rarity = list->buckets[i].achievements[j]->rarity;
            buckets[i].achievements[j]->rarity_hardcore = list->buckets[i].achievements[j]->rarity_hardcore;

            const rc_client_achievement_t* achievement = list->buckets[i].achievements[j];
            if (rc_client_achievement_get_image_url(achievement, achievement->state, &url[0],
                                                    url.size()) == RC_OK)
            {
                uint32_t id = achievement->id;
                ra_achievement_t* achievement_ptr = buckets[i].achievements[j].get();
                achievement_ptr->tile = atlas_add_tile_from_url(game_state->atlas_map, url.c_str());
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

void ra_state_t::rebuild_achievement_list(ra_game_state_ptr game_state)
{
    game_state->achievement_list.initialize(
        game_state,
        rc_client_create_achievement_list(
            rc_client,
            RC_CLIENT_ACHIEVEMENT_CATEGORY_CORE, // TODO: option for _AND_UNOFFICIAL achievements?
            RC_CLIENT_ACHIEVEMENT_LIST_GROUPING_PROGRESS));
}

extern "C" uint32_t retro_achievements_read_memory_callback(uint32_t address, uint8_t* buffer,
                                                            uint32_t num_bytes,
                                                            rc_client_t* client);

void retro_achievements_initialize(void* state, bool hardcore)
{
    ra_state = new ra_state_t((sb_emu_state_t*)state);
    ra_state->rc_client = rc_client_create(retro_achievements_read_memory_callback,
                                           retro_achievements_server_callback);
    ra_state->user_image_atlas = atlas_create_map();

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

    ra_state->game_state.reset();

    delete ra_state;
}

bool retro_achievements_load_game()
{
    if (!ra_state->emu_state->rom_loaded)
        return true;

    const rc_client_user_t* user = rc_client_get_user_info(ra_state->rc_client);
    if (!user)
        return false; // not logged in or login in progress, in which case the game will be loaded
                     // when the login is done

    if (loading_game)
        return false;

    // the old one will be destroyed when the last reference is gone
    ra_state->game_state.reset(new ra_game_state_t());

    // We need to create a shared_ptr*, so we can pass it to the C api.
    ra_game_state_ptr* game_state = new ra_game_state_ptr(ra_state->game_state);

    loading_game = true;

    switch (ra_state->emu_state->system)
    {
        case SYSTEM_GB:
            rc_client_begin_identify_and_load_game(
                ra_state->rc_client, RC_CONSOLE_GAMEBOY, NULL, ra_state->emu_state->rom_data,
                ra_state->emu_state->rom_size, retro_achievements_load_game_callback, game_state);
            break;
        case SYSTEM_GBA:
            rc_client_begin_identify_and_load_game(
                ra_state->rc_client, RC_CONSOLE_GAMEBOY_ADVANCE, NULL,
                ra_state->emu_state->rom_data, ra_state->emu_state->rom_size,
                retro_achievements_load_game_callback, game_state);
            break;
        case SYSTEM_NDS:
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

bool retro_achievements_is_pending_login()
{
    return ra_state->pending_login;
}

const char* retro_achievements_get_login_error()
{
    return ra_state->error_message.load();
}

struct rc_client_t* retro_achievements_get_client()
{
    return ra_state->rc_client;
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
    ra_game_state_ptr game_state = ra_state->game_state;
    if (!game_state)
        return nullptr;

    return game_state->game_image;
}

atlas_tile_t* retro_achievements_get_user_image()
{
    return ra_state->user_image;
}

bool retro_achievements_has_game_loaded()
{
    return rc_client_get_game_info(ra_state->rc_client)!=NULL;
}

void retro_achievements_draw_panel()
{
    igPushIDStr("RetroAchievementsPanel");
    retro_achievements_draw_achievements();
    igPopID();
}

// https://easings.net/#easeOutBack
float easeOutBack(float t) {
    const float c1 = 1.30158;
    const float c3 = c1 + 1;
    const float t1 = t - 1;
    return 1 + c3 * (t1 * t1 * t1) + c1 * (t1 * t1);
}

void retro_achievements_draw_notifications(float left, float top, float screen_width, bool only_one_notification)
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

        if (notification.start_time == 0) {
            notification.start_time = se_time();
        }

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
        if (easing < 0.97f) {
            if (!only_one_notification) {
                continue;
            } else {
                break;
            }
        }

#define ALPHA(x) ((uint32_t)(multiplier * x) << 24)

        float padding_adj = 0.01 * screen_width * easing;
        float image_width = screen_width * 0.05f * easing;
        float image_height = screen_width * 0.05f * easing;
        float placard_width =
            padding_adj + screen_width * 0.30f * easing + padding_adj; // notifications that have the same width are more appealing
        float wrap_width = placard_width - padding_adj * 3 - image_width;
        float title_font_size = 0.02f * screen_width * easing;
        float submessage_font_size = 0.015f * screen_width * easing;

        float title_height = 0, submessage_height = 0;

        ImVec2 out;
        ImFont* font = igGetFont();
        ImFont_CalcTextSizeA(&out, font, title_font_size, std::numeric_limits<float>::max(), wrap_width,
                             notification.submessage.c_str(), NULL, NULL);
        title_height = out.y;

        ImFont_CalcTextSizeA(&out, font, submessage_font_size, std::numeric_limits<float>::max(), wrap_width,
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
        uint32_t id = atlas_get_tile_id(notification.tile);
        if (notification.tile && id != SG_INVALID_ID)
        {
            atlas_uvs_t uvs = atlas_get_tile_uvs(notification.tile);
            ImVec2 uv0 = {uvs.x1, uvs.y1};
            ImVec2 uv1 = {uvs.x2, uvs.y2};
            ImDrawList_AddImageRounded(ig, (ImTextureID)(intptr_t)id, img_top_left, img_bottom_right, uv0, uv1, 0xffffff | ALPHA(255), 8.0f, ImDrawCornerFlags_All);
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
                ig, igGetFont(), title_font_size,
                ImVec2{top_left.x + padding_adj + image_width + padding_adj, top_left.y + padding_adj},
                0xffffff | ALPHA(text_alpha), notification.submessage.c_str(), NULL, wrap_width, NULL);
            ImDrawList_AddTextFontPtr(
                ig, igGetFont(), submessage_font_size,
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
            ImFont_CalcTextSizeA(&out, font, title_font_size, std::numeric_limits<float>::max(), wrap_width,
                             notification.title.c_str(), NULL, NULL);
            title_height = out.y;
            ImDrawList_AddTextFontPtr(ig, igGetFont(), title_font_size,
                ImVec2{top_left.x + padding_adj + image_width + padding_adj, top_left.y + + padding_adj},
                0xffffff | ALPHA(text_alpha), notification.title.c_str(), NULL,
                wrap_width, NULL);
        }

        y += placard_height + padding;

        if (only_one_notification)
            break;
    }
}

void retro_achievements_draw_progress_indicator(float right, float top, float screen_width)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    if (!game_state->progress_indicator.show)
        return;

    ra_progress_indicator_t& indicator = game_state->progress_indicator;

    float image_size = screen_width * 0.04f;
    float font_size = 0.015f * screen_width;

    if (font_size < 9.0f) {
        font_size = 9.0f;
    }

    int numerator, denominator;
    bool is_percentage = false;

    if (strchr(indicator.measured_progress.c_str(), '/') != NULL) {
        int res = sscanf(indicator.measured_progress.c_str(), "%d/%d", &numerator, &denominator);
        if (res != 2) {
            is_percentage = true;
        }
    } else {
        is_percentage = true;
    }

    std::string nums = std::to_string(numerator);
    std::string dens = std::to_string(denominator);
    ImVec2 numout, denout;
    if (!is_percentage) {
        ImFont_CalcTextSizeA(&numout, igGetFont(), font_size, std::numeric_limits<float>::max(), 0, nums.c_str(), NULL, NULL);
        ImFont_CalcTextSizeA(&denout, igGetFont(), font_size, std::numeric_limits<float>::max(), 0, dens.c_str(), NULL, NULL);

        image_size = std::max(std::max(image_size, numout.x + 8), denout.x + 8);
    }

    uint32_t id = atlas_get_tile_id(indicator.tile);
    if (indicator.tile && id != SG_INVALID_ID) {
        atlas_uvs_t uvs = atlas_get_tile_uvs(indicator.tile);
        ImDrawList_AddImage(igGetWindowDrawList(),
                    (ImTextureID)(intptr_t)id, ImVec2{right-image_size, top},
                    ImVec2{right, top+image_size},
                    ImVec2{uvs.x1, uvs.y1},
                    ImVec2{uvs.x2, uvs.y2}, 0x80ffffff);
    } else {
        ImDrawList_AddRectFilled(igGetWindowDrawList(), ImVec2{right-image_size, top},
                                ImVec2{right, top+image_size}, 0x80242424, 0, 0);
    }

    if (is_percentage) {
        char percentage[8];
        snprintf(percentage, sizeof(percentage), "%.2f%%", indicator.measured_percent);
        ImVec2 out;
        ImFont_CalcTextSizeA(&out, igGetFont(), font_size, std::numeric_limits<float>::max(), 0, percentage, NULL, NULL);
        float text_height = out.y;
        float start_of_rectangle = top + image_size / 2 - text_height / 2;
        float start_of_text = right - image_size / 2 - out.x / 2;
        ImDrawList_AddRectFilled(igGetWindowDrawList(), ImVec2{start_of_text - 4, start_of_rectangle - 4},
                                ImVec2{right, start_of_rectangle + text_height + 4}, 0x80515151, 0, 0);
        ImDrawList_AddTextFontPtr(igGetWindowDrawList(), igGetFont(), font_size, ImVec2{start_of_text, start_of_rectangle},
                                0xffffffff, percentage, NULL, std::numeric_limits<float>::max(), NULL);
    } else {
        float text_height = numout.y;
        float start_of_rectangle = top + image_size / 2 - text_height - 8;
        float start_of_text_num = right - image_size / 2 - numout.x / 2;
        float start_of_text_den = right - image_size / 2 - denout.x / 2;
        float start_of_text_num_y = start_of_rectangle + 4;
        float start_of_text_den_y = start_of_rectangle + 4 + text_height + 4;
        float start_of_line = start_of_text_den - 2;
        float start_of_line_y = start_of_text_num_y + text_height + 2;
        ImDrawList_AddTextFontPtr(igGetWindowDrawList(), igGetFont(), font_size, ImVec2{start_of_text_num, start_of_text_num_y},
                                0xffffffff, nums.c_str(), NULL, std::numeric_limits<float>::max(), NULL);
        ImDrawList_AddLine(igGetWindowDrawList(), ImVec2{start_of_line, start_of_line_y},
                            ImVec2{start_of_line + denout.x + 2, start_of_line_y}, 0xffffffff, 2.0f);
        ImDrawList_AddTextFontPtr(igGetWindowDrawList(), igGetFont(), font_size, ImVec2{start_of_text_den, start_of_text_den_y},
                                0xffffffff, dens.c_str(), NULL, std::numeric_limits<float>::max(), NULL);
    }
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

void retro_achievements_draw_challenge_indicators(float right, float bottom, float screen_width)
{
    ra_game_state_ptr game_state = ra_state->game_state;

    if (!game_state)
        return;

    std::unique_lock<std::mutex> lock(game_state->mutex);

    if (game_state->challenges.empty())
        return;

    float padding_adj = 0.005 * screen_width;
    float x = right - padding_adj;
    float y = bottom - padding_adj * 2;
    float image_size = screen_width * 0.04f;
    int i = 0;

    for (const auto& item : game_state->challenges)
    {
        const ra_challenge_indicator_t& challenge = item.second;

        uint32_t id = atlas_get_tile_id(challenge.tile);
        if (challenge.tile && id != SG_INVALID_ID)
        {
            atlas_uvs_t uvs = atlas_get_tile_uvs(challenge.tile);
            ImDrawList_AddImage(igGetWindowDrawList(),
                                (ImTextureID)(intptr_t)id, ImVec2{x-image_size, y-image_size},
                                ImVec2{x, y},
                                ImVec2{uvs.x1, uvs.y1},
                                ImVec2{uvs.x2, uvs.y2}, 0x80ffffff);
        }

        if (i++ % 3 != 2)
        {
            x -= image_size + padding_adj;
        }
        else
        {
            x = right - padding_adj;
            y -= image_size + padding_adj;
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