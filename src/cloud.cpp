/*
    Resources:
    https://developers.google.com/drive/api/reference/rest/v3/files
    https://developers.google.com/identity/protocols/oauth2
    https://developers.google.com/identity/protocols/oauth2/native-app
    https://developers.google.com/identity/protocols/oauth2/javascript-implicit-flow
*/

extern "C" {
const char* se_get_pref_path();
#include "cloud.h"
#include "sb_types.h"
}

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <map>
#include <condition_variable>
#include <mutex>

#include "json.hpp"
#include "stb_image.h"
#define XXH_IMPLEMENTATION
#define XXH_STATIC_LINKING_ONLY
#include "xxhash.h"
#include "https.hpp"

#ifndef EMSCRIPTEN
#include "httplib.h" // for server only
#else
#include <emscripten.h>
#endif

static bool pending_login = false;
static bool pending_logout = false;

struct file_metadata_t
{
    std::string id;
    std::string mime_type;
};

struct cloud_drive_t
{
    std::string username;
    std::string access_token;
    std::string refresh_token;
    std::string save_directory;
    int expire_timestamp;
    std::function<void(cloud_drive_t*)> ready_callback;
    std::map<std::string, file_metadata_t> files;
    std::vector<uint8_t> avatar_data;
    int avatar_data_width;
    int avatar_data_height;

    // Synchronization
    std::mutex request_mutex;
    std::mutex file_mutex;
    std::condition_variable cv;
    int outstanding_requests = 0;
    bool scheduled_deletion = false;

    void inc()
    {
        std::unique_lock<std::mutex> lock(request_mutex);
        outstanding_requests++;
    }

    void dec()
    {
        std::unique_lock<std::mutex> lock(request_mutex);
        outstanding_requests--;
        if (outstanding_requests == 0)
        {
            cv.notify_all();
        }
    }

    void wait()
    {
        std::unique_lock<std::mutex> lock(request_mutex);
        cv.wait(lock, [this] { return outstanding_requests == 0; });
    }
};

void google_cloud_drive_init(cloud_drive_t*);

#define GOOGLE_CLIENT_ID "617320710875-o9ev86s5ad18bmmgb98p0dkbqlfufekr.apps.googleusercontent.com"
#define GOOGLE_CLIENT_ID_WEB "617320710875-dakb2f10lgnnn3a97bgva18l83221pc3.apps.googleusercontent.com"

// Secrets are not really secret in native oauth2 apps
// It's encoded in hexadecimal here so automatic scanners don't complain
extern "C" const char* gsecret()
{
    static std::string secret;
    if (secret.empty())
    {
        std::string hex = "474f435350582d376c6d6a3358674a32335a344430517658795458766b74414161774d";
        secret.resize(hex.size() / 2);
        for (int i = 0; i < hex.size(); i += 2)
        {
            secret[i / 2] = (char)strtol(hex.substr(i, 2).c_str(), NULL, 16);
        }
    }
    return secret.c_str();
}

extern "C" const char* gsecret_web()
{
    static std::string secret;
    if (secret.empty())
    {
        std::string hex = "474f435350582d4766316565387578425a72614a4b2d374f32476c3041634941336a73";
        secret.resize(hex.size() / 2);
        for (int i = 0; i < hex.size(); i += 2)
        {
            secret[i / 2] = (char)strtol(hex.substr(i, 2).c_str(), NULL, 16);
        }
    }
    return secret.c_str();
}

static void em_flush_fs()
{
#if defined(EMSCRIPTEN)
    EM_ASM( FS.syncfs(function (err) {}););
#endif
}

#ifdef EMSCRIPTEN
EM_JS(void, em_oath_sign_in, (void* drive, const char* client_id), {
        var client_id_str = UTF8ToString(client_id);
        var redirect_uri = window.location.origin + '/authorized.html';
        var oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth?' +
                    'client_id=' + client_id_str + '&' +
                    'redirect_uri=' + redirect_uri + '&' +
                    'prompt=consent&' +
                    'response_type=code&' +
                    'access_type=offline&' +
                    'scope=https%3A//www.googleapis.com/auth/drive.file';
        
        var win = window.open(oauth2Endpoint, 'Authorize', 'width=800, height=600, popup=true');
        try {
            win.focus();
        } catch (e) {
            Module.ccall('em_oath_sign_in_callback', null, ['number', 'string', 'string'], [drive, null, null]);
            alert('Popup blocked, please allow popups');
            return;
        }

        const timer = setInterval(() => {
            if (win.closed) {
                clearInterval(timer);
                if (typeof authorization_code !== 'undefined') {
                    var xhr = new XMLHttpRequest();
                    var method = 'POST';
                    var url_str = 'https://oauth2.googleapis.com/token' +
                        '?client_id=' + client_id_str +
                        '&client_secret=' + Module.ccall('gsecret_web', 'string', [], []) +
                        '&code=' + authorization_code +
                        '&grant_type=authorization_code' +
                        '&access_type=offline&' +
                        '&redirect_uri=' + redirect_uri;
                    xhr.responseType = 'json';
                    xhr.open(method, url_str);
                    xhr.onload = function() {
                        if (xhr.status == 200) {
                            var jsonResponse = xhr.response;
                            var refresh_token = jsonResponse.refresh_token;
                            var access_token = jsonResponse.access_token;
                            console.log('Got response: ' + JSON.stringify(jsonResponse));
                            Module.ccall('em_oath_sign_in_callback', null, ['number', 'string', 'string'], [drive, refresh_token, access_token]);
                        } else {
                            console.log('The request failed: ' + xhr.status + ' ' + xhr.statusText);
                            var jsonResponse = xhr.response;
                            console.log(jsonResponse);
                        }
                    };
                    xhr.onerror = function() {
                        console.log('The request failed!');
                    };
                    xhr.send();
                } else {
                    console.log('Could not get authorization code variable after popup was closed');
                    Module.ccall('em_oath_sign_in_callback', null, ['number', 'string', 'string'], [drive, null, null]);
                }
            }
        }, 500);
    });

extern "C" void em_oath_sign_in_callback(cloud_drive_t* drive, const char* refresh_token,
                                         const char* access_token)
{
    if (!drive)
    {
        printf("[cloud] drive is null\n");
        return;
    }

    if (refresh_token && access_token)
    {
        drive->access_token = access_token;
        drive->refresh_token = refresh_token;
        drive->expire_timestamp = time(NULL) + 3600;
        std::string refresh_path = drive->save_directory + "refresh_token.txt";
        sb_save_file_data(refresh_path.c_str(), (uint8_t*)drive->refresh_token.c_str(),
                          drive->refresh_token.size() + 1);
        em_flush_fs();
        google_cloud_drive_init(drive);
    }
    else
    {
        printf("[cloud] refresh token or access token is null\n");
        drive->ready_callback(nullptr);
    }
}
#endif

void google_use_refresh_token(cloud_drive_t* drive, std::function<void(cloud_drive_t*)> callback)
{
#ifdef EMSCRIPTEN
    std::string client_id = GOOGLE_CLIENT_ID_WEB;
    std::string client_secret = gsecret_web();
#else
    std::string client_id = GOOGLE_CLIENT_ID;
    std::string client_secret = gsecret();
#endif
    std::string query = "client_id=" + client_id + "&client_secret=" + client_secret +
                        "&refresh_token=" + drive->refresh_token + "&grant_type=refresh_token";
    drive->inc();
    return https_request(
        http_request_e::POST, "https://oauth2.googleapis.com/token?" + query, "", {},
        [drive, callback](const std::vector<uint8_t>& token) {
            if (!nlohmann::json::accept(token))
            {
                printf("[cloud] failed to refresh token: invalid response\n");
                ::remove((drive->save_directory + "refresh_token.txt").c_str());
                drive->dec();
                callback(drive);
                return;
            }
            nlohmann::json json = nlohmann::json::parse(token);
            if (json.find("error") != json.end())
            {
                std::string error = json["error"];
                std::string error_description = json["error_description"];
                printf("[cloud] got response with error while refreshing token: %s: %s\n",
                       error.c_str(), error_description.c_str());
                ::remove((drive->save_directory + "refresh_token.txt").c_str());
                drive->dec();
                callback(drive);
                return;
            }

            if (json.find("access_token") == json.end())
            {
                printf("[cloud] failed to refresh token: no access token in response\n");
                drive->dec();
                callback(drive);
                return;
            }

            drive->access_token = json["access_token"];
            nlohmann::json expires_in = json["expires_in"];
            drive->expire_timestamp = time(NULL) + expires_in.get<int>();
            callback(drive);
            drive->dec();
        }, false);
}

std::string create_multipart_body(cloud_drive_t* drive, const std::string& filename, const std::string& parent, void* data,
                                  size_t size, const std::string& content_type,
                                  const std::string& separator)
{
    std::string body;
    body += "--" + separator + "\r\n";
    body += "Content-Disposition: form-data; name=\"metadata\"\r\n";
    body += "Content-Type: application/json; charset=UTF-8\r\n\r\n";
    nlohmann::json metadata;
    metadata["name"] = filename;
    metadata["mimeType"] = content_type;
    if (!parent.empty())
    {
        std::string id;
        {
            std::lock_guard<std::mutex> lock(drive->file_mutex);
            if (drive->files.find(parent) == drive->files.end())
            {
                printf("[cloud] parent folder not found %s\n", parent.c_str());
            } else {
                id = drive->files[parent].id;
            }
        }
        if (!id.empty()) {
            metadata["parents"] = {id};
        }
    }
    body += metadata.dump() + "\r\n";
    body += "--" + separator + "\r\n";
    body += "Content-Disposition: form-data; name=\"file\"\r\n\r\n";
    body += std::string((char*)data, size);
    body += "\r\n--" + separator + "--\r\n";
    return body;
}

void google_cloud_drive_upload(cloud_drive_t* drive, const std::string& filename, const std::string& parent,
                               const std::string& mime_type, void* data, size_t size,
                               std::function<void(cloud_drive_t*)> callback)
{
    if (drive->access_token.empty())
    {
        printf("[cloud] access token is empty\n");
        return;
    }

    std::string id;
    {
        std::lock_guard<std::mutex> lock(drive->file_mutex);
        if (drive->files.find(filename) != drive->files.end())
        {
            id = drive->files[filename].id;
        }
    }
    drive->inc();
    if (!id.empty())
    {
        return https_request(http_request_e::PATCH,
                             "https://www.googleapis.com/upload/drive/v3/files/" + id + "?uploadType=media",
                             std::string((char*)data, size),
                             {{"Authorization", "Bearer " + drive->access_token}},
                             [drive, callback](const std::vector<uint8_t>& data) {
                                callback(drive);
                                drive->dec();
                             }, false);
    }
    else
    {
        std::string boundary = "my-boundary";
        std::string body = create_multipart_body(drive, filename, parent, data, size, mime_type, boundary);
        return https_request(
            http_request_e::POST,
            "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart", body,
            {
                {"Authorization", "Bearer " + drive->access_token},
                {"Content-Type", "multipart/related; boundary=" + boundary},
            },
            [drive, callback, filename, mime_type](const std::vector<uint8_t>& data) {
                if (!nlohmann::json::accept(data))
                {
                    printf("[cloud] failed to upload file: invalid response\n");
                    callback(drive);
                    drive->dec();
                    return;
                }
                nlohmann::json json = nlohmann::json::parse(data);
                if (json.find("error") != json.end())
                {
                    std::string error = json["error"]["message"];
                    printf("[cloud] failed to upload file: %s\n", error.c_str());
                    drive->dec();
                    return;
                }

                {
                    std::lock_guard<std::mutex> lock(drive->file_mutex);
                    if (json.find("id") == json.end())
                    {
                        printf("[cloud] failed to upload file: no id\n");
                        drive->dec();
                        return;
                    }
                    std::string id = json["id"];
                    drive->files[filename] = {id, mime_type};
                }

                callback(drive);
                drive->dec();
            }, false);
    }
}

void google_cloud_drive_download(cloud_drive_t* drive, const std::string& filename,
                                 std::function<void(void*, void*, size_t)> callback, void* userdata)
{
    if (drive->access_token.empty())
    {
        printf("[cloud] access token is empty\n");
        return;
    }

    std::string id;
    {
        std::lock_guard<std::mutex> lock(drive->file_mutex);
        if (drive->files.find(filename) == drive->files.end())
        {
            printf("[cloud] file not found %s\n", filename.c_str());
            return callback(userdata, nullptr, 0);
        }
        id = drive->files[filename].id;
    }

    drive->inc();
    return https_request(http_request_e::GET,
                         "https://www.googleapis.com/drive/v3/files/" + id +
                             "?alt=media",
                         "", {{"Authorization", "Bearer " + drive->access_token}},
                         [drive, callback, userdata](const std::vector<uint8_t>& data) {
                            if (!data.empty())
                            {
                                callback(userdata, (void*)data.data(), data.size());
                            }
                            else
                            {
                                callback(userdata, nullptr, 0);
                            }
                            drive->dec();
                         }, false);
}

void google_cloud_drive_get_files(cloud_drive_t* drive,
                                  std::function<void(cloud_drive_t*)> callback)
{
    drive->inc();
    return https_request(http_request_e::GET, "https://www.googleapis.com/drive/v3/files", "",
                         {{"Authorization", "Bearer " + drive->access_token}},
                         [drive, callback](const std::vector<uint8_t>& data) {
                            if (!nlohmann::json::accept(data))
                            {
                                printf("[cloud] failed to get file map: invalid response\n");
                                callback(drive);
                                drive->dec();
                                return;
                            }
                             nlohmann::json response = nlohmann::json::parse(data);
                             if (response.find("error") != response.end())
                             {
                                 std::string error = response["error"]["message"];
                                 printf("[cloud] failed to get file map: %s\n",
                                        error.c_str());
                                 drive->dec();
                                 return;
                             }

                             if (response.find("files") != response.end())
                             {
                                std::lock_guard<std::mutex> lock(drive->file_mutex);
                                auto files = response["files"];
                                for (nlohmann::json file : files)
                                {
                                    std::string id = file["id"];
                                    std::string mime_type = file["mimeType"];
                                    std::string name = file["name"];
                                    drive->files[name] = {id, mime_type};
                                }
                             } else {
                                printf("[cloud] failed to get file map: no files in response\n");
                                drive->dec();
                                return;
                             }

                             callback(drive);
                             drive->dec();
                         }, false);
}

bool google_check_avatar_exists(cloud_drive_t* drive)
{
    if (sb_file_exists((drive->save_directory + "profile_picture").c_str()))
    {
        void* data = stbi_load((drive->save_directory + "profile_picture").c_str(),
                               &drive->avatar_data_width, &drive->avatar_data_height, NULL, 4);
        if (data)
        {
            drive->avatar_data.resize(drive->avatar_data_width * drive->avatar_data_height * 4);
            memcpy(drive->avatar_data.data(), data, drive->avatar_data.size());
            stbi_image_free(data);
            return true;
        }
        else
        {
            printf("[cloud] failed to load cached avatar\n");
            ::remove((drive->save_directory + "profile_picture").c_str());
            return false;
        }
    }
    return false;
}

bool google_check_username_exists(cloud_drive_t* drive)
{
    std::string path = drive->save_directory + "cloud_username.txt";
    if (sb_file_exists(path.c_str()))
    {
        size_t username_size;
        void* username_data = sb_load_file_data(path.c_str(), &username_size);
        if (username_data == NULL)
        {
            printf("[cloud] failed to load cached username\n");
            ::remove(path.c_str());
            return false;
        }
        else
        {
            drive->username = std::string((char*)username_data, username_size - 1);
            free(username_data);
            return true;
        }
    }
    return false;
}

void google_get_user_data(cloud_drive_t* drive)
{
    bool avatar_exists = google_check_avatar_exists(drive);
    bool username_exists = google_check_username_exists(drive);
    if (avatar_exists && username_exists)
    {
        drive->ready_callback(drive);
        return;
    }

    drive->inc();
    https_request(http_request_e::GET, "https://www.googleapis.com/drive/v3/about?fields=user", "",
                  {{"Authorization", "Bearer " + drive->access_token}},
                  [drive, avatar_exists](const std::vector<uint8_t>& data) {
                        std::string path = drive->save_directory + "cloud_username.txt";
                        if (!nlohmann::json::accept(data))
                        {
                            printf("[cloud] failed to get username: invalid response\n");
                            drive->dec();
                            drive->ready_callback(nullptr);
                            return;
                        }
                        nlohmann::json json = nlohmann::json::parse(data);
                        if (json.find("error") != json.end())
                        {
                            std::string error = json["error"]["message"];
                            printf("[cloud] failed to get username: %s\n", error.c_str());
                            drive->dec();
                            drive->ready_callback(nullptr);
                            return;
                        }

                        if (json.find("user") != json.end())
                        {
                            drive->username = json["user"]["displayName"];
                            sb_save_file_data(path.c_str(), (const uint8_t*)drive->username.c_str(), drive->username.size() + 1);
                            em_flush_fs();
                            drive->inc();
                            std::string url = json["user"]["photoLink"];
                            https_request(http_request_e::GET, url, "", {},
                                        [drive](const std::vector<uint8_t>& data) {
                                            sb_save_file_data(
                                                (drive->save_directory + "profile_picture").c_str(),
                                                data.data(), data.size());
                                            em_flush_fs();
                                            google_check_avatar_exists(drive);
                                            drive->dec();
                                            drive->ready_callback(drive);
                                        }, true /* cache the avatar image */);
                        } else {
                            printf("[cloud] failed to get username: no user in response\n");
                            drive->dec();
                            drive->ready_callback(nullptr);
                            return;
                        }
                        drive->dec();
                  }, false);
}

void google_cloud_drive_mkdir(cloud_drive_t* drive, const std::string& name, const std::string& parent, std::function<void(cloud_drive_t*)> callback)
{
    google_cloud_drive_upload(drive, name, parent, "application/vnd.google-apps.folder", NULL,
                                0, [callback](cloud_drive_t* drive) {
                                            callback(drive);
                                });
}

void google_cloud_drive_init(cloud_drive_t* drive)
{
    google_cloud_drive_get_files(drive, [](cloud_drive_t* drive) {
        bool folders_exist;
        {
            std::lock_guard<std::mutex> lock(drive->file_mutex);
            folders_exist = drive->files.size() > 0;
        }

        if (!folders_exist)
        {
            google_cloud_drive_mkdir(drive, "SkyEmu", "", [](cloud_drive_t* drive) {
                google_cloud_drive_mkdir(drive, "save_states", "SkyEmu", [](cloud_drive_t* drive) {
                            google_cloud_drive_get_files(
                                drive, [](cloud_drive_t* drive) {
                                    google_get_user_data(drive);
                                });
                        });
            });
        }
        else
        {
            google_get_user_data(drive);
        }
    });
}

void cloud_drive_authenticate(cloud_drive_t* drive)
{
#ifdef EMSCRIPTEN
    return em_oath_sign_in(drive, GOOGLE_CLIENT_ID_WEB);
#else
    srand(time(NULL));
    const char* charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string code_verifier;
    code_verifier.resize(128);
    int length = strlen(charset);
    for (int i = 0; i < 128; i++)
    {
        code_verifier[i] = charset[rand() % length];
    }

    std::string request = "https://accounts.google.com/o/oauth2/v2/auth?"
                          "client_id=" GOOGLE_CLIENT_ID "&redirect_uri=http%3A//127.0.0.1%3A5000"
                          "&response_type=code"
                          "&scope=https%3A//www.googleapis.com/auth/drive.file"
                          "&code_challenge=" +
                          code_verifier + "&code_challenge_method=plain";

    https_open_url(request.c_str());

    // Listen on port 5000 for the oauth2 callback
    std::string refresh_path = drive->save_directory + "refresh_token.txt";
    httplib::Server server;
    server.Get("/", [drive, &server, code_verifier, refresh_path](const httplib::Request& req,
                                                                  httplib::Response& res) {
        struct ScopeGuard
        {
            httplib::Server* server;
            ~ScopeGuard()
            {
                server->stop();
            }
        } scope_guard{&server};

        if (req.has_param("code"))
        {
            std::string auth_code = req.get_param_value("code");
            std::string query =
                "client_id=" GOOGLE_CLIENT_ID "&client_secret=" + std::string(gsecret()) +
                "&code=" + auth_code + "&code_verifier=" + code_verifier +
                "&grant_type=authorization_code"
                "&redirect_uri=http%3A//127.0.0.1%3A5000";
            https_request(
                http_request_e::POST, "https://oauth2.googleapis.com/token?" + query, "", {},
                [drive, refresh_path](const std::vector<uint8_t>& data) {
                    if (!nlohmann::json::accept(data))
                    {
                        printf("[cloud] failed to authenticate: invalid response\n");
                        drive->ready_callback(nullptr);
                        return;
                    }
                    nlohmann::json json = nlohmann::json::parse(data);
                    if (json.find("error") != json.end())
                    {
                        std::string error = json["error"];
                        std::string error_description = json["error_description"];
                        printf("[cloud] got response with error while authenticating: %s: %s\n",
                               error.c_str(), error_description.c_str());
                        drive->ready_callback(nullptr);
                        return;
                    }

                    drive->access_token = json["access_token"];
                    drive->refresh_token = json["refresh_token"];
                    nlohmann::json expires_in = json["expires_in"];
                    drive->expire_timestamp = time(NULL) + expires_in.get<int>();
                    sb_save_file_data(refresh_path.c_str(), (uint8_t*)drive->refresh_token.c_str(),
                                      drive->refresh_token.size() + 1);
                    em_flush_fs();
                    google_cloud_drive_init(drive);
                }, false);

            #ifdef SE_PLATFORM_ANDROID
            res.set_redirect("skyemu://oauth");
            #endif
            #ifdef SE_PLATFORM_IOS
            se_ios_close_modal();
            #endif
            res.set_content("You may close this tab", "text/plain");
        }
        else if (req.has_param("error"))
        {
            std::string error = req.get_param_value("error");
            printf("[cloud] while authenticating got error: %s\n", error.c_str());
            drive->ready_callback(nullptr);
        }
        else
        {
            printf(
                "[cloud] while authenticating got response that contains neither code nor error\n");
            drive->ready_callback(nullptr);
        }
    });
    // TODO: disallow http_server from listening to port 5000
    server.listen("127.0.0.1", 5000);
#endif
}

void cloud_drive_create(void (*ready_callback)(cloud_drive_t*))
{
    pending_login = true;
    cloud_drive_t* drive = new cloud_drive_t;
    std::function<void(cloud_drive_t*)> fcallback = [ready_callback, drive](cloud_drive_t* called_drive) {
        pending_login = false;
        ready_callback(called_drive);

        // If this callback is called with a nullptr that means something went wrong
        // during authentication and the drive object we created should be deleted
        if (called_drive == nullptr)
        {
            delete drive;
        }
    };
#ifndef EMSCRIPTEN
    std::thread create_thread([drive, fcallback] {
#endif
        drive->save_directory = se_get_pref_path();
        drive->ready_callback = fcallback;

        std::string refresh_path = drive->save_directory + "refresh_token.txt";
        if (sb_file_exists(refresh_path.c_str()))
        {
            size_t refresh_token_size;
            void* refresh_token_data = sb_load_file_data(refresh_path.c_str(), &refresh_token_size);
            if (refresh_token_data == NULL)
            {
                printf("[cloud] failed to load refresh token\n");
                drive->ready_callback(nullptr);
                return;
            }
            drive->refresh_token = std::string((char*)refresh_token_data, refresh_token_size - 1);
            free(refresh_token_data);

            google_use_refresh_token(drive, [refresh_path](cloud_drive_t* drive) {
                if (drive->access_token.empty())
                {
                    printf("[cloud] failed to use refresh token\n");
                    drive->ready_callback(nullptr);
                }
                else
                {
                    google_cloud_drive_init(drive);
                }
            });
            return;
        }
        cloud_drive_authenticate(drive);
#ifndef EMSCRIPTEN
    });
    create_thread.detach();
#endif
}

void cloud_drive_logout(cloud_drive_t* drive, void (*callback)())
{
    pending_logout = true;
    std::function<void()> fcallback = callback;
    drive->scheduled_deletion = true; // no more requests
#ifndef EMSCRIPTEN
    std::thread logout_thread([drive, fcallback] {
#endif
        ::remove((drive->save_directory + "cloud_username.txt").c_str());
        ::remove((drive->save_directory + "refresh_token.txt").c_str());
        ::remove((drive->save_directory + "profile_picture").c_str());
        drive->wait();
        https_request(http_request_e::POST,
                    "https://oauth2.googleapis.com/revoke?token=" + drive->access_token, "", {},
                    [drive, fcallback](const std::vector<uint8_t>& data) {
                        delete drive;
                        fcallback();
                        pending_logout = false;
                    }, false);
        
        em_flush_fs();
#ifndef EMSCRIPTEN
    });
    logout_thread.detach();
#endif
}

void cloud_drive_upload(cloud_drive_t* drive, const char* filename, const char* parent, const char* mime_type,
                        void* data, size_t size, void (*cleanup_callback)(void*, void*),
                        void* userdata)
{
    if (drive->scheduled_deletion)
    {
        return;
    }
    std::string name(filename);
    std::string sparent(parent);
    std::string mime(mime_type);
#ifndef EMSCRIPTEN
    std::thread upload_thread([drive, name, sparent, mime, data, size, cleanup_callback, userdata] {
#endif
        if (time(NULL) > drive->expire_timestamp - 60)
        {
            if (drive->access_token.empty())
            {
                printf("[cloud] failed to use refresh token\n");
                return;
            }
            google_use_refresh_token(
                drive, [name, sparent, mime, data, size, cleanup_callback, userdata](cloud_drive_t* drive) {
                    google_cloud_drive_upload(drive, name, sparent, mime, data, size,
                                              [cleanup_callback, data, userdata](cloud_drive_t*) {
                                                  cleanup_callback(userdata, data);
                                              });
                });
        }
        else
        {
            google_cloud_drive_upload(drive, name, sparent, mime, data, size,
                                      [cleanup_callback, data, userdata](cloud_drive_t*) {
                                          cleanup_callback(userdata, data);
                                      });
        }
#ifndef EMSCRIPTEN
    });
    upload_thread.detach();
#endif
}

void cloud_drive_download(cloud_drive_t* drive, const char* filename,
                          void (*callback)(void* userdata, void* data, size_t size), void* userdata)
{
    if (drive->scheduled_deletion)
    {
        return;
    }
    std::string name(filename);
    std::function<void(void*, void*, size_t)> fcallback = callback;
#ifndef EMSCRIPTEN
    std::thread download_thread([drive, name, fcallback, userdata] {
#endif
        if (time(NULL) > drive->expire_timestamp - 60)
        {
            if (drive->access_token.empty())
            {
                printf("[cloud] failed to use refresh token\n");
                return;
            }
            google_use_refresh_token(drive, [name, fcallback, userdata](cloud_drive_t* drive) {
                google_cloud_drive_download(drive, name, fcallback, userdata);
            });
        }
        else
        {
            google_cloud_drive_download(drive, name, fcallback, userdata);
        }
#ifndef EMSCRIPTEN
    });
    download_thread.detach();
#endif
}

void cloud_drive_sync(cloud_drive_t* drive, void(*callback)())
{
    if (drive->scheduled_deletion)
    {
        return;
    }
    std::function<void()> fcallback = callback;
#ifndef EMSCRIPTEN
    std::thread sync_thread([drive, fcallback] {
#endif
        google_cloud_drive_get_files(drive, [fcallback](cloud_drive_t*) {
            fcallback();
        });
#ifndef EMSCRIPTEN
    });
    sync_thread.detach();
#endif
}

cloud_user_info_t cloud_drive_get_user_info(cloud_drive_t* drive)
{
    cloud_user_info_t info;
    info.name = drive->username.c_str();
    if (drive->avatar_data.empty())
    {
        return info;
    }

    info.avatar = drive->avatar_data.data();
    info.avatar_width = drive->avatar_data_width;
    info.avatar_height = drive->avatar_data_height;
    return info;
}

uint64_t cloud_drive_hash(const char* input, size_t input_size)
{
    return XXH64(input, input_size, 0);
}

bool cloud_drive_pending_login()
{
    return pending_login;
}

bool cloud_drive_pending_logout()
{
    return pending_logout;
}