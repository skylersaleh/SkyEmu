#ifndef SKYEMU_HTTPS
#define SKYEMU_HTTPS 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>

void https_initialize();
void https_shutdown();
uint64_t https_cache_size();
void https_clear_cache();
void https_set_cache_enabled(bool enabled);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <string>
#include <vector>
#include <functional>

enum class http_request_e
{
    GET,
    POST,
    PATCH,
};

void https_request(http_request_e type, const std::string& url, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   std::function<void(const std::vector<uint8_t>&)> callback, bool do_cache);
#endif
#endif