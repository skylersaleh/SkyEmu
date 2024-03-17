#ifndef SKYEMU_HTTPS
#define SKYEMU_HTTPS 1

#ifdef __cplusplus
extern "C" {
#endif

void https_initialize();
void https_shutdown();

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

enum class http_request_e
{
    GET,
    POST,
    PATCH,
};

void https_request(http_request_e type, const std::string& url, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   std::function<void(const std::vector<uint8_t>&)> callback);
#endif
#endif