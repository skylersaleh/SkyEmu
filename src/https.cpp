#include "https.hpp"
#include <mutex>
#include <string.h>
#include <unordered_map>
#include <vector>
#include <string>

#ifndef EMSCRIPTEN
#include <atomic>
#include <curl/curl.h>
#include <condition_variable>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <thread>
#include <queue>
extern "C" {
#include "res.h"
}
#else
#include <emscripten.h>
#endif

extern "C" {
const char* se_get_pref_path();
}

std::mutex cache_mutex;
std::atomic_bool cache_enabled;
std::atomic_uint64_t cache_size;
std::unordered_map<std::string, std::vector<uint8_t>> download_cache;
FILE* cache_file = nullptr;

#ifndef EMSCRIPTEN
struct job {
    http_request_e type;
    std::string url;
    std::string body;
    std::vector<std::pair<std::string, std::string>> headers;
    std::function<void(const std::vector<uint8_t>&)> callback;
    bool do_cache;
};

struct thread_pool {
    thread_pool(uint8_t n) {
        for (uint8_t i = 0; i < n; i++) {
            threads.push_back(std::thread(&thread_pool::main_loop, this));
        }
    }

    ~thread_pool() {
        terminate_all = true;
        jobs_cv.notify_all();
        for (auto& t : threads) {
            t.join();
        }
    }

    void push_job(const job& j) {
        {
            std::unique_lock<std::mutex> lock(jobs_mutex);
            jobs.push(j);
        }
        jobs_cv.notify_one();
    }

private:
    void main_loop() {
        CURL* curl = curl_easy_init();
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L); 
        curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L); 
        while (!terminate_all) {
            job j;
            {
                std::unique_lock<std::mutex> lock(jobs_mutex);
                jobs_cv.wait(lock, [this] { return !jobs.empty() || terminate_all; });
                if (terminate_all) {
                    return;
                }
                j = jobs.front();
                jobs.pop();
            }
            handle_job(j,curl);
        }
        curl_easy_cleanup(curl);
    }

    void handle_job(job& j, CURL* curl);

    std::atomic_bool terminate_all = { false };

    std::vector<std::thread> threads;
    std::mutex jobs_mutex;
    std::condition_variable jobs_cv;
    std::queue<job> jobs;
};

size_t curl_write_data(void* buffer, size_t size, size_t nmemb, void* d)
{
    std::vector<uint8_t>* data = (std::vector<uint8_t>*)d;
    data->insert(data->end(), (uint8_t*)buffer, (uint8_t*)buffer + size * nmemb);
    return size * nmemb;
}
#else
EM_JS(void, em_https_request, (const char* type, const char* url, const char* body, size_t body_size, const char* headers, void* callback, int do_cache), {
        var xhr = new XMLHttpRequest();
        var method = UTF8ToString(type);
        var url_str = UTF8ToString(url);
        var body_arr = new Uint8Array(Module.HEAPU8.buffer, body, body_size);
        xhr.open(method, url_str);
        xhr.responseType = "arraybuffer";
        xhr.timeout = 5000; // set timeout to 5 seconds

        var headers_str = UTF8ToString(headers);
        if (headers_str.length > 0) {
            var headers_arr = headers_str.split('\n');
            for (var i = 0; i < headers_arr.length; i++) {
                var header = headers_arr[i].split(':');
                if (header.length == 2) {
                    xhr.setRequestHeader(header[0], header[1]);
                } else {
                    console.log('Invalid header: ' + headers_arr[i]);
                }
            }
        }

        xhr.onload = function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                var response_size = xhr.response.byteLength;
                var response_buffer = Module._malloc(response_size);
                var response_view = new Uint8Array(xhr.response);
                Module.HEAPU8.set(response_view, response_buffer);
                Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number', 'number'], [callback, response_buffer, response_size, do_cache ? url : 0]);
                Module._free(response_buffer);
            } else {
                console.log('The request failed: ' + xhr.status + ' ' + xhr.statusText);
                Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number', 'number'], [callback, 0, 0, 0]);
            }
        };
        xhr.onerror = function() {
            console.log('The request failed!');
            Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number', 'number'], [callback, 0, 0, 0]);
        };
        xhr.ontimeout = function () {
            console.log('The request timed out!');
            Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number', 'number'], [callback, 0, 0, 0]);
        };
        xhr.send(body_arr);
    });


extern "C" void em_https_request_callback_wrapper(void* callback, void* data, int size, const char* url)
{
    std::vector<uint8_t> result;

    if (size != 0)
    {
        result = std::vector<uint8_t>((uint8_t*)data, (uint8_t*)data + (size_t)size);

        if (url != nullptr) {
            std::unique_lock<std::mutex> lock(cache_mutex);
            download_cache[url] = result;
            size_t url_len = strlen(url);
            fwrite(&url_len, 1, 2, cache_file);
            fwrite(url, 1, url_len, cache_file);
            uint32_t data_len = result.size();
            fwrite(&data_len, 1, 4, cache_file);
            fwrite(result.data(), 1, data_len, cache_file);
            cache_size += 2 + url_len + 4 + data_len;
        }
    }

    std::function<void(const std::vector<uint8_t>&)>* fcallback =
        (std::function<void(const std::vector<uint8_t>&)>*)callback;
    (*fcallback)(result);
    delete fcallback;
}
#endif

#ifndef EMSCRIPTEN
// See cacertinmem.c example from libcurl
CURLcode sslctx_function(CURL *curl, void *sslctx, void *parm)
{
    CURLcode rv = CURLE_ABORTED_BY_CALLBACK;
    
    uint64_t cacert_pem_len;
    const uint8_t* cacert_pem = se_get_resource(SE_CACERT_PEM, &cacert_pem_len);

    BIO *cbio = BIO_new_mem_buf(cacert_pem, cacert_pem_len);
    X509_STORE  *cts = SSL_CTX_get_cert_store((SSL_CTX *)sslctx);
    int i;
    STACK_OF(X509_INFO) *inf;
    (void)curl;
    (void)parm;

    if(!cts || !cbio) {
        return rv;
    }

    inf = PEM_X509_INFO_read_bio(cbio, NULL, NULL, NULL);

    if(!inf) {
        BIO_free(cbio);
        return rv;
    }

    for(i = 0; i < sk_X509_INFO_num(inf); i++) {
        X509_INFO *itmp = sk_X509_INFO_value(inf, i);
        if(itmp->x509) {
        X509_STORE_add_cert(cts, itmp->x509);
        }
        if(itmp->crl) {
        X509_STORE_add_crl(cts, itmp->crl);
        }
    }

    sk_X509_INFO_pop_free(inf, X509_INFO_free);
    BIO_free(cbio);

    rv = CURLE_OK;
    return rv;
}

void thread_pool::handle_job(job& j, CURL * curl)
{
    if (!curl)
    {
        printf("[https] failed to initialize curl\n");
        return;
    }

    CURLcode res;
#define VALIDATE_CURL() if (res != CURLE_OK) { printf("curl failed, line: %d, error: %s\n", __LINE__, curl_easy_strerror(res)); return; }

    std::vector<uint8_t> result;
    res = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&result); VALIDATE_CURL();

    /* Turn off the default CA locations, otherwise libcurl will load CA
    * certificates from the locations that were detected/specified at
    * build-time
    */
    res = curl_easy_setopt(curl, CURLOPT_CAINFO, NULL); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_CAPATH, NULL); VALIDATE_CURL();

    res = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctx_function); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5); VALIDATE_CURL(); // 5 second timeout

    switch (j.type)
    {
        case http_request_e::GET:
            res = curl_easy_setopt(curl, CURLOPT_URL, j.url.c_str()); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L); VALIDATE_CURL();
            break;
        case http_request_e::POST:
            res = curl_easy_setopt(curl, CURLOPT_URL, j.url.c_str()); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_POST, 1L); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, j.body.c_str()); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, j.body.size()); VALIDATE_CURL();
            break;
        case http_request_e::PATCH:
            res = curl_easy_setopt(curl, CURLOPT_URL, j.url.c_str()); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH"); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, j.body.c_str()); VALIDATE_CURL();
            res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, j.body.size()); VALIDATE_CURL();
            break;
        default:
            printf("[https] invalid request type\n");
            return;
    }

    struct curl_slist* chunk = NULL;
    for (auto& header : j.headers)
    {
        std::string header_string = header.first + ": " + header.second;
        chunk = curl_slist_append(chunk, header_string.c_str());
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        printf("[https] curl failed: %s\n", curl_easy_strerror(res));
        j.callback({});
    }
    else
    {
        j.callback(result);

        if (j.do_cache && result.size() != 0) {
            std::unique_lock<std::mutex> lock(cache_mutex);
            download_cache[j.url] = result;
            size_t url_len = j.url.size();
            fwrite(&url_len, 1, 2, cache_file);
            fwrite(j.url.c_str(), 1, url_len, cache_file);
            uint32_t data_len = result.size();
            fwrite(&data_len, 1, 4, cache_file);
            fwrite(result.data(), 1, data_len, cache_file);
            cache_size += 2 + url_len + 4 + data_len;
        }
    }

    res = curl_easy_setopt(curl, CURLOPT_HTTPGET, 0L); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_POST, 0L); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, ""); VALIDATE_CURL();
    res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0); VALIDATE_CURL();

    curl_slist_free_all(chunk);
}
#endif

// Abstraction layer for http requests
void https_request(http_request_e type, const std::string& url, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   std::function<void(const std::vector<uint8_t>&)> callback, bool do_cache)
{
    if (type == http_request_e::GET && do_cache && cache_enabled.load(std::memory_order_relaxed)) {
        std::unique_lock<std::mutex> lock(cache_mutex);
        auto it = download_cache.find(url);
        if (it != download_cache.end()) {
            callback(it->second);
            return;
        }
    }

#ifndef EMSCRIPTEN
    static thread_pool pool(32);
    pool.push_job({type, url, body, headers, callback, do_cache});
#else
    std::string method;
    switch (type)
    {
        case http_request_e::GET:
            method = "GET";
            break;
        case http_request_e::POST:
            method = "POST";
            break;
        case http_request_e::PATCH:
            method = "PATCH";
            break;
        default:
            return;
    }

    std::string hstring;
    for (auto& header : headers)
    {
        hstring += header.first + ":" + header.second;
        if (header != headers.back())
        {
            hstring += "\n";
        }
    }

    // Deleted when the callback is called
    std::function<void(const std::vector<uint8_t>&)>* fcallback =
        new std::function<void(const std::vector<uint8_t>&)>(callback);
    return em_https_request(method.c_str(), url.c_str(), body.c_str(), body.size(), hstring.c_str(),
                            (void*)fcallback, do_cache);
#endif
}

extern "C" void https_initialize()
{
#ifndef EMSCRIPTEN
    curl_global_init(CURL_GLOBAL_ALL);
#endif
    std::string path = std::string(se_get_pref_path()) + "/download_cache.bin";
    cache_file = fopen(path.c_str(), "rb+");
    if (!cache_file) {
        cache_file = fopen(path.c_str(), "wb+");
    }

    fseek(cache_file, 0, SEEK_END);
    size_t size = ftell(cache_file);
    fseek(cache_file, 0, SEEK_SET);

    if (size == 0) {
        // This is the first time the disk cache is being accessed
        fwrite("SKYEMUCACHE", 1, 12, cache_file);
    } else {
        bool corrupted = false;

        // Read the header first
        char header[12];
        fread(header, 1, 12, cache_file);
        if (memcmp(header, "SKYEMUCACHE", 12) != 0) {
            corrupted = true;
        }

        // Read the cache entries
        // 2 bytes for url length
        // variable url data
        // 4 bytes for data length
        // variable data
        while (!corrupted && ftell(cache_file) < size) {
            uint16_t url_len;
            int read = fread(&url_len, 1, 2, cache_file);
            if (read != 2) {
                corrupted = true;
                break;
            }

            std::string url;
            url.resize(url_len);
            read = fread(&url[0], 1, url_len, cache_file);
            if (read != url_len) {
                corrupted = true;
                break;
            }

            uint32_t data_len;
            read = fread(&data_len, 1, 4, cache_file);
            if (read != 4) {
                corrupted = true;
                break;
            }

            std::vector<uint8_t> data;
            data.resize(data_len);
            read = fread(&data[0], 1, data_len, cache_file);
            if (read != data_len) {
                corrupted = true;
                break;
            }

            // Don't need to lock here since this is very early initialization code
            download_cache[url] = data;
        }

        if (corrupted) {
            fclose(cache_file);
            
            cache_file = fopen(path.c_str(), "wb+"); // truncates file
            fwrite("SKYEMUCACHE", 1, 12, cache_file);
        }
    }
}

extern "C" void https_shutdown()
{
#ifndef EMSCRIPTEN
    curl_global_cleanup();
#endif

    fclose(cache_file);
}

extern "C" uint64_t https_cache_size()
{
    return cache_size.load(std::memory_order_relaxed);
}

extern "C" void https_clear_cache()
{
    std::unique_lock<std::mutex> lock(cache_mutex);
    download_cache.clear();
    cache_size.store(0, std::memory_order_relaxed);

    std::string path = std::string(se_get_pref_path()) + "download_cache.bin";
    fclose(cache_file);

    cache_file = fopen(path.c_str(), "wb+"); // truncates file
    fwrite("SKYEMUCACHE", 1, 12, cache_file);
}

extern "C" void https_set_cache_enabled(bool enabled)
{
    cache_enabled.store(enabled, std::memory_order_relaxed);
}