#include "https.hpp"

#ifndef EMSCRIPTEN
#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <thread>
extern "C" {
#include "res.h"
}
#else
#include <emscripten.h>
#endif

#ifndef EMSCRIPTEN
size_t curl_write_data(void* buffer, size_t size, size_t nmemb, void* d)
{
    std::vector<uint8_t>* data = (std::vector<uint8_t>*)d;
    data->insert(data->end(), (uint8_t*)buffer, (uint8_t*)buffer + size * nmemb);
    return size * nmemb;
}
#else
EM_JS(void, em_https_request, (const char* type, const char* url, const char* body, size_t body_size, const char* headers, void* callback), {
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
                Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number'], [callback, response_buffer, response_size]);
                Module._free(response_buffer);
            } else {
                console.log('The request failed: ' + xhr.status + ' ' + xhr.statusText);
                Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number'], [callback, 0, 0]);
            }
        };
        xhr.onerror = function() {
            console.log('The request failed!');
            Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number'], [callback, 0, 0]);
        };
        xhr.ontimeout = function () {
            console.log('The request timed out!');
            Module.ccall('em_https_request_callback_wrapper', 'void', ['number', 'number', 'number'], [callback, 0, 0]);
        };
        xhr.send(body_arr);
    });


extern "C" void em_https_request_callback_wrapper(void* callback, void* data, int size)
{
    std::vector<uint8_t> result;

    if (size != 0)
    {
        result = std::vector<uint8_t>((uint8_t*)data, (uint8_t*)data + (size_t)size);
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
#endif

// Abstraction layer for http requests
void https_request(http_request_e type, const std::string& url, const std::string& body,
                   const std::vector<std::pair<std::string, std::string>>& headers,
                   std::function<void(const std::vector<uint8_t>&)> callback)
{
#ifndef EMSCRIPTEN
    std::thread request_thread([=] {
        CURL* curl = curl_easy_init();
        if (!curl)
        {
            printf("[cloud] failed to initialize curl\n");
            return;
        }

        CURLcode res;
#define se_validate() if (res != CURLE_OK) { printf("curl failed, line: %d, error: %s\n", __LINE__, curl_easy_strerror(res)); return; }

        std::vector<uint8_t> result;
        res = curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L); se_validate();
        res = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); se_validate();
        res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_data); se_validate();
        res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&result); se_validate();

        /* Turn off the default CA locations, otherwise libcurl will load CA
        * certificates from the locations that were detected/specified at
        * build-time
        */
        res = curl_easy_setopt(curl, CURLOPT_CAINFO, NULL); se_validate();
        res = curl_easy_setopt(curl, CURLOPT_CAPATH, NULL); se_validate();

        res = curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctx_function); se_validate();
        res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5); se_validate(); // 5 second timeout

        switch (type)
        {
            case http_request_e::GET:
                res = curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L); se_validate();
                break;
            case http_request_e::POST:
                res = curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_POST, 1L); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str()); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size()); se_validate();
                break;
            case http_request_e::PATCH:
                res = curl_easy_setopt(curl, CURLOPT_URL, url.c_str()); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH"); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str()); se_validate();
                res = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size()); se_validate();
                break;
            default:
                printf("[cloud] invalid request type\n");
                return;
        }

        struct curl_slist* chunk = NULL;
        for (auto& header : headers)
        {
            std::string header_string = header.first + ": " + header.second;
            chunk = curl_slist_append(chunk, header_string.c_str());
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
        {
            printf("[cloud] curl failed: %s\n", curl_easy_strerror(res));
            callback({});
        }
        else
        {
            callback(result);
        }

        curl_slist_free_all(chunk);
        curl_easy_cleanup(curl);
#undef se_validate
    });
    request_thread.detach();
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
                            (void*)fcallback);
#endif
}

extern "C" void https_initialize()
{
#ifndef EMSCRIPTEN
    curl_global_init(CURL_GLOBAL_ALL);
#endif
}

extern "C" void https_shutdown()
{
#ifndef EMSCRIPTEN
    curl_global_cleanup();
#endif
}