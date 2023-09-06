extern "C" {
    #include "recursive_mutex.h"
}
#include <mutex>

recursive_mutex_t create_mutex() {
    recursive_mutex_t mutex = new std::recursive_mutex;
    return mutex;
}

void destroy_mutex(recursive_mutex_t mutex) {
    delete (std::recursive_mutex*)mutex;
}

void lock_mutex(recursive_mutex_t mutex) {
    ((std::recursive_mutex*)mutex)->lock();
}

void unlock_mutex(recursive_mutex_t mutex) {
    ((std::recursive_mutex*)mutex)->unlock();
}