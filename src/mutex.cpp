extern "C" {
#include "mutex.h"
}
#include <mutex>

mutex_t mutex_create() {
    return new std::mutex();
}

void mutex_destroy(mutex_t mutex) {
    delete (std::mutex*)mutex;
}

void mutex_lock(mutex_t mutex) {
    ((std::mutex*)mutex)->lock();
}

void mutex_unlock(mutex_t mutex) {
    ((std::mutex*)mutex)->unlock();
}