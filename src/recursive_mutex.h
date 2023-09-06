#ifndef RECURSIVE_MUTEX_WRAPPER
#define RECURSIVE_MUTEX_WRAPPER
typedef void* recursive_mutex_t;
recursive_mutex_t create_mutex();
void destroy_mutex(recursive_mutex_t mutex);
void lock_mutex(recursive_mutex_t mutex);
void unlock_mutex(recursive_mutex_t mutex);
#endif