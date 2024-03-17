#ifndef MUTEX_H
#define MUTEX_H 1

typedef void* mutex_t;
mutex_t mutex_create();
void mutex_destroy(mutex_t mutex);
void mutex_lock(mutex_t mutex);
void mutex_unlock(mutex_t mutex);

#endif