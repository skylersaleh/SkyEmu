#ifndef HTTP_CONTROL_SERVER
#define HTTP_CONTROL_SERVER
#include <stdint.h>
#include <stdbool.h>
//Called on a command being recieved from the HTTP Control Server
// cmd is the cmd received
// params is an array of strings interleaving the param names and their value, terminated by two NULL pointers
// the call back will set result_size to the size of the returned malloc'd data
// the call back will set mime_type to the desired mime type for the return; 
//Returns malloc'd data for a handled response or NULL for a non-handled response. 
typedef uint8_t* (*hcs_callback)(const char* cmd, const char** params, uint64_t* result_size, const char** mime_type);

//Streaming callback for /stream endpoint
// Called repeatedly to get new frames for streaming
// Returns malloc'd JPEG data for the current frame or NULL to end stream
// result_size will be set to the size of the returned data
typedef uint8_t* (*hcs_stream_callback)(uint64_t* result_size);

//Update the HCS, and start/kill the server if needed
void hcs_update(bool enable, int64_t port, hcs_callback callback);

//Set the streaming callback for /stream endpoint
void hcs_set_stream_callback(hcs_stream_callback stream_callback);

//Suspend and resume callbacks from multiple threads
void hcs_suspend_callbacks();
void hcs_resume_callbacks();

//Join this thread to the server thread
void hcs_join_server_thread();

#endif