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
//Update the HCS, and start/kill the server if needed
void hcs_update(bool enable, int64_t port, hcs_callback callback);

//Suspend and resume callbacks from multiple threads
void hcs_suspend_callbacks();
void hcs_resume_callbacks();


#endif