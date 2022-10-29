// sokol implementation library on non-Apple platforms
#define SOKOL_IMPL
#define SOKOL_IMGUI_IMPL
#if defined(_WIN32)
#define SOKOL_D3D11
#elif defined(__EMSCRIPTEN__)
#define SOKOL_GLES2
#elif defined(PLATFORM_ANDROID)
#define SOKOL_GLES3
#elif defined(__APPLE__)
#error "Must use sokol.m on macOS"
#else
#define SOKOL_GLCORE33
#endif
#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_time.h"
#include "sokol_glue.h"
#include "sokol_audio.h"
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "sokol_imgui.h"
