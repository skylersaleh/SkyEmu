// sokol implementation library on macOS (must be compiled as ObjC)
#define SOKOL_IMPL
#define SOKOL_IMGUI_IMPL
#define SOKOL_METAL
#include "sokol_app.h"
#include "sokol_gfx.h"
#include "sokol_time.h"
#include "sokol_glue.h"
#include "sokol_audio.h"
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "sokol_imgui.h"
