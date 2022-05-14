// dear imgui: Platform Backend for SDL2
// This needs to be used along with a Renderer (e.g. DirectX11, OpenGL3, Vulkan..)
// (Info: SDL2 is a cross-platform general purpose library for handling windows, inputs, graphics context creation, etc.)

// Implemented features:
//  [X] Platform: Clipboard support.
//  [X] Platform: Keyboard support. Since 1.87 we are using the io.AddKeyEvent() function. Pass ImGuiKey values to all key functions e.g. ImGui::IsKeyPressed(ImGuiKey_Space). [Legacy SDL_SCANCODE_* values will also be supported unless IMGUI_DISABLE_OBSOLETE_KEYIO is set]
//  [X] Platform: Gamepad support. Enabled with 'io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad'.
//  [X] Platform: Mouse cursor shape and visibility. Disable with 'io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange'.
//  [X] Platform: Multi-viewport support (multiple windows). Enable with 'io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable'.
// Missing features:
//  [ ] Platform: SDL2 handling of IME under Windows appears to be broken and it explicitly disable the regular Windows IME. You can restore Windows IME by compiling SDL with SDL_DISABLE_WINDOWS_IME.
//  [ ] Platform: Multi-viewport + Minimized windows seems to break mouse wheel events (at least under Windows).

// You can use unmodified imgui_impl_* files in your project. See examples/ folder for examples of using this.
// Prefer including the entire imgui/ repository into your project (either as a copy or as a submodule), and only build the backends you need.
// If you are new to Dear ImGui, read documentation from the docs/ folder + read the top of imgui.cpp.
// Read online: https://github.com/ocornut/imgui/tree/master/docs
#ifdef IMGUI_ENABLE_FREETYPE
#ifndef CIMGUI_FREETYPE
#error "IMGUI_FREETYPE should be defined for Freetype linking"
#endif
#else
#ifdef CIMGUI_FREETYPE
#error "IMGUI_FREETYPE should not be defined without freetype generated cimgui"
#endif
#endif
#include "imgui.h"
#ifdef IMGUI_ENABLE_FREETYPE
#include "misc/freetype/imgui_freetype.h"
#endif
#include "imgui_internal.h"
#include "cimgui.h"

#include "cimgui_sdl_ogl3_backend.h"

#include "backends/imgui_impl_opengl3.h"
#include "backends/imgui_impl_sdl.h"

CIMGUI_API bool  igImplSDL2_InitForOpenGL(SDL_Window* window, void* sdl_gl_context){ return ImGui_ImplSDL2_InitForOpenGL(window,sdl_gl_context);}
CIMGUI_API bool  igImplSDL2_InitForVulkan(SDL_Window* window){ return ImGui_ImplSDL2_InitForVulkan(window);}
CIMGUI_API bool  igImplSDL2_InitForD3D(SDL_Window* window){ return ImGui_ImplSDL2_InitForD3D(window);}
CIMGUI_API bool  igImplSDL2_InitForMetal(SDL_Window* window){ return ImGui_ImplSDL2_InitForMetal(window);}
CIMGUI_API bool  igImplSDL2_InitForSDLRenderer(SDL_Window* window, SDL_Renderer* renderer){ return ImGui_ImplSDL2_InitForSDLRenderer(window,renderer);}
CIMGUI_API void  igImplSDL2_Shutdown(){ return ImGui_ImplSDL2_Shutdown();}
CIMGUI_API void  igImplSDL2_NewFrame(){ return ImGui_ImplSDL2_NewFrame();}
CIMGUI_API bool  igImplSDL2_ProcessEvent(const SDL_Event* event){ return ImGui_ImplSDL2_ProcessEvent(event);}

// Backend API
CIMGUI_API bool igImplOpenGL3_Init(const char* glsl_version){ return ImGui_ImplOpenGL3_Init(glsl_version);}
CIMGUI_API void igImplOpenGL3_Shutdown(){ return ImGui_ImplOpenGL3_Shutdown();}
CIMGUI_API void igImplOpenGL3_NewFrame(){ return ImGui_ImplOpenGL3_NewFrame();}
CIMGUI_API void igImplOpenGL3_RenderDrawData(ImDrawData* draw_data){ return ImGui_ImplOpenGL3_RenderDrawData(draw_data);}

// (Optional) Called by Init/NewFrame/Shutdown
CIMGUI_API bool igImplOpenGL3_CreateFontsTexture(){ return ImGui_ImplOpenGL3_CreateFontsTexture();}
CIMGUI_API void igImplOpenGL3_DestroyFontsTexture(){ return ImGui_ImplOpenGL3_DestroyFontsTexture();}
CIMGUI_API bool igImplOpenGL3_CreateDeviceObjects(){ return ImGui_ImplOpenGL3_CreateDeviceObjects();}
CIMGUI_API void igImplOpenGL3_DestroyDeviceObjects(){ return ImGui_ImplOpenGL3_DestroyDeviceObjects();}
