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

typedef struct SDL_Window SDL_Window;
typedef struct SDL_Renderer SDL_Renderer;
typedef union SDL_Event SDL_Event;
#include "cimgui.h"

CIMGUI_API bool  igImplSDL2_InitForOpenGL(SDL_Window* window, void* sdl_gl_context);
CIMGUI_API bool  igImplSDL2_InitForVulkan(SDL_Window* window);
CIMGUI_API bool  igImplSDL2_InitForD3D(SDL_Window* window);
CIMGUI_API bool  igImplSDL2_InitForMetal(SDL_Window* window);
CIMGUI_API bool  igImplSDL2_InitForSDLRenderer(SDL_Window* window, SDL_Renderer* renderer);
CIMGUI_API void  igImplSDL2_Shutdown();
CIMGUI_API void  igImplSDL2_NewFrame();
CIMGUI_API bool  igImplSDL2_ProcessEvent(const SDL_Event* event);

// Backend API
CIMGUI_API bool igImplOpenGL3_Init(const char* glsl_version);
CIMGUI_API void igImplOpenGL3_Shutdown();
CIMGUI_API void igImplOpenGL3_NewFrame();
CIMGUI_API void igImplOpenGL3_RenderDrawData(ImDrawData* draw_data);

// (Optional) Called by Init/NewFrame/Shutdown
CIMGUI_API bool igImplOpenGL3_CreateFontsTexture();
CIMGUI_API void igImplOpenGL3_DestroyFontsTexture();
CIMGUI_API bool igImplOpenGL3_CreateDeviceObjects();
CIMGUI_API void igImplOpenGL3_DestroyDeviceObjects();


