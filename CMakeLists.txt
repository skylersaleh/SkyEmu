cmake_minimum_required(VERSION 3.15) # Needed to set MSVC Runtime type
project(SkyEmu)


set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(LINK_LIBS "")
if (EMSCRIPTEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1  -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html -s USE_CLOSURE_COMPILER=1 ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html  -s USE_CLOSURE_COMPILER=1 ")
    set(CMAKE_EXECUTABLE_SUFFIX ".html") # This line is used to set your executable to build with the emscripten html template so taht you can directly open it.
endif ()
if (MSVC)
    # Perform extremely aggressive optimization on Release builds:
    # Flags on Visual Studio 2010 and newer:
    # Runtime library: Multi-threaded (/MT) as opposed to default 'Multi-threaded DLL' - static runtime library allows better LTCG inlining opportunities.
    # Optimization: Full Optimization (/Ox)
    # Inline Function Expansion: Any Suitable (/Ob2)
    # Enable Intrinsic Functions: Yes (/Oi)
    # Favor Size Or Speed: Favor fast code (/Ot)
    # Enable Fiber-Safe Optimizations: Yes (/GT)
    # Enable String Pooling: Yes (/GF)
    # Buffer Security Check: No (/GS-)
    # Floating Point Model: Fast (/fp:fast)
    # Enable Floating Point Exceptions: No (/fp:except-)
    # Build with Multiple Processes (/MP)
    # No secure development lifecycle features
    # Exception handling model: Catch C++ exceptions only, assume that "extern C" functions will never throw a C++ exception.
    # Disable all forms of MSVC debug iterator checking in new and old Visual Studios.
    # Causes the application to use the multithread, static version of the run-time library. 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /MT /Ox /Ob2 /Oi /Ot /GT /GF /GS- /fp:fast /fp:except- /MP /sdl- /EHsc /D_SECURE_SCL=0 /D_SCL_SECURE_NO_WARNINGS /D_ITERATOR_DEBUG_LEVEL=0 /D_HAS_ITERATOR_DEBUGGING=0")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT /Ox /Ob2 /Oi /Ot /GT /GF /GS- /fp:fast /fp:except- /MP /sdl- /EHsc /D_SECURE_SCL=0 /D_SCL_SECURE_NO_WARNINGS /D_ITERATOR_DEBUG_LEVEL=0 /D_HAS_ITERATOR_DEBUGGING=0 ")

endif()

if (NOT EMSCRIPTEN)
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -O3")
  set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -g -O3") 
else () 
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
  set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -O3 -DNDEBUG") 
endif ()
find_package(OpenGL)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Linux -pthread shenanigans
if (CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    find_package(ALSA REQUIRED)
endif()

# TinyFileDialogs
if ((NOT IOS) OR (NOT EMSCRIPTEN) OR (NOT ANDROID))
    set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DUSE_TINY_FILE_DIALOGS")
    set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -DUSE_TINY_FILE_DIALOGS") 
    add_library(tinyfd STATIC 
        src/tinyfiledialogs/tinyfiledialogs.h
        src/tinyfiledialogs/tinyfiledialogs.c
    )
    target_include_directories(tinyfd INTERFACE src/tinyfiledialogs)
    set(LINK_LIBS ${LINK_LIBS} tinyfd)
    set_property(TARGET tinyfd PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

#=== LIBRARY: cimgui + Dear ImGui
add_library(cimgui STATIC 
    src/cimgui/cimgui.cpp 
    src/cimgui/cimgui.h 
    src/cimgui/imgui/imgui.cpp
    src/cimgui/imgui/imgui.h
    src/cimgui/imgui/imgui_widgets.cpp 
    src/cimgui/imgui/imgui_draw.cpp 
    src/cimgui/imgui/imgui_tables.cpp
    src/cimgui/imgui/imgui_demo.cpp
    )
set_property(TARGET cimgui PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

target_include_directories(cimgui INTERFACE src/cimgui)

#=== LIBRARY: sokol
# add headers to the the file list because they are useful to have in IDEs
set(SOKOL_HEADERS
    src/sokol/sokol_gfx.h
    src/sokol/sokol_app.h
    src/sokol/sokol_time.h
    src/sokol/sokol_imgui.h
    src/sokol/sokol_audio.h
    src/sokol/sokol_glue.h)
if(CMAKE_SYSTEM_NAME STREQUAL Darwin)
    add_library(sokol STATIC src/sokol/sokol.m ${SOKOL_HEADERS})
    target_link_libraries(sokol PUBLIC
        "-framework QuartzCore"
        "-framework Cocoa"
        "-framework MetalKit"
        "-framework AudioToolbox"
        "-framework Metal")
else()
    add_library(sokol STATIC src/sokol/sokol.c ${SOKOL_HEADERS})
    set_property(TARGET sokol PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    if (CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(sokol INTERFACE X11 Xi Xcursor GL dl m)
        target_link_libraries(sokol PUBLIC Threads::Threads)
    endif()
endif()
target_link_libraries(sokol PUBLIC cimgui)
target_include_directories(sokol INTERFACE src/sokol)
if(WIN32)
    add_executable(${PROJECT_NAME} WIN32 src/main.c)
else()
    add_executable(${PROJECT_NAME} src/main.c)
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-s TOTAL_MEMORY=256MB -lidbfs.js -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -flto -s USE_CLOSURE_COMPILER=1 --closure 1 ")
endif ()
set(LINK_LIBS ${LINK_LIBS} sokol ${ALSA_LIBRARIES})
target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})
set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

# That's it! You should have an example executable that you can run. Have fun!
