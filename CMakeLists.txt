cmake_minimum_required(VERSION 3.11) # FetchContent is available in 3.11+
project(SkyBoy)


set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

if (EMSCRIPTEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1  -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html")
    set(CMAKE_EXECUTABLE_SUFFIX ".html") # This line is used to set your executable to build with the emscripten html template so taht you can directly open it.
endif ()
 
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} ") 
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
    if (CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(sokol INTERFACE X11 Xi Xcursor GL dl m)
        target_link_libraries(sokol PUBLIC Threads::Threads)
    endif()
endif()
target_link_libraries(sokol PUBLIC cimgui)
target_include_directories(sokol INTERFACE src/sokol)

add_executable(${PROJECT_NAME} src/main.c)
if (${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-s TOTAL_MEMORY=256MB -lidbfs.js")
endif ()

target_link_libraries(${PROJECT_NAME} sokol)

# That's it! You should have an example executable that you can run. Have fun!
