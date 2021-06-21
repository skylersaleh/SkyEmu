cmake_minimum_required(VERSION 3.11) # FetchContent is available in 3.11+
project(SkyBoy)

if (EMSCRIPTEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s USE_GLFW=3 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1  -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s USE_GLFW=3 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html")
    set(CMAKE_EXECUTABLE_SUFFIX ".html") # This line is used to set your executable to build with the emscripten html template so taht you can directly open it.
endif ()
 
set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -O2 ")
set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -O2 ") 

find_package(OpenGL)

#add_subdirectory(${CMAKE_SOURCE_DIR}/libs/raylib)
# Set this to the minimal version you want to support
# find_package(raylib QUIET) # Let CMake search for a raylib-config.cmake
# 
# You could change the QUIET above to REQUIRED and remove this if() clause
# This part downloads raylib and builds it if it's not installed on your system
if (NOT raylib_FOUND) # If there's none, fetch and build raylib
  include(FetchContent)

  FetchContent_Declare(
    raylib
    GIT_REPOSITORY https://github.com/skylersaleh/raylib.git
    GIT_TAG origin/emscripten-resize
  )

  FetchContent_GetProperties(raylib)
  if (NOT raylib_POPULATED) # Have we downloaded raylib yet?
    set(FETCHCONTENT_QUIET NO)
    FetchContent_Populate(raylib)

    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE) # don't build the supplied examples

    # build raylib
    add_subdirectory(${raylib_SOURCE_DIR} ${raylib_BINARY_DIR})

  endif()

endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# This is the main part:

add_executable(${PROJECT_NAME} src/main.c)
if (${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-s TOTAL_MEMORY=128MB -lidbfs.js")
endif ()
#set(raylib_VERBOSE 1)
target_link_libraries(${PROJECT_NAME} raylib)

# That's it! You should have an example executable that you can run. Have fun!
