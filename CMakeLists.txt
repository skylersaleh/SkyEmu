cmake_minimum_required(VERSION 3.15) # Needed to set MSVC Runtime type
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)

if(APPLE AND (NOT IOS) AND (NOT ANDROID))
  set(MACOS 1)
endif()
if(MACOS OR IOS)
  project(SkyEmu OBJC C CXX)
  if(IOS)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -x objective-c")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -x objective-c++")
  endif()
else()
  project(SkyEmu C CXX)
endif()


set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(LINK_LIBS "")
if (EMSCRIPTEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html -s USE_CLOSURE_COMPILER=0 ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DPLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html  -s USE_CLOSURE_COMPILER=0 ")
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

if( (NOT ANDROID))
    set(USE_SDL 1)
    add_definitions(-DUSE_SDL=1)
endif()

if (NOT EMSCRIPTEN)
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -g -O3 ")
  set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -g -O3 ")
  set(UNICODE_GUI 1)
else () 
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -O3 -DNDEBUG")
  set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -O3 -DNDEBUG") 
endif ()
if(IOS)
    set(CMAKE_XCODE_ATTRIBUTE_IPHONEOS_DEPLOYMENT_TARGET "11.0" CACHE STRING "Minimum iOS deployment version" FORCE)
    set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_REQUIRED "NO" FORCE)
    set(CMAKE_XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO" FORCE)
endif()
if(WIN32)
  message("Building for Windows")
  add_definitions(-DPLATFORM_WINDOWS=1)
endif()
if(ANDROID)
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS}")
  set(CMAKE_C_FLAGS  "${CMAKE_C_FLAGS}") 
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
if(NOT IOS)
  find_package(OpenGL)
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Linux -pthread shenanigans
if (CMAKE_SYSTEM_NAME STREQUAL Linux)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    find_package(ALSA REQUIRED)
    set(PLATFORM_LINUX TRUE)
endif()
if (UNIX AND NOT APPLE AND NOT PLATFORM_LINUX)
  set(PLATFORM_FREEBSD TRUE)
endif()
# TinyFileDialogs
if ((NOT IOS) AND (NOT EMSCRIPTEN) AND (NOT ANDROID) AND (NOT PLATFORM_LINUX) AND (NOT PLATFORM_FREEBSD))
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

if(NOT EMSCRIPTEN)
  set(ENABLE_HTTP_CONTROL_SERVER 1)
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
if(USE_SDL)
    message("Build with SDL!")

    #=== LIBRARY: SDL2
    set(SDL_SHARED OFF CACHE BOOL "Build Shared" FORCE)
    set(SDL_STATIC ON CACHE BOOL "Build Static" FORCE)
    set(SDL_FORCE_STATIC_VCRT ON CACHE BOOL "USE LIBC" FORCE)
    set(SDL_LIBC ON CACHE BOOL "USE LIBC" FORCE)    
    set(SDL_STATIC_PIC ON CACHE BOOL "Build Static PIC" FORCE)
    # Allow some projects to be built conditionally.
    set(SDL2_DISABLE_SDL2MAIN  ON CACHE BOOL "Disable building/installation of SDL2main" FORCE)
    set(SDL2_DISABLE_INSTALL    ON CACHE BOOL "Disable installation of SDL2" FORCE)
    set(SDL2_DISABLE_UNINSTALL  ON CACHE BOOL "Disable uninstallation of SDL2" FORCE)    

    set(SDL_LIBC               ON CACHE BOOL "Use the system C library" ${OPT_DEF_LIBC} FORCE)
    set(SDL_ATOMIC OFF CACHE BOOL "SDL Video support" FORCE)
    set(SDL_AUDIO OFF CACHE BOOL "SDL Video support" FORCE)
    set(SDL_FILE OFF CACHE BOOL "SDL Video support" FORCE)
    set(SDL_THREAD OFF CACHE BOOL "SDL Video support" FORCE)
    set(SDL_RENDER OFF CACHE BOOL "SDL Video support" FORCE)
    set(SDL_LOCALE OFF CACHE BOOL "SDL Video support" FORCE)    

    add_definitions(-DSDL_LEAN_AND_MEAN=1)
    add_subdirectory(src/SDL2)
    set_property(TARGET SDL2-static PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

if (EMSCRIPTEN)
    set(CMAKE_EXECUTABLE_SUFFIX ".html") # This line is used to set your executable to build with the emscripten html template so taht you can directly open it.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -sEXPORTED_FUNCTIONS=[_se_load_settings,_main] -sEXPORTED_RUNTIME_METHODS=ccall ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -sEXPORTED_FUNCTIONS=[_se_load_settings,_main] -sEXPORTED_RUNTIME_METHODS=ccall ")
endif ()

#=== LIBRARY: sokol
# add headers to the the file list because they are useful to have in IDEs
set(SOKOL_HEADERS
    src/sokol/sokol_gfx.h
    src/sokol/sokol_app.h
    src/sokol/sokol_time.h
    src/sokol/sokol_imgui.h
    src/sokol/sokol_audio.h
    src/sokol/sokol_glue.h)
if(ANDROID)
    add_definitions(-DPLATFORM_ANDROID)
    set(LINK_LIBS ${LINK_LIBS}  GLESv3 EGL OpenSLES log android)
    message("Android Build!")
endif()
if(MACOS OR IOS)
    add_library(sokol STATIC src/sokol/sokol.m ${SOKOL_HEADERS})
    if(MACOS AND (NOT IOS))
        add_definitions(-DPLATFORM_MACOS)
        target_link_libraries(sokol PUBLIC
            "-framework QuartzCore"
            "-framework Cocoa"
            "-framework MetalKit"
            "-framework AudioToolbox"
            "-framework Metal")
    endif()
    if(IOS)
        set(system_libs ${system_libs} "-framework Foundation" "-framework UIKit" "-framework AudioToolbox" "-framework AVFoundation -framework GameController")
        if (SOKOL_BACKEND STREQUAL SOKOL_METAL)
            set(system_libs ${system_libs} "-framework Metal" "-framework MetalKit")
        else()
            set(system_libs ${system_libs} "-framework OpenGLES" "-framework GLKit")
        endif()
        target_link_libraries(sokol PUBLIC ${system_libs})
    endif()
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

find_package(Git)

if(GIT_EXECUTABLE)
  # Generate a git-describe version string from Git repository tags
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if(NOT GIT_DESCRIBE_ERROR_CODE)
    set(GIT_COMMIT_HASH ${GIT_DESCRIBE})
  endif()
  execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if(NOT GIT_DESCRIBE_ERROR_CODE)
    set(GIT_BRANCH ${GIT_DESCRIBE})
  endif()
  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --exact-match --tags
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE
    RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if(NOT GIT_DESCRIBE_ERROR_CODE)
    set(GIT_TAG ${GIT_DESCRIBE})
  endif()
endif()

# Final fallback: Just use a bogus version string that is semantically older
# than anything else and spit out a warning to the developer.
if(NOT DEFINED GIT_COMMIT_HASH)
  set(GIT_COMMIT_HASH "(Modified Local Build)")
  message(WARNING "Failed to determine GIT_COMMIT_HASH from Git tags. Using default version \"${GIT_COMMIT_HASH}\".")
endif()
add_definitions(-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\")
add_definitions(-DGIT_BRANCH=\"${GIT_BRANCH}\")
add_definitions(-DGIT_TAG=\"${GIT_TAG}\")

set(SKYEMU_SRC src/main.c src/stb.c src/miniz.c src/res.c src/localization.c)

if(ENABLE_HTTP_CONTROL_SERVER)
  add_definitions(-DENABLE_HTTP_CONTROL_SERVER=1)
  set(SKYEMU_SRC ${SKYEMU_SRC} src/http_control_server.cpp)
endif()

if(UNICODE_GUI)
  set(SKYEMU_SRC ${SKYEMU_SRC} src/utf8proc/utf8proc.c)
  include_directories(src/utf8proc/)
  add_definitions(-DUNICODE_GUI=1)
  add_definitions(-DUTF8PROC_STATIC=1)

endif()

if(USE_SDL)
    include_directories(${SDL2_INCLUDE_DIRS})
endif()

if(IOS)
    set(SKYEMU_SRC ${SKYEMU_SRC} src/ios_support.m)
    add_definitions(-DPLATFORM_IOS)
endif()

if(WIN32)
    set(APP_ICON_RESOURCE_WINDOWS "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/icons/appicon.rc")
    add_executable(${PROJECT_NAME} WIN32 ${SKYEMU_SRC} ${APP_ICON_RESOURCE_WINDOWS})
elseif(MACOS OR IOS)
    set(MACOSX_BUNDLE_GUI_IDENTIFIER "SkyEmu")
    set(MACOSX_BUNDLE_SHORT_VERSION_STRING ${GIT_COMMIT_HASH})
    set(MACOSX_BUNDLE_LONG_VERSION_STRING ${GIT_COMMIT_HASH})
    set(MACOSX_BUNDLE_BUNDLE_VERSION ${GIT_COMMIT_HASH})
    if(MACOS)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "10.13" CACHE STRING "Minimum OS X deployment version" FORCE)
    endif()

    set(MACOSX_BUNDLE_ICON_FILE AppIcon.icns)
    set(APP_ICON src/resources/icons/AppIcon.icns)
    set_source_files_properties(${APP_ICON} PROPERTIES MACOSX_PACKAGE_LOCATION "Resources")
    add_executable(${PROJECT_NAME} ${SKYEMU_SRC} ${APP_ICON})
    if(IOS)
        set_property(TARGET ${PROJECT_NAME} PROPERTY XCODE_ATTRIBUTE_PRODUCT_BUNDLE_IDENTIFIER "SkyEmu")
        set_property(TARGET ${PROJECT_NAME} PROPERTY MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/src/resources/ios-info.plist.in")
        set_target_properties(${PROJECT_NAME} PROPERTIES XCODE_ATTRIBUTE_TARGETED_DEVICE_FAMILY "1,2")
    endif()
elseif(ANDROID)
    add_library(${PROJECT_NAME} SHARED ${SKYEMU_SRC})
else()
    add_executable(${PROJECT_NAME} ${SKYEMU_SRC})
endif()
if (${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-s TOTAL_MEMORY=1024MB -lidbfs.js -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -flto -s USE_CLOSURE_COMPILER=0 --closure 0 ")
endif ()
if (EMSCRIPTEN)
  configure_file(src/sw.js.in ${CMAKE_CURRENT_BINARY_DIR}/bin/sw.js)
endif ()
set(LINK_LIBS ${LINK_LIBS} sokol ${ALSA_LIBRARIES})

set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build capstone tests" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build capstone cstool" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build capstone shared library" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Include all CAPSTONE architectures" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "ARM disasm support")
set(CAPSTONE_BUILD_STATIC_RUNTIME ON CACHE BOOL "Capstone static runtime" FORCE)
add_subdirectory(src/capstone)
set_property(TARGET capstone-static PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

set(LINK_LIBS ${LINK_LIBS} capstone-static ${ALSA_LIBRARIES})
if(USE_SDL)
  set(LINK_LIBS ${LINK_LIBS} SDL2-static)
endif()

target_link_libraries(${PROJECT_NAME} ${LINK_LIBS})
if(MSVC)
    set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
elseif(MACOS OR IOS)
    set_target_properties(${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE ON
        MACOSX_BUNDLE_BUNDLE_NAME ${PROJECT_NAME}
        MACOSX_BUNDLE_BUNDLE_IDENTIFIER "com.sky.${PROJECT_NAME}")
elseif(EMSCRIPTEN)
    add_custom_command(
        TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${CMAKE_CURRENT_SOURCE_DIR}/src/resources/icons/favicon_package
                ${CMAKE_CURRENT_BINARY_DIR}/bin)
endif()

