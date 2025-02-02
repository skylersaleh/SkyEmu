cmake_minimum_required(VERSION 3.15) # Needed to set MSVC Runtime type
set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64" CACHE STRING "" FORCE)
include("cmake/FindOpenGL.cmake")

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

if(CMAKE_SYSTEM_PROCESSOR MATCHES "armv7l|aarch64|arm")
    set(IS_ARM TRUE)
else()
    set(IS_ARM FALSE)
endif()

# Function to check if a command exists
function(command_exists CMD RESULT_VAR)
    execute_process(COMMAND which ${CMD} OUTPUT_VARIABLE CMD_PATH RESULT_VARIABLE CMD_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(CMD_RESULT EQUAL 0)
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)
    endif()
endfunction()

command_exists("vcgencmd" IS_VIDEOCORE)

function(check_gles3_support SUPPORTS_GLES3)
    # Initialize variable
    set(${SUPPORTS_GLES3} OFF PARENT_SCOPE)

    # Run the Bash one-liner to get the SoC version as a decimal number
    execute_process(
        COMMAND bash -c "awk '/Revision/ { rev = \"0x\" substr(\$3, length(\$3)-3, 4); printf \"%d\n\", (rev / 4096) % 16 }' /proc/cpuinfo"
        OUTPUT_VARIABLE SOC_VERSION_DEC
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Determine GLES3 support based on the SoC version
    if(SOC_VERSION_DEC GREATER_EQUAL 3)
        # BCM2711 or newer
        set(${SUPPORTS_GLES3} ON PARENT_SCOPE)
    endif()
endfunction()

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)
set(LINK_LIBS "")

# Set compile_commands.json generation for clangd on by default
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(ENABLE_RETRO_ACHIEVEMENTS "Enable Retro Achievements" ON)

option(USE_SYSTEM_CURL "Use the system's libcurl package" OFF)
option(USE_SYSTEM_OPENSSL "Use the system's OpenSSL package" OFF)
option(USE_SYSTEM_SDL2 "Use the system's SDL2 package" OFF)

if (EMSCRIPTEN)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DSE_PLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html -s USE_CLOSURE_COMPILER=0 ")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s ERROR_ON_UNDEFINED_SYMBOLS=0 -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -s ENVIRONMENT=web -s ASSERTIONS=0 -s WASM=1 -DSE_PLATFORM_WEB --shell-file ${PROJECT_SOURCE_DIR}/src/shell.html  -s USE_CLOSURE_COMPILER=0 ")
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

if(NOT ANDROID)
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
  add_definitions(-DSE_PLATFORM_WINDOWS=1)
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
if ((CMAKE_SYSTEM_NAME STREQUAL Linux) AND NOT EMSCRIPTEN AND NOT ANDROID)
    set(THREADS_PREFER_PTHREAD_FLAG ON)
    find_package(Threads REQUIRED)
    find_package(ALSA REQUIRED)
    set(SE_PLATFORM_LINUX TRUE)

    # Check for GLES3 support on the Raspberry Pi
    if (IS_ARM AND IS_VIDEOCORE)
        check_gles3_support(SUPPORTS_GLES3)
        if(SUPPORTS_GLES3)
           set(SE_FORCE_GLES3 TRUE)
           add_definitions(-DSE_FORCE_GLES3=1)
        else()
           set(SE_FORCE_GLES2 TRUE)
           add_definitions(-DSE_FORCE_GLES2=1)
        endif()
    endif()
    add_definitions(-DSE_PLATFORM_LINUX=1)
endif()
if (UNIX AND NOT APPLE AND NOT SE_PLATFORM_LINUX AND NOT EMSCRIPTEN AND NOT ANDROID)
  set(SE_PLATFORM_FREEBSD TRUE)
  add_definitions(-DSE_PLATFORM_FREEBSD=1)
  find_package(ALSA REQUIRED)
  link_directories(/usr/local/lib)
endif()

if (SE_PLATFORM_LINUX OR SE_PLATFORM_FREEBSD)
    find_package(X11 REQUIRED)
endif()

if (USE_SYSTEM_CURL OR USE_SYSTEM_OPENSSL)
  find_package(PkgConfig REQUIRED)
endif()

if(NOT EMSCRIPTEN)
  if (USE_SYSTEM_CURL)
    pkg_check_modules(Curl REQUIRED IMPORTED_TARGET libcurl)
  else()
    set(WITH_APPS OFF CACHE BOOL "" FORCE) # don't build executable
    set(CURL_USE_LIBSSH2 OFF)
    set(CURL_USE_LIBPSL OFF)
    set(CURL_USE_OPENSSL ON)
    set(CURL_DISABLE_LDAP ON)
    set(USE_LIBIDN2 OFF)
    set(CURL_ENABLE_EXPORT_TARGET OFF)
    set(BUILD_TESTING OFF)
    set(BUILD_CURL_EXE OFF)
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_STATIC_LIBS ON)
    if (WIN32)
      set(CURL_STATIC_CRT ON)
    endif()
    # see "Important static libcurl usage note" in INSTALL.md
    add_definitions(-DCURL_STATICLIB)
    add_subdirectory(src/curl)
    set_property(TARGET libcurl_static PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  endif()

  if(USE_SYSTEM_OPENSSL)
    pkg_check_modules(OpenSSL REQUIRED IMPORTED_TARGET openssl)
  else()
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_STATIC_LIBS ON)
    add_subdirectory(src/openssl)
    set_property(TARGET ssl PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
    set_property(TARGET crypto PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  endif()
endif()

# TinyFileDialogs
if ((NOT IOS) AND (NOT EMSCRIPTEN) AND (NOT ANDROID) AND (NOT SE_PLATFORM_LINUX) AND (NOT SE_PLATFORM_FREEBSD))
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
  if (USE_SYSTEM_SDL2)
    pkg_check_modules(SDL2 REQUIRED IMPORTED_TARGET sdl2)
  else()
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
endif()

if (EMSCRIPTEN)
    set(CMAKE_EXECUTABLE_SUFFIX ".html") # This line is used to set your executable to build with the emscripten html template so taht you can directly open it.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -sEXPORTED_FUNCTIONS=[_se_load_settings,_se_login_cloud,_https_open_url,_main,_malloc,_free,_em_oath_sign_in_callback,_em_https_request_callback_wrapper,_gsecret_web] -sEXPORTED_RUNTIME_METHODS=ccall")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -sEXPORTED_FUNCTIONS=[_se_load_settings,_se_login_cloud,_https_open_url,_main,_malloc,_free,_em_oath_sign_in_callback,_em_https_request_callback_wrapper,_gsecret_web] -sEXPORTED_RUNTIME_METHODS=ccall")
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
    add_definitions(-DSE_PLATFORM_ANDROID)
    set(LINK_LIBS ${LINK_LIBS}  GLESv3 EGL OpenSLES log android)
    message("Android Build!")
endif()
if(MACOS OR IOS)
    add_library(sokol STATIC src/sokol/sokol.m ${SOKOL_HEADERS})
    if(MACOS AND (NOT IOS))
        add_definitions(-DSE_PLATFORM_MACOS)
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
    if (SE_PLATFORM_LINUX OR SE_PLATFORM_FREEBSD)
        target_include_directories(sokol PRIVATE "${X11_INCLUDE_DIR}")
        if(SE_FORCE_GLES2)
          target_link_libraries(sokol INTERFACE ${X11_X11_LIB} ${X11_Xi_LIB} ${X11_Xcursor_LIB} OpenGL::GLES2 EGL dl)
        elseif(SE_FORCE_GLES3)
          target_link_libraries(sokol INTERFACE ${X11_X11_LIB} ${X11_Xi_LIB} ${X11_Xcursor_LIB} OpenGL::GLES3 EGL dl)
        else()
          target_link_libraries(sokol INTERFACE ${X11_X11_LIB} ${X11_Xi_LIB} ${X11_Xcursor_LIB} OpenGL::OpenGL dl)
        endif()
    endif()
    if (CMAKE_SYSTEM_NAME STREQUAL Linux)
        target_link_libraries(sokol INTERFACE m)
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

set(SKYEMU_SRC src/main.c src/shared.c src/cloud.cpp src/https.cpp src/stb.c src/miniz.c src/res.c src/localization.c src/mutex.cpp)

if(ENABLE_HTTP_CONTROL_SERVER)
  add_definitions(-DENABLE_HTTP_CONTROL_SERVER=1)
  set(SKYEMU_SRC ${SKYEMU_SRC} src/http_control_server.cpp)
endif()

set(SKYEMU_SRC ${SKYEMU_SRC} src/cloud.cpp src/https.cpp src/atlas.cpp)

if(UNICODE_GUI)
  set(SKYEMU_SRC ${SKYEMU_SRC} src/utf8proc/utf8proc.c)
  include_directories(src/utf8proc/)
  add_definitions(-DUNICODE_GUI=1)
  add_definitions(-DUTF8PROC_STATIC=1)
endif()

if(USE_SDL AND NOT USE_SYSTEM_SDL2)
    include_directories(${SDL2_INCLUDE_DIRS})
endif()

if(ENABLE_RETRO_ACHIEVEMENTS)
  add_definitions(-DENABLE_RETRO_ACHIEVEMENTS=1)
  add_definitions(-DRC_CLIENT_SUPPORTS_HASH)
  add_library(Lua STATIC src/lua/onelua.c)
  if(IOS)
    target_compile_definitions(Lua PRIVATE LUA_USE_IOS) # makes it so system is not used
  endif()
  set_property(TARGET Lua PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")
  set(LINK_LIBS ${LINK_LIBS} Lua)
  set(RCHEEVOS_SRC src/rcheevos/src/rapi/rc_api_common.c
    src/rcheevos/src/rapi/rc_api_editor.c
    src/rcheevos/src/rapi/rc_api_info.c
    src/rcheevos/src/rapi/rc_api_runtime.c
    src/rcheevos/src/rapi/rc_api_user.c
    src/rcheevos/src/rapi/rc_api_common.c
    src/rcheevos/src/rcheevos/alloc.c
    src/rcheevos/src/rcheevos/condition.c
    src/rcheevos/src/rcheevos/condset.c
    src/rcheevos/src/rcheevos/consoleinfo.c
    src/rcheevos/src/rcheevos/format.c
    src/rcheevos/src/rcheevos/lboard.c
    src/rcheevos/src/rcheevos/memref.c
    src/rcheevos/src/rcheevos/operand.c
    src/rcheevos/src/rc_compat.c
    src/rcheevos/src/rc_client.c
    src/rcheevos/src/rc_util.c
    src/rcheevos/src/rc_client_raintegration.c
    src/rcheevos/src/rcheevos/rc_validate.c
    src/rcheevos/src/rcheevos/richpresence.c
    src/rcheevos/src/rcheevos/runtime.c
    src/rcheevos/src/rcheevos/runtime_progress.c
    src/rcheevos/src/rcheevos/trigger.c
    src/rcheevos/src/rcheevos/value.c
    src/rcheevos/src/rhash/cdreader.c
    src/rcheevos/src/rhash/hash.c
    src/rcheevos/src/rhash/md5.c
    src/rcheevos/src/rhash/aes.c
    src/rcheevos/src/rurl/url.c
  )
  set(SKYEMU_SRC ${SKYEMU_SRC} ${RCHEEVOS_SRC} src/retro_achievements.cpp)
  include_directories(src/rcheevos/include src/lua)
endif()

if(IOS)
    set(SKYEMU_SRC ${SKYEMU_SRC} src/ios_support.m)
    add_definitions(-DSE_PLATFORM_IOS)
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

add_library(skyemu_libretro SHARED EXCLUDE_FROM_ALL src/libretro.c src/shared.c src/localization.c)
set_target_properties(skyemu_libretro PROPERTIES PREFIX "")
if (MACOS OR IOS)
    find_library(FoundationLib CoreFoundation)
    target_link_libraries(skyemu_libretro ${FoundationLib})
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Emscripten")
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-sALLOW_MEMORY_GROWTH -s TOTAL_MEMORY=192MB -lidbfs.js -s ELIMINATE\_DUPLICATE\_FUNCTIONS=1 -flto -s USE_CLOSURE_COMPILER=0 --closure 0 ")
endif ()
if (EMSCRIPTEN)
  configure_file(src/sw.js.in ${CMAKE_CURRENT_BINARY_DIR}/bin/sw.js)
endif ()

set(LINK_LIBS ${LINK_LIBS} sokol ${ALSA_LIBRARIES})

if(NOT EMSCRIPTEN)
  if (USE_SYSTEM_OPENSSL)
    set(LINK_LIBS ${LINK_LIBS} PkgConfig::OpenSSL)
  else()
    target_include_directories(${PROJECT_NAME} PRIVATE src/openssl/include)
    # OpenSSL autogenerates some header file such as openssl/opensslconf.h and we want to include them
    target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/src/openssl/include)
  endif()
  if (USE_SYSTEM_CURL)
    set(LINK_LIBS ${LINK_LIBS} PkgConfig::Curl)
  else()
    target_include_directories(${PROJECT_NAME} PRIVATE src/curl/include)
    set(LINK_LIBS ${LINK_LIBS} libcurl_static ssl crypto)
  endif()
endif()

set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "Build capstone tests" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "Build capstone cstool" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Build capstone shared library" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Include all CAPSTONE architectures" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "ARM disasm support")
set(CAPSTONE_BUILD_STATIC_RUNTIME ON CACHE BOOL "Capstone static runtime" FORCE)
add_subdirectory(src/capstone EXCLUDE_FROM_ALL)
set_property(TARGET capstone-static PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded")

set(LINK_LIBS ${LINK_LIBS} capstone-static ${ALSA_LIBRARIES})
if(USE_SDL)
  if(USE_SYSTEM_SDL2)
    set(LINK_LIBS ${LINK_LIBS} PkgConfig::SDL2)
  else()
    set(LINK_LIBS ${LINK_LIBS} SDL2-static)
  endif()
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

install(TARGETS ${PROJECT_NAME}
  RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}/bin"
  BUNDLE DESTINATION "${CMAKE_INSTALL_PREFIX}/Applications")
