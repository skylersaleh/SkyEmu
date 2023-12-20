# Based on original work by David Manura
# Copyright (C) 2007-2012 LuaDist.
# Copyright (C) 2013 Brian Sidebotham
# Copyright (C) 2016-2019 Jean-Luc Barriere

# Redistribution and use of this file is allowed according to the terms of the
# MIT license.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
cmake_minimum_required( VERSION 3.1.0 )
set( CMAKE_LEGACY_CYGWIN_WIN32 0 )
project( openssl )

set( CMAKE_DISABLE_SOURCE_CHANGES ON )
set( CMAKE_DISABLE_IN_SOURCE_BUILD ON )

set( CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" )

option( WITH_APPS "Build applications" ON )

# OpenSSL version detection imported from FindOpenSSL.cmake

file( STRINGS "${PROJECT_SOURCE_DIR}/include/openssl/opensslv.h" openssl_version_str
  REGEX "^#[\t ]*define[\t ]+OPENSSL_VERSION_NUMBER[\t ]+0x([0-9a-fA-F])+.*" )

function(from_hex HEX DEC)
  string( TOUPPER "${HEX}" HEX )
  set( _res 0 )
  string( LENGTH "${HEX}" _strlen )

  while( _strlen GREATER 0 )
    math( EXPR _res "${_res} * 16" )
    string( SUBSTRING "${HEX}" 0 1 NIBBLE )
    string( SUBSTRING "${HEX}" 1 -1 HEX )
    if( NIBBLE STREQUAL "A" )
      math( EXPR _res "${_res} + 10" )
    elseif( NIBBLE STREQUAL "B" )
      math( EXPR _res "${_res} + 11" )
    elseif( NIBBLE STREQUAL "C" )
      math( EXPR _res "${_res} + 12" )
    elseif( NIBBLE STREQUAL "D" )
      math( EXPR _res "${_res} + 13" )
    elseif( NIBBLE STREQUAL "E" )
      math( EXPR _res "${_res} + 14" )
    elseif( NIBBLE STREQUAL "F" )
      math( EXPR _res "${_res} + 15" )
    else()
      math( EXPR _res "${_res} + ${NIBBLE}" )
    endif()

    string( LENGTH "${HEX}" _strlen )
  endwhile()

  set( ${DEC} ${_res} PARENT_SCOPE )
endfunction()

string( REGEX REPLACE "^.*OPENSSL_VERSION_NUMBER[\t ]+0x([0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F][0-9a-fA-F])([0-9a-fA-F]).*$"
  "\\1;\\2;\\3;\\4;\\5" OPENSSL_VERSION_LIST "${openssl_version_str}" )
  list( GET OPENSSL_VERSION_LIST 0 OPENSSL_VERSION_MAJOR )
  list( GET OPENSSL_VERSION_LIST 1 OPENSSL_VERSION_MINOR )
  from_hex( "${OPENSSL_VERSION_MINOR}" OPENSSL_VERSION_MINOR )
  list( GET OPENSSL_VERSION_LIST 2 OPENSSL_VERSION_FIX )
  from_hex( "${OPENSSL_VERSION_FIX}" OPENSSL_VERSION_FIX )
  list( GET OPENSSL_VERSION_LIST 3 OPENSSL_VERSION_PATCH )

if( NOT OPENSSL_VERSION_PATCH STREQUAL "00" )
  from_hex( "${OPENSSL_VERSION_PATCH}" _tmp )
  # 96 is the ASCII code of 'a' minus 1
  math( EXPR OPENSSL_VERSION_PATCH_ASCII "${_tmp} + 96" )
  unset( _tmp )
  string( ASCII "${OPENSSL_VERSION_PATCH_ASCII}" OPENSSL_VERSION_PATCH_STRING )
endif()

set( OPENSSL_VERSION "${OPENSSL_VERSION_MAJOR}.${OPENSSL_VERSION_MINOR}.${OPENSSL_VERSION_FIX}${OPENSSL_VERSION_PATCH_STRING}" )

message( STATUS "OpenSSL version ${OPENSSL_VERSION}" )

set( VERSION_MAJOR ${OPENSSL_VERSION_MAJOR} )
set( VERSION_MINOR ${OPENSSL_VERSION_MINOR} )
set( VERSION_PATCH ${OPENSSL_VERSION_FIX} )

set( VERSION_STRING ${OPENSSL_VERSION} )
set( LIB_VERSION ${VERSION_MAJOR}.${VERSION_MINOR} )
set( LIB_SOVERSION ${VERSION_MAJOR}.${VERSION_MINOR} )

add_definitions( -DOPENSSL_NO_ASM )
add_definitions( -DOPENSSL_NO_STATIC_ENGINE )

if( MSVC )
  include( MSVCRuntime )
  configure_msvc_runtime()
  set( OPENSSLDIR "C:/ssl" )
  set( ENGINESDIR "C:/engines-1.1" )
else()
  set( OPENSSLDIR "${CMAKE_INSTALL_PREFIX}/ssl" )
  set( ENGINESDIR "${CMAKE_INSTALL_PREFIX}/engines-1.1" )
endif()
add_definitions( "-DOPENSSLDIR=\"${OPENSSLDIR}\"" )
add_definitions( "-DENGINESDIR=\"${ENGINESDIR}\"" )

if( APPLE )
  set( CMAKE_MACOSX_RPATH ON )
  add_definitions( -DOPENSSL_SYSNAME_MACOSX )
endif()

if( WIN32 )
  set( CMAKE_SHARED_LIBRARY_PREFIX "lib" )
  set( CMAKE_STATIC_LIBRARY_PREFIX "lib" )
endif()

if( WIN32 AND NOT CYGWIN )
  add_definitions( -DOPENSSL_SYSNAME_WIN32 )
  add_definitions( -DWIN32_LEAN_AND_MEAN )
  add_definitions( -D_CRT_SECURE_NO_WARNINGS )

  if(BUILD_SHARED_LIBS)
    # avoid conflict: ocsp.h and wincrypt.h
    add_definitions( -D_WINDLL )
  endif()
endif()

if( MINGW )
  set( CMAKE_SHARED_LINKER_FLAGS "-Wl,--export-all" )
endif()

include( CheckTypeSize )
check_type_size( "long" LONG_INT )
check_type_size( "long long" LONG_LONG_INT )
check_type_size( "int" INT )
if( HAVE_LONG_INT AND (${LONG_INT} EQUAL 8) )
  set( SIXTY_FOUR_BIT_LONG ON )
elseif( CMAKE_SIZEOF_VOID_P EQUAL 8 )
  set( SIXTY_FOUR_BIT ON )
else()
  set( THIRTY_TWO_BIT ON )
endif()

if( MSVC OR ( WIN32 AND MINGW AND NOT CYGWIN ) )
  set( OPENSSL_EXPORT_VAR_AS_FUNCTION 1 )
endif()

# Begin configure public headers
file( COPY ${PROJECT_SOURCE_DIR}/include/internal DESTINATION include )
file( COPY ${PROJECT_SOURCE_DIR}/include/crypto DESTINATION include )
file( COPY ${PROJECT_SOURCE_DIR}/include/openssl DESTINATION include )

file( READ ${PROJECT_SOURCE_DIR}/opensslconf.h.cmake CONF )
set( CONF "
#define OPENSSL_NO_MD2
#define OPENSSL_NO_RC5
#define OPENSSL_NO_RFC3779
#define OPENSSL_NO_EC_NISTP_64_GCC_128
${CONF}" )
file( WRITE ${PROJECT_BINARY_DIR}/opensslconf.h.cmake "${CONF}" )

configure_file( ${PROJECT_BINARY_DIR}/opensslconf.h.cmake
  ${PROJECT_BINARY_DIR}/include/openssl/opensslconf.h )
# End configure public headers

add_subdirectory(crypto)
add_subdirectory(ssl)

if( WITH_APPS AND NOT ANDROID AND NOT IOS )
  add_subdirectory(apps)

  file( READ ${PROJECT_SOURCE_DIR}/c_rehash.cmake C_REHASH )
  string( REPLACE "@OPENSSLDIR@" "${OPENSSLDIR}" C_REHASH "${C_REHASH}" )
  string( REPLACE "@CMAKE_INSTALL_PREFIX@" "${CMAKE_INSTALL_PREFIX}" C_REHASH "${C_REHASH}" )
  file( WRITE ${PROJECT_BINARY_DIR}/c_rehash "${C_REHASH}" )

  install( FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/apps/openssl.cnf
    ${CMAKE_CURRENT_SOURCE_DIR}/apps/ct_log_list.cnf
    DESTINATION ssl )
  install( CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/ssl/certs)" )
  install( CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/ssl/misc)" )
  install( CODE "FILE(MAKE_DIRECTORY \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/ssl/private)" )
  install( FILES ${PROJECT_BINARY_DIR}/c_rehash DESTINATION bin )
endif()

file( GLOB PUBLIC_HEADERS "${PROJECT_BINARY_DIR}/include/openssl/*.h" )
install( FILES ${PUBLIC_HEADERS} DESTINATION include/openssl )

install( FILES
  FAQ LICENSE README README.ENGINE
  DESTINATION share/openssl )

install( DIRECTORY doc DESTINATION share )

set( prefix      "${CMAKE_INSTALL_PREFIX}" )
set( includedir  "include" )
set( libdir      "lib" )
get_target_property( libcrypto crypto OUTPUT_NAME )
get_target_property( libssl ssl OUTPUT_NAME )
configure_file(openssl.pc.in.cmake openssl.pc @ONLY)
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/openssl.pc
  DESTINATION lib/pkgconfig)

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake IMMEDIATE @ONLY
)

if( ${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME} )
  add_custom_target(
    "uninstall"
    ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
  )
endif()

# Generate the package target
set( CPACK_GENERATOR ZIP TGZ )
set( CPACK_PACKAGE_NAME "${CMAKE_PROJECT_NAME}" )
set( CPACK_PACKAGE_VERSION_MAJOR ${VERSION_MAJOR} )
set( CPACK_PACKAGE_VERSION_MINOR ${VERSION_MINOR} )
set( CPACK_PACKAGE_VERSION_PATCH ${VERSION_PATCH} )
set( CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${VERSION_STRING}" )

include( CPack )
