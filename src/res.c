#include "res.h"
#include "forkawesome.h"
#include "default_theme.h"
#ifdef UNICODE_GUI
#include "noto.h"
#include "noto_armenian.h"
#include "noto_sans.h"
#endif
#ifndef EMSCRIPTEN
#include "cacert_pem.h"
#endif
#include "sv_basic_manual.h"
#include "karla.h"
#include <stdlib.h>
const uint8_t* se_get_resource(int res_id, uint64_t* size){
  uint64_t sz_dummy = 0; 
  if(!size)size=&sz_dummy; 
  switch(res_id){
    case SE_THEME_DEFAULT: *size = theme_default_png_len; return theme_default_png;
    case SE_FORKAWESOME: *size = forkawesome_compressed_size; return (uint8_t*)forkawesome_compressed_data;
    case SE_KARLA: *size = karla_compressed_size; return (uint8_t*)karla_compressed_data;
    case SE_SV_BASIC_MANUAL: *size = sv_basic_manual_compressed_size; return (uint8_t*)sv_basic_manual_compressed_data;
#ifdef UNICODE_GUI
    case SE_NOTO: *size = notosans_cjksc_compressed_size; return (uint8_t*)notosans_cjksc_compressed_data;
    case SE_NOTO_ARMENIAN: *size = noto_armenian_compressed_size; return (uint8_t*)noto_armenian_compressed_data;
    case SE_NOTO_SANS: *size = noto_sans_compressed_size; return (uint8_t*)noto_sans_compressed_data;
#endif
#ifndef EMSCRIPTEN
    case SE_CACERT_PEM: *size = cacert_pem_len; return (uint8_t*)cacert_pem;
#endif
  }
  *size = 0; 
  return NULL;
}
