/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#define SE_REBIND_TIMER_LENGTH 5.0

#define SE_TRANSPARENT_BG_ALPHA 0.9

#ifdef ENABLE_HTTP_CONTROL_SERVER
#include "http_control_server.h"
#endif 

#include "gba.h"
#include "nds.h"
#include "gb.h"
#include "capstone/include/capstone/capstone.h"
#include "miniz.h"
#include "localization.h"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

#include "res.h"
#include "sokol_app.h"
#include "sokol_audio.h"
#include "sokol_gfx.h"
#include "sokol_time.h"
#include "sokol_glue.h"
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "sokol_imgui.h"
#include "IconsForkAwesome.h"
#define STBI_ONLY_PNG
#include "stb_image.h"
#include "stb_image_write.h"

#ifdef USE_TINY_FILE_DIALOGS
#include "tinyfiledialogs.h"
#endif

#define UNICODE
#define USE_BUILT_IN_FILEBROWSER
#include "tinydir.h"

#ifdef PLATFORM_ANDROID
  #include <android/log.h>
#endif
#ifdef PLATFORM_IOS
#include "ios_support.h"
#endif
#ifdef USE_SDL
#include "SDL.h"
#endif 
#ifdef PLATFORM_ANDROID
#include <android/native_activity.h>
#endif
#ifdef UNICODE_GUI
#include "utf8proc.h"
#endif
#ifdef PLATFORM_WINDOWS
//Needed for setlocale(...)
#include <locale.h>
#endif

#include "lcd_shaders.h"

#define SE_HAT_MASK (1<<16)
#define SE_JOY_POS_MASK (1<<17)
#define SE_JOY_NEG_MASK (1<<18)

#define GBA_SKYEMU_CORRECTION 0 
#define GBA_HIGAN_CORRECTION  1

const static char* se_keybind_names[SE_NUM_KEYBINDS]={
  "A",
  "B",
  "X",
  "Y",
  "Up",
  "Down",
  "Left",
  "Right",
  "L",
  "R",
  "Start",
  "Select",
  "Fold Screen (NDS)",
  "Tap Screen (NDS)",
  "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY,
  "Emulator " ICON_FK_BACKWARD,
  "Emulator " ICON_FK_FORWARD,
  "Emulator " ICON_FK_FAST_FORWARD,
  "Capture State 0",
  "Restore State 0",
  "Capture State 1",
  "Restore State 1",
  "Capture State 2",
  "Restore State 2",
  "Capture State 3",
  "Restore State 3",
  "Reset Game",
  "Turbo A",
  "Turbo B",
  "Turbo X",
  "Turbo Y",
  "Turbo L",
  "Turbo R",
  "Solar Sensor+",
  "Solar Sensor-",
  "Toggle Full Screen"
};
#define SE_ANALOG_UP_DOWN    0
#define SE_ANALOG_LEFT_RIGHT 1
#define SE_ANALOG_L 2
#define SE_ANALOG_R 3
#define SE_NUM_ANALOGBINDS  4

const static char* se_analog_bind_names[]={
  "Analog Up/Down",
  "Analog Left/Right",
  "Analog L",
  "Analog R",
};
//Reserve space for extra keybinds/analog binds so that adding them in new versions don't break
//a users settings.
#define SE_NUM_BINDS_ALLOC 64

#define GUI_MAX_IMAGES_PER_FRAME 16
#define SE_NUM_RECENT_PATHS 32
#define SE_FONT_CACHE_PAGE_SIZE 16
#define SE_MAX_UNICODE_CODE_POINT 0xffff

typedef struct{
  int bind_being_set;
  double rebind_start_time;//The time that the rebind button was pressed (used for the timer to cancel keybinding)
  int last_bind_activitiy;// ID of binding with latest activity only within the current frame. -1 if no keys pressed/movement during frame. 
  int32_t bound_id[SE_NUM_BINDS_ALLOC];
  float value[SE_NUM_BINDS_ALLOC];
}se_keybind_state_t;
typedef struct{
  char name[128];
  char guid[64];
  #ifdef USE_SDL
  SDL_Joystick * sdl_joystick; 
  SDL_GameController * sdl_gc; 
  #endif
  bool active; 
  bool connected;
  se_keybind_state_t key;
  se_keybind_state_t analog;
}se_controller_state_t;
typedef struct{
  char path[SB_FILE_PATH_SIZE];
}se_game_info_t;
typedef struct{
  // This structure is directly saved out for the user settings. 
  // Be very careful to keep alignment and ordering the same otherwise you will break the settings. 
  uint32_t draw_debug_menu;
  float volume; 
  uint32_t theme; 
  uint32_t settings_file_version; 
  uint32_t gb_palette[4];
  float ghosting;
  float color_correction;
  uint32_t integer_scaling; 
  uint32_t screen_shader; //0: pixels, 1: lcd, 2: lcd+subpixels, 3: upscale
  uint32_t screen_rotation; //0: No rotation, 1: Rotate Left, 2: Rotate Right, 3: Upside Down
  uint32_t stretch_to_fit;
  uint32_t auto_hide_touch_controls;
  float touch_controls_opacity; 
  uint32_t always_show_menubar;
  uint32_t language;
  float touch_controls_scale; 
  uint32_t touch_controls_show_turbo; 
  uint32_t save_to_path;
  uint32_t force_dmg_mode; 
  uint32_t gba_color_correction_mode; // 0 = SkyEmu, 1 = Higan
  uint32_t http_control_server_port; 
  uint32_t http_control_server_enable; 
  uint32_t padding[231];
}persistent_settings_t; 
_Static_assert(sizeof(persistent_settings_t)==1024, "persistent_settings_t must be exactly 1024 bytes");
#define SE_STATS_GRAPH_DATA 256
typedef struct{
  double last_render_time;
  double last_emu_time;
  float volume_l;
  float volume_r;
  float waveform_l[SE_STATS_GRAPH_DATA];
  float waveform_r[SE_STATS_GRAPH_DATA];
  float waveform_fps_emulation[SE_STATS_GRAPH_DATA];
  float waveform_fps_render[SE_STATS_GRAPH_DATA];
}se_emulator_stats_t;
#define SE_FILE_BROWSER_CLOSED 0
#define SE_FILE_BROWSER_OPEN 1
#define SE_FILE_BROWSER_SELECTED 2

typedef struct{
  char current_path[SB_FILE_PATH_SIZE];
  char file_path[SB_FILE_PATH_SIZE];
  int state; // 0 = Closed no file selected,  1= Open,  2 = closed file selected
  tinydir_file* cached_files;
  char cached_path[SB_FILE_PATH_SIZE];
  char cached_ext_filter[SB_FILE_PATH_SIZE];
  size_t num_cached_files;
  double cached_time; 
  tinydir_dir cached_dir; 
  bool has_cache;
}se_file_browser_state_t;
typedef struct{
  uint32_t turbo_toggle;
  uint32_t hold_toggle; 
  uint32_t last_turbo_toggle_presses;
  uint32_t last_hold_toggle_presses;
}se_touch_controls_t; 

typedef struct{
  char save[SB_FILE_PATH_SIZE];
  char bios[SB_FILE_PATH_SIZE];
  char padding[6][SB_FILE_PATH_SIZE];
}se_search_paths_t;

_Static_assert(sizeof(se_search_paths_t)==SB_FILE_PATH_SIZE*8, "se_search_paths_t must contain 8 paths");

#define SE_MAX_BIOS_FILES 8
#define SE_BIOS_NAME_SIZE 32

typedef struct{
  char path[SE_MAX_BIOS_FILES][SB_FILE_PATH_SIZE];
  char name[SE_MAX_BIOS_FILES][SE_BIOS_NAME_SIZE];
  bool success[SE_MAX_BIOS_FILES];
}se_bios_info_t;
typedef struct {
    uint64_t laptime;
    sg_pass_action pass_action;
    sg_image image_stack[GUI_MAX_IMAGES_PER_FRAME];
    int current_image; 
    int screen_width;
    int screen_height;
    int button_state[SAPP_MAX_KEYCODES];
    struct{
      bool active;
      float pos[2];
    }touch_points[SAPP_MAX_TOUCHPOINTS];
    float last_touch_time;
    int mem_view_address;
    int mem_dump_size;
    int mem_dump_start_address;
    bool sidebar_open;
    se_keybind_state_t key;
    se_controller_state_t controller;
    se_game_info_t recently_loaded_games[SE_NUM_RECENT_PATHS];
    persistent_settings_t settings;
    persistent_settings_t last_saved_settings;
    bool overlay_open;
    se_emulator_stats_t emu_stats; 
    // Utilize a watchdog channel to detect if the audio context has encountered an error
    // and restart it if a problem occurred. 
    int audio_watchdog_timer; 
    int audio_watchdog_triggered; 
    bool block_touchscreen;
    bool test_runner_mode;
    sg_shader lcd_prog;
    sg_buffer quad_vb;
    sg_pipeline lcd_pipeline;
    se_file_browser_state_t file_browser; 
    float mouse_pos[2];
    bool mouse_button[3];
    float menubar_hide_timer;
    se_touch_controls_t touch_controls; 
    se_search_paths_t paths;
    se_bios_info_t bios_info;
    sg_image font_atlas_image;
    uint8_t font_cache_page_valid[(SE_MAX_UNICODE_CODE_POINT+1)/SE_FONT_CACHE_PAGE_SIZE];
    bool update_font_atlas;
    sb_joy_t hcs_joypad; 
} gui_state_t;

#define SE_REWIND_BUFFER_SIZE (1024*1024)
#define SE_REWIND_SEGMENT_SIZE 64
#define SE_LAST_DELTA_IN_TX (1<<31)

#define SE_NUM_SAVE_STATES 4
#define SE_MAX_SCREENSHOT_SIZE (NDS_LCD_H*NDS_LCD_W*2*4)

#define SE_THEME_DARK 0
#define SE_THEME_LIGHT 1
#define SE_THEME_BLACK 2

#define SE_MENU_BAR_HEIGHT 24
#define SE_MENU_BAR_BUTTON_WIDTH 30
#define SE_TOGGLE_WIDTH 35
#define SE_VOLUME_SLIDER_WIDTH 100

//TODO: Clean this up to use unions...
sb_emu_state_t emu_state = {.pc_breakpoint = -1};
#define SE_MAX_CONST(A,B) ((A)>(B)? (A) : (B) )
typedef union{
  sb_gb_t gb;
  gba_t gba;  
  nds_t nds;
  // Raw data padded out to 64B to make rewind efficient
  uint64_t raw_data[SE_MAX_CONST(SE_MAX_CONST(sizeof(gba_t), sizeof(nds_t)), sizeof(sb_gb_t))/SE_REWIND_SEGMENT_SIZE+1];
}se_core_state_t;
typedef union{
  gba_scratch_t gba;
  gb_scratch_t gb; 
  nds_scratch_t nds;
}se_core_scratch_t;

typedef struct{
  uint32_t offset; 
  uint64_t data[SE_REWIND_SEGMENT_SIZE/8];
}se_core_delta_t;
typedef struct{
  se_core_delta_t deltas[SE_REWIND_BUFFER_SIZE];
  uint32_t size;
  uint32_t index; 
  bool first_push; 
  se_core_state_t last_core; 
}se_core_rewind_buffer_t;
typedef struct{
  uint8_t screenshot[SE_MAX_SCREENSHOT_SIZE];
  int32_t screenshot_width; 
  int32_t screenshot_height; 
  int32_t system;
  int32_t valid; //0: invalid, 1: Valid (Perfect Save State) 2: Valid (BESS restore)
  se_core_state_t state;
}se_save_state_t; 
typedef struct{
  char name[39];
  char build[41];
  uint32_t bess_offset;
  uint32_t system;
  uint8_t padding[20];
}se_emu_id;
gui_state_t gui_state={ .update_font_atlas=true }; 

void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha);
void se_draw_lcd(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, float rotation);
void se_load_rom_overlay(bool visible);
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h, int controller_y_pad,bool preview);
void se_reset_save_states();
void se_set_new_controller(se_controller_state_t* cont, int index);
static void se_emscripten_flush_fs();
static uint32_t se_save_best_effort_state(se_core_state_t* state);
static bool se_load_best_effort_state(se_core_state_t* state,uint8_t *save_state_data, uint32_t size, uint32_t bess_offset);
static size_t se_get_core_size();

static const char* se_get_pref_path(){
#if defined(EMSCRIPTEN)
  return "/offline/";
#elif defined(USE_SDL)
  static const char* cached_pref_path=NULL;
  if(cached_pref_path==NULL)cached_pref_path=SDL_GetPrefPath("Sky","SkyEmu");
  return cached_pref_path;
#elif defined(PLATFORM_ANDROID)
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  if(activity->internalDataPath)return activity->internalDataPath;
#endif
  return "";
}

static float se_dpi_scale(){
  float dpi_scale = sapp_dpi_scale();
  if(dpi_scale<=0)dpi_scale=1.;
  dpi_scale*=1.10;
#ifdef PLATFORM_ANDROID
  dpi_scale*=3.3;
#endif
  return dpi_scale;
}

static void se_cache_glyphs(const char* input_string){
  #ifdef UNICODE_GUI
  utf8proc_int32_t codepoint_ref=0;
  const utf8proc_uint8_t *str = (const utf8proc_uint8_t *)input_string;
  while(str[0]){
    int size = utf8proc_iterate(str, -1, &codepoint_ref);
    if(size<=0)break;
    str+=size;
    if(codepoint_ref>SE_MAX_UNICODE_CODE_POINT)continue;;
    uint32_t font_cache_page = codepoint_ref/SE_FONT_CACHE_PAGE_SIZE;
    if(gui_state.font_cache_page_valid[font_cache_page]==0x0){
      gui_state.font_cache_page_valid[font_cache_page]=0x1;
      gui_state.update_font_atlas=true;
    }
  }
  #endif
}
static inline const char* se_localize_and_cache(const char* input_str){
  const char * localized_string = se_localize(input_str);
  se_cache_glyphs(localized_string);
  return localized_string;
}
static inline bool se_checkbox(const char* label, bool * v){
  return igCheckbox(se_localize_and_cache(label),v);
}
static void se_text(const char* label,...){
  va_list args;
  va_start(args, label);
  igTextV(se_localize_and_cache(label),args);
  va_end(args);
}
static void se_text_disabled(const char* label,...){
  va_list args;
  va_start(args, label);
  igTextDisabledV(se_localize_and_cache(label),args);
  va_end(args);
}
static bool se_combo_str(const char* label,int* current_item,const char* items_separated_by_zeros,int popup_max_height_in_items){
  const char* localize_string= items_separated_by_zeros;
  while(localize_string[0]){
    se_cache_glyphs(localize_string);
    localize_string+=strlen(localize_string)+1;
  }
  return igComboStr(se_localize_and_cache(label),current_item,se_localize_and_cache(items_separated_by_zeros),popup_max_height_in_items);
}
static int se_slider_float(const char* label,float* v,float v_min,float v_max,const char* format){
  return igSliderFloat(se_localize_and_cache(label),v,v_min,v_max,se_localize_and_cache(format),ImGuiSliderFlags_AlwaysClamp);
}
static bool se_input_int(const char* label,int* v,int step,int step_fast,ImGuiInputTextFlags flags){
  return igInputInt(se_localize_and_cache(label),v,step,step_fast,flags);
}
static bool se_input_path(const char* label, char* path, ImGuiInputTextFlags flags){
  int win_w = igGetWindowWidth();
  se_text(label);igSameLine(win_w*0.4,0);
  igPushIDStr(label);
  igPushItemWidth(-1);
  bool b = igInputText("##",path,SB_FILE_PATH_SIZE,flags,NULL,NULL);
  igPopItemWidth();
  igPopID();
  return b; 
}
static bool se_button(const char* label, ImVec2 size){
  return igButton(se_localize_and_cache(label),size);
}
const char* se_keycode_to_string(int keycode){
  switch(keycode){
    default:           return "Unknown";
    case SAPP_KEYCODE_SPACE:         return "SPACE";
    case SAPP_KEYCODE_APOSTROPHE:    return "'";
    case SAPP_KEYCODE_COMMA:         return ",";
    case SAPP_KEYCODE_MINUS:         return "-";
    case SAPP_KEYCODE_PERIOD:        return ".";
    case SAPP_KEYCODE_SLASH:         return "/";
    case SAPP_KEYCODE_0:             return "0";
    case SAPP_KEYCODE_1:             return "1";
    case SAPP_KEYCODE_2:             return "2";
    case SAPP_KEYCODE_3:             return "3";
    case SAPP_KEYCODE_4:             return "4";
    case SAPP_KEYCODE_5:             return "5";
    case SAPP_KEYCODE_6:             return "6";
    case SAPP_KEYCODE_7:             return "7";
    case SAPP_KEYCODE_8:             return "8";
    case SAPP_KEYCODE_9:             return "9";
    case SAPP_KEYCODE_SEMICOLON:     return ";";
    case SAPP_KEYCODE_EQUAL:         return "=";
    case SAPP_KEYCODE_A:             return "A";
    case SAPP_KEYCODE_B:             return "B";
    case SAPP_KEYCODE_C:             return "C";
    case SAPP_KEYCODE_D:             return "D";
    case SAPP_KEYCODE_E:             return "E";
    case SAPP_KEYCODE_F:             return "F";
    case SAPP_KEYCODE_G:             return "G";
    case SAPP_KEYCODE_H:             return "H";
    case SAPP_KEYCODE_I:             return "I";
    case SAPP_KEYCODE_J:             return "J";
    case SAPP_KEYCODE_K:             return "K";
    case SAPP_KEYCODE_L:             return "L";
    case SAPP_KEYCODE_M:             return "M";
    case SAPP_KEYCODE_N:             return "N";
    case SAPP_KEYCODE_O:             return "O";
    case SAPP_KEYCODE_P:             return "P";
    case SAPP_KEYCODE_Q:             return "Q";
    case SAPP_KEYCODE_R:             return "R";
    case SAPP_KEYCODE_S:             return "S";
    case SAPP_KEYCODE_T:             return "T";
    case SAPP_KEYCODE_U:             return "U";
    case SAPP_KEYCODE_V:             return "V";
    case SAPP_KEYCODE_W:             return "W";
    case SAPP_KEYCODE_X:             return "X";
    case SAPP_KEYCODE_Y:             return "Y";
    case SAPP_KEYCODE_Z:             return "Z";
    case SAPP_KEYCODE_LEFT_BRACKET:  return "[";
    case SAPP_KEYCODE_BACKSLASH:     return "\\";
    case SAPP_KEYCODE_RIGHT_BRACKET: return "]";
    case SAPP_KEYCODE_GRAVE_ACCENT:  return "`";
    case SAPP_KEYCODE_WORLD_1:       return "WORLD 1";
    case SAPP_KEYCODE_WORLD_2:       return "WORLD 2";
    case SAPP_KEYCODE_ESCAPE:        return "ESCAPE";
    case SAPP_KEYCODE_ENTER:         return "ENTER";
    case SAPP_KEYCODE_TAB:           return "TAB";
    case SAPP_KEYCODE_BACKSPACE:     return "BACKSPACE";
    case SAPP_KEYCODE_INSERT:        return "INSERT";
    case SAPP_KEYCODE_DELETE:        return "DELETE";
    case SAPP_KEYCODE_RIGHT:         return "RIGHT";
    case SAPP_KEYCODE_LEFT:          return "LEFT";
    case SAPP_KEYCODE_DOWN:          return "DOWN";
    case SAPP_KEYCODE_UP:            return "UP";
    case SAPP_KEYCODE_PAGE_UP:       return "PAGE UP";
    case SAPP_KEYCODE_PAGE_DOWN:     return "PAGE DOWN";
    case SAPP_KEYCODE_HOME:          return "HOME";
    case SAPP_KEYCODE_END:           return "END";
    case SAPP_KEYCODE_CAPS_LOCK:     return "CAPS LOCK";
    case SAPP_KEYCODE_SCROLL_LOCK:   return "SCROLL LOCK";
    case SAPP_KEYCODE_NUM_LOCK:      return "NUM LOCK";
    case SAPP_KEYCODE_PRINT_SCREEN:  return "PRINT SCREEN";
    case SAPP_KEYCODE_PAUSE:         return "PAUSE";
    case SAPP_KEYCODE_F1:            return "F1";
    case SAPP_KEYCODE_F2:            return "F2";
    case SAPP_KEYCODE_F3:            return "F3";
    case SAPP_KEYCODE_F4:            return "F4";
    case SAPP_KEYCODE_F5:            return "F5";
    case SAPP_KEYCODE_F6:            return "F6";
    case SAPP_KEYCODE_F7:            return "F7";
    case SAPP_KEYCODE_F8:            return "F8";
    case SAPP_KEYCODE_F9:            return "F9";
    case SAPP_KEYCODE_F10:           return "F10";
    case SAPP_KEYCODE_F11:           return "F11";
    case SAPP_KEYCODE_F12:           return "F12";
    case SAPP_KEYCODE_F13:           return "F13";
    case SAPP_KEYCODE_F14:           return "F14";
    case SAPP_KEYCODE_F15:           return "F15";
    case SAPP_KEYCODE_F16:           return "F16";
    case SAPP_KEYCODE_F17:           return "F17";
    case SAPP_KEYCODE_F18:           return "F18";
    case SAPP_KEYCODE_F19:           return "F19";
    case SAPP_KEYCODE_F20:           return "F20";
    case SAPP_KEYCODE_F21:           return "F21";
    case SAPP_KEYCODE_F22:           return "F22";
    case SAPP_KEYCODE_F23:           return "F23";
    case SAPP_KEYCODE_F24:           return "F24";
    case SAPP_KEYCODE_F25:           return "F25";
    case SAPP_KEYCODE_KP_0:          return "KP 0";
    case SAPP_KEYCODE_KP_1:          return "KP 1";
    case SAPP_KEYCODE_KP_2:          return "KP 2";
    case SAPP_KEYCODE_KP_3:          return "KP 3";
    case SAPP_KEYCODE_KP_4:          return "KP 4";
    case SAPP_KEYCODE_KP_5:          return "KP 5";
    case SAPP_KEYCODE_KP_6:          return "KP 6";
    case SAPP_KEYCODE_KP_7:          return "KP 7";
    case SAPP_KEYCODE_KP_8:          return "KP 8";
    case SAPP_KEYCODE_KP_9:          return "KP 9";
    case SAPP_KEYCODE_KP_DECIMAL:    return "KP .";
    case SAPP_KEYCODE_KP_DIVIDE:     return "KP /";
    case SAPP_KEYCODE_KP_MULTIPLY:   return "KP *";
    case SAPP_KEYCODE_KP_SUBTRACT:   return "KP -";
    case SAPP_KEYCODE_KP_ADD:        return "KP +";
    case SAPP_KEYCODE_KP_ENTER:      return "KP ENTER";
    case SAPP_KEYCODE_KP_EQUAL:      return "KP =";
    case SAPP_KEYCODE_LEFT_SHIFT:    return "LEFT SHIFT";
    case SAPP_KEYCODE_LEFT_CONTROL:  return "LEFT CONTROL";
    case SAPP_KEYCODE_LEFT_ALT:      return "LEFT ALT";
    case SAPP_KEYCODE_LEFT_SUPER:    return "LEFT SUPER";
    case SAPP_KEYCODE_RIGHT_SHIFT:   return "RIGHT SHIFT";
    case SAPP_KEYCODE_RIGHT_CONTROL: return "RIGHT CONTROL";
    case SAPP_KEYCODE_RIGHT_ALT:     return "RIGHT ALT";
    case SAPP_KEYCODE_RIGHT_SUPER:   return "RIGHT SUPER";
    case SAPP_KEYCODE_MENU:          return "MENU";
  }
}


se_core_state_t core;
se_core_scratch_t scratch;
se_core_rewind_buffer_t rewind_buffer;
se_save_state_t save_states[SE_NUM_SAVE_STATES];

bool se_more_rewind_deltas(se_core_rewind_buffer_t* rewind, uint32_t index){
  return (rewind->deltas[index%SE_REWIND_BUFFER_SIZE].offset&SE_LAST_DELTA_IN_TX)==0;
}
void se_push_rewind_state(se_core_state_t* core, se_core_rewind_buffer_t* rewind){
  if(!rewind->first_push){
    rewind->first_push=true;
    rewind->last_core= *core;
    return; 
  }
  int total_segments = sizeof(se_core_state_t)/SE_REWIND_SEGMENT_SIZE;
  uint64_t * new_data = (uint64_t*)core;
  uint64_t * old_data = (uint64_t*)&rewind->last_core;
  int total_deltas =0; 
  for(int s=0; s<total_segments;++s){
    bool delta = false; 
    int base_off = s*SE_REWIND_SEGMENT_SIZE/8;
    for(int s_off = 0; s_off< SE_REWIND_SEGMENT_SIZE/8;++s_off){
      if(new_data[base_off+s_off]!=old_data[base_off+s_off]){delta = true;break;}
    }
    if(delta){
      int rewind_index = rewind->index%SE_REWIND_BUFFER_SIZE;
      int offset = s; 
      if(total_deltas==0)offset|= SE_LAST_DELTA_IN_TX;
      for(int s_off = 0; s_off< SE_REWIND_SEGMENT_SIZE/8;++s_off){
        rewind->deltas[rewind_index].data[s_off] =old_data[base_off+s_off];
        old_data[base_off+s_off]= new_data[base_off+s_off]; 
      } 
      rewind->deltas[rewind_index].offset = offset;
      rewind->index++;
      rewind->size++;
      ++total_deltas;
    }
  }
  if(rewind->size>=SE_REWIND_BUFFER_SIZE)rewind->size=SE_REWIND_BUFFER_SIZE-1; 
  rewind->index= rewind->index%SE_REWIND_BUFFER_SIZE;
  //Discard partial transactions remaing
  while(rewind->size>0 && se_more_rewind_deltas(rewind,rewind->index-rewind->size))rewind->size--;
}
void se_rewind_state_single_tick(se_core_state_t* core, se_core_rewind_buffer_t* rewind){
  uint64_t * old_data = (uint64_t*)&rewind->last_core;
  int rewound_deltas=0; 
  bool more_transactions = true;
  while(rewind->size&&more_transactions){
    ++rewound_deltas;
    --rewind->size;
    uint32_t rewind_index = (--rewind->index)%SE_REWIND_BUFFER_SIZE;
    int s = rewind->deltas[rewind_index].offset; 
    if(s&SE_LAST_DELTA_IN_TX){
      more_transactions=false;
      s&=~SE_LAST_DELTA_IN_TX;
    }
    int base_off = s*SE_REWIND_SEGMENT_SIZE/8;
    for(int s_off = 0; s_off< SE_REWIND_SEGMENT_SIZE/8;++s_off){
      old_data[base_off+s_off]=rewind->deltas[rewind_index].data[s_off];
    }
  }
  rewind->index= rewind->index%SE_REWIND_BUFFER_SIZE;
  *core = rewind->last_core;
}
void se_reset_rewind_buffer(se_core_rewind_buffer_t* rewind){
  rewind->index = rewind->size = 0; 
  rewind->first_push = false;
}
se_emu_id se_get_emu_id(){
  se_emu_id emu_id={0};
  strncpy(emu_id.name,"SkyEmu",sizeof(emu_id.name));
  strncpy(emu_id.build,GIT_COMMIT_HASH,sizeof(emu_id.build));
  return emu_id;
}
uint8_t* se_save_state_to_image(se_save_state_t * save_state, uint32_t *width, uint32_t *height){
  se_emu_id emu_id=se_get_emu_id();
  emu_id.bess_offset = se_save_best_effort_state(&save_state->state);
  emu_id.system = save_state->system;
  printf("Bess offset: %d\n",emu_id.bess_offset);
  size_t save_state_size = se_get_core_size();
  size_t net_save_state_size = sizeof(emu_id)+save_state_size;
  int screenshot_size = save_state->screenshot_width*save_state->screenshot_height;

  int scale = 1; 
  while(screenshot_size*scale*scale<net_save_state_size)scale++;

  uint8_t *imdata = malloc(scale*scale*screenshot_size*4);
  uint8_t *emu_id_dat = (uint8_t*)&emu_id;
  uint8_t *save_state_dat = (uint8_t*)&(save_state->state);
  for(int y=0;y<save_state->screenshot_height*scale;++y){
    for(int x=0;x<save_state->screenshot_width*scale;++x){
      int px = x/scale;
      int py = y/scale;
      int p = (px+py*save_state->screenshot_width);
      uint8_t r = save_state->screenshot[p*4+0];
      uint8_t g = save_state->screenshot[p*4+1];
      uint8_t b = save_state->screenshot[p*4+2];
      uint8_t a = 0xff; 
      int p_out = x+y*save_state->screenshot_width*scale;
      uint8_t data =0; 
      if(p_out<sizeof(emu_id))data = emu_id_dat[p_out];
      else if(p_out-sizeof(emu_id)<save_state_size) data = save_state_dat[p_out-sizeof(emu_id)];

      r&=0xfC;
      g&=0xfC;
      b&=0xfC;
      a&=0xfC;

      r|= SB_BFE(data,0,2);
      g|= SB_BFE(data,2,2);
      b|= SB_BFE(data,4,2);
      a|= SB_BFE(data,6,2);
      imdata[p_out*4+0]=r;
      imdata[p_out*4+1]=g;
      imdata[p_out*4+2]=b;
      imdata[p_out*4+3]=a;
    }
  }
  *width = save_state->screenshot_width*scale;
  *height = save_state->screenshot_height*scale;
  return imdata;
}
bool se_save_state_to_disk(se_save_state_t* save_state, const char* filename){
  uint32_t width=0, height=0;
  uint8_t* imdata = se_save_state_to_image(save_state, &width,&height);
  bool success= stbi_write_png(filename, width,height, 4, imdata, 0);
  free(imdata);
  se_emscripten_flush_fs();
  return success;
}
bool se_bess_state_restore(uint8_t*state_data, size_t data_size, const se_emu_id emu_id, se_save_state_t* state){
  state->state = core;
  printf("Attempting BESS Restore\n");
  if(sizeof(emu_id)>data_size)return false; 
  size_t save_state_size = data_size-sizeof(emu_id);
  uint8_t *data = state_data +sizeof(emu_id);
  bool valid = se_load_best_effort_state(&(state->state),data, save_state_size, emu_id.bess_offset);
  printf("Valid:%d\n",valid);
  if(!valid){
    state->screenshot_width=1;
    state->screenshot_height=1;
    state->screenshot[0] = 0; 
    state->screenshot[1] = 0; 
    state->screenshot[2] = 0; 
    state->screenshot[3] = 255; 
  }
  return valid; 
}
bool se_load_state_from_disk(se_save_state_t* save_state, const char* filename){
  save_state->valid = false;
  int im_w, im_h, im_c; 
  uint8_t *imdata = stbi_load(filename, &im_w, &im_h, &im_c, 4);
  if(!imdata)return false; 

  uint8_t *data = malloc(im_w*im_h);
  size_t data_size = im_w*im_h;
  for(int i=0;i<data_size;++i){
    uint8_t d = 0;
    d |= SB_BFE(imdata[i*4+0],0,2)<<0;
    d |= SB_BFE(imdata[i*4+1],0,2)<<2;
    d |= SB_BFE(imdata[i*4+2],0,2)<<4;
    d |= SB_BFE(imdata[i*4+3],0,2)<<6;
    data[i]=d;
  }
  int downscale= 1; 
  while((im_w/downscale)*(im_h/downscale)*4>=sizeof(save_state->screenshot))downscale++;
  save_state->screenshot_width=im_w/downscale;
  save_state->screenshot_height=im_h/downscale;
  for(int y=0;y<im_h;y+=downscale){
    for(int x=0;x<im_w;x+=downscale){
      int p1 = x+y*im_w;
      int p2 = x/downscale+(y/downscale)*save_state->screenshot_width;
      for(int i=0;i<3;++i)save_state->screenshot[p2*4+i]= imdata[p1*4+i];
      save_state->screenshot[p2*4+3]=0xff;
    }
  }
  
  stbi_image_free(imdata);

  bool valid = data_size<sizeof(se_emu_id);

  if(sizeof(se_emu_id)<data_size){

    se_emu_id emu_id=se_get_emu_id();
    se_emu_id comp_id = *(se_emu_id*)data;
    bool bess= false; 
    if(memcmp(&comp_id.name,&emu_id.name,sizeof(emu_id.name))){
      printf("ERROR: Save state:%s has non-matching emu-name:%s\n",filename, emu_id.name);
      bess=true; 
    }
    if(memcmp(&comp_id.build,&emu_id.build,sizeof(emu_id.build))){
      printf("ERROR: Save state:%s has non-matching emu-build:%s\n",filename, emu_id.build);
      bess=true; 
    }
    save_state->system = comp_id.system;
    if(!bess&&se_get_core_size()+sizeof(se_emu_id)<=data_size){
      memcpy(&(save_state->state), data+sizeof(se_emu_id), se_get_core_size());
      save_state->valid = 1; 
    }else if(se_bess_state_restore(data, data_size,comp_id, save_state)){
      save_state->valid = 2;
    }
    
    if(save_state->valid)printf("Loaded save state:%s\n",filename);
    else printf("Failed to load state from file:%s\n",filename);
  }
  free(data);
  return save_state->valid;
}
double se_time(){
  static uint64_t base_time=0;
  if(base_time==0) base_time= stm_now();
  return stm_sec(stm_diff(stm_now(),base_time));
}
static void se_tooltip(const char * tooltip){
  if(igGetCurrentContext()->HoveredIdTimer<1.5||gui_state.last_touch_time>0)return;
  if (igIsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)&&!igIsItemActive()){
    igSetTooltip(se_localize_and_cache(tooltip));
  }
}
double se_fps_counter(int tick){
  static int call = -1;
  static double last_t = 0;
  static double fps = 1.0/60.0; 
  if(!tick)return 1.0/fps;
  if(call==-1){
    call = 0;
    last_t = se_time();
    fps = 1.0/60;
  }else{
    call+=tick;
    double t = se_time();
    double delta = t-last_t;
    if(delta>0.5){
      fps=delta/call;
      last_t = t;
      call=0;
    }
    
  }
  return 1.0/fps; 
}

static void se_emscripten_flush_fs(){
#if defined(EMSCRIPTEN)
    EM_ASM( FS.syncfs(function (err) {}););
#endif
}
void se_load_search_paths(){
  char settings_path[SB_FILE_PATH_SIZE];
  snprintf(settings_path,SB_FILE_PATH_SIZE,"%ssearch_paths.bin",se_get_pref_path());
  if(!sb_load_file_data_into_buffer(settings_path,(void*)&gui_state.paths,sizeof(gui_state.paths)))memset(&gui_state.paths,0,sizeof(gui_state.paths));
  char * paths[]={
    gui_state.paths.save,
    gui_state.paths.bios,
  };
  for(int i=0;i<sizeof(paths)/sizeof(paths[0]);++i){
    paths[i][SB_FILE_PATH_SIZE-1]=0;
    uint32_t len = strlen(paths[i]);
    if(len==0){
      paths[i][0]='.';
      paths[i][1]='/';
      paths[i][2]=0;
    }else{
      char last_c = paths[i][len-1];
      if((last_c!='/'&&last_c!='\\')&&len<SB_FILE_PATH_SIZE)paths[i][len]='/';
    }
  }
}
void se_save_search_paths(){
  char settings_path[SB_FILE_PATH_SIZE];
  snprintf(settings_path,SB_FILE_PATH_SIZE,"%ssearch_paths.bin",se_get_pref_path());
  sb_save_file_data(settings_path,(uint8_t*)&gui_state.paths,sizeof(gui_state.paths));
}
void se_reset_bios_info(){
  memset(&gui_state.bios_info,0,sizeof(se_bios_info_t));
}
bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t * data, size_t data_size){
  bool loaded_bios=false;
  const char* base, *file, *ext; 
  sb_breakup_path(base_path, &base,&file, &ext);
  static char bios_path[SB_FILE_PATH_SIZE];
  se_join_path(bios_path,SB_FILE_PATH_SIZE,base,file_name,NULL);
  size_t bios_bytes=0;
  uint8_t *bios_data = sb_load_file_data(bios_path, &bios_bytes);
  if(bios_data){
    if(bios_bytes==data_size){
      printf("Loaded %s from %s\n",name, bios_path);
      memcpy(data,bios_data,data_size);
      loaded_bios=true;
    }else{
      printf("%s file at %s is incorrectly sized. Expected %zu bytes, got %zu bytes",name,file_name,data_size,bios_bytes);
    }
  }
  if(!loaded_bios){
    se_join_path(bios_path,SB_FILE_PATH_SIZE,gui_state.paths.bios,file_name,NULL);
    size_t bios_bytes=0;
    uint8_t *bios_data = sb_load_file_data(bios_path, &bios_bytes);
    if(bios_data){
      if(bios_bytes==data_size){
        printf("Loaded %s from %s\n",name, bios_path);
        memcpy(data,bios_data,data_size);
        loaded_bios=true;
      }else{
        printf("%s file at %s is incorrectly sized. Expected %zu bytes, got %zu bytes",name,file_name,data_size,bios_bytes);
      }
    }
  }
  se_bios_info_t* info = &gui_state.bios_info;
  for(int i=0;i<sizeof(info->name)/sizeof(info->name[0]);++i){
    if(info->name[i][0]==0){
      strncpy(info->name[i],name,sizeof(info->name[i]));
      strncpy(info->path[i],bios_path,sizeof(info->path[i]));
      info->success[i]=loaded_bios;
      break;
    }
    if(strcmp(info->name[i],name)==0){
      if(loaded_bios){
        strncpy(info->path[i],bios_path,sizeof(info->path[i]));
        info->success[i]=true;
      }
      break;
    }
  }
  free(bios_data);
  return loaded_bios;
}
static void se_save_recent_games_list(){
  gui_state_t* gui = &gui_state;
  char pref_path[SB_FILE_PATH_SIZE];
  snprintf(pref_path,SB_FILE_PATH_SIZE,"%s/%s",se_get_pref_path(), "recent_games.txt");
  FILE* f = fopen(pref_path,"wb");
  if(!f){
    printf("Failed to save recent games list to: %s\n",pref_path);
    return;
  }
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    if(strcmp("",gui->recently_loaded_games[i].path)==0)break;
    fprintf(f,"%s\n",gui->recently_loaded_games[i].path);
  }
  fclose(f);
  se_emscripten_flush_fs();
}
void se_load_recent_games_list(){
  gui_state_t* gui = &gui_state;
  char pref_path[SB_FILE_PATH_SIZE];
  snprintf(pref_path,SB_FILE_PATH_SIZE,"%s/%s",se_get_pref_path(), "recent_games.txt");
  FILE* f = fopen(pref_path,"rb");
  if(!f)return; 
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    memset(gui->recently_loaded_games[i].path,0,SB_FILE_PATH_SIZE);
  }
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    char* res = fgets(gui->recently_loaded_games[i].path, SB_FILE_PATH_SIZE,f);
    if(res==NULL)break;
    //Get rid of newline and carriage return characters at end
    while(*res){
      if(*res=='\n'||*res=='\r')*res='\0';
      ++res;
    }
  }
  fclose(f);
}

bool se_key_is_pressed(int keycode){
  if(keycode>SAPP_MAX_KEYCODES||keycode==-1)return false;
  return gui_state.button_state[keycode];
}
static sg_image* se_get_image(){
  if(gui_state.current_image<GUI_MAX_IMAGES_PER_FRAME){
    gui_state.current_image++;
    return gui_state.image_stack + gui_state.current_image-1; 
  }
  return NULL;
}
static void se_free_all_images(){
  for(int i=0;i<gui_state.current_image;++i){
    sg_destroy_image(gui_state.image_stack[i]);
  }
  gui_state.current_image=0;
}
typedef uint8_t (*emu_byte_read_t)(uint64_t address);
typedef void (*emu_byte_write_t)(uint64_t address,uint8_t data);
typedef sb_debug_mmio_access_t (*emu_mmio_access_type)(uint64_t address);

static uint16_t se_read16(emu_byte_read_t read,uint64_t address){
  uint16_t data = (*read)(address+1);
  data<<=8;
  data |= (*read)(address+0);
  return data;
}
static uint32_t se_read32(emu_byte_read_t read,uint64_t address){
  uint32_t data = (*read)(address+3);
  data<<=8;
  data |= (*read)(address+2);
  data<<=8;
  data |= (*read)(address+1);
  data<<=8;
  data |= (*read)(address+0);
  return data;
}
static void se_write16(emu_byte_write_t write, uint64_t address,uint16_t data){
  write(address,SB_BFE(data,0,8));
  write(address+1,SB_BFE(data,8,8));
}
static void se_write32(emu_byte_write_t write, uint64_t address,uint32_t data){
  write(address,SB_BFE(data,0,8));
  write(address+1,SB_BFE(data,8,8));
  write(address+2,SB_BFE(data,16,8));
  write(address+3,SB_BFE(data,24,8));
}
void se_record_emulation_frame_stats(se_emulator_stats_t *stats, int frames_emulated){
  if(frames_emulated==0)return;
  double time = se_time();
  double delta = time-stats->last_emu_time;
  stats->last_emu_time = time;
  double fps = 1.0/delta*frames_emulated; 

  int abs_frames = abs(frames_emulated);
  for(int i=0;i<SE_STATS_GRAPH_DATA-abs_frames;++i){
    stats->waveform_fps_emulation[i]=stats->waveform_fps_emulation[i+abs_frames];
  }
  for(int i=0;i<abs_frames;++i)
    stats->waveform_fps_emulation[SE_STATS_GRAPH_DATA-abs_frames+i]= fps;
}
void se_draw_emu_stats(){
  se_emulator_stats_t *stats = &gui_state.emu_stats;
  double curr_time = se_time();
  double fps_render = 1.0/(curr_time-stats->last_render_time);
  stats->last_render_time=curr_time;
  float render_min=1e9, render_max=0, render_avg=0; 
  float emulate_min=1e9, emulate_max=0, emulate_avg=0; 
  int render_data_points = 0; 
  int emulate_data_points =0;

  se_record_emulation_frame_stats(&gui_state.emu_stats,emu_state.frame);

  for(int i=0;i<SE_STATS_GRAPH_DATA-1;++i){
    stats->waveform_fps_render[i]=stats->waveform_fps_render[i+1];
    if(stats->waveform_fps_render[i]>render_max)render_max=stats->waveform_fps_render[i];
    if(stats->waveform_fps_render[i]<render_min)render_min=stats->waveform_fps_render[i];
    if(stats->waveform_fps_render[i]>5){
      render_avg+=1.0/stats->waveform_fps_render[i];
      render_data_points++;
    }

    if(stats->waveform_fps_emulation[i]>emulate_max)emulate_max=stats->waveform_fps_emulation[i];
    if(stats->waveform_fps_emulation[i]<emulate_min)emulate_min=stats->waveform_fps_emulation[i];
    if(stats->waveform_fps_emulation[i]>5){
      emulate_avg+=1.0/stats->waveform_fps_emulation[i];
      ++emulate_data_points;
    }
  }
  if(render_data_points<1)render_data_points=1;
  if(emulate_data_points<1)emulate_data_points=1;
  render_avg/=render_data_points;
  render_avg=1.0/render_avg;
  emulate_avg/=emulate_data_points;
  emulate_avg=1.0/emulate_avg;

  stats->waveform_fps_render[SE_STATS_GRAPH_DATA-1] = fps_render;

  for(int i=0;i<SE_STATS_GRAPH_DATA;++i){
    float l = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.write_ptr-i*2-2)%SB_AUDIO_RING_BUFFER_SIZE]/32768.;
    float r = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.write_ptr-i*2-1)%SB_AUDIO_RING_BUFFER_SIZE]/32768.;
    stats->waveform_l[i]=l;
    stats->waveform_r[i]=r;
  }

  float content_width = igGetWindowContentRegionWidth();
  se_text(ICON_FK_CLOCK_O " FPS");
  igSeparator();
  char label_tmp[128];
  snprintf(label_tmp,128,se_localize_and_cache("Display FPS: %2.1f\n"),render_avg);
  igPlotLinesFloatPtr("",stats->waveform_fps_render,SE_STATS_GRAPH_DATA,0,label_tmp,0,render_max*1.3,(ImVec2){content_width,80},4);

  snprintf(label_tmp,128,se_localize_and_cache("Emulation FPS: %2.1f\n"),emulate_avg);
  igPlotLinesFloatPtr("",stats->waveform_fps_emulation,SE_STATS_GRAPH_DATA,0,label_tmp,0,emulate_max*1.3,(ImVec2){content_width,80},4);
  
  se_text(ICON_FK_VOLUME_UP " Audio");
  igSeparator();
  igPlotLinesFloatPtr("",stats->waveform_l,SE_STATS_GRAPH_DATA,0,se_localize_and_cache("Left Audio Channel"),-1,1,(ImVec2){content_width,80},4);
  igPlotLinesFloatPtr("",stats->waveform_r,SE_STATS_GRAPH_DATA,0,se_localize_and_cache("Right Audio Channel"),-1,1,(ImVec2){content_width,80},4);
  
  const char* null_names[] = {NULL};
  const char ** channel_names = null_names; 
  if(emu_state.system == SYSTEM_GB){
    static const char* names[] ={"Channel 1 (Square)","Channel 2 (Square)","Channel 3 (Wave)","Channel 4 (Noise)",NULL};
    channel_names= names;
  }else if(emu_state.system == SYSTEM_GBA){
    static const char* names[] ={"Channel 1 (Square)","Channel 2 (Square)","Channel 3 (Wave)","Channel 4 (Noise)", "Channel A (FIFO)", "Channel B (FIFO)",NULL};
    channel_names= names;
  }else if(emu_state.system == SYSTEM_NDS){
    static const char* names[] ={
      "Channel 0","Channel 1","Channel 2","Channel 3",
      "Channel 4","Channel 5","Channel 6","Channel 7",
      "Channel 8","Channel 9","Channel A","Channel B",
      "Channel C","Channel D","Channel E","Channel F",
      NULL};
    channel_names= names;
  }
  for(int i=0;i<16;++i){
    if(!channel_names[i])break;
    se_text(channel_names[i]);
    igSameLine(content_width*0.42,0);
    igProgressBar(emu_state.audio_channel_output[i],(ImVec2){content_width*0.6,0},"");
  }
  float audio_buff_size = sb_ring_buffer_size(&emu_state.audio_ring_buff)/(float)SB_AUDIO_RING_BUFFER_SIZE;
  snprintf(label_tmp,128,se_localize_and_cache("Audio Ring (Samples Available: %d)"),sb_ring_buffer_size(&emu_state.audio_ring_buff));
  se_text(label_tmp);
  igProgressBar(audio_buff_size,(ImVec2){content_width,0},"");
  snprintf(label_tmp,128,se_localize_and_cache("Audio Watchdog Triggered %d Times"),gui_state.audio_watchdog_triggered);
  se_text(label_tmp);

  se_text(ICON_FK_INFO_CIRCLE " Build Info");
  igSeparator();
  se_text("Branch \"%s\" built on %s %s", GIT_BRANCH, __DATE__, __TIME__);
  se_text("Commit Hash:");
  igPushItemWidth(-1);
  igInputText("##COMMIT_HASH",GIT_COMMIT_HASH,sizeof(GIT_COMMIT_HASH),ImGuiInputTextFlags_ReadOnly,NULL,NULL);
  igPopItemWidth();

}
void se_draw_arm_state(const char* label, arm7_t *arm, emu_byte_read_t read){
  const char* reg_names[]={"R0","R1","R2","R3","R4","R5","R6","R7","R8","R9 (SB)","R10 (SL)","R11 (FP)","R12 (IP)","R13 (SP)","R14 (LR)","R15 (" ICON_FK_BUG ")","CPSR","SPSR",NULL};
  if(se_button("Step Instruction",(ImVec2){0,0})){
    arm->step_instructions=1;
    emu_state.run_mode= SB_MODE_RUN;
  }
  if(arm->log_cmp_file){
    igSameLine(0,0);
    if(se_button("Disconnect Log",(ImVec2){0,0})){
      fclose(arm->log_cmp_file);
      arm->log_cmp_file=NULL;
    }
  }
  int r = 0; 
  se_text(ICON_FK_SERVER " Registers");
  igSeparator();
  int w= igGetWindowWidth();
  while(reg_names[r]){
    int value = arm7_reg_read(arm,r);
    if(r%2){
      igSetNextItemWidth(-50);
      igSameLine(w*0.5,0);
    }else igSetNextItemWidth((w-100)*0.5);

    if(se_input_int(reg_names[r],&value, 0,0,ImGuiInputTextFlags_CharsHexadecimal)){
      arm7_reg_write(arm,r,value);
    }
    ++r;
  }
  uint32_t cpsr = arm7_reg_read(arm,CPSR);
  int flag_bits[]={
    31,30,29,28,
    27,5,6,7,
  };
  const char * flag_names[]={
    "N","Z","C","V","Q","T","F","I",NULL
  };
  for(int i=0;i<sizeof(flag_bits)/sizeof(flag_bits[0]);++i){
    int b= flag_bits[i];
    bool v = SB_BFE(cpsr,b,1);
    int y = i/4;
    int x = i%4; 
    if(x!=0)igSameLine(x*w/4,0);
    se_checkbox(flag_names[i],&v);
    cpsr&=~(1<<b);
    cpsr|= ((int)v)<<b;
  }
  arm7_reg_write(arm,CPSR,cpsr);
  unsigned pc = arm7_reg_read(arm,PC);
  bool thumb = arm7_get_thumb_bit(arm);
  //pc-=thumb? 4: 8;
  uint8_t buffer[128];
  int buffer_size = sizeof(buffer);
  if(thumb)buffer_size/=2;
  int off = buffer_size/2;
  if(pc<off)off=pc;
  for(int i=0;i<buffer_size;++i)buffer[i]=read(pc-off+i);
  se_text(ICON_FK_LIST_OL " Disassembly");
  igSeparator();
  csh handle;
  if (cs_open(CS_ARCH_ARM, thumb? CS_MODE_THUMB: CS_MODE_ARM, &handle) == CS_ERR_OK){
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_insn *insn;
    int count = cs_disasm(handle, buffer, buffer_size, pc-off, 0, &insn);
    size_t j;
    for (j = 0; j < count; j++) {
      char instr_str[80];
      
      if(insn[j].address==pc){
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
        se_text("PC " ICON_FK_ARROW_RIGHT);
        igSameLine(40,0);
        snprintf(instr_str,80,"0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        se_text(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(130,0);
        se_text(instr_str);
        igPopStyleColor(1);
      }else{
        snprintf(instr_str,80,"0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        se_text("");
        igSameLine(40,0);
        se_text(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(130,0);
        se_text(instr_str);
      }
    }  
  }

  se_text(ICON_FK_RANDOM " Last Branch Locations");
  igSeparator();
  for(int i=0;i<ARM_DEBUG_BRANCH_RING_SIZE;++i){
    uint32_t ind = (arm->debug_branch_ring_offset-i-1);
    ind%=ARM_DEBUG_BRANCH_RING_SIZE;
    se_text("%d",i+1);
    igSameLine(40,0);
    se_text("0x%08x",arm->debug_branch_ring[ind]);
  }
}
void se_draw_mem_debug_state(const char* label, gui_state_t* gui, emu_byte_read_t read,emu_byte_write_t write){
  se_text(ICON_FK_EXCHANGE " Read/Write Memory Address");
  igSeparator();
  se_input_int("address",&gui->mem_view_address, 1,5,ImGuiInputTextFlags_CharsHexadecimal);
  igSeparator();
  int v = se_read32(read,gui->mem_view_address);
  if(se_input_int("data (32 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    se_write32(write,gui->mem_view_address,v);
  }
  v = se_read16(read,gui->mem_view_address);
  if(se_input_int("data (16 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    se_write16(write,gui->mem_view_address,v);
  }
  v = (*read)(gui->mem_view_address);
  if(se_input_int("data (8 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    (*write)(gui->mem_view_address,v);
  }
  v = se_read32(read,gui->mem_view_address);
  if(se_input_int("data (signed 32b)",&v, 1,5,ImGuiInputTextFlags_None)){
    se_write32(write,gui->mem_view_address,v);
  }
  v = se_read16(read,gui->mem_view_address);
  if(se_input_int("data (signed 16b)",&v, 1,5,ImGuiInputTextFlags_None)){
    se_write16(write,gui->mem_view_address,v);
  }
  v = (*read)(gui->mem_view_address);
  if(se_input_int("data (signed 8b)",&v, 1,5,ImGuiInputTextFlags_None)){
    (*write)(gui->mem_view_address,v);
  }
  se_text(ICON_FK_FILE_O " Dump Memory to File");
  igSeparator();
  se_input_int("Start Address",&gui->mem_dump_start_address, 1,5,ImGuiInputTextFlags_CharsHexadecimal);
  se_input_int("Size",&gui->mem_dump_size, 1,5,ImGuiInputTextFlags_None);
  if(se_button("Save Memory Dump",(ImVec2){0,0})){
    uint8_t *data = (uint8_t*)malloc(gui->mem_dump_size);
    for(int i=0;i<gui->mem_dump_size;++i)data[i]=(*read)(gui->mem_dump_start_address+i);
    const char *base, *file_name,*ext;
    sb_breakup_path(emu_state.save_file_path,&base,&file_name,&ext);
    char new_path[SB_FILE_PATH_SIZE];
    snprintf(new_path,SB_FILE_PATH_SIZE,"%s/%s-memdump.bin",base,file_name);
    sb_save_file_data(new_path,data,gui->mem_dump_size);
    free(data);
  }

}
void se_draw_io_state(const char * label, mmio_reg_t* mmios, int mmios_size, emu_byte_read_t read, emu_byte_write_t write, emu_mmio_access_type access_type){
  for(int i = 0; i<mmios_size;++i){
    uint32_t addr = mmios[i].addr;
    uint32_t data = se_read32(read, addr);
    bool has_fields = false;
    igPushIDInt(i);
    char lab[80];
    sb_debug_mmio_access_t access={0};
    if(access_type)access=access_type(addr);
    else{
      access.read_since_reset=true;
      access.write_since_reset=true;
    }
    snprintf(lab,80,"0x%08x: %s %s%s",addr,mmios[i].name,access.write_in_tick?ICON_FK_PENCIL_SQUARE_O:"",access.read_in_tick?ICON_FK_SEARCH:"");
    if (igTreeNodeStrStr(mmios[i].name,lab)){
      for(int f = 0; f<sizeof(mmios[i].bits)/sizeof(mmios[i].bits[0]);++f){
        igPushIDInt(f);
        uint32_t start = mmios[i].bits[f].start; 
        uint32_t size = mmios[i].bits[f].size; 
        if(size){
          uint32_t field_data = SB_BFE(data,start,size);
          has_fields=true;
          uint32_t mask = (((1<<size)-1)<<start);
          bool edit = false;
          if(size==1){
            bool v = field_data!=0;
            edit=se_checkbox("",&v);
            data &= ~mask;
            data |= (v<<start)&mask; 
          }else{
            int v = field_data;
            igPushItemWidth(100);
            edit = se_input_int("",&v, 1,5,ImGuiInputTextFlags_CharsDecimal);
            data &= ~mask;
            data |= (v<<start)&mask;
            igPopItemWidth();
          }
          if(edit){
            se_write32(write,addr,data);
          }
          igSameLine(0,2);
          if(size>1)se_text("%s (Bits [%d:%d])",mmios[i].bits[f].name,start, start+size-1);
          else se_text("%s (Bit %d)",mmios[i].bits[f].name,start);
        }
        igPopID();
      }
      if(!has_fields){
        int v = data; 
        igPushIDInt(0);
        igPushItemWidth(150);
        if(se_input_int("",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
          se_write32(write,addr,v);
        }
        igSameLine(0,2);
        se_text("Data");
        igPopID();
      }
      igTreePop();
    }
    igPopID();
  }
}
/////////////////////////////////
// BEGIN UPDATE FOR NEW SYSTEM //
/////////////////////////////////

// Used for file loading dialogs
static const char* valid_rom_file_types[] = { "*.gb", "*.gba","*.gbc" ,"*.nds","*.zip"};
void se_load_rom_from_emu_state(sb_emu_state_t*emu){
  if(!emu->rom_data)return;
  printf("Loading: %s\n",emu_state.rom_path);
  emu_state.rom_loaded = false; 
  if(gba_load_rom(emu, &core.gba, &scratch.gba)){
    emu->system = SYSTEM_GBA;
    emu->rom_loaded = true;
  }else if(sb_load_rom(emu,&core.gb,&scratch.gb)){
    emu->system = SYSTEM_GB;
    emu->rom_loaded = true; 
  }else if(nds_load_rom(emu,&core.nds,&scratch.nds)){
    emu->system = SYSTEM_NDS;
    emu->rom_loaded = true; 
  }
}
void se_load_rom(const char *filename){
  se_reset_rewind_buffer(&rewind_buffer);
  se_reset_save_states();
  se_reset_bios_info();
  emu_state.force_dmg_mode=gui_state.settings.force_dmg_mode;
  char *save_file=emu_state.save_file_path; 
  save_file[0] = '\0';
  const char* base, *c, *ext; 
  sb_breakup_path(filename,&base, &c, &ext);
#if defined(EMSCRIPTEN)
    if(sb_path_has_file_ext(filename,".sav")){
      if(strncmp(filename,gui_state.recently_loaded_games[0].path,SB_FILE_PATH_SIZE)!=0){
        return se_load_rom(gui_state.recently_loaded_games[0].path);
      }
      return;
    }
    snprintf(emu_state.save_data_base_path, SB_FILE_PATH_SIZE,"/offline/%s", c);
#else
    se_join_path(emu_state.save_data_base_path, SB_FILE_PATH_SIZE, base, c, NULL);
#endif
  snprintf(save_file, SB_FILE_PATH_SIZE, "%s.sav",emu_state.save_data_base_path);
  if(!sb_file_exists(save_file)){
    const char* base, *c, *ext; 
    sb_breakup_path(filename,&base, &c, &ext);
    char tmp_path[SB_FILE_PATH_SIZE];
    se_join_path(tmp_path,SB_FILE_PATH_SIZE,gui_state.paths.save,c,".sav");
    printf("c: %s tmp path: %s\n",c,tmp_path);
    printf("save_base: %s\n",gui_state.paths.save);

    if(sb_file_exists(tmp_path)||gui_state.settings.save_to_path){
      se_join_path(emu_state.save_data_base_path,SB_FILE_PATH_SIZE,gui_state.paths.save,c,NULL);
      strncpy(save_file,tmp_path,SB_FILE_PATH_SIZE);
    }
  }
  strncpy(emu_state.rom_path, filename, sizeof(emu_state.rom_path));

  if(emu_state.rom_loaded){
    if(emu_state.system==SYSTEM_NDS)nds_unload(&core.nds, &scratch.nds);
    else if(emu_state.system==SYSTEM_GBA)gba_unload(&core.gba,&scratch.gba);
  }
  if(emu_state.rom_data){
    free(emu_state.rom_data);
    emu_state.rom_data = NULL;
    emu_state.rom_size = 0; 
    emu_state.rom_loaded=false;
  }
  memset(&core,0,sizeof(core));
  printf("Loading ROM: %s\n", filename); 

  if(sb_path_has_file_ext(filename,".zip")){
    printf("Loading Zip:%s \n",filename);
    mz_zip_archive zip = {0};
    mz_zip_zero_struct(&zip);
    if(mz_zip_reader_init_file(&zip, filename, 0)){
      size_t total_files = mz_zip_reader_get_num_files(&zip);
      for(size_t i=0;i<total_files;++i){
        char file_name_buff[SB_FILE_PATH_SIZE];
        bool success= true;
        mz_zip_reader_get_filename(&zip, i, file_name_buff, SB_FILE_PATH_SIZE);
        file_name_buff[SB_FILE_PATH_SIZE-1]=0;
        mz_zip_archive_file_stat stat={0};
        success&= mz_zip_reader_file_stat(&zip,i, &stat);
        success&= !stat.m_is_directory;
        emu_state.rom_data = NULL;
        emu_state.rom_size = 0; 
        snprintf(emu_state.rom_path,sizeof(emu_state.rom_path),"%s/%s",filename,file_name_buff);
        if(success){
          emu_state.rom_size = stat.m_uncomp_size;
          emu_state.rom_data = (uint8_t*)malloc(emu_state.rom_size);
          success&= mz_zip_reader_extract_to_mem(&zip,i,emu_state.rom_data, emu_state.rom_size,0);
          if(!success)free(emu_state.rom_data);
        }
        if(success)se_load_rom_from_emu_state(&emu_state);
        if(emu_state.rom_loaded)break;
      }
      mz_zip_reader_end(&zip);
    }else printf("Failed to load zip: %s\n",filename);

  }else{
    emu_state.rom_data = sb_load_file_data(emu_state.rom_path, &emu_state.rom_size);
    se_load_rom_from_emu_state(&emu_state);
  }
  if(emu_state.rom_loaded==false){
    printf("ERROR: Unknown ROM type: %s\n", filename);
    emu_state.run_mode= SB_MODE_PAUSE;
  }else{
    emu_state.run_mode= SB_MODE_RESET;
    se_game_info_t * recent_games=gui_state.recently_loaded_games;
    //Create a copy in case file name comes from one of these slots that will be modified. 
    char temp_filename[SB_FILE_PATH_SIZE];
    strncpy(temp_filename,filename,SB_FILE_PATH_SIZE);
    if(strncmp(filename,recent_games[0].path,SB_FILE_PATH_SIZE)!=0){
      se_game_info_t g;
      strncpy(g.path,filename,SB_FILE_PATH_SIZE);
      for(int i=0; i<SE_NUM_RECENT_PATHS;++i){
        se_game_info_t g2 = recent_games[i];
        recent_games[i]=g;
        if(strncmp(temp_filename,g2.path,SB_FILE_PATH_SIZE)==0||strncmp("",g2.path,SB_FILE_PATH_SIZE)==0)break;
        g=g2;
      }
    }
    se_save_recent_games_list();
  }
  for(int i=0;i<SE_NUM_SAVE_STATES;++i){
    save_states[i].valid=false;
    char save_state_path[SB_FILE_PATH_SIZE];
    snprintf(save_state_path,SB_FILE_PATH_SIZE,"%s.slot%d.state.png",emu_state.save_data_base_path,i);
    se_load_state_from_disk(save_states+i,save_state_path);
    if(!save_states[i].valid){
      const char* base, *file,*ext;
      sb_breakup_path(emu_state.save_data_base_path,&base,&file,&ext);
      snprintf(save_state_path,SB_FILE_PATH_SIZE,"%s%s.slot%d.state.png",gui_state.paths.save,file,i);
      se_load_state_from_disk(save_states+i,save_state_path);
    }
  }
  return; 
}
static void se_reset_core(){
  se_load_rom(gui_state.recently_loaded_games[0].path);
}
static bool se_write_save_to_disk(const char* path){
  bool saved = false;
  if(emu_state.system== SYSTEM_GB){
    if(core.gb.cart.ram_is_dirty){
      saved=true;
      if(sb_save_file_data(path,core.gb.cart.ram_data,core.gb.cart.ram_size)){
      }else printf("Failed to write out save file: %s\n",path);
      core.gb.cart.ram_is_dirty=false;
    }
  }else if(emu_state.system ==SYSTEM_GBA){
    if(core.gba.cart.backup_is_dirty){
      int size = 0; 
      switch(core.gba.cart.backup_type){
        case GBA_BACKUP_NONE       : size = 0;       break;
        case GBA_BACKUP_EEPROM     : size = 8*1024;  break;
        case GBA_BACKUP_EEPROM_512B: size = 512;     break;
        case GBA_BACKUP_EEPROM_8KB : size = 8*1024;  break;
        case GBA_BACKUP_SRAM       : size = 32*1024; break;
        case GBA_BACKUP_FLASH_64K  : size = 64*1024; break;
        case GBA_BACKUP_FLASH_128K : size = 128*1024;break;
      }
      if(size){
        saved =true;
        if(sb_save_file_data(path,core.gba.mem.cart_backup,size)){
        }else printf("Failed to write out save file: %s\n",path);
      }
      core.gba.cart.backup_is_dirty=false;
    }
  }else if(emu_state.system ==SYSTEM_NDS){
    if(core.nds.backup.is_dirty){
      int size = nds_get_save_size(&core.nds);
      if(size){
        saved =true;
        if(sb_save_file_data(path,core.nds.mem.save_data,size)){
        }else printf("Failed to write out save file: %s\n",path);
      }
      core.nds.backup.is_dirty=false;
    }
  }
  return saved;
}
static bool se_sync_save_to_disk(){return se_write_save_to_disk(emu_state.save_file_path);}
//Returns offset into savestate where bess info can be found
static uint32_t se_save_best_effort_state(se_core_state_t* state){
  if(emu_state.system==SYSTEM_GB)return sb_save_best_effort_state(&state->gb);
  if(emu_state.system==SYSTEM_GBA)return gba_save_best_effort_state(&state->gba);
  return -1; 
}
static bool se_load_best_effort_state(se_core_state_t* state,uint8_t *save_state_data, uint32_t size, uint32_t bess_offset){
  if(emu_state.system==SYSTEM_GB)return sb_load_best_effort_state(&state->gb,save_state_data,size,bess_offset);
  if(emu_state.system==SYSTEM_GBA)return gba_load_best_effort_state(&state->gba,save_state_data,size,bess_offset);
  return false;
}
static double se_get_sim_fps(){
  double sim_fps=1.0;
  if(emu_state.system==SYSTEM_GB)sim_fps = 59.727;
  else if(emu_state.system == SYSTEM_GBA) sim_fps = 59.727;
  else if(emu_state.system == SYSTEM_NDS) sim_fps = 59.8261;
  return sim_fps;
}
static size_t se_get_core_size(){
  if(emu_state.system==SYSTEM_GB)return sizeof(core.gb);
  else if(emu_state.system == SYSTEM_GBA) return sizeof(core.gba);
  else if(emu_state.system == SYSTEM_NDS) return sizeof(core.nds);
  return 0; 
}
typedef struct{
  float red_color[3];
  float green_color[3];
  float blue_color[3];
  float gamma; 
  bool is_grayscale;
}se_lcd_info_t;
se_lcd_info_t se_get_lcd_info(){
  if(emu_state.system==SYSTEM_GB){
    if(core.gb.model==SB_GBC){
      return (se_lcd_info_t){
        .red_color  ={26./32,0./32.,6./32.},
        .green_color={4./32,24/32.,4./32.},
        .blue_color ={2./32,8./32,22./32},
        .gamma = 2.2,
      };
    }else{
      return (se_lcd_info_t){
        .red_color  ={1,0,0},
        .green_color={0,1,0},
        .blue_color ={0,0,1},
        .gamma = 2.2,
        .is_grayscale = true
      };
    }
  }else if(emu_state.system == SYSTEM_GBA){
    if(gui_state.settings.gba_color_correction_mode==GBA_HIGAN_CORRECTION){
      return (se_lcd_info_t){
        .red_color  ={1,0.039,0.196},
        .green_color={0.196 ,0.901,0.039},
        .blue_color ={0,0.117,0.862},
        .gamma = 4.0
      };
    }
    return (se_lcd_info_t){
      .red_color  ={1,0.05,0.0},
      .green_color={0.05,1,0.05},
      .blue_color ={0,0.05,1.0},
      .gamma = 3.7
    };
  }
  return (se_lcd_info_t){
    .red_color  ={1,0,0},
    .green_color={0,1,0},
    .blue_color ={0,0,1},
    .gamma = 2.2
  };
}
static void se_emulate_single_frame(){
  if(emu_state.system == SYSTEM_GB){
    if(gui_state.test_runner_mode){
      uint8_t palette[4*3] = { 0xff,0xff,0xff,0xAA,0xAA,0xAA,0x55,0x55,0x55,0x00,0x00,0x00 };
      for(int i=0;i<12;++i)core.gb.dmg_palette[i]=palette[i];
    }else{
      for(int i=0;i<4;++i){
        uint32_t v = gui_state.settings.gb_palette[i];
        core.gb.dmg_palette[i*3+0]=SB_BFE(v,0,8);
        core.gb.dmg_palette[i*3+1]=SB_BFE(v,8,8);
        core.gb.dmg_palette[i*3+2]=SB_BFE(v,16,8);
      }
    }
    sb_tick(&emu_state,&core.gb, &scratch.gb);
  }
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &core.gba, &scratch.gba);
  else if(emu_state.system == SYSTEM_NDS)nds_tick(&emu_state, &core.nds, &scratch.nds);
  
}
static void se_screenshot(uint8_t * output_buffer, int * out_width, int * out_height){
  *out_height=*out_width=0;
  // output_bufer is always SE_MAX_SCREENSHOT_SIZE bytes. RGB8
  if(emu_state.system==SYSTEM_GBA){
    *out_width = GBA_LCD_W;
    *out_height = GBA_LCD_H;
    memcpy(output_buffer,core.gba.framebuffer,GBA_LCD_W*GBA_LCD_H*4);
  }else if (emu_state.system==SYSTEM_NDS){
    *out_width = NDS_LCD_W;
    *out_height = NDS_LCD_H*2;
    memcpy(output_buffer,core.nds.framebuffer_top,NDS_LCD_W*NDS_LCD_H*4);
    memcpy(output_buffer+NDS_LCD_W*NDS_LCD_H*4,core.nds.framebuffer_bottom,NDS_LCD_W*NDS_LCD_H*4);
  }else if (emu_state.system==SYSTEM_GB){
    *out_width = SB_LCD_W;
    *out_height = SB_LCD_H;
    memcpy(output_buffer,core.gb.lcd.framebuffer,SB_LCD_W*SB_LCD_H*4);
  }
  for(int i=3;i<SE_MAX_SCREENSHOT_SIZE;i+=4)output_buffer[i]=0xff;
}
static void se_draw_emulated_system_screen(bool preview){
  int lcd_render_x = 0, lcd_render_y = 0; 
  int lcd_render_w = 0, lcd_render_h = 0; 

  float native_w = SB_LCD_W;
  float native_h = SB_LCD_H;
  float lcd_aspect = SB_LCD_H/(float)SB_LCD_W;
  if(emu_state.system==SYSTEM_GBA){native_w = GBA_LCD_W; native_h = GBA_LCD_H;}
  else if(emu_state.system==SYSTEM_NDS){native_w = NDS_LCD_W; native_h = NDS_LCD_H*2;}

  float rotation = gui_state.settings.screen_rotation*0.5*3.14159;

  lcd_aspect= native_h/native_w;

  float scr_w = igGetWindowWidth();
  float scr_h = igGetWindowHeight();
 
  float height = scr_h;
  float render_w = native_w;
  float render_h = native_h;
  switch(gui_state.settings.screen_rotation){
    case 1: case 3:
      render_w = native_h;
      render_h = native_w;
  }
  float render_aspect = render_h/render_w; 

  float render_scale =1;
  if(scr_w*render_aspect>height){
    render_scale = height/render_h;
  }else{
    render_scale = scr_w/render_w;
  }

  lcd_render_w = native_w*render_scale;
  lcd_render_h = native_h*render_scale;
  render_w*=render_scale;
  render_h*=render_scale;

  float dpi_scale =  preview?1.0: se_dpi_scale();

  //Don't hide menubar if it doesn't make the screen smaller
  if(gui_state.screen_height/dpi_scale-SE_MENU_BAR_HEIGHT>gui_state.screen_width/dpi_scale*render_aspect&&!preview){
      gui_state.menubar_hide_timer=se_time();
  }

  int controller_h = fmin(scr_h,scr_w*0.8); 
  int controller_y_pad = 0; 
  if(gui_state.last_touch_time>=0||gui_state.settings.auto_hide_touch_controls==false){
    lcd_render_y = -(height-render_h)*0.9*0.5;
    if(controller_h+render_h<height){
      float off = (height-render_h-controller_h)*0.15;
      lcd_render_y+=off;
      controller_y_pad=(height-render_h-controller_h-off)*0.20;
    }
  }
  if(gui_state.settings.integer_scaling){
    float old_w = lcd_render_w;
    float old_h = lcd_render_h;
    lcd_render_h = ((int)((lcd_render_h)/native_h))*native_h;
    lcd_render_w = ((int)((lcd_render_w)/native_w))*native_w;
  }
  if(gui_state.settings.stretch_to_fit){
    if(gui_state.last_touch_time>=0){
      if(scr_w*render_aspect<scr_h-(controller_h+controller_y_pad*2)){
        lcd_render_h = scr_h-(controller_h+controller_y_pad*2);
        lcd_render_y = scr_h-(controller_h+controller_y_pad*2+lcd_render_h*0.5)-scr_h*0.5;
      }
    }else{
      lcd_render_h = scr_h;
      lcd_render_w = scr_w;
    }
    if(gui_state.settings.screen_rotation==1 || gui_state.settings.screen_rotation==3){
      int t = lcd_render_w;
      lcd_render_w = lcd_render_h; 
      lcd_render_h= t; 
    }
  }
  ImVec2 v;
  igGetWindowPos(&v);
  lcd_render_x+=v.x*dpi_scale+scr_w*0.5;
  lcd_render_y+=v.y*dpi_scale+scr_h*0.5;
  if(preview){
    
    ImVec2 min = {lcd_render_x-lcd_render_w*0.5,lcd_render_y-lcd_render_h*0.5};
    ImVec2 max = {lcd_render_x+lcd_render_w*0.5,lcd_render_y+lcd_render_h*0.5};
    
    ImU32 col = 0xffC08000;
    igRenderFrame(min,max,col,true,0);
  }else{
    if(emu_state.system==SYSTEM_GBA){
      se_draw_lcd(core.gba.framebuffer,GBA_LCD_W,GBA_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,rotation);
    }else if (emu_state.system==SYSTEM_NDS){
      float p[4]={
        0,-lcd_render_h*0.25,
        0,lcd_render_h*0.25
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }

      float x = gui_state.mouse_pos[0];
      float y = gui_state.mouse_pos[1];
      x-=lcd_render_x+p[2];
      y-=lcd_render_y+p[3];
      x/=lcd_render_w;
      y/=lcd_render_h*0.5;
      x+=0.5;
      y+=0.5;
      emu_state.joy.touch_pos[0]=x;
      emu_state.joy.touch_pos[1]=y;
      if(gui_state.mouse_button[0]&&x>=0&&x<=1.0&&y>=0.&&y<=1.0)emu_state.joy.inputs[SE_KEY_PEN_DOWN]=true;
      se_draw_lcd(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lcd_render_x+p[0],lcd_render_y+p[1], lcd_render_w, lcd_render_h*0.5,rotation);
      se_draw_lcd(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lcd_render_x+p[2],lcd_render_y+p[3], lcd_render_w, lcd_render_h*0.5,rotation);
    }else if (emu_state.system==SYSTEM_GB){
      se_draw_lcd(core.gb.lcd.framebuffer,SB_LCD_W,SB_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,rotation);
    }
  }
  if(!gui_state.block_touchscreen||preview)sb_draw_onscreen_controller(&emu_state, controller_h, controller_y_pad,preview);
}
static uint8_t gba_byte_read(uint64_t address){return gba_read8(&core.gba,address);}
static void gba_byte_write(uint64_t address, uint8_t data){gba_store8(&core.gba,address,data);}
static uint8_t gb_byte_read(uint64_t address){return sb_read8(&core.gb,address);}
static void gb_byte_write(uint64_t address, uint8_t data){sb_store8(&core.gb,address,data);}

static uint8_t nds9_byte_read(uint64_t address){return nds9_debug_read8(&core.nds,address);}
static void nds9_byte_write(uint64_t address, uint8_t data){nds9_debug_write8(&core.nds,address,data);}
static uint8_t nds7_byte_read(uint64_t address){return nds7_debug_read8(&core.nds,address);}
static void nds7_byte_write(uint64_t address, uint8_t data){nds7_debug_write8(&core.nds,address,data);}
typedef struct{
  const char* short_label;
  const char* label;
  void (*function)();
  bool visible;
}se_debug_tool_desc_t; 

void gba_memory_debugger(){se_draw_mem_debug_state("GBA MEM", &gui_state, &gba_byte_read, &gba_byte_write); }
void gba_cpu_debugger(){se_draw_arm_state("CPU",&core.gba.cpu,&gba_byte_read);}
void gba_mmio_debugger(){se_draw_io_state("GBA MMIO", gba_io_reg_desc,sizeof(gba_io_reg_desc)/sizeof(mmio_reg_t), &gba_byte_read, &gba_byte_write,NULL);}

void gb_mmio_debugger(){se_draw_io_state("GB MMIO", gb_io_reg_desc,sizeof(gb_io_reg_desc)/sizeof(mmio_reg_t), &gb_byte_read, &gb_byte_write,NULL);}
void gb_memory_debugger(){se_draw_mem_debug_state("GB MEM", &gui_state, &gb_byte_read, &gb_byte_write);}

sb_debug_mmio_access_t nds7_mmio_access_type(uint64_t address){return nds_debug_mmio_access(&core.nds,NDS_ARM7,address);}
sb_debug_mmio_access_t nds9_mmio_access_type(uint64_t address){return nds_debug_mmio_access(&core.nds,NDS_ARM9,address);}
void nds7_mmio_debugger(){se_draw_io_state("NDS7 MMIO", nds7_io_reg_desc,sizeof(nds7_io_reg_desc)/sizeof(mmio_reg_t), &nds7_byte_read, &nds7_byte_write,&nds7_mmio_access_type); }
void nds9_mmio_debugger(){se_draw_io_state("NDS9 MMIO", nds9_io_reg_desc,sizeof(nds9_io_reg_desc)/sizeof(mmio_reg_t), &nds9_byte_read, &nds9_byte_write,&nds9_mmio_access_type); }
void nds7_mem_debugger(){se_draw_mem_debug_state("NDS9 MEM",&gui_state, &nds9_byte_read, &nds9_byte_write); }
void nds9_mem_debugger(){se_draw_mem_debug_state("NDS7_MEM",&gui_state, &nds7_byte_read, &nds7_byte_write);}
void nds7_cpu_debugger(){se_draw_arm_state("ARM7",&core.nds.arm7,&nds7_byte_read); }
void nds9_cpu_debugger(){se_draw_arm_state("ARM9",&core.nds.arm9,&nds9_byte_read);}
void nds_io_debugger(){
  nds_t * nds = &core.nds;
  for(int cpu=0;cpu<2;++cpu){
    se_text(cpu? ICON_FK_EXCHANGE " ARM9 IPC FIFO":ICON_FK_EXCHANGE " ARM7 IPC FIFO");
    igSeparator();
    se_text("Write Pointer: %d\n", nds->ipc[cpu].write_ptr);
    se_text("Read Pointer: %d\n", nds->ipc[cpu].read_ptr);
    se_text("Size: %d\n", (nds->ipc[cpu].write_ptr-nds->ipc[cpu].read_ptr)&0x1f);
    se_text("Error: %d\n", nds->ipc[cpu].error);

  }
}

se_debug_tool_desc_t gba_debug_tools[]={
  {ICON_FK_TELEVISION, ICON_FK_TELEVISION " CPU", gba_cpu_debugger},
  {ICON_FK_SITEMAP, ICON_FK_SITEMAP " MMIO", gba_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O, ICON_FK_PENCIL_SQUARE_O " Memory",gba_memory_debugger},
  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats},
  {NULL,NULL,NULL}
};
se_debug_tool_desc_t gb_debug_tools[]={
  {ICON_FK_SITEMAP, ICON_FK_SITEMAP " MMIO", gb_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O, ICON_FK_PENCIL_SQUARE_O " Memory",gb_memory_debugger},
  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats},
  {NULL,NULL,NULL}
};
se_debug_tool_desc_t nds_debug_tools[]={
  {ICON_FK_TELEVISION " 7", ICON_FK_TELEVISION " ARM7 CPU", nds7_cpu_debugger},
  {ICON_FK_TELEVISION " 9", ICON_FK_TELEVISION " ARM9 CPU", nds9_cpu_debugger},
  {ICON_FK_SITEMAP " 7", ICON_FK_SITEMAP " ARM7 MMIO", nds7_mmio_debugger},
  {ICON_FK_SITEMAP " 9", ICON_FK_SITEMAP " ARM9 MMIO", nds9_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O " 7", ICON_FK_PENCIL_SQUARE_O " ARM7 Memory",nds7_mem_debugger},
  {ICON_FK_PENCIL_SQUARE_O " 9", ICON_FK_PENCIL_SQUARE_O " ARM9 Memory",nds9_mem_debugger},
  {ICON_FK_INFO_CIRCLE, ICON_FK_INFO_CIRCLE " NDS IO",nds_io_debugger},

  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats},
  {NULL,NULL,NULL}
};
static se_debug_tool_desc_t* se_get_debug_description(){
  se_debug_tool_desc_t *desc = NULL;
  if(emu_state.system ==SYSTEM_GBA)desc = gba_debug_tools;
  if(emu_state.system ==SYSTEM_GB)desc = gb_debug_tools;
  if(emu_state.system ==SYSTEM_NDS)desc = nds_debug_tools;
  return desc; 
}
uint8_t se_read_byte(uint64_t address, int addr_map){
  if(emu_state.system ==SYSTEM_GBA)return gba_byte_read(address);
  if(emu_state.system ==SYSTEM_GB)return gb_byte_read(address);
  if(emu_state.system ==SYSTEM_NDS)return addr_map==7? nds7_byte_read(address):nds9_byte_read(address);
  return 0; 
}
void se_write_byte(uint64_t address, int addr_map, uint8_t byte){
  if(emu_state.system ==SYSTEM_GBA)return gba_byte_write(address,byte);
  if(emu_state.system ==SYSTEM_GB)return gb_byte_write(address,byte);
  if(emu_state.system ==SYSTEM_NDS)return addr_map==7? nds7_byte_write(address,byte):nds9_byte_write(address,byte);
}
///////////////////////////////
// END UPDATE FOR NEW SYSTEM //
///////////////////////////////
void se_capture_state(se_core_state_t* core, se_save_state_t * save_state){
  save_state->state = *core; 
  save_state->valid = true;
  save_state->system = emu_state.system;
  se_screenshot(save_state->screenshot, &save_state->screenshot_width, &save_state->screenshot_height);
}
void se_restore_state(se_core_state_t* core, se_save_state_t * save_state){
  if(!save_state->valid || save_state->system != emu_state.system)return; 
  *core=save_state->state;
  emu_state.render_frame = true;
  se_emulate_single_frame();
}
void se_reset_save_states(){
  for(int i=0;i<SE_NUM_SAVE_STATES;++i)save_states[i].valid = false;
}
static void se_draw_debug_menu(){
  se_debug_tool_desc_t* desc=se_get_debug_description();
  if(!desc)return;
  ImGuiStyle* style = igGetStyle();
  int id = 10;

  if(gui_state.screen_width*0.5/se_dpi_scale()-SE_TOGGLE_WIDTH*2.5<(SE_MENU_BAR_BUTTON_WIDTH+1)*9){
    igSetNextItemWidth(SE_MENU_BAR_BUTTON_WIDTH);
    if(igBeginCombo("##debug combo","  " ICON_FK_BUG,ImGuiComboFlags_NoArrowButton|ImGuiComboFlags_HeightLarge)){
      while(desc->label){
        bool is_selected = desc->visible; // You can store your selection however you want, outside or inside your objects
        if (igSelectableBool(se_localize_and_cache(desc->label), is_selected,ImGuiSelectableFlags_None,(ImVec2){0,30})){
          desc->visible=!desc->visible;
        }
        char tmp_str[256];
        snprintf(tmp_str,sizeof(tmp_str),"Show/Hide %s Panel\n",desc->label);
        se_tooltip(tmp_str);
        desc++;
      }
      igEndCombo();
    }
    igSameLine(0,1);
  }else{
    while(desc->label){
      igPushIDInt(id++);
      if(desc->visible){
        igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
        if(se_button(desc->short_label,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,0})){desc->visible=!desc->visible;}
        igPopStyleColor(1);
      }else{
        if(se_button(desc->short_label,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,0})){desc->visible=!desc->visible;}
      }
      igSameLine(0,1);
      char tmp_str[256];
      snprintf(tmp_str,sizeof(tmp_str),"Show/Hide %s Panel\n",desc->label);
      se_tooltip(tmp_str);
      desc++;
      igPopID();
    }
  }
}
static float se_draw_debug_panels(float screen_x, float sidebar_w, float y, float height){
  se_debug_tool_desc_t* desc= se_get_debug_description();
  if(!desc)return screen_x;
  while(desc->label){
    if(desc->visible){
      gui_state.menubar_hide_timer=se_time();
      int w = sidebar_w+screen_x-(int)screen_x;
      igSetNextWindowPos((ImVec2){screen_x,y}, ImGuiCond_Always, (ImVec2){0,0});
      igSetNextWindowSize((ImVec2){w, height}, ImGuiCond_Always);
      igBegin(se_localize_and_cache(desc->label),&desc->visible, ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
      desc->function();
      float bottom_padding =0;
      #ifdef PLATFORM_IOS
      se_ios_get_safe_ui_padding(NULL,&bottom_padding,NULL,NULL);
      #endif
      igDummy((ImVec2){0,bottom_padding});
      igEnd();
      screen_x+=sidebar_w;
    }
    desc++;
  }
  return screen_x;
}
void se_set_default_keybind(gui_state_t *gui){
  for(int i=0;i<SE_NUM_KEYBINDS;++i)gui->key.bound_id[i]=-1;
  gui->key.bound_id[SE_KEY_A]     = SAPP_KEYCODE_J;  
  gui->key.bound_id[SE_KEY_B]     = SAPP_KEYCODE_K;
  gui->key.bound_id[SE_KEY_X]     = SAPP_KEYCODE_N;
  gui->key.bound_id[SE_KEY_Y]     = SAPP_KEYCODE_M;
  gui->key.bound_id[SE_KEY_UP]     = SAPP_KEYCODE_W;  
  gui->key.bound_id[SE_KEY_DOWN]   = SAPP_KEYCODE_S;    
  gui->key.bound_id[SE_KEY_LEFT]   = SAPP_KEYCODE_A;    
  gui->key.bound_id[SE_KEY_RIGHT]  = SAPP_KEYCODE_D;     
  gui->key.bound_id[SE_KEY_L]      = SAPP_KEYCODE_U; 
  gui->key.bound_id[SE_KEY_R]      = SAPP_KEYCODE_I; 
  gui->key.bound_id[SE_KEY_START]  = SAPP_KEYCODE_ENTER;      
  gui->key.bound_id[SE_KEY_SELECT] = SAPP_KEYCODE_APOSTROPHE; 
  gui->key.bound_id[SE_KEY_FOLD_SCREEN]= SAPP_KEYCODE_B;     
  gui->key.bound_id[SE_KEY_PEN_DOWN]= SAPP_KEYCODE_V; 
  gui->key.bound_id[SE_KEY_EMU_PAUSE]= SAPP_KEYCODE_V;

  gui->key.bound_id[SE_KEY_EMU_PAUSE]= SAPP_KEYCODE_SPACE;     
  gui->key.bound_id[SE_KEY_EMU_REWIND]= SAPP_KEYCODE_R;     
  gui->key.bound_id[SE_KEY_EMU_FF_2X]= SAPP_KEYCODE_F;     
  gui->key.bound_id[SE_KEY_EMU_FF_MAX]= SAPP_KEYCODE_TAB;     
  gui->key.bound_id[SE_KEY_SOLAR_M]= SAPP_KEYCODE_MINUS;     
  gui->key.bound_id[SE_KEY_SOLAR_P]= SAPP_KEYCODE_EQUAL;     
  gui->key.bound_id[SE_KEY_TOGGLE_FULLSCREEN] = SAPP_KEYCODE_F11;

  for(int i=0;i<SE_NUM_SAVE_STATES;++i){
    gui->key.bound_id[SE_KEY_CAPTURE_STATE(i)]=SAPP_KEYCODE_1+i;
    gui->key.bound_id[SE_KEY_RESTORE_STATE(i)]=SAPP_KEYCODE_F1+i;
  }

}
void sb_poll_controller_input(sb_joy_t* joy){
  for(int i=0;i<SE_NUM_KEYBINDS;++i){
    gui_state.key.value[i]=se_key_is_pressed(gui_state.key.bound_id[i]);
    joy->inputs[i] += 0.5<gui_state.key.value[i];
  }
}
void se_reset_joy(sb_joy_t*joy){
  for(int i=0;i<SE_NUM_KEYBINDS;++i){
    joy->inputs[i]=0;
  }
}

void se_draw_image_opacity(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha,float opacity){
  sg_image *image = se_get_image();
  if(!image||!data){return; }
  if(im_width<=0)im_width=1;
  if(im_height<=0)im_height=1;
  sg_image_data im_data={0};
  uint8_t * rgba8_data = data;
  if(has_alpha==false){
    rgba8_data= malloc(im_width*im_height*4);
    for(int i=0;i<im_width*im_height;++i){
      rgba8_data[i*4+0]= data[i*3+0];
      rgba8_data[i*4+1]= data[i*3+1];
      rgba8_data[i*4+2]= data[i*3+2];
      rgba8_data[i*4+3]= 255; 
    }
  }
  im_data.subimage[0][0].ptr = rgba8_data;
  im_data.subimage[0][0].size = im_width*im_height*4; 
  sg_image_desc desc={
    .type=              SG_IMAGETYPE_2D,
    .render_target=     false,
    .width=             im_width,
    .height=            im_height,
    .num_slices=        1,
    .num_mipmaps=       1,
    .usage=             SG_USAGE_IMMUTABLE,
    .pixel_format=      SG_PIXELFORMAT_RGBA8,
    .sample_count=      1,
    .min_filter=        SG_FILTER_NEAREST,
    .mag_filter=        SG_FILTER_NEAREST,
    .wrap_u=            SG_WRAP_CLAMP_TO_EDGE,
    .wrap_v=            SG_WRAP_CLAMP_TO_EDGE,
    .wrap_w=            SG_WRAP_CLAMP_TO_EDGE,
    .border_color=      SG_BORDERCOLOR_OPAQUE_BLACK,
    .max_anisotropy=    1,
    .min_lod=           0.0f,
    .max_lod=           1e9f,
    .data=              im_data,
  };

  *image =  sg_make_image(&desc);
  float dpi_scale = se_dpi_scale();
  unsigned tint = opacity*0xff;
  tint*=0x010101;
  tint|=0xff000000;
  ImDrawList_AddImage(igGetWindowDrawList(),
    (ImTextureID)(uintptr_t)image->id,
    (ImVec2){x/dpi_scale,y/dpi_scale},
    (ImVec2){(x+render_width)/dpi_scale,(y+render_height)/dpi_scale},
    (ImVec2){0,0},(ImVec2){1,1},
    tint);
  if(has_alpha==false)free(rgba8_data);
}

void se_draw_lcd(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, float rotation){
  sg_image *image = se_get_image();
  if(!image||!data){return; }
  if(im_width<=0)im_width=1;
  if(im_height<=0)im_height=1;
  sg_image_data im_data={0};
  uint8_t * rgba8_data = data;
  /*
  Delta compression codec
  static uint8_t last_value[1024*1024];
  int packet_count=0;
  uint32_t last_color =-1;
  for(int i=0;i<im_width*im_height;++i){

    uint16_t color = SB_BFE(rgba8_data[i*4+0]-last_value[i*4+0],3,5)|(SB_BFE(rgba8_data[i*4+1]-last_value[i*4+1],2,6)<<5)|(SB_BFE(rgba8_data[i*4+2]-last_value[i*4+2],3,5)<<11);
    last_value[i*4+0]=rgba8_data[i*4+0];
    last_value[i*4+1]=rgba8_data[i*4+1];
    last_value[i*4+2]=rgba8_data[i*4+2];
    if(color!=last_color){
      packet_count++;
      last_color=color;
    }
  }
  printf("Compressed Size:%d\n",packet_count*2);
  */
  im_data.subimage[0][0].ptr = rgba8_data;
  im_data.subimage[0][0].size = im_width*im_height*4; 
  sg_image_desc desc={
    .type=              SG_IMAGETYPE_2D,
    .render_target=     false,
    .width=             im_width,
    .height=            im_height,
    .num_slices=        1,
    .num_mipmaps=       1,
    .usage=             SG_USAGE_IMMUTABLE,
    .pixel_format=      SG_PIXELFORMAT_RGBA8,
    .sample_count=      1,
    .min_filter=        SG_FILTER_NEAREST,
    .mag_filter=        SG_FILTER_NEAREST,
    .wrap_u=            SG_WRAP_CLAMP_TO_EDGE,
    .wrap_v=            SG_WRAP_CLAMP_TO_EDGE,
    .wrap_w=            SG_WRAP_CLAMP_TO_EDGE,
    .border_color=      SG_BORDERCOLOR_OPAQUE_BLACK,
    .max_anisotropy=    1,
    .min_lod=           0.0f,
    .max_lod=           1e9f,
    .data=              im_data,
  };

  *image =  sg_make_image(&desc);
  float dpi_scale = se_dpi_scale();

  ImGuiIO* io = igGetIO();

  const int fb_width = (int) (io->DisplaySize.x * dpi_scale);
  const int fb_height = (int) (io->DisplaySize.y * dpi_scale);
  sg_apply_viewport(0, 0, fb_width, fb_height, true);
  sg_apply_scissor_rect(0, 0, fb_width, fb_height, true);

  sg_apply_pipeline(gui_state.lcd_pipeline);
  se_lcd_info_t lcd_info=se_get_lcd_info();
  lcd_params_t lcd_params={
    .display_size[0] = fb_width,
    .display_size[1] = fb_height,
    .render_off[0] = x, 
    .render_off[1] = y, 
    .render_size[0]= render_width,
    .render_size[1]= render_height,
    .emu_lcd_size[0]= im_width,
    .emu_lcd_size[1]= im_height,
    .display_mode = gui_state.test_runner_mode?0:gui_state.settings.screen_shader,
    .render_scale_x[0] = cos(rotation),
    .render_scale_x[1] = sin(rotation),
    .render_scale_y[0] = -sin(rotation),
    .render_scale_y[1] = cos(rotation),
    .lcd_is_grayscale = lcd_info.is_grayscale,
    .input_gamma = lcd_info.gamma,
    .red_color = {lcd_info.red_color[0],lcd_info.red_color[1],lcd_info.red_color[2]},
    .green_color = {lcd_info.green_color[0],lcd_info.green_color[1],lcd_info.green_color[2]},
    .blue_color = {lcd_info.blue_color[0],lcd_info.blue_color[1],lcd_info.blue_color[2]},
    .color_correction_strength=gui_state.test_runner_mode?0:gui_state.settings.color_correction
  };

  sg_bindings bind={
    .vertex_buffers[0] = gui_state.quad_vb,
    .fs_images[0] = *image
  };
  sg_apply_bindings(&bind);
  sg_apply_uniforms(SG_SHADERSTAGE_VS, 0, SG_RANGE_REF(lcd_params));
  sg_apply_uniforms(SG_SHADERSTAGE_FS, 0, SG_RANGE_REF(lcd_params));
  int verts = 6;
  sg_draw(0, verts, 1);
}

void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
  se_draw_image_opacity(data,im_width,im_height,x,y,render_width,render_height,has_alpha,1.0);
}
bool se_draw_image_button(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
  float dpi_scale = se_dpi_scale();
  igPushStyleColorVec4(ImGuiCol_Button, (ImVec4){0.f, 0.f, 0.f, 0.f});
  igPushStyleColorVec4(ImGuiCol_ButtonActive, (ImVec4){0.f, 0.f, 0.f, 0.0f});
  igPushStyleColorVec4(ImGuiCol_ButtonHovered, (ImVec4){0.f, 0.f, 0.f, 0.0f});
  igSetCursorScreenPos((ImVec2){x/dpi_scale,y/dpi_scale});
  bool clicked = igButtonEx("",
    (ImVec2){(render_width)/dpi_scale,(render_height)/dpi_scale},
    ImGuiButtonFlags_None);

  float opacity = 1.0; 
  if(igIsItemActive())opacity=0.6;
  else if(igIsItemHovered(ImGuiHoveredFlags_None))opacity=0.8;
  se_draw_image_opacity(data,im_width,im_height,x,y,render_width,render_height,has_alpha,opacity);

  igPopStyleColor(3);
  return clicked; 
}
float sb_distance(float * a, float* b, int dims){
  float v = 0;
  for(int i=0;i<dims;++i)v+=(a[i]-b[i])*(a[i]-b[i]);
  return sqrtf(v);
}
void se_initialize_keybind(se_keybind_state_t * state){
  for(int i=0;i<SE_NUM_BINDS_ALLOC;++i){
    state->bound_id[i]=-1;
    state->value[i]=0; 
  }
  state->rebind_start_time= - SE_REBIND_TIMER_LENGTH;
  state->bind_being_set=-1;
  state->last_bind_activitiy=-1;

}
//Returns true if modifed
bool se_handle_keybind_settings(int keybind_type, se_keybind_state_t * state){
  double rebind_timer = SE_REBIND_TIMER_LENGTH-(se_time()-state->rebind_start_time);
  int num_keybinds = SE_NUM_KEYBINDS;
  const char ** button_labels = se_keybind_names;
  const char * action = "Press new button " ICON_FK_SIGN_IN;
  if(keybind_type==SE_BIND_ANALOG){
    num_keybinds = SE_NUM_ANALOGBINDS;
    button_labels = se_analog_bind_names;
    action = "Move Axis " ICON_FK_SIGN_IN;
  }
  if(rebind_timer<0){state->bind_being_set=-1;}
  igPushIDInt(keybind_type);
  ImGuiStyle* style = igGetStyle();
  bool settings_changed = false; 
  for(int k=0;k<num_keybinds;++k){
    igPushIDInt(k);
    se_text("%s",se_localize_and_cache(button_labels[k]));
    float active = (state->value[k])>0.4;
    igSameLine(100,0);
    if(state->bind_being_set==k)active=true;
    if(active)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
    const char* button_label = "Not bound"; 
    char buff[32];
    if(state->bound_id[k]!=-1){
      switch(keybind_type){
        case SE_BIND_KEYBOARD: button_label=se_keycode_to_string(state->bound_id[k]);break;
        #ifdef USE_SDL
        case SE_BIND_KEY: 
          { 
            int key = state->bound_id[k];
            bool is_hat = key&SE_HAT_MASK;
            bool is_joy = key&(SE_JOY_NEG_MASK|SE_JOY_POS_MASK);
            if(is_hat){
              int hat_id = SB_BFE(key,8,8);
              int hat_val = SB_BFE(key,0,8);
              const char * dir = "";
              if(hat_val == SDL_HAT_UP)dir="UP";
              if(hat_val == SDL_HAT_DOWN)dir="DOWN";
              if(hat_val == SDL_HAT_LEFT)dir="LEFT";
              if(hat_val == SDL_HAT_RIGHT)dir="RIGHT";

              snprintf(buff, sizeof(buff),"Hat %d %s", hat_id, dir);
              button_label=buff;
            }else if(is_joy){
              int joy_id = SB_BFE(key,0,16);
              const char* dir = (key&SE_JOY_NEG_MASK)? "<-0.3": ">0.3";
              snprintf(buff, sizeof(buff),"Analog %d %s",joy_id,dir);
            }else snprintf(buff, sizeof(buff),"Key %d", state->bound_id[k]);button_label=buff;
          }
          button_label=buff;
          break;
        case SE_BIND_ANALOG: 
          snprintf(buff, sizeof(buff),"Analog %d (%0.2f)", state->bound_id[k],state->value[k]);button_label=buff;
          button_label=buff;
          break;
        #endif
      }
    }
    if(state->bind_being_set==k){
      button_label = buff; 
      snprintf(buff,sizeof(buff),"%s (%d)",action,(int)(rebind_timer+1));
      if(state->last_bind_activitiy!=-1){
        state->bound_id[k]=state->last_bind_activitiy;
        state->bind_being_set=-1; 
        settings_changed = true;
      }
      if(gui_state.button_state[SAPP_KEYCODE_BACKSPACE]){
        state->bound_id[k]=-1;
        state->bind_being_set=-1;
        settings_changed = true;
      }
    }
    if(se_button(button_label,(ImVec2){-1, 0})){
      state->bind_being_set = k;
      state->rebind_start_time = se_time();
    }
    if(active)igPopStyleColor(1);
    igPopID();
  } 
  igPopID();
  return settings_changed;
}
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h, int controller_y_pad,bool preview){
  if(state->run_mode!=SB_MODE_RUN)return;
  controller_h*=gui_state.settings.touch_controls_scale;
  float win_w = igGetWindowWidth();
  float win_h = igGetWindowHeight();
  if(preview==false){
    win_w /=se_dpi_scale();
    win_h /=se_dpi_scale();
    controller_h/=se_dpi_scale();
  }

  ImVec2 pos; 
  igGetWindowPos(&pos);
  float win_x = pos.x;
  float win_y = pos.y+win_h-controller_h-controller_y_pad;
  win_h=controller_h;
  float size_scalar = win_w;
  if(controller_h*1.4<win_w)size_scalar=controller_h*1.4;
  size_scalar*=1.15;
  if(gui_state.settings.touch_controls_scale)size_scalar*=sqrtf(gui_state.settings.touch_controls_scale);

  int button_padding =0.02*size_scalar; 
  int button_h = win_h*0.12;

  int face_button_h = win_h;
  int face_button_y = 0;

  ImU32 line_color = 0xffffff;
  ImU32 line_color2 =0x000000;
  ImU32 sel_color =0x000000;
  double turbo_t = se_time()*5;
  turbo_t-=floor(turbo_t);
  ImU32 turbo_color =0x0070ff;
  ImU32 hold_color =0xff4000;

  float opacity = 3.-(se_time()-gui_state.last_touch_time);
  if(opacity>1||preview)opacity=1;
  if(!gui_state.settings.auto_hide_touch_controls)opacity=1;   
  if(opacity<=0){opacity=0;}
  opacity*=gui_state.settings.touch_controls_opacity;


  line_color|=(int)(opacity*0x8f)<<24;
  line_color2|=(int)(opacity*0x8f)<<24;
  sel_color|=(int)(opacity*0x8f)<<24;
  hold_color|=(int)(0xff)<<24;
  turbo_color|=(int)(fmin(opacity+turbo_t*0.5,1)*0xff)<<24;

  int line_w0 = 1;
  int line_w1 = 3; 
  float button_r = size_scalar*0.0815;

  float dpad_sz0 = size_scalar*0.051;
  float dpad_sz1 = size_scalar*0.180;

  float a_pos[2] = {win_w-button_r*1.5,face_button_h*0.48+face_button_y};
  float b_pos[2] = {win_w-button_r*3.8,face_button_h*0.54+face_button_y};
  float dpad_pos[2] = {dpad_sz1+button_padding*2,face_button_h*0.5+face_button_y};
  if(emu_state.system==SYSTEM_GB){
    dpad_pos[1]*=0.8;
    a_pos[1]*=0.8;
    b_pos[1]*=0.8;
  }

  a_pos[0]+=win_x;
  b_pos[0]+=win_x;
  dpad_pos[0]+=win_x;

  a_pos[1]+=win_y;
  b_pos[1]+=win_y;
  dpad_pos[1]+=win_y;

  bool a=false,b=false,up=false,down=false, left=false,right=false;
 
  enum{max_points = 5};
  float points[max_points][2]={0};

  int p = 0;
  //if(IsMouseButtonDown(0))points[p++] = GetMousePosition();
  for(int i=0; i<SAPP_MAX_TOUCHPOINTS;++i){
    if(p<max_points&&gui_state.touch_points[i].active&&!preview){
      points[p][0]=gui_state.touch_points[i].pos[0]/se_dpi_scale();
      points[p][1]=gui_state.touch_points[i].pos[1]/se_dpi_scale();
      ++p;
    }
  }

  for(int i = 0;i<p;++i){
    if(sb_distance(points[i],a_pos,2)<button_r*1.6)a=true;
    if(sb_distance(points[i],b_pos,2)<button_r*1.6)b=true;

    int dx = points[i][0]-dpad_pos[0];
    int dy = points[i][1]-dpad_pos[1];
    if(dx>=-dpad_sz1*1.15 && dx<=dpad_sz1*1.15 && dy>=-dpad_sz1*1.15 && dy<=dpad_sz1*1.15 ){
      if(dy>dpad_sz0)down=true;
      if(dy<-dpad_sz0)up=true;

      if(dx>dpad_sz0)right=true;
      if(dx<-dpad_sz0)left=true;
    }
  }
  int scale = 1;
  int button_press=0;

  button_press|= a<<0;
  button_press|= b<<1;

  ImDrawList*dl= igGetWindowDrawList();

  ImU32 a_col = SB_BFE(gui_state.touch_controls.hold_toggle,0,1)?hold_color: SB_BFE(gui_state.touch_controls.turbo_toggle,0,1)? turbo_color: line_color;
  ImU32 b_col = SB_BFE(gui_state.touch_controls.hold_toggle,1,1)?hold_color: SB_BFE(gui_state.touch_controls.turbo_toggle,1,1)? turbo_color: line_color;

  if(a)  ImDrawList_AddCircleFilled(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,sel_color,128);
  ImDrawList_AddCircle(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,line_color2,128,line_w1);
  ImDrawList_AddCircle(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,a_col,128,line_w0);

  if(b)ImDrawList_AddCircleFilled(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,line_color2,128);
  ImDrawList_AddCircle(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,line_color2,128,line_w1);
  ImDrawList_AddCircle(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,b_col,128,line_w0);


  ImVec2 dpad_points[12]={
    //Up
    {dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},
    {dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz1}, 
    {dpad_pos[0]+dpad_sz0,dpad_pos[1]+dpad_sz1}, 
    //right
    {dpad_pos[0]+dpad_sz0,dpad_pos[1]+dpad_sz0}, 
    {dpad_pos[0]+dpad_sz1,dpad_pos[1]+dpad_sz0}, 
    {dpad_pos[0]+dpad_sz1,dpad_pos[1]-dpad_sz0}, 
    //Down
    {dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},
    {dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz1}, 
    {dpad_pos[0]-dpad_sz0,dpad_pos[1]-dpad_sz1}, 
    //left
    {dpad_pos[0]-dpad_sz0,dpad_pos[1]-dpad_sz0}, 
    {dpad_pos[0]-dpad_sz1,dpad_pos[1]-dpad_sz0}, 
    {dpad_pos[0]-dpad_sz1,dpad_pos[1]+dpad_sz0}, 
  };
  ImDrawList_AddPolyline(dl,dpad_points,12,line_color2,true,line_w1);
  ImDrawList_AddPolyline(dl,dpad_points,12,line_color,true,line_w0);
  
  if(down) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]+dpad_sz1},sel_color,0,ImDrawCornerFlags_None);
  if(up)   ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]-dpad_sz1},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},sel_color,0,ImDrawCornerFlags_None);

  if(left) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz1,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawCornerFlags_None);
  if(right)ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz1,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawCornerFlags_None);

  char * button_name[] ={"Start", "Hold", "Turbo", "Select"};
  int num_buttons =  sizeof(button_name)/sizeof(button_name[0]);
  int button_x_off = button_padding+win_x;
  int button_w = dpad_sz1*2+dpad_pos[0]-dpad_sz1-button_padding-win_x;
  int button_y = win_y+win_h-button_h-button_padding;
  typedef struct{const char* button_name; float x; float width;}button_row_t;
  button_row_t row[]={
    {"Select" , button_x_off,button_w*0.67-button_padding},
    {"Hold"  , button_x_off+button_w*0.67,button_w*0.33},
    {"Turbo", b_pos[0]-button_r,button_w*0.33},
    {"Start" , b_pos[0]-button_r+button_w*0.33+button_padding,button_w*0.67-button_padding},
  };
  int hold_button =1;
  int turbo_button =2; 
  if(gui_state.settings.touch_controls_show_turbo==false){
    row[0].width = button_w;
    row[1].width = 0; 
    row[2].width = 0; 
    row[3].width = button_w; 
    row[3].x = row[2].x;
    gui_state.touch_controls.hold_toggle=gui_state.touch_controls.turbo_toggle=0;
    gui_state.touch_controls.last_hold_toggle_presses= gui_state.touch_controls.last_turbo_toggle_presses=0;
  }

  for(int b=0;b<sizeof(row)/sizeof(row[0]);++b){                                           
    int state = 0;   
    int x_min = row[b].x;
    int x_max = row[b].x+row[b].width;
    if(row[b].width==0)continue;
    bool pressed = false;
    for(int i = 0;i<p;++i){
      int dx = points[i][0]-x_min;
      int dy = points[i][1]-button_y;
      if(dx>=-(x_max-x_min)*0.05 && dx<=(x_max-x_min)*1.05 && dy>=0 && dy<=button_h ){
        button_press|=1<<(b+6); 
        pressed=true;
        ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawCornerFlags_None);  
      }
    }
    ImU32 col = line_color;
    if(b==turbo_button&&(pressed || gui_state.touch_controls.turbo_toggle))col=turbo_color;
    if(b==hold_button&&(pressed || gui_state.touch_controls.hold_toggle))col=hold_color;
    if(SB_BFE(gui_state.touch_controls.hold_toggle,b+6,1))col = hold_color;
    if(SB_BFE(gui_state.touch_controls.turbo_toggle,b+6,1))col = turbo_color;
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawCornerFlags_None,line_w1);  
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},col,0,ImDrawCornerFlags_None,line_w0);  
  }
  button_y=win_y+button_padding;
  if(emu_state.system!=SYSTEM_GB){
    button_row_t row[]={
      {"L" , button_x_off,button_w},
      {"R"  ,b_pos[0]-button_r,button_w},
    };

    for(int b=0;b<sizeof(row)/sizeof(row[0]);++b){                                           
      int state = 0;   
      int x_min = row[b].x;; 
      int x_max = row[b].x+row[b].width;
      for(int i = 0;i<p;++i){
        int dx = points[i][0]-x_min;
        int dy = points[i][1]-button_y;
        if(dx>=-(x_max-x_min)*0.05 && dx<=(x_max-x_min)*1.05 && dy>=0 && dy<=button_h ){
          button_press|=1<<(b+4); 
          ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawCornerFlags_None);  
        }
      }
       ImU32 col = line_color;
      if(SB_BFE(gui_state.touch_controls.hold_toggle,b+4,1))col = hold_color;
      if(SB_BFE(gui_state.touch_controls.turbo_toggle,b+4,1))col = turbo_color;
      ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawCornerFlags_None,line_w1);  
      ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},col,0,ImDrawCornerFlags_None,line_w0);  
    }
  }


  bool hold = SB_BFE(button_press,7,1);
  bool turbo = SB_BFE(button_press,8,1);
  state->joy.inputs[SE_KEY_START] += SB_BFE(button_press,9,1);

  if(hold)turbo=false;

  uint32_t hold_mask = hold? button_press:0; 
  uint32_t turbo_mask = turbo? button_press: 0;

  //Prevent the hold and turbo buttons from being held or turbo'd
  uint32_t valid_hold_turbo_mask = ~((1<<7)|(1<<8));
  hold_mask&=valid_hold_turbo_mask;
  turbo_mask&=valid_hold_turbo_mask;

  gui_state.touch_controls.hold_toggle^= hold_mask&~gui_state.touch_controls.last_hold_toggle_presses;
  gui_state.touch_controls.turbo_toggle^= turbo_mask&~gui_state.touch_controls.last_turbo_toggle_presses;
  gui_state.touch_controls.turbo_toggle&= ~(hold_mask&~gui_state.touch_controls.last_hold_toggle_presses);
  gui_state.touch_controls.hold_toggle&= ~(turbo_mask&~gui_state.touch_controls.last_turbo_toggle_presses);

  if(!hold&&!turbo){
    gui_state.touch_controls.turbo_toggle&= ~(button_press);
    gui_state.touch_controls.hold_toggle&= ~(button_press);
  }

  gui_state.touch_controls.last_hold_toggle_presses = hold_mask;
  gui_state.touch_controls.last_turbo_toggle_presses = turbo_mask;

  if(turbo_t>0.5)button_press|=gui_state.touch_controls.turbo_toggle;
  button_press|=gui_state.touch_controls.hold_toggle;

  state->joy.inputs[SE_KEY_LEFT]  += left;
  state->joy.inputs[SE_KEY_RIGHT] += right;
  state->joy.inputs[SE_KEY_UP]    += up;
  state->joy.inputs[SE_KEY_DOWN]  += down;

  state->joy.inputs[SE_KEY_A] += SB_BFE(button_press,0,1);
  state->joy.inputs[SE_KEY_B] += SB_BFE(button_press,1,1);
  state->joy.inputs[SE_KEY_X] += SB_BFE(button_press,2,1);
  state->joy.inputs[SE_KEY_Y] += SB_BFE(button_press,3,1);

  state->joy.inputs[SE_KEY_L] += SB_BFE(button_press,4,1);
  state->joy.inputs[SE_KEY_R] += SB_BFE(button_press,5,1);
  state->joy.inputs[SE_KEY_SELECT] += SB_BFE(button_press,6,1);
}
void se_update_key_turbo(sb_emu_state_t *state){
  double t = se_time()*15;
  bool turbo_press = (t-(int)t)>0.5;
  if(turbo_press){
    state->joy.inputs[SE_KEY_A]+=state->joy.inputs[SE_KEY_TURBO_A];
    state->joy.inputs[SE_KEY_B]+=state->joy.inputs[SE_KEY_TURBO_B];
    state->joy.inputs[SE_KEY_X]+=state->joy.inputs[SE_KEY_TURBO_X];
    state->joy.inputs[SE_KEY_Y]+=state->joy.inputs[SE_KEY_TURBO_Y];
    state->joy.inputs[SE_KEY_L]+=state->joy.inputs[SE_KEY_TURBO_L];
    state->joy.inputs[SE_KEY_R]+=state->joy.inputs[SE_KEY_TURBO_R];
  }
}
void se_update_solar_sensor(sb_emu_state_t*state){
  static double last_t =0; 
  double dt = se_time()-last_t;

  state->joy.solar_sensor-=state->joy.inputs[SE_KEY_SOLAR_M]*dt*0.5;
  state->joy.solar_sensor+=state->joy.inputs[SE_KEY_SOLAR_P]*dt*0.5;
  if(state->joy.solar_sensor>1.0)state->joy.solar_sensor=1.0;
  if(state->joy.solar_sensor<0.0)state->joy.solar_sensor=0.0;
  last_t = se_time();
}
void se_text_centered_in_box(ImVec2 p, ImVec2 size, const char* text){
  ImVec2 curr_cursor;
  igGetCursorPos(&curr_cursor);
  ImVec2 backup_cursor = curr_cursor;
  ImVec2 curr_cursor_screen;
  igGetCursorScreenPos(&curr_cursor_screen);

  curr_cursor.x+=p.x;
  curr_cursor.y+=p.y;
  curr_cursor_screen.x+=p.x;
  curr_cursor_screen.y+=p.y;
  ImU32 color = igColorConvertFloat4ToU32(igGetStyle()->Colors[ImGuiCol_ButtonActive]);
  ImDrawList_AddRectFilled(igGetWindowDrawList(),curr_cursor_screen,(ImVec2){curr_cursor_screen.x+size.x,curr_cursor_screen.y+size.y},color,0,ImDrawCornerFlags_None);

  ImVec2 text_sz; 
  igCalcTextSize(&text_sz, text,NULL,0,0);

  curr_cursor.x+=(size.x-text_sz.x)*0.5;
  curr_cursor.y+=(size.y-text_sz.y)*0.5;
  igSetCursorPos(curr_cursor);
  se_text(text);
  igSetCursorPos(backup_cursor);
}
//CPU: 73%->48
bool se_selectable_with_box(const char * first_label, const char* second_label, const char* box, bool force_hover, int reduce_width){
  ImVec2 win_min,win_sz,win_max;
  win_min.x=0;
  win_min.y=0;                                  // content boundaries min (roughly (0,0)-Scroll), in window coordinates
  igGetWindowSize(&win_sz);
  win_min.y+=igGetScrollY();
  win_max.x = win_min.x+win_sz.x; 
  win_max.y = win_min.y+win_sz.y; 

  int item_height = 40; 
  int padding = 4; 

  float disp_y_min = igGetCursorPosY();
  float disp_y_max = disp_y_min+item_height+padding*2;
  //Early out if not visible (helps for long lists)
  if(disp_y_max<win_min.y||disp_y_min>win_max.y){
    igSetCursorPosY(disp_y_max);
    return false;
  }

#ifdef UNICODE_GUI
  first_label= (const char*)utf8proc_NFC((const utf8proc_uint8_t *)first_label);
  second_label= (const char*)utf8proc_NFC((const utf8proc_uint8_t *)second_label);
#endif
  int box_h = item_height-padding*2;
  int box_w = box_h;
  bool clicked = false;
  igPushIDStr(second_label);
  ImVec2 curr_pos; 
  igGetCursorPos(&curr_pos);
  curr_pos.y+=padding; 
  curr_pos.x+=padding;
  if(igSelectableBool("",force_hover,ImGuiSelectableFlags_None, (ImVec2){igGetWindowContentRegionWidth()-reduce_width,item_height}))clicked=true;
  ImVec2 next_pos;
  igGetCursorPos(&next_pos);
  igSetCursorPos(curr_pos);
  ImVec2 rect_p = (ImVec2){0,0};
  se_text_centered_in_box((ImVec2){0,0}, (ImVec2){box_w,box_h},box);
  igSetCursorPosY(curr_pos.y-padding*0.5);
  igSetCursorPosX(curr_pos.x+box_w);
  igBeginChildFrame(igGetIDStr(first_label),(ImVec2){igGetWindowContentRegionWidth()-box_w-padding-reduce_width,item_height},ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse|ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoInputs);
  se_text(first_label);
  se_text_disabled(second_label);
  igEndChildFrame();
  igSetCursorPos(next_pos);
  igPopID();
#ifdef UNICODE_GUI
  free((void*)first_label);
  free((void*)second_label);
#endif
  return clicked; 
}
#ifdef PLATFORM_ANDROID
void se_android_open_file_picker(){
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;

  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  if ( nResult != JNI_ERR ) 
  {
      // Retrieves NativeActivity.
      jobject nativeActivity = activity->clazz;
      jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity );
      jmethodID MethodShowKeyboard = (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "openFile", "()V" );
      (*pJNIEnv)->CallVoidMethod(pJNIEnv, nativeActivity, MethodShowKeyboard );
      

      // Finished with the JVM.
      (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }
}
void se_android_request_permissions(){
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;

  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  if ( nResult != JNI_ERR ) 
  {
      // Retrieves NativeActivity.
      jobject nativeActivity = activity->clazz;
      jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity );
      jmethodID MethodShowKeyboard = (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "requestPermissions", "()V" );
      (*pJNIEnv)->CallVoidMethod(pJNIEnv, nativeActivity, MethodShowKeyboard );
      

      // Finished with the JVM.
      (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }
}
#endif
#ifdef EMSCRIPTEN
void se_download_emscripten_file(const char * path){
  const char * base,*file, *ext;
  sb_breakup_path(path,&base,&file,&ext);
  char name[SB_FILE_PATH_SIZE];
  snprintf(name,SB_FILE_PATH_SIZE,"%s.%s",file,ext);
  size_t data_size;
  uint8_t*data = sb_load_file_data(path,&data_size);

  EM_ASM_({
    name = $0;
    data = $1;
    data_size = $2;
    const a = document.createElement('a');
    a.style = 'display:none';
    document.body.appendChild(a);
    const view = new Uint8Array(Module.HEAPU8.buffer, data, data_size);
    const blob = new Blob([view], {
        type: 'octet/stream'
    });
    const url = window.URL.createObjectURL(blob);
    a.href = url;
    const filename = UTF8ToString(name);
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, name, data, data_size);
}
#endif 

int file_sorter (const void * a, const void * b) {
  tinydir_file*af = (tinydir_file*)a;
  tinydir_file*bf = (tinydir_file*)b;
  if(af->is_dir!=bf->is_dir)return af->is_dir?-1:1;
  int i=0;
  for(i = 0; af->path[i];++i){
    if(af->path[i]!=bf->path[i]){
      char ac = af->path[i];
      char bc = bf->path[i];
      if(ac>='A'&&ac<='Z')ac=ac-'A'+'a';
      if(bc>='A'&&bc<='Z')bc=bc-'A'+'a';
      if(ac!=bc)return ac>bc?1:-1;
    }
  }
  return bf->path[i]=='\0'?0:-1;
}
void se_load_rom_overlay(bool visible){
  static bool last_visible = false;
  if(visible==false){
#if defined(EMSCRIPTEN)
    if(last_visible==true){
      EM_ASM({
        var input = document.getElementById('fileInput');
        input.style.visibility= "hidden";
      });
    }
#endif
    last_visible=false;
    return;
  }
  last_visible=true;

  ImVec2 w_pos, w_size;
  igGetWindowPos(&w_pos);
  igGetWindowSize(&w_size);
  w_size.x/=se_dpi_scale();
  w_size.y/=se_dpi_scale();
  igSetNextWindowSize((ImVec2){w_size.x,0},ImGuiCond_Always);
  igSetNextWindowPos((ImVec2){w_pos.x,w_pos.y},ImGuiCond_Always,(ImVec2){0,0});
  igSetNextWindowBgAlpha(SE_TRANSPARENT_BG_ALPHA);
  igBegin(se_localize_and_cache(ICON_FK_FILE_O " Load Game"),&gui_state.overlay_open,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
  
  float list_y_off = igGetWindowHeight(); 
  bool hover = false;
  #ifdef EMSCRIPTEN
    int x, y, w,  h;
    ImVec2 win_p,win_max;
    igGetWindowContentRegionMin(&win_p);
    igGetWindowContentRegionMax(&win_max);
    x = win_p.x;
    y = win_p.y;
    w = win_max.x-win_p.x;
    h = win_max.y-win_p.y;
    y+=w_pos.y;
      char * new_path = (char*)EM_ASM_INT({
      var input = document.getElementById('fileInput');
      input.style.left = $0 +'px';
      input.style.top = $1 +'px';
      input.style.width = $2 +'px';
      input.style.height= $3 +'px';
      input.style.visibility = 'visible';
      input = document.getElementById('fileInput');
      if(input.value!= ''){
        console.log(input.value);
        var reader= new FileReader();
        var file = input.files[0];
        function print_file(e){
            var result=reader.result;
            const uint8_view = new Uint8Array(result);
            var out_file = '/offline/'+filename;
            FS.writeFile(out_file, uint8_view);
            FS.syncfs(function (err) {});
            var input_stage = document.getElementById('fileStaging');
            input_stage.value = out_file;
        }
        reader.addEventListener('loadend', print_file);
        reader.readAsArrayBuffer(file);
        var filename = file.name;
        input.value = '';
      }
      var input_stage = document.getElementById('fileStaging');
      var ret_path = '';
      if(input_stage.value !=''){
        ret_path = input_stage.value;
        input_stage.value = '';
      }
      var sz = lengthBytesUTF8(ret_path)+1;
      var string_on_heap = _malloc(sz);
      stringToUTF8(ret_path, string_on_heap, sz);
      return string_on_heap;
    },x,y,w,h);

    if(new_path[0])se_load_rom(new_path);
    free(new_path);
    hover = (bool)EM_ASM_INT({
      var input = document.getElementById('fileInput');
      return input.matches('#fileInput:hover');
    });
  #endif 
  const char * prompt1 = "Load ROM from file (.gb, .gbc, .gba, .zip)";
  const char * prompt2= "You can also drag & drop a ROM to load it";
  #if defined(PLATFORM_ANDROID) || defined(PLATFORM_IOS)
    prompt2 = "";
  #endif
  #ifdef EMSCRIPTEN
  prompt1 = "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) from file";
  prompt2 = "You can also drag & drop a ROM/save file to load it";
  #endif

  if(gui_state.file_browser.state!=SE_FILE_BROWSER_OPEN){
    if(se_selectable_with_box(prompt1,prompt2,ICON_FK_FOLDER_OPEN,hover,0)){
      #ifdef USE_BUILT_IN_FILEBROWSER
        gui_state.file_browser.state=SE_FILE_BROWSER_OPEN;
      #endif
      #ifdef USE_TINY_FILE_DIALOGS
        if(tinyfd_openFileDialog("tinyfd_query","", sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]),
                                            valid_rom_file_types,NULL,0)){
          gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
        }
        char *outPath= tinyfd_openFileDialog("Open ROM","", sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]),
                                            valid_rom_file_types,NULL,0);
        if (outPath){
            se_load_rom(outPath);
        }
      #endif
      #ifdef PLATFORM_IOS
        gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
        char * out_path= se_ios_open_file_picker(sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]),valid_rom_file_types);
        if(out_path){
          se_load_rom(out_path);
          free(out_path);
        }
      #endif 
    }
  }else{
    if(se_selectable_with_box("Exit File Browser","Go back to recently loaded games",ICON_FK_BAN,hover,0)){
      gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    }
    const char* parent_dir = sb_parent_path(gui_state.file_browser.current_path);
    if(se_selectable_with_box("Go to parent directory",parent_dir,ICON_FK_ARROW_UP,hover,0)){
      strncpy(gui_state.file_browser.current_path, parent_dir, SB_FILE_PATH_SIZE);
    }
  }
  igEnd();
  ImVec2 child_size; 
  child_size.x = w_size.x;
  child_size.y = w_size.y-list_y_off;
  igSetNextWindowSize(child_size,ImGuiCond_Always);
  igSetNextWindowPos((ImVec2){(w_pos.x),list_y_off+w_pos.y},ImGuiCond_Always,(ImVec2){0,0});
  igSetNextWindowBgAlpha(0.9);
  if(gui_state.file_browser.state==SE_FILE_BROWSER_CLOSED){
    igBegin(se_localize_and_cache(ICON_FK_CLOCK_O " Load Recently Played Game"),NULL,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
    int num_entries=0;
    for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
      se_game_info_t *info = gui_state.recently_loaded_games+i;
      if(strcmp(info->path,"")==0)break;
      igPushIDInt(i);
      const char* base, *file_name, *ext; 
      sb_breakup_path(info->path,&base,&file_name,&ext);
      char ext_upper[8]={0};
      for(int i=0;i<7&&ext[i];++i)ext_upper[i]=toupper(ext[i]);
      int reduce_width = 0; 
      #ifdef EMSCRIPTEN
      char save_file_path[SB_FILE_PATH_SIZE];
      snprintf(save_file_path,SB_FILE_PATH_SIZE,"%s/%s.sav",base,file_name);
      bool save_exists = sb_file_exists(save_file_path);
      if(save_exists)reduce_width=85; 
      #endif
      if(se_selectable_with_box(file_name,info->path,ext_upper,false,reduce_width)){
        se_load_rom(info->path);
      }
      #ifdef EMSCRIPTEN
      if(save_exists){
        igSameLine(0,4);
        if(se_button(ICON_FK_DOWNLOAD " Export Save",(ImVec2){reduce_width-4,40}))se_download_emscripten_file(save_file_path);
      }
      #endif 
      igSeparator();
      num_entries++;
      igPopID();
    }
    if(num_entries==0)se_text("No recently played games");
    igEnd();
  }else{
    se_file_browser_state_t* file_browse = &gui_state.file_browser;
    igBegin(se_localize_and_cache(ICON_FK_FOLDER_OPEN " Open File From Disk"),NULL,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
    bool update_cache = file_browse->has_cache==false||file_browse->cached_time+5.<se_time()||strncmp(file_browse->cached_path,file_browse->current_path,SB_FILE_PATH_SIZE)!=0;
    if(update_cache){
      strncpy(file_browse->cached_path,file_browse->current_path,SB_FILE_PATH_SIZE);
      file_browse->cached_time=se_time();
      if(file_browse->has_cache){
        if(file_browse->cached_files){
          free(file_browse->cached_files);
          file_browse->cached_files = NULL;
          file_browse->num_cached_files=0;
        }
        tinydir_close(&file_browse->cached_dir);
        file_browse->has_cache=false;
      }
      if(tinydir_open(&file_browse->cached_dir, gui_state.file_browser.current_path)==-1){
        strncpy(gui_state.file_browser.current_path,sb_get_home_path(),SB_FILE_PATH_SIZE);
        if(tinydir_open(&file_browse->cached_dir, gui_state.file_browser.current_path)==-1){
          printf("Error opening %s\n",gui_state.file_browser.current_path);
        }
      }else{
        int max_files = 4096;
        file_browse->cached_files= (tinydir_file*)malloc(sizeof(tinydir_file)*max_files);
        int f = 0; 
        while(file_browse->cached_dir.has_next&&f<max_files){
          tinydir_readfile(&file_browse->cached_dir, &file_browse->cached_files[f]);
          char *ext = file_browse->cached_files[f].extension;
          bool show_item = true; 
          if(!file_browse->cached_files[f].is_dir){
            show_item=false;
            for(int i=0;i<sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]);++i){
              if(sb_path_has_file_ext(file_browse->cached_files[f].path,valid_rom_file_types[i])){show_item=true;break;}
            }
          }else{
            const char* name = file_browse->cached_files[f].name;
            if(strcmp(name,".")==0||strcmp(name,"..")==0)show_item=false;
          }
          if(show_item)++f;
          tinydir_next(&file_browse->cached_dir);
        }
        file_browse->num_cached_files = f;
        qsort(file_browse->cached_files,f,sizeof(tinydir_file),file_sorter);
      }
      file_browse->has_cache=true;
    }
    for(int f = 0;f<file_browse->num_cached_files;++f) {
      const char *ext = ICON_FK_FOLDER_OPEN;
      if (!file_browse->cached_files[f].is_dir) {
        const char* base, *file;
        sb_breakup_path(file_browse->cached_files[f].path, &base, &file, &ext);
      }
      if (se_selectable_with_box(file_browse->cached_files[f].name, file_browse->cached_files[f].path, ext, false, 0)) {
        if (file_browse->cached_files[f].is_dir)
          strncpy(gui_state.file_browser.current_path, file_browse->cached_files[f].path, SB_FILE_PATH_SIZE);
        else se_load_rom(file_browse->cached_files[f].path);
      }
    }
    igEnd();
  }
  return;
}
#ifdef USE_SDL
static void se_poll_sdl(){
  SDL_Event sdlEvent;
  se_controller_state_t *cont = &gui_state.controller;
  cont->key.last_bind_activitiy=-1;
  cont->analog.last_bind_activitiy=-1;
  while( SDL_PollEvent( &sdlEvent ) ) {
      switch( sdlEvent.type ) {
      case SDL_JOYDEVICEADDED:{
        if(!cont->sdl_joystick){
          se_set_new_controller(cont,sdlEvent.jdevice.which);
        }
        break;
      }
      case SDL_JOYDEVICEREMOVED:
        if(cont->sdl_joystick==SDL_JoystickFromInstanceID(sdlEvent.jdevice.which)){
          SDL_JoystickClose(cont->sdl_joystick);
          SDL_GameControllerClose(cont->sdl_gc);
          cont->sdl_joystick = NULL;
          cont->sdl_gc = NULL;
        }
        break;
      case SDL_JOYHATMOTION:{
        int value = 0;
        if(sdlEvent.jhat.value==SDL_HAT_UP)value = SDL_HAT_UP;
        if(sdlEvent.jhat.value==SDL_HAT_DOWN)value = SDL_HAT_DOWN;
        if(sdlEvent.jhat.value==SDL_HAT_LEFT)value = SDL_HAT_LEFT;
        if(sdlEvent.jhat.value==SDL_HAT_RIGHT)value = SDL_HAT_RIGHT;
        if(value){
          value |= sdlEvent.jhat.hat<<8;
          value |= SE_HAT_MASK;
          cont->key.last_bind_activitiy = value;
        }
        }break;
      case SDL_JOYBUTTONDOWN:
        if(SDL_JoystickFromInstanceID(sdlEvent.jbutton.which)==cont->sdl_joystick)
          cont->key.last_bind_activitiy = sdlEvent.jbutton.button;
        break;
      case SDL_CONTROLLERBUTTONDOWN:
      case SDL_CONTROLLERBUTTONUP:
        //OnControllerButton( sdlEvent.cbutton );
        break;
      case SDL_JOYAXISMOTION:
        if(SDL_JoystickFromInstanceID(sdlEvent.jaxis.which)==cont->sdl_joystick){
          float v = sdlEvent.jaxis.value/32768.f;
          if((v>0.3)||(v<-0.3&&v>-0.6))
            cont->analog.last_bind_activitiy = sdlEvent.jaxis.axis;  

          if(v>0.3&&v<0.6)cont->key.last_bind_activitiy = sdlEvent.jaxis.axis|SE_JOY_POS_MASK;
          if(v<-0.3&&v>-0.6)cont->key.last_bind_activitiy = sdlEvent.jaxis.axis|SE_JOY_NEG_MASK;
        }
        break;      
      }
  }
  if(cont->sdl_joystick){
    for(int k= 0; k<SE_NUM_KEYBINDS;++k){
      int key = cont->key.bound_id[k];
      if(key==-1)continue;
      bool val = false; 
      bool is_hat = key&(SE_HAT_MASK);
      bool is_joy = key&(SE_JOY_NEG_MASK|SE_JOY_POS_MASK);
      if(is_hat){
        int hat_id = SB_BFE(key,8,8);
        if(hat_id<SDL_JoystickNumHats(cont->sdl_joystick)){
          int hat_value = SDL_JoystickGetHat(cont->sdl_joystick,hat_id);
          int match_value = SB_BFE(key,0,8);
          if(match_value==SDL_HAT_UP)val |= (hat_value==SDL_HAT_UP)|(hat_value==SDL_HAT_RIGHTUP)|(hat_value==SDL_HAT_LEFTUP);
          if(match_value==SDL_HAT_DOWN)val |= (hat_value==SDL_HAT_DOWN)|(hat_value==SDL_HAT_RIGHTDOWN)|(hat_value==SDL_HAT_LEFTDOWN);
          if(match_value==SDL_HAT_LEFT)val |= (hat_value==SDL_HAT_LEFT)|(hat_value==SDL_HAT_LEFTDOWN)|(hat_value==SDL_HAT_LEFTUP);
          if(match_value==SDL_HAT_RIGHT)val |= (hat_value==SDL_HAT_RIGHT)|(hat_value==SDL_HAT_RIGHTDOWN)|(hat_value==SDL_HAT_RIGHTUP);
        }
      }else if(is_joy){
        int joy_id = SB_BFE(key,0,16);
        if(joy_id<SDL_JoystickNumAxes(cont->sdl_joystick)){
          float v = SDL_JoystickGetAxis(cont->sdl_joystick,joy_id)/32768.f;
          val = false; 
          if(key&SE_JOY_NEG_MASK)val|= v<-0.3;
          if(key&SE_JOY_POS_MASK)val|= v>0.3;
        }
      }else{
        if(key<SDL_JoystickNumButtons(cont->sdl_joystick)){
          val = SDL_JoystickGetButton(cont->sdl_joystick,key);
        }
      }
      
      cont->key.value[k] = val;
    }
    for(int a= 0; a<SE_NUM_ANALOGBINDS;++a){
      int axis= cont->analog.bound_id[a];
      float val = 0; 
      if(axis<SDL_JoystickNumAxes(cont->sdl_joystick)&&axis!=-1){
        val = SDL_JoystickGetAxis(cont->sdl_joystick,axis)/32768.f;
      }
      cont->analog.value[a]= val;
    }
    float intensity= emu_state.joy.rumble*65000;
    SDL_JoystickRumble(cont->sdl_joystick, intensity, intensity, 100);

    for(int i=0;i<SE_NUM_KEYBINDS;++i)emu_state.joy.inputs[i]  += cont->key.value[i]>0.5;

    emu_state.joy.inputs[SE_KEY_LEFT]  += cont->analog.value[SE_ANALOG_LEFT_RIGHT]<-0.3;
    emu_state.joy.inputs[SE_KEY_RIGHT] += cont->analog.value[SE_ANALOG_LEFT_RIGHT]> 0.3;
    emu_state.joy.inputs[SE_KEY_UP]   += cont->analog.value[SE_ANALOG_UP_DOWN]<-0.3;
    emu_state.joy.inputs[SE_KEY_DOWN] += cont->analog.value[SE_ANALOG_UP_DOWN]>0.3;

    emu_state.joy.inputs[SE_KEY_L]  += cont->analog.value[SE_ANALOG_L]>0.1;
    emu_state.joy.inputs[SE_KEY_R]  += cont->analog.value[SE_ANALOG_R]>0.1;
  }
}
#endif
void se_update_frame() {
  if(emu_state.run_mode == SB_MODE_RESET){
    se_reset_core();
    emu_state.run_mode = SB_MODE_RUN;
  }
  static unsigned frames_since_last_save = 0; 
  frames_since_last_save++;
  if(frames_since_last_save>10){
    bool saved = se_sync_save_to_disk();
    if(saved){
      frames_since_last_save=0;
      se_emscripten_flush_fs();
    }
  }

  emu_state.screen_ghosting_strength = gui_state.settings.ghosting;
  const int frames_per_rewind_state = 8; 
  if(emu_state.run_mode==SB_MODE_RUN||emu_state.run_mode==SB_MODE_STEP||emu_state.run_mode==SB_MODE_REWIND){
    emu_state.frame=0;
    int max_frames_per_tick =2+ emu_state.step_frames;

    emu_state.render_frame = true;

    static double simulation_time = -1;
    static double display_time = 0;
    if(emu_state.step_frames==0)emu_state.step_frames=1;

    double sim_fps= se_get_sim_fps();
    double sim_time_increment = 1./sim_fps/emu_state.step_frames;
    bool unlocked_mode = emu_state.step_frames<0;
    double curr_time = se_time();
    if(fabs(curr_time-simulation_time)>0.5||emu_state.run_mode==SB_MODE_PAUSE)simulation_time = curr_time-sim_time_increment;
    if(gui_state.test_runner_mode)unlocked_mode=true;
    if(unlocked_mode){
      sim_time_increment=0;
      max_frames_per_tick=1000;
      simulation_time=curr_time+1./50.;
    }
    while(max_frames_per_tick--){
      double error = curr_time-simulation_time;
      // On steps emulate all frames, but only render the last frame of the step
      // and don't allow screen ghosting
      if(emu_state.run_mode==SB_MODE_STEP){
        emu_state.render_frame = max_frames_per_tick==0;
        emu_state.screen_ghosting_strength=0; 
      }else{
        if(unlocked_mode){
          if(simulation_time<curr_time&&emu_state.frame){break;}
        }else{
          if(emu_state.frame==0&&simulation_time>curr_time)break;
          if(emu_state.frame&&curr_time-simulation_time<sim_time_increment*0.8){break;}
        }
      }
      if(emu_state.run_mode==SB_MODE_REWIND){
        se_rewind_state_single_tick(&core, &rewind_buffer);
        emu_state.render_frame = true;
        se_emulate_single_frame();
        se_emulate_single_frame();
        simulation_time+=sim_time_increment*2;
      }else{
        se_emulate_single_frame();
        ++emu_state.frames_since_rewind_push;
        if(emu_state.frames_since_rewind_push>frames_per_rewind_state-1 ){
          se_push_rewind_state(&core,&rewind_buffer);
          emu_state.frames_since_rewind_push=0;
        }
        simulation_time+=sim_time_increment;
      }
      emu_state.frame++;
      emu_state.render_frame = false;
      curr_time = se_time();
      if(emu_state.run_mode==SB_MODE_PAUSE)break;

    }
  }
  if(emu_state.run_mode == SB_MODE_STEP) emu_state.run_mode = SB_MODE_PAUSE; 
  bool mute = emu_state.run_mode != SB_MODE_RUN;
  emu_state.prev_frame_joy = emu_state.joy; 
  se_reset_joy(&emu_state.joy);
  se_draw_emulated_system_screen(false);
  if(emu_state.run_mode==SB_MODE_PAUSE)emu_state.frame = 0; 
  if(emu_state.run_mode==SB_MODE_REWIND)emu_state.frame = - emu_state.frame*frames_per_rewind_state;
  for(int i=0;i<SAPP_MAX_TOUCHPOINTS;++i){
    if(gui_state.touch_points[i].active)gui_state.last_touch_time = se_time();
  }
}
void se_imgui_theme()
{
  ImVec4* colors = igGetStyle()->Colors;
  colors[ImGuiCol_Text]                   = (ImVec4){1.00f, 1.00f, 1.00f, 1.00f};
  colors[ImGuiCol_TextDisabled]           = (ImVec4){0.6f, 0.6f, 0.6f, 0.5f};
  colors[ImGuiCol_WindowBg]               = (ImVec4){0.14f, 0.14f, 0.14f, 1.00f};
  colors[ImGuiCol_ChildBg]                = (ImVec4){0.14f, 0.14f, 0.14f, 0.40f};
  colors[ImGuiCol_PopupBg]                = (ImVec4){0.19f, 0.19f, 0.19f, 0.92f};
  colors[ImGuiCol_Border]                 = (ImVec4){0.1f, 0.1f, 0.1f, 1.0f};
  colors[ImGuiCol_BorderShadow]           = (ImVec4){0.00f, 0.00f, 0.00f, 0.24f};
  colors[ImGuiCol_FrameBg]                = (ImVec4){0.2f, 0.2f, 0.2f, 0.8f};
  colors[ImGuiCol_FrameBgHovered]         = (ImVec4){0.1f, 0.1f, 0.1f, 1.0f};
  colors[ImGuiCol_FrameBgActive]          = (ImVec4){0.29f, 0.29f, 0.29f, 1.00f};
  colors[ImGuiCol_TitleBg]                = (ImVec4){0.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_TitleBgActive]          = (ImVec4){0.06f, 0.06f, 0.06f, 1.00f};
  colors[ImGuiCol_TitleBgCollapsed]       = (ImVec4){0.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_MenuBarBg]              = (ImVec4){0.10f, 0.10f, 0.10f, 1.00f};
  colors[ImGuiCol_ScrollbarBg]            = (ImVec4){0.05f, 0.05f, 0.05f, 0.54f};
  colors[ImGuiCol_ScrollbarGrab]          = (ImVec4){0.34f, 0.34f, 0.34f, 0.54f};
  colors[ImGuiCol_ScrollbarGrabHovered]   = (ImVec4){0.40f, 0.40f, 0.40f, 0.54f};
  colors[ImGuiCol_ScrollbarGrabActive]    = (ImVec4){0.56f, 0.56f, 0.56f, 0.54f};
  colors[ImGuiCol_CheckMark]              = (ImVec4){0.33f, 0.67f, 0.86f, 1.00f};
  colors[ImGuiCol_SliderGrab]             = (ImVec4){0.34f, 0.34f, 0.34f, 0.54f};
  colors[ImGuiCol_SliderGrabActive]       = (ImVec4){0.56f, 0.56f, 0.56f, 0.54f};
  colors[ImGuiCol_Button]                 = (ImVec4){0.25f, 0.25f, 0.25f, 1.00f};
  colors[ImGuiCol_ButtonHovered]          = (ImVec4){0.19f, 0.19f, 0.19f, 0.54f};
  colors[ImGuiCol_ButtonActive]           = (ImVec4){0.4f, 0.4f, 0.4f, 1.00f};
  colors[ImGuiCol_Header]                 = (ImVec4){0.00f, 0.00f, 0.00f, 0.52f};
  colors[ImGuiCol_HeaderHovered]          = (ImVec4){0.00f, 0.00f, 0.00f, 0.36f};
  colors[ImGuiCol_HeaderActive]           = (ImVec4){0.20f, 0.22f, 0.23f, 0.33f};
  colors[ImGuiCol_Separator]              = (ImVec4){0.28f, 0.28f, 0.28f, 0.9f};
  colors[ImGuiCol_SeparatorHovered]       = (ImVec4){0.44f, 0.44f, 0.44f, 0.29f};
  colors[ImGuiCol_SeparatorActive]        = (ImVec4){0.40f, 0.44f, 0.47f, 1.00f};
  colors[ImGuiCol_ResizeGrip]             = (ImVec4){0.28f, 0.28f, 0.28f, 0.29f};
  colors[ImGuiCol_ResizeGripHovered]      = (ImVec4){0.44f, 0.44f, 0.44f, 0.29f};
  colors[ImGuiCol_ResizeGripActive]       = (ImVec4){0.40f, 0.44f, 0.47f, 1.00f};
  colors[ImGuiCol_Tab]                    = (ImVec4){0.00f, 0.00f, 0.00f, 0.52f};
  colors[ImGuiCol_TabHovered]             = (ImVec4){0.14f, 0.14f, 0.14f, 1.00f};
  colors[ImGuiCol_TabActive]              = (ImVec4){0.20f, 0.20f, 0.20f, 0.36f};
  colors[ImGuiCol_TabUnfocused]           = (ImVec4){0.00f, 0.00f, 0.00f, 0.52f};
  colors[ImGuiCol_TabUnfocusedActive]     = (ImVec4){0.14f, 0.14f, 0.14f, 1.00f};
  //colors[ImGuiCol_DockingPreview]         = (ImVec4){0.33f, 0.67f, 0.86f, 1.00f};
  //colors[ImGuiCol_DockingEmptyBg]         = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_PlotLines]              = (ImVec4){0.33f, 0.67f, 0.86f, 1.00f};
  colors[ImGuiCol_PlotLinesHovered]       = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_PlotHistogram]          = (ImVec4){0.33f, 0.67f, 0.86f, 1.00f};
  colors[ImGuiCol_PlotHistogramHovered]   = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_TableHeaderBg]          = (ImVec4){0.00f, 0.00f, 0.00f, 0.52f};
  colors[ImGuiCol_TableBorderStrong]      = (ImVec4){0.00f, 0.00f, 0.00f, 0.52f};
  colors[ImGuiCol_TableBorderLight]       = (ImVec4){0.28f, 0.28f, 0.28f, 0.29f};
  colors[ImGuiCol_TableRowBg]             = (ImVec4){0.00f, 0.00f, 0.00f, 0.00f};
  colors[ImGuiCol_TableRowBgAlt]          = (ImVec4){1.00f, 1.00f, 1.00f, 0.06f};
  colors[ImGuiCol_TextSelectedBg]         = (ImVec4){0.20f, 0.22f, 0.23f, 1.00f};
  colors[ImGuiCol_DragDropTarget]         = (ImVec4){0.33f, 0.67f, 0.86f, 1.00f};
  colors[ImGuiCol_NavHighlight]           = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_NavWindowingHighlight]  = (ImVec4){1.00f, 0.00f, 0.00f, 0.70f};
  colors[ImGuiCol_NavWindowingDimBg]      = (ImVec4){1.00f, 0.00f, 0.00f, 0.20f};
  colors[ImGuiCol_ModalWindowDimBg]       = (ImVec4){1.00f, 0.00f, 0.00f, 0.35f};
  
  if(gui_state.settings.theme == SE_THEME_LIGHT){
    int invert_list[]={
      ImGuiCol_Text,
      ImGuiCol_TextDisabled,
      ImGuiCol_WindowBg,
      ImGuiCol_ChildBg,
      ImGuiCol_PopupBg,
      ImGuiCol_Border,
      ImGuiCol_BorderShadow,
      ImGuiCol_FrameBg,
      ImGuiCol_FrameBgHovered,
      ImGuiCol_FrameBgActive,
      ImGuiCol_TitleBg,
      ImGuiCol_TitleBgActive,
      ImGuiCol_TitleBgCollapsed,
      ImGuiCol_MenuBarBg,
      ImGuiCol_ScrollbarBg,
      ImGuiCol_ScrollbarGrab,
      ImGuiCol_ScrollbarGrabHovered,
      ImGuiCol_ScrollbarGrabActive,
      ImGuiCol_SliderGrab,
      ImGuiCol_SliderGrabActive,
      ImGuiCol_Button,
      ImGuiCol_ButtonHovered,
      ImGuiCol_ButtonActive,
      ImGuiCol_Header,
      ImGuiCol_HeaderHovered,
      ImGuiCol_HeaderActive,
      ImGuiCol_Separator,
      ImGuiCol_SeparatorHovered,
      ImGuiCol_SeparatorActive,
      ImGuiCol_ResizeGrip,
      ImGuiCol_ResizeGripHovered,
      ImGuiCol_ResizeGripActive,
      ImGuiCol_Tab,
      ImGuiCol_TabHovered,
      ImGuiCol_TabActive,
      ImGuiCol_TabUnfocused,
      ImGuiCol_TabUnfocusedActive,
      ImGuiCol_TableHeaderBg,
      ImGuiCol_TableBorderStrong,
      ImGuiCol_TableBorderLight,
      ImGuiCol_TableRowBg,
      ImGuiCol_TableRowBgAlt,
      ImGuiCol_TextSelectedBg,
      ImGuiCol_DragDropTarget,
      ImGuiCol_NavHighlight,
      ImGuiCol_NavWindowingHighlight,
      ImGuiCol_NavWindowingDimBg,
      ImGuiCol_ModalWindowDimBg,
    };
    for(int i=0;i<sizeof(invert_list)/sizeof(invert_list[0]);++i){
      colors[invert_list[i]].x=1.0-colors[invert_list[i]].x;
      colors[invert_list[i]].y=1.0-colors[invert_list[i]].y;
      colors[invert_list[i]].z=1.0-colors[invert_list[i]].z;
    }
  }

  ImGuiStyle* style = igGetStyle();
  style->WindowPadding                     = (ImVec2){8.00f, 8.00f};
  style->FramePadding                      = (ImVec2){5.00f, 2.00f};
  //style->CellPadding                       = (ImVec2){6.00f, 6.00f};
  style->ItemSpacing                       = (ImVec2){6.00f, 6.00f};
  //style->ItemInnerSpacing                  = (ImVec2){6.00f, 6.00f};
  style->TouchExtraPadding                 = (ImVec2){2.00f, 4.00f};
  style->IndentSpacing                     = 25;
  style->ScrollbarSize                     = 15;
  style->GrabMinSize                       = 10;
  style->WindowBorderSize                  = 0;
  style->ChildBorderSize                   = 0;
  style->PopupBorderSize                   = 0;
  style->FrameBorderSize                   = 0;
  style->TabBorderSize                     = 1;
  style->WindowRounding                    = 0;
  style->ChildRounding                     = 4;
  style->FrameRounding                     = 0;
  style->PopupRounding                     = 0;
  style->ScrollbarRounding                 = 9;
  style->GrabRounding                      = 3;
  style->LogSliderDeadzone                 = 4;
  style->TabRounding                       = 4;
  style->ButtonTextAlign = (ImVec2){0.5,0.5};

  if(gui_state.settings.theme == SE_THEME_BLACK){
    int black_list[]={
      ImGuiCol_WindowBg,
      ImGuiCol_ChildBg,
      ImGuiCol_PopupBg,
      //ImGuiCol_FrameBg,
      ImGuiCol_TitleBg,
      ImGuiCol_MenuBarBg,
      //ImGuiCol_ScrollbarBg,
    };
    colors[ImGuiCol_Button]                 = (ImVec4){0.18f, 0.18f, 0.18f, 1.00f};
    colors[ImGuiCol_FrameBg]                = (ImVec4){0.1f, 0.1f, 0.1f, 0.8f};
    colors[ImGuiCol_ScrollbarBg]                = (ImVec4){0.1f, 0.1f, 0.1f, 0.6f};

    for(int i=0;i<sizeof(black_list)/sizeof(black_list[0]);++i){
      colors[black_list[i]].x=0;
      colors[black_list[i]].y=0;
      colors[black_list[i]].z=0;
    }
  
  }

}
#if defined(EMSCRIPTEN)
  //Setup the offline file system
  EM_JS(void, em_init_fs, (),{
      // Make a directory other than '/'
      FS.mkdir('/offline');
      // Then mount with IDBFS type
      FS.mount(IDBFS, {}, '/offline');
      // Then sync
      FS.syncfs(true, function (err) {
        Module.ccall('se_load_settings');
      });
  });
  #endif
#ifdef USE_SDL
int se_get_sdl_key_bind(SDL_GameController* gc, int button){
  SDL_GameControllerButtonBind bind = SDL_GameControllerGetBindForButton(gc, button);
  if(bind.bindType==SDL_CONTROLLER_BINDTYPE_HAT){
    int hat_id = bind.value.hat.hat;
    int hat_mask = bind.value.hat.hat_mask;
    int mask = 0;
    if(hat_mask&SDL_HAT_UP)mask = SDL_HAT_UP;
    if(hat_mask&SDL_HAT_DOWN)mask = SDL_HAT_DOWN;
    if(hat_mask&SDL_HAT_LEFT)mask = SDL_HAT_LEFT;
    if(hat_mask&SDL_HAT_RIGHT)mask = SDL_HAT_RIGHT;
    if(!mask)return -1;
    return SE_HAT_MASK| (hat_id<<8)|mask;
  };
  if(bind.bindType!=SDL_CONTROLLER_BINDTYPE_BUTTON)return -1;
  else return bind.value.button;
}
int se_get_sdl_axis_bind(SDL_GameController* gc, int button){
  SDL_GameControllerButtonBind bind = SDL_GameControllerGetBindForAxis(gc, button);
  if(bind.bindType!=SDL_CONTROLLER_BINDTYPE_AXIS)return -1;
  else return bind.value.axis;
}
//Returns true if loaded successfully
bool se_load_controller_settings(se_controller_state_t * cont){
  if(!cont||!cont->sdl_joystick)return false;
  int32_t bind_map[SE_NUM_BINDS_ALLOC*2];
  char settings_path[SB_FILE_PATH_SIZE];
  snprintf(settings_path,SB_FILE_PATH_SIZE,"%s%s-bindings.bin",se_get_pref_path(),cont->name);
  bool load_old_settings = sb_load_file_data_into_buffer(settings_path,(uint8_t*)bind_map,sizeof(bind_map));
  if(load_old_settings){
    for(int i=0;i<SE_NUM_BINDS_ALLOC;++i){
      cont->key.bound_id[i]=bind_map[i];
      cont->analog.bound_id[i]=bind_map[i+SE_NUM_BINDS_ALLOC];
    }
  }
  return load_old_settings;
}
void se_set_default_controller_binds(se_controller_state_t* cont){
  if(!cont ||!cont->sdl_gc)return; 
  SDL_GameController * gc = cont->sdl_gc;
  SDL_GameControllerUpdate();
  for(int i=0;i<SE_NUM_KEYBINDS;++i)cont->key.bound_id[i]=-1;
  cont->key.bound_id[SE_KEY_A]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_A);
  cont->key.bound_id[SE_KEY_B]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_B);
  cont->key.bound_id[SE_KEY_X]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_X);
  cont->key.bound_id[SE_KEY_Y]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_Y);
  cont->key.bound_id[SE_KEY_L]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_LEFTSHOULDER);
  cont->key.bound_id[SE_KEY_R]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_RIGHTSHOULDER);
  cont->key.bound_id[SE_KEY_UP]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_UP);
  cont->key.bound_id[SE_KEY_DOWN]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_DOWN);
  cont->key.bound_id[SE_KEY_LEFT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_LEFT);
  cont->key.bound_id[SE_KEY_RIGHT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_RIGHT);
  cont->key.bound_id[SE_KEY_START]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_START);
  cont->key.bound_id[SE_KEY_SELECT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_BACK);

  cont->key.bound_id[SE_KEY_EMU_PAUSE] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_GUIDE);
  cont->key.bound_id[SE_KEY_EMU_REWIND] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE1);
  cont->key.bound_id[SE_KEY_EMU_FF_2X] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE2);
  cont->key.bound_id[SE_KEY_EMU_FF_MAX] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE3);

  cont->analog.bound_id[SE_ANALOG_UP_DOWN] = se_get_sdl_axis_bind(gc,SDL_CONTROLLER_AXIS_LEFTY);
  cont->analog.bound_id[SE_ANALOG_LEFT_RIGHT] = se_get_sdl_axis_bind(gc,SDL_CONTROLLER_AXIS_LEFTX);
  cont->analog.bound_id[SE_ANALOG_L] = se_get_sdl_axis_bind(gc,SDL_CONTROLLER_AXIS_TRIGGERLEFT);
  cont->analog.bound_id[SE_ANALOG_R] = se_get_sdl_axis_bind(gc,SDL_CONTROLLER_AXIS_TRIGGERRIGHT);
}
void se_set_new_controller(se_controller_state_t* cont, int index){
  SDL_Joystick*joy = SDL_JoystickOpen(index);
  if(joy==cont->sdl_joystick)return; 
  if(cont->sdl_joystick)SDL_JoystickClose(cont->sdl_joystick);
  if(cont->sdl_gc)SDL_GameControllerClose(cont->sdl_gc);
  cont->sdl_gc = SDL_GameControllerOpen(index);
  SDL_GameControllerUpdate();
  cont->sdl_joystick = joy; 
  if(cont->sdl_joystick==NULL)return;
  strncpy(cont->name, SDL_JoystickName(cont->sdl_joystick),sizeof(cont->name));
  SDL_JoystickGetGUIDString(SDL_JoystickGetGUID(joy), cont->guid, sizeof(cont->guid));

  se_initialize_keybind(&cont->key);
  se_initialize_keybind(&cont->analog);
  if(!se_load_controller_settings(cont))se_set_default_controller_binds(cont);
}
void se_draw_controller_config(gui_state_t* gui){
  se_text(ICON_FK_GAMEPAD " Controllers");
  igSeparator();
  ImGuiStyle* style = igGetStyle();
  se_controller_state_t *cont = &gui->controller;
  const char* cont_name = "No Controller";
  if(cont->sdl_joystick){
    cont_name = SDL_JoystickName(cont->sdl_joystick);
  }
  if(igBeginCombo(se_localize_and_cache("Controller"), se_localize_and_cache(cont_name), ImGuiComboFlags_None)){
    {
      bool is_selected=cont->sdl_joystick==NULL;
      if(igSelectableBool(se_localize_and_cache("No Controller"),is_selected,ImGuiSelectableFlags_None, (ImVec2){0,0})){
        if(cont->sdl_joystick)SDL_JoystickClose(cont->sdl_joystick);
        if(cont->sdl_gc)SDL_GameControllerClose(cont->sdl_gc);
        cont->sdl_joystick=NULL;
        cont->sdl_gc = NULL;
      }
      if(is_selected)igSetItemDefaultFocus();
    }
    for(int j= 0;j<SDL_NumJoysticks();++j){
      bool is_selected=false;
      const char* jname = SDL_JoystickNameForIndex(j);
      if(igSelectableBool(jname,is_selected,ImGuiSelectableFlags_None, (ImVec2){0,0})){
        se_set_new_controller(cont,j);
      }
      if(is_selected)igSetItemDefaultFocus();
    }
    igEndCombo();
  }
  if(!cont->sdl_joystick)return;
  bool modified = se_handle_keybind_settings(SE_BIND_KEY,&(cont->key));
  modified |= se_handle_keybind_settings(SE_BIND_ANALOG,&(cont->analog));
  if(se_button("Reset Default Controller Bindings",(ImVec2){0,0})){
    se_set_default_controller_binds(cont);
    modified=true;
  }
  if(modified){
    int32_t bind_map[SE_NUM_BINDS_ALLOC*2];
    for(int i=0;i<SE_NUM_BINDS_ALLOC;++i){
      bind_map[i]= cont->key.bound_id[i];
      bind_map[i+SE_NUM_BINDS_ALLOC]= cont->analog.bound_id[i];
    }
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%s%s-bindings.bin",se_get_pref_path(),cont_name);
    sb_save_file_data(settings_path,(uint8_t*)bind_map,sizeof(bind_map));
    se_emscripten_flush_fs();
  }

  if(SDL_JoystickHasRumble(cont->sdl_joystick)){se_text("Rumble Supported");
  }else se_text("Rumble Not Supported");
}
#endif 
void se_reset_default_gb_palette(){
  uint8_t palette[4*3] = { 0x81,0x8F,0x38,0x64,0x7D,0x43,0x56,0x6D,0x3F,0x31,0x4A,0x2D };
  for(int i=0;i<4;++i){
    gui_state.settings.gb_palette[i]=palette[i*3]|(palette[i*3+1]<<8)|(palette[i*3+2]<<16);
  }
}
void se_capture_state_slot(int slot){
  se_capture_state(&core, save_states+slot);
  char save_state_path[SB_FILE_PATH_SIZE];
  snprintf(save_state_path,SB_FILE_PATH_SIZE,"%s.slot%d.state.png",emu_state.save_data_base_path,slot);
  se_save_state_to_disk(save_states+slot,save_state_path);
}
void se_restore_state_slot(int slot){
  if(save_states[slot].valid)se_restore_state(&core, save_states+slot);
}
void se_push_disabled(){
  ImGuiStyle *style = igGetStyle();
  igPushStyleColorVec4(ImGuiCol_Text, style->Colors[ImGuiCol_TextDisabled]);
  igPushItemFlag(ImGuiItemFlags_Disabled, true);
}
void se_pop_disabled(){
   igPopStyleColor(1);
   igPopItemFlag();
}
void se_draw_menu_panel(){
  ImGuiStyle *style = igGetStyle();
  se_text(ICON_FK_FLOPPY_O " Save States");
  igSeparator();

  int win_w = igGetWindowContentRegionWidth();
  ImDrawList*dl= igGetWindowDrawList();
  if(!emu_state.rom_loaded)se_push_disabled();
  for(int i=0;i<SE_NUM_SAVE_STATES;++i){
    int slot_x = 0;
    int slot_y = i;
    int slot_w = (win_w-style->FramePadding.x)*0.5;
    int slot_h = 64; 
    if(i%2)igSameLine(0,style->FramePadding.x);

    igBeginChildFrame(i+100, (ImVec2){slot_w,slot_h},ImGuiWindowFlags_None);
    ImVec2 screen_p;
    igGetCursorScreenPos(&screen_p);
    int screen_x = screen_p.x;
    int screen_y = screen_p.y;
    int screen_w = 64;
    int screen_h = 64+style->FramePadding.y*2; 
    int button_w = 55; 
    se_text(se_localize_and_cache("Save Slot %d"),i);
    if(se_button(se_localize_and_cache("Capture"),(ImVec2){button_w,0}))se_capture_state_slot(i);
    if(!save_states[i].valid)se_push_disabled();
    if(se_button(se_localize_and_cache("Restore"),(ImVec2){button_w,0}))se_restore_state_slot(i);
    if(!save_states[i].valid)se_pop_disabled();

    if(save_states[i].valid){
      float w_scale = 1.0;
      float h_scale = 1.0;
      if(save_states[i].screenshot_width>save_states[i].screenshot_height){
        h_scale = (float)save_states[i].screenshot_height/(float)save_states[i].screenshot_width;
      }else{
        w_scale = (float)save_states[i].screenshot_width/(float)save_states[i].screenshot_height;
      }
      screen_w*=w_scale;
      screen_h*=h_scale;
      screen_x+=button_w+(slot_w-screen_w-button_w)*0.5;
      screen_y+=(slot_h-screen_h)*0.5-style->FramePadding.y;
   
      se_draw_image(save_states[i].screenshot,save_states[i].screenshot_width,save_states[i].screenshot_height,
                    screen_x*se_dpi_scale(),screen_y*se_dpi_scale(),screen_w*se_dpi_scale(),screen_h*se_dpi_scale(), true);
      if(save_states[i].valid==2){
        igSetCursorScreenPos((ImVec2){screen_x+screen_w*0.5-15,screen_y+screen_h*0.5-15});
        se_button(ICON_FK_EXCLAMATION_TRIANGLE,(ImVec2){30,30});
        se_tooltip("This save state came from an incompatible build. SkyEmu has attempted to recover it, but there may be issues");
      }
    }else{
      screen_h*=0.85;
      screen_x+=button_w+(slot_w-screen_w-button_w)*0.5;
      screen_y+=(slot_h-screen_h)*0.5-style->FramePadding.y;
      ImU32 color = igColorConvertFloat4ToU32(style->Colors[ImGuiCol_MenuBarBg]);
      ImDrawList_AddRectFilled(igGetWindowDrawList(),(ImVec2){screen_x,screen_y},(ImVec2){screen_x+screen_w,screen_y+screen_h},color,0,ImDrawCornerFlags_None);
      ImVec2 anchor;
      igSetCursorScreenPos((ImVec2){screen_x+screen_w*0.5-5,screen_y+screen_h*0.5-5});
      se_text(ICON_FK_BAN);
    }
    igEndChildFrame();
  }
  if(!emu_state.rom_loaded)se_pop_disabled();
  se_text(ICON_FK_DESKTOP " Display Settings");
  igSeparator();
  int v = gui_state.settings.screen_shader;
  igPushItemWidth(-1);
  se_text("Screen Shader");igSameLine(win_w*0.4,0);
  se_combo_str("##Screen Shader",&v,"Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",0);
  gui_state.settings.screen_shader=v;
  v = gui_state.settings.screen_rotation;
  se_text("Screen Rotation");igSameLine(win_w*0.4,0);
  se_combo_str("##Screen Rotation",&v,"0 degrees\00090 degrees\000180 degrees\000270 degrees\0",0);
  gui_state.settings.screen_rotation=v;
  se_text("Color Correction");igSameLine(win_w*0.4,0);
  se_slider_float("##Color Correction",&gui_state.settings.color_correction,0,1.0,"Strength: %.2f");
  int color_correct = gui_state.settings.gba_color_correction_mode;
  se_text("GBA Color Correction Type");igSameLine(win_w*0.6,0);
  se_combo_str("##ColorAlgorithm",&color_correct,"SkyEmu\0Higan\0",0);
  igPopItemWidth();
  gui_state.settings.gba_color_correction_mode=color_correct;
  {
    bool b = gui_state.settings.ghosting;
    se_checkbox("Screen Ghosting", &b);
    gui_state.settings.ghosting=b;
  }
  {
    bool b = gui_state.settings.integer_scaling;
    se_checkbox("Force Integer Scaling", &b);
    gui_state.settings.integer_scaling = b;
  }
  {
    bool b = gui_state.settings.stretch_to_fit;
    se_checkbox("Stretch Screen to Fit", &b);
    gui_state.settings.stretch_to_fit = b;
  }
  se_text("Game Boy Color Palette");
  for(int i=0;i<4;++i){
    char buff[60];
    snprintf(buff,60,se_localize_and_cache("GB Palette %d"),i);
    float color[3]; 
    uint32_t col = gui_state.settings.gb_palette[i];
    color[0]= SB_BFE(col,0,8)/255.;
    color[1]= SB_BFE(col,8,8)/255.;
    color[2]= SB_BFE(col,16,8)/255.;
    igColorEdit3(buff,color,ImGuiColorEditFlags_None);
    col = (((int)(color[0]*255))&0xff);
    col |= (((int)(color[1]*255))&0xff)<<8;
    col |= (((int)(color[2]*255))&0xff)<<16;
    gui_state.settings.gb_palette[i]=col;
  }
  if(se_button("Reset Palette to Defaults",(ImVec2){0,0}))se_reset_default_gb_palette();

#if !defined(PLATFORM_IOS) && !defined(PLATFORM_ANDROID)
  se_text(ICON_FK_KEYBOARD_O " Keybinds");
  igSeparator();
  bool value= true; 
  bool modified = se_handle_keybind_settings(SE_BIND_KEYBOARD,&gui_state.key);
  if(se_button("Reset Default Keybinds",(ImVec2){0,0})){
    se_set_default_keybind(&gui_state);
    modified=true;
  }

  if(modified){
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%skeyboard-bindings.bin",se_get_pref_path());
    sb_save_file_data(settings_path,(uint8_t*)gui_state.key.bound_id,sizeof(gui_state.key.bound_id));
    se_emscripten_flush_fs();
  }
  #endif
  #ifdef USE_SDL
  se_draw_controller_config(&gui_state);
  #endif
  se_text(ICON_FK_HAND_O_RIGHT " Touch Control Settings");
  igSeparator();
  float aspect_ratio = gui_state.screen_width/(float)gui_state.screen_height;
  float scale = (igGetWindowContentRegionWidth()-2)/(aspect_ratio+1.0/aspect_ratio);

  if(igBeginChildFrame(0,(ImVec2){scale*aspect_ratio,scale},ImGuiWindowFlags_None)){
    se_draw_emulated_system_screen(true);
  }
  igEndChildFrame();
  igSameLine(0,2);

  if(igBeginChildFrame(1,(ImVec2){scale/aspect_ratio,scale},ImGuiWindowFlags_None)){
    se_draw_emulated_system_screen(true);
  }
  igEndChildFrame();

  se_text("Scale");igSameLine(win_w*0.4,0);
  igPushItemWidth(-1);
  se_slider_float("##TouchControlsScale",&gui_state.settings.touch_controls_scale,0.3,1.0,"Scale: %.2f");

  se_text("Opacity");igSameLine(win_w*0.4,0);
  igPushItemWidth(-1);
  se_slider_float("##TouchControlsOpacity",&gui_state.settings.touch_controls_opacity,0,1.0,"Opacity: %.2f");
  igPopItemWidth();
  bool auto_hide = gui_state.settings.auto_hide_touch_controls;
  se_checkbox("Hide when inactive",&auto_hide);
  gui_state.settings.auto_hide_touch_controls = auto_hide;

  bool show_turbo = gui_state.settings.touch_controls_show_turbo;
  se_checkbox("Enable Turbo and Hold Button Modifiers",&show_turbo);
  gui_state.settings.touch_controls_show_turbo = show_turbo;

  se_text(ICON_FK_TEXT_HEIGHT " GUI");
  igSeparator();
  se_text("Language");igSameLine(win_w*0.4,0);
  igPushItemWidth(-1);
  if(igBeginCombo("##Language", se_language_string(gui_state.settings.language), ImGuiComboFlags_None)){
    int lang_id = 0; 
    for(int lang_id=0;lang_id<SE_MAX_LANG_VALUE;++lang_id){
      const char* lang = se_language_string(lang_id);
      se_cache_glyphs(lang);
      if(lang[0]){
        if(igSelectableBool(lang,false,ImGuiSelectableFlags_None, (ImVec2){0,0}))gui_state.settings.language=lang_id;
      }
    }
    igEndCombo();
  }
  igPopItemWidth();
  int theme = gui_state.settings.theme; 
  se_text("Theme");igSameLine(win_w*0.4,0);
  igPushItemWidth(-1);
  se_combo_str("##Theme",&theme,"Dark\0Light\0Black\0",0);
  igPopItemWidth();
  gui_state.settings.theme = theme;
  bool always_show_menubar = gui_state.settings.always_show_menubar;
  se_checkbox("Always Show Menu/Nav Bar",&always_show_menubar);
  gui_state.settings.always_show_menubar = always_show_menubar;
#if !defined(EMSCRIPTEN) && !defined(PLATFORM_ANDROID) &&!defined(PLATFORM_IOS)
  bool fullscreen = sapp_is_fullscreen();
  se_checkbox("Full Screen",&fullscreen);
  if(fullscreen!=sapp_is_fullscreen())sapp_toggle_fullscreen();
#endif

#ifndef EMSCRIPTEN
  {
    se_text(ICON_FK_CODE_FORK " Additional Search Paths");
    igSeparator();
    bool modified = se_input_path("Save File/State Path", gui_state.paths.save,ImGuiInputTextFlags_None);
    modified|=se_input_path("BIOS/Firmware Path", gui_state.paths.bios,ImGuiInputTextFlags_None);
    bool save_to_path=gui_state.settings.save_to_path;
    se_checkbox("Create new save files in Save Path",&save_to_path);
    gui_state.settings.save_to_path=save_to_path;

    if(modified)se_save_search_paths();
  }
#endif
  {
    se_bios_info_t * info = &gui_state.bios_info;
    if(emu_state.rom_loaded){
      se_text(ICON_FK_CROSSHAIRS " Located BIOS/Firmware Files");
      igSeparator();
      bool missing_bios = false;
      for(int i=0;i<sizeof(info->name)/sizeof(info->name[0]);++i){
        if(info->name[i][0]){
          if(info->success[i]){
            igPushStyleColorU32(ImGuiCol_Text,0xff00ff00);
            se_text(ICON_FK_CHECK);
          }else{
            igPushStyleColorU32(ImGuiCol_Text,0xff0000ff);
            se_text(ICON_FK_TIMES);
            missing_bios=true;
          }
          igPopStyleColor(1);
          igSameLine(0,2);
          se_input_path(info->name[i],info->path[i],ImGuiInputTextFlags_ReadOnly);
        }
      }
      if(missing_bios){
        igPushStyleColorU32(ImGuiCol_Text,0xff0000ff);
        se_text("Can't find all needed BIOS/Boot ROM/Firmware Files.");
        se_text("Accuracy will suffer and some features won't work.");
        igPopStyleColor(1);
      }
    }
  }
  
  se_text(ICON_FK_WRENCH " Advanced");
  igSeparator();
  se_text("Solar Sensor");igSameLine(win_w*0.4,0);
  igPushItemWidth(-1);
  se_slider_float("##Solar Sensor",&emu_state.joy.solar_sensor,0.,1.,"Brightness: %.2f");
  bool force_dmg_mode = gui_state.settings.force_dmg_mode;
  se_checkbox("Force GB games to run in DMG mode",&force_dmg_mode);
  gui_state.settings.force_dmg_mode=force_dmg_mode;
  bool draw_debug_menu = gui_state.settings.draw_debug_menu;
  se_checkbox("Show Debug Tools",&draw_debug_menu);
  gui_state.settings.draw_debug_menu = draw_debug_menu;

#ifdef ENABLE_HTTP_CONTROL_SERVER
  bool enable_hcs = gui_state.settings.http_control_server_enable;
  se_checkbox("Enable HTTP Control Server",&enable_hcs);
  gui_state.settings.http_control_server_enable =enable_hcs;
  if(enable_hcs){
    int port = gui_state.settings.http_control_server_port;
    se_text("Server Port");igSameLine(win_w*0.4,0);
    igPushItemWidth(-1);
    if(se_input_int("##Server Port",&port,1,10,ImGuiInputTextFlags_None))gui_state.settings.http_control_server_port=port; 
    igPopItemWidth();
  }
#endif 

  float bottom_padding =0;
  #ifdef PLATFORM_IOS
  se_ios_get_safe_ui_padding(NULL,&bottom_padding,NULL,NULL);
  #endif
  igDummy((ImVec2){0,bottom_padding});
}
static void se_reset_audio_ring(){
  //Reset the audio ring to 50% full with empty samples to avoid crackles while the buffer fills back up. 
  emu_state.audio_ring_buff.read_ptr = 0;
  emu_state.audio_ring_buff.write_ptr=4096;
  for(int i=0;i<SB_AUDIO_RING_BUFFER_SIZE;++i)emu_state.audio_ring_buff.data[i]=0; 
}
static void se_init_audio(){
 saudio_setup(&(saudio_desc){
    .sample_rate=SE_AUDIO_SAMPLE_RATE,
    .num_channels=2,
    .num_packets=4,
    .buffer_frames=1024*2,
    .packet_frames=1024
  });
 se_reset_audio_ring();
}

// For the main menu bar, which cannot be moved, we honor g.Style.DisplaySafeAreaPadding to ensure text can be visible on a TV set.
bool se_begin_menu_bar(){
  ImGuiContext* g = igGetCurrentContext();
  ImVec2 menu_bar_size={g->IO.DisplaySize.x, g->NextWindowData.MenuBarOffsetMinVal.y + SE_MENU_BAR_HEIGHT};
  float y_off = (3+gui_state.menubar_hide_timer-se_time())*2.;
  if(y_off>0)y_off=0;
  if(gui_state.settings.always_show_menubar)y_off=0;
  y_off = y_off*menu_bar_size.y;
  if(y_off<-menu_bar_size.y)y_off=-menu_bar_size.y;
  float y_pos = g->Style.DisplaySafeAreaPadding.y - g->Style.FramePadding.y;
  if(y_pos<0)y_pos=0;
  g->NextWindowData.MenuBarOffsetMinVal = (ImVec2){g->Style.DisplaySafeAreaPadding.x, y_pos};
  igSetNextWindowPos((ImVec2){0.0f, y_off},ImGuiCond_Always,(ImVec2){0,0});
  igSetNextWindowSize(menu_bar_size,ImGuiCond_Always);
  igPushStyleVarFloat(ImGuiStyleVar_WindowRounding, 0.0f);
  igPushStyleVarVec2(ImGuiStyleVar_WindowMinSize, (ImVec2){0, 0});
  ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings;
  bool is_open = igBegin("##MainMenuBar", NULL, window_flags);
  igPopStyleVar(2);
  g->NextWindowData.MenuBarOffsetMinVal = (ImVec2){0.0f, 0.0f};
  if (!is_open){
      igEnd();
      return false;
  }
  igSetCursorPosY(0);
  return true; //-V1020
}

void se_end_menu_bar(){
  igEnd();
}

#ifdef ENABLE_HTTP_CONTROL_SERVER
typedef struct{
  uint8_t* data; 
  size_t size; 
}se_png_write_context_t;
void se_png_write_mem(void *context, void *data, int size){
  se_png_write_context_t * cont =(se_png_write_context_t*)context;
  cont->data = realloc(cont->data,size+cont->size);
  memcpy(cont->data+cont->size,data,size);
  cont->size+=size; 
}
uint64_t se_hex_string_to_int(const char* s){
  uint64_t num = 0; 
  while(*s){
    num<<=4;
    if(s[0]>='a'&&s[0]<='f')num+=s[0]-'a'+10;
    if(s[0]>='A'&&s[0]<='F')num+=s[0]-'A'+10;
    if(s[0]>='0'&&s[0]<='9')num+=s[0]-'0';
    ++s;
  }
  return num;
}
void se_append_char_to_string(char** str, uint64_t* size, char c){
  if(*size==0)*size=1; 
  *str = realloc(*str,*size+1);
  (*str)[*size-1]=c;
  (*str)[*size]='\0';
  *size+=1;
}
uint8_t* se_hcs_callback(const char* cmd, const char** params, uint64_t* result_size, const char** mime_type){
  *result_size = 0;
  *mime_type = "text/html";
  printf("Got HCS Cmd: %s\n",cmd);
  const char ** p = params;
  while(*p){
    printf("%s = %s\n",p[0],p[1]);
    p+=2;
  }
  const char* str_result = NULL;
  if(strcmp(cmd,"/ping")==0)str_result="pong";
  else if(strcmp(cmd,"/load_rom")==0){
    while(*params){
      if(strcmp(params[0],"path")==0)se_load_rom(params[1]);
      if(strcmp(params[0],"pause")==0){
        if(atoi(params[1]))emu_state.run_mode=SB_MODE_PAUSE;
      };
      params+=2;
    }
    str_result=emu_state.rom_loaded?"ok":"Failed to load ROM";
  }else if(strcmp(cmd,"/step")==0){
    int step_frames = 1; 
    while(*params){
      if(strcmp(params[0],"frames")==0)step_frames=atoi(params[1]);
      params+=2;
    }
    emu_state.step_frames=step_frames;
    emu_state.run_mode = SB_MODE_STEP;
    str_result="ok";
  }else if(strcmp(cmd,"/run")==0){
    emu_state.step_frames=1;
    emu_state.run_mode = SB_MODE_RUN;
    str_result="ok";
  }else if(strcmp(cmd,"/screen")==0){
    se_save_state_t* save_state = (se_save_state_t*)malloc(sizeof(se_save_state_t));
    se_capture_state(&core,save_state);
    uint32_t width=0, height=0; 
    uint8_t* imdata = se_save_state_to_image(save_state, &width,&height);
    free(save_state);
    se_png_write_context_t cont ={0};
    stbi_write_png_to_func(se_png_write_mem, &cont,width,height,4, imdata, 0);
    free(imdata);
    *result_size = cont.size;
    *mime_type="image/png";
    return cont.data;
  }else if(strcmp(cmd,"/read_byte")==0){
    uint64_t response_size = 0; 
    char *response = NULL;
    while(*params){
      if(strcmp(params[0],"addr")==0){
        uint64_t addr = se_hex_string_to_int(params[1]);
        uint8_t byte = se_read_byte(addr,0);
        const char *map="0123456789abcdef";
        se_append_char_to_string(&response,&response_size,map[SB_BFE(byte,4,4)]);
        se_append_char_to_string(&response,&response_size,map[SB_BFE(byte,0,4)]);
      }
      params+=2;
    }
    if(response){
      *result_size = response_size;
      return (uint8_t*)response;
    }   
  }else if(strcmp(cmd,"/write_byte")==0){
    uint64_t response_size = 0; 
    char *response = NULL;
    while(*params){
      uint64_t addr = se_hex_string_to_int(params[0]);
      uint8_t data = se_hex_string_to_int(params[1]);
      se_write_byte(addr,0,data);
      params+=2;
    }
    str_result="ok";
  }else if(strcmp(cmd,"/input")==0){
    while(*params){
      for(int i=0; i<SE_NUM_KEYBINDS;++i){
        if(strcmp(params[0],se_keybind_names[i])==0){
          gui_state.hcs_joypad.inputs[i]=atof(params[1]);
          break;
        }
      }
      params+=2; 
    }
    str_result = "ok";
  }else if(strcmp(cmd,"/status")==0){
    *mime_type = "text/plain";
    char buffer[4096]={0};
    int off = 0;
    off+=snprintf(buffer+off,sizeof(buffer)-off,"SkyEmu (%s)\n",GIT_COMMIT_HASH);
    switch(emu_state.run_mode){
      case SB_MODE_PAUSE: off+=snprintf(buffer+off,sizeof(buffer)-off,"MODE: PAUSE\n");break;
      case SB_MODE_RUN: off+=snprintf(buffer+off,sizeof(buffer)-off,"MODE: RUN\n");break;
      case SB_MODE_STEP: off+=snprintf(buffer+off,sizeof(buffer)-off,"MODE: STEP\n");break;
      case SB_MODE_RESET: off+=snprintf(buffer+off,sizeof(buffer)-off,"MODE: RESET\n");break;
      case SB_MODE_REWIND: off+=snprintf(buffer+off,sizeof(buffer)-off,"MODE: REWIND\n");break;
    }
    off+=snprintf(buffer+off,sizeof(buffer)-off,"ROM Loaded: %s\n",emu_state.rom_loaded?"true":"false");
    if(emu_state.rom_loaded){
      off+=snprintf(buffer+off,sizeof(buffer)-off,"ROM Path: %s\n",emu_state.rom_path);
      off+=snprintf(buffer+off,sizeof(buffer)-off,"Save Path: %s\n",emu_state.save_file_path);
    }
    off+=snprintf(buffer+off,sizeof(buffer)-off,"Inputs: \n");
    
    for(int i=0; i<SE_NUM_KEYBINDS;++i){
      off+=snprintf(buffer+off,sizeof(buffer)-off,"- %s: %f\n",se_keybind_names[i],gui_state.hcs_joypad.inputs[i]);
    }
    str_result = buffer;
  }else if(strcmp(cmd,"/save")==0){
    bool okay=false;; 
    while(*params){
      if(strcmp(params[0],"path")==0){
        se_save_state_t* save_state = (se_save_state_t*)malloc(sizeof(se_save_state_t));
        se_capture_state(&core,save_state);
        okay|=se_save_state_to_disk(save_state,params[1]);
        free(save_state);
      }
      params+=2;
    }
    str_result=okay? "ok":"failed";
  }else if(strcmp(cmd,"/load")==0){
    bool okay=false;; 
    while(*params){
      if(strcmp(params[0],"path")==0){
        se_save_state_t* save_state = (se_save_state_t*)malloc(sizeof(se_save_state_t));
        if(se_load_state_from_disk(save_state,params[1])){
          okay=true;
          se_restore_state(&core,save_state);
        }
        free(save_state);
      }
      params+=2;
    }
    str_result=okay? "ok":"failed";
  }
  if(str_result){
    const char * result = strdup(str_result);
    *result_size = strlen(result)+1;
    return (uint8_t*)result;
  }
  return NULL;
}

#endif 

static void frame(void) {
  #ifdef ENABLE_HTTP_CONTROL_SERVER
  hcs_update(gui_state.settings.http_control_server_enable,gui_state.settings.http_control_server_port,se_hcs_callback);
  if(gui_state.settings.http_control_server_enable){
    for(int i=0;i<SE_NUM_KEYBINDS;++i)emu_state.joy.inputs[i]+=gui_state.hcs_joypad.inputs[i];
  }
  hcs_suspend_callbacks();
  #endif
  sb_poll_controller_input(&emu_state.joy);
#ifdef USE_SDL
  se_poll_sdl();
#endif
  se_set_language(gui_state.settings.language);
  se_update_key_turbo(&emu_state);
  se_update_solar_sensor(&emu_state);
#if !defined(EMSCRIPTEN) && !defined(PLATFORM_ANDROID) &&!defined(PLATFORM_IOS)
  static bool last_toggle_fullscreen=false;
  if(emu_state.joy.inputs[SE_KEY_TOGGLE_FULLSCREEN]&&last_toggle_fullscreen==false)sapp_toggle_fullscreen();
  last_toggle_fullscreen = emu_state.joy.inputs[SE_KEY_TOGGLE_FULLSCREEN];
#endif
  int width = sapp_width();
  const int height = sapp_height();
  const double delta_time = stm_sec(stm_round_to_common_refresh_rate(stm_laptime(&gui_state.laptime)));
  gui_state.screen_width=width;
  gui_state.screen_height=height;
  sg_begin_default_pass(&gui_state.pass_action, width, height);
  simgui_new_frame(width, height, delta_time);
  float menu_height = 0; 
  se_imgui_theme();
  /*=== UI CODE STARTS HERE ===*/
  igPushStyleVarVec2(ImGuiStyleVar_FramePadding,(ImVec2){5,5});
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0,5});
  ImGuiStyle* style = igGetStyle();
  float top_padding =0;
  float left_padding = 0, right_padding=0;
#ifdef PLATFORM_IOS
  se_ios_get_safe_ui_padding(&top_padding,NULL,&left_padding,&right_padding);
  style->ScrollbarSize=4;
  style->DisplaySafeAreaPadding.x = left_padding;
  style->DisplaySafeAreaPadding.y = top_padding;
#endif

  if (gui_state.test_runner_mode==false&&se_begin_menu_bar())
  {
    float menu_bar_y = igGetCursorPosY();
    if(gui_state.sidebar_open){
      igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(se_button(ICON_FK_TIMES,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,0})){gui_state.sidebar_open=!gui_state.sidebar_open;}
      igPopStyleColor(1);
    }else{
      if(se_button(ICON_FK_BARS,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,0})){gui_state.sidebar_open=!gui_state.sidebar_open;}
    }
    igSameLine(0,1);
    se_tooltip("Show/Hide Menu Panel");

    if(gui_state.settings.draw_debug_menu)se_draw_debug_menu();
    

    int orig_x = igGetCursorPosX();
    int v = (int)(gui_state.settings.volume*100);
    float volume_width = SE_VOLUME_SLIDER_WIDTH+5;
#if defined(PLATFORM_IOS) || defined(PLATFORM_ANDROID)
    gui_state.settings.volume=1.;
    volume_width = 0; 
#endif

    
    int num_toggles = 5;
    int sel_width =SE_TOGGLE_WIDTH;
    igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
    int toggle_x = (width/2)/se_dpi_scale()-sel_width*num_toggles/2;
    if((width)/se_dpi_scale()-toggle_x-(sel_width+1)*num_toggles<volume_width)toggle_x=(width)/se_dpi_scale()-(sel_width+1)*num_toggles-volume_width;
    if(toggle_x<orig_x)toggle_x=orig_x;

#if !defined(PLATFORM_IOS) && !defined(PLATFORM_ANDROID)
    int vol_x = width/se_dpi_scale()-volume_width;
    if(vol_x<toggle_x+(sel_width+1)*num_toggles)vol_x=toggle_x+(sel_width+1)*num_toggles;
    igSetCursorPosX(vol_x);
    igPushItemWidth(-0.01);
    igSliderInt("",&v,0,100,"%d%% "ICON_FK_VOLUME_UP,ImGuiSliderFlags_AlwaysClamp);
    se_tooltip("Adjust volume");
    gui_state.settings.volume=v*0.01;
    igPopItemWidth();
    igSetCursorPosX(orig_x);
#endif
    

    float toggle_width = sel_width*num_toggles;

    igSameLine(toggle_x,0);
    igPushItemWidth(sel_width);

    sb_joy_t *curr = &emu_state.joy;
    sb_joy_t *prev = &emu_state.prev_frame_joy;

    if(curr->inputs[SE_KEY_RESET_GAME]){
      emu_state.run_mode=SB_MODE_RESET;
    }

    if(!emu_state.rom_loaded) emu_state.run_mode = SB_MODE_PAUSE;

    int curr_toggle = 3;
    if(emu_state.run_mode==SB_MODE_REWIND&&emu_state.step_frames==2)curr_toggle=0;
    if(emu_state.run_mode==SB_MODE_REWIND&&emu_state.step_frames==1)curr_toggle=1;
    if(emu_state.run_mode==SB_MODE_PAUSE)curr_toggle=2;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==1)curr_toggle=2;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==2)curr_toggle=3;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==-1)curr_toggle=4;

    if(emu_state.run_mode==SB_MODE_PAUSE)gui_state.menubar_hide_timer=se_time();
    const char* toggle_labels[]={ICON_FK_FAST_BACKWARD, ICON_FK_BACKWARD, ICON_FK_PAUSE, ICON_FK_FORWARD,ICON_FK_FAST_FORWARD};
    const char* toggle_tooltips[]={
      "Rewind at 8x speed",
      "Rewind at 4x speed",
      "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
      "Run at 2x Speed",
      "Run at the fastest speed possible",
    };
    if(emu_state.run_mode==SB_MODE_PAUSE)toggle_labels[2]=ICON_FK_PLAY;
    int next_toggle_id = -1; 

    if(emu_state.run_mode!=SB_MODE_PAUSE){
      if(curr->inputs[SE_KEY_EMU_REWIND] && !prev->inputs[SE_KEY_EMU_REWIND])next_toggle_id = 1;
      if(!curr->inputs[SE_KEY_EMU_REWIND] && prev->inputs[SE_KEY_EMU_REWIND])next_toggle_id = 2;
      if(curr->inputs[SE_KEY_EMU_FF_2X] && !prev->inputs[SE_KEY_EMU_FF_2X])next_toggle_id = 3;
      if(!curr->inputs[SE_KEY_EMU_FF_2X] && prev->inputs[SE_KEY_EMU_FF_2X])next_toggle_id = 2;
      if(curr->inputs[SE_KEY_EMU_FF_MAX] && !prev->inputs[SE_KEY_EMU_FF_MAX])next_toggle_id = 4;
      if(!curr->inputs[SE_KEY_EMU_FF_MAX] && prev->inputs[SE_KEY_EMU_FF_MAX])next_toggle_id = 2;

      //Don't pause a game that is already running at normal speed. 
      if(curr_toggle==2 &&next_toggle_id==2)next_toggle_id=-1;
    }

    for(int i=0;i<SE_NUM_SAVE_STATES;++i){
      if(curr->inputs[SE_KEY_CAPTURE_STATE(i)])se_capture_state_slot(i);
      if(curr->inputs[SE_KEY_RESTORE_STATE(i)])se_restore_state_slot(i);
    }
    if(!emu_state.rom_loaded)se_push_disabled();
    for(int i=0;i<num_toggles;++i){
      bool active_button = i==curr_toggle;
      if(active_button)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(se_button(toggle_labels[i],(ImVec2){sel_width, SE_MENU_BAR_HEIGHT}))next_toggle_id = i;
      igSameLine(0,1);
      se_tooltip(toggle_tooltips[i]);
      
      if(active_button)igPopStyleColor(1);

      if(i==num_toggles-1)igPopStyleVar(1);
    }
    if(!emu_state.rom_loaded)se_pop_disabled();
    switch(next_toggle_id){
      case 0: {emu_state.run_mode=SB_MODE_REWIND;emu_state.step_frames=2;} ;break;
      case 1: {emu_state.run_mode=SB_MODE_REWIND;emu_state.step_frames=1;} ;break;
      case 2: {emu_state.run_mode=emu_state.run_mode==SB_MODE_RUN&&emu_state.step_frames==1?SB_MODE_PAUSE: SB_MODE_RUN;emu_state.step_frames=1;} ;break;
      case 3: {emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=2;} ;break;
      case 4: {emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=-1;} ;break;
    }

    if(curr->inputs[SE_KEY_EMU_PAUSE] && !prev->inputs[SE_KEY_EMU_PAUSE]){
      if(emu_state.run_mode!=SB_MODE_RUN){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=1;}
      else emu_state.run_mode = SB_MODE_PAUSE;
    }

    igPopItemWidth();
    
    ImVec2 menu_p; igGetWindowPos(&menu_p);
    menu_height= igGetWindowHeight()+menu_p.y;
    se_end_menu_bar();
  }
  igPopStyleVar(2);

  float screen_x = 0; 
  float screen_width = width; 
  float scaled_screen_width = screen_width/se_dpi_scale();

  float sidebar_w = 300; 
  int num_sidebars_open = gui_state.sidebar_open;
  if(gui_state.settings.draw_debug_menu){
    se_debug_tool_desc_t* desc=se_get_debug_description();
    while(desc&&desc->label){
      num_sidebars_open+=desc->visible;
      ++desc;
    }
  }
  bool draw_sidebars_over_screen = scaled_screen_width-sidebar_w*num_sidebars_open<sidebar_w*0.5;
  if(draw_sidebars_over_screen){
    sidebar_w = scaled_screen_width/num_sidebars_open;
    ImVec4 window_bg = style->Colors[ImGuiCol_WindowBg];
    window_bg.w = SE_TRANSPARENT_BG_ALPHA; 
    igPushStyleColorVec4(ImGuiCol_WindowBg, window_bg);
  }
  screen_x = left_padding;
  screen_width-=(left_padding+right_padding)*se_dpi_scale();
  if(gui_state.sidebar_open){
    igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
    igSetNextWindowSize((ImVec2){sidebar_w, (height-menu_height*se_dpi_scale())/se_dpi_scale()}, ImGuiCond_Always);
    igBegin(se_localize_and_cache("Menu"),&gui_state.sidebar_open, ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
    se_draw_menu_panel();
    igEnd();
    screen_x += sidebar_w;
    screen_width -=sidebar_w*se_dpi_scale();
    gui_state.key.last_bind_activitiy = -1;
    gui_state.menubar_hide_timer=se_time();
  }
  if(gui_state.settings.draw_debug_menu){
    int orig_screen_x = screen_x;
    screen_x = se_draw_debug_panels(screen_x, sidebar_w,menu_height,(height-menu_height*se_dpi_scale())/se_dpi_scale());
    screen_width -=(screen_x-orig_screen_x)*se_dpi_scale();
  }
  if(draw_sidebars_over_screen){
    screen_x = 0;
    screen_width = width;
    igPopStyleColor(1);
  }
  gui_state.block_touchscreen = draw_sidebars_over_screen;

  igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
  igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0.0f);
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
  igPushStyleColorVec4(ImGuiCol_WindowBg, (ImVec4){0,0,0,0.});

  igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration
    |ImGuiWindowFlags_NoBringToFrontOnFocus);
 
  se_update_frame();
  igPopStyleVar(2);
  igPopStyleColor(1);
  igEnd();
  bool draw_click_region = emu_state.run_mode!=SB_MODE_RUN&&emu_state.run_mode!=SB_MODE_REWIND && !draw_sidebars_over_screen&& gui_state.overlay_open;
  if(draw_click_region){
    igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
    igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
    igBegin("##ClickRegion",&gui_state.overlay_open,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoResize);
  }
  se_load_rom_overlay(draw_click_region);
  if(draw_click_region)igEnd();
  if(emu_state.run_mode==SB_MODE_RUN||emu_state.run_mode==SB_MODE_REWIND)gui_state.overlay_open= true; 

  /*=== UI CODE ENDS HERE ===*/

  simgui_render();
  sg_end_pass();
  if(gui_state.update_font_atlas){
    gui_state.update_font_atlas=false;
    ImFontAtlas* atlas = igGetIO()->Fonts;    
    uint64_t karla_compressed_size; 
    const uint8_t* karla_compressed_data = se_get_resource(SE_KARLA,&karla_compressed_size);
    uint64_t forkawesome_compressed_size; 
    const uint8_t* forkawesome_compressed_data = se_get_resource(SE_FORKAWESOME,&forkawesome_compressed_size);
    ImFont* font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
      atlas,karla_compressed_data,karla_compressed_size,13*se_dpi_scale(),NULL,NULL);
    
    static const ImWchar icons_ranges[] = { ICON_MIN_FK, ICON_MAX_FK, 0 }; // Will not be copied by AddFont* so keep in scope.
    ImFontConfig* config=ImFontConfig_ImFontConfig();
    config->MergeMode = true;
    config->GlyphMinAdvanceX = 13.0f;
    ImFont* font2 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,
      forkawesome_compressed_data,forkawesome_compressed_size,13*se_dpi_scale(),config,icons_ranges);
    ImFontConfig_destroy(config);
    igGetIO()->FontDefault=font2;
  
    #ifdef UNICODE_GUI
      uint64_t notosans_cjksc_compressed_size; 
      const uint8_t* notosans_cjksc_compressed_data = se_get_resource(SE_NOTO,&notosans_cjksc_compressed_size);
      ImFontConfig* config3=ImFontConfig_ImFontConfig();
      config3->MergeMode = true;
      config3->OversampleH=1;
      config3->PixelSnapH = true;

      static ImWchar ranges[((SE_MAX_UNICODE_CODE_POINT+1)/SE_FONT_CACHE_PAGE_SIZE)*2+1] = {0};
      int index = 0; 
      for(int i = 0; i<((SE_MAX_UNICODE_CODE_POINT+1)/SE_FONT_CACHE_PAGE_SIZE);++i){
        if(gui_state.font_cache_page_valid[i]==0x1){
          ranges[index*2] = i*SE_FONT_CACHE_PAGE_SIZE;
          if(ranges[index*2]==0)ranges[index*2]=1;
          ranges[index*2+1] = i*SE_FONT_CACHE_PAGE_SIZE+SE_FONT_CACHE_PAGE_SIZE;
          index++;
        }
      }
      ImFont* font3 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,notosans_cjksc_compressed_data,notosans_cjksc_compressed_size,14*se_dpi_scale(),config3,ranges);
      ImFontConfig_destroy(config3);
      igGetIO()->FontDefault=font3;
    #endif
    

    unsigned char* font_pixels;
    int font_width, font_height;
    int bytes_per_pixel;
    ImFontAtlas_GetTexDataAsRGBA32(atlas, &font_pixels, &font_width, &font_height, &bytes_per_pixel);
    sg_image_desc img_desc;
    memset(&img_desc, 0, sizeof(img_desc));
    img_desc.width = font_width;
    img_desc.height = font_height;
    img_desc.pixel_format = SG_PIXELFORMAT_RGBA8;
    img_desc.wrap_u = SG_WRAP_CLAMP_TO_EDGE;
    img_desc.wrap_v = SG_WRAP_CLAMP_TO_EDGE;
    img_desc.min_filter = SG_FILTER_NEAREST;
    img_desc.mag_filter = SG_FILTER_NEAREST;
    img_desc.data.subimage[0][0].ptr = font_pixels;
    img_desc.data.subimage[0][0].size = (size_t)(font_width * font_height) * sizeof(uint32_t);
    img_desc.label = "sokol-imgui-font";
    static bool has_atlas_image = false;
    if(has_atlas_image)sg_destroy_image(gui_state.font_atlas_image);
    has_atlas_image = true;
    gui_state.font_atlas_image = sg_make_image(&img_desc);
    atlas->TexID = (ImTextureID)(uintptr_t)gui_state.font_atlas_image.id;
    ImFontAtlas_ClearTexData(atlas);
    ImFontAtlas_ClearInputData(atlas);
    
    igGetIO()->Fonts=atlas;
    igGetIO()->FontGlobalScale=1./se_dpi_scale();
  }
  sg_commit();
  int num_samples_to_push = saudio_expect()*2;
  enum{samples_to_push=128};
  float volume_sq = gui_state.settings.volume*gui_state.settings.volume/32768.;
  for(int s = 0; s<num_samples_to_push;s+=samples_to_push){
    static int fill = 0; 
    float average_volume=0;
    float audio_buff[samples_to_push];
    int pushed = 0; 
    if(sb_ring_buffer_size(&emu_state.audio_ring_buff)<=samples_to_push){
      se_reset_audio_ring();
      break;
    }
    for(int i=0;i<samples_to_push;++i){
      int16_t data = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE];
      audio_buff[i]=data*volume_sq;
      ++pushed;
      average_volume+=fabs(audio_buff[i]);
    }
    saudio_push(audio_buff, samples_to_push/2);
    gui_state.audio_watchdog_timer = 0;
  }
  //This watchdog timer was inserted since 
  gui_state.audio_watchdog_timer++;
  if(gui_state.audio_watchdog_timer>100){
    gui_state.audio_watchdog_timer=0;
    saudio_shutdown();
    se_init_audio();
    gui_state.audio_watchdog_triggered++;
  }
  
  se_free_all_images();
  if(memcmp(&gui_state.last_saved_settings, &gui_state.settings,sizeof(gui_state.settings))){
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%suser_settings.bin",se_get_pref_path());
    sb_save_file_data(settings_path,(uint8_t*)&gui_state.settings,sizeof(gui_state.settings));
    se_emscripten_flush_fs();
    gui_state.last_saved_settings=gui_state.settings;
  }
  #ifdef ENABLE_HTTP_CONTROL_SERVER
  hcs_resume_callbacks();
  #endif
}
void se_load_settings(){
  se_load_recent_games_list();
  se_load_search_paths();
  {
    char keybind_path[SB_FILE_PATH_SIZE];
    snprintf(keybind_path,SB_FILE_PATH_SIZE,"%skeyboard-bindings.bin",se_get_pref_path());
    if(!sb_load_file_data_into_buffer(keybind_path,(uint8_t*)gui_state.key.bound_id,sizeof(gui_state.key.bound_id))){
      se_set_default_keybind(&gui_state);
    }
  }
#ifdef USE_SDL
  se_load_controller_settings(&gui_state.controller);
#endif
  {
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%suser_settings.bin",se_get_pref_path());
    if(!sb_load_file_data_into_buffer(settings_path,(void*)&gui_state.settings,sizeof(gui_state.settings))){gui_state.settings.settings_file_version=-1;}
    int max_settings_version_supported =2;
    if(gui_state.settings.settings_file_version>max_settings_version_supported){
      gui_state.settings.volume=0.8;
      gui_state.settings.draw_debug_menu = false; 
      gui_state.settings.settings_file_version = 0;
    }
    if(gui_state.settings.settings_file_version<1){
      gui_state.settings.settings_file_version=1; 
      se_reset_default_gb_palette();
      gui_state.settings.ghosting = 1.0;
      gui_state.settings.color_correction=1.0;
      gui_state.settings.integer_scaling=false;
      gui_state.settings.screen_shader=3;
      gui_state.settings.screen_rotation=0;
      gui_state.settings.stretch_to_fit = 0; 
    }
    if(gui_state.settings.screen_shader>4)gui_state.settings.screen_shader=4;
    if(gui_state.settings.settings_file_version<2){
      gui_state.settings.settings_file_version = 2; 
      gui_state.settings.auto_hide_touch_controls=true;
      gui_state.settings.touch_controls_opacity = 0.5;
      gui_state.settings.always_show_menubar=false;
      gui_state.settings.language=SE_LANG_DEFAULT;
      gui_state.settings.touch_controls_scale=1.0;
      gui_state.settings.touch_controls_show_turbo = 1; 
      gui_state.settings.save_to_path = false;
      gui_state.settings.http_control_server_enable = false; 
      gui_state.settings.http_control_server_port=8080;
    }
    if(gui_state.settings.touch_controls_scale<0.1)gui_state.settings.touch_controls_scale=1.0;
    if(!(gui_state.settings.touch_controls_opacity>=0&&gui_state.settings.touch_controls_opacity<1.0))gui_state.settings.touch_controls_opacity=0.5;
    if(gui_state.settings.gba_color_correction_mode> GBA_HIGAN_CORRECTION)gui_state.settings.gba_color_correction_mode=GBA_SKYEMU_CORRECTION;
    gui_state.last_saved_settings=gui_state.settings;
  }
}
static void init(void) {
  printf("SkyEmu %s\n",GIT_COMMIT_HASH);
  gui_state.overlay_open= true;
#ifdef USE_SDL
  if(SDL_Init(SDL_INIT_GAMECONTROLLER)){
    printf("Failed to init SDL: %s\n",SDL_GetError());
  }
#endif
  se_initialize_keybind(&gui_state.key);
  se_load_settings();
  sg_setup(&(sg_desc){
      .context = sapp_sgcontext()
  });
  stm_setup();
  simgui_setup(&(simgui_desc_t){ .dpi_scale= se_dpi_scale()});
  se_imgui_theme();
  // initial clear color
  gui_state.pass_action = (sg_pass_action) {
      .colors[0] = { .action = SG_ACTION_CLEAR, .value={0,0,0,1} }
  };
  gui_state.last_touch_time=-10000;
  se_init_audio();
  bool http_server_mode = false;
  if(emu_state.cmd_line_arg_count >3&&strcmp("http_server",emu_state.cmd_line_args[1])==0){
    gui_state.test_runner_mode=true;
    gui_state.settings.http_control_server_port = atoi(emu_state.cmd_line_args[2]);
    emu_state.cmd_line_arg_count =emu_state.cmd_line_arg_count-2;
    emu_state.cmd_line_args =emu_state.cmd_line_args+2;
    gui_state.settings.http_control_server_enable=true;
    http_server_mode=true;
  } 
  if(emu_state.cmd_line_arg_count>=2){
    se_load_rom(emu_state.cmd_line_args[1]);
    if(http_server_mode)emu_state.run_mode=SB_MODE_PAUSE;
  }

  sg_push_debug_group("LCD Shader Init");

  gui_state.lcd_prog = sg_make_shader(lcdprog_shader_desc(sg_query_backend()));
  /* pipeline object for imgui rendering */
  sg_pipeline_desc pip_desc={0};
  pip_desc.layout.buffers[0].stride = 16;
  {
      sg_vertex_attr_desc* attr = &pip_desc.layout.attrs[0];
      attr->offset =0;
      attr->format = SG_VERTEXFORMAT_FLOAT2;
  }
  {
      sg_vertex_attr_desc* attr = &pip_desc.layout.attrs[1];
      attr->offset = 8;
      attr->format = SG_VERTEXFORMAT_FLOAT2;
  }
  pip_desc.shader = gui_state.lcd_prog;
  pip_desc.index_type = SG_INDEXTYPE_NONE;
  pip_desc.colors[0].blend.enabled = false;
  pip_desc.colors[0].blend.src_factor_rgb = SG_BLENDFACTOR_SRC_ALPHA;
  pip_desc.colors[0].blend.dst_factor_rgb = SG_BLENDFACTOR_ONE_MINUS_SRC_ALPHA;
  pip_desc.label = "lcd-pipeline";
  gui_state.lcd_pipeline = sg_make_pipeline(&pip_desc);
  printf("Built pipeline: %d\n",gui_state.lcd_pipeline.id);
  static float quad_verts[6*4]={
    0,0, 0,0,
    1,0, 1,0,
    1,1, 1,1,

    1,1, 1,1,
    0,1, 0,1,
    0,0, 0,0,
  };

  sg_buffer_desc vb_desc={
    .usage     = SG_USAGE_IMMUTABLE,
    .data.size =sizeof(quad_verts),
    .data.ptr  = quad_verts
  };
  gui_state.quad_vb = sg_make_buffer(&vb_desc);
  sg_pop_debug_group();
#ifdef PLATFORM_ANDROID
  se_android_request_permissions();
  sapp_android_disable_vsync();
  #endif
}
static void cleanup(void) {
  simgui_shutdown();
  se_free_all_images();
  sg_shutdown();
  saudio_shutdown();
#ifdef USE_SDL
  SDL_Quit();
#endif
}
#ifdef EMSCRIPTEN
static void emsc_load_callback(const sapp_html5_fetch_response* response) {
  if (response->succeeded) {
    sb_save_file_data((char*)response->user_data, (uint8_t*)response->buffer_ptr, response->fetched_size);
    se_load_rom((char*)response->user_data);
  }else{
    printf("Failed to load dropped file:%d\n",response->error_code);
  }
  free(response->buffer_ptr);
  free(response->user_data);
}
#endif 
static void event(const sapp_event* ev) {
  simgui_handle_event(ev);
  if (ev->type == SAPP_EVENTTYPE_FILES_DROPPED) {
    // get the number of files and their paths like this:
    const int num_dropped_files = sapp_get_num_dropped_files();
    if(num_dropped_files){
#ifdef EMSCRIPTEN
    for(int i=0;i<num_dropped_files;++i){
      uint32_t size = sapp_html5_get_dropped_file_size(i);
      uint8_t * buffer = (uint8_t*)malloc(size);
      char *rom_file=(char*)malloc(4096); 
      snprintf(rom_file,4096,"/offline/%s",sapp_get_dropped_file_path(i));

      sapp_html5_fetch_dropped_file(&(sapp_html5_fetch_request){
        .dropped_file_index = i,
                  .callback = emsc_load_callback,
                  .buffer_ptr = buffer,
                  .buffer_size = size,
                  .user_data=rom_file});
    }
#else
        se_load_rom(sapp_get_dropped_file_path(0));
#endif
    }
  }else if (ev->type == SAPP_EVENTTYPE_KEY_DOWN) {
    gui_state.button_state[ev->key_code] = true;
    gui_state.key.last_bind_activitiy = ev->key_code; 
  }
  else if (ev->type == SAPP_EVENTTYPE_KEY_UP) {
    gui_state.button_state[ev->key_code] = false;
  }else if(ev->type==SAPP_EVENTTYPE_TOUCHES_BEGAN||
    ev->type==SAPP_EVENTTYPE_TOUCHES_MOVED||
    ev->type==SAPP_EVENTTYPE_TOUCHES_ENDED||
    ev->type==SAPP_EVENTTYPE_TOUCHES_CANCELLED){

    for(int i=0;i<SAPP_MAX_TOUCHPOINTS;++i){
      gui_state.touch_points[i].active = ev->num_touches>i;
      if(ev->type==SAPP_EVENTTYPE_TOUCHES_ENDED||ev->type==SAPP_EVENTTYPE_TOUCHES_CANCELLED)
        gui_state.touch_points[i].active &= !ev->touches[i].changed;
      gui_state.touch_points[i].pos[0] = ev->touches[i].pos_x;
      gui_state.touch_points[i].pos[1] = ev->touches[i].pos_y;
      if(ev->touches[i].pos_y<gui_state.screen_height*0.05&& gui_state.touch_points[i].active)gui_state.menubar_hide_timer=se_time();
    }
  }else if(ev->type==SAPP_EVENTTYPE_MOUSE_MOVE){
    gui_state.mouse_pos[0]=ev->mouse_x;
    gui_state.mouse_pos[1]=ev->mouse_y;
    if(gui_state.mouse_pos[1]<gui_state.screen_height*0.1)gui_state.menubar_hide_timer=se_time();
  }else if(ev->type==SAPP_EVENTTYPE_MOUSE_UP||ev->type==SAPP_EVENTTYPE_MOUSE_DOWN){
    int b = ev->mouse_button;
    if(b<3)gui_state.mouse_button[0] = ev->type==SAPP_EVENTTYPE_MOUSE_DOWN;
  }
}

sapp_desc sokol_main(int argc, char* argv[]) {
  #ifdef PLATFORM_WINDOWS
  //Should let windows open UTF-8 files
  setlocale(LC_ALL, ".65001");
  #endif
  emu_state.cmd_line_arg_count =argc;
  emu_state.cmd_line_args =argv;
  int width = 1280;
  int height = 800;
  if(argc>2&&strcmp("run_gb_test",argv[1])==0){
    gui_state.test_runner_mode=true;
    emu_state.cmd_line_arg_count =argc-1;
    emu_state.cmd_line_args =argv+1;
    width = SB_LCD_W;
    height= SB_LCD_H;
  }
  if(argc>2&&strcmp("run_gba_test",argv[1])==0){
    gui_state.test_runner_mode=true;
    emu_state.cmd_line_arg_count =argc-1;
    emu_state.cmd_line_args =argv+1;
    width = GBA_LCD_W;
    height= GBA_LCD_H;
  } 
  #if defined(EMSCRIPTEN)
    em_init_fs();  
  #endif
  return (sapp_desc){
      .init_cb = init,
      .frame_cb = frame,
      .cleanup_cb = cleanup,
      .event_cb = event,
      .window_title = "SkyEmu",
      .width = width,
      .height = height,
      .enable_dragndrop = true,
      .enable_clipboard =true,
      .high_dpi = true,
      .max_dropped_file_path_length = 8192,
#if defined(EMSCRIPTEN)
      .max_dropped_files=32,
#endif
      .swap_interval=0,
      .ios_keyboard_resizes_canvas=true
  };
}
