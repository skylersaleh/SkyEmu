/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#include <stdbool.h>
#include <stdio.h>

#include "shared.h"
#define SE_REBIND_TIMER_LENGTH 5.0

#ifdef ENABLE_HTTP_CONTROL_SERVER
#include "http_control_server.h"
#endif 

#ifdef ENABLE_RETRO_ACHIEVEMENTS
#include "rc_client.h"
#include "rc_consoles.h"
#include "retro_achievements.h"
#endif

#include "gba.h"
#include "nds.h"
#include "gb.h"
#include "capstone/include/capstone/capstone.h"
#include "miniz.h"
#include "localization.h"
#include "https.hpp"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

#include "cloud.h"
#include "mutex.h"
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
#include "stb_image.h"
#include "stb_image_write.h"

#ifdef USE_TINY_FILE_DIALOGS
#include "tinyfiledialogs.h"
#endif

#define UNICODE
#define USE_BUILT_IN_FILEBROWSER
#include "tinydir.h"

#ifdef SE_PLATFORM_ANDROID
  #include <android/log.h>
#endif
#ifdef SE_PLATFORM_IOS
#include "ios_support.h"
#endif
#ifdef USE_SDL
#include "SDL.h"
#endif 
#ifdef SE_PLATFORM_ANDROID
#include <android/native_activity.h>
#endif
#ifdef UNICODE_GUI
#include "utf8proc.h"
#endif

#include "lcd_shaders.h"

#define SE_ANDROID_CONTROLLER_NAME "Default Controller"

#define SE_HAT_MASK (1<<16)
#define SE_JOY_POS_MASK (1<<17)
#define SE_JOY_NEG_MASK (1<<18)

#define GBA_SKYEMU_CORRECTION 0 
#define GBA_HIGAN_CORRECTION  1

#define SE_FIELD_INDENT 125

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
  "Emulator " ICON_FK_PAUSE "/" ICON_FK_PLAY, // NOLINT
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
  double axis_last_zero_time[256];
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
  uint32_t avoid_overlaping_touchscreen;
  float custom_font_scale;
  uint32_t hardcore_mode;
  uint32_t draw_challenge_indicators;
  uint32_t draw_progress_indicators;
  uint32_t draw_leaderboard_trackers;
  uint32_t draw_notifications;
  float gui_scale_factor;
  uint32_t only_one_notification;
  uint32_t enable_download_cache;
  uint32_t nds_layout; 
  uint32_t touch_screen_show_button_labels;
  uint32_t show_screen_bezel;
  uint32_t padding[218];
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
  bool allow_directory;
  unsigned num_file_types;
  const char** file_types; 
  void (*file_open_fn)(const char* dir);
  char * output_path;
}se_file_browser_state_t;
typedef struct{
  uint32_t turbo_toggle;
  uint32_t hold_toggle; 
  bool turbo_modifier;
  bool hold_modifier;
}se_touch_controls_t; 

typedef struct{
  char save[SB_FILE_PATH_SIZE];
  char bios[SB_FILE_PATH_SIZE];
  char cheat_codes[SB_FILE_PATH_SIZE];
  char theme[SB_FILE_PATH_SIZE];
  char custom_font[SB_FILE_PATH_SIZE];
  char padding[3][SB_FILE_PATH_SIZE];
}se_search_paths_t;

_Static_assert(sizeof(se_search_paths_t)==SB_FILE_PATH_SIZE*8, "se_search_paths_t must contain 8 paths");

#define SE_MAX_BIOS_FILES 8
#define SE_BIOS_NAME_SIZE 32

#define SE_UI_DESKTOP 0
#define SE_UI_ANDROID 1 
#define SE_UI_IOS     2
#define SE_UI_WEB     3

typedef struct{
  char path[SE_MAX_BIOS_FILES][SB_FILE_PATH_SIZE];
  char name[SE_MAX_BIOS_FILES][SE_BIOS_NAME_SIZE];
  bool success[SE_MAX_BIOS_FILES];
}se_bios_info_t;

#define SE_MAX_CONTROL_POINTS 32
#define SE_REGION_NAME                 0
#define SE_REGION_AUTHOR               1
#define SE_REGION_BEZEL_PORTRAIT       2
#define SE_REGION_BEZEL_LANDSCAPE      3
#define SE_REGION_KEY_L                4
#define SE_REGION_KEY_L_PRESSED        5
#define SE_REGION_KEY_R                6
#define SE_REGION_KEY_R_PRESSED        7
#define SE_REGION_KEY_START            8
#define SE_REGION_KEY_START_PRESSED    9
#define SE_REGION_KEY_SELECT           10
#define SE_REGION_KEY_SELECT_PRESSED   11
#define SE_REGION_KEY_A                12
#define SE_REGION_KEY_A_PRESSED        13
#define SE_REGION_KEY_B                14
#define SE_REGION_KEY_B_PRESSED        15
#define SE_REGION_KEY_X                16
#define SE_REGION_KEY_X_PRESSED        17
#define SE_REGION_KEY_Y                18
#define SE_REGION_KEY_Y_PRESSED        19
#define SE_REGION_KEY_TURBO            20
#define SE_REGION_KEY_TURBO_PRESSED    21
#define SE_REGION_KEY_HOLD             22
#define SE_REGION_KEY_HOLD_PRESSED     23
#define SE_REGION_KEY_BLANK            24
#define SE_REGION_KEY_BLANK_PRESSED    25
#define SE_REGION_DPAD_UL              26
#define SE_REGION_DPAD_UP              27
#define SE_REGION_DPAD_UR              28
#define SE_REGION_DPAD_LEFT            29
#define SE_REGION_DPAD_CENTER          30
#define SE_REGION_DPAD_RIGHT           31
#define SE_REGION_DPAD_DL              32
#define SE_REGION_DPAD_DOWN            33
#define SE_REGION_DPAD_DR              34
#define SE_REGION_MENU                 35
#define SE_REGION_MENU_HOVER           36
#define SE_REGION_MENU_ACTIVE          37
#define SE_REGION_MAX_REWIND           38
#define SE_REGION_MAX_REWIND_HOVER     39
#define SE_REGION_MAX_REWIND_ACTIVE    40
#define SE_REGION_REWIND               41
#define SE_REGION_REWIND_HOVER         42
#define SE_REGION_REWIND_ACTIVE        43
#define SE_REGION_PLAY                 44
#define SE_REGION_PLAY_HOVER           45
#define SE_REGION_PLAY_ACTIVE          46
#define SE_REGION_PAUSE                47
#define SE_REGION_PAUSE_HOVER          48
#define SE_REGION_PAUSE_ACTIVE         49
#define SE_REGION_FF                   50
#define SE_REGION_FF_HOVER             51
#define SE_REGION_FF_ACTIVE            52
#define SE_REGION_MAX_FF               53
#define SE_REGION_MAX_FF_HOVER         54
#define SE_REGION_MAX_FF_ACTIVE        55
#define SE_REGION_BLANK                56
#define SE_REGION_BLANK_HOVER          57
#define SE_REGION_BLANK_ACTIVE         58
#define SE_REGION_VOL_EMPTY            59
#define SE_REGION_VOL_EMPTY_ACTIVE     60
#define SE_REGION_VOL_FULL             61
#define SE_REGION_VOL_FULL_ACTIVE      62
#define SE_REGION_VOL_KNOB             63
#define SE_REGION_VOL_KNOB_ACTIVE      64
#define SE_REGION_MENUBAR              65
#define SE_REGION_KEY_RECT_BLANK         66
#define SE_REGION_KEY_RECT_BLANK_PRESSED 67
#define SE_REGION_NO_BEZEL               68
#define SE_TOTAL_REGIONS                 69

#define SE_RESIZE_STRETCH  0
#define SE_RESIZE_ONLY_PORTRAIT  0x20
#define SE_RESIZE_ONLY_LANDSCAPE 0x40
#define SE_RESIZE_FIXED 0x80

#define SE_SCREEN_NONE  0
#define SE_SCREEN_BOTH  0xC0

#define SE_NO_SORT 0
#define SE_SORT_ALPHA_ASC 1
#define SE_SORT_ALPHA_DESC 2

#define SE_GAMEPAD_PORTRAIT_LEFT  0x40
#define SE_GAMEPAD_PORTRAIT_RIGHT 0x80
#define SE_GAMEPAD_PORTRAIT_BOTH  0xC0
#define SE_GAMEPAD_LANDSCAPE_LEFT  0x10
#define SE_GAMEPAD_LANDSCAPE_RIGHT 0x20
#define SE_GAMEPAD_LANDSCAPE_BOTH  0x30

#define SE_GAMEPAD_LEFT  0x40
#define SE_GAMEPAD_RIGHT 0x80
#define SE_GAMEPAD_BOTH  0xC0

#define SE_THEME_DREW_BACKGROUND 0x1
#define SE_THEME_DREW_SCREEN     0x2  
#define SE_THEME_DREW_CONTROLLER 0x4

#define SE_NDS_LAYOUT_AUTO 0 
#define SE_NDS_LAYOUT_VERTICAL 1
#define SE_NDS_LAYOUT_HORIZONTAL 2
#define SE_NDS_LAYOUT_HYBRID_LARGE_TOP 3
#define SE_NDS_LAYOUT_HYBRID_LARGE_BOTTOM 4
#define SE_NDS_LAYOUT_VERTICAL_LARGE_TOP 5
#define SE_NDS_LAYOUT_VERTICAL_LARGE_BOTTOM 6
#define SE_NDS_LAYOUT_HORIZONTAL_LARGE_TOP 7
#define SE_NDS_LAYOUT_HORIZONTAL_LARGE_BOTTOM 8

typedef struct{
  uint16_t start_pixel;
  uint16_t end_pixel;
  uint8_t resize_control;
  uint8_t screen_control;
  uint8_t gamepad_control;
}se_control_point_t;

typedef struct{
  int x,y;
  int w,h;
  bool active;
  se_control_point_t control_points_x[SE_MAX_CONTROL_POINTS];
  se_control_point_t control_points_y[SE_MAX_CONTROL_POINTS];
}se_theme_region_t;
#define SE_THEME_IMAGE_MIPS 5
typedef struct{
  sg_image image[SE_THEME_IMAGE_MIPS];
  uint32_t im_w;
  uint32_t im_h;
  uint32_t version_code; 
  uint8_t palettes[5*4];
  se_theme_region_t regions[SE_TOTAL_REGIONS];
}se_custom_theme_t;
typedef struct se_deferred_image_free_t{
  sg_image image; 
  struct se_deferred_image_free_t * next; 
}se_deferred_image_free_t;
typedef struct {
    uint64_t laptime;
    sg_pass_action pass_action;
    se_deferred_image_free_t * image_free_list;
    int screen_width;
    int screen_height;
    float dpi_override;
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
    bool ra_sidebar_open; 
    bool ra_encore_mode;
    bool ra_logged_in;
    bool ra_needs_reload;
    se_keybind_state_t key;
    se_controller_state_t controller;
    se_game_info_t recently_loaded_games[SE_NUM_RECENT_PATHS];
    int sorted_recently_loaded_games[SE_NUM_RECENT_PATHS];
    int recent_games_sort_type;
    bool allow_deletion_from_game_list;
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
    se_search_paths_t last_saved_paths;
    se_bios_info_t bios_info;
    sg_image font_atlas_image;
    uint8_t font_cache_page_valid[(SE_MAX_UNICODE_CODE_POINT+1)/SE_FONT_CACHE_PAGE_SIZE];
    bool update_font_atlas;
    sb_joy_t hcs_joypad; 
    int editing_cheat_index; //-1 when not editing a cheat
    char cheat_path[SB_FILE_PATH_SIZE];
    ImFont* mono_font; 

    uint32_t current_click_region_id;
    uint32_t max_click_region_id;
    uint32_t ui_type; 
    bool fake_paths; 
    char loaded_theme_path[SB_FILE_PATH_SIZE];
    char loaded_custom_font_path[SB_FILE_PATH_SIZE];
    se_custom_theme_t theme;
    bool ran_from_launcher;
    char search_buffer[32];
} gui_state_t;

#define SE_REWIND_BUFFER_SIZE (1024*1024)
#define SE_REWIND_SEGMENT_SIZE 64
#define SE_LAST_DELTA_IN_TX (1u<<31)

#define SE_NUM_SAVE_STATES 4
#define SE_MAX_SCREENSHOT_SIZE (NDS_LCD_H*NDS_LCD_W*2*4)

#define SE_THEME_DARK 0
#define SE_THEME_LIGHT 1
#define SE_THEME_BLACK 2
#define SE_THEME_CUSTOM 3

#define SE_MENU_BAR_HEIGHT 24
#define SE_MENU_BAR_BUTTON_WIDTH 30
#define SE_TOGGLE_WIDTH 35
#define SE_VOLUME_SLIDER_WIDTH 100

//TODO: Clean this up to use unions...
sb_emu_state_t emu_state = { .joy.solar_sensor=0.5};
#define SE_MAX_CONST(A,B) ((A)>(B)? (A) : (B) )
typedef union{
  // Do not reorder items in this struct otherwise you may break save states.
  // Append new data to the end of this structure. 
  struct {
    union {
      sb_gb_t gb;
      gba_t gba;  
      nds_t nds;
    };
    #ifdef ENABLE_RETRO_ACHIEVEMENTS
      uint8_t rc_buffer[SE_RC_BUFFER_SIZE]; // buffer for RetroAchievements state, should be more than enough
    #endif
  };
  // Raw data padded out to 64B to make rewind efficient
  uint64_t raw_data[(SE_MAX_CONST(SE_MAX_CONST(sizeof(gba_t), sizeof(nds_t)), sizeof(sb_gb_t))+SE_RC_BUFFER_SIZE)/SE_REWIND_SEGMENT_SIZE+1];
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
  char name[39]; //Emulator Name
  char build[41];//Emulator build/commit hash
  uint32_t bess_offset; //Number of bytes after the se_emu_id where the save state descriptor is located. 
  uint32_t system; //SYSTEM_UNKNOWN=0 ,SYSTEM_GB=1, SYSTEM_GBA=2, SYSTEM_NDS 3
  uint32_t rcheevos_buffer_offset; // Byte offset of rc_buffer
  uint32_t rcheevos_buffer_size;   // Size of rc_buffer
  uint8_t padding[12];//Zero padding
}se_emu_id;
typedef struct{
  cloud_drive_t* drive;
  se_save_state_t save_states[SE_NUM_SAVE_STATES];
  mutex_t save_states_mutex;
  bool save_states_busy[SE_NUM_SAVE_STATES];
  cloud_user_info_t user_info;
} se_cloud_state_t;
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
static void se_sync_cloud_save_states();
gui_state_t gui_state={ .update_font_atlas=true }; 

void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha);
void se_draw_lcd(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, float rotation,bool is_touch);
void se_load_rom_overlay(bool visible);
void se_draw_onscreen_controller(sb_emu_state_t*state, int mode, float win_x, float win_y, float win_w, float win_h, bool preview, bool center);
static float se_compute_touchscreen_controls_min_dim(float w, float h, bool *portrait);
void se_reset_save_states();
void se_set_new_controller(se_controller_state_t* cont, int index);
bool se_run_ar_cheat(const uint32_t* buffer, uint32_t size);
void se_emscripten_flush_fs();
static uint32_t se_save_best_effort_state(se_core_state_t* state);
static bool se_load_best_effort_state(se_core_state_t* state,uint8_t *save_state_data, uint32_t size, uint32_t bess_offset);
static size_t se_get_core_size();
uint8_t* se_hcs_callback(const char* cmd, const char** params, uint64_t* result_size, const char** mime_type);
void se_open_file_browser(bool clicked, float x, float y, float w, float h, void (*file_open_fn)(const char* dir), const char ** file_types,char * output_path);
void se_file_browser_accept(const char * path);
static void se_reset_core();
static bool se_load_theme_from_file(const char * filename);
static bool se_load_theme_from_memory(const uint8_t* data, int64_t size, bool invert, bool blacken);
static bool se_reload_theme();

double se_time();
void se_push_disabled();
void se_pop_disabled();


static int se_draw_theme_region(int region, float x, float y, float w, float h);
static int se_draw_theme_region_tint(int region, float x, float y, float w, float h,uint32_t tint);
static int se_draw_theme_region_tint_partial(int region, float x, float y, float w, float h, float w_ratio, float h_ratio, uint32_t tint);

static void se_compute_draw_lcd_rect(float *lcd_render_w, float *lcd_render_h, int* nds_layout);
static void se_draw_lcd_in_rect(float lcd_render_x, float lcd_render_y, float lcd_render_w, float lcd_render_h, int nds_layout);

const char* se_get_pref_path(){
#if defined(EMSCRIPTEN)
  return "/offline/";
#elif defined(USE_SDL)
  static const char* cached_pref_path=NULL;
  if(cached_pref_path==NULL)cached_pref_path=SDL_GetPrefPath("Sky","SkyEmu");
  return cached_pref_path;
#elif defined(SE_PLATFORM_ANDROID)
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  if(activity->internalDataPath)return activity->internalDataPath;
#endif
  return "";
}
#ifdef SE_PLATFORM_ANDROID
float se_android_get_display_dpi_scale();
#endif
static float se_dpi_scale(){
  if(gui_state.dpi_override)return gui_state.dpi_override/120.;
  static float dpi_scale = -1.0;
  if(dpi_scale>0.)return dpi_scale*gui_state.settings.gui_scale_factor;
  dpi_scale = sapp_dpi_scale();
  if(dpi_scale<=0)dpi_scale=1.;
  dpi_scale*=1.10;
#ifdef SE_PLATFORM_ANDROID
  dpi_scale = se_android_get_display_dpi_scale();
#endif
  return dpi_scale*gui_state.settings.gui_scale_factor;
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
char* se_replace_fake_path(char * new_path){
  static char fake_path[SB_FILE_PATH_SIZE]; 
  if(gui_state.fake_paths){
    const char* base, *filename, *ext; 
    sb_breakup_path(new_path,&base, &filename,&ext);
    char* new_base = "/fakepath/";
    if(gui_state.ui_type==SE_UI_ANDROID)new_base = "/storage/emulated/0/Android/data/com.sky.SkyEmu/";
    snprintf(fake_path,sizeof(fake_path),"%s%s.%s",new_base,filename,ext);
    new_path = fake_path; 
  }
  return new_path;
}
const char* se_localize_and_cache(const char* input_str){
  const char * localized_string = se_localize(input_str);
  se_cache_glyphs(localized_string);
  return localized_string;
}
bool se_checkbox(const char* label, bool * v){
  return igCheckbox(se_localize_and_cache(label),v);
}
void se_text(const char* label,...){
  va_list args;
  va_start(args, label);
  igTextWrappedV(se_localize_and_cache(label),args);
  va_end(args);
}
static void se_text_disabled(const char* label,...){
  va_list args;
  va_start(args, label);
  se_push_disabled();
  igTextWrappedV(se_localize_and_cache(label),args);
  se_pop_disabled();
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
static bool se_input_int(const char* label,int* v,int step,int step_fast,ImGuiInputTextFlags flags){
  return igInputInt(se_localize_and_cache(label),v,step,step_fast,flags);
}
static bool se_input_uint32(const char* label,uint32_t* v,int step,int step_fast,ImGuiInputTextFlags flags){
  int val = *v; 
  bool ret = se_input_int(label,&val,step,step_fast,flags);
  *v = val;
  return ret;
}
static bool se_input_int32(const char* label,int32_t* v,int step,int step_fast,ImGuiInputTextFlags flags){
  int val = *v; 
  bool ret = se_input_int(label,&val,step,step_fast,flags);
  *v = val;
  return ret;
}
void se_section(const char* label,...){
  ImGuiStyle * style = igGetStyle();
  ImDrawList*dl= igGetWindowDrawList();
  ImVec2 b_min,b_sz,b_max,b_cursor;

  igGetWindowPos(&b_min);
  igGetWindowSize(&b_sz);
  igGetCursorPos(&b_cursor);
  
  b_min.x+=b_cursor.x-style->FramePadding.x;
  b_min.y+=b_cursor.y-style->FramePadding.y;
  b_min.y-=igGetScrollY();
  b_max.x = b_min.x+b_sz.x-b_cursor.x; 

  char buffer[256]="";
  va_list args;
  va_start(args, label);
  vsnprintf(buffer,sizeof(buffer),se_localize_and_cache(label),args);
  va_end(args);
  ImVec2 text_size; 
  igCalcTextSize(&text_size,buffer,NULL,false,b_max.x-b_min.x);

  b_max.y = b_min.y+text_size.y+style->FramePadding.y * 2.0f; 
  
  ImDrawList_AddRectFilled(dl,b_min,b_max,igGetColorU32Col(ImGuiCol_TitleBg,1.0),0,ImDrawCornerFlags_None);
  igTextWrapped("%s",buffer);
}
static bool se_button_themed(int region, const char* label, ImVec2 size, bool always_draw_label){
  label=se_localize_and_cache(label);
  ImVec2 label_size;
  igCalcTextSize(&label_size,label, NULL, true,-1.0);
  ImGuiStyle * style = igGetStyle();

  igCalcItemSize(&size, size, label_size.x + style->FramePadding.x * 2.0f, label_size.y + style->FramePadding.y * 2.0f);

  ImVec2 pos,v;
  igGetCursorPos(&pos);
  igGetWindowPos(&v);
  pos.x+=v.x-igGetScrollX();
  pos.y+=v.y-igGetScrollY();
  ImGuiStyle restore_style = *style;
  if(gui_state.theme.regions[region].active){
    for(int i=0;i<ImGuiCol_COUNT;++i)style->Colors[i].w = 0.;
    if(always_draw_label){
      style->Colors[ImGuiCol_Text] = restore_style.Colors[ImGuiCol_Text];
      style->Colors[ImGuiCol_TextDisabled] = restore_style.Colors[ImGuiCol_TextDisabled];
    }
  }
  bool hover = igIsMouseHoveringRect((ImVec2){pos.x,pos.y},(ImVec2){pos.x+size.x,pos.y+size.y},true);
  float alpha = 1.0;
  if(hover) alpha=0.5;
  uint32_t tint = 0x00ffffff|((uint32_t)(alpha*255)<<24u); 
  if(se_draw_theme_region_tint(region, pos.x,pos.y,size.x,size.y,tint));
  else if(se_draw_theme_region_tint(SE_REGION_BLANK, pos.x,pos.y,size.x,size.y,tint));
  else *style = restore_style; 
  bool button_result = igButton(label,size);

  *style = restore_style; 
  return button_result;
}
uint32_t se_hsv_to_rgb(uint16_t H, uint8_t S, uint8_t V) {
	float r, g, b;
	
	float h = (float)H / 360;
	float s = (float)S / 100;
	float v = (float)V / 100;
	
	int i = floor(h * 6);
	float f = h * 6 - i;
	float p = v * (1 - s);
	float q = v * (1 - f * s);
	float t = v * (1 - (1 - f) * s);
	
	switch (i % 6) {
		case 0: r = v, g = t, b = p; break;
		case 1: r = q, g = v, b = p; break;
		case 2: r = p, g = v, b = t; break;
		case 3: r = p, g = q, b = v; break;
		case 4: r = t, g = p, b = v; break;
		case 5: r = v, g = p, b = q; break;
	}
	
	uint8_t r8 = r * 255;
  uint8_t g8 = g * 255;
  uint8_t b8 = b * 255;
	
	return b8 << 16 | g8 << 8 | r8;
}
bool se_slider_float_themed(const char* label, float* p_data, float p_min, float p_max, const char* format){
  if(igGetCurrentWindow()->SkipItems)return false;

  label = se_localize_and_cache(label);
  format = se_localize_and_cache(format);
  const float w = igCalcItemWidth();

  ImVec2 label_size;
  igCalcTextSize(&label_size,label, NULL, true,-1);
  ImVec2 pos,v;
  igGetCursorPos(&pos);
  igGetWindowPos(&v);
  pos.x+=v.x-igGetScrollX();
  pos.y+=v.y-igGetScrollY();
  ImGuiStyle * style = igGetStyle();
  ImGuiStyle restore_style = *style;

  ImVec2 frame_size ={w, label_size.y + style->FramePadding.y * 2.0f};
  float bar_growth =0.0;
  ImVec2 orig_pos = pos;
  ImVec2 orig_size= frame_size;
  pos.x-=frame_size.x*bar_growth;
  pos.y-=frame_size.y*bar_growth;
  frame_size.x+=frame_size.x*bar_growth;
  frame_size.y+=frame_size.y*bar_growth;

  if( gui_state.theme.regions[SE_REGION_VOL_EMPTY].active){
    for(int i=0;i<ImGuiCol_COUNT;++i)style->Colors[i].w = 0.;
    style->Colors[ImGuiCol_Text] = restore_style.Colors[ImGuiCol_Text];
    style->Colors[ImGuiCol_TextDisabled] = restore_style.Colors[ImGuiCol_TextDisabled];
  }
  bool hover = igIsMouseHoveringRect((ImVec2){pos.x,pos.y},(ImVec2){pos.x+frame_size.x,pos.y+frame_size.y},true);
  float alpha = 1.0;
  if(hover) alpha=0.75;
  uint32_t tint = 0x00ffffff|((uint32_t)(alpha*255)<<24u); 
  se_draw_theme_region_tint(SE_REGION_VOL_EMPTY, pos.x,pos.y,frame_size.x,frame_size.y,tint);
  float bar_value = (*p_data-p_min)/(p_max-p_min);
  if(bar_value<0.0)bar_value=0;
  if(bar_value>1.0)bar_value=1.0;
  float grab_padding = 2.0;
  float knob_size =style->GrabMinSize+grab_padding*2.0; 
  float knob_x = orig_pos.x+ bar_value*(orig_size.x-knob_size)+knob_size*0.5;
  bar_value=(knob_x-pos.x)/frame_size.x;
  se_draw_theme_region_tint_partial(SE_REGION_VOL_FULL, pos.x,pos.y,frame_size.x,frame_size.y,bar_value,1.0,tint);
  float render_knob_size = 20.0; 
  se_draw_theme_region_tint(SE_REGION_VOL_KNOB, knob_x-render_knob_size*0.5,pos.y,render_knob_size,frame_size.y,tint);

  igPushAllowKeyboardFocus(false); // disables focus by tab
  bool button_result = igSliderFloat(label,p_data,p_min,p_max,format,ImGuiSliderFlags_AlwaysClamp);
  igPopAllowKeyboardFocus();

  *style = restore_style; 
  return button_result;

}

bool se_slider_int_themed(const char* label, int* v, float v_min, float v_max, const char* format){
  float vf = *v;
  bool ret = se_slider_float_themed(label, &vf, v_min, v_max, format);
  *v = vf;
  return ret;
}
static int se_slider_float(const char* label,float* v,float v_min,float v_max,const char* format){
  return se_slider_float_themed(label,v,v_min,v_max,format);
}

bool se_button(const char* label, ImVec2 size){
  return se_button_themed(SE_REGION_BLANK,se_localize_and_cache(label),size,true);
}
static bool se_input_path(const char* label, char* new_path, ImGuiInputTextFlags flags){
  int win_w = igGetWindowWidth();
  se_text(label);igSameLine(SE_FIELD_INDENT,0);
  igPushIDStr(label);
  bool read_only = (flags&ImGuiInputTextFlags_ReadOnly)!=0;
  float button_w = 25; 
  bool has_path = strlen(new_path);
  if(!read_only)igPushItemWidth(has_path?-button_w*2 : -button_w);
  else igPushItemWidth(-1);

  new_path = se_replace_fake_path(new_path);
  bool b = igInputText("##",new_path,SB_FILE_PATH_SIZE,flags|ImGuiInputTextFlags_ReadOnly,NULL,NULL);
  igPopItemWidth();
  if(!read_only){
    if(has_path){
      igSameLine(0,1);
      if(se_button("" ICON_FK_TIMES,(ImVec2){button_w-2,0})){
        strncpy(new_path,"",SB_FILE_PATH_SIZE);
      }
    }
    igSameLine(0,1);
    bool clicked = false; 
    if(se_button("" ICON_FK_FOLDER_OPEN,(ImVec2){button_w-2,0}))clicked = true;
    
    if(igIsItemVisible()){
      ImVec2 min, max;
      igGetItemRectMin(&min);
      igGetItemRectMax(&max);
      ImGuiStyle *style = igGetStyle();
      max.x+=style->FramePadding.y;
      max.y+=style->FramePadding.y;
      static const char *types[]={"$DIR$",NULL};
      se_open_file_browser(clicked, min.x, min.y, max.x-min.x, max.y-min.y, NULL,types,new_path);
    }
  }

  igPopID();
  return b; 
}
static bool se_input_file_callback(const char* label, char* new_path, const char**types,void (*file_open_fn)(const char*), ImGuiInputTextFlags flags){
  int win_w = igGetWindowWidth();
  se_text(label);igSameLine(SE_FIELD_INDENT,0);
  igPushIDStr(label);
  bool read_only = (flags&ImGuiInputTextFlags_ReadOnly)!=0;
  float button_w = 25; 
  bool has_path = strlen(new_path);
  if(!read_only)igPushItemWidth(has_path?-button_w*2 : -button_w);
  else igPushItemWidth(-1);
  new_path = se_replace_fake_path(new_path);
  bool b = igInputText("##",new_path,SB_FILE_PATH_SIZE,flags|ImGuiInputTextFlags_ReadOnly,NULL,NULL);
  igPopItemWidth();
  if(!read_only){
    if(has_path){
      igSameLine(0,1);
      if(se_button("" ICON_FK_TIMES,(ImVec2){button_w-2,0})){
        gui_state.file_browser.output_path=new_path;
        gui_state.file_browser.file_open_fn=file_open_fn;
        se_file_browser_accept("");
      }
    }
    igSameLine(0,1);
    bool clicked = false; 
    if(se_button("" ICON_FK_FOLDER_OPEN,(ImVec2){button_w-2,0}))clicked = true;
    
    if(igIsItemVisible()){
      ImVec2 min, max;
      igGetItemRectMin(&min);
      igGetItemRectMax(&max);
      ImGuiStyle *style = igGetStyle();
      max.x+=style->FramePadding.y;
      max.y+=style->FramePadding.y;
      se_open_file_browser(clicked, min.x, min.y, max.x-min.x, max.y-min.y, file_open_fn,types,new_path);
    }
  }

  igPopID();
  return b; 
}
static bool se_input_file(const char* label, char* new_path, const char**types, ImGuiInputTextFlags flags){
  return se_input_file_callback(label,new_path,types,NULL,flags);
}
static void se_tooltip(const char * tooltip){
  if(igGetCurrentContext()->HoveredIdTimer<1.5||gui_state.last_touch_time>0)return;
  if (igIsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)&&!igIsItemActive()){
    igSetTooltip(se_localize_and_cache(tooltip));
  }
}
static void se_panel_toggle(int region, bool * is_open, const char* icon, const char* tooltip ){
  if(gui_state.theme.regions[region].active==false)region = SE_REGION_BLANK;
  igPushIDStr(icon);
  if(*is_open){
    igPushStyleColorVec4(ImGuiCol_Button, igGetStyle()->Colors[ImGuiCol_ButtonActive]);
    if(se_button_themed(region+2,icon,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,SE_MENU_BAR_HEIGHT},region!=SE_REGION_MENU)){*is_open=!*is_open;}
    igPopStyleColor(1);
  }else{
    if(se_button_themed(region,icon,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,SE_MENU_BAR_HEIGHT},region!=SE_REGION_MENU)){*is_open=!*is_open;}
  }
  igPopID();
  igSameLine(0,1);
  se_tooltip(tooltip);
}
void se_mkdir(char *path) {
    char *sep = strrchr(path, '/');
    if(sep != NULL) {
        *sep = 0;
        se_mkdir(path);
        *sep = '/';
    }
    if(mkdir(path, 0777) && errno != EEXIST)
        printf("error while trying to create '%s'\n%m\n", path); 
}
FILE *se_fopen_mkdir(const char *fpath, char *mode) {
    char *path = strdup(fpath);
    char *sep = strrchr(path, '/');
    char *sep2 = strrchr(path, '\\');
    if(sep2&&(!sep||sep2<sep))sep=sep2;
    if(sep) { 
        char *path0 = strdup(path);
        path0[ sep - path ] = 0;
        se_mkdir(path0);
        free(path0);
    }
    free(path);
    return fopen(fpath,mode);
}
void se_copy_file(const char * original_path, const char* copy_path){

  FILE* source = fopen(original_path, "rb");
  FILE* dest  = se_fopen_mkdir(copy_path, "wb");
  if (source == NULL ||dest==NULL) {
    perror("Error opening source or dest file for copy\n");
    if(source)fclose(source);
    if(dest)fclose(dest);
    return; 
  }
  char buffer[1024];
  size_t read = 0;;

  while ((read = fread(buffer, 1, sizeof(buffer), source)) > 0) {
      fwrite(buffer, 1, read, dest);
  }
  fclose(source);
  fclose(dest);
}
void se_bios_file_open_fn(const char* dir){
  //Make use of the fact that the accept function is called before the output path is updated.
  char * se_bios_file_open_tmp_path = gui_state.file_browser.output_path;
  if(strncmp(dir,se_bios_file_open_tmp_path,SB_FILE_PATH_SIZE)!=0){
    if(sb_file_exists(se_bios_file_open_tmp_path)||strncmp(dir,"",SB_FILE_PATH_SIZE)==0)remove(se_bios_file_open_tmp_path);
    if(strncmp(dir,"",SB_FILE_PATH_SIZE)!=0)se_copy_file(dir,se_bios_file_open_tmp_path);
  }
  emu_state.run_mode=SB_MODE_RESET;
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
se_cloud_state_t cloud_state;

bool se_more_rewind_deltas(se_core_rewind_buffer_t* rewind, uint32_t index){
  return (rewind->deltas[index%SE_REWIND_BUFFER_SIZE].offset&SE_LAST_DELTA_IN_TX)==0;
}
void se_push_rewind_state(se_core_state_t* core, se_core_rewind_buffer_t* rewind){
  #ifdef ENABLE_RETRO_ACHIEVEMENTS
    retro_achievements_capture_state(core->rc_buffer);
  #endif
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
  #ifdef ENABLE_RETRO_ACHIEVEMENTS
    retro_achievements_restore_state(core->rc_buffer);
  #endif
}
void se_reset_rewind_buffer(se_core_rewind_buffer_t* rewind){
  rewind->index = rewind->size = 0; 
  rewind->first_push = false;
}
// Detection based on code by Freak, modified by Sky to add WebAsm, and RISC-V
const char *se_get_host_arch() { 
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_2__)
    return "ARM2";
    #elif defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__)
    return "ARM3";
    #elif defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "ARM4T";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "ARM5"
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_)
    return "ARM6T2";
    #elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "ARM6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7";
    #elif defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7A";
    #elif defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "ARM7R";
    #elif defined(__ARM_ARCH_7M__)
    return "ARM7M";
    #elif defined(__ARM_ARCH_7S__)
    return "ARM7S";
    #elif defined(__aarch64__) || defined(_M_ARM64)
    return "ARM64";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "MIPS";
    #elif defined(__sh__)
    return "SUPERH";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__PPC__) || defined(_ARCH_PPC)
    return "POWERPC";
    #elif defined(__PPC64__) || defined(__ppc64__) || defined(_ARCH_PPC64)
    return "POWERPC64";
    #elif defined(__sparc__) || defined(__sparc)
    return "SPARC";
    #elif defined(__m68k__)
    return "M68K";
    #elif defined(__EMSCRIPTEN__)
    return "WebAsm";
    #elif defined(__riscv) || defined(__riscv32) || defined(__riscv__) || defined(_riscv)
    #else
    return "Unknown Arch";
    #endif
}
const char *se_get_host_platform() { 
  #if defined(SE_PLATFORM_WINDOWS)
    return "Windows";
  #elif defined(SE_PLATFORM_LINUX)
    return "Linux";
  #elif defined(SE_PLATFORM_FREEBSD)
    return "FreeBSD";
  #elif defined(SE_PLATFORM_MACOS)
    return "macOS";
  #elif defined(SE_PLATFORM_IOS)
    return "iOS";
  #elif defined(SE_PLATFORM_ANDROID)
    return "Android";
  #elif defined(__EMSCRIPTEN__)
    return "Web";
  #endif
  return "Unknown Platform";
}

se_emu_id se_get_emu_id(){
  se_emu_id emu_id={0};
  snprintf(emu_id.name,sizeof(emu_id.name),"SkyEmu (%s,%s)",se_get_host_platform(),se_get_host_arch());
  strncpy(emu_id.build,GIT_COMMIT_HASH,sizeof(emu_id.build));

  emu_id.rcheevos_buffer_offset = offsetof(se_core_state_t,rc_buffer);
  emu_id.rcheevos_buffer_size = SE_RC_BUFFER_SIZE;
  return emu_id;
}
uint8_t* se_save_state_to_image(se_save_state_t * save_state, uint32_t *width, uint32_t *height){
  se_emu_id emu_id=se_get_emu_id();
  emu_id.bess_offset = se_save_best_effort_state(&save_state->state);
  emu_id.system = save_state->system;
  printf("Bess offset: %d\n",emu_id.bess_offset);
  size_t save_state_size = se_get_core_size();
  size_t net_save_state_size = sizeof(emu_id)+save_state_size+SE_RC_BUFFER_SIZE;
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
      else if(p_out-sizeof(emu_id)-save_state_size<SE_RC_BUFFER_SIZE) data = save_state->state.rc_buffer[p_out-sizeof(emu_id)-save_state_size];

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
  if(emu_state.rom_loaded==false)return false;
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
bool se_load_state_common(se_save_state_t* save_state, const char* filename, uint8_t* imdata, int im_w, int im_h){
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
      printf("ERROR: Save state:%s has non-matching emu-name:%s\n",filename, comp_id.name);
      bess=true; 
    }
    if(memcmp(&comp_id.build,&emu_id.build,sizeof(emu_id.build))){
      printf("ERROR: Save state:%s has non-matching emu-build:%s\n",filename, comp_id.build);
      bess=true; 
    }
    save_state->system = comp_id.system;
    if(!bess&&se_get_core_size()+sizeof(se_emu_id)<=data_size){
      memcpy(&(save_state->state), data+sizeof(se_emu_id), se_get_core_size());
      save_state->valid = 1; 
    }else{
      // SkyEmu versions after the RetroAchievements merge move the location of the core structure
      // which messes up bess indexing. This workaround corrects the BESS calculations so it works correctly. 
      const char * workaround_version_hashes[]={
        "311eeee4067cd12e15327b5af5db39ccecae70c6",
        "d220aa73cdd20366692983f566ae3dc0278cfd55",
        "083a2ef343dfb6da325c19127f5293ad097d8589",
        "5bac217faa64a64e21b28d8789847e3a10eedd6e",
        "830b2c0f7f6c718d945e82a465efca49b9257f24",
        "ece7aa8b3c807e449c110787021c3e0ac77f9ecb",
        "8a326fec84e0e6cf729ebfc2b1fb53368f46923e",
        "c5ece1c3c1e6ee354f99855e85e95162baad47f0",
        "7621a3b80bddb76b35f68027dec6ff8381db3e3b",
        "ebdfd7451a929fa13506a6c6a3781a8bb6d10c4e",
        NULL
      };
      const char ** curr_str = workaround_version_hashes;
      bool needs_wrong_rc_buffer_location_workaround = false;
      while(*curr_str){
        if(strcmp(*curr_str,comp_id.build)==0){needs_wrong_rc_buffer_location_workaround=true;break;}
        ++curr_str;
      }
      if(needs_wrong_rc_buffer_location_workaround){
        printf("Applying bad rc_buffer location work around for: %s\n",comp_id.build);
        comp_id.rcheevos_buffer_offset=0;
        comp_id.rcheevos_buffer_size=256*1024;
        if(se_bess_state_restore(data+comp_id.rcheevos_buffer_size, data_size-comp_id.rcheevos_buffer_size,comp_id, save_state)){
          save_state->valid = 2;
        }
      }else if(se_bess_state_restore(data, data_size,comp_id, save_state)){
        save_state->valid = 2;
      }
    }
    int rc_buffer_bytes = SE_RC_BUFFER_SIZE;
    if(rc_buffer_bytes>comp_id.rcheevos_buffer_size)rc_buffer_bytes=comp_id.rcheevos_buffer_size;
    if(comp_id.rcheevos_buffer_offset+comp_id.rcheevos_buffer_size+sizeof(se_emu_id)<=data_size){
      printf("Restoring RC Buffer %d bytes\n", rc_buffer_bytes);
      memcpy(save_state->state.rc_buffer,data+sizeof(se_emu_id)+comp_id.rcheevos_buffer_offset,rc_buffer_bytes);
    }
  }
  free(data);
  return save_state->valid;
}
bool se_load_state_from_mem(se_save_state_t* save_state, void* data, size_t data_size){
  save_state->valid = false;
  int im_w, im_h, im_c;
  uint8_t *imdata = stbi_load_from_memory(data, data_size, &im_w, &im_h, &im_c, 4);
  if(!imdata)return false;

  return se_load_state_common(save_state, NULL, imdata, im_w, im_h);
}
bool se_load_state_from_disk(se_save_state_t* save_state, const char* filename){
  save_state->valid = false;
  int im_w, im_h, im_c; 
  uint8_t *imdata = stbi_load(filename, &im_w, &im_h, &im_c, 4);
  if(!imdata)return false; 

  bool ret = se_load_state_common(save_state, filename, imdata, im_w, im_h);
  if(save_state->valid)printf("Loaded save state:%s\n",filename);
  else printf("Failed to load state from file:%s\n",filename);
  return ret;
}
double se_time(){
  static uint64_t base_time=0;
  if(base_time==0) base_time= stm_now();
  return stm_sec(stm_diff(stm_now(),base_time));
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

void se_emscripten_flush_fs(){
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
    gui_state.paths.cheat_codes
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
  se_emscripten_flush_fs();
}
void se_reset_bios_info(){
  memset(&gui_state.bios_info,0,sizeof(se_bios_info_t));
}
bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t * data, size_t data_size){
  bool loaded_bios=false;
  const char* base, *file, *ext; 
  sb_breakup_path(base_path, &base,&file, &ext);
  static char bios_path[SB_FILE_PATH_SIZE];
  static char bios_create_path[SB_FILE_PATH_SIZE];
  se_join_path(bios_path,SB_FILE_PATH_SIZE,base,file_name,NULL);
  size_t bios_bytes=0;
  strncpy(bios_create_path,bios_path,SB_FILE_PATH_SIZE);
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
    if(gui_state.settings.save_to_path)strncpy(bios_create_path,bios_path,SB_FILE_PATH_SIZE);

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
      strncpy(info->path[i],bios_create_path,sizeof(info->path[i]));
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
static int se_game_info_alpha_comparator(const void* a, const void* b){
  const int ga = *(int*)a;
  const int gb = *(int*)b;
  return strcmp(gui_state.recently_loaded_games[ga].path,gui_state.recently_loaded_games[gb].path);
}
static int se_game_info_rev_alpha_comparator(const void* a, const void* b){
  const int ga = *(int*)a;
  const int gb = *(int*)b;
  return strcmp(gui_state.recently_loaded_games[gb].path,gui_state.recently_loaded_games[ga].path);
}
static void se_sort_recent_games_list(){
  int size = 0; 
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    if(gui_state.recently_loaded_games[i].path[0]=='\0')gui_state.sorted_recently_loaded_games[i]=-1;
    else{
      gui_state.sorted_recently_loaded_games[i]=i;
      size++;
    }
  }
  if(gui_state.recent_games_sort_type==SE_SORT_ALPHA_ASC)qsort(gui_state.sorted_recently_loaded_games,size,sizeof(int),se_game_info_alpha_comparator);
  else if(gui_state.recent_games_sort_type==SE_SORT_ALPHA_DESC)qsort(gui_state.sorted_recently_loaded_games,size,sizeof(int),se_game_info_rev_alpha_comparator);
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
  se_sort_recent_games_list();
}
static void se_load_recent_games_list(){
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
  se_sort_recent_games_list();
}

static void se_clear_game_from_recents(int index) {
  gui_state_t* gui = &gui_state;
  strcpy(gui->recently_loaded_games[index].path, "");
  for(int i=index+1;i<SE_NUM_RECENT_PATHS;++i){
    strcpy(gui->recently_loaded_games[i-1].path, gui->recently_loaded_games[i].path);
    if (i == SE_NUM_RECENT_PATHS-1) {
      strcpy(gui->recently_loaded_games[i].path, "");
      break;
    }
  }
  se_save_recent_games_list();
}

bool se_key_is_pressed(int keycode){
  if(keycode>SAPP_MAX_KEYCODES||keycode==-1)return false;
  // Don't let keyboard input reach emulator when ImGUI is capturing it. 
  // Allow inputs if the touch screen is being pressed as the screen is an ImGUI object that 
  // registers drag events. 
  if(igGetIO()->WantCaptureKeyboard && ! emu_state.joy.inputs[SE_KEY_PEN_DOWN] )return false; 
  return gui_state.button_state[keycode];
}
static sg_image* se_get_image(){
  se_deferred_image_free_t * tmp_image = (se_deferred_image_free_t*)calloc(1,sizeof(se_deferred_image_free_t));
  tmp_image->next = gui_state.image_free_list;
  gui_state.image_free_list = tmp_image;
  return &tmp_image->image;
}
static void se_free_image_deferred(sg_image image){
  se_deferred_image_free_t * tmp_image = (se_deferred_image_free_t*)calloc(1,sizeof(se_deferred_image_free_t));
  tmp_image->next = gui_state.image_free_list;
  tmp_image->image=image;
  gui_state.image_free_list = tmp_image;
}
static void se_free_all_images(){
  while(gui_state.image_free_list){
    se_deferred_image_free_t * tmp = gui_state.image_free_list;
    sg_destroy_image(tmp->image);
    gui_state.image_free_list=tmp->next;
    free(tmp);
  }
}
typedef uint8_t (*emu_byte_read_t)(uint64_t address);
typedef void (*emu_byte_write_t)(uint64_t address,uint8_t data);
typedef sb_debug_mmio_access_t (*emu_mmio_access_type)(uint64_t address, int trigger_breakpoint);

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
    if(fabs(stats->waveform_fps_render[i])>1.0){
      render_avg+=1.0/stats->waveform_fps_render[i];
      render_data_points++;
    }
    

    if(stats->waveform_fps_emulation[i]>emulate_max)emulate_max=stats->waveform_fps_emulation[i];
    if(stats->waveform_fps_emulation[i]<emulate_min)emulate_min=stats->waveform_fps_emulation[i];
    if(fabs(stats->waveform_fps_emulation[i])>1.0){
      emulate_avg+=1.0/fabs(stats->waveform_fps_emulation[i]);
      ++emulate_data_points;
    }
  }
  if(render_data_points<1)render_data_points=1;
  if(emulate_data_points<1)emulate_data_points=1;
  render_avg/=render_data_points;
  render_avg=1.0/render_avg;
  emulate_avg/=emulate_data_points;
  emulate_avg=1.0/emulate_avg;
  if(stats->waveform_fps_emulation[SE_STATS_GRAPH_DATA-1]<0)emulate_avg*=-1;

  stats->waveform_fps_render[SE_STATS_GRAPH_DATA-1] = fps_render;

  for(int i=0;i<SE_STATS_GRAPH_DATA;++i){
    float l = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.write_ptr-i*2-2)%SB_AUDIO_RING_BUFFER_SIZE]/32768.;
    float r = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.write_ptr-i*2-1)%SB_AUDIO_RING_BUFFER_SIZE]/32768.;
    stats->waveform_l[i]=l;
    stats->waveform_r[i]=r;
  }

  float content_width = igGetWindowContentRegionWidth();
  se_section(ICON_FK_CLOCK_O " FPS");
  char label_tmp[128];
  snprintf(label_tmp,128,se_localize_and_cache("Display FPS: %2.1f\n"),render_avg);
  igPlotLinesFloatPtr("",stats->waveform_fps_render,SE_STATS_GRAPH_DATA,0,label_tmp,0,render_max*1.3,(ImVec2){content_width,80},4);

  snprintf(label_tmp,128,se_localize_and_cache("Emulation FPS: %2.1f\n"),emulate_avg);
  igPlotLinesFloatPtr("",stats->waveform_fps_emulation,SE_STATS_GRAPH_DATA,0,label_tmp,emulate_min,emulate_max*1.3,(ImVec2){content_width,80},4);
  
  se_section(ICON_FK_VOLUME_UP " Audio");
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

  se_section(ICON_FK_INFO_CIRCLE " Build Info");
  se_text("%s (%s)", se_get_host_platform(),se_get_host_arch());
  se_text("Branch \"%s\" built on %s %s", GIT_BRANCH, __DATE__, __TIME__);
  se_text("Commit Hash:");
  igPushItemWidth(-1);
  igInputText("##COMMIT_HASH",GIT_COMMIT_HASH,sizeof(GIT_COMMIT_HASH),ImGuiInputTextFlags_ReadOnly,NULL,NULL);
  igPopItemWidth();

}
#ifdef ENABLE_RETRO_ACHIEVEMENTS
uint32_t retro_achievements_read_memory_callback(uint32_t address, uint8_t* buffer, uint32_t num_bytes, rc_client_t* client){
  if(emu_state.system==SYSTEM_GB){
    if (address >= 0x00D000U && address <= 0x00DFFFU) {
      // this region is always mapped to WRAM bank 1 (unlike during normal gbc operation)
      uint8_t* wram = &core.gb.mem.wram[(SB_WRAM_BANK_SIZE * 1) + address - 0x00D000U];
      for(int j=0;j<num_bytes;j++){
        buffer[j]=wram[j];
      }
      return num_bytes;
    } else if (address < 0x010000U) {
      // these follow the normal gb memory map
      for(int j=0;j<num_bytes;j++){
        buffer[j]=sb_read8(&core.gb,address+j);
      }
      return num_bytes;
    } else if (address <= 0x015FFFU) {
      // 0x10000 - 0x15FFF is WRAM banks 2-7
      uint8_t* wram = &core.gb.mem.wram[(SB_WRAM_BANK_SIZE * 2) + address - 0x010000U];
      for(int j=0;j<num_bytes;j++){
        buffer[j]=wram[j];
      }
      return num_bytes;
    }
    printf("GB address %08x not found\n",address);
  }else if(emu_state.system==SYSTEM_GBA){
    const rc_memory_regions_t* regions = rc_console_memory_regions(RC_CONSOLE_GAMEBOY_ADVANCE);
    for (int i=0;i<regions->num_regions;i++) {
      const rc_memory_region_t* region = &regions->region[i];
      if (address >= 0x048000U && address <= 0x057FFFU) { // handle eeprom region specially
        for (int j=0;j<num_bytes;j++){
          buffer[j]=core.gba.mem.cart_backup[address-0x048000U+j];
        }
        return num_bytes;
      } else if (address >= region->start_address && address <= region->end_address) {
        for(int j=0;j<num_bytes;j++){
          buffer[j]=gba_read8(&core.gba,region->real_address+(address-region->start_address)+j);
        }
        return num_bytes;
      }
    }
    printf("GBA address %08x not found\n",address);
  }else if(emu_state.system==SYSTEM_NDS){
    const rc_memory_regions_t* regions = rc_console_memory_regions(RC_CONSOLE_NINTENDO_DS);
    for (int i=0;i<regions->num_regions;i++) {
      const rc_memory_region_t* region = &regions->region[i];
      if (address >= region->start_address && address <= region->end_address) {
        for(int j=0;j<num_bytes;j++){
          buffer[j]=nds9_read8(&core.nds,region->real_address+(address-region->start_address)+j);
        }
        return num_bytes;
      }
    }
    printf("NDS address %08x not found\n",address);
  }
  return 0;
}
#endif
void se_psg_debugger(){

  // NOTE: GB and GBA framesequencer should each contain the same struct data
  sb_frame_sequencer_t* seq = emu_state.system == SYSTEM_GB ? &core.gb.audio.sequencer : (sb_frame_sequencer_t*)&core.gba.audio.sequencer;

  for(int i=0;i<4;++i){
    se_section("Channel %d",i+1);
    se_checkbox("Active", &seq->active[i]);
    se_checkbox("Powered", &seq->powered[i]);
    se_text("Channel t: %f",seq->chan_t[i]);
    se_checkbox("Use Length", &seq->use_length[i]);
    se_input_int32("Length", &seq->length[i],1,10,ImGuiInputTextFlags_None);
    se_input_uint32("Volume", &seq->volume[i],1,10,ImGuiInputTextFlags_None);
    se_input_uint32("Frequency", &seq->frequency[i],1,10,ImGuiInputTextFlags_None);
    
    if(i==0){
      se_checkbox("Sweep Enable", &seq->sweep_enable);
    se_input_int32("Sweep Dir.", &seq->sweep_direction,1,10,ImGuiInputTextFlags_None);
      se_input_uint32("Sweep Timer", &seq->sweep_timer,1,10,ImGuiInputTextFlags_None);
      se_input_uint32("Sweep Period", &seq->sweep_period,1,10,ImGuiInputTextFlags_None);
      se_input_uint32("Sweep Shift", &seq->sweep_shift,1,10,ImGuiInputTextFlags_None);
    }
    se_input_int32("Env Dir.", &seq->env_direction[i],1,10,ImGuiInputTextFlags_None);
    se_input_uint32("Env Period", &seq->env_period[i],1,10,ImGuiInputTextFlags_None);
    se_input_uint32("Env Timer", &seq->env_period_timer[i],1,10,ImGuiInputTextFlags_None);
    se_checkbox("Env Overflowed", &seq->env_overflow[i]);

    if(i==3){
      se_text("LFSR Value: %04x",seq->lfsr4);
    }
  }
}
void se_draw_arm_state(const char* label, arm7_t *arm, emu_byte_read_t read){
  const char* reg_names[]={"R0","R1","R2","R3","R4","R5","R6","R7","R8","R9 (SB)","R10 (SL)","R11 (FP)","R12 (IP)","R13 (SP)","R14 (LR)","R15 (" ICON_FK_BUG ")","CPSR","SPSR",NULL}; // NOLINT
  if(se_button("Step Instruction",(ImVec2){0,0})){
    arm->step_instructions=1;
    emu_state.run_mode= SB_MODE_RUN;
  }
  igSameLine(0,4);
  if(se_button("Step Frame",(ImVec2){0,0})){
    emu_state.step_frames=1;
    emu_state.run_mode=SB_MODE_STEP;
  }
  if(arm->log_cmp_file){
    igSameLine(0,0);
    if(se_button("Disconnect Log",(ImVec2){0,0})){
      fclose(arm->log_cmp_file);
      arm->log_cmp_file=NULL;
    }
  }
  int r = 0; 
  se_section(ICON_FK_SERVER " Registers");
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
    if(x!=0)igSameLine((float)x*w/4,0);
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
  se_section(ICON_FK_LIST_OL " Disassembly");
  csh handle;
  if (cs_open(CS_ARCH_ARM, thumb? CS_MODE_THUMB: CS_MODE_ARM, &handle) == CS_ERR_OK){
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_insn *insn;
    int count = cs_disasm(handle, buffer, buffer_size, pc-off, 0, &insn);
    size_t j;
    for (j = 0; j < count; j++) {      
      if(insn[j].address==pc){
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
        se_text("PC" ICON_FK_ARROW_RIGHT);
      }else se_text("");
      ImVec4 text_color = *igGetStyleColorVec4(ImGuiCol_Text);
      text_color.w*=0.5;
      igPushStyleColorVec4(ImGuiCol_Text, text_color);
      igSameLine(32,0);
      se_text("0x%08x:", (int)insn[j].address);
      igPopStyleColor(1);
      igSameLine(102,0);
      se_text(insn[j].mnemonic);
      igSameLine(150,0);
      text_color = *igGetStyleColorVec4(ImGuiCol_Text);
      float ratio = 0.3; 
      text_color.x*=1.0-ratio;
      text_color.y*=1.0-ratio;
      text_color.z*=1.0-ratio;
      text_color.z+=ratio;
      if(text_color.z<ratio*2)text_color.z+=ratio;
      igPushStyleColorVec4(ImGuiCol_Text, text_color);
      se_text(insn[j].op_str);
      igPopStyleColor(1);
      if(insn[j].address==pc)igPopStyleColor(1);
    }  
  }
  bool clear_step_data = emu_state.run_mode!=SB_MODE_PAUSE;
  se_section(ICON_FK_RANDOM " Last Branch Locations");
  igBeginChildStr(("##BranchLoc"),(ImVec2){0,150},true,ImGuiWindowFlags_None);
  for(int i=0;i<ARM_DEBUG_BRANCH_RING_SIZE&&i<arm->debug_branch_ring_offset;++i){
    uint32_t ind = (arm->debug_branch_ring_offset-i-1);
    ind%=ARM_DEBUG_BRANCH_RING_SIZE;
    se_text("%d",i+1);
    igSameLine(60,0);
    se_text("0x%08x",arm->debug_branch_ring[ind]);
  }
  igEndChild();
  if(clear_step_data)arm->debug_branch_ring_offset=0;
  se_section("SWI");
  igBeginChildStr(("##SWI"),(ImVec2){0,150},true,ImGuiWindowFlags_None);
  for(int i=0;i<ARM_DEBUG_SWI_RING_SIZE&&i<arm->debug_swi_ring_offset;++i){
    uint32_t ind = (arm->debug_swi_ring_offset-i-1);
    ind%=ARM_DEBUG_SWI_RING_SIZE;
    se_text("%d",i+1);
    igSameLine(60,0);
    if(arm->debug_swi_ring_times[ind]>=2)se_text("SWI 0x%02x (%dx)",arm->debug_swi_ring[ind],arm->debug_swi_ring_times[ind]);
    else se_text("SWI 0x%02x",arm->debug_swi_ring[ind]);
  }
  igEndChild();
  if(clear_step_data)arm->debug_swi_ring_offset=0;

}

void gb_cpu_debugger(){
  sb_gb_t* gb = &core.gb;
  sb_gb_cpu_t *cpu_state = &gb->cpu;
  if(se_button("Step Instruction",(ImVec2){0,0})){
    emu_state.step_instructions=1;
    emu_state.run_mode= SB_MODE_STEP;
  }
  igSameLine(0,4);
  if(se_button("Step Frame",(ImVec2){0,0})){
    emu_state.step_frames=1;
    emu_state.run_mode=SB_MODE_STEP;
  }
  

  const char *register_names_16b[] = {"AF", "BC", "DE", "HL", "SP", "PC", NULL};

  int register_values_16b[] = {cpu_state->af, cpu_state->bc, cpu_state->de,
                               cpu_state->hl, cpu_state->sp, cpu_state->pc};

  const char *register_names_8b[] = {"A", "F", "B", "C", "D",
                                     "E", "H", "L", NULL};

  int register_values_8b[] = {
      SB_U16_HI(cpu_state->af), SB_U16_LO(cpu_state->af),
      SB_U16_HI(cpu_state->bc), SB_U16_LO(cpu_state->bc),
      SB_U16_HI(cpu_state->de), SB_U16_LO(cpu_state->de),
      SB_U16_HI(cpu_state->hl), SB_U16_LO(cpu_state->hl),
  };

  const char *flag_names[] = {"Z", "N", "H", "C","Inter. En.", "Prefix", "Wait Inter",  NULL};

  bool flag_values[] = {
      SB_BFE(cpu_state->af, SB_Z_BIT, 1), // Z
      SB_BFE(cpu_state->af, SB_N_BIT, 1), // N
      SB_BFE(cpu_state->af, SB_H_BIT, 1), // H
      SB_BFE(cpu_state->af, SB_C_BIT, 1), // C
      cpu_state->interrupt_enable,
      cpu_state->prefix_op,
      cpu_state->wait_for_interrupt
  };
  int w= igGetWindowWidth();
  int r = 0; 
  se_section(ICON_FK_SERVER " 16b Registers");
  while(register_names_16b[r]){
    int value = register_values_16b[r];
    if(r%2){
      igSetNextItemWidth(-50);
      igSameLine(w*0.5,0);
    }else igSetNextItemWidth((w-100)*0.5);
    se_input_int(register_names_16b[r],&value, 0,0,ImGuiInputTextFlags_CharsHexadecimal);
    ++r;
  }
  r = 0; 
  se_section(ICON_FK_SERVER " 8b Registers");
  while(register_names_8b[r]){
    int value = register_values_8b[r];
    if(r%2){
      igSetNextItemWidth(-50);
      igSameLine(w*0.5,0);
    }else igSetNextItemWidth((w-100)*0.5);
    se_input_int(register_names_8b[r],&value, 0,0,ImGuiInputTextFlags_CharsHexadecimal);
    ++r;
  }
  r = 0; 
  se_section(ICON_FK_SERVER " Flag Registers");
  while(flag_names[r]){
    bool value = flag_values[r];
    if(r%2){
      igSetNextItemWidth(-50);
      igSameLine(w*0.5,0);
    }else igSetNextItemWidth((w-100)*0.5);
    se_checkbox(flag_names[r],&value);
    ++r;
  }
  se_section(ICON_FK_SERVER " Instructions"); 
  for (int i = -6; i < 5; ++i) {
      char instr_str[80];
      int pc_render = i + cpu_state->pc;
      int opcode = sb_read8(gb, pc_render);
      if(pc_render== cpu_state->pc){
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
        se_text("PC" ICON_FK_ARROW_RIGHT);
      }else se_text("");
      ImVec4 text_color = *igGetStyleColorVec4(ImGuiCol_Text);
      text_color.w*=0.5;
      igPushStyleColorVec4(ImGuiCol_Text, text_color);
      igSameLine(32,0);
      se_text("0x%04x:", (int)pc_render);
      igPopStyleColor(1);
      igSameLine(102,0);
      se_text(sb_decode_table[opcode].opcode_name);
      if(pc_render== cpu_state->pc)igPopStyleColor(1);
    }  
}
void se_draw_mem_debug_state(const char* label, gui_state_t* gui, emu_byte_read_t read,emu_byte_write_t write){
  se_section(ICON_FK_EXCHANGE " Read/Write Memory Address");
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
  se_section(ICON_FK_FILE_O " Dump Memory to File");
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
void gb_tile_map_debugger(){
  sb_gb_t *gb = &core.gb;
  static uint8_t tmp_image[512*512*3];

  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  int bg_tile_map_base      = SB_BFE(ctrl,3,1)==1 ? 0x9c00 : 0x9800;
  int bg_win_tile_data_mode = SB_BFE(ctrl,4,1)==1;
  int win_tile_map_base      = SB_BFE(ctrl,6,1)==1 ? 0x9c00 : 0x9800;

  ImVec2 win;
  igGetWindowPos(&win);

  // Draw Tilemaps
  for(int tile_map = 0;tile_map<2;++tile_map){
    int image_height = 32*(8+2);
    int image_width =  32*(8+2);
    float scale = igGetWindowContentRegionWidth()/image_width; 

    int wx = sb_read8_direct(gb, SB_IO_LCD_WX)-7;
    int wy = sb_read8_direct(gb, SB_IO_LCD_WY);
    int sx = sb_read8_direct(gb, SB_IO_LCD_SX);
    int sy = sb_read8_direct(gb, SB_IO_LCD_SY);

    int box_x1 = tile_map ==0 ? sx : wx;
    int box_x2 = box_x1+(SB_LCD_W-1);
    int box_y1 = tile_map ==0 ? sy : wy;
    int box_y2 = box_y1+(SB_LCD_H-1);
    int tile_map_base = tile_map==0? bg_tile_map_base:win_tile_map_base;
    se_section("%s Tile Map",tile_map == 0  ? "Background" : "Window");
    int x = igGetCursorPosX()+win.x-igGetScrollX();
    int y = igGetCursorPosY()+win.y-igGetScrollY();
    int w = image_width*scale;
    int h = image_height*scale;
    int scanline = tile_map==0 ? gb->lcd.curr_scanline +sy : gb->lcd.curr_window_scanline;
    for(int yt = 0; yt<32;++yt)
      for(int xt = 0; xt<32;++xt)
        for(int py = 0;py<8;++py)
          for(int px = 0;px<8;++px){
            int x = xt*8+px;
            int y = yt*8+py;
            int color_id = sb_lookup_tile(gb,x,y,tile_map_base,bg_win_tile_data_mode);
            int p = (xt*10+(px)+1)+(yt*10+py+1)*image_width;
            int r=0,g=0,b=0;
            sb_lookup_palette_color(gb,color_id,&r,&g,&b);
            if(((x==(box_x1%256)||x==(box_x2%256)) && (((y-box_y1)&0xff)>=0 && ((box_y2-y)&0xff) <=box_y2-box_y1))||
               ((y==(box_y1%256)||y==(box_y2%256)) && (((x-box_x1)&0xff)>=0 && ((box_x2-x)&0xff) <=box_x2-box_x1))){
               r=255; g=b=0;
            }
            if(y == (scanline&0xff) &&(((x-box_x1)&0xff)>=0 && (((x-box_x1)&0xff)>=0 && ((box_x2-x)&0xff) <=box_x2-box_x1))){
              b = 255;  r=g=0;
            }
            tmp_image[p*3+0]=r;
            tmp_image[p*3+1]=g;
            tmp_image[p*3+2]=b;
          }

    se_draw_image(tmp_image,image_width,image_height, x*se_dpi_scale(), y*se_dpi_scale(), w*se_dpi_scale(),h*se_dpi_scale(), false);
    igDummy((ImVec2){w,h});
    
    const char * name = tile_map == 0  ? "Background" : "Window";
    ImVec2 mouse_pos = {gui_state.mouse_pos[0]/se_dpi_scale(),gui_state.mouse_pos[1]/se_dpi_scale()};
    mouse_pos.x-=x;
    mouse_pos.y-=y;
    if(mouse_pos.x<w && mouse_pos.y <h &&
      mouse_pos.x>=0 && mouse_pos.y>=0){
      int tx = (mouse_pos.x -1)/w*32;
      int ty = (mouse_pos.y -1)/h*32;
      int t = tx+ty*32;
      int tile_data0 = sb_read_vram(gb, tile_map_base+t,0);
      int tile_data1 = sb_read_vram(gb, tile_map_base+t,1);
      se_text("Tile (%d, %d) Index=0x%02x Attr=0x%02x)",tx,ty,tile_data0,tile_data1);
    }else se_text("No tile hovered");
  }
}
void gb_tile_data_debugger(){
  sb_gb_t *gb= &core.gb;
  static uint8_t tmp_image[512*512*3];
  ImVec2 win;
  igGetWindowPos(&win);

  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  int bg_tile_map_base      = SB_BFE(ctrl,3,1)==1 ? 0x9c00 : 0x9800;
  int bg_win_tile_data_mode = SB_BFE(ctrl,4,1)==1;
  int win_tile_map_base      = SB_BFE(ctrl,6,1)==1 ? 0x9c00 : 0x9800;

  // Draw tile data arrays
  for(int tile_data_bank = 0;tile_data_bank<SB_VRAM_NUM_BANKS;++tile_data_bank){
    se_section("Tile Data Bank %d\n",tile_data_bank);
    int tiles_per_row = 16;
    int image_height = 384/tiles_per_row*(8+2);
    int image_width =  tiles_per_row*(8+2);
    float scale = igGetWindowContentRegionWidth()/image_width; 
    int x = igGetCursorPosX()+win.x-igGetScrollX();
    int y = igGetCursorPosY()+win.y-igGetScrollY();
    int w = image_width*scale;
    int h = image_height*scale;

    ImVec2 mouse_pos = {gui_state.mouse_pos[0]/se_dpi_scale(),gui_state.mouse_pos[1]/se_dpi_scale()};
    mouse_pos.x-=x;
    mouse_pos.y-=y;

    int tile_data_base = 0x8000;
    for(int t=0;t<384;++t){
      int xt = (t%tiles_per_row)*10;
      int yt = (t/tiles_per_row)*10;

      for(int py = 0;py<8;++py)
        for(int px = 0;px<8;++px){
          int d = tile_data_base+py*2+ t*16;
          uint8_t data1 = sb_read_vram(gb,d,tile_data_bank);
          uint8_t data2 = sb_read_vram(gb,d+1,tile_data_bank);
          uint8_t value = SB_BFE(data1,px,1)+SB_BFE(data2,px,1)*2;
          uint8_t color = value*80;
          int p = (xt+(7-px)+1)+(yt+py+1)*image_width;
          tmp_image[p*3+0]=color;
          tmp_image[p*3+1]=color;
          tmp_image[p*3+2]=color;
        }
    }
    se_draw_image(tmp_image,image_width,image_height, x*se_dpi_scale(), y*se_dpi_scale(), w*se_dpi_scale(),h*se_dpi_scale(), false);
    igDummy((ImVec2){w,h});

    if(mouse_pos.x<w && mouse_pos.y <h &&
      mouse_pos.x>=0 && mouse_pos.y>=0){
      int px = (mouse_pos.x -1)/w*image_width;
      int py = (mouse_pos.y -1)/h*image_height;

      int tx = px/8;
      int ty = py/8;
      px%=8;
      py%=8;
      int t = tx+ty*32;
      int d = tile_data_base+py*2+ t*16;
      uint8_t data1 = sb_read_vram(gb,d,tile_data_bank);
      uint8_t data2 = sb_read_vram(gb,d+1,tile_data_bank);
      uint8_t value = SB_BFE(data1,px,1)+SB_BFE(data2,px,1)*2;
      se_text("Tile 0x%02x tx:%d ty:%d color:%d",t&0xff,px,py,value);
    }else se_text("No tile hovered");
  }
}

void se_draw_io_state(const char * label, mmio_reg_t* mmios, int mmios_size, emu_byte_read_t read, emu_byte_write_t write, emu_mmio_access_type access_type){
  for(int i = 0; i<mmios_size;++i){
    uint32_t addr = mmios[i].addr;
    bool has_fields = false;
    igPushIDInt(i);
    char lab[80];
    sb_debug_mmio_access_t access={0};
    if(access_type)access=access_type(addr,-1);
    else{
      access.read_since_reset=true;
      access.write_since_reset=true;
    }
    snprintf(lab,80,"0x%08x: %s %s%s",addr,mmios[i].name,access.write_in_tick?ICON_FK_PENCIL_SQUARE_O:"",access.read_in_tick?ICON_FK_SEARCH:"");
    if (igTreeNodeStrStr(mmios[i].name,lab)){
      uint32_t data = se_read32(read, addr);
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
        igPopItemWidth();
        igSameLine(0,2);
        se_text("Data");
        igPopID();
      }
      igSeparator();
      if(se_checkbox("CPU breakpoint on access",&access.trigger_breakpoint)){
          access_type(addr,access.trigger_breakpoint);
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
static const char* valid_rom_file_types[] = { "*.gb", "*.gba","*.gbc" ,"*.nds","*.zip",NULL};
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
  se_reset_cheats();
  gui_state.editing_cheat_index = -1;
  se_reset_bios_info();
  emu_state.force_dmg_mode=gui_state.settings.force_dmg_mode;
  //Compute Save File Path
  {
    char *save_file=emu_state.save_file_path; 
    save_file[0] = '\0';
    const char* base, *c, *ext; 
    sb_breakup_path(filename,&base, &c, &ext);
  #if defined(EMSCRIPTEN)
      if(sb_path_has_file_ext(filename,".sav")||sb_path_has_file_ext(filename,".code")){
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

      if(sb_file_exists(tmp_path)||gui_state.settings.save_to_path){
        se_join_path(emu_state.save_data_base_path,SB_FILE_PATH_SIZE,gui_state.paths.save,c,NULL);
        strncpy(save_file,tmp_path,SB_FILE_PATH_SIZE);
      }
    }
  }
  //Compute Cheat Code File Path
  {
    char *cheat_path=gui_state.cheat_path; 
    cheat_path[0] = '\0';
    const char* base, *c, *ext; 
    sb_breakup_path(filename,&base, &c, &ext);
    snprintf(cheat_path, SB_FILE_PATH_SIZE, "%s.code",emu_state.save_data_base_path);
    if(!sb_file_exists(cheat_path)){
      const char* base, *c, *ext; 
      sb_breakup_path(filename,&base, &c, &ext);
      char tmp_path[SB_FILE_PATH_SIZE];
      se_join_path(tmp_path,SB_FILE_PATH_SIZE,gui_state.paths.cheat_codes,c,".code");
      if(sb_file_exists(tmp_path)||gui_state.settings.save_to_path){
        strncpy(cheat_path,tmp_path,SB_FILE_PATH_SIZE);
      }
    }
    se_load_cheats(cheat_path);
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
    printf("Reading zip\n");
    mz_zip_archive zip = {0};
    mz_zip_zero_struct(&zip);
    if(mz_zip_reader_init_file(&zip, filename, 0)){
      size_t total_files = mz_zip_reader_get_num_files(&zip);
      for(size_t i=0;i<total_files;++i){
        char file_name_buff[SB_FILE_PATH_SIZE];
        uint8_t *file_data = NULL;
        bool success= true;
        mz_zip_reader_get_filename(&zip, i, file_name_buff, SB_FILE_PATH_SIZE);
        file_name_buff[SB_FILE_PATH_SIZE-1]=0;
        mz_zip_archive_file_stat stat={0};
        success&= mz_zip_reader_file_stat(&zip,i, &stat);
        success&= !stat.m_is_directory;
        snprintf(emu_state.rom_path,sizeof(emu_state.rom_path),"%s/%s",filename,file_name_buff);
        if(success){
          file_data = (uint8_t *)malloc(stat.m_uncomp_size);
          success&= mz_zip_reader_extract_to_mem(&zip,i,file_data, stat.m_uncomp_size,0);
          if(!success){
              if(zip.m_last_error==MZ_ZIP_UNSUPPORTED_METHOD)
                  printf("Unsupported compression method, supported: deflate\n");
              free(file_data);
          }else{
              emu_state.rom_size = stat.m_uncomp_size;
              emu_state.rom_data = file_data;
          }
        }
        if(success)se_load_rom_from_emu_state(&emu_state);
        if(emu_state.rom_loaded)break;
      }
      mz_zip_reader_end(&zip);
    }else printf("Failed to read zip\n");

  }else{
    emu_state.rom_data = sb_load_file_data(emu_state.rom_path, &emu_state.rom_size);
    se_load_rom_from_emu_state(&emu_state);
  }
  if(emu_state.rom_loaded==false){
    printf("ERROR: failed to load ROM: %s\n", filename);
    emu_state.run_mode= SB_MODE_PAUSE;
  }else{
    emu_state.run_mode= SB_MODE_RUN;
    emu_state.step_frames = 1; 
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
  emu_state.game_checksum = cloud_drive_hash((const char*)emu_state.rom_data,emu_state.rom_size);
  se_sync_cloud_save_states();
  #ifdef ENABLE_RETRO_ACHIEVEMENTS
  gui_state.ra_needs_reload=true;
  #endif
}
static void se_reset_core(){
  if(emu_state.rom_loaded==false)return; 
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
  if(emu_state.system==SYSTEM_NDS)return nds_save_best_effort_state(&state->nds);
  return -1; 
}
static bool se_load_best_effort_state(se_core_state_t* state,uint8_t *save_state_data, uint32_t size, uint32_t bess_offset){
  if(emu_state.system==SYSTEM_GB)return sb_load_best_effort_state(&state->gb,save_state_data,size,bess_offset);
  if(emu_state.system==SYSTEM_GBA)return gba_load_best_effort_state(&state->gba,save_state_data,size,bess_offset);
  if(emu_state.system==SYSTEM_NDS)return nds_load_best_effort_state(&state->nds,save_state_data,size,bess_offset);
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

#ifdef ENABLE_RETRO_ACHIEVEMENTS
  if (rc_client_get_user_info(retro_achievements_get_client())){
    if (gui_state.ra_needs_reload) {
      rc_client_set_encore_mode_enabled(retro_achievements_get_client(), gui_state.ra_encore_mode);
      rc_client_set_hardcore_enabled(retro_achievements_get_client(), gui_state.settings.hardcore_mode);
      if (retro_achievements_load_game()) {
        gui_state.ra_needs_reload = false;
      }
    } else {
      retro_achievements_frame();
    }
  }
#endif
  se_run_all_ar_cheats(se_run_ar_cheat);
}
static void se_screenshot(uint8_t * output_buffer, int * out_width, int * out_height){
  *out_height=*out_width=0;
  // output_bufer is always SE_MAX_SCREENSHOT_SIZE bytes. RGB8
  if(emu_state.system==SYSTEM_GBA){
    *out_width = GBA_LCD_W;
    *out_height = GBA_LCD_H;
    memcpy(output_buffer,scratch.gba.framebuffer,GBA_LCD_W*GBA_LCD_H*4);
  }else if (emu_state.system==SYSTEM_NDS){
    *out_width = NDS_LCD_W;
    *out_height = NDS_LCD_H*2;
    memcpy(output_buffer,scratch.nds.framebuffer_top,NDS_LCD_W*NDS_LCD_H*4);
    memcpy(output_buffer+NDS_LCD_W*NDS_LCD_H*4,scratch.nds.framebuffer_bottom,NDS_LCD_W*NDS_LCD_H*4);
  }else if (emu_state.system==SYSTEM_GB){
    *out_width = SB_LCD_W;
    *out_height = SB_LCD_H;
    memcpy(output_buffer,scratch.gb.framebuffer,SB_LCD_W*SB_LCD_H*4);
  }
  for(int i=3;i<SE_MAX_SCREENSHOT_SIZE;i+=4)output_buffer[i]=0xff;
}
typedef struct{
  uint8_t *data;
  int im_width; 
  int im_height;
  int x;
  int y;
  int render_width;
  int render_height;
  float rotation;
  bool is_touch;
}se_draw_lcd_callback_t;
void se_draw_lcd_callback(const ImDrawList* parent_list, const ImDrawCmd* cmd){
  if(cmd->UserCallbackData==NULL)return;
  se_draw_lcd_callback_t *call = (se_draw_lcd_callback_t*)cmd->UserCallbackData;
  se_draw_lcd(call->data,call->im_width,call->im_height,call->x,call->y,call->render_width,call->render_height,call->rotation,call->is_touch);
  free(call);
}
void se_draw_lcd_defer(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, float rotation,bool is_touch){
  se_draw_lcd_callback_t *call = (se_draw_lcd_callback_t*)malloc(sizeof(se_draw_lcd_callback_t));
  call->data = data;
  call->im_width=im_width;
  call->im_height=im_height;
  call->x = x;
  call->y = y;
  call->render_width=render_width;
  call->render_height=render_height;
  call->rotation=rotation;
  call->is_touch=is_touch;
  ImDrawList_AddCallback(igGetWindowDrawList(),se_draw_lcd_callback,call);
}
static void se_draw_emulated_system_screen(bool preview){
  float scr_w = igGetWindowWidth();
  float scr_h = igGetWindowHeight();

  if(preview==true){
    scr_w *=se_dpi_scale();
    scr_h *=se_dpi_scale();
  }
  int nds_layout=gui_state.settings.nds_layout; 
  float rotation = gui_state.settings.screen_rotation*0.5*3.14159;

  float dims[2]={scr_w/se_dpi_scale(),scr_h/se_dpi_scale()};
  bool portrait = false; 
  float min_dim = se_compute_touchscreen_controls_min_dim(scr_w,scr_h, &portrait);
  bool touch_controller_active = gui_state.last_touch_time>=0||gui_state.settings.auto_hide_touch_controls==false;
  if(!touch_controller_active)min_dim = 0;

  float native_w = dims[0], native_h = dims[1];
  se_compute_draw_lcd_rect(&native_w, &native_h, &nds_layout);
  
  ImVec2 win_pos;
  igGetWindowPos(&win_pos);

  int result =0;
  if(!gui_state.settings.show_screen_bezel)result = se_draw_theme_region(SE_REGION_NO_BEZEL, win_pos.x,win_pos.y,dims[0],dims[1]);

  if(!result)result =  se_draw_theme_region(portrait?SE_REGION_BEZEL_PORTRAIT:SE_REGION_BEZEL_LANDSCAPE, win_pos.x,win_pos.y,dims[0],dims[1]);
  if(!result)result = se_draw_theme_region(SE_REGION_BEZEL_PORTRAIT, win_pos.x,win_pos.y,dims[0],dims[1]);
  
  float pad_x = scr_h/se_dpi_scale()*0.025;
  // Handle themes where there is no controller region, or when screen overlap is allowed. 
  if(!(result&SE_THEME_DREW_CONTROLLER)&&(!gui_state.block_touchscreen||preview)){
    float x = win_pos.x+pad_x; 
    float y = win_pos.y+pad_x; 
    float w = scr_w/se_dpi_scale()-pad_x*2;
    float h = scr_h/se_dpi_scale()-pad_x*2;
    float min_dim_adj=min_dim*0.5;
  
    if(h>min_dim_adj){
      if(portrait)y+=h-min_dim_adj;
      else y+=(h-min_dim_adj)*0.5;
      h=min_dim_adj;
    }

    
    
    float adj_w = w;
    if(adj_w>min_dim_adj)adj_w=min_dim_adj;
    se_draw_onscreen_controller(&emu_state, SE_GAMEPAD_LEFT,x,y,adj_w*0.5,h, preview,false);
    se_draw_onscreen_controller(&emu_state, SE_GAMEPAD_RIGHT,x+w-adj_w*0.5,y,adj_w*0.5,h, preview,false);
  }
}
static uint8_t gba_byte_read(uint64_t address){return gba_read8_debug(&core.gba,address);}
static void gba_byte_write(uint64_t address, uint8_t data){gba_store8_debug(&core.gba,address,data);}

static uint8_t gb_byte_read(uint64_t address){return sb_read8(&core.gb,address);}
static void gb_byte_write(uint64_t address, uint8_t data){sb_store8(&core.gb,address,data);}

static uint8_t nds9_byte_read(uint64_t address){return nds9_debug_read8(&core.nds,address);}
static void nds9_byte_write(uint64_t address, uint8_t data){nds9_debug_write8(&core.nds,address,data);}
static uint8_t nds7_byte_read(uint64_t address){return nds7_debug_read8(&core.nds,address);}
static void nds7_byte_write(uint64_t address, uint8_t data){nds7_debug_write8(&core.nds,address,data);}

static void null_byte_write(uint64_t address, uint8_t data){}
static uint8_t null_byte_read(uint64_t address){return 0;}


typedef struct{
  const char* short_label;
  const char* label;
  void (*function)();
  bool visible;
  bool allow_hardcore;
}se_debug_tool_desc_t; 

sb_debug_mmio_access_t gba_mmio_access_type(uint64_t address,int trigger_breakpoint){return gba_debug_mmio_access(&core.gba,address,trigger_breakpoint);}
void gba_memory_debugger(){se_draw_mem_debug_state("GBA MEM", &gui_state, &gba_byte_read, &gba_byte_write); }
void gba_cpu_debugger(){se_draw_arm_state("CPU",&core.gba.cpu,&gba_byte_read);}
void gba_mmio_debugger(){se_draw_io_state("GBA MMIO", gba_io_reg_desc,sizeof(gba_io_reg_desc)/sizeof(mmio_reg_t), &gba_byte_read, &gba_byte_write,&gba_mmio_access_type);}

void gb_mmio_debugger(){se_draw_io_state("GB MMIO", gb_io_reg_desc,sizeof(gb_io_reg_desc)/sizeof(mmio_reg_t), &gb_byte_read, &gb_byte_write,NULL);}
void gb_memory_debugger(){se_draw_mem_debug_state("GB MEM", &gui_state, &gb_byte_read, &gb_byte_write);}

sb_debug_mmio_access_t nds7_mmio_access_type(uint64_t address,int trigger_breakpoint){return nds_debug_mmio_access(&core.nds,NDS_ARM7,address,trigger_breakpoint);}
sb_debug_mmio_access_t nds9_mmio_access_type(uint64_t address,int trigger_breakpoint){return nds_debug_mmio_access(&core.nds,NDS_ARM9,address,trigger_breakpoint);}
void nds7_mmio_debugger(){se_draw_io_state("NDS7 MMIO", nds7_io_reg_desc,sizeof(nds7_io_reg_desc)/sizeof(mmio_reg_t), &nds7_byte_read, &nds7_byte_write,&nds7_mmio_access_type); }
void nds9_mmio_debugger(){se_draw_io_state("NDS9 MMIO", nds9_io_reg_desc,sizeof(nds9_io_reg_desc)/sizeof(mmio_reg_t), &nds9_byte_read, &nds9_byte_write,&nds9_mmio_access_type); }
void nds7_mem_debugger(){se_draw_mem_debug_state("NDS9 MEM",&gui_state, &nds9_byte_read, &nds9_byte_write); }
void nds9_mem_debugger(){se_draw_mem_debug_state("NDS7_MEM",&gui_state, &nds7_byte_read, &nds7_byte_write);}
void nds7_cpu_debugger(){se_draw_arm_state("ARM7",&core.nds.arm7,&nds7_byte_read); }
void nds9_cpu_debugger(){se_draw_arm_state("ARM9",&core.nds.arm9,&nds9_byte_read);}
void nds_io_debugger(){
  nds_t * nds = &core.nds;
  for(int cpu=0;cpu<2;++cpu){
    se_section(cpu? ICON_FK_EXCHANGE " ARM9 IPC FIFO":ICON_FK_EXCHANGE " ARM7 IPC FIFO");
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
  {ICON_FK_VOLUME_UP, ICON_FK_VOLUME_UP " PSG",se_psg_debugger},
  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats, .allow_hardcore=true},
  {NULL,NULL,NULL}
};
se_debug_tool_desc_t gb_debug_tools[]={
  {ICON_FK_TELEVISION, ICON_FK_TELEVISION " CPU", gb_cpu_debugger},
  {ICON_FK_SITEMAP, ICON_FK_SITEMAP " MMIO", gb_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O, ICON_FK_PENCIL_SQUARE_O " Memory",gb_memory_debugger},
  {ICON_FK_VOLUME_UP, ICON_FK_VOLUME_UP " PSG",se_psg_debugger},
  {ICON_FK_DELICIOUS, ICON_FK_DELICIOUS " Tile Map",gb_tile_map_debugger},
  {ICON_FK_TH, ICON_FK_TH " Tile Data",gb_tile_data_debugger},
  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats, .allow_hardcore=true},
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

  {ICON_FK_AREA_CHART, ICON_FK_AREA_CHART " Emulator Stats",se_draw_emu_stats, .allow_hardcore=true},
  {NULL,NULL,NULL}
};
static se_debug_tool_desc_t* se_get_debug_description(){
  se_debug_tool_desc_t *desc = NULL;
  if(emu_state.system ==SYSTEM_GBA)desc = gba_debug_tools;
  if(emu_state.system ==SYSTEM_GB)desc = gb_debug_tools;
  if(emu_state.system ==SYSTEM_NDS)desc = nds_debug_tools;
  return desc; 
}
emu_byte_read_t se_read_byte_func(int addr_map){
  if(emu_state.system ==SYSTEM_GBA)return gba_byte_read;
  if(emu_state.system ==SYSTEM_GB)return gb_byte_read;
  if(emu_state.system ==SYSTEM_NDS)return addr_map==7? nds7_byte_read:nds9_byte_read;
  return null_byte_read;
}
emu_byte_write_t se_write_byte_func(int addr_map){
  if(emu_state.system ==SYSTEM_GBA)return gba_byte_write;
  if(emu_state.system ==SYSTEM_GB)return gb_byte_write;
  if(emu_state.system ==SYSTEM_NDS)return addr_map==7? nds7_byte_write:nds9_byte_write;
  return null_byte_write;
}
///////////////////////////////
// END UPDATE FOR NEW SYSTEM //
///////////////////////////////

void se_capture_state(se_core_state_t* core, se_save_state_t * save_state){
#ifdef ENABLE_RETRO_ACHIEVEMENTS
  retro_achievements_capture_state(save_state->state.rc_buffer);
#endif
  save_state->state = *core; 
  save_state->valid = true;
  save_state->system = emu_state.system;
  se_screenshot(save_state->screenshot, &save_state->screenshot_width, &save_state->screenshot_height);
}
void se_restore_state(se_core_state_t* core, se_save_state_t * save_state){
  if(!save_state->valid || save_state->system != emu_state.system||(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in))return; 
  *core=save_state->state;
#ifdef ENABLE_RETRO_ACHIEVEMENTS
  retro_achievements_restore_state(save_state->state.rc_buffer);
#endif
  emu_state.render_frame = true;
  se_emulate_single_frame();
}
void se_state_download_callback(void* userdata, void* data, size_t size){
  size_t slot = (size_t)userdata;
  se_save_state_t* save_state = cloud_state.save_states+slot;
  if (data == NULL) {
    printf("Failed to download save state\n");
    cloud_state.save_states_busy[slot] = false;
    return;
  }

  mutex_lock(cloud_state.save_states_mutex);
  se_load_state_from_mem(save_state, data, size);
  cloud_state.save_states_busy[slot] = false;
  mutex_unlock(cloud_state.save_states_mutex);
}
void se_capture_cloud_callback(void* userdata, void* data){
  free(data);
  size_t slot = (size_t)userdata;
  mutex_lock(cloud_state.save_states_mutex);
  cloud_state.save_states[slot].valid = true;
  cloud_state.save_states_busy[slot] = false;
  mutex_unlock(cloud_state.save_states_mutex);
}
void se_logged_out_cloud_callback(){
  cloud_state.drive = NULL;
  memset(cloud_state.save_states, 0, sizeof(cloud_state.save_states));
  memset(cloud_state.save_states_busy, 0, sizeof(cloud_state.save_states_busy));
}
void se_write_png_cloud(void* context, void* data, int size){
  char file[SB_FILE_PATH_SIZE];
  size_t slot = (size_t)context;
  snprintf(file,SB_FILE_PATH_SIZE,"%016llx.slot%zu.state.png",emu_state.game_checksum,slot);
  // data is freed after this function returns, so we need to copy it
  void* data_copy = malloc(size);
  memcpy(data_copy,data,size);
  cloud_drive_upload(cloud_state.drive, file, "save_states", "image/png", data_copy, (size_t)size, se_capture_cloud_callback, (void*)slot);
}
void se_capture_state_slot_cloud(size_t slot){
  if(emu_state.rom_loaded==false)return;
  se_save_state_t* save_state = cloud_state.save_states+slot;
  se_capture_state(&core, save_state);
  save_state->valid = false;
  cloud_state.save_states_busy[slot] = true;
  uint32_t width=0, height=0;
  uint8_t* imdata = se_save_state_to_image(save_state, &width,&height);
  int len;
  stbi_write_png_to_func(se_write_png_cloud, (void*)slot, width, height, 4, imdata, 0);
  free(imdata);
}
void se_restore_state_slot_cloud(size_t slot){
  se_restore_state(&core, cloud_state.save_states+slot);
}
static void se_drive_ready_callback(cloud_drive_t* drive){
  cloud_state.drive = drive;
  if(drive){
    cloud_state.user_info = cloud_drive_get_user_info(drive);

    // If there's a game, check if there's any save states to download
    if(emu_state.rom_loaded){
      se_sync_cloud_save_states();
    }
  }else{
    printf("Something went wrong during cloud login\n");
  }
}
ImFont* se_get_mono_font(){
  return gui_state.mono_font;
}
void se_login_cloud(){
  cloud_drive_create(se_drive_ready_callback);
}
static void se_sync_cloud_save_states_callback(){
  for(size_t i=0;i<SE_NUM_SAVE_STATES;++i){
    char file[SB_FILE_PATH_SIZE];
    snprintf(file,SB_FILE_PATH_SIZE,"%016llx.slot%d.state.png",emu_state.game_checksum,(int)i);
    cloud_drive_download(cloud_state.drive, file, se_state_download_callback, (void*)i);
  }
}
static void se_sync_cloud_save_states(){
  if(cloud_state.drive == NULL) return;
  printf("Syncing cloud saves...\n");
  for(size_t i=0;i<SE_NUM_SAVE_STATES;++i){
    memset(&cloud_state.save_states[i], 0, sizeof(cloud_state.save_states[i]));
    cloud_state.save_states_busy[i] = true;
  }
  cloud_drive_sync(cloud_state.drive, se_sync_cloud_save_states_callback);
}
void se_drive_login(bool clicked, int x, int y, int w, int h){
#ifdef EMSCRIPTEN
  float delta_dpi_scale = se_dpi_scale()/sapp_dpi_scale();
  static bool button_created = false;
  if(!button_created){
    button_created = true;
    EM_ASM({
        var input = document.createElement('input');
        input.id = 'driveLogin';
        input.value = '';
        input.type = 'button';
        document.body.appendChild(input);
        input.onmousemove = input.onmouseover =  function(e) {
          const mouseMoveEvent = new MouseEvent('mousemove', {
            bubbles: true,
            cancelable: true,
            clientX: event.clientX,
            clientY: event.clientY
          });
          document.getElementById('canvas').dispatchEvent(mouseMoveEvent);
        };
        input.onclick = function(e) {
          Module.ccall('se_login_cloud');
        };
    });
  }
  if(cloud_drive_pending_login()) return;
  EM_ASM_INT({
    var input = document.getElementById('driveLogin');
    input.style.left = $0 +'px';
    input.style.top = $1 +'px';
    input.style.width = $2 +'px';
    input.style.height = $3 +'px';
    input.style.visibility = 'visible';
    input.style.position = 'absolute';
    input.style.opacity = 0;
  }, x*delta_dpi_scale, y*delta_dpi_scale, w*delta_dpi_scale, h*delta_dpi_scale);
#else
  if (clicked)
    se_login_cloud();
#endif
}
void se_ra_register(bool clicked, int x, int y, int w, int h){
#ifdef EMSCRIPTEN
  float delta_dpi_scale = se_dpi_scale()/sapp_dpi_scale();
  static bool button_created = false;
  if(!button_created){
    button_created = true;
    EM_ASM({
        var input = document.createElement('input');
        input.id = 'raRegister';
        input.value = '';
        input.type = 'button';
        document.body.appendChild(input);
        input.onmousemove = input.onmouseover =  function(e) {
          const mouseMoveEvent = new MouseEvent('mousemove', {
            bubbles: true,
            cancelable: true,
            clientX: event.clientX,
            clientY: event.clientY
          });
          document.getElementById('canvas').dispatchEvent(mouseMoveEvent);
        };
        input.onclick = function(e) {
          var url = 'https://retroachievements.org/createaccount.php';
          Module.ccall('https_open_url', 'void', ['string'], [url]);
        };
    });
  }
  EM_ASM_INT({
    var input = document.getElementById('raRegister');
    input.style.left = $0 +'px';
    input.style.top = $1 +'px';
    input.style.width = $2 +'px';
    input.style.height = $3 +'px';
    input.style.visibility = 'visible';
    input.style.position = 'absolute';
    input.style.opacity = 0;
  }, x*delta_dpi_scale, y*delta_dpi_scale, w*delta_dpi_scale, h*delta_dpi_scale);
#else
  if (clicked)
    https_open_url("https://retroachievements.org/createaccount.php");
#endif
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
    static bool debug_menu_open; 
    se_panel_toggle(SE_REGION_BLANK,&debug_menu_open,ICON_FK_BUG,"Debuggers");
    if(debug_menu_open){
      igSetNextWindowSize((ImVec2){gui_state.screen_width/se_dpi_scale(),0},ImGuiCond_Always);
      ImVec2 win;
      igGetWindowPos(&win);
      ImVec2 size;
      igGetWindowSize(&size);
      igSetNextWindowPos((ImVec2){0,win.y+size.y},ImGuiCond_Always,(ImVec2){0,0});
      if(igBegin("##debug combo",&debug_menu_open,ImGuiWindowFlags_NoTitleBar|ImGuiWindowFlags_NoMove|ImGuiWindowFlags_NoResize)){
        while(desc->label){
          igSetCursorPosX(4);
          bool is_selected = desc->visible; // You can store your selection however you want, outside or inside your objects
          if (igSelectableBool(se_localize_and_cache(desc->label), is_selected,ImGuiSelectableFlags_None,(ImVec2){0,30})){
            desc->visible=!desc->visible;
            debug_menu_open = false;
          }
          char tmp_str[256];
          snprintf(tmp_str,sizeof(tmp_str),se_localize_and_cache("Show/Hide %s Panel"),se_localize_and_cache(desc->label));
          se_tooltip(tmp_str);
          igSeparator();
          desc++;
        }
        igEndPopup();
      }
    }
    igSameLine(0,1);
  }else{
    while(desc->label){
      igPushIDInt(id++);
      if(desc->visible){
        igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
        if(se_button_themed(SE_REGION_BLANK_ACTIVE,desc->short_label,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,SE_MENU_BAR_HEIGHT},true)){desc->visible=!desc->visible;}
        igPopStyleColor(1);
      }else{
        if(se_button_themed(SE_REGION_BLANK,desc->short_label,(ImVec2){SE_MENU_BAR_BUTTON_WIDTH,SE_MENU_BAR_HEIGHT},true)){desc->visible=!desc->visible;}
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
      if(gui_state.settings.hardcore_mode && gui_state.ra_logged_in && desc->allow_hardcore == false){
        se_text("Disabled in Hardcore Mode");
      }else desc->function();
  
      float bottom_padding =0;
      #ifdef SE_PLATFORM_IOS
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

void se_draw_lcd(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, float rotation,bool is_touch){
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
    .integer_scaling = gui_state.settings.integer_scaling,
    .input_gamma = lcd_info.gamma,
    .red_color = {lcd_info.red_color[0],lcd_info.red_color[1],lcd_info.red_color[2]},
    .green_color = {lcd_info.green_color[0],lcd_info.green_color[1],lcd_info.green_color[2]},
    .blue_color = {lcd_info.blue_color[0],lcd_info.blue_color[1],lcd_info.blue_color[2]},
    .color_correction_strength=gui_state.test_runner_mode?0:gui_state.settings.color_correction
  };

  if(is_touch){
    float tx = gui_state.mouse_pos[0];
    float ty = gui_state.mouse_pos[1];
    tx-=x;
    ty-=y;

    float rx=cos(-rotation)*tx-sin(-rotation)*ty;
    float ry=sin(-rotation)*tx+cos(-rotation)*ty;

    rx/=render_width;
    ry/=render_height;
    rx+=0.5;
    ry+=0.5;

    emu_state.joy.touch_pos[0]=rx;
    emu_state.joy.touch_pos[1]=ry;
    if(gui_state.mouse_button[0]&&rx>=0&&rx<=1.0&&ry>=0.&&ry<=1.0)emu_state.joy.inputs[SE_KEY_PEN_DOWN]=true;

    for(int i=0;i<SAPP_MAX_TOUCHPOINTS;++i){
      if(gui_state.touch_points[i].active==false)continue;

      float tx = gui_state.touch_points[i].pos[0];
      float ty = gui_state.touch_points[i].pos[1];
      tx-=x;
      ty-=y;

      float rx=cos(-rotation)*tx-sin(-rotation)*ty;
      float ry=sin(-rotation)*tx+cos(-rotation)*ty;

      rx/=render_width;
      ry/=render_height;
      rx+=0.5;
      ry+=0.5;

      if(rx>=0&&rx<=1.0&&ry>=0.&&ry<=1.0){
        emu_state.joy.touch_pos[0]=rx;
        emu_state.joy.touch_pos[1]=ry;
        emu_state.joy.inputs[SE_KEY_PEN_DOWN]=true;
        break;
      }
    }

  }

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
#ifdef SE_PLATFORM_ANDROID
const char* se_android_key_to_name(int key){
  switch(key){
    case AKEYCODE_UNKNOWN:                        return "UNKNOWN";
    case AKEYCODE_SOFT_LEFT:                      return "SOFT_LEFT";
    case AKEYCODE_SOFT_RIGHT:                     return "SOFT_RIGHT";
    case AKEYCODE_HOME:                           return "HOME";
    case AKEYCODE_BACK:                           return "BACK";
    case AKEYCODE_CALL:                           return "CALL";
    case AKEYCODE_ENDCALL:                        return "ENDCALL";
    case AKEYCODE_0:                              return "0";
    case AKEYCODE_1:                              return "1";
    case AKEYCODE_2:                              return "2";
    case AKEYCODE_3:                              return "3";
    case AKEYCODE_4:                              return "4";
    case AKEYCODE_5:                              return "5";
    case AKEYCODE_6:                              return "6";
    case AKEYCODE_7:                              return "7";
    case AKEYCODE_8:                              return "8";
    case AKEYCODE_9:                              return "9";
    case AKEYCODE_STAR:                           return "STAR";
    case AKEYCODE_POUND:                          return "POUND";
    case AKEYCODE_DPAD_UP:                        return "DPAD_UP";
    case AKEYCODE_DPAD_DOWN:                      return "DPAD_DOWN";
    case AKEYCODE_DPAD_LEFT:                      return "DPAD_LEFT";
    case AKEYCODE_DPAD_RIGHT:                     return "DPAD_RIGHT";
    case AKEYCODE_DPAD_CENTER:                    return "DPAD_CENTER";
    case AKEYCODE_VOLUME_UP:                      return "VOLUME_UP";
    case AKEYCODE_VOLUME_DOWN:                    return "VOLUME_DOWN";
    case AKEYCODE_POWER:                          return "POWER";
    case AKEYCODE_CAMERA:                         return "CAMERA";
    case AKEYCODE_CLEAR:                          return "CLEAR";
    case AKEYCODE_A:                              return "A";
    case AKEYCODE_B:                              return "B";
    case AKEYCODE_C:                              return "C";
    case AKEYCODE_D:                              return "D";
    case AKEYCODE_E:                              return "E";
    case AKEYCODE_F:                              return "F";
    case AKEYCODE_G:                              return "G";
    case AKEYCODE_H:                              return "H";
    case AKEYCODE_I:                              return "I";
    case AKEYCODE_J:                              return "J";
    case AKEYCODE_K:                              return "K";
    case AKEYCODE_L:                              return "L";
    case AKEYCODE_M:                              return "M";
    case AKEYCODE_N:                              return "N";
    case AKEYCODE_O:                              return "O";
    case AKEYCODE_P:                              return "P";
    case AKEYCODE_Q:                              return "Q";
    case AKEYCODE_R:                              return "R";
    case AKEYCODE_S:                              return "S";
    case AKEYCODE_T:                              return "T";
    case AKEYCODE_U:                              return "U";
    case AKEYCODE_V:                              return "V";
    case AKEYCODE_W:                              return "W";
    case AKEYCODE_X:                              return "X";
    case AKEYCODE_Y:                              return "Y";
    case AKEYCODE_Z:                              return "Z";
    case AKEYCODE_COMMA:                          return "COMMA";
    case AKEYCODE_PERIOD:                         return "PERIOD";
    case AKEYCODE_ALT_LEFT:                       return "ALT_LEFT";
    case AKEYCODE_ALT_RIGHT:                      return "ALT_RIGHT";
    case AKEYCODE_SHIFT_LEFT:                     return "SHIFT_LEFT";
    case AKEYCODE_SHIFT_RIGHT:                    return "SHIFT_RIGHT";
    case AKEYCODE_TAB:                            return "TAB";
    case AKEYCODE_SPACE:                          return "SPACE";
    case AKEYCODE_SYM:                            return "SYM";
    case AKEYCODE_EXPLORER:                       return "EXPLORER";
    case AKEYCODE_ENVELOPE:                       return "ENVELOPE";
    case AKEYCODE_ENTER:                          return "ENTER";
    case AKEYCODE_DEL:                            return "DEL";
    case AKEYCODE_GRAVE:                          return "GRAVE";
    case AKEYCODE_MINUS:                          return "MINUS";
    case AKEYCODE_EQUALS:                         return "EQUALS";
    case AKEYCODE_LEFT_BRACKET:                   return "LEFT_BRACKET";
    case AKEYCODE_RIGHT_BRACKET:                  return "RIGHT_BRACKET";
    case AKEYCODE_BACKSLASH:                      return "BACKSLASH";
    case AKEYCODE_SEMICOLON:                      return "SEMICOLON";
    case AKEYCODE_APOSTROPHE:                     return "APOSTROPHE";
    case AKEYCODE_SLASH:                          return "SLASH";
    case AKEYCODE_AT:                             return "AT";
    case AKEYCODE_NUM:                            return "NUM";
    case AKEYCODE_HEADSETHOOK:                    return "HEADSETHOOK";
    case AKEYCODE_FOCUS:                          return "FOCUS";
    case AKEYCODE_PLUS:                           return "PLUS";
    case AKEYCODE_MENU:                           return "MENU";
    case AKEYCODE_NOTIFICATION:                   return "NOTIFICATION";
    case AKEYCODE_SEARCH:                         return "SEARCH";
    case AKEYCODE_MEDIA_PLAY_PAUSE:               return "MEDIA_PLAY_PAUSE";
    case AKEYCODE_MEDIA_STOP:                     return "MEDIA_STOP";
    case AKEYCODE_MEDIA_NEXT:                     return "MEDIA_NEXT";
    case AKEYCODE_MEDIA_PREVIOUS:                 return "MEDIA_PREVIOUS";
    case AKEYCODE_MEDIA_REWIND:                   return "MEDIA_REWIND";
    case AKEYCODE_MEDIA_FAST_FORWARD:             return "MEDIA_FAST_FORWARD";
    case AKEYCODE_MUTE:                           return "MUTE";
    case AKEYCODE_PAGE_UP:                        return "PAGE_UP";
    case AKEYCODE_PAGE_DOWN:                      return "PAGE_DOWN";
    case AKEYCODE_PICTSYMBOLS:                    return "PICTSYMBOLS";
    case AKEYCODE_SWITCH_CHARSET:                 return "SWITCH_CHARSET";
    case AKEYCODE_BUTTON_A:                       return "BUTTON_A";
    case AKEYCODE_BUTTON_B:                       return "BUTTON_B";
    case AKEYCODE_BUTTON_C:                       return "BUTTON_C";
    case AKEYCODE_BUTTON_X:                       return "BUTTON_X";
    case AKEYCODE_BUTTON_Y:                       return "BUTTON_Y";
    case AKEYCODE_BUTTON_Z:                       return "BUTTON_Z";
    case AKEYCODE_BUTTON_L1:                      return "BUTTON_L1";
    case AKEYCODE_BUTTON_R1:                      return "BUTTON_R1";
    case AKEYCODE_BUTTON_L2:                      return "BUTTON_L2";
    case AKEYCODE_BUTTON_R2:                      return "BUTTON_R2";
    case AKEYCODE_BUTTON_THUMBL:                  return "BUTTON_THUMBL";
    case AKEYCODE_BUTTON_THUMBR:                  return "BUTTON_THUMBR";
    case AKEYCODE_BUTTON_START:                   return "BUTTON_START";
    case AKEYCODE_BUTTON_SELECT:                  return "BUTTON_SELECT";
    case AKEYCODE_BUTTON_MODE:                    return "BUTTON_MODE";
    case AKEYCODE_ESCAPE:                         return "ESCAPE";
    case AKEYCODE_FORWARD_DEL:                    return "FORWARD_DEL";
    case AKEYCODE_CTRL_LEFT:                      return "CTRL_LEFT";
    case AKEYCODE_CTRL_RIGHT:                     return "CTRL_RIGHT";
    case AKEYCODE_CAPS_LOCK:                      return "CAPS_LOCK";
    case AKEYCODE_SCROLL_LOCK:                    return "SCROLL_LOCK";
    case AKEYCODE_META_LEFT:                      return "META_LEFT";
    case AKEYCODE_META_RIGHT:                     return "META_RIGHT";
    case AKEYCODE_FUNCTION:                       return "FUNCTION";
    case AKEYCODE_SYSRQ:                          return "SYSRQ";
    case AKEYCODE_BREAK:                          return "BREAK";
    case AKEYCODE_MOVE_HOME:                      return "MOVE_HOME";
    case AKEYCODE_MOVE_END:                       return "MOVE_END";
    case AKEYCODE_INSERT:                         return "INSERT";
    case AKEYCODE_FORWARD:                        return "FORWARD";
    case AKEYCODE_MEDIA_PLAY:                     return "MEDIA_PLAY";
    case AKEYCODE_MEDIA_PAUSE:                    return "MEDIA_PAUSE";
    case AKEYCODE_MEDIA_CLOSE:                    return "MEDIA_CLOSE";
    case AKEYCODE_MEDIA_EJECT:                    return "MEDIA_EJECT";
    case AKEYCODE_MEDIA_RECORD:                   return "MEDIA_RECORD";
    case AKEYCODE_F1:                             return "F1";
    case AKEYCODE_F2:                             return "F2";
    case AKEYCODE_F3:                             return "F3";
    case AKEYCODE_F4:                             return "F4";
    case AKEYCODE_F5:                             return "F5";
    case AKEYCODE_F6:                             return "F6";
    case AKEYCODE_F7:                             return "F7";
    case AKEYCODE_F8:                             return "F8";
    case AKEYCODE_F9:                             return "F9";
    case AKEYCODE_F10:                            return "F10";
    case AKEYCODE_F11:                            return "F11";
    case AKEYCODE_F12:                            return "F12";
    case AKEYCODE_NUM_LOCK:                       return "NUM_LOCK";
    case AKEYCODE_NUMPAD_0:                       return "NUMPAD_0";
    case AKEYCODE_NUMPAD_1:                       return "NUMPAD_1";
    case AKEYCODE_NUMPAD_2:                       return "NUMPAD_2";
    case AKEYCODE_NUMPAD_3:                       return "NUMPAD_3";
    case AKEYCODE_NUMPAD_4:                       return "NUMPAD_4";
    case AKEYCODE_NUMPAD_5:                       return "NUMPAD_5";
    case AKEYCODE_NUMPAD_6:                       return "NUMPAD_6";
    case AKEYCODE_NUMPAD_7:                       return "NUMPAD_7";
    case AKEYCODE_NUMPAD_8:                       return "NUMPAD_8";
    case AKEYCODE_NUMPAD_9:                       return "NUMPAD_9";
    case AKEYCODE_NUMPAD_DIVIDE:                  return "NUMPAD_DIVIDE";
    case AKEYCODE_NUMPAD_MULTIPLY:                return "NUMPAD_MULTIPLY";
    case AKEYCODE_NUMPAD_SUBTRACT:                return "NUMPAD_SUBTRACT";
    case AKEYCODE_NUMPAD_ADD:                     return "NUMPAD_ADD";
    case AKEYCODE_NUMPAD_DOT:                     return "NUMPAD_DOT";
    case AKEYCODE_NUMPAD_COMMA:                   return "NUMPAD_COMMA";
    case AKEYCODE_NUMPAD_ENTER:                   return "NUMPAD_ENTER";
    case AKEYCODE_NUMPAD_EQUALS:                  return "NUMPAD_EQUALS";
    case AKEYCODE_NUMPAD_LEFT_PAREN:              return "NUMPAD_LEFT_PAREN";
    case AKEYCODE_NUMPAD_RIGHT_PAREN:             return "NUMPAD_RIGHT_PAREN";
    case AKEYCODE_VOLUME_MUTE:                    return "VOLUME_MUTE";
    case AKEYCODE_INFO:                           return "INFO";
    case AKEYCODE_CHANNEL_UP:                     return "CHANNEL_UP";
    case AKEYCODE_CHANNEL_DOWN:                   return "CHANNEL_DOWN";
    case AKEYCODE_ZOOM_IN:                        return "ZOOM_IN";
    case AKEYCODE_ZOOM_OUT:                       return "ZOOM_OUT";
    case AKEYCODE_TV:                             return "TV";
    case AKEYCODE_WINDOW:                         return "WINDOW";
    case AKEYCODE_GUIDE:                          return "GUIDE";
    case AKEYCODE_DVR:                            return "DVR";
    case AKEYCODE_BOOKMARK:                       return "BOOKMARK";
    case AKEYCODE_CAPTIONS:                       return "CAPTIONS";
    case AKEYCODE_SETTINGS:                       return "SETTINGS";
    case AKEYCODE_TV_POWER:                       return "TV_POWER";
    case AKEYCODE_TV_INPUT:                       return "TV_INPUT";
    case AKEYCODE_STB_POWER:                      return "STB_POWER";
    case AKEYCODE_STB_INPUT:                      return "STB_INPUT";
    case AKEYCODE_AVR_POWER:                      return "AVR_POWER";
    case AKEYCODE_AVR_INPUT:                      return "AVR_INPUT";
    case AKEYCODE_PROG_RED:                       return "PROG_RED";
    case AKEYCODE_PROG_GREEN:                     return "PROG_GREEN";
    case AKEYCODE_PROG_YELLOW:                    return "PROG_YELLOW";
    case AKEYCODE_PROG_BLUE:                      return "PROG_BLUE";
    case AKEYCODE_APP_SWITCH:                     return "APP_SWITCH";
    case AKEYCODE_BUTTON_1:                       return "BUTTON_1";
    case AKEYCODE_BUTTON_2:                       return "BUTTON_2";
    case AKEYCODE_BUTTON_3:                       return "BUTTON_3";
    case AKEYCODE_BUTTON_4:                       return "BUTTON_4";
    case AKEYCODE_BUTTON_5:                       return "BUTTON_5";
    case AKEYCODE_BUTTON_6:                       return "BUTTON_6";
    case AKEYCODE_BUTTON_7:                       return "BUTTON_7";
    case AKEYCODE_BUTTON_8:                       return "BUTTON_8";
    case AKEYCODE_BUTTON_9:                       return "BUTTON_9";
    case AKEYCODE_BUTTON_10:                      return "BUTTON_10";
    case AKEYCODE_BUTTON_11:                      return "BUTTON_11";
    case AKEYCODE_BUTTON_12:                      return "BUTTON_12";
    case AKEYCODE_BUTTON_13:                      return "BUTTON_13";
    case AKEYCODE_BUTTON_14:                      return "BUTTON_14";
    case AKEYCODE_BUTTON_15:                      return "BUTTON_15";
    case AKEYCODE_BUTTON_16:                      return "BUTTON_16";
    case AKEYCODE_LANGUAGE_SWITCH:                return "LANGUAGE_SWITCH";
    case AKEYCODE_MANNER_MODE:                    return "MANNER_MODE";
    case AKEYCODE_3D_MODE:                        return "3D_MODE";
    case AKEYCODE_CONTACTS:                       return "CONTACTS";
    case AKEYCODE_CALENDAR:                       return "CALENDAR";
    case AKEYCODE_MUSIC:                          return "MUSIC";
    case AKEYCODE_CALCULATOR:                     return "CALCULATOR";
    case AKEYCODE_ZENKAKU_HANKAKU:                return "ZENKAKU_HANKAKU";
    case AKEYCODE_EISU:                           return "EISU";
    case AKEYCODE_MUHENKAN:                       return "MUHENKAN";
    case AKEYCODE_HENKAN:                         return "HENKAN";
    case AKEYCODE_KATAKANA_HIRAGANA:              return "KATAKANA_HIRAGANA";
    case AKEYCODE_YEN:                            return "YEN";
    case AKEYCODE_RO:                             return "RO";
    case AKEYCODE_KANA:                           return "KANA";
    case AKEYCODE_ASSIST:                         return "ASSIST";
    case AKEYCODE_BRIGHTNESS_DOWN:                return "BRIGHTNESS_DOWN";
    case AKEYCODE_BRIGHTNESS_UP:                  return "BRIGHTNESS_UP";
    case AKEYCODE_MEDIA_AUDIO_TRACK:              return "MEDIA_AUDIO_TRACK";
    case AKEYCODE_SLEEP:                          return "SLEEP";
    case AKEYCODE_WAKEUP:                         return "WAKEUP";
    case AKEYCODE_PAIRING:                        return "PAIRING";
    case AKEYCODE_MEDIA_TOP_MENU:                 return "MEDIA_TOP_MENU";
    case AKEYCODE_11:                             return "11";
    case AKEYCODE_12:                             return "12";
    case AKEYCODE_LAST_CHANNEL:                   return "LAST_CHANNEL";
    case AKEYCODE_TV_DATA_SERVICE:                return "TV_DATA_SERVICE";
    case AKEYCODE_VOICE_ASSIST:                   return "VOICE_ASSIST";
    case AKEYCODE_TV_RADIO_SERVICE:               return "TV_RADIO_SERVICE";
    case AKEYCODE_TV_TELETEXT:                    return "TV_TELETEXT";
    case AKEYCODE_TV_NUMBER_ENTRY:                return "TV_NUMBER_ENTRY";
    case AKEYCODE_TV_TERRESTRIAL_ANALOG:          return "TV_TERRESTRIAL_ANALOG";
    case AKEYCODE_TV_TERRESTRIAL_DIGITAL:         return "TV_TERRESTRIAL_DIGITAL";
    case AKEYCODE_TV_SATELLITE:                   return "TV_SATELLITE";
    case AKEYCODE_TV_SATELLITE_BS:                return "TV_SATELLITE_BS";
    case AKEYCODE_TV_SATELLITE_CS:                return "TV_SATELLITE_CS";
    case AKEYCODE_TV_SATELLITE_SERVICE:           return "TV_SATELLITE_SERVICE";
    case AKEYCODE_TV_NETWORK:                     return "TV_NETWORK";
    case AKEYCODE_TV_ANTENNA_CABLE:               return "TV_ANTENNA_CABLE";
    case AKEYCODE_TV_INPUT_HDMI_1:                return "TV_INPUT_HDMI_1";
    case AKEYCODE_TV_INPUT_HDMI_2:                return "TV_INPUT_HDMI_2";
    case AKEYCODE_TV_INPUT_HDMI_3:                return "TV_INPUT_HDMI_3";
    case AKEYCODE_TV_INPUT_HDMI_4:                return "TV_INPUT_HDMI_4";
    case AKEYCODE_TV_INPUT_COMPOSITE_1:           return "TV_INPUT_COMPOSITE_1";
    case AKEYCODE_TV_INPUT_COMPOSITE_2:           return "TV_INPUT_COMPOSITE_2";
    case AKEYCODE_TV_INPUT_COMPONENT_1:           return "TV_INPUT_COMPONENT_1";
    case AKEYCODE_TV_INPUT_COMPONENT_2:           return "TV_INPUT_COMPONENT_2";
    case AKEYCODE_TV_INPUT_VGA_1:                 return "TV_INPUT_VGA_1";
    case AKEYCODE_TV_AUDIO_DESCRIPTION:           return "TV_AUDIO_DESCRIPTION";
    case AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_UP:    return "TV_AUDIO_DESCRIPTION_MIX_UP";
    case AKEYCODE_TV_AUDIO_DESCRIPTION_MIX_DOWN:  return "TV_AUDIO_DESCRIPTION_MIX_DOWN";
    case AKEYCODE_TV_ZOOM_MODE:                   return "TV_ZOOM_MODE";
    case AKEYCODE_TV_CONTENTS_MENU:               return "TV_CONTENTS_MENU";
    case AKEYCODE_TV_MEDIA_CONTEXT_MENU:          return "TV_MEDIA_CONTEXT_MENU";
    case AKEYCODE_TV_TIMER_PROGRAMMING:           return "TV_TIMER_PROGRAMMING";
    case AKEYCODE_HELP:                           return "HELP";
    case AKEYCODE_NAVIGATE_PREVIOUS:              return "NAVIGATE_PREVIOUS";
    case AKEYCODE_NAVIGATE_NEXT:                  return "NAVIGATE_NEXT";
    case AKEYCODE_NAVIGATE_IN:                    return "NAVIGATE_IN";
    case AKEYCODE_NAVIGATE_OUT:                   return "NAVIGATE_OUT";
    case AKEYCODE_STEM_PRIMARY:                   return "STEM_PRIMARY";
    case AKEYCODE_STEM_1:                         return "STEM_1";
    case AKEYCODE_STEM_2:                         return "STEM_2";
    case AKEYCODE_STEM_3:                         return "STEM_3";
    case AKEYCODE_DPAD_UP_LEFT:                   return "DPAD_UP_LEFT";
    case AKEYCODE_DPAD_DOWN_LEFT:                 return "DPAD_DOWN_LEFT";
    case AKEYCODE_DPAD_UP_RIGHT:                  return "DPAD_UP_RIGHT";
    case AKEYCODE_DPAD_DOWN_RIGHT:                return "DPAD_DOWN_RIGHT";
    case AKEYCODE_MEDIA_SKIP_FORWARD:             return "MEDIA_SKIP_FORWARD";
    case AKEYCODE_MEDIA_SKIP_BACKWARD:            return "MEDIA_SKIP_BACKWARD";
    case AKEYCODE_MEDIA_STEP_FORWARD:             return "MEDIA_STEP_FORWARD";
    case AKEYCODE_MEDIA_STEP_BACKWARD:            return "MEDIA_STEP_BACKWARD";
    case AKEYCODE_SOFT_SLEEP:                     return "SOFT_SLEEP";
    case AKEYCODE_CUT:                            return "CUT";
    case AKEYCODE_COPY:                           return "COPY";
    case AKEYCODE_PASTE:                          return "PASTE";
    case AKEYCODE_SYSTEM_NAVIGATION_UP:           return "SYSTEM_NAVIGATION_UP";
    case AKEYCODE_SYSTEM_NAVIGATION_DOWN:         return "SYSTEM_NAVIGATION_DOWN";
    case AKEYCODE_SYSTEM_NAVIGATION_LEFT:         return "SYSTEM_NAVIGATION_LEFT";
    case AKEYCODE_SYSTEM_NAVIGATION_RIGHT:        return "SYSTEM_NAVIGATION_RIGHT";
    case AKEYCODE_ALL_APPS:                       return "ALL_APPS";
    case AKEYCODE_REFRESH:                        return "REFRESH";
    case AKEYCODE_THUMBS_UP:                      return "THUMBS_UP";
    case AKEYCODE_THUMBS_DOWN:                    return "THUMBS_DOWN";
    case AKEYCODE_PROFILE_SWITCH:                 return "PROFILE_SWITCH";
  }
  return NULL;
}
#endif
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
  action = se_localize(action);
  if(rebind_timer<0){state->bind_being_set=-1;}
  igPushIDInt(keybind_type);
  ImGuiStyle* style = igGetStyle();
  bool settings_changed = false; 
  for(int k=0;k<num_keybinds;++k){
    igPushIDInt(k);
    se_text("%s",se_localize_and_cache(button_labels[k]));
    float active = (state->value[k])>0.4;
    igSameLine(SE_FIELD_INDENT,0);
    if(state->bind_being_set==k)active=true;
    if(active)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
    const char* button_label = "Not bound"; 
    char buff[32];
    if(state->bound_id[k]!=-1){
      switch(keybind_type){
        case SE_BIND_KEYBOARD: button_label=se_keycode_to_string(state->bound_id[k]);break;
        #if defined(USE_SDL) || defined(SE_PLATFORM_ANDROID)
        case SE_BIND_KEY: 
          { 
            int key = state->bound_id[k];
            bool is_hat = key&SE_HAT_MASK;
            bool is_joy = key&(SE_JOY_NEG_MASK|SE_JOY_POS_MASK);
        #ifdef USE_SDL
            if(is_hat){
              int hat_id = SB_BFE(key,8,8);
              int hat_val = SB_BFE(key,0,8);
              const char * dir = "";
              if(hat_val == SDL_HAT_UP)dir="UP";
              if(hat_val == SDL_HAT_DOWN)dir="DOWN";
              if(hat_val == SDL_HAT_LEFT)dir="LEFT";
              if(hat_val == SDL_HAT_RIGHT)dir="RIGHT";

              snprintf(buff, sizeof(buff),se_localize("Hat %d %s"), hat_id, dir);
              button_label=buff;
            }else
        #endif
              if(is_joy){
              int joy_id = SB_BFE(key,0,16);
              const char* dir = (key&SE_JOY_NEG_MASK)? "<-0.3": ">0.3";
              snprintf(buff, sizeof(buff),se_localize("Analog %d %s"),joy_id,dir);
            }else {
        #ifdef SE_PLATFORM_ANDROID
              const char* android_name = se_android_key_to_name(state->bound_id[k]);
              if(android_name) {
                android_name = se_localize_and_cache(android_name);
                button_label = android_name;
                break;
              }
        #endif
              snprintf(buff, sizeof(buff),se_localize("Key %d"), state->bound_id[k]);button_label=buff;
            }
          }
          button_label=buff;
          break;
        case SE_BIND_ANALOG: 
          snprintf(buff, sizeof(buff),se_localize("Analog %d (%0.2f)"), state->bound_id[k],state->value[k]);button_label=buff;
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
    }
    if(se_button(button_label,(ImVec2){-25, 0})){
      state->bind_being_set = k;
      state->rebind_start_time = se_time();
    }
    igSameLine(0,1);
    if(se_button(ICON_FK_TIMES,(ImVec2){-1, 0})){
      state->bound_id[k]=-1;
      state->bind_being_set=-1;
      settings_changed = true;
    }
    if(active)igPopStyleColor(1);
    igPopID();
  } 
  igPopID();
  return settings_changed;
}
void se_draw_onscreen_controller(sb_emu_state_t*state, int mode, float win_x, float win_y, float win_w, float win_h, bool preview, bool center){  
  if(state->run_mode!=SB_MODE_RUN&&preview==false)return;

  //Split the region in half if this is a both LEFT/RIGHT command
  float right_x_off = 0; 
  if((mode&SE_GAMEPAD_LEFT) && (mode&SE_GAMEPAD_RIGHT)){
    win_w*=0.5;
    right_x_off = win_w;
  }

  bool half_height = (win_h<win_w*1.6);
  float size_scalar = 1.0;

  ImU32 line_color = 0xffffff;
  ImU32 line_color2 =0x000000;
  ImU32 sel_color =0x000000;
  double turbo_t = se_time()*5;
  turbo_t-=floor(turbo_t);
  bool press_turbo = turbo_t>0.5;
  ImU32 turbo_color =0x0070ff;
  ImU32 hold_color =0xff4000;

  float opacity = 3.-(se_time()-gui_state.last_touch_time);
  if(opacity>1||preview)opacity=1;
  if(!gui_state.settings.auto_hide_touch_controls)opacity=1;   
  if(opacity<=0){opacity=0;}
  opacity*=gui_state.settings.touch_controls_opacity;

  line_color|=(int)(opacity*0xff)<<24;
  line_color2|=(int)(opacity*0xff)<<24;
  sel_color|=(int)(opacity*0x80)<<24;
  hold_color|=(uint32_t)(0xffu)<<24;
  turbo_color|=(int)(fmin(opacity+turbo_t*0.5,1)*0xffu)<<24;

  float themed_scale = 1.05;
  int line_w0 = 1; 
  int line_w1 = 3; 

  float dpad_r = size_scalar*0.45;
  float button_r = dpad_r*0.39;

  enum{max_points = 5};
  float points[max_points][2]={0};

  int p = 0;
  //if(IsMouseButtonDown(0))points[p++] = GetMousePosition();
  for(int i=0; i<SAPP_MAX_TOUCHPOINTS;++i){
    if(p<max_points&&gui_state.touch_points[i].active){
      points[p][0]=gui_state.touch_points[i].pos[0]/se_dpi_scale();
      points[p][1]=gui_state.touch_points[i].pos[1]/se_dpi_scale();
      ++p;
    }
  }
  ImDrawList*dl= igGetWindowDrawList();

  enum {ROUND,DPAD,RECT};
  typedef struct{int input_id; int theme_region; int mode; bool enable; int type; float pos[2]; float size[2];}se_button_info_t;

  bool abxy= emu_state.system==SYSTEM_NDS;
  bool lr_en = emu_state.system!=SYSTEM_GB;
  bool ht_en = gui_state.settings.touch_controls_show_turbo;
  const int SE_KEY_HOLD = -1; 
  const int SE_KEY_TURBO = -2; 
  float full_h = win_h/win_w;
  
  float a_pos[2] = {0.5+button_r*1.1,full_h*0.47};
  float b_pos[2] = {0.5-button_r*1.1,full_h*0.55};
  float dpad_y = 0.5*full_h;
  if(abxy){
    a_pos[0] = 0.5+button_r*1.5; a_pos[1] = 0.5*full_h;
    b_pos[0] = 0.5;              b_pos[1] = 0.5*full_h+button_r*1.5;
  }
  if(!lr_en){
    a_pos[1]-=full_h*0.1;
    b_pos[1]-=full_h*0.1;
    
    float y_off_scale = (full_h-dpad_r*2);
    y_off_scale = fmin(1.0,fmax(0.0,y_off_scale)); 
    dpad_y -=full_h*y_off_scale*0.1;
  }
  float row_h = 0.32*size_scalar ;
  float rect_width_scalar = 1;
  float rect_offset = 0;
  float lr_y = 0*full_h;
  float start_sel_row_y = full_h-row_h;
  if(half_height){
    rect_width_scalar = 0.3;
    row_h*=0.5;
    start_sel_row_y+=row_h;
  }
  float full_row_w = rect_width_scalar*0.99;
  float start_sel_row_w = (ht_en?0.66:0.99);
  float hold_turbo_w = 0.3;
  if(hold_turbo_w>full_row_w)hold_turbo_w = full_row_w; 
  if(start_sel_row_w>full_row_w)start_sel_row_w = full_row_w;
  se_button_info_t buttons[]={
    {SE_KEY_L      ,SE_REGION_KEY_L,      SE_GAMEPAD_LEFT, lr_en,RECT, {0+rect_offset,lr_y}, {full_row_w,row_h}}, 
    {SE_KEY_UP     ,SE_REGION_DPAD_CENTER,SE_GAMEPAD_LEFT, true, DPAD, {0.5,dpad_y}, {dpad_r,0.8}},
    {SE_KEY_SELECT ,SE_REGION_KEY_SELECT, SE_GAMEPAD_LEFT,true, RECT, {0+rect_offset,start_sel_row_y}, {start_sel_row_w,row_h}},
    {SE_KEY_HOLD   ,SE_REGION_KEY_HOLD,   SE_GAMEPAD_LEFT,ht_en,RECT, {0.68+0.3-hold_turbo_w+rect_offset,start_sel_row_y}, {hold_turbo_w,row_h}},
    {SE_KEY_R      ,SE_REGION_KEY_R,      SE_GAMEPAD_RIGHT,lr_en,RECT, {0.01+0.99-full_row_w-rect_offset,lr_y}, {full_row_w,row_h}},
    {SE_KEY_A      ,SE_REGION_KEY_A,      SE_GAMEPAD_RIGHT,true, ROUND,{a_pos[0],a_pos[1]},{button_r,0.2}},
    {SE_KEY_B      ,SE_REGION_KEY_B,      SE_GAMEPAD_RIGHT,true, ROUND,{b_pos[0],b_pos[1]},{button_r,0.2}},
    {SE_KEY_X      ,SE_REGION_KEY_X,      SE_GAMEPAD_RIGHT,abxy, ROUND,{0.5,0.5*full_h-button_r*1.5},{button_r,0.2}},
    {SE_KEY_Y      ,SE_REGION_KEY_Y,      SE_GAMEPAD_RIGHT,abxy, ROUND,{0.5-button_r*1.5,0.5*full_h},{button_r,0.2}},
    {SE_KEY_START  ,SE_REGION_KEY_START,  SE_GAMEPAD_RIGHT, true, RECT, {(ht_en?0.33:0.00)+(ht_en?0.67:1.01)-start_sel_row_w-rect_offset,start_sel_row_y}, {start_sel_row_w,row_h}},
    {SE_KEY_TURBO  ,SE_REGION_KEY_TURBO,  SE_GAMEPAD_RIGHT, ht_en,RECT, {0.01-rect_offset,start_sel_row_y}, {hold_turbo_w,row_h}},
  };
  bool touch_only_key_pressed[3] = {0};

  int button_pressed_mask = 0;

  for(int bi =0; bi<sizeof(buttons)/sizeof(buttons[0]); ++bi){
    se_button_info_t * b = &buttons[bi];
    if(!(mode&b->mode)||!b->enable)continue;

    ImU32 col = line_color;
    ImU32 pressed_color = col;
    if(b->input_id==SE_KEY_TURBO){
      pressed_color = turbo_color; 
      if(gui_state.touch_controls.turbo_toggle)col=turbo_color;
    }
    if(b->input_id==SE_KEY_HOLD &&(gui_state.touch_controls.hold_toggle)){
      pressed_color = hold_color; 
      if(gui_state.touch_controls.hold_toggle)col=hold_color;
    }
    bool force_pressed = false;
    if(SB_BFE(gui_state.touch_controls.hold_toggle,bi,1)){
      col = hold_color;
      force_pressed=true;
      sel_color = 0;
    }
    if(SB_BFE(gui_state.touch_controls.turbo_toggle,bi,1)){
      col = turbo_color;
      force_pressed= press_turbo;
    }
    if(b->input_id>=0&&force_pressed){
      emu_state.joy.inputs[b->input_id]=1;
    }
    float x_off = 0;
    if(b->mode&SE_GAMEPAD_RIGHT)x_off+=right_x_off;
    bool show_labels = gui_state.settings.touch_screen_show_button_labels;
    if(b->type ==RECT){
      int region =b->theme_region;
      bool pressed = b->input_id>=0 && emu_state.prev_frame_joy.inputs[b->input_id]>0.1;
      
      float x = b->pos[0]*win_w+win_x+x_off;
      float y = b->pos[1]*win_w+win_y;
      float w = b->size[0]*win_w;
      float h = b->size[1]*win_w;
      for(int i = 0;i<p;++i){
        int dx = points[i][0]-x;
        int dy = points[i][1]-y;
        if(dx>=-w*0.05 && dx<=w*1.05 && dy>=h*0.05 && dy<=h*1.05 ){
          col = pressed_color;
          if(b->input_id>=0){
            button_pressed_mask|=1<<bi;
            emu_state.joy.inputs[b->input_id]=1;
          }else touch_only_key_pressed[- b->input_id]=1;
          pressed=true;
        }
      }
      int orig_region = show_labels? region : SE_REGION_KEY_RECT_BLANK;
      int fallback_region = show_labels?SE_REGION_KEY_RECT_BLANK :region;
      if(se_draw_theme_region_tint(orig_region+pressed,x,y,w,h,col)){
      }else if(se_draw_theme_region_tint(orig_region,x,y,w,h,col)){
        if(pressed){
          se_draw_theme_region_tint(orig_region,x,y,w,h,sel_color);
        }
      }else if(se_draw_theme_region_tint(fallback_region+pressed,x,y,w,h,col)){
      }else if(se_draw_theme_region_tint(fallback_region,x,y,w,h,col)){
        if(pressed){
          se_draw_theme_region_tint(fallback_region,x,y,w,h,sel_color);
        }
      }else{
        ImDrawList_AddRect(dl,(ImVec2){x,y},(ImVec2){x+w,y+h},line_color2,0,ImDrawCornerFlags_None,line_w1);  
        ImDrawList_AddRect(dl,(ImVec2){x,y},(ImVec2){x+w,y+h},col,0,ImDrawCornerFlags_None,line_w0);  
        if(pressed){
          ImDrawList_AddRectFilled(dl,(ImVec2){x,y},(ImVec2){x+w,y+h},sel_color,0,ImDrawCornerFlags_None);  
        }
      }
    }else if(b->type==ROUND){
      ImU32 col = SB_BFE(gui_state.touch_controls.hold_toggle,bi,1)?hold_color: SB_BFE(gui_state.touch_controls.turbo_toggle,bi,1)? turbo_color: line_color;
      bool pressed = b->input_id>=0 && emu_state.prev_frame_joy.inputs[b->input_id]>0.1;
      int region = b->theme_region; 
      
      float pos[2] ={
        x_off+win_x+b->pos[0]*win_w,
        win_y+b->pos[1]*win_w
      };
      float r = win_w*b->size[0];
      
      for(int i = 0;i<p;++i){
        int dx = points[i][0]-pos[0];
        int dy = points[i][1]-pos[1];
        if(dx>=-r*1.15 && dx<=r*1.15 && dy>=-r*1.15 && dy<=r*1.15 ){
          col = pressed_color;
          if(b->input_id>=0){
            emu_state.joy.inputs[b->input_id]=1;
            button_pressed_mask|=1<<bi;
          }else touch_only_key_pressed[- b->input_id]=1;
          pressed=true;
        }
      }
      int orig_region = show_labels? region : SE_REGION_KEY_BLANK;
      int fallback_region = show_labels?SE_REGION_KEY_BLANK :region;
      if(se_draw_theme_region_tint(orig_region+(pressed?1:0),
                              pos[0]-r*themed_scale,
                              pos[1]-r*themed_scale,
                              r*2*themed_scale,
                              r*2*themed_scale,
                              col));
      else if(se_draw_theme_region_tint(orig_region,
                              pos[0]-r*themed_scale,
                              pos[1]-r*themed_scale,
                              r*2*themed_scale,
                              r*2*themed_scale,
                              col)){
        if(pressed) se_draw_theme_region_tint(orig_region,
                                               pos[0]-r*themed_scale,
                                               pos[1]-r*themed_scale,
                                               r*2*themed_scale,
                                               r*2*themed_scale,
                                               sel_color);

      }else if(se_draw_theme_region_tint(fallback_region+(pressed?1:0),
                              pos[0]-r*themed_scale,
                              pos[1]-r*themed_scale,
                              r*2*themed_scale,
                              r*2*themed_scale,
                              col));
      else if(se_draw_theme_region_tint(fallback_region,
                              pos[0]-r*themed_scale,
                              pos[1]-r*themed_scale,
                              r*2*themed_scale,
                              r*2*themed_scale,
                              col)){
        if(pressed)  se_draw_theme_region_tint(fallback_region,
                                               pos[0]-r*themed_scale,
                                               pos[1]-r*themed_scale,
                                               r*2*themed_scale,
                                               r*2*themed_scale,
                                               sel_color);
      }else{
        if(pressed)  ImDrawList_AddCircleFilled(dl,(ImVec2){pos[0],pos[1]},r,sel_color,128);
        ImDrawList_AddCircle(dl,(ImVec2){pos[0],pos[1]},r,line_color2,128,line_w1);
        ImDrawList_AddCircle(dl,(ImVec2){pos[0],pos[1]},r,col,128,line_w0);
      }

    }else if(b->type==DPAD){
      float dpad_pos[2]={
        x_off+win_x+b->pos[0]*win_w,
        win_y+b->pos[1]*win_w
      };
      float dpad_sz1 = b->size[0]*win_w;
      float dpad_sz0 = dpad_sz1*0.29;
      bool up = false, down= false, left = false, right = false; 
      for(int i = 0;i<p;++i){
        float dx = points[i][0]-dpad_pos[0];
        float dy = points[i][1]-dpad_pos[1];
        if(dx>=-dpad_sz1*1.15 && dx<=dpad_sz1*1.15 && dy>=-dpad_sz1*1.15 && dy<=dpad_sz1*1.15 && fabs(dx)+fabs(dy)<dpad_sz1+dpad_sz0){
          if(dy>dpad_sz0)down=true;
          if(dy<-dpad_sz0)up=true;

          if(dx>dpad_sz0)right=true;
          if(dx<-dpad_sz0)left=true;
        }
      }

      int dpad_code = up ? 0: down? 6: 3; 
      dpad_code += left? 0: right? 2: 1;
      int draw_dpad_code = dpad_code;
      if(draw_dpad_code==4){
        draw_dpad_code = state->prev_frame_joy.inputs[SE_KEY_UP]>0.2 ? 0: state->prev_frame_joy.inputs[SE_KEY_DOWN]>0.2? 6: 3;
        draw_dpad_code += state->prev_frame_joy.inputs[SE_KEY_LEFT]>0.2? 0: state->prev_frame_joy.inputs[SE_KEY_RIGHT]>0.2? 2: 1;
      }
      if(!se_draw_theme_region_tint(SE_REGION_DPAD_UL+draw_dpad_code,dpad_pos[0]-dpad_sz1*themed_scale,
                                              dpad_pos[1]-dpad_sz1*themed_scale,
                                              dpad_sz1*2*themed_scale,
                                              dpad_sz1*2*themed_scale,
                                    line_color)){
        if(!se_draw_theme_region_tint(SE_REGION_DPAD_UL+4,dpad_pos[0]-dpad_sz1*themed_scale,
                                      dpad_pos[1]-dpad_sz1*themed_scale,
                                      dpad_sz1*2*themed_scale,
                                      dpad_sz1*2*themed_scale,
                                      line_color)){
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
        }
        
        
        if(draw_dpad_code>=6) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]+dpad_sz1},sel_color,0,ImDrawCornerFlags_None);
        if(draw_dpad_code<3)   ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]-dpad_sz1},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},sel_color,0,ImDrawCornerFlags_None);
        
        if((draw_dpad_code%3)==0) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz1,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawCornerFlags_None);
        if((draw_dpad_code%3)==2)ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz1,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawCornerFlags_None);
      }
      if(dpad_code!=4){
        if((dpad_code%3)==0)state->joy.inputs[SE_KEY_LEFT]+=1.0;
        if((dpad_code%3)==2)state->joy.inputs[SE_KEY_RIGHT]+=1.0;
        if(dpad_code<3)state->joy.inputs[SE_KEY_UP]+=1.0;
        if(dpad_code>=6)state->joy.inputs[SE_KEY_DOWN]+=1.0;
      }
    }else printf("Unknown button type: %d\n",b->type);
  }
  if(mode&SE_GAMEPAD_RIGHT)gui_state.touch_controls.turbo_modifier= touch_only_key_pressed[-SE_KEY_TURBO];
  if(mode&SE_GAMEPAD_LEFT)gui_state.touch_controls.hold_modifier= touch_only_key_pressed[-SE_KEY_HOLD];
  if(gui_state.touch_controls.turbo_modifier)gui_state.touch_controls.turbo_toggle|=button_pressed_mask;
  else gui_state.touch_controls.turbo_toggle&=~button_pressed_mask;
  if(gui_state.touch_controls.hold_modifier)gui_state.touch_controls.hold_toggle|=button_pressed_mask;
  else gui_state.touch_controls.hold_toggle&=~button_pressed_mask;
  // Turbo overrides hold
  gui_state.touch_controls.hold_toggle&=~gui_state.touch_controls.turbo_toggle;

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
  if(disp_y_max<win_min.y-item_height||disp_y_min>win_max.y+item_height){
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
  igPushIDStr(first_label);
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
  igPopID();
#ifdef UNICODE_GUI
  free((void*)first_label);
  free((void*)second_label);
#endif
  return clicked; 
}
void se_boxed_image_triple_label(const char * first_label, const char* second_label, const char* third_label, uint32_t third_label_color, const char* box, atlas_tile_t * tile, bool glow){
  ImVec2 win_min,win_sz,win_max;
  win_min.x=0;
  win_min.y=0;                                  // content boundaries min (roughly (0,0)-Scroll), in window coordinates
  igGetWindowSize(&win_sz);
  win_min.y+=igGetScrollY();
  win_max.x = win_min.x+win_sz.x; 
  win_max.y = win_min.y+win_sz.y;

  int item_height = 60; 
  int padding = 4; 

  ImVec2 screen_pos;
  igGetCursorScreenPos(&screen_pos);

  float disp_y_min = igGetCursorPosY();
  int box_h = item_height-padding*2;
  int box_w = box_h;
  ImVec2 curr_pos; 
  igGetCursorPos(&curr_pos);
  ImVec2 next_pos=curr_pos;
  curr_pos.y+=padding; 
  igSetCursorPos(curr_pos);

  ImGuiStyle* style = igGetStyle();
  int scrollbar_width = style->ScrollbarSize;
  int wrap_width = win_sz.x - curr_pos.x - box_w - padding*2 - scrollbar_width - style->ItemSpacing.x - 2;

  ImVec2 out;
  igCalcTextSize(&out,first_label,NULL,false,wrap_width);

  ImVec2 out2;
  igCalcTextSize(&out2,second_label,NULL,false,wrap_width);

  ImVec2 out3 = {0, 0};
  if(third_label)igCalcTextSize(&out3,third_label,NULL,false,wrap_width);

  float spacing = 3;
  float text_height = out.y + out2.y + out3.y + spacing * 2;
  if (text_height > box_h+padding*2)
    next_pos.y+=text_height+2;
  else
    next_pos.y+=box_h+padding*2;

  float disp_y_max = next_pos.y;

  //Early out if not visible (helps for long lists)
  if(disp_y_max<win_min.y||disp_y_min>win_max.y){
    igSetCursorPosY(disp_y_max);
    return;
  }


  // Draw a rectangle to show the text size
  ImDrawList* ig = igGetWindowDrawList();
  // ImVec2 top_left = {screen_pos.x+box_w+padding,screen_pos.y};

  // float max_x = fmax(out.x,out2.x);
  // max_x = fmax(max_x,out3.x);

  // ImVec2 bottom_right = {screen_pos.x+max_x+box_w,screen_pos.y+out.y+out2.y+out3.y+spacing*2};
  // ImDrawList_AddRect(ig, top_left, bottom_right, 0xff0000ff, 0, 0, 1.0f);

  igPushIDStr(second_label);
  // TODO: if (glow)se_draw_glow((ImVec2){screen_pos.x+box_w*0.5,screen_pos.y+box_h*0.5+padding});
  igSetCursorPosX(curr_pos.x+box_w+padding*2);
  igSetCursorPosY(curr_pos.y-padding+1);
  igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing, (ImVec2){spacing,spacing});
  igPushStyleColorU32(ImGuiCol_Text,third_label_color);

  int vert_start = ig->VtxBuffer.Size+4;
  se_section("%s", first_label);
  if (third_label_color == 0xff000000) { // black means rainbow
    int vert_end = ig->VtxBuffer.Size;
    int h = (uint64_t)(stm_now() / 10000000.0) % 360;
    for (int i = vert_start; i < vert_end; i++) {
      h+=5;
      ig->VtxBuffer.Data[i].col = 0xff000000 + se_hsv_to_rgb(h, 40, 100);
    }
  }
  igPopStyleColor(1);

  igSetCursorPosX(curr_pos.x+box_w+padding*2);
  igGetContentRegionAvail(&out);
  se_text("%s", second_label);
  if(third_label){
    igSetCursorPosX(curr_pos.x+box_w+padding*2);
    ImDrawList* ig = igGetWindowDrawList();
    int vert_start = ig->VtxBuffer.Size;
    se_text_disabled("%s", third_label);
  }
  igPopStyleVar(1);
  curr_pos.y-=3;
  igSetCursorPos(curr_pos);
  sg_image image = {SG_INVALID_ID};
  ImVec2 uv0 = (ImVec2){0, 0};
  ImVec2 uv1 = (ImVec2){1, 1};
  if (tile)
  {
      image.id = atlas_get_tile_id(tile);
      atlas_uvs_t uvs = atlas_get_tile_uvs(tile);
      uv0 = (ImVec2){uvs.x1, uvs.y1};
      uv1 = (ImVec2){uvs.x2, uvs.y2};
  }
  if(image.id != SG_INVALID_ID){
      float border_size = 2; 
      ImU32 col = igGetColorU32Col(ImGuiCol_FrameBg,1.0);
      col = third_label_color;
      ImVec2 screen_p;
      igGetCursorScreenPos(&screen_p);
      int vert_start = ig->VtxBuffer.Size;
      ImDrawList_AddRectFilled(igGetWindowDrawList(),
                              (ImVec2){screen_p.x-border_size,screen_p.y-border_size},
                              (ImVec2){screen_p.x+border_size+box_w,screen_p.y+box_h+border_size},
                              col,0,ImDrawCornerFlags_None);
      if (third_label_color == 0xff000000) { // black means rainbow
        int vert_end = ig->VtxBuffer.Size;
        int h = (uint64_t)(stm_now() / 10000000.0) % 360;
        for (int i = vert_start; i < vert_end; i++) {
          h+=50;
          ig->VtxBuffer.Data[i].col = 0xff000000 + se_hsv_to_rgb(h, 40, 100);
        }
      }
    
    igImageButton((ImTextureID)(intptr_t)image.id,(ImVec2){box_w,box_h},uv0,uv1,0,(ImVec4){1,1,1,1},(ImVec4){1,1,1,1});
  }else se_text_centered_in_box((ImVec2){0,0}, (ImVec2){box_w,box_h},box);
  igDummy((ImVec2){1,1});
  igSetCursorPos(next_pos);
  igPopID();
  igSeparator();
}
#ifdef SE_PLATFORM_ANDROID
#include <android/log.h>

#define TAG "SkyEmu"

#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,    TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,     TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,     TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,    TAG, __VA_ARGS__)

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
float se_android_get_display_dpi_scale(){
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;

  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  float result = 1.0;
  if ( nResult != JNI_ERR ){
    // Retrieves NativeActivity.
    jobject nativeActivity = activity->clazz;
    jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity );
    jmethodID MethodDPI= (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "getDPIScale", "()F" );
    result = (*pJNIEnv)->CallFloatMethod(pJNIEnv, nativeActivity, MethodDPI );

    // Finished with the JVM.
    (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }
  return result;
}
void se_android_get_visible_rect(float * top, float * bottom){
  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;

  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  if ( nResult != JNI_ERR ){
    // Retrieves NativeActivity.
    jobject nativeActivity = activity->clazz;
    jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity );
    jmethodID MethodBottom= (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "getVisibleBottom", "()F" );
    *bottom = (*pJNIEnv)->CallFloatMethod(pJNIEnv, nativeActivity, MethodBottom )/se_dpi_scale();
    jmethodID MethodTop= (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "getVisibleTop", "()F" );
    *top = (*pJNIEnv)->CallFloatMethod(pJNIEnv, nativeActivity, MethodTop )/se_dpi_scale();
    // Finished with the JVM.
    (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }
}
void se_android_get_language(char* language_buffer, size_t buffer_size){

  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;

  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  if ( nResult != JNI_ERR ){
    // Retrieves NativeActivity.
    jobject nativeActivity = activity->clazz;
    jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity );
    jmethodID getLanguageMethod= (*pJNIEnv)->GetStaticMethodID(pJNIEnv, ClassNativeActivity, "getLanguage", "()Ljava/lang/String;" );
    if(getLanguageMethod) {
        jstring joStringPropVal = (jstring) (*pJNIEnv)->CallStaticObjectMethod(pJNIEnv,ClassNativeActivity,getLanguageMethod);
        const jchar *jcVal = (*pJNIEnv)->GetStringUTFChars(pJNIEnv, joStringPropVal, JNI_FALSE);
        LOGD("Android Language is %s", jcVal);
        strncpy(language_buffer, jcVal, buffer_size);
        (*pJNIEnv)->ReleaseStringChars(pJNIEnv, joStringPropVal, jcVal);
    }else LOGE("Failed to find getLanguage() method in JNIEnv");
    // Finished with the JVM.
    (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }
}

void se_android_send_controller_key(uint32_t bound_id, bool value) {
  se_controller_state_t *cont = &gui_state.controller;
  for(int k= 0; k<SE_NUM_KEYBINDS;++k){
    int key = cont->key.bound_id[k];
    if(key!=bound_id)continue;
    cont->key.value[k] = value;
  }
}
void se_android_poll_events(bool visible){
  se_controller_state_t *cont = &gui_state.controller;
  cont->key.last_bind_activitiy=-1;
  cont->analog.last_bind_activitiy=-1;
  static bool last_visible = false;
  if(visible!=last_visible){
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
      if(visible){
        jmethodID MethodShowKeyboard = (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "showKeyboard", "()V" );
        (*pJNIEnv)->CallVoidMethod(pJNIEnv, nativeActivity, MethodShowKeyboard );
      }else{
        jmethodID MethodShowKeyboard = (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "hideKeyboard", "()V" );
        (*pJNIEnv)->CallVoidMethod(pJNIEnv, nativeActivity, MethodShowKeyboard );
      }
      // Finished with the JVM.
      (*pJavaVM)->DetachCurrentThread(pJavaVM);
    }
    last_visible = visible;
  }
  float top = 0;
  float bottom = 0;
  se_android_get_visible_rect(&top, &bottom);
  float size = (bottom-top);
  gui_state.screen_height= (bottom-top)*se_dpi_scale();

  ANativeActivity* activity =(ANativeActivity*)sapp_android_get_native_activity();
  // Attaches the current thread to the JVM.
  JavaVM *pJavaVM = activity->vm;
  JNIEnv *pJNIEnv = activity->env;


  jint nResult = (*pJavaVM)->AttachCurrentThread(pJavaVM, &pJNIEnv, NULL );
  if ( nResult != JNI_ERR ) {
    // Retrieves NativeActivity.
    jobject nativeActivity = activity->clazz;
    jclass ClassNativeActivity = (*pJNIEnv)->GetObjectClass(pJNIEnv, nativeActivity);
    jmethodID getEvent= (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "getEvent", "()I" );
    jmethodID pollKeyboard= (*pJNIEnv)->GetMethodID(pJNIEnv, ClassNativeActivity, "pollKeyboard", "()V" );
    (*pJNIEnv)->CallVoidMethod(pJNIEnv, nativeActivity, pollKeyboard );
    ImGuiIO* io= igGetIO();

    io->KeysDown[io->KeyMap[ImGuiKey_Backspace]]=false;
    io->KeysDown[io->KeyMap[ImGuiKey_LeftArrow]]=false;
    io->KeysDown[io->KeyMap[ImGuiKey_RightArrow]]=false;
    io->KeysDown[io->KeyMap[ImGuiKey_Enter]]=false;
    while (true) {
      int32_t event = (*pJNIEnv)->CallIntMethod(pJNIEnv, nativeActivity, getEvent );
      if(event==-1)break;
      if(!(event&0xF0000000))
          ImGuiIO_AddInputCharacter(igGetIO(),event&0x0fffffff);
      else if(event&0x40000000){
          int imgui_key = io->KeyMap[event&0xff];
          io->KeysDown[imgui_key] = (event&0x80000000)==0;
          io->KeysDownDuration[imgui_key]=0;
      }else if(event&0x20000000){
        //Controller keypad
        int keycode = SB_BFE(event,0,16);
        int pressed = SB_BFE(event,16,1);
        cont->key.last_bind_activitiy = keycode;
        se_android_send_controller_key(keycode,pressed);
      }else if(event&0x10000000){
        //Controller joy axis
        int16_t value = SB_BFE(event,0,16);
        float fv = value/32768.;
        int axis = SB_BFE(event,16,8);

        if(fv<0.2&&fv>-0.2 && (int)axis < sizeof(cont->axis_last_zero_time)/sizeof(cont->axis_last_zero_time[0])){
          cont->axis_last_zero_time[axis]=se_time();
        }
        if((fv>0.3)||(fv<-0.3&&fv>-0.6))cont->analog.last_bind_activitiy = axis;
        double delta = se_time()-cont->axis_last_zero_time[axis];

        if(fv>0.4&&delta<2)cont->key.last_bind_activitiy = axis|SE_JOY_POS_MASK;
        if(fv<-0.4&&delta<2)cont->key.last_bind_activitiy = axis|SE_JOY_NEG_MASK;
        se_android_send_controller_key(axis|SE_JOY_POS_MASK,fv>0.3);
        se_android_send_controller_key(axis|SE_JOY_NEG_MASK,fv<-0.3);
        for(int a= 0; a<SE_NUM_ANALOGBINDS;++a){
          int bound_id= cont->analog.bound_id[a];
          if(axis==bound_id){
            cont->analog.value[a]= fv;
            break;
          }
        }
      }
    }
    (*pJavaVM)->DetachCurrentThread(pJavaVM);
  }

  for(int i=0;i<SE_NUM_KEYBINDS;++i)emu_state.joy.inputs[i]  += cont->key.value[i]>0.5;

  emu_state.joy.inputs[SE_KEY_LEFT]  += cont->analog.value[SE_ANALOG_LEFT_RIGHT]<-0.3;
  emu_state.joy.inputs[SE_KEY_RIGHT] += cont->analog.value[SE_ANALOG_LEFT_RIGHT]> 0.3;
  emu_state.joy.inputs[SE_KEY_UP]   += cont->analog.value[SE_ANALOG_UP_DOWN]<-0.3;
  emu_state.joy.inputs[SE_KEY_DOWN] += cont->analog.value[SE_ANALOG_UP_DOWN]>0.3;

  emu_state.joy.inputs[SE_KEY_L]  += cont->analog.value[SE_ANALOG_L]>0.1;
  emu_state.joy.inputs[SE_KEY_R]  += cont->analog.value[SE_ANALOG_R]>0.1;
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
  free(data);
}
void se_download_emscripten_save_states()
{
  mz_zip_error zip_error;
  char archive_filename[SB_FILE_PATH_SIZE];
  const char* base, *file_name, *ext;
  sb_breakup_path(emu_state.rom_path,&base,&file_name,&ext);
  snprintf(archive_filename,SB_FILE_PATH_SIZE,"%s.save_states.zip",file_name);
  for(int i=0;i<SE_NUM_SAVE_STATES;++i)
  {
    char save_state_path[SB_FILE_PATH_SIZE];
    char save_state_name[SB_FILE_PATH_SIZE];
    snprintf(save_state_path,SB_FILE_PATH_SIZE,"%s.slot%d.state.png",emu_state.save_data_base_path,i);
    snprintf(save_state_name,SB_FILE_PATH_SIZE,"slot%d.state.png",i);
    if(!sb_file_exists(save_state_path))continue;
    size_t data_size;
    uint8_t* data = sb_load_file_data(save_state_path,&data_size);
    mz_bool status = mz_zip_add_mem_to_archive_file_in_place_v2(archive_filename,save_state_name,data,data_size,NULL,0,MZ_BEST_COMPRESSION,&zip_error);
    free(data);
    if (!status)
    {
      printf("mz_zip_add_mem_to_archive_file_in_place_v2 failed: %s\n",mz_zip_get_error_string(zip_error));
      break;
    }
  }
  mutex_lock(cloud_state.save_states_mutex);
  for(int i=0;i<SE_NUM_SAVE_STATES;++i){
    if(cloud_state.save_states_busy[i]||cloud_state.save_states[i].valid==false)continue;
    char save_state_name[SB_FILE_PATH_SIZE];
    snprintf(save_state_name,SB_FILE_PATH_SIZE,"cloud.slot%d.state.png",i);
    uint32_t width=0, height=0;
    uint8_t* imdata = se_save_state_to_image(&cloud_state.save_states[i], &width,&height);
    se_png_write_context_t cont ={0};
    stbi_write_png_to_func(se_png_write_mem, &cont,width,height,4, imdata, 0);
    free(imdata);
    if(cont.data){
      mz_bool status = mz_zip_add_mem_to_archive_file_in_place_v2(archive_filename,save_state_name,cont.data,cont.size,NULL,0,MZ_BEST_COMPRESSION,&zip_error);
      free(cont.data);
      if (!status){
        printf("mz_zip_add_mem_to_archive_file_in_place_v2 failed: %s\n",mz_zip_get_error_string(zip_error));
        break;
      }
    }
  }
  mutex_unlock(cloud_state.save_states_mutex);

  se_download_emscripten_file(archive_filename);
  remove(archive_filename);
}
#endif 


void se_bring_text_field_into_view(){
  if(igGetIO()->WantTextInput){
    
    ImGuiWindow* window = igGetCurrentContext()->HoveredWindow;
    if(igGetCurrentContext()->ActiveIdWindow)window=igGetCurrentContext()->ActiveIdWindow;
    
    if (window!=NULL) {
      float size = gui_state.screen_height/se_dpi_scale();
      float y = igGetCurrentContext()->PlatformImeLastPos.y+30;
      if (y >= size) igSetScrollYWindowPtr(window, window->Scroll.y + (y - size));
    }
  }
}

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
void se_file_browser_accept(const char * path){
  se_file_browser_state_t* file_browse = &gui_state.file_browser;
  if(file_browse->file_open_fn){
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    file_browse->file_open_fn(path);
  }
  if(file_browse->output_path){
    strncpy(file_browse->output_path,path,SB_FILE_PATH_SIZE);
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
  }
}
static void se_file_picker_click_region(int x, int y, int w, int h, void (*accept_func)(const char*)){
  float delta_dpi_scale = se_dpi_scale()/sapp_dpi_scale();

    #ifdef EMSCRIPTEN
      while(gui_state.current_click_region_id>=gui_state.max_click_region_id){
        EM_ASM({
            var input = document.createElement('input');
            input.id = 'fileInput'+$0;
            input.value = '';
            input.type = 'file';
            document.body.appendChild(input);
            var inputStage = document.createElement('input');
            inputStage.id = 'fileStaging'+$0;
            inputStage.value = '';
            document.body.appendChild(inputStage);
            input.onmousemove =  input.onmouseover =  function(e) {
              const mouseMoveEvent = new MouseEvent('mousemove', {
                bubbles: true,
                cancelable: true,
                clientX: event.clientX,
                clientY: event.clientY
              });
              document.getElementById('canvas').dispatchEvent(mouseMoveEvent);
            };
        },gui_state.current_click_region_id);
        gui_state.max_click_region_id++;
      }
      char * new_path = (char*)EM_ASM_INT({
      var input = document.getElementById('fileInput'+$0);
      input.style.left = $1 +'px';
      input.style.top = $2 +'px';
      input.style.width = $3 +'px';
      input.style.height= $4 +'px';
      input.style.visibility = 'visible';
      input = document.getElementById('fileInput'+$0);
      if(input.value!= ''){
        console.log(input.value);
        var reader= new FileReader();
        var file = input.files[0];
        function print_file(e){
            var result=reader.result;
            const uint8_view = new Uint8Array(result);
            var out_file = '/offline/'+filename;
            if(FS.analyzePath(out_file)["exists"])FS.unlink(out_file);
            FS.writeFile(out_file, uint8_view);
            FS.syncfs(function (err) {});
            var input_stage = document.getElementById('fileStaging'+$0);
            input_stage.value = out_file;
        }
        reader.addEventListener('loadend', print_file);
        reader.readAsArrayBuffer(file);
        var filename = file.name;
        input.value = '';
      }
      var input_stage = document.getElementById('fileStaging'+$0);
      var ret_path = '';
      if(input_stage.value !=''){
        ret_path = input_stage.value;
        input_stage.value = '';
      }
      var sz = lengthBytesUTF8(ret_path)+1;
      var string_on_heap = _malloc(sz);
      stringToUTF8(ret_path, string_on_heap, sz);
      return string_on_heap;
    },gui_state.current_click_region_id,x*delta_dpi_scale,y*delta_dpi_scale,w*delta_dpi_scale,h*delta_dpi_scale);

    if(new_path&&new_path[0]){
      se_file_browser_accept(new_path);
    }
    free(new_path);
  #endif 
  ++gui_state.current_click_region_id;
}
static void se_reset_html_click_regions(){
  while(gui_state.current_click_region_id<gui_state.max_click_region_id){
#if defined(EMSCRIPTEN)
    EM_ASM({
      var input = document.getElementById('fileInput'+$0);
      input.style.visibility= "hidden";
    },gui_state.current_click_region_id);
#endif
    gui_state.current_click_region_id++;
  }
  gui_state.current_click_region_id=0;

#if defined(EMSCRIPTEN)
  EM_ASM({
    var input = document.getElementById('driveLogin');
    if (typeof(input) != 'undefined' && input != null) {
      input.style.visibility= "hidden";
    }
    var input2 = document.getElementById('raRegister');
    if (typeof(input2) != 'undefined' && input2 != null) {
      input2.style.visibility= "hidden";
    }
  });
#endif
}
//Opens a file picker when clicked is true or a user clicks in the click region defined by x,y,w,h in ImGUI coordinates
//File pickers only open for the click region on web platforms due to web security precautions. On Desktop/Native platforms
//they only open if clicked is set to true. 
void se_open_file_browser(bool clicked, float x, float y, float w, float h, void (*file_open_fn)(const char* dir), const char ** file_types,char * output_path){
  #ifndef EMSCRIPTEN
  if(!clicked)return; 
  #endif 
  unsigned num_file_types = 0; 
  bool allow_directory =false;
  while(file_types[num_file_types]){
    if(!strcmp(file_types[num_file_types],"$DIR$"))allow_directory=true;
    num_file_types++;
  }
  gui_state.file_browser.allow_directory=allow_directory;
  gui_state.file_browser.num_file_types = num_file_types;
  gui_state.file_browser.file_types = file_types;
  gui_state.file_browser.file_open_fn = file_open_fn;
  gui_state.file_browser.output_path = output_path;

  #ifdef EMSCRIPTEN
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    se_file_picker_click_region(x,y,w,h,file_open_fn);
    return;
  #endif

  #ifdef USE_BUILT_IN_FILEBROWSER
    gui_state.file_browser.state=SE_FILE_BROWSER_OPEN;
  #endif
  #ifdef USE_TINY_FILE_DIALOGS
    if(tinyfd_openFileDialog("tinyfd_query","", num_file_types,file_types,NULL,0)){
      gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    }
    char *outPath= NULL;
    if(allow_directory)outPath=tinyfd_selectFolderDialog(se_localize_and_cache("Select Folder"),output_path?output_path:"");
    else outPath = tinyfd_openFileDialog(se_localize_and_cache("Open ROM"),"", num_file_types,file_types,NULL,0);
    if (outPath){
        se_file_browser_accept(outPath);
    }
  #endif
  #ifdef SE_PLATFORM_IOS
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    se_ios_open_file_picker(num_file_types,file_types);
  #endif
  #ifdef SE_PLATFORM_ANDROID
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
    se_android_open_file_picker();
  #endif
}

bool se_process_file_browser(){
  const char *home_dir = sb_get_home_path();
  
  if(gui_state.file_browser.state==SE_FILE_BROWSER_CLOSED)return false; 
  if(gui_state.file_browser.current_path[0]=='\0')strncpy(gui_state.file_browser.current_path,home_dir,SB_FILE_PATH_SIZE);

  ImVec2 w_pos={0,0};
  ImVec2 w_size={gui_state.screen_width,gui_state.screen_height};
 
  w_size.x/=se_dpi_scale();
  w_size.y/=se_dpi_scale();
  igSetNextWindowPos(w_pos, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){w_size.x,0}, ImGuiCond_Always);
  bool file_browser_open =true;
  se_file_browser_state_t* file_browse = &gui_state.file_browser;

  igBegin(se_localize_and_cache(ICON_FK_FILE_O " File Browser"),&file_browser_open,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
  if(!file_browser_open)gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
  if(se_selectable_with_box("Exit File Browser","Go back to recently loaded games",ICON_FK_BAN,false,0)){
    gui_state.file_browser.state=SE_FILE_BROWSER_CLOSED;
  }
  if(file_browse->allow_directory){
    if(se_selectable_with_box("Select Folder",gui_state.file_browser.current_path,ICON_FK_CHECK,false,0)){
      size_t len = strnlen(gui_state.file_browser.current_path,SB_FILE_PATH_SIZE);
      if(len<SB_FILE_PATH_SIZE-2){
        if(gui_state.file_browser.current_path[len-1]!='\\' && gui_state.file_browser.current_path[len-1]!= '/' ){
          gui_state.file_browser.current_path[len]='/';
          gui_state.file_browser.current_path[len+1]=0;
        }
      }
      se_file_browser_accept(gui_state.file_browser.current_path);
    }
  }

  if(se_selectable_with_box("Go to home directory",home_dir,ICON_FK_HOME,false,0)){
    strncpy(gui_state.file_browser.current_path, home_dir, SB_FILE_PATH_SIZE);
  }

  const char* parent_dir = sb_parent_path(gui_state.file_browser.current_path);
  if(se_selectable_with_box("Go to parent directory",parent_dir,ICON_FK_ARROW_UP,false,0)){
    strncpy(gui_state.file_browser.current_path, parent_dir, SB_FILE_PATH_SIZE);
  }
  float list_y_off = igGetWindowHeight(); 

  igEnd();

  igSetNextWindowPos((ImVec2){w_pos.x,w_pos.y+list_y_off}, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){w_size.x,w_size.y-list_y_off}, ImGuiCond_Always);

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
      printf("Error opening %s\n",gui_state.file_browser.current_path);
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
          for(int i=0;i<file_browse->num_file_types;++i){
            if(sb_path_has_file_ext(file_browse->cached_files[f].path,file_browse->file_types[i])){show_item=true;break;}
          }
          if(file_browse->num_file_types==0)show_item=true;
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
    const char *ext = file_browse->cached_files[f].is_link ? ICON_FK_FOLDER_OPEN_O:ICON_FK_FOLDER_OPEN;
    if (!file_browse->cached_files[f].is_dir) {
      const char* base, *file;
      sb_breakup_path(file_browse->cached_files[f].path, &base, &file, &ext);
    }
    if (se_selectable_with_box(file_browse->cached_files[f].name, file_browse->cached_files[f].path, ext, false, 0)) {
      if (file_browse->cached_files[f].is_dir)
        strncpy(gui_state.file_browser.current_path, file_browse->cached_files[f].path, SB_FILE_PATH_SIZE);
      else {
        se_file_browser_accept(file_browse->cached_files[f].path);
      }
    }
  }
  igEnd();
  return true;
}
bool se_load_rom_file_browser_callback(const char* path){
  se_load_rom(path);
  return emu_state.rom_loaded;
}
bool se_string_contains_string_case_insensitive(char *canidate, char *search) {
  int len1 = strlen(canidate);
  int len2 = strlen(search);
  if(len2==0)return true;
  for (int i = 0; i < len1 - len2; i++) {
    int j=0;
    for (j = 0; j < len2; j++) {
        if (tolower(canidate[i+j]) != tolower(search[j]))break;
    }
    if (j == len2) return true;
  }
  return false;
}
void se_load_rom_overlay(bool visible){
  if(visible==false)return;
  ImVec2 w_pos, w_size;
  igGetWindowPos(&w_pos);
  igGetWindowSize(&w_size);
  w_size.x/=se_dpi_scale();
  w_size.y/=se_dpi_scale();
  igSetNextWindowSize((ImVec2){w_size.x,w_size.y},ImGuiCond_Always);
  igSetNextWindowPos((ImVec2){w_pos.x,w_pos.y},ImGuiCond_Always,(ImVec2){0,0});
  igSetNextWindowBgAlpha(gui_state.settings.hardcore_mode? 1.0: SE_TRANSPARENT_BG_ALPHA);
  igBegin(se_localize_and_cache(ICON_FK_FILE_O " Load Game"),(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in)?NULL:&gui_state.overlay_open,ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
  
  float list_y_off = igGetWindowHeight(); 
  int x, y, w,  h;
  ImVec2 win_p,win_max;
  igGetWindowContentRegionMin(&win_p);
  igGetWindowContentRegionMax(&win_max);
  x = win_p.x;
  y = win_p.y;
  w = win_max.x-win_p.x;
  h = win_max.y-win_p.y;
  y+=w_pos.y;
  x+=w_pos.x;
  const char * prompt1 = "Load ROM from file (.gb, .gbc, .gba, .zip)";
  const char * prompt2= "You can also drag & drop a ROM to load it";
  if(gui_state.ui_type==SE_UI_ANDROID||gui_state.ui_type==SE_UI_IOS){
    prompt2 = "";
  }else if (gui_state.ui_type==SE_UI_WEB){
    prompt1 = "Load ROM(.gb, .gbc, .gba, .zip), save(.sav), or GBA bios (gba_bios.bin) from file";
    prompt2 = "You can also drag & drop a ROM/save file to load it";
  }
  float y1 = igGetCursorPosY();
  bool clicked = se_selectable_with_box(prompt1,prompt2,ICON_FK_FOLDER_OPEN,false,0);
  float y2 = igGetCursorPosY();
  se_open_file_browser(clicked, x,y,w,y2-y1, se_load_rom,valid_rom_file_types,NULL);
  
  
  se_section(ICON_FK_CLOCK_O " Load Recently Played Game");
  igDummy((ImVec2){1,1});

  igSameLine(0,5);
  se_text("%s ",ICON_FK_SEARCH);
  igSameLine(0,5);
  int button_w = 40-4; 
  igPushItemWidth(-(button_w+5)*2);
  igInputText("##search",gui_state.search_buffer,sizeof(gui_state.search_buffer),ImGuiInputTextFlags_None, NULL,NULL);
  igPopItemWidth();
  igSameLine(0,5);

  const char* icon=ICON_FK_LONG_ARROW_DOWN ICON_FK_CLOCK_O;
  switch(gui_state.recent_games_sort_type){
    case SE_NO_SORT:        icon=ICON_FK_LONG_ARROW_DOWN ICON_FK_CLOCK_O ;break;
    case SE_SORT_ALPHA_ASC: icon=ICON_FK_SORT_ALPHA_ASC;break;
    case SE_SORT_ALPHA_DESC:icon=ICON_FK_SORT_ALPHA_DESC;break;
    default: 
      gui_state.recent_games_sort_type = SE_NO_SORT;
      se_sort_recent_games_list();
  }
  if(se_button(icon,(ImVec2){button_w,0})){
    gui_state.recent_games_sort_type++;
    if(gui_state.recent_games_sort_type>SE_SORT_ALPHA_DESC)gui_state.recent_games_sort_type=SE_NO_SORT;
    se_sort_recent_games_list();
  }
  igSameLine(0,5);
  bool pop_style = false;
  if(gui_state.allow_deletion_from_game_list){
    ImVec4 c = igGetStyle()->Colors[ImGuiCol_Button];
    c.x = c.x*0.5+0.5;
    c.y *=0.5;
    c.z *=0.5;
    igPushStyleColorVec4(ImGuiCol_Button, c);
    pop_style=true;
  }
  if(se_button(ICON_FK_TRASH,(ImVec2){button_w,0})){
    gui_state.allow_deletion_from_game_list = !gui_state.allow_deletion_from_game_list;
  }
  if(pop_style)igPopStyleColor(1);
  igSeparator();
  int num_entries=0;
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    if(gui_state.sorted_recently_loaded_games[i]==-1)break;
    se_game_info_t *info = gui_state.recently_loaded_games+gui_state.sorted_recently_loaded_games[i];
    if(strcmp(info->path,"")==0)break;
    igPushIDInt(i);
    const char* base, *file_name, *ext; 
    sb_breakup_path(info->path,&base,&file_name,&ext);
    char ext_upper[8]={0};
    for(int i=0;i<7&&ext[i];++i)ext_upper[i]=toupper(ext[i]);
    int reduce_width = 0; 
    int cross_width = 40;
    if(!gui_state.allow_deletion_from_game_list)cross_width=0;
    #ifdef EMSCRIPTEN
    char save_file_path[SB_FILE_PATH_SIZE];
    snprintf(save_file_path,SB_FILE_PATH_SIZE,"%s/%s.sav",base,file_name);
    bool save_exists = sb_file_exists(save_file_path);
    if(save_exists)reduce_width=85; 
    #endif
    if(!se_string_contains_string_case_insensitive(info->path,gui_state.search_buffer)){
      igPopID();
      continue;
    }
    if(se_selectable_with_box(file_name,se_replace_fake_path(info->path),ext_upper,false,reduce_width+cross_width)){
      se_load_rom(info->path);
    }
    #ifdef EMSCRIPTEN
    if(save_exists){
      igSameLine(0,4);
      if(se_button(ICON_FK_DOWNLOAD " Export Save",(ImVec2){reduce_width-4,40}))se_download_emscripten_file(save_file_path);
    }
    #endif 
    if(gui_state.allow_deletion_from_game_list){
      float old_y = igGetCursorPosY();
      igSameLine(0, 4);
      if(se_button(ICON_FK_TIMES, (ImVec2){cross_width-4,cross_width-4}))se_clear_game_from_recents(gui_state.sorted_recently_loaded_games[i]);
      se_tooltip("Remove from recently played");
      igSetCursorPosY(old_y);
    }
    igSeparator();
    num_entries++;
    igPopID();
  }
  if(num_entries==0)se_text("No recently played games");
  igEnd();
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
          if(v<0.2&&v>-0.2 && (int)sdlEvent.jaxis.axis < sizeof(cont->axis_last_zero_time)/sizeof(cont->axis_last_zero_time[0])){
            cont->axis_last_zero_time[sdlEvent.jaxis.axis]=se_time();
          }
          if((v>0.3)||(v<-0.3&&v>-0.6))
            cont->analog.last_bind_activitiy = sdlEvent.jaxis.axis;  
          double delta = se_time()-cont->axis_last_zero_time[sdlEvent.jaxis.axis];
          if(v>0.4&&delta<2)cont->key.last_bind_activitiy = sdlEvent.jaxis.axis|SE_JOY_POS_MASK;
          if(v<-0.4&&delta<2)cont->key.last_bind_activitiy = sdlEvent.jaxis.axis|SE_JOY_NEG_MASK;
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
  #ifdef ENABLE_HTTP_CONTROL_SERVER
  hcs_update(gui_state.settings.http_control_server_enable,gui_state.settings.http_control_server_port,se_hcs_callback);
  if(gui_state.settings.http_control_server_enable){
    for(int i=0;i<SE_NUM_KEYBINDS;++i)emu_state.joy.inputs[i]+=gui_state.hcs_joypad.inputs[i];
  }
  hcs_suspend_callbacks();
  #endif
  se_update_key_turbo(&emu_state);
  se_update_solar_sensor(&emu_state);

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
  static double simulation_time = -1;
  double curr_time = se_time();

  if(fabs(curr_time-simulation_time)>1.0/60.*10||emu_state.run_mode==SB_MODE_PAUSE)simulation_time = curr_time;
  if(emu_state.run_mode==SB_MODE_RUN||emu_state.run_mode==SB_MODE_STEP||emu_state.run_mode==SB_MODE_REWIND){
    emu_state.frame=0;
    int max_frames_per_tick =1+ emu_state.step_frames;
    if(emu_state.run_mode==SB_MODE_STEP)max_frames_per_tick= emu_state.step_frames;

    emu_state.render_frame = true;

    double sim_fps= se_get_sim_fps();
    double sim_time_increment = 1./sim_fps/emu_state.step_frames;
    if(emu_state.run_mode==SB_MODE_REWIND)sim_time_increment*=frames_per_rewind_state/2;
    if(emu_state.step_frames<0){
      max_frames_per_tick =1;
      sim_time_increment = 1./sim_fps*-emu_state.step_frames;
    }
    bool unlocked_mode = emu_state.step_frames==0;
    if(gui_state.test_runner_mode)unlocked_mode=true;
    if(unlocked_mode&&emu_state.run_mode!=SB_MODE_STEP){
      sim_time_increment=0;
      max_frames_per_tick=1000;
      simulation_time=curr_time+1./30.;
    }
    while(max_frames_per_tick--){
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
  if(emu_state.run_mode==SB_MODE_STEP)printf("Emulated %d frames\n",emu_state.frame);
  if(emu_state.run_mode==SB_MODE_STEP)emu_state.run_mode = SB_MODE_PAUSE; 
  if(emu_state.run_mode==SB_MODE_PAUSE)emu_state.frame = 0; 
  if(emu_state.run_mode==SB_MODE_REWIND)emu_state.frame = - emu_state.frame*frames_per_rewind_state;

  emu_state.prev_frame_joy = emu_state.joy; 
  se_reset_joy(&emu_state.joy);

  #ifdef ENABLE_HTTP_CONTROL_SERVER
    hcs_resume_callbacks();
  #endif
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
  colors[ImGuiCol_FrameBg]                = (ImVec4){0.2f, 0.2f, 0.2f, 0.9f};
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
  colors[ImGuiCol_SliderGrab]             = (ImVec4){0.34f, 0.34f, 0.34f, 0.8f};
  colors[ImGuiCol_SliderGrabActive]       = (ImVec4){0.56f, 0.56f, 0.56f, 0.8f};
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

  uint8_t *palette = gui_state.theme.palettes;
  //Base color
  if(palette[0*4+3]){
    float r = palette[0*4+0]/255.;
    float g = palette[0*4+1]/255.;
    float b = palette[0*4+2]/255.;
    float a = palette[0*4+3]/255.;
    colors[ImGuiCol_WindowBg]               = (ImVec4){r, g, b, a};
    colors[ImGuiCol_ChildBg]                = (ImVec4){r, g, b, a};
    colors[ImGuiCol_PopupBg]                = (ImVec4){r, g, b, a};
    colors[ImGuiCol_MenuBarBg]              = (ImVec4){r, g, b, a};
  }
  //Text Color
  if(palette[1*4+3]){
    float r = palette[1*4+0]/255.;
    float g = palette[1*4+1]/255.;
    float b = palette[1*4+2]/255.;
    float a = palette[1*4+3]/255.;
    colors[ImGuiCol_PlotLinesHovered]   =
    colors[ImGuiCol_PlotHistogramHovered]   =
    colors[ImGuiCol_Text]                   = (ImVec4){r,g,b,a};
    colors[ImGuiCol_TextDisabled]           = (ImVec4){r,g,b,a*0.4f};
    colors[ImGuiCol_ScrollbarGrabHovered]           = (ImVec4){r,g,b,a*0.6f};
    colors[ImGuiCol_SliderGrabActive] = colors[ImGuiCol_ScrollbarGrabActive]           = (ImVec4){r,g,b,a*0.8f};
  }
  //Second Color
  if(palette[2*4+3]){
    float r = palette[2*4+0]/255.;
    float g = palette[2*4+1]/255.;
    float b = palette[2*4+2]/255.;
    float a = palette[2*4+3]/255.;
    colors[ImGuiCol_FrameBg]                = (ImVec4){r,g,b,a};
    colors[ImGuiCol_Border]                 = (ImVec4){r,g,b,a};

    colors[ImGuiCol_ScrollbarBg]            = (ImVec4){r,g,b,a};
    colors[ImGuiCol_Button] = (ImVec4){r, g, b, a};
    colors[ImGuiCol_ButtonHovered]          = (ImVec4){r,g,b, a*0.54f};
    colors[ImGuiCol_ButtonActive]           = (ImVec4){r*2,g*2,b*2, a*1.00f};
  }
  //Tab/Header
  if(palette[3*4+3]){
    float r = palette[3*4+0]/255.;
    float g = palette[3*4+1]/255.;
    float b = palette[3*4+2]/255.;
    float a = palette[3*4+3]/255.;
    colors[ImGuiCol_TitleBg]                = 
    colors[ImGuiCol_TitleBgActive]          = 
    colors[ImGuiCol_TitleBgCollapsed]       = 
    colors[ImGuiCol_TableHeaderBg]          =
    colors[ImGuiCol_TableBorderStrong]      = (ImVec4){r,g,b,a};

    colors[ImGuiCol_SliderGrab] = colors[ImGuiCol_ScrollbarGrab]           = (ImVec4){r,g,b,a};

    colors[ImGuiCol_FrameBgHovered]         = (ImVec4){r,g,b,a*0.75};
    colors[ImGuiCol_FrameBgActive]          = (ImVec4){r,g,b,a};

    colors[ImGuiCol_Tab]                    = 
    colors[ImGuiCol_Header]                 = (ImVec4){r,g,b,a*0.25};
    colors[ImGuiCol_TabHovered]             = 
    colors[ImGuiCol_HeaderHovered]          = (ImVec4){r,g,b,a*0.75};
    colors[ImGuiCol_TabActive]              = 
    colors[ImGuiCol_HeaderActive]           = (ImVec4){r,g,b,a};

  }
  //Accent color (checkmark, bar/line graph)
  if(palette[4*4+3]){
    float r = palette[4*4+0]/255.;
    float g = palette[4*4+1]/255.;
    float b = palette[4*4+2]/255.;
    float a = palette[4*4+3]/255.;
    colors[ImGuiCol_PlotLines]              = 
    colors[ImGuiCol_PlotHistogram]          =
    colors[ImGuiCol_CheckMark]              = (ImVec4){r,g,b,a};
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
  style->PopupBorderSize                   = 1;
  style->FrameBorderSize                   = 0;
  style->TabBorderSize                     = 0;
  style->WindowRounding                    = 0;
  style->ChildRounding                     = 4;
  style->FrameRounding                     = 1;
  style->PopupRounding                     = 0;
  style->ScrollbarRounding                 = 9;
  style->GrabRounding                      = 100;
  style->LogSliderDeadzone                 = 4;
  style->TabRounding                       = 4;
  style->ButtonTextAlign = (ImVec2){0.5,0.5};
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
#ifdef SE_PLATFORM_ANDROID
void se_set_default_controller_binds(se_controller_state_t* cont){
  if(!cont)return;
  for(int i=0;i<SE_NUM_KEYBINDS;++i)cont->key.bound_id[i]=-1;
  cont->key.bound_id[SE_KEY_A]= AKEYCODE_BUTTON_A;
  cont->key.bound_id[SE_KEY_B]= AKEYCODE_BUTTON_B;
  cont->key.bound_id[SE_KEY_X]= AKEYCODE_BUTTON_X;
  cont->key.bound_id[SE_KEY_Y]= AKEYCODE_BUTTON_Y;
  cont->key.bound_id[SE_KEY_L]= AKEYCODE_BUTTON_L1;
  cont->key.bound_id[SE_KEY_R]= AKEYCODE_BUTTON_R1;
  cont->key.bound_id[SE_KEY_UP]= AKEYCODE_DPAD_UP;
  cont->key.bound_id[SE_KEY_DOWN]= AKEYCODE_DPAD_DOWN;
  cont->key.bound_id[SE_KEY_LEFT]= AKEYCODE_DPAD_LEFT;
  cont->key.bound_id[SE_KEY_RIGHT]= AKEYCODE_DPAD_RIGHT;
  cont->key.bound_id[SE_KEY_START]= AKEYCODE_BUTTON_START;
  cont->key.bound_id[SE_KEY_SELECT]= AKEYCODE_BUTTON_SELECT;

  cont->key.bound_id[SE_KEY_EMU_PAUSE]= AKEYCODE_BUTTON_MODE;
  cont->key.bound_id[SE_KEY_RESET_GAME]= AKEYCODE_R;
  cont->key.bound_id[SE_KEY_CAPTURE_STATE(0)]= AKEYCODE_1;
  cont->key.bound_id[SE_KEY_CAPTURE_STATE(1)]= AKEYCODE_2;
  cont->key.bound_id[SE_KEY_CAPTURE_STATE(2)]= AKEYCODE_3;
  cont->key.bound_id[SE_KEY_CAPTURE_STATE(3)]= AKEYCODE_4;
  cont->key.bound_id[SE_KEY_RESTORE_STATE(0)]= AKEYCODE_F1;
  cont->key.bound_id[SE_KEY_RESTORE_STATE(1)]= AKEYCODE_F2;
  cont->key.bound_id[SE_KEY_RESTORE_STATE(2)]= AKEYCODE_F3;
  cont->key.bound_id[SE_KEY_RESTORE_STATE(3)]= AKEYCODE_F4;

  cont->key.bound_id[SE_KEY_SOLAR_P]= AKEYCODE_PLUS;
  cont->key.bound_id[SE_KEY_SOLAR_M]= AKEYCODE_MINUS;
  /*
  cont->key.bound_id[SE_KEY_EMU_PAUSE] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_GUIDE,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_REWIND] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE1,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_FF_2X] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE2,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_FF_MAX] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE3,SE_JOY_POS_MASK);
  */
  cont->analog.bound_id[SE_ANALOG_UP_DOWN] = AMOTION_EVENT_AXIS_Y;
  cont->analog.bound_id[SE_ANALOG_LEFT_RIGHT] = AMOTION_EVENT_AXIS_X;
  cont->analog.bound_id[SE_ANALOG_L] = AMOTION_EVENT_AXIS_LTRIGGER;
  cont->analog.bound_id[SE_ANALOG_R] = AMOTION_EVENT_AXIS_RTRIGGER;
}
#endif
//Returns true if loaded successfully
bool se_load_controller_settings(se_controller_state_t * cont){
  if(!cont)return false;
#ifdef USE_SDL
  if(!cont->sdl_joystick)return false;
#endif
#ifdef SE_PLATFORM_ANDROID
  strncpy(cont->name,SE_ANDROID_CONTROLLER_NAME, sizeof(cont->name) );
#endif
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
#ifdef USE_SDL
int se_get_sdl_key_bind(SDL_GameController* gc, int button, int joystick_direction_mask){
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
  if(bind.bindType==SDL_CONTROLLER_BINDTYPE_AXIS){
    return bind.value.axis|joystick_direction_mask;
  }
  if(bind.bindType!=SDL_CONTROLLER_BINDTYPE_BUTTON)return -1;
  else return bind.value.button;
}
int se_get_sdl_axis_bind(SDL_GameController* gc, int button){
  SDL_GameControllerButtonBind bind = SDL_GameControllerGetBindForAxis(gc, button);
  if(bind.bindType!=SDL_CONTROLLER_BINDTYPE_AXIS)return -1;
  else return bind.value.axis;
}
void se_set_default_controller_binds(se_controller_state_t* cont){
  if(!cont ||!cont->sdl_gc)return;
  SDL_GameController * gc = cont->sdl_gc;
  SDL_GameControllerUpdate();
  for(int i=0;i<SE_NUM_KEYBINDS;++i)cont->key.bound_id[i]=-1;
  cont->key.bound_id[SE_KEY_A]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_A,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_B]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_B,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_X]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_X,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_Y]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_Y,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_L]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_LEFTSHOULDER,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_R]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_RIGHTSHOULDER,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_UP]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_UP,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_DOWN]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_DOWN,SE_JOY_NEG_MASK);
  cont->key.bound_id[SE_KEY_LEFT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_LEFT,SE_JOY_NEG_MASK);
  cont->key.bound_id[SE_KEY_RIGHT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_DPAD_RIGHT,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_START]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_START,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_SELECT]= se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_BACK,SE_JOY_POS_MASK);

  cont->key.bound_id[SE_KEY_EMU_PAUSE] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_GUIDE,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_REWIND] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE1,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_FF_2X] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE2,SE_JOY_POS_MASK);
  cont->key.bound_id[SE_KEY_EMU_FF_MAX] = se_get_sdl_key_bind(gc,SDL_CONTROLLER_BUTTON_PADDLE3,SE_JOY_POS_MASK);

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
#endif

void se_draw_controller_config(gui_state_t* gui){
  se_section(ICON_FK_GAMEPAD " Controllers");
  ImGuiStyle* style = igGetStyle();
  se_controller_state_t *cont = &gui->controller;
#if USE_SDL
  const char* cont_name = "No Controller";
  if(cont->sdl_joystick){
    cont_name = SDL_JoystickName(cont->sdl_joystick);
  }
  igPushItemWidth(-1);
  if(igBeginCombo("##Controller", se_localize_and_cache(cont_name), ImGuiComboFlags_None)){
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
  igPopItemWidth();
  if(!cont->sdl_joystick)return;
#else
  const char* cont_name = SE_ANDROID_CONTROLLER_NAME;
#endif
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
#ifdef USE_SDL
  if(SDL_JoystickHasRumble(cont->sdl_joystick)){se_text("Rumble Supported");
  }else se_text("Rumble Not Supported");
#endif
}

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
void se_draw_touch_controls_settings(){

  se_section(ICON_FK_HAND_O_RIGHT " Touch Control Settings");
  float aspect_ratio = gui_state.screen_width/(float)gui_state.screen_height;
  float scale = (igGetWindowContentRegionWidth()-2)/(aspect_ratio+1.0/aspect_ratio);

  igDummy((ImVec2){0,(igGetWindowContentRegionWidth()*0.5-2-scale)*0.5});
  if(igBeginChildFrame(1,(ImVec2){scale*aspect_ratio,scale},ImGuiWindowFlags_None)){
    se_draw_emulated_system_screen(true);
  }
  igEndChildFrame();
  igSameLine(0,2);

  if(igBeginChildFrame(2,(ImVec2){scale/aspect_ratio,scale},ImGuiWindowFlags_None)){
    se_draw_emulated_system_screen(true);
  }
  igEndChildFrame();
  igDummy((ImVec2){0,(igGetWindowContentRegionWidth()*0.5-2-scale)*0.5});

  se_text("Scale");igSameLine(SE_FIELD_INDENT,0);
  igPushItemWidth(-1);
  se_slider_float("##TouchControlsScale",&gui_state.settings.touch_controls_scale,0.3,1.,"Scale: %.2f");

  se_text("Opacity");igSameLine(SE_FIELD_INDENT,0);
  se_slider_float("##TouchControlsOpacity",&gui_state.settings.touch_controls_opacity,0,1.0,"Opacity: %.2f");
  bool auto_hide = gui_state.settings.auto_hide_touch_controls;
  se_checkbox("Hide when inactive",&auto_hide);
  gui_state.settings.auto_hide_touch_controls = auto_hide;

  bool show_turbo = gui_state.settings.touch_controls_show_turbo;
  se_checkbox("Enable Turbo and Hold Button Modifiers",&show_turbo);
  gui_state.settings.touch_controls_show_turbo = show_turbo;
  
  bool avoid_touchscreen = gui_state.settings.avoid_overlaping_touchscreen;
  se_checkbox("Never Overlap Screen",&avoid_touchscreen);
  gui_state.settings.avoid_overlaping_touchscreen = avoid_touchscreen;

  bool button_labels = gui_state.settings.touch_screen_show_button_labels;
  se_checkbox("Button Labels",&button_labels);
  gui_state.settings.touch_screen_show_button_labels = button_labels;
  igPopItemWidth();
}
void se_draw_save_states(bool cloud){
  ImGuiStyle *style = igGetStyle();
  float win_w = igGetWindowContentRegionWidth();
  ImDrawList*dl= igGetWindowDrawList();
  bool has_save_states=false;
  if(!emu_state.rom_loaded)se_push_disabled();

  for(size_t i=0;i<SE_NUM_SAVE_STATES;++i){
    mutex_lock(cloud_state.save_states_mutex);
    se_save_state_t* states = cloud?cloud_state.save_states:save_states;
    has_save_states|=save_states[i].valid||cloud_state.save_states[i].valid;
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
    bool cloud_busy = cloud&&cloud_state.save_states_busy[i];
    if(cloud_busy)se_push_disabled();
    if(se_button("Capture",(ImVec2){button_w,0})){
      if (cloud) {
        se_capture_state_slot_cloud(i);
      } else {
        se_capture_state_slot(i);
      }
    }
    if(!states[i].valid)se_push_disabled();
    if(se_button("Restore",(ImVec2){button_w,0})){
      if (cloud) {
        se_restore_state_slot_cloud(i);
      } else {
        se_restore_state_slot(i);
      }
    }
    if(!states[i].valid)se_pop_disabled();
    if(cloud_busy)se_pop_disabled();
    if(states[i].valid){
      float w_scale = 1.0;
      float h_scale = 1.0;
      if(states[i].screenshot_width>states[i].screenshot_height){
        h_scale = (float)states[i].screenshot_height/(float)states[i].screenshot_width;
      }else{
        w_scale = (float)states[i].screenshot_width/(float)states[i].screenshot_height;
      }
      screen_w*=w_scale;
      screen_h*=h_scale;
      screen_x+=button_w+(slot_w-screen_w-button_w)*0.5;
      screen_y+=(slot_h-screen_h)*0.5-style->FramePadding.y;
   
      se_draw_image(states[i].screenshot,states[i].screenshot_width,states[i].screenshot_height,
                    screen_x*se_dpi_scale(),screen_y*se_dpi_scale(),screen_w*se_dpi_scale(),screen_h*se_dpi_scale(), true);
      if(!cloud&&states[i].valid==2){
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
      if(cloud_busy){
        se_text(ICON_FK_SPINNER);
      } else
      se_text(ICON_FK_BAN);
    }
    igEndChildFrame();
    mutex_unlock(cloud_state.save_states_mutex);
  }
  #ifdef EMSCRIPTEN
  if(!has_save_states)se_push_disabled();
  if(se_button(ICON_FK_DOWNLOAD " Export Save States",(ImVec2){win_w,0})) { se_download_emscripten_save_states(); }
  if(!has_save_states)se_pop_disabled();
  #endif 
  if(!emu_state.rom_loaded)se_pop_disabled();
}
void se_draw_menu_panel(){
  ImGuiStyle *style = igGetStyle();
  int win_w = igGetWindowContentRegionWidth();
  se_section(ICON_FK_FLOPPY_O " Save States");
  if(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in)se_text("Disabled in Hardcore Mode");
  else{
    if (cloud_state.drive){
      if (igBeginTabBar("Saves",ImGuiTabBarFlags_None)){
        if (igBeginTabItem("Local",NULL,ImGuiTabItemFlags_None)){
          se_draw_save_states(false);
          igEndTabItem();
        }
        if (igBeginTabItem("Cloud",NULL,ImGuiTabItemFlags_None)){
          se_draw_save_states(true);
          igEndTabItem();
        }
        igEndTabBar();
      }
    }else{
      se_draw_save_states(false);
    }
  }
  se_section(ICON_FK_CLOUD " Google Drive");
  if (!cloud_state.drive){
    bool pending_login = cloud_drive_pending_login();
    if (pending_login) se_push_disabled();
    bool clicked = false;
    if (se_button(ICON_FK_SIGN_IN " Login",(ImVec2){0,0})){clicked=true;}
    if (pending_login) se_pop_disabled();
    if(igIsItemVisible()){
      ImVec2 min, max;
      igGetItemRectMin(&min);
      igGetItemRectMax(&max);
      ImGuiStyle *style = igGetStyle();
      max.x+=style->FramePadding.x;
      max.y+=style->FramePadding.y;
      se_drive_login(clicked, min.x, min.y, max.x-min.x, max.y-min.y);
    }
  } else {
    ImVec2 screen_p;
    igGetCursorScreenPos(&screen_p);
    int screen_x = screen_p.x;
    int screen_y = screen_p.y;
    ImVec2 ava_dims = {38,38};
    if (cloud_state.user_info.avatar){
      void* avatar = cloud_state.user_info.avatar;
      int avatar_w = cloud_state.user_info.avatar_width;
      int avatar_h = cloud_state.user_info.avatar_height;
      float border_size = 1; 
      igDummy(ava_dims);
      ImU32 col = igGetColorU32Col(ImGuiCol_FrameBg,1.0);
      ImDrawList_AddRectFilled(igGetWindowDrawList(),
                              (ImVec2){screen_x-border_size,screen_y-border_size},
                              (ImVec2){screen_x+border_size+ava_dims.x,screen_y+border_size+ava_dims.y},
                              col,0,ImDrawCornerFlags_None);
    
      se_draw_image(avatar,avatar_w,avatar_h,screen_x*se_dpi_scale(),screen_y*se_dpi_scale(),ava_dims.x*se_dpi_scale(),ava_dims.y*se_dpi_scale(), true);
      igSameLine(0,5);
    }
    igBeginGroup();
    se_text("%s",cloud_state.user_info.name);
    bool pending_logout = cloud_drive_pending_logout();
    if (pending_logout) se_push_disabled();
    if (se_button(ICON_FK_SIGN_OUT " Logout",(ImVec2){0,0})){
      cloud_drive_logout(cloud_state.drive,se_logged_out_cloud_callback);
    }
    if (pending_logout) se_pop_disabled();
    igEndGroup();
  }

  if(emu_state.system==SYSTEM_NDS || emu_state.system == SYSTEM_GBA || emu_state.system == SYSTEM_GB){
    se_section(ICON_FK_KEY " Action Replay Codes");
    if(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in) se_text("Disabled in Hardcore Mode");
    else{
      int free_cheat_index = -1; 
      for(int i=0;i<SE_NUM_CHEATS;i++){
        se_cheat_t* cheat = &cheats[i];
        if (cheat->state==-1){free_cheat_index=i; continue;}
        igPushIDInt(i);
        if(gui_state.editing_cheat_index==i){
          igSetNextItemWidth(win_w-55);
          igInputText("##Name",cheat->name,SE_MAX_CHEAT_NAME_SIZE-1,ImGuiInputTextFlags_None,NULL,NULL);
          cheat->state = 0; 
          igSameLine(win_w-40,0);
          if(se_button(ICON_FK_CHECK, (ImVec2){0,0})) {
            gui_state.editing_cheat_index = -1;
            se_save_cheats(gui_state.cheat_path);
          }
        }else{
          bool active = cheat->state;
          if(se_checkbox(cheat->name, &active)){
            cheat->state = active ? 1:0;
            se_save_cheats(gui_state.cheat_path);
          }
          igSameLine(win_w-40,0);
          if(se_button(ICON_FK_WRENCH, (ImVec2){0,0})) {
            gui_state.editing_cheat_index = i;
          }
        }
        igSameLine(win_w-15,0);
        if(se_button(ICON_FK_TRASH, (ImVec2){-1,0})){
          if(gui_state.editing_cheat_index == i)gui_state.editing_cheat_index=-1;
          cheat->state = -1;
          se_save_cheats(gui_state.cheat_path);
        }
        if(gui_state.editing_cheat_index==i){
          igPushFont(gui_state.mono_font);
          char code_buffer[SE_MAX_CHEAT_CODE_SIZE*8] = { 0 };        
          int off=0;
          for(int i=0;i<cheat->size;i+=1){
            off+=snprintf(code_buffer+off,sizeof(code_buffer)-off,"%08X",cheat->buffer[i]);
            if(i%2)off+=snprintf(code_buffer+off,sizeof(code_buffer)-off,"\n");
            else off+=snprintf(code_buffer+off,sizeof(code_buffer)-off," ");
          }
          igSetNextItemWidth(win_w);
          // Not setting ImGuiInputTextFlags_CharsHexadecimal as it doesn't allow whitespace
          if(igInputTextMultiline("##CheatCode",code_buffer,sizeof(code_buffer),(ImVec2){0,300},ImGuiInputTextFlags_CharsUppercase,NULL,NULL)){
            se_convert_cheat_code(code_buffer,gui_state.editing_cheat_index);
          }
          igPopFont();
        }
        igPopID();
      }
      if(free_cheat_index!=-1){
        if(se_button(ICON_FK_PLUS " New", (ImVec2){0,0})){
          gui_state.editing_cheat_index = free_cheat_index;
          se_cheat_t * cheat = cheats+gui_state.editing_cheat_index;
          cheat->state = 0; 
          strcpy(cheat->name,"Untitled Code");
          memset(cheat->buffer,0,sizeof(cheat->buffer));
        }
      }
    }
  }
  #ifdef ENABLE_RETRO_ACHIEVEMENTS
  se_section(ICON_FK_TROPHY " RetroAchievements");
  const rc_client_user_t* user = rc_client_get_user_info(retro_achievements_get_client());
  igPushIDStr("RetroAchievements");
  if (!user)
  {
      static char username[256] = {0};
      static char password[256] = {0};
      bool pending_login = retro_achievements_is_pending_login();
      igPushItemWidth(-1);
      se_text("Username");
      igSameLine(win_w - 150, 0);
      if (pending_login)
          se_push_disabled();
      bool enter = igInputText("##Username", username, sizeof(username),
                        ImGuiInputTextFlags_EnterReturnsTrue, NULL, NULL);
      if (pending_login)
          se_pop_disabled();
      se_text("Password");
      igSameLine(win_w - 150, 0);
      if (pending_login)
          se_push_disabled();
      enter |= igInputText("##Password", password, sizeof(password),
                        ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue,
                        NULL, NULL);
      igPopItemWidth();
      const char* error_message = retro_achievements_get_login_error();
      if (error_message) {
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.0f, 0.0f, 0.0f, 1.0f});
        se_text("%s", error_message);
        igPopStyleColor(1);
      }
      if (se_button(ICON_FK_SIGN_IN " Login", (ImVec2){0, 0}) || enter)
      {
        gui_state.ra_needs_reload = true;
        gui_state.settings.hardcore_mode = false;
        retro_achievements_login(username, password);
      }
      igSameLine(0, 6);
      bool register_clicked=false;
      if (se_button(ICON_FK_USER_PLUS " Register", (ImVec2){0, 0}))register_clicked=true;
      if(igIsItemVisible()){
        ImVec2 min, max;
        igGetItemRectMin(&min);
        igGetItemRectMax(&max);
        ImGuiStyle *style = igGetStyle();
        max.x+=style->FramePadding.x;
        max.y+=style->FramePadding.y;
        se_ra_register(register_clicked, min.x, min.y, max.x-min.x, max.y-min.y);
      }
      if (pending_login)
        se_pop_disabled();
  }else{
      const rc_client_game_t* game = rc_client_get_game_info(retro_achievements_get_client());
      ImVec2 pos;
      sg_image image = {SG_INVALID_ID};
      ImVec2 offset1 = {0, 0};
      ImVec2 offset2 = {1, 1};
      struct atlas_tile_t* user_image = retro_achievements_get_user_image();
      if (user_image)
      {
        image.id = atlas_get_tile_id(user_image);
        struct atlas_uvs_t uvs = atlas_get_tile_uvs(user_image);
        offset1 = (ImVec2){uvs.x1, uvs.y1};
        offset2 = (ImVec2){uvs.x2, uvs.y2};
      }
      bool hardcore = gui_state.settings.hardcore_mode&&gui_state.ra_logged_in;
      bool encore = gui_state.ra_encore_mode;
      {
        ImVec2 screen_p;
        igGetCursorScreenPos(&screen_p);
        int screen_x = screen_p.x;
        int screen_y = screen_p.y;
        ImVec2 ava_dims = {38,38};
        float border_size = 1; 
        ImU32 col = igGetColorU32Col(ImGuiCol_FrameBg,1.0);
        ImDrawList_AddRectFilled(igGetWindowDrawList(),
                                (ImVec2){screen_x-border_size,screen_y-border_size},
                                (ImVec2){screen_x+border_size+ava_dims.x,screen_y+border_size+ava_dims.y},
                                col,0,ImDrawCornerFlags_None);
        if (image.id != SG_INVALID_ID) {
          igImageButton((ImTextureID)(intptr_t)image.id,(ImVec2){ava_dims.x,ava_dims.y},offset1,offset2,0,(ImVec4){1,1,1,1},(ImVec4){1,1,1,1});
        } else {
          igPushItemFlag(ImGuiItemFlags_Disabled, true);
          se_button(ICON_FK_USER,(ImVec2){ava_dims.x,ava_dims.y});
          igPopItemFlag();
        }
        igSameLine(0,5);
        igBeginGroup();
        se_text(se_localize_and_cache("%s (Points: %d)"), user->display_name,hardcore ? user->score : user->score_softcore);
        if (se_button(ICON_FK_SIGN_OUT " Logout",(ImVec2){0,0})){
          char buffer[SB_FILE_PATH_SIZE];
          snprintf(buffer, SB_FILE_PATH_SIZE, "%sra_token.txt", se_get_pref_path());
          remove(buffer);
          rc_client_logout(retro_achievements_get_client());
        }
        igEndGroup();
      }
      bool draw_checkboxes_bool[6] = {
        gui_state.settings.hardcore_mode,
        gui_state.settings.draw_notifications,
        gui_state.settings.draw_progress_indicators,
        gui_state.settings.draw_leaderboard_trackers,
        gui_state.settings.draw_challenge_indicators,
        gui_state.settings.only_one_notification,
      };

      if (encore) se_push_disabled();
      if (se_checkbox("Hardcore Mode", &draw_checkboxes_bool[0]))
      {
        rc_client_set_hardcore_enabled(retro_achievements_get_client(), draw_checkboxes_bool[0]);
      }
      if (encore) se_pop_disabled();

      if (se_checkbox("Encore Mode", &gui_state.ra_encore_mode))
      {
        se_reset_core();
      }

      se_checkbox("Notifications", &draw_checkboxes_bool[1]);
      if (!gui_state.settings.draw_notifications) se_push_disabled();
      igIndent(15);
      se_checkbox("Only one notification at a time", &draw_checkboxes_bool[5]);
      igUnindent(15);
      if (!gui_state.settings.draw_notifications) se_pop_disabled();
      se_checkbox("Progress Indicators",&draw_checkboxes_bool[2]);
      if (!hardcore&&!encore) se_push_disabled();
      se_checkbox("Leaderboard Trackers",&draw_checkboxes_bool[3]);
      if (!hardcore&&!encore) se_pop_disabled();
      se_checkbox("Challenge Indicators",&draw_checkboxes_bool[4]);

      uint32_t* checkboxes[6] = {
        &gui_state.settings.hardcore_mode,
        &gui_state.settings.draw_notifications,
        &gui_state.settings.draw_progress_indicators,
        &gui_state.settings.draw_leaderboard_trackers,
        &gui_state.settings.draw_challenge_indicators,
        &gui_state.settings.only_one_notification,
      };

      for (int i = 0; i < 6; i++)
      {
        *checkboxes[i] = draw_checkboxes_bool[i];
      }
  }
  igPopID();
  #endif
  {
    se_bios_info_t * info = &gui_state.bios_info;
    if(emu_state.rom_loaded){
      se_section(ICON_FK_CROSSHAIRS " Located Files");
      static const char* wildcard_types[]={NULL};
      if(sb_file_exists(emu_state.save_file_path)){
        igPushStyleColorU32(ImGuiCol_Text,0xff00ff00);
        se_text(ICON_FK_CHECK);
      }else{
        igPushStyleColorU32(ImGuiCol_Text,0xff0000ff);
        se_text(ICON_FK_TIMES);
      }
      igPopStyleColor(1);
      igSameLine(0,2);
      igSetNextItemWidth(win_w-55);
      se_input_file_callback("Save File",emu_state.save_file_path,wildcard_types,se_bios_file_open_fn,ImGuiInputTextFlags_None);

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
          igSetNextItemWidth(win_w-55);
          se_input_file_callback(info->name[i],info->path[i],wildcard_types,se_bios_file_open_fn,ImGuiInputTextFlags_None);
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
  se_section(ICON_FK_DESKTOP " Display Settings");
  int v = gui_state.settings.screen_shader;
  igPushItemWidth(-1);
  se_text("Screen Shader");igSameLine(SE_FIELD_INDENT,0);
  se_combo_str("##Screen Shader",&v,"Pixelate\0Bilinear\0LCD\0LCD & Subpixels\0Smooth Upscale (xBRZ)\0",0);
  gui_state.settings.screen_shader=v;
  v = gui_state.settings.screen_rotation;
  se_text("Screen Rotation");igSameLine(SE_FIELD_INDENT,0);
  se_combo_str("##Screen Rotation",&v,"0 degrees\00090 degrees\000180 degrees\000270 degrees\0",0);
  gui_state.settings.screen_rotation=v;
  se_text("Color Correction");igSameLine(SE_FIELD_INDENT,0);
  se_slider_float("##Color Correction",&gui_state.settings.color_correction,0,1.0,"Strength: %.2f");
  int color_correct = gui_state.settings.gba_color_correction_mode;
  se_text("GBA Color Correction Type");igSameLine(180,0);
  se_combo_str("##ColorAlgorithm",&color_correct,"SkyEmu\0Higan\0",0);
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
  {
    if(gui_state.theme.regions[SE_REGION_NO_BEZEL].active){
      bool b = gui_state.settings.show_screen_bezel;
      se_checkbox("Show Screen Bezel", &b);
      gui_state.settings.show_screen_bezel = b;
    }
  }
  {
    se_text("NDS Screen Layout");
    int layout = gui_state.settings.nds_layout;
    igSameLine(SE_FIELD_INDENT,0);
    se_combo_str("##NDSLayout",&layout,"Auto\0Vertical\0Horizontal\0Hybrid Large Top\0Hybrid Large Bottom\0Vertical Large Top\0Vertical Large Bottom\0Horizontal Large Top\0Horizontal Large Bottom\0\0",0);
    gui_state.settings.nds_layout=layout; 
  }
  igPopItemWidth();
  se_text("Game Boy Color Palette");
  for(int i=0;i<4;++i){
    igPushIDInt(i);
    float color[4]; 
    uint32_t col = gui_state.settings.gb_palette[i];
    color[0]= SB_BFE(col,0,8)/255.;
    color[1]= SB_BFE(col,8,8)/255.;
    color[2]= SB_BFE(col,16,8)/255.;
    float w = (win_w-20)*0.25-2;
    if(i)igSameLine(0,2);
    if(igColorButton("##color-button",(ImVec4){color[0],color[1],color[2],1.0},ImGuiColorEditFlags_NoInputs| ImGuiColorEditFlags_NoLabel,(ImVec2){w,20})){
      igOpenPopup("##picker-popup",ImGuiWindowFlags_None);
    }
    if (igBeginPopup("##picker-popup",ImGuiWindowFlags_None)){
      igColorPicker3("##picker", color, ImGuiColorEditFlags_None);
      igEndPopup();
    }
    col = (((int)(color[0]*255))&0xff);
    col |= (((int)(color[1]*255))&0xff)<<8;
    col |= (((int)(color[2]*255))&0xff)<<16;
    gui_state.settings.gb_palette[i]=col;
    igPopID();
  }
  igSameLine(0,2);
  if(se_button(ICON_FK_REPEAT,(ImVec2){20,20}))se_reset_default_gb_palette();
  if(gui_state.ui_type==SE_UI_ANDROID||gui_state.ui_type==SE_UI_IOS){
    se_draw_touch_controls_settings();
  }else{
    se_section(ICON_FK_KEYBOARD_O " Keybinds");
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
  }
  #if defined( USE_SDL) ||defined(SE_PLATFORM_ANDROID)
  se_draw_controller_config(&gui_state);
  #endif

  if(gui_state.ui_type!=SE_UI_ANDROID&&gui_state.ui_type!=SE_UI_IOS){
    se_draw_touch_controls_settings();
  }
  se_section(ICON_FK_TEXT_HEIGHT " GUI");
  se_text("Language");igSameLine(SE_FIELD_INDENT,0);
  igPushItemWidth(-1);
  if(igBeginCombo("##Language", se_language_string(gui_state.settings.language), ImGuiComboFlags_HeightLargest)){
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
  se_text("Theme");igSameLine(SE_FIELD_INDENT,0);
  igPushItemWidth(-1);
  bool load = se_combo_str("##Theme",&theme,"Dark\0Light\0Black\0Custom\0",0);
  igPopItemWidth();
  gui_state.settings.theme = theme;
  if(gui_state.settings.theme==SE_THEME_CUSTOM){
    static const char *types[]={"*.png",NULL};
    load|= se_input_file("Theme Path", gui_state.paths.theme,types,ImGuiInputTextFlags_None);
    load|= strncmp(gui_state.loaded_theme_path,gui_state.paths.theme,SB_FILE_PATH_SIZE)!=0;
    if(load){
      if(se_reload_theme()) {
        se_save_search_paths();
      }else strncpy(gui_state.paths.theme,"INVALID",SB_FILE_PATH_SIZE);
    }
    load=false; 
    static const char *font_types[]={"*.ttf",NULL};

    load|= se_input_file("Custom Font", gui_state.paths.custom_font,font_types,ImGuiInputTextFlags_None);
    load|= strncmp(gui_state.loaded_custom_font_path,gui_state.paths.custom_font,SB_FILE_PATH_SIZE)!=0;
    if(load){
      gui_state.update_font_atlas=true;
      strncpy(gui_state.loaded_custom_font_path,gui_state.paths.custom_font,SB_FILE_PATH_SIZE);
    }
    igPushItemWidth(-1);
    float old_scale = gui_state.settings.custom_font_scale;
    se_text("Font Scale");igSameLine(SE_FIELD_INDENT,0);
    se_slider_float("##FontScale",&gui_state.settings.custom_font_scale,0.5,1.5,"Scale: %0.2fx");
    if(old_scale!=gui_state.settings.custom_font_scale)gui_state.update_font_atlas=true;
    igPopItemWidth();

  
    se_custom_theme_t * theme = &gui_state.theme;
    float w = igGetWindowContentRegionWidth();
    float h = w*theme->regions[SE_REGION_NAME].h/theme->regions[SE_REGION_NAME].w;
    ImVec2 p,v;

    if(theme->regions[SE_REGION_NAME].active){
      se_text("Custom Theme Name");
      igGetCursorPos(&p);
      igGetWindowPos(&v);
      p.x+=v.x-igGetScrollX();
      p.y+=v.y-igGetScrollY();

      se_draw_theme_region(SE_REGION_NAME, p.x,p.y,w,h);
      igDummy((ImVec2){0,h});
    }
    if(theme->regions[SE_REGION_AUTHOR].active){
      se_text("Custom Theme Author");
      igGetCursorPos(&p);
      igGetWindowPos(&v);
      p.x+=v.x-igGetScrollX();
      p.y+=v.y-igGetScrollY();
      se_draw_theme_region(SE_REGION_AUTHOR, p.x,p.y,w,h);
      igDummy((ImVec2){0,h});
    }/*
    for(int i=0;i<5;++i){
      igPushIDInt(i);
      float color[4];
      color[0] = gui_state.theme.palettes[i*4+0]/255.;
      color[1] = gui_state.theme.palettes[i*4+1]/255.;
      color[2] = gui_state.theme.palettes[i*4+2]/255.;
      color[3] = gui_state.theme.palettes[i*4+3]/255.;
      if(i)igSameLine(0,2);
      float w = (win_w-20)*0.20-2;
      if(igColorButton("##color-button2",(ImVec4){color[0],color[1],color[2],1.0},ImGuiColorEditFlags_NoInputs| ImGuiColorEditFlags_NoLabel,(ImVec2){w,20})){
        igOpenPopup("##picker-popup2",ImGuiWindowFlags_None);
      }
      if (igBeginPopup("##picker-popup2",ImGuiWindowFlags_None)){
        igColorPicker4("##picker2", color, ImGuiColorEditFlags_None,color);
        igEndPopup();
      }
      gui_state.theme.palettes[i*4+0]=color[0]*255;
      gui_state.theme.palettes[i*4+1]=color[1]*255;
      gui_state.theme.palettes[i*4+2]=color[2]*255;
      gui_state.theme.palettes[i*4+3]=color[3]*255;

      igPopID();
    }*/
  }else{
    if(load)se_reload_theme();
  }


  {
    se_text("GUI Scale");igSameLine(SE_FIELD_INDENT,0);
    static double last_edit_time = 0; 
    static float curr_slider_scale = -1;
    if(curr_slider_scale<0)curr_slider_scale = gui_state.settings.gui_scale_factor;
    float last_slider_scale = curr_slider_scale; 
    igPushItemWidth(-1);
    se_slider_float("##GUI Scale",&curr_slider_scale,0.5,2.5,"Scale: %0.2fx");
    igPopItemWidth();
    // Changing the GUI scale factor requires reseting the entire GUI, so wait for a little over
    // a second after the user stops making changes to set the new scale factor
    if(last_slider_scale!=curr_slider_scale){
      last_edit_time = se_time();
    }
    if(se_time()-last_edit_time>1.5)gui_state.settings.gui_scale_factor=curr_slider_scale;
  }


  bool always_show_menubar = gui_state.settings.always_show_menubar;
  se_checkbox("Always Show Menu/Nav Bar",&always_show_menubar);
  gui_state.settings.always_show_menubar = always_show_menubar;

  if(gui_state.ui_type==SE_UI_DESKTOP){
    bool fullscreen = sapp_is_fullscreen();
    se_checkbox("Full Screen",&fullscreen);
    if(fullscreen!=sapp_is_fullscreen())sapp_toggle_fullscreen();
    se_section(ICON_FK_CODE_FORK " Additional Search Paths");
    se_input_path("Save File/State Path", gui_state.paths.save,ImGuiInputTextFlags_None);
    se_input_path("BIOS/Firmware Path", gui_state.paths.bios,ImGuiInputTextFlags_None);
    se_input_path("Cheat Code Path", gui_state.paths.cheat_codes,ImGuiInputTextFlags_None);
    bool save_to_path=gui_state.settings.save_to_path;
    se_checkbox("Create new files in paths",&save_to_path);
    gui_state.settings.save_to_path=save_to_path;
    if(memcmp(&gui_state.last_saved_paths, &gui_state.paths,sizeof(gui_state.paths))){
      se_save_search_paths();
      gui_state.last_saved_paths=gui_state.paths;
    }
  }
  se_section(ICON_FK_WRENCH " Advanced");
  se_text("Solar Sensor");igSameLine(SE_FIELD_INDENT,0);
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
    se_text("Server Port");igSameLine(SE_FIELD_INDENT,0);
    igPushItemWidth(-1);
    se_input_int("##Server Port",&port,1,10,ImGuiInputTextFlags_None);
    if(igIsItemDeactivated())gui_state.settings.http_control_server_port=port; 
    igPopItemWidth();
  }
#endif 

  char byte_str[32];
  uint64_t cache_size = https_cache_size();
  if(cache_size>1024*1024*1024){
    cache_size/=1024*1024*1024;
    snprintf(byte_str,32,"%d GiB",(int)cache_size);
  }else if(cache_size>1024*1024){
    cache_size/=1024*1024;
    snprintf(byte_str,32,"%d MiB",(int)cache_size);
  }else if(cache_size>1024){
    cache_size/=1024;
    snprintf(byte_str,32,"%d KiB",(int)cache_size);
  }else{
    snprintf(byte_str,32,"%d bytes",(int)cache_size);
  }

  bool enable_download_cache = gui_state.settings.enable_download_cache;
  if (se_checkbox("Enable Download Cache",&enable_download_cache)) {
    gui_state.settings.enable_download_cache = enable_download_cache;
    https_set_cache_enabled(enable_download_cache);
  }
  if (!enable_download_cache)se_push_disabled();
  se_text("Download Cache Size: %s",byte_str);
  if (se_button("Clear Download Cache", (ImVec2){0,0})){
    https_clear_cache();
  }
  if (!enable_download_cache)se_pop_disabled();

  float bottom_padding =0;
  #ifdef SE_PLATFORM_IOS
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
  ImGuiStyle *style = igGetStyle();
  ImVec2 menu_bar_size={g->IO.DisplaySize.x, g->NextWindowData.MenuBarOffsetMinVal.y + SE_MENU_BAR_HEIGHT};
  float y_off = (3+gui_state.menubar_hide_timer-se_time())*2.;
  if(y_off>0)y_off=0;
  if(gui_state.settings.always_show_menubar)y_off=0;
  y_off = y_off*menu_bar_size.y+style->DisplaySafeAreaPadding.y;
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
  igSetCursorPosX(style->DisplaySafeAreaPadding.x);
  se_draw_theme_region(SE_REGION_MENUBAR,0,y_off,menu_bar_size.x,menu_bar_size.y);
  return true; //-V1020
}

void se_end_menu_bar(){
  igEnd();
}

#ifdef ENABLE_HTTP_CONTROL_SERVER
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
  }else if(strcmp(cmd,"/setting")==0){
    while(*params){
      if(strcmp(params[0],"ui_type")==0){
        if(strcmp(params[1],"DESKTOP")==0)gui_state.ui_type = SE_UI_DESKTOP; 
        if(strcmp(params[1],"ANDROID")==0)gui_state.ui_type = SE_UI_ANDROID;  
        if(strcmp(params[1],"IOS")==0)gui_state.ui_type = SE_UI_IOS;     
        if(strcmp(params[1],"WEB")==0)gui_state.ui_type = SE_UI_WEB;
      }else if(strcmp(params[0],"menu")==0)gui_state.sidebar_open=atoi(params[1]);
      else if(strcmp(params[0],"dpi")==0)gui_state.dpi_override=atof(params[1]);
      else if(strcmp(params[0],"touch_controls_scale")==0)gui_state.settings.touch_controls_scale=atof(params[1]);
      else if(strcmp(params[0],"language")==0)gui_state.settings.language=se_convert_locale_to_enum(params[1]);
      else if(strcmp(params[0],"shader")==0)gui_state.settings.screen_shader=atof(params[1]);
      else if(strcmp(params[0],"load_slot")==0)se_restore_state_slot(atoi(params[1]));
      else if(strcmp(params[0],"capture_slot")==0)se_capture_state_slot(atoi(params[1]));
      else if(strcmp(params[0],"edit_cheat_index")==0)gui_state.editing_cheat_index = atoi(params[1]);
      else if(strcmp(params[0],"debug_tools")==0)gui_state.settings.draw_debug_menu = atoi(params[1]);
      else if(strcmp(params[0],"fake_paths")==0)gui_state.fake_paths = atoi(params[1]);
      else if(strcmp(params[0],"theme")==0)gui_state.settings.theme = atoi(params[1]);
      else if(strcmp(params[0],"menu_bar")==0){
        if(atoi(params[1])){
          gui_state.settings.always_show_menubar=true;
        }else{
          gui_state.settings.always_show_menubar=false;
          gui_state.menubar_hide_timer = 0; 
        }
      }
      params+=2;
    }
    str_result=emu_state.rom_loaded?"ok":"Failed to load ROM";
  }else if(strcmp(cmd,"/step")==0){
    int step_frames = 1; 
    int old_step = emu_state.step_frames;
    while(*params){
      if(strcmp(params[0],"frames")==0)step_frames=atoi(params[1]);
      params+=2;
    }
    emu_state.step_frames=step_frames;
    emu_state.run_mode = SB_MODE_STEP;
    se_update_frame(); 
    emu_state.step_frames=old_step;
    str_result="ok";
  }else if(strcmp(cmd,"/run")==0){
    emu_state.step_frames=1;
    emu_state.run_mode = SB_MODE_RUN;
    str_result="ok";
  }else if(strcmp(cmd,"/screen")==0){
    if(emu_state.rom_loaded){
      bool embed_state = false;
      int format = 0; 
      while(*params){
        if(strcmp(params[0],"embed_state")==0)embed_state=atoi(params[1])!=0;
        if(strcmp(params[0],"format")==0){
          if(strcmp(params[1],"BMP")==0||strcmp(params[1],"bmp")==0)format = 1; 
          if(strcmp(params[1],"JPG")==0||strcmp(params[1],"jpg")==0)format = 2; 
        }
        params+=2;
      }
      uint8_t* imdata = NULL;
      uint32_t width=0, height=0; 
      if(embed_state){
        se_save_state_t* save_state = (se_save_state_t*)malloc(sizeof(se_save_state_t));
        se_capture_state(&core,save_state);
        imdata = se_save_state_to_image(save_state, &width,&height);
        free(save_state);
      }else{
        imdata = (uint8_t*)malloc(SE_MAX_SCREENSHOT_SIZE);
        int out_width=0, out_height=0;
        se_screenshot(imdata, &out_width, &out_height);
        width = out_width;
        height = out_height;
      }
      if(format==0){
        se_png_write_context_t cont ={0};
        stbi_write_png_to_func(se_png_write_mem, &cont,width,height,4, imdata, 0);
        free(imdata);
        *result_size = cont.size;
        *mime_type="image/png";
        return cont.data;
      }else if(format==1){
        se_png_write_context_t cont ={0};
        stbi_write_bmp_to_func(se_png_write_mem, &cont,width,height,4, imdata);
        free(imdata);
        *result_size = cont.size;
        *mime_type="image/bmp";
        return cont.data;
      }else if(format==2){
        se_png_write_context_t cont ={0};
        stbi_write_jpg_to_func(se_png_write_mem, &cont,width,height,4, imdata,95);
        free(imdata);
        *result_size = cont.size;
        *mime_type="image/jpg";
        return cont.data;
      }
    }else str_result = "Failed (no ROM loaded)";
  }else if(strcmp(cmd,"/read_byte")==0){
    uint64_t response_size = 0; 
    char *response = NULL;
    int address_map=0; 
    while(*params){
      if(strcmp(params[0],"map")==0) address_map = atoi(params[1]);
      else if(strcmp(params[0],"addr")==0){
        uint64_t addr = se_hex_string_to_int(params[1]);
        uint8_t byte = se_read_byte_func(address_map)(addr);
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
    int address_map = 0; 
    while(*params){
      if(strcmp(params[0],"map")==0) address_map = atoi(params[1]);
      else{
        uint64_t addr = se_hex_string_to_int(params[0]);
        uint8_t data = se_hex_string_to_int(params[1]);
        se_write_byte_func(address_map)(addr,data);
      }
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
    *mime_type = "application/json";
    char buffer[4096]={0};
    int off = 0;
    off+=snprintf(buffer+off,sizeof(buffer)-off,"{\n");

    off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"emulator\": \"SkyEmu (%s)\",\n",GIT_COMMIT_HASH);
    off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"run-mode\": ");
    switch(emu_state.run_mode){
      case SB_MODE_PAUSE: off+=snprintf(buffer+off,sizeof(buffer)-off,"\"PAUSE\",\n");break;
      case SB_MODE_RUN: off+=snprintf(buffer+off,sizeof(buffer)-off,"\"RUN\",\n");break;
      case SB_MODE_STEP: off+=snprintf(buffer+off,sizeof(buffer)-off,"\"STEP\",\n");break;
      case SB_MODE_RESET: off+=snprintf(buffer+off,sizeof(buffer)-off,"\"RESET\",\n");break;
      case SB_MODE_REWIND: off+=snprintf(buffer+off,sizeof(buffer)-off,"\"REWIND\",\n");break;
    }
    off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"rom-loaded\" : %s,\n",emu_state.rom_loaded?"true":"false");
    if(emu_state.rom_loaded){
      off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"rom-path\": \"%s\",\n",emu_state.rom_path);
      off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"save-path\": \"%s\",\n",emu_state.save_file_path);
    }
    off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"rewind-info\" : {\n");
    off+=snprintf(buffer+off,sizeof(buffer)-off,"    \"entries-used\" : %d,\n",rewind_buffer.size);
    off+=snprintf(buffer+off,sizeof(buffer)-off,"    \"capacity\" : %d,\n",SE_REWIND_BUFFER_SIZE);
    off+=snprintf(buffer+off,sizeof(buffer)-off,"    \"percent_full\" : %0.1f\n",(float)(rewind_buffer.size)/SE_REWIND_BUFFER_SIZE*100.);
    off+=snprintf(buffer+off,sizeof(buffer)-off,"  },\n");

    off+=snprintf(buffer+off,sizeof(buffer)-off,"  \"inputs\": {\n");
    for(int i=0; i<SE_NUM_KEYBINDS;++i){
      off+=snprintf(buffer+off,sizeof(buffer)-off,"    \"%s\": %f",se_keybind_names[i],gui_state.hcs_joypad.inputs[i]);
      if(i+1==SE_NUM_KEYBINDS)off+=snprintf(buffer+off,sizeof(buffer)-off,"\n");
      else off+=snprintf(buffer+off,sizeof(buffer)-off,",\n");
    }
    off+=snprintf(buffer+off,sizeof(buffer)-off,"  }\n");

    off+=snprintf(buffer+off,sizeof(buffer)-off,"}");

    str_result = buffer;
    const char* result=strdup(str_result);
    *result_size=strlen(result);
    return (uint8_t*)result;
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
  }else if(strcmp(cmd,"/cheats")==0){
    *mime_type = "text/plain";
    size_t cheat_count = 0;
    for(int i=0; i<SE_NUM_CHEATS;++i){
      if(cheats[i].state!=-1) cheat_count++;
    }
    if(cheat_count==0){
      str_result = "No cheats enabled";
    }else{
      size_t max_size = SE_MAX_CHEAT_CODE_SIZE*cheat_count + SE_MAX_CHEAT_NAME_SIZE*cheat_count + 64*cheat_count;
      char* max_buffer = (char*)calloc(max_size,sizeof(char));
      int off = 0;

      for(int i=0; i<SE_NUM_CHEATS;++i){
        if(cheats[i].state!=-1){
          off+=snprintf(max_buffer+off,max_size-off,"%d - %s:",i,cheats[i].name);
          for(int j=0;j<cheats[i].size;++j){
            off+=snprintf(max_buffer+off,max_size-off," %08x",cheats[i].buffer[j]);
          }
          if(cheats[i].state==0){
            off+=snprintf(max_buffer+off,max_size-off," (disabled)");
          }else{
            off+=snprintf(max_buffer+off,max_size-off," (enabled)");
          }
          off+=snprintf(max_buffer+off,max_size-off,"\n");
        }
      }

      size_t actual_size = off+1;
      char* buffer = (char*)malloc(actual_size);
      memcpy(buffer,max_buffer,actual_size);
      buffer[actual_size-1]='\0';
      free(max_buffer);
      *result_size = actual_size;
      return (uint8_t*)buffer;
    }
  }else if(strcmp(cmd,"/remove_cheat")==0){
    bool okay=false;
    while(*params){
      if(strcmp(params[0],"id")==0){
        int id=-1;
        int result=sscanf(params[1],"%d",&id);
        if(result!=EOF&&id>=0&&id<SE_NUM_CHEATS){
          cheats[id].state=-1;
          okay=true;
        }else{
          okay=false;
        }
      }
      params+=2;
    }
    str_result=okay? "ok":"failed";
  }else if(strcmp(cmd,"/edit_cheat")==0){
    bool okay=true;
    int editing_id=-1;
    bool name_changed=false, code_changed=false, enabled_changed=false;
    char new_name[SE_MAX_CHEAT_NAME_SIZE+1] = {0};
    char new_code[SE_MAX_CHEAT_CODE_SIZE+1] = {0};
    int new_enabled=1;
    while(*params){
      if(strcmp(params[0],"id")==0){
        int result=sscanf(params[1],"%d",&editing_id);
        if(result==EOF||(editing_id<0||editing_id>=SE_NUM_CHEATS)){
          okay=false;
          break;
        }
      }else if(strcmp(params[0],"name")==0){
        name_changed=true;
        strncpy(new_name,params[1],SE_MAX_CHEAT_NAME_SIZE);
      }else if(strcmp(params[0],"code")==0){
        code_changed=true;
        strncpy(new_code,params[1],SE_MAX_CHEAT_CODE_SIZE);
      }else if(strcmp(params[0],"enabled")==0){
        int result=sscanf(params[1],"%d",&new_enabled);
        if(result==EOF){
          okay=false;
          break;
        }
        enabled_changed=true;
      }
      params+=2;
    }

    if(okay){
      // Find an empty slot if an id wasn't specified
      if(editing_id==-1){
        okay=false;
        for(int i=0;i<SE_NUM_CHEATS;++i){
          if(cheats[i].state==-1){
            editing_id=i;
            okay=true;
            break;
          }
        }
      }

      if(editing_id!=-1){
        if(!name_changed&&!code_changed&&!enabled_changed){
          okay=false;
        }else{
          if(name_changed){
            strncpy(cheats[editing_id].name,new_name,SE_MAX_CHEAT_NAME_SIZE);
          }
          if(code_changed){
            se_convert_cheat_code(new_code,editing_id);
          }
          if(enabled_changed){
            cheats[editing_id].state=new_enabled;
          }
          if(cheats[editing_id].state==-1){
            cheats[editing_id].state=1;
          }
        }
      }
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
  se_reset_html_click_regions();
#ifdef USE_SDL
  se_poll_sdl();
#endif
  se_set_language(gui_state.settings.language);
#if !defined(EMSCRIPTEN) && !defined(SE_PLATFORM_ANDROID) &&!defined(SE_PLATFORM_IOS)
  static bool last_toggle_fullscreen=false;
  if(emu_state.joy.inputs[SE_KEY_TOGGLE_FULLSCREEN]&&last_toggle_fullscreen==false)sapp_toggle_fullscreen();
  last_toggle_fullscreen = emu_state.joy.inputs[SE_KEY_TOGGLE_FULLSCREEN];
#endif
#ifdef ENABLE_RETRO_ACHIEVEMENTS
  retro_achievements_keep_alive();
  gui_state.ra_logged_in = rc_client_get_user_info(retro_achievements_get_client()) != NULL;
#endif
#ifdef SE_PLATFORM_ANDROID
  //Handle Android Back Button Navigation
  static bool last_back_press = false;
  if(!last_back_press&&gui_state.button_state[SAPP_KEYCODE_BACK]){
      if(gui_state.ra_sidebar_open)gui_state.ra_sidebar_open = false;
      else if(gui_state.sidebar_open)gui_state.sidebar_open = false;
      else if(emu_state.run_mode!=SB_MODE_PAUSE)emu_state.run_mode = SB_MODE_PAUSE;
      else if(emu_state.rom_loaded &&!gui_state.ran_from_launcher)emu_state.run_mode = SB_MODE_RUN;
      else sapp_quit();
  }
  last_back_press= gui_state.button_state[SAPP_KEYCODE_BACK];
#endif

  int width = sapp_width();
  int height = sapp_height();
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
  style->DisplaySafeAreaPadding.x = style->DisplaySafeAreaPadding.y =0;
#ifdef SE_PLATFORM_IOS
  se_ios_get_safe_ui_padding(&top_padding,NULL,&left_padding,&right_padding);
  style->DisplaySafeAreaPadding.x = left_padding;
  style->DisplaySafeAreaPadding.y = top_padding;
#endif

#ifdef SE_PLATFORM_ANDROID
  se_android_poll_events(igGetIO()->WantTextInput);
#endif
  sb_poll_controller_input(&emu_state.joy);
  

  if(gui_state.ui_type==SE_UI_ANDROID || gui_state.ui_type == SE_UI_IOS){
      style->ScrollbarSize=4;
  }
#if !defined(EMSCRIPTEN) && !defined(SE_PLATFORM_ANDROID) &&!defined(SE_PLATFORM_IOS)
  if(!emu_state.joy.inputs[SE_KEY_TOGGLE_FULLSCREEN]&&emu_state.prev_frame_joy.inputs[SE_KEY_TOGGLE_FULLSCREEN])sapp_toggle_fullscreen();
#endif
  se_bring_text_field_into_view();

  if (gui_state.test_runner_mode==false&&se_begin_menu_bar())
  {
    float menu_bar_y = igGetCursorPosY();
    se_panel_toggle(SE_REGION_MENU,&gui_state.sidebar_open,ICON_FK_BARS,"Show/Hide Menu Panel");

#ifdef ENABLE_RETRO_ACHIEVEMENTS
    if(retro_achievements_has_game_loaded()){
      se_panel_toggle(SE_REGION_BLANK,&gui_state.ra_sidebar_open,ICON_FK_TROPHY,"Show/Hide RetroAchievements Panel");
    }
#endif


    if(gui_state.settings.draw_debug_menu)se_draw_debug_menu();
    

    int orig_x = igGetCursorPosX();
    int v = (gui_state.settings.volume*100);
    float volume_width = SE_VOLUME_SLIDER_WIDTH+5;
    
    if(gui_state.ui_type==SE_UI_ANDROID||gui_state.ui_type==SE_UI_IOS){
      gui_state.settings.volume=1.;
      volume_width = 0; 
    }

    
    int num_toggles = 4;
    int sel_width =SE_TOGGLE_WIDTH;
    igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
    int toggle_x = ((float)width/2)/se_dpi_scale()-(float)sel_width*num_toggles/2;
    if((width)/se_dpi_scale()-toggle_x-(sel_width+1)*num_toggles<volume_width)toggle_x=(width)/se_dpi_scale()-(sel_width+1)*num_toggles-volume_width;
    if(toggle_x<orig_x)toggle_x=orig_x;

    if(gui_state.ui_type!=SE_UI_ANDROID&&gui_state.ui_type!=SE_UI_IOS){
      int vol_x = width/se_dpi_scale()-volume_width;
      if(vol_x<toggle_x+(sel_width+1)*num_toggles)vol_x=toggle_x+(sel_width+1)*num_toggles;
      igSetCursorPosX(vol_x);
      igPushItemWidth(-0.01);
      se_slider_int_themed("",&v,0,100,"%2.f%% "ICON_FK_VOLUME_UP);
      se_tooltip("Adjust volume");
      gui_state.settings.volume=v*0.01;
      igPopItemWidth();
      igSetCursorPosX(orig_x);
    }    

    float toggle_width = sel_width*num_toggles;

    igSameLine(toggle_x,0);
    igPushItemWidth(sel_width);

    sb_joy_t *curr = &emu_state.joy;
    sb_joy_t *prev = &emu_state.prev_frame_joy;

    if(curr->inputs[SE_KEY_RESET_GAME]){
      emu_state.run_mode=SB_MODE_RESET;
    }

    for(int i=0;i<SE_NUM_SAVE_STATES;++i){
      if(curr->inputs[SE_KEY_CAPTURE_STATE(i)])se_capture_state_slot(i);
      if(curr->inputs[SE_KEY_RESTORE_STATE(i)])se_restore_state_slot(i);
    }

    if(!emu_state.rom_loaded) emu_state.run_mode = SB_MODE_PAUSE;

    int curr_toggle = 3;
    if(emu_state.run_mode==SB_MODE_REWIND)curr_toggle=0;
    if(emu_state.run_mode==SB_MODE_RUN && (emu_state.step_frames<0))curr_toggle=1;
    if(emu_state.run_mode==SB_MODE_PAUSE)curr_toggle=2;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==1)curr_toggle=2;
    if(emu_state.run_mode==SB_MODE_RUN && (emu_state.step_frames>1 || emu_state.step_frames==0))curr_toggle=3;

    if(emu_state.run_mode==SB_MODE_PAUSE)gui_state.menubar_hide_timer=se_time();

    const char* fast_forward_label = ICON_FK_FORWARD;
    if(emu_state.run_mode==SB_MODE_RUN){
      if(emu_state.step_frames==0)fast_forward_label=ICON_FK_UNLOCK;
      if(emu_state.step_frames>1){
        static char buffer[3]="2X";
        buffer[0]='0'+emu_state.step_frames;
        fast_forward_label=buffer;
      }
    }
    const char* rewind_label = ICON_FK_BACKWARD;
    if(emu_state.run_mode==SB_MODE_REWIND){
      if(emu_state.step_frames<0)rewind_label=ICON_FK_UNLOCK;
      else if(emu_state.step_frames>=1){
        static char buffer[3]="2X";
        buffer[0]='0'+emu_state.step_frames;
        rewind_label=buffer;
      }
    }
    const char* slow_label = ICON_FK_HOURGLASS;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames<0){
      static char buffer[4]="1/X";
      buffer[2]='0'-emu_state.step_frames;
      slow_label=buffer;
    }
    const char* toggle_labels[]={
      rewind_label,
      slow_label,
      ICON_FK_PLAY,
      fast_forward_label
    };

    const char* toggle_tooltips[]={
      "Rewind",
      "Slow",
      "Toggle pause/play.\n When paused, the rom selection screen will be shown.",
      "Fast Forward",
    };
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==1){
      toggle_labels[2]=ICON_FK_PAUSE;
    }
    int next_toggle_id = -1; 

    int first_hardcore_toggle = 2;

    if(emu_state.run_mode!=SB_MODE_PAUSE){
      if(curr->inputs[SE_KEY_EMU_REWIND] && !prev->inputs[SE_KEY_EMU_REWIND]){
        emu_state.run_mode=SB_MODE_REWIND;
        emu_state.step_frames=2;
      }
      if(
          (!curr->inputs[SE_KEY_EMU_REWIND] && prev->inputs[SE_KEY_EMU_REWIND]) ||
          (!curr->inputs[SE_KEY_EMU_FF_2X] && prev->inputs[SE_KEY_EMU_FF_2X]) ||
          (!curr->inputs[SE_KEY_EMU_FF_MAX] && prev->inputs[SE_KEY_EMU_FF_MAX])
        ){
        emu_state.run_mode=SB_MODE_RUN;
        emu_state.step_frames=1;
      }
      if(curr->inputs[SE_KEY_EMU_FF_2X] && !prev->inputs[SE_KEY_EMU_FF_2X]){
        emu_state.run_mode=SB_MODE_RUN;
        emu_state.step_frames=2;
      }
      if(curr->inputs[SE_KEY_EMU_FF_MAX] && !prev->inputs[SE_KEY_EMU_FF_MAX]){
        emu_state.run_mode=SB_MODE_RUN;
        emu_state.step_frames=-1;
      }
    }

    if(!emu_state.rom_loaded)se_push_disabled();
    for(int i=0;i<num_toggles;++i){
      bool hardcore_disabled = gui_state.settings.hardcore_mode&&gui_state.ra_logged_in&& i<first_hardcore_toggle;
      if(hardcore_disabled)se_push_disabled();
      bool active_button = i==curr_toggle;
      if(active_button)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(se_button_themed(SE_REGION_BLANK+ (active_button? 2:0),toggle_labels[i],(ImVec2){sel_width, SE_MENU_BAR_HEIGHT},true))next_toggle_id = i;
      igSameLine(0,1);
      if(hardcore_disabled) se_tooltip("Disabled in Hardcore Mode");
      else se_tooltip(toggle_tooltips[i]);
      
      if(active_button)igPopStyleColor(1);

      if(i==num_toggles-1)igPopStyleVar(1);
      if(hardcore_disabled)se_pop_disabled();
    }
    if(!emu_state.rom_loaded)se_pop_disabled();
    
    switch(next_toggle_id){
      case 0: {
        emu_state.run_mode=SB_MODE_REWIND;
        if(emu_state.step_frames==2 && curr_toggle == next_toggle_id)emu_state.step_frames=4;
        else if(emu_state.step_frames==4 && curr_toggle == next_toggle_id)emu_state.step_frames=8;
        else emu_state.step_frames=2;
      } ;break;
      case 1: {
        emu_state.run_mode=SB_MODE_RUN;
        if(emu_state.step_frames==-2&& curr_toggle == next_toggle_id)emu_state.step_frames=-4;
        else if(emu_state.step_frames==-4&& curr_toggle == next_toggle_id)emu_state.step_frames=-8;
        else emu_state.step_frames=-2;
      } ;break;
      case 2: {emu_state.run_mode=emu_state.run_mode==SB_MODE_RUN&&emu_state.step_frames==1?SB_MODE_PAUSE: SB_MODE_RUN;emu_state.step_frames=1;} ;break;
      case 3: {
        emu_state.run_mode=SB_MODE_RUN;
        if(emu_state.step_frames==2     && curr_toggle == next_toggle_id)emu_state.step_frames=4;
        else if(emu_state.step_frames==4&& curr_toggle == next_toggle_id)emu_state.step_frames=8;
        else if(emu_state.step_frames==8&& curr_toggle == next_toggle_id)emu_state.step_frames=0;
        else emu_state.step_frames=2;
        break;
      } 
    }

    if(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in){
      if(emu_state.run_mode==SB_MODE_REWIND||emu_state.run_mode==SB_MODE_STEP){
        emu_state.run_mode= SB_MODE_RUN;
        emu_state.step_frames=1;
      }
      if(emu_state.step_frames<1&&emu_state.step_frames!=-1)emu_state.step_frames=1; 
    }

    if(gui_state.settings.hardcore_mode&&gui_state.ra_logged_in){
      if(emu_state.run_mode==SB_MODE_REWIND||emu_state.run_mode==SB_MODE_STEP)emu_state.run_mode= SB_MODE_RUN;
      if(emu_state.step_frames<1&&emu_state.step_frames!=-1)emu_state.step_frames=1; 
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
  bool active = se_process_file_browser();
  if(!active){
    float screen_x = 0; 
    float screen_width = width; 
    float scaled_screen_width = screen_width/se_dpi_scale();

    float sidebar_w = 300; 
    int num_sidebars_open = gui_state.sidebar_open+gui_state.ra_sidebar_open;
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
      igSetNextWindowSize((ImVec2){sidebar_w, (gui_state.screen_height-menu_height*se_dpi_scale())/se_dpi_scale()}, ImGuiCond_Always);
      igBegin(se_localize_and_cache("Menu"),&gui_state.sidebar_open, ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
      se_draw_menu_panel();
      igEnd();
      screen_x += sidebar_w;
      screen_width -=sidebar_w*se_dpi_scale();
      gui_state.key.last_bind_activitiy = -1;
      gui_state.menubar_hide_timer=se_time();
    }
    #ifdef ENABLE_RETRO_ACHIEVEMENTS
    bool logged_in = rc_client_get_user_info(retro_achievements_get_client());
    if(gui_state.ra_sidebar_open&&logged_in){
      igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
      igSetNextWindowSize((ImVec2){sidebar_w, (gui_state.screen_height-menu_height*se_dpi_scale())/se_dpi_scale()}, ImGuiCond_Always);
      igBegin(se_localize_and_cache(ICON_FK_TROPHY " RetroAchievements"),&gui_state.ra_sidebar_open, ImGuiWindowFlags_NoCollapse|ImGuiWindowFlags_NoResize);
      retro_achievements_draw_panel();
      igEnd();
      screen_x += sidebar_w;
      screen_width -=sidebar_w*se_dpi_scale();
      gui_state.menubar_hide_timer=se_time();
    }
    #endif
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
    bool draw_click_region = emu_state.run_mode!=SB_MODE_RUN&&emu_state.run_mode!=SB_MODE_REWIND && !draw_sidebars_over_screen&& (gui_state.overlay_open||!emu_state.rom_loaded);
    gui_state.block_touchscreen = draw_sidebars_over_screen;
    // The menubar shouldn't resize the screen when it autohides as it re-layouts the controls. 
    if(gui_state.settings.always_show_menubar==false&&screen_width==width&&draw_sidebars_over_screen==false&&draw_click_region==false)menu_height=0;
    igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
    igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
    igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0.0f);
    igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
    igPushStyleColorVec4(ImGuiCol_WindowBg, (ImVec4){0,0,0,0.});

    igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration
      |ImGuiWindowFlags_NoBringToFrontOnFocus);
  
    se_update_frame();

    se_draw_emulated_system_screen(false);

#ifdef ENABLE_RETRO_ACHIEVEMENTS
    float left = screen_x;
    float top = menu_height;
    float right = screen_x+screen_width/se_dpi_scale();
    float bottom = height/se_dpi_scale();
    float padding = screen_width/se_dpi_scale()* 0.02;

    if (gui_state.settings.draw_notifications)
      retro_achievements_draw_notifications(left+padding,top+padding,screen_width/se_dpi_scale(),gui_state.settings.only_one_notification);

    if (gui_state.settings.draw_progress_indicators)
      retro_achievements_draw_progress_indicator(right-padding,top+padding,screen_width/se_dpi_scale());

    if (gui_state.settings.draw_leaderboard_trackers)
      retro_achievements_draw_leaderboard_trackers(left+padding,bottom-padding);

    if (gui_state.settings.draw_challenge_indicators)
      retro_achievements_draw_challenge_indicators(right-padding,bottom-padding,screen_width/se_dpi_scale());
#endif

    for(int i=0;i<SAPP_MAX_TOUCHPOINTS;++i){
      if(gui_state.touch_points[i].active)gui_state.last_touch_time = se_time();
    }

    igPopStyleVar(2);
    igPopStyleColor(1);
    igEnd();
    if(draw_click_region){
      igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
      igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
      igBegin("##ClickRegion",&gui_state.overlay_open,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoResize);
    }
    se_load_rom_overlay(draw_click_region);
    if(draw_click_region)igEnd();
  }
  if(emu_state.run_mode==SB_MODE_RUN||emu_state.run_mode==SB_MODE_REWIND)gui_state.overlay_open= true; 
  /*=== UI CODE ENDS HERE ===*/

  simgui_render();
  sg_end_pass();
  static float old_dpi= 0;
  if(old_dpi!=se_dpi_scale()){
    simgui_shutdown();
    simgui_setup(&(simgui_desc_t){ .dpi_scale= se_dpi_scale()});
    old_dpi =se_dpi_scale();
    gui_state.update_font_atlas=true;
  }
  if(gui_state.update_font_atlas){
    gui_state.update_font_atlas=false;
    ImFontAtlas* atlas = igGetIO()->Fonts;    

    ImFont *font = NULL;
    float font_scale=1.0;
   
    if(gui_state.settings.theme==SE_THEME_CUSTOM){
      size_t size =0; 
      font_scale = gui_state.settings.custom_font_scale;
      uint8_t* data = sb_load_file_data(gui_state.paths.custom_font,&size);
      if(data){
        font =ImFontAtlas_AddFontFromMemoryTTF(
        atlas,data,size,13*se_dpi_scale()*font_scale,NULL,NULL);
      }
    }
    
    if(!font){
      uint64_t karla_compressed_size; 
      const uint8_t* karla_compressed_data = se_get_resource(SE_KARLA,&karla_compressed_size);
      font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
        atlas,karla_compressed_data,karla_compressed_size,13*se_dpi_scale()*font_scale,NULL,NULL);
    }
    
    uint64_t forkawesome_compressed_size; 
    const uint8_t* forkawesome_compressed_data = se_get_resource(SE_FORKAWESOME,&forkawesome_compressed_size);

    static const ImWchar icons_ranges[] = { ICON_MIN_FK, ICON_MAX_FK, 0 }; // Will not be copied by AddFont* so keep in scope.
    ImFontConfig* config=ImFontConfig_ImFontConfig();
    config->MergeMode = true;
    config->GlyphMinAdvanceX = 13.0f;
    ImFont* font2 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,
      forkawesome_compressed_data,forkawesome_compressed_size,13*se_dpi_scale()*font_scale,config,icons_ranges);
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
      ImFont* font3 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,notosans_cjksc_compressed_data,notosans_cjksc_compressed_size,14*se_dpi_scale()*font_scale,config3,ranges);
      uint64_t noto_armenian_size;
      const uint8_t *noto_armenian = se_get_resource(SE_NOTO_ARMENIAN,&noto_armenian_size);
      ImFont* font4 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,noto_armenian,noto_armenian_size,14*se_dpi_scale()*font_scale,config3,ranges);
      uint64_t noto_sans_size=0;
      const uint8_t *noto_sans = se_get_resource(SE_NOTO_SANS,&noto_sans_size);
      ImFont* font5 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,noto_sans,noto_sans_size,14*se_dpi_scale()*font_scale,config3,ranges);
      ImFontConfig_destroy(config3);
      igGetIO()->FontDefault=font3;
    #endif

    {
      uint64_t karla_compressed_size; 
      const uint8_t* karla_compressed_data = se_get_resource(SE_SV_BASIC_MANUAL,&karla_compressed_size);
      gui_state.mono_font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
        atlas,karla_compressed_data,karla_compressed_size,13*se_dpi_scale()*font_scale,NULL,NULL);
    }
    

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
  int sample_copies = 1;
  if(emu_state.step_frames<0)sample_copies = -emu_state.step_frames;
  int sample_copy_index = sample_copies; 
  for(int s = 0; s<num_samples_to_push;s+=samples_to_push){
    float audio_buff[samples_to_push];
    if(sb_ring_buffer_size(&emu_state.audio_ring_buff)<=samples_to_push){
      se_reset_audio_ring();
      break;
    }
    for(int i=0;i<samples_to_push/2;++i){
      int16_t data0 = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr)%SB_AUDIO_RING_BUFFER_SIZE];
      int16_t data1 = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr+1)%SB_AUDIO_RING_BUFFER_SIZE];
      if(--sample_copy_index == 0){
        sample_copy_index = sample_copies;
        emu_state.audio_ring_buff.read_ptr+=2;
      }
      audio_buff[i*2]=data0*volume_sq;
      audio_buff[i*2+1]=data1*volume_sq;
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
  atlas_upload_all();
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
#if defined(USE_SDL) || defined(SE_PLATFORM_ANDROID)
  if(!se_load_controller_settings(&gui_state.controller)){
    se_set_default_controller_binds(&gui_state.controller);
  }
#endif
  {
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%suser_settings.bin",se_get_pref_path());
    if(!sb_load_file_data_into_buffer(settings_path,(void*)&gui_state.settings,sizeof(gui_state.settings))){gui_state.settings.settings_file_version=-1;}
    int max_settings_version_supported =3;
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
      gui_state.settings.always_show_menubar=true;
      gui_state.settings.language=SE_LANG_DEFAULT;
      gui_state.settings.touch_controls_scale=1.0;
      gui_state.settings.touch_controls_show_turbo = 1; 
      gui_state.settings.save_to_path = false;
      gui_state.settings.http_control_server_enable = false; 
      gui_state.settings.http_control_server_port=8080;
      gui_state.settings.avoid_overlaping_touchscreen = true;
    }
    if(gui_state.settings.settings_file_version<3){
      gui_state.settings.gui_scale_factor = 1.0; 
      gui_state.settings.settings_file_version = 3;
      gui_state.settings.hardcore_mode=0;
      gui_state.settings.draw_challenge_indicators=1;
      gui_state.settings.draw_progress_indicators=1;
      gui_state.settings.draw_leaderboard_trackers=1;
      gui_state.settings.draw_notifications=1;
      gui_state.settings.show_screen_bezel=true;

      bool is_mobile = gui_state.ui_type == SE_UI_ANDROID || gui_state.ui_type == SE_UI_IOS;
      if(is_mobile){
        gui_state.settings.only_one_notification=1;
      }
      gui_state.settings.enable_download_cache=1;
      https_set_cache_enabled(gui_state.settings.enable_download_cache);
      gui_state.settings.nds_layout = 0; 
      gui_state.settings.touch_screen_show_button_labels= true;
    }
    if(gui_state.settings.gui_scale_factor<0.5)gui_state.settings.gui_scale_factor=1.0;
    if(gui_state.settings.gui_scale_factor>4.0)gui_state.settings.gui_scale_factor=1.0;

    if(gui_state.settings.custom_font_scale<0.5)gui_state.settings.custom_font_scale=1.0;
    if(gui_state.settings.custom_font_scale>2.0)gui_state.settings.custom_font_scale=1.0;
    if(gui_state.settings.touch_controls_scale<0.1)gui_state.settings.touch_controls_scale=1.0;
    if(gui_state.settings.touch_controls_opacity<0||gui_state.settings.touch_controls_opacity>1.0)gui_state.settings.touch_controls_opacity=0.5;
    if(gui_state.settings.gba_color_correction_mode> GBA_HIGAN_CORRECTION)gui_state.settings.gba_color_correction_mode=GBA_SKYEMU_CORRECTION;
    gui_state.last_saved_settings=gui_state.settings;
    se_reload_theme();
  }
  {
    memset(&cloud_state,0,sizeof(se_cloud_state_t));
    cloud_state.save_states_mutex = mutex_create();
    char refresh_token_path[SB_FILE_PATH_SIZE];
    snprintf(refresh_token_path,SB_FILE_PATH_SIZE,"%srefresh_token.txt",se_get_pref_path());
    if(sb_file_exists(refresh_token_path)){
      cloud_drive_create(se_drive_ready_callback);
    }
  }
#ifdef ENABLE_RETRO_ACHIEVEMENTS
  bool is_mobile = gui_state.ui_type == SE_UI_ANDROID || gui_state.ui_type == SE_UI_IOS;
  retro_achievements_initialize(&emu_state,gui_state.settings.hardcore_mode);
#endif
}
static void se_compute_draw_lcd_rect(float *lcd_render_w, float *lcd_render_h, int* nds_layout){
  float rotation = gui_state.settings.screen_rotation*0.5*3.14159;
  if(!gui_state.settings.stretch_to_fit){
    float scr_w = *lcd_render_w;
    float scr_h = *lcd_render_h;
    float native_w = SB_LCD_W;
    float native_h = SB_LCD_H;
    bool touch_controller_active = gui_state.last_touch_time>=0||gui_state.settings.auto_hide_touch_controls==false;
    *nds_layout= gui_state.settings.nds_layout;
    if(emu_state.system==SYSTEM_GBA){native_w = GBA_LCD_W; native_h = GBA_LCD_H;}
    else if(emu_state.system==SYSTEM_NDS){
      if(*nds_layout==SE_NDS_LAYOUT_AUTO){
        *nds_layout = SE_NDS_LAYOUT_VERTICAL;
        if(scr_w/scr_h>1&&!touch_controller_active)*nds_layout = SE_NDS_LAYOUT_HYBRID_LARGE_TOP;
      }
      switch(*nds_layout){
        case SE_NDS_LAYOUT_VERTICAL: 
          native_w = NDS_LCD_W; native_h = NDS_LCD_H*2;
          break; 
        case SE_NDS_LAYOUT_HORIZONTAL: 
          native_w = NDS_LCD_W*2; native_h = NDS_LCD_H;
          break; 
        case SE_NDS_LAYOUT_HYBRID_LARGE_TOP:  
        case SE_NDS_LAYOUT_HYBRID_LARGE_BOTTOM: 
         native_w = NDS_LCD_W+NDS_LCD_W*0.5;
         native_h = NDS_LCD_H;
          break; 
        case SE_NDS_LAYOUT_VERTICAL_LARGE_BOTTOM: 
        case SE_NDS_LAYOUT_VERTICAL_LARGE_TOP: 
          native_w = NDS_LCD_W; native_h = NDS_LCD_H*1.5;
          break;
        case SE_NDS_LAYOUT_HORIZONTAL_LARGE_BOTTOM: 
        case SE_NDS_LAYOUT_HORIZONTAL_LARGE_TOP: 
          native_w = NDS_LCD_W*1.5; native_h = NDS_LCD_H;
          break; 
        default:
          gui_state.settings.nds_layout = SE_NDS_LAYOUT_AUTO;
          break;
      }
    }
    float lcd_aspect= native_h/native_w;

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
    if(scr_w*render_aspect>height) render_scale = height/render_h;
    else render_scale = scr_w/render_w;

    *lcd_render_w = native_w*render_scale;
    *lcd_render_h = native_h*render_scale;

    if(gui_state.settings.integer_scaling){
      float old_w = *lcd_render_w;
      float old_h = *lcd_render_h;
      float dpi_scale = se_dpi_scale();
      *lcd_render_h = ((int)((*lcd_render_h)/(native_h/dpi_scale)))*native_h/dpi_scale;
      *lcd_render_w = ((int)((*lcd_render_w)/(native_w/dpi_scale)))*native_w/dpi_scale;
      if(*lcd_render_w==0)*lcd_render_w=old_w;
      if(*lcd_render_h==0)*lcd_render_h=old_h;
    }
  }
  switch(gui_state.settings.screen_rotation){
    case 1: case 3:{
      float tmp = *lcd_render_w;
      *lcd_render_w = *lcd_render_h;
      *lcd_render_h = tmp;
    }
  }
}
static void se_draw_lcd_in_rect(float lcd_render_x, float lcd_render_y, float lcd_render_w, float lcd_render_h, int nds_layout){
  float dpi_scale = se_dpi_scale();
  float lx = lcd_render_x*dpi_scale;
  float ly = lcd_render_y*dpi_scale;
  float rotation = gui_state.settings.screen_rotation*0.5*3.14159;
  float lw = lcd_render_w*dpi_scale;
  float lh = lcd_render_h*dpi_scale;

  if(gui_state.settings.screen_rotation==1||gui_state.settings.screen_rotation==3){
    float t = lw;
    lw = lh;
    lh=t;
  }

  if(emu_state.system==SYSTEM_GBA){
    se_draw_lcd_defer(core.gba.framebuffer,GBA_LCD_W,GBA_LCD_H,lx,ly, lw, lh,rotation,false);
  }else if (emu_state.system==SYSTEM_NDS){
    if(nds_layout==SE_NDS_LAYOUT_HYBRID_LARGE_TOP){
      float p[6]={
        0.3333* lw,- lh*0.25,
        0.3333* lw, lh*0.25,
        -0.1666* lw,0,
      };
      for(int i=0;i<3;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw/3, lh*0.5,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw/3, lh*0.5,rotation,true);
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[4],ly+p[5], lw*2/3, lh,rotation,false);
    }else if(nds_layout==SE_NDS_LAYOUT_HYBRID_LARGE_BOTTOM){
      float p[6]={
        0.3333* lw,- lh*0.25,
        0.3333* lw, lh*0.25,
        -0.1666* lw,0,
      };
      for(int i=0;i<3;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw/3, lh*0.5,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw/3, lh*0.5,rotation,true);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[4],ly+p[5], lw*2/3, lh,rotation,true);
    }else if(nds_layout==SE_NDS_LAYOUT_HORIZONTAL){
      float p[4]={
        0.25* lw,0,
        -0.25* lw,0,
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw/2, lh,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw/2, lh,rotation,true);
    }else if(nds_layout==SE_NDS_LAYOUT_HORIZONTAL_LARGE_TOP){
      float p[4]={
        -0.166666* lw,0,
        0.3333333* lw,0,
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw*2/3, lh,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw/3, lh*0.5,rotation,true);
    }else if(nds_layout==SE_NDS_LAYOUT_HORIZONTAL_LARGE_BOTTOM){
      float p[4]={
        -0.3333333* lw,0,
        0.166666* lw,0,
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw/3, lh*0.5,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw*2/3, lh,rotation,true);
    }else if(nds_layout==SE_NDS_LAYOUT_VERTICAL_LARGE_TOP){
      float p[4]={
        0,-0.1666666*lh,
        0, 0.33333333*lh,
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw, lh*2/3,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw*0.5, lh/3,rotation,true);
    }else if(nds_layout==SE_NDS_LAYOUT_VERTICAL_LARGE_BOTTOM){
      float p[4]={
        0,-0.333333*lh,
        0,0.16666666*lh,
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw*0.5, lh/3,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw, lh*2/3,rotation,true);
    }else{
      float p[4]={
        0,- lh*0.25,
        0,lh*0.25
      };
      for(int i=0;i<2;++i){
        float x = p[i*2+0];
        float y = p[i*2+1];
        p[i*2+0] = x*cos(-rotation)+y*sin(-rotation);
        p[i*2+1] = x*-sin(-rotation)+y*cos(-rotation);
      }
      se_draw_lcd_defer(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lx+p[0],ly+p[1], lw, lh*0.5,rotation,false);
      se_draw_lcd_defer(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lx+p[2],ly+p[3], lw, lh*0.5,rotation,true);
    }
  }else if (emu_state.system==SYSTEM_GB){
    se_draw_lcd_defer(core.gb.lcd.framebuffer,SB_LCD_W,SB_LCD_H,lx,ly, lw, lh,rotation,false);
  }
}
static float se_compute_touchscreen_controls_min_dim(float w, float h, bool * portrait){
  float min_dim = fmax(w,h*0.5)*0.6*gui_state.settings.touch_controls_scale*gui_state.settings.touch_controls_scale;
  int nds_layout =0; 
  //Shrink width if height is too small
  if(h*2<min_dim)min_dim=h*2;


  // Choose portrait or not based on which direction makes the screen largest
  float lcd_w_p=w, lcd_h_p = h;
  float lcd_w_l=w, lcd_h_l = h;
  lcd_h_p-=min_dim*0.5;
  lcd_w_l-=min_dim;

  se_compute_draw_lcd_rect(&lcd_w_p,&lcd_h_p,&nds_layout);
  se_compute_draw_lcd_rect(&lcd_w_l,&lcd_h_l,&nds_layout);
  *portrait = lcd_w_p*lcd_h_p> lcd_w_l*lcd_h_l;
  
  return min_dim; 
}
static int se_draw_theme_region_tint_partial(int region, float x, float y, float w, float h, float w_ratio, float h_ratio, uint32_t tint){
  se_theme_region_t* r = &gui_state.theme.regions[region];
  if(!r->active)return 0; 
  if(w==0||h==0)return 0;

  int lod = log2(fmin(r->w/w,r->h/h))-0.5;
  if(lod<0)lod =0;
  else if (lod>=SE_THEME_IMAGE_MIPS)lod = SE_THEME_IMAGE_MIPS-1;
  if(gui_state.theme.image[lod].id==SG_INVALID_ID)return 0;

  float tex_w = gui_state.theme.im_w;
  float tex_h = gui_state.theme.im_h;

  float fixed_pixels[2]={0,0};
  float screen_pixels[2]={0,0};
  float fixed_screen_pixels[2]={0,0};
  float gamepad_fixed[2] = {0,0};
  float gamepad_screen_stretch[2]={0,0};
  float gamepad_stretch[2]={0,0};
  float screen_gamepad_pixels[2]={0,0};
  float screen_no_gamepad_pixels[2]={0,0};
  float non_screen[2]={0,0};

  float native_w = w, native_h = h;
  int nds_layout = gui_state.settings.nds_layout;
  se_compute_draw_lcd_rect(&native_w, &native_h, &nds_layout);
  bool portrait = false;
  float min_dim = se_compute_touchscreen_controls_min_dim(w,h,&portrait);

  bool has_gamepad = false;

  int gamepad_mask = portrait? 0x30 : 0xC0;
  int skip_mask = portrait? SE_RESIZE_ONLY_LANDSCAPE : SE_RESIZE_ONLY_PORTRAIT;
  //When overlap is allowed, just render gamepad over screen
  if(gui_state.settings.avoid_overlaping_touchscreen==false)gamepad_mask = 0x0;
  if(gui_state.settings.auto_hide_touch_controls && gui_state.last_touch_time<0.01){
    skip_mask = SE_RESIZE_ONLY_LANDSCAPE | SE_RESIZE_ONLY_PORTRAIT;
    gamepad_mask = 0;
  }

  //Categorize pixels
  float rdims[2]={0,0};
  for(int axis=0;axis<2;++axis)
    for(int i=0;i<SE_MAX_CONTROL_POINTS;++i){
      se_control_point_t *cp = axis? r->control_points_y+i:r->control_points_x+i;
      bool fixed = (cp->resize_control& SE_RESIZE_FIXED);
      bool screen = cp->screen_control== SE_SCREEN_BOTH;
      bool gamepad = (cp->gamepad_control&gamepad_mask)!=0;
      float pixels = cp->end_pixel-cp->start_pixel;
      if(cp->resize_control&skip_mask)pixels*=0;

      if(fixed&& cp->screen_control==0)fixed_pixels[axis] +=pixels;
      if(screen) screen_pixels[axis]+=pixels;
      if(!screen) non_screen[axis]+=pixels;

      if(screen&&!gamepad&&!fixed)screen_no_gamepad_pixels[axis]+=pixels;
      if(fixed&&screen) fixed_screen_pixels[axis]+=pixels;
      if(gamepad){
        if(fixed)   gamepad_fixed[axis]+=pixels;
        else if(screen)gamepad_screen_stretch[axis]+=pixels;
        else gamepad_stretch[axis]+=pixels; 
        has_gamepad=true;
      }
      rdims[axis]+=pixels;
    }

  float uniform_scale_factor = fmin(w/rdims[0], h/rdims[1]);
  for(int r=0;r<2;++r){
    fixed_pixels[r]*=uniform_scale_factor;
    screen_pixels[r]*=uniform_scale_factor;
    fixed_screen_pixels[r]*=uniform_scale_factor; 
    gamepad_fixed[r]*=uniform_scale_factor; 
    gamepad_screen_stretch[r]*=uniform_scale_factor; 
    gamepad_stretch[r]*=uniform_scale_factor; 
    screen_no_gamepad_pixels[r]*=uniform_scale_factor;
    non_screen[r]*=uniform_scale_factor;
  }

  float dims[2]={w,h};
  float lcd_non_fixed_scale[2]={1,1};
  float non_fixed_pixels_scale[2]={1,1};
  float lcd_dims[2];
  SE_RPT2 lcd_dims[r]=screen_pixels[r]? dims[r]-fixed_pixels[r]:0;

  {
    float   non_fixed_pixels[2];
    SE_RPT2 non_fixed_pixels[r]      = dims[r]-fixed_pixels[r]-lcd_dims[r];
    SE_RPT2 non_fixed_pixels_scale[r]= (non_fixed_pixels[r])/(rdims[r]*uniform_scale_factor-fixed_pixels[r]-screen_pixels[r]);

    bool touch_controller_active = gui_state.last_touch_time>=0||gui_state.settings.auto_hide_touch_controls==false;
    if(!touch_controller_active)min_dim = 0;
    float adj[2]={0,0};
    //Shrink screen to fit gamepad
    if(gamepad_mask){
      int i = portrait;
      float md = i? min_dim*0.5:min_dim;
      float gamepad_size = (gamepad_screen_stretch[i]+gamepad_fixed[i])+gamepad_stretch[i]*non_fixed_pixels_scale[i];
      if(md>gamepad_size&&lcd_dims[i]){
        lcd_dims[i]-=md-gamepad_size;
        adj[i] = md-gamepad_size;
      }
    }
    se_compute_draw_lcd_rect(&lcd_dims[0],&lcd_dims[1],&nds_layout);

    SE_RPT2 lcd_non_fixed_scale[r]=(lcd_dims[r]-fixed_screen_pixels[r])/(screen_pixels[r]-fixed_screen_pixels[r]);

    SE_RPT2 non_fixed_pixels[r]= dims[r]-fixed_pixels[r]-lcd_dims[r];
    SE_RPT2 non_fixed_pixels_scale[r]= (non_fixed_pixels[r])/(rdims[r]*uniform_scale_factor-fixed_pixels[r]-screen_pixels[r]);
  }

  float x_clamp = x+w*w_ratio;
  float y_clamp = y+h*h_ratio; 
  ImVec2 pmin = {x,y};
  ImVec2 pmax = {x,y};
  bool first_screen = true;
  bool drew_controller = false;

  for(int yc=0;yc<SE_MAX_CONTROL_POINTS;++yc){
    se_control_point_t *ycp = &r->control_points_y[yc];
    if(ycp->start_pixel>=ycp->end_pixel)continue;
    pmax.x=pmin.x=x;
    float rh = (ycp->end_pixel-ycp->start_pixel)*uniform_scale_factor;
    if(ycp->screen_control){
      if(!(ycp->resize_control&SE_RESIZE_FIXED)){
        rh*=lcd_non_fixed_scale[1];
      }
    }else if(!(ycp->resize_control&SE_RESIZE_FIXED)){
      rh*=non_fixed_pixels_scale[1];
    }
    if(ycp->resize_control&skip_mask)rh*=0;
    pmax.y += rh;
    for(int xc=0;xc<SE_MAX_CONTROL_POINTS;++xc){
      se_control_point_t *xcp = &r->control_points_x[xc];
      if(xcp->start_pixel>=xcp->end_pixel)continue;
      ImVec2 uv0 = {(xcp->start_pixel)/tex_w, (ycp->start_pixel)/tex_h};
      ImVec2 uv1 = {(xcp->end_pixel)/tex_w, (ycp->end_pixel)/tex_h};
      float rw= (xcp->end_pixel-xcp->start_pixel)*uniform_scale_factor;
      if(xcp->screen_control){
        if(!(xcp->resize_control&SE_RESIZE_FIXED)){
          rw*=lcd_non_fixed_scale[0];
        }
      }else if(!(xcp->resize_control&SE_RESIZE_FIXED)){
        rw*=non_fixed_pixels_scale[0];
      }
      if(xcp->resize_control&skip_mask)rw*=0;

      pmax.x += rw;
      if(pmin.x>x_clamp||pmin.y>y_clamp)continue; 
      if(pmax.x>x_clamp){
        uv1.x = uv0.x+(uv1.x-uv0.x)*(x_clamp-pmin.x)/(pmax.x-pmin.x);
        pmax.x = x_clamp;
      }
      if(pmax.y>y_clamp){
        uv1.y = uv0.y+(uv1.y-uv0.y)*(y_clamp-pmin.y)/(pmax.y-pmin.y);
        pmax.y = y_clamp;
      }
      if(xcp->screen_control&&ycp->screen_control&&first_screen){
        first_screen = false; 
        float dpi_scale = se_dpi_scale();
        float lcd_pos[2] = {ceil((pmin.x+lcd_dims[0]*0.5)*dpi_scale)/dpi_scale,ceil((pmin.y+lcd_dims[1]*0.5)*dpi_scale)/dpi_scale};
        se_draw_lcd_in_rect(lcd_pos[0],lcd_pos[1],lcd_dims[0],lcd_dims[1],nds_layout);
      }

      int t = 0xff000000; 
      ImDrawList_AddImage(igGetWindowDrawList(),(ImTextureID)(uintptr_t)gui_state.theme.image[lod].id,pmin,pmax,uv0,uv1,tint);
      //ImDrawList_AddRect(igGetWindowDrawList(),pmin,pmax,t,0,ImDrawCornerFlags_None, 2);

      if((xcp->gamepad_control&gamepad_mask)&&(ycp->gamepad_control&gamepad_mask)){
        //This needs to run when exiting the gamepad region so the game pad doesnt get covered by other sub regions
        if((xc==SE_MAX_CONTROL_POINTS-1||(r->control_points_x[xc+1].gamepad_control&gamepad_mask)==0)&&(yc==SE_MAX_CONTROL_POINTS-1||(r->control_points_y[yc+1].gamepad_control&gamepad_mask)==0)){
          float width=0;
          float height=0; 
          for(int xc2=xc;xc2>=0;--xc2){
            se_control_point_t* p = &r->control_points_x[xc2];
            if((p->gamepad_control&gamepad_mask)==0)break;
            float span = (p->end_pixel-p->start_pixel)*uniform_scale_factor;
            if(p->screen_control){
              if(!(p->resize_control&SE_RESIZE_FIXED)){
                span*=lcd_non_fixed_scale[0];
              }
            }else if(!(p->resize_control&SE_RESIZE_FIXED))span*=non_fixed_pixels_scale[0];
            width+= span;
          }
          for(int yc2=yc;yc2>=0;--yc2){
            se_control_point_t* p = &r->control_points_y[yc2];
            if((p->gamepad_control&gamepad_mask)==0)break;
            float span = (p->end_pixel-p->start_pixel)*uniform_scale_factor;
            if(p->screen_control){
              if(!(p->resize_control&SE_RESIZE_FIXED)){
                span*=lcd_non_fixed_scale[1];
              }
            }else if(!(p->resize_control&SE_RESIZE_FIXED)){
              span*=non_fixed_pixels_scale[1];
            }
            height+= span;
          }
          ImVec2 pmin_gamepad = {pmax.x-width,pmax.y-height};
          int gc_mode = xcp->gamepad_control&ycp->gamepad_control;
          gc_mode = (gc_mode|(gc_mode<<2))&0xc0;
          int off_y = 0;
          if(height>min_dim){
            off_y-=(height-min_dim)*0.5;
            height = min_dim;
          }
          float min_dim_new = min_dim; 
          if(gc_mode==SE_GAMEPAD_BOTH){
            if(min_dim_new>width)min_dim_new=width;
          }else{
            if(width>min_dim*0.5){
              if(gc_mode==SE_GAMEPAD_RIGHT){
                pmin_gamepad.x+=width-min_dim*0.5;
              }
              width = min_dim*0.5;
            }else if(min_dim*0.5>width)min_dim_new=width*2.0;
          }
  
          pmin_gamepad.y-=off_y;
          ImVec2 pmax_gamepad = pmin_gamepad;
          pmax_gamepad.x+=width;
          pmax_gamepad.y+=height;
          //ImDrawList_AddRect(igGetWindowDrawList(),pmin_gamepad,pmax_gamepad,0xffffffff,0,ImDrawCornerFlags_None, 2);
          if(gc_mode&SE_GAMEPAD_LEFT)se_draw_onscreen_controller(&emu_state,SE_GAMEPAD_LEFT,pmin_gamepad.x,pmin_gamepad.y,min_dim_new*0.5,height,true, true);
          if(gc_mode&SE_GAMEPAD_RIGHT)se_draw_onscreen_controller(&emu_state,SE_GAMEPAD_RIGHT,pmax_gamepad.x-min_dim_new*0.5,pmin_gamepad.y,min_dim_new*0.5,height,true, true);
          drew_controller = true;
        }
      }
      pmin.x=pmax.x;
    }
    pmin.y = pmax.y;
  }
  bool drew_screen = first_screen==false;
  int result = SE_THEME_DREW_BACKGROUND; 
  if(drew_screen)result|= SE_THEME_DREW_SCREEN;
  if(drew_controller)result|=SE_THEME_DREW_CONTROLLER;
  return result;
}
static int se_draw_theme_region_tint(int region, float x, float y, float w, float h,uint32_t tint){
  return se_draw_theme_region_tint_partial(region, x, y, w, h, 1.0, 1.0, tint);
}
static int se_draw_theme_region(int region, float x, float y, float w, float h){
  return se_draw_theme_region_tint(region,x,y,w,h,0xffffffff);
}
static bool se_load_theme_from_image_format_full(uint8_t* im, uint32_t im_w, uint32_t im_h){

  uint32_t version_code = (uint32_t)im[(75+32*im_w)*4+3];
  version_code |= (uint32_t)im[(75+32*im_w)*4+2]<<(8*1);
  version_code |= (uint32_t)im[(75+32*im_w)*4+1]<<(8*2);
  version_code |= (uint32_t)im[(75+32*im_w)*4+0]<<(8*3);
  if(version_code!= 0x6f8a91ff){
    printf("Error Loading Theme: Unknown Version Code %08x\n",version_code);
    return false;
  }
  se_custom_theme_t* theme = &gui_state.theme;
  theme->im_h= im_h;
  theme->im_w= im_w;

  // Name and author
  for(int i=0;i<2;++i){
    se_theme_region_t * region = &theme->regions[SE_REGION_NAME+i];
    region->x = 51;
    region->y = 94+i*(154-94);
    region->w = 900;
    region->h = 146-94;
  }
  // Palettes
  for(int i=0;i<5;++i){
    int im_x = i*70 + 1420;
    int im_y = 177; 
    theme->palettes[i*4+0]= im[(im_x+im_y*im_w)*4+0];
    theme->palettes[i*4+1]= im[(im_x+im_y*im_w)*4+1];
    theme->palettes[i*4+2]= im[(im_x+im_y*im_w)*4+2];
    theme->palettes[i*4+3]= im[(im_x+im_y*im_w)*4+3];
  }

  //Menu Buttons
  for(int x=0;x<8;++x){
    for(int y=0;y<3;++y){
      se_theme_region_t * region = &theme->regions[SE_REGION_MENU+y+x*3];
      region->x=2220+x*(2450-2220);
      region->y=82+y*(262-82);
      region->w=2440-2220;
      region->h=252-82;
    }
  }

  //Volume Bar
  for(int x=0;x<2;++x){
    for(int y=0;y<2;++y){
      se_theme_region_t * region = &theme->regions[SE_REGION_VOL_EMPTY+y+x*2];
      region->x=4057+x*(4567-4057);
      region->y=82+y*(262-82);
      region->w=4557-4057;
      region->h=252-82;
    }
  }

  //Volume Knob
  for(int y=0;y<2;++y){
    se_theme_region_t * region = &theme->regions[SE_REGION_VOL_KNOB+y];
    region->x=5077;
    region->y=82+y*(262-82);
    region->w=5237-5077;
    region->h=252-82;
  }

  //Menu background
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_MENUBAR];
    region->x=4057;
    region->y=442;
    region->w=5237-region->x;
    region->h=612-region->y;
  }

  //Bezel Portrait
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_BEZEL_PORTRAIT];
    region->x=15;
    region->y=250;
    region->w=2160;
    region->h=3840;
  }
  //NoBezel
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_NO_BEZEL];
    region->x=7;
    region->y=7;
    region->w=1;
    region->h=1;
    region->active=false;
  }
  //Bezel Landscape
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_BEZEL_LANDSCAPE];
    region->x=15;
    region->y=4158;
    region->w=3840;
    region->h=2160;
  }

  for(int key = 0; key<7;++key){
    se_theme_region_t * key_up = &theme->regions[key*2+SE_REGION_KEY_A];
    se_theme_region_t * key_down = &theme->regions[key*2+SE_REGION_KEY_A_PRESSED];
    key_up->x = 4194;
    key_up->y = 3764+(4284-3764)*key;
    key_up->w = 500;
    key_up->h = 500;
    key_down->x = 4704;
    key_down->y = key_up->y;
    key_down->w = key_up->w;
    key_down->h = key_up->h;
  }
  for(int dpad = 0; dpad<9;++dpad){
    se_theme_region_t * dpad_region = &theme->regions[dpad+SE_REGION_DPAD_UL];
    int x = dpad%3;
    int y = dpad/3;
  
    dpad_region->x = 2209 + (3219-2209)*x;
    dpad_region->y = 704+ (1714-704)*y;
    dpad_region->w = 1000;
    dpad_region->h = 1000;
  }
  //Select/start
  for(int x=0;x<2;++x){
    for(int y=0;y<2;++y){
      se_theme_region_t * region = &theme->regions[SE_REGION_KEY_START+y+x*2];
      region->x=2055+x*(3062-2055);
      region->y=6378+y*(6888-6378);
      region->w=3048-2055;
      region->h=6878-6378;
    }
  }

  //L/R
  for(int x=0;x<2;++x){
    for(int y=0;y<2;++y){
      se_theme_region_t * region = &theme->regions[SE_REGION_KEY_L+y+x*2];
      region->x=15+x*(3062-2055);
      region->y=6378+y*(6888-6378);
      region->w=3048-2055;
      region->h=6878-6378;
    }
  }
  return true;
}
static bool se_load_theme_from_image_format_mini(uint8_t* im, uint32_t im_w, uint32_t im_h){

  uint32_t version_code = (uint32_t)im[(32+32*im_w)*4+3];
  version_code |= (uint32_t)im[(32+32*im_w)*4+2]<<(8*1);
  version_code |= (uint32_t)im[(32+32*im_w)*4+1]<<(8*2);
  version_code |= (uint32_t)im[(32+32*im_w)*4+0]<<(8*3);
  if(version_code!= 0x6f8a91ff){
    printf("Error Loading Theme: Unknown Version Code %08x\n",version_code);
    return false;
  }
  se_custom_theme_t* theme = &gui_state.theme;
  theme->im_h= im_h;
  theme->im_w= im_w;

  // Name and author
  for(int i=0;i<2;++i){
    se_theme_region_t * region = &theme->regions[SE_REGION_NAME+i];
    region->x = 7;
    region->y = 65+i*(125-65);
    region->w = 662;
    region->h = 53;
  }
  // Palettes
  for(int i=0;i<5;++i){
    int im_x = i*57 + 420;
    int im_y = 40; 
    theme->palettes[i*4+0]= im[(im_x+im_y*im_w)*4+0];
    theme->palettes[i*4+1]= im[(im_x+im_y*im_w)*4+1];
    theme->palettes[i*4+2]= im[(im_x+im_y*im_w)*4+2];
    theme->palettes[i*4+3]= im[(im_x+im_y*im_w)*4+3];
  }

  //Menu Buttons
  for(int button=0;button<2;++button)
  for(int state=0;state<2;++state){
    se_theme_region_t * region = &theme->regions[(button?SE_REGION_BLANK:SE_REGION_MENU)+state*2];
    region->x=1027+button*(220+7);
    region->y=2500+state*(160+7);
    region->w=220;
    region->h=160;
  }


  //Volume Bar
  for(int y=0;y<2;++y){
    se_theme_region_t * region = &theme->regions[SE_REGION_VOL_EMPTY+y*2];
    region->x=1481;
    region->y=2500+y*(160+7);
    region->w=500;
    region->h=160;
  }
  

  //Volume Knob
  for(int y=0;y<2;++y){
    se_theme_region_t * region = &theme->regions[SE_REGION_VOL_KNOB+y*2];
    region->x=1988;
    region->y=2500+y*(160+7);
    region->w=160;
    region->h=160;
  }

  //Menu background
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_MENUBAR];
    region->x=1014;
    region->y=2323;
    region->w=1514;
    region->h=170;
  }

  //Bezel Portrait
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_BEZEL_PORTRAIT];
    region->x=1014;
    region->y=7;
    region->w=2021;
    region->h=1802;
  }

  //No Bezel
  {
    se_theme_region_t * region = &theme->regions[SE_REGION_NO_BEZEL];
    region->x=879;
    region->y=7;
    region->w=127;
    region->h=170;
  }
  //ABXY
  for(int k = 0; k<4;++k){
    se_theme_region_t * key = &theme->regions[k*2+SE_REGION_KEY_A];
    key->x = 1014 +k*(500+7);
    key->y = 1816;
    key->w = 500;
    key->h = 500;
  }
  //Turbo/Hold
  for(int k = 0; k<2;++k){
    se_theme_region_t * key = &theme->regions[k*2+SE_REGION_KEY_TURBO];
    key->x = 7 +k*(333+7);
    key->y = 2500;
    key->w = 333;
    key->h = 320;
  }
  //Rect Blank
  {
    se_theme_region_t * key = &theme->regions[SE_REGION_KEY_RECT_BLANK];
    key->x = 7 +2*(333+7);
    key->y = 2500;
    key->w = 333;
    key->h = 320;
  }
  //Blank
  {
    se_theme_region_t * key = &theme->regions[SE_REGION_KEY_BLANK];
    key->x = 2535;
    key->y = 2323;
    key->w = 500;
    key->h = 500;
  }
  //Dpad
  {
    se_theme_region_t * dpad_region = &theme->regions[SE_REGION_DPAD_CENTER];
    dpad_region->x = 7;
    dpad_region->y = 185;
    dpad_region->w = 1000;
    dpad_region->h = 1000;
  }
  //L/R/Start/Select
  for(int y=0;y<4;++y){
    se_theme_region_t * region = &theme->regions[SE_REGION_KEY_L+y*2];
    region->x=7;
    region->y=1192+y*(7+320);
    region->w=1000;
    region->h=320;
  }
  return true;
}
static uint8_t * se_pad_image_to_size(uint8_t* im, uint32_t im_w, uint32_t im_h, uint32_t new_w, uint32_t new_h){
  uint8_t * new_image = malloc(new_w*new_h*4);
  memset(new_image,0,new_w*new_h*4);
  for(int y = 0; y< im_h;++y)
    for(int x = 0; x< im_w;++x){
      new_image[(y*new_w + x)*4+0] = im[(y*im_w+x)*4+0];
      new_image[(y*new_w + x)*4+1] = im[(y*im_w+x)*4+1];
      new_image[(y*new_w + x)*4+2] = im[(y*im_w+x)*4+2];
      new_image[(y*new_w + x)*4+3] = im[(y*im_w+x)*4+3];
    }
  return new_image;
} 
static bool se_load_theme_from_image(uint8_t* im, uint32_t im_w, uint32_t im_h, bool invert, bool blacken){
  if(!im){return false; }
  bool loaded = false; 
  se_custom_theme_t* theme = &gui_state.theme;
  for(int i=0; i<SE_TOTAL_REGIONS;++i){
    se_theme_region_t * region = &theme->regions[i];
    region->x=region->y=region->w=region->h=0;
    region->active=false;
  }

  if(im_w==5250 && im_h == 7400)loaded = se_load_theme_from_image_format_full(im,im_w,im_h);
  else if(im_w==3042 && im_h == 2835)loaded= se_load_theme_from_image_format_mini(im,im_w,im_h);
  else{ 
    printf("Unknown theme template size: %d %d\n", (int)im_w, (int)im_h);
    return false; 
  }
  if(loaded){

    for(int i=0; i<SE_TOTAL_REGIONS;++i){
      se_theme_region_t * region = &theme->regions[i];
      region->active = false; 
      //Determine if region is active
      if(region->x+region->w>=im_w&&region->y+region->h>=im_h||region->y<=0||region->x<=0)continue;
      for(int y=1;y<region->h-1;++y){
        for(int x=1;x<region->w-1;++x){
          int pixel = (x+region->x)+(y+region->y)*im_w;
          if(im[pixel*4+3]>0x01){
            region->active=true;
            break;
          }
        }
        if(region->active)break;
      }
      for(int i=0;i<SE_MAX_CONTROL_POINTS;++i){
        region->control_points_x[i].start_pixel=
        region->control_points_x[i].end_pixel=
        region->control_points_y[i].start_pixel=
        region->control_points_y[i].end_pixel=0;
        region->control_points_x[i].resize_control=
        region->control_points_x[i].screen_control=
        region->control_points_x[i].gamepad_control=0;
        region->control_points_y[i].resize_control=
        region->control_points_y[i].screen_control=
        region->control_points_y[i].gamepad_control=0;
      }
      //Load Control Points
      for(int dir = 0; dir<2;++dir){
        int current_point = 0; 
        se_control_point_t * cp = region->control_points_x;
        int start_x = region->x;
        int start_y = region->y-3;
        int end_x = region->x+region->w;
        int end_y = region->y+region->h; 
        int inc_x = 1;
        int inc_y = 0; 
        if(dir){
          cp = region->control_points_y;
          start_x = region->x-3;
          start_y = region->y;
          inc_x = 0;
          inc_y = 1; 
        }
        int curr_x = start_x;
        int curr_y = start_y; 
        

        cp->start_pixel=dir? curr_y : curr_x;

        int p = (curr_x+curr_y*im_w)*4;
        for(int i=-2;i<3;++i){
          int p2= p+(inc_x*im_w+inc_y)*4*i;
          if(im[p2+0])cp->resize_control|=im[p2+0];
          if(im[p2+1])cp->screen_control|=im[p2+1];
          if(im[p2+2])cp->gamepad_control|=im[p2+2];
        }

        
        while(curr_x<end_x&&curr_y<end_y){
          int p = (curr_x+curr_y*im_w)*4;
          int resize = 0;
          int screen = 0;
          int gamepad = 0;
          for(int i=-2;i<3;++i){
            int p2= p+(inc_x*im_w+inc_y)*4*i;
            if(im[p2+0])resize|=im[p2+0];
            if(im[p2+1])screen|=im[p2+1];
            if(im[p2+2])gamepad|=im[p2+2];
          }
          if(resize!=cp->resize_control||screen!=cp->screen_control||gamepad!=cp->gamepad_control){
            ++current_point;
            if(current_point>=SE_MAX_CONTROL_POINTS){
              printf("Error: Theme requires more control points than the %d limit for region:%d\n",SE_MAX_CONTROL_POINTS,i);
              break;
            }
            region->active=true;
            cp++;
            cp->start_pixel=dir? curr_y : curr_x;
            cp->screen_control=screen;
            cp->resize_control=resize;
            cp->gamepad_control=gamepad; 
          }
          curr_x+=inc_x; 
          curr_y+=inc_y; 
          cp->end_pixel=dir? curr_y : curr_x;
        }
      }
    }
  
    for(int i=0; i<SE_TOTAL_REGIONS;++i){
      se_theme_region_t * region = &theme->regions[i];
      if(!region->active)continue;
      for(int y = region->y-4; y<region->y+region->h+3;++y){
        for(int x = region->x-4;x<=region->x;++x){
          int x2 = x<region->x? region->x : x>=region->x+region->w? region->x+region->w-1: x;
          int y2 = y<region->y? region->y : y>=region->y+region->h? region->y+region->h-1: y;
          SE_RPT4 im[(x+y*im_w)*4+r]=im[(x2+y2*im_w)*4+r];
        }
        for(int x = region->x+region->w;x<region->x+region->w+3;++x){
          int x2 = x<region->x? region->x : x>=region->x+region->w? region->x+region->w-1: x;
          int y2 = y<region->y? region->y : y>=region->y+region->h? region->y+region->h-1: y;
          SE_RPT4 im[(x+y*im_w)*4+r]=im[(x2+y2*im_w)*4+r];
        }
      }
      for(int x = region->x-4; x<region->x+region->w+3;++x){
        for(int y = region->y-4;y<=region->y;++y){
          int x2 = x<region->x? region->x : x>=region->x+region->w? region->x+region->w-1: x;
          int y2 = y<region->y? region->y : y>=region->y+region->h? region->y+region->h-1: y;
          SE_RPT4 im[(x+y*im_w)*4+r]=im[(x2+y2*im_w)*4+r];
        }
        for(int y = region->y+region->h;y<region->y+region->h+3;++y){
          int x2 = x<region->x? region->x : x>=region->x+region->w? region->x+region->w-1: x;
          int y2 = y<region->y? region->y : y>=region->y+region->h? region->y+region->h-1: y;
          SE_RPT4 im[(x+y*im_w)*4+r]=im[(x2+y2*im_w)*4+r];
        }
      }
    }
    if(invert){
      for(int p=0;p<im_w*im_h;++p){
        im[(p*4)+0]=255-im[(p*4)+0];
        im[(p*4)+1]=255-im[(p*4)+1];
        im[(p*4)+2]=255-im[(p*4)+2];
      }
      for(int i=0;i<sizeof(theme->palettes)/4;++i){
        theme->palettes[i*4+0]= 255-theme->palettes[i*4+0];
        theme->palettes[i*4+1]= 255-theme->palettes[i*4+1];
        theme->palettes[i*4+2]= 255-theme->palettes[i*4+2];
      }
    }
    if(blacken){
      int thresh = 40;
      for(int p=0;p<im_w*im_h;++p){
        if(im[(p*4)+0]<thresh&&im[(p*4)+1]<thresh&&im[(p*4)+0]<thresh){
          im[(p*4)+0]=0;
          im[(p*4)+1]=0;
          im[(p*4)+2]=0;
        }
      }
      for(int i=0;i<sizeof(theme->palettes)/4;++i){
        if(theme->palettes[(i*4)+0]<thresh&&theme->palettes[(i*4)+1]<thresh&&theme->palettes[(i*4)+0]<thresh){
          theme->palettes[(i*4)+0]=0;
          theme->palettes[(i*4)+1]=0;
          theme->palettes[(i*4)+2]=0;
        }
      }
    }
  
    theme->im_h=im_h;
    theme->im_w=im_w;
  
    int num_mips = 0;
    uint8_t* data2 = im;
    for(int m = 0; m<SE_THEME_IMAGE_MIPS;++m){
      int mip_w = (im_w)>>(m);
      int mip_h = (im_h)>>(m);
      uint8_t* data = data2;
      if(m!=0){
        data =(uint8_t*)malloc(mip_w*mip_h*4);
        printf("Gen Mip-layer %d %d\n",mip_w,mip_h);
        for(int y=0;y<mip_h;++y){
          for(int x=0;x<mip_w;++x){
            for(int c = 0; c<4;++c){
              int parent_w = im_w>>(m-1);
              data[(x+y*mip_w)*4+c]=(data2[((x*2+0)+(y*2+0)*parent_w)*4+c]+
                                    data2[((x*2+1)+(y*2+0)*parent_w)*4+c]+
                                    data2[((x*2+0)+(y*2+1)*parent_w)*4+c]+
                                    data2[((x*2+1)+(y*2+1)*parent_w)*4+c])/4;
              
            }
          }
        }
      }
      sg_image_data im_data={0};
      im_data.subimage[0][0].ptr =data;
      im_data.subimage[0][0].size =mip_h*mip_w*4;
      sg_image_desc desc={
        .type=              SG_IMAGETYPE_2D,
        .render_target=     false,
        .width=             mip_w,
        .height=            mip_h,
        .num_slices=        1,
        .num_mipmaps=       0,
        .usage=             SG_USAGE_IMMUTABLE,
        .pixel_format=      SG_PIXELFORMAT_RGBA8,
        .sample_count=      1,
        .min_filter=        SG_FILTER_LINEAR,
        .mag_filter=        SG_FILTER_LINEAR,
        .wrap_u=            SG_WRAP_CLAMP_TO_EDGE,
        .wrap_v=            SG_WRAP_CLAMP_TO_EDGE,
        .border_color=      SG_BORDERCOLOR_OPAQUE_BLACK,
        .data=              im_data,
      };
      gui_state.theme.image[m]=  sg_make_image(&desc);
      if(m>1)free((uint8_t*)data2);
      data2=data;
    }
  }

  return loaded; 
}
static bool se_load_theme_from_file(const char * filename){
  int im_w, im_h, im_c; 
  strncpy(gui_state.loaded_theme_path,filename,SB_FILE_PATH_SIZE);
  uint8_t *imdata = stbi_load(filename, &im_w, &im_h, &im_c, 4);
  if(!imdata){
    printf("Failed to open theme image %s\n",filename);
    return false;
  }
  bool ret = se_load_theme_from_image(imdata, im_w, im_h,false,false);
  stbi_image_free(imdata);
  if(ret){
    printf("Successfully loaded theme: %s\n",filename);
  }
  return ret; 
}
static bool se_load_theme_from_memory(const uint8_t* data, int64_t size, bool invert, bool blacken){
  int im_w, im_h, im_c; 
  uint8_t *imdata = stbi_load_from_memory((const stbi_uc*)data,size, &im_w, &im_h, &im_c, 4);
  if(!imdata){
    printf("Failed to open theme from memory\n");
    return false;
  }
  bool ret = se_load_theme_from_image(imdata, im_w, im_h,invert,blacken);
  stbi_image_free(imdata);
  return ret; 
}
static bool se_reload_theme(){
  if(gui_state.settings.theme ==SE_THEME_CUSTOM){
    return se_load_theme_from_file(gui_state.paths.theme);
  }else{
    uint64_t size; 
    const uint8_t* theme_data = se_get_resource(SE_THEME_DEFAULT,&size);
    return se_load_theme_from_memory(theme_data,size, gui_state.settings.theme==SE_THEME_LIGHT,gui_state.settings.theme==SE_THEME_BLACK);
  }
  return false;
}
static void se_init(){
  printf("SkyEmu %s\n",GIT_COMMIT_HASH);
  stm_setup();
  se_load_settings();
  se_reset_cheats();
  gui_state.editing_cheat_index = -1;
  bool http_server_mode = false;
  if(emu_state.cmd_line_arg_count >3&&strcmp("http_server",emu_state.cmd_line_args[1])==0){
    gui_state.test_runner_mode=true;
    gui_state.settings.http_control_server_port = atoi(emu_state.cmd_line_args[2]);
    emu_state.cmd_line_arg_count =emu_state.cmd_line_arg_count-2;
    emu_state.cmd_line_args =emu_state.cmd_line_args+2;
    gui_state.settings.http_control_server_enable=true;
    http_server_mode=true;
    // HTTP Server mode only has frame stepping which is not allowed in hardcore mode.
    gui_state.settings.hardcore_mode = false; // TODO: this doesn't do much as it can be re-enabled
  } 
  if(emu_state.cmd_line_arg_count>=2){
    se_load_rom(emu_state.cmd_line_args[1]);
    if(http_server_mode)emu_state.run_mode=SB_MODE_PAUSE;
  }
}
static void init(void) {
  #if defined(EMSCRIPTEN)
  em_init_fs();
  #endif
  https_initialize();
  gui_state.overlay_open= true;
#ifdef USE_SDL
  SDL_SetMainReady();
  if(SDL_Init(SDL_INIT_GAMECONTROLLER)){
    printf("Failed to init SDL: %s\n",SDL_GetError());
  }
#endif
  gui_state.ui_type=SE_UI_DESKTOP;
  #if defined(SE_PLATFORM_ANDROID)
  gui_state.ui_type = SE_UI_ANDROID;
  #elif defined(SE_PLATFORM_IOS)
  gui_state.ui_type = SE_UI_IOS;
  #elif defined(SE_PLATFORM_WEB)
  gui_state.ui_type = SE_UI_WEB;
  #endif

  se_initialize_keybind(&gui_state.key);
  sg_setup(&(sg_desc){
      .context = sapp_sgcontext()
  });
  simgui_setup(&(simgui_desc_t){ .dpi_scale= se_dpi_scale()});
  se_init();
  se_imgui_theme();
  // initial clear color
  gui_state.pass_action = (sg_pass_action) {
      .colors[0] = { .action = SG_ACTION_CLEAR, .value={0,0,0,1} }
  };
  gui_state.last_touch_time=-10000;
  se_init_audio();
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
#ifdef SE_PLATFORM_ANDROID
  se_android_request_permissions();
  #endif
}
static void cleanup(void) {
  simgui_shutdown();
  se_free_all_images();
#ifdef ENABLE_RETRO_ACHIEVEMENTS
  retro_achievements_shutdown();
#endif
  sg_shutdown();
  saudio_shutdown();
#ifdef USE_SDL
  SDL_Quit();
#endif
  https_shutdown();
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
bool se_run_ar_cheat(const uint32_t* buffer, uint32_t size){
  if(emu_state.system ==SYSTEM_GBA)return gba_run_ar_cheat(&core.gba, buffer, size);
  if(emu_state.system ==SYSTEM_GB)return sb_run_ar_cheat(&core.gb, buffer, size);
  if(emu_state.system ==SYSTEM_NDS)return nds_run_ar_cheat(&core.nds, buffer, size);

  return false;
}

static void headless_mode(){
  //Leave here so the entry point still exists
#ifdef ENABLE_HTTP_CONTROL_SERVER
  se_init();
  se_update_frame();
  hcs_join_server_thread();
#endif 
}

#ifdef SE_PLATFORM_ANDROID
void Java_com_sky_SkyEmu_EnhancedNativeActivity_se_1android_1load_1rom(JNIEnv *env, jobject thiz, jstring filePath) {
    const char *nativeFilePath = (*env)->GetStringUTFChars(env, filePath, 0);
    gui_state.ran_from_launcher=true;
    se_load_rom(nativeFilePath);
    (*env)->ReleaseStringUTFChars(env, filePath, nativeFilePath);
}
void Java_com_sky_SkyEmu_EnhancedNativeActivity_se_1android_1load_1file(JNIEnv *env, jobject thiz, jstring filePath) {
  const char *nativeFilePath = (*env)->GetStringUTFChars(env, filePath, 0);
  se_file_browser_accept(nativeFilePath);
  (*env)->ReleaseStringUTFChars(env, filePath, nativeFilePath);
}
#endif

sapp_desc sokol_main(int argc, char* argv[]) {
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
  if(emu_state.cmd_line_arg_count >3&&strcmp("http_server",emu_state.cmd_line_args[1])==0)headless_mode();

  #ifdef SE_PLATFORM_IOS
  se_ios_set_documents_working_directory();
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
