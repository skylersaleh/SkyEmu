#define SE_BIND_KEYBOARD 0
#define SE_BIND_KEY 1
#define SE_BIND_ANALOG 2
#define SE_KEY_A 0 
#define SE_KEY_B 1 
#define SE_KEY_X 2 
#define SE_KEY_Y 3 
#define SE_KEY_UP 4
#define SE_KEY_DOWN 5
#define SE_KEY_LEFT 6
#define SE_KEY_RIGHT 7
#define SE_KEY_L 8
#define SE_KEY_R 9
#define SE_KEY_START 10
#define SE_KEY_SELECT 11
#define SE_KEY_FOLD_SCREEN 12
#define SE_KEY_PEN_DOWN 13
#define SE_KEY_EMU_PAUSE 14
#define SE_KEY_EMU_REWIND 15
#define SE_KEY_EMU_FF_2X 16
#define SE_KEY_EMU_FF_MAX 17
#define SE_KEY_CAPTURE_STATE(A) (18+(A)*2)
#define SE_KEY_RESTORE_STATE(A) (18+(A)*2+1)
#define SE_KEY_RESET_GAME 26
#define SE_KEY_TURBO_A  27
#define SE_KEY_TURBO_B  28
#define SE_KEY_TURBO_X  29
#define SE_KEY_TURBO_Y  30
#define SE_KEY_TURBO_L  31
#define SE_KEY_TURBO_R  32
#define SE_KEY_SOLAR_P  33
#define SE_KEY_SOLAR_M  34
#define SE_KEY_TOGGLE_FULLSCREEN 35
#define SE_NUM_KEYBINDS 36
#define SE_MAX_BIOS_FILES 8
#define SE_BIOS_NAME_SIZE 32
#define SE_FILE_PATH_SIZE 1024

#define SE_REWIND_BUFFER_SIZE (1024*1024)
#define SE_REWIND_SEGMENT_SIZE 64
#define SE_LAST_DELTA_IN_TX (1u<<31)

#define SE_NUM_SAVE_STATES 4
#define SE_MAX_SCREENSHOT_SIZE (NDS_LCD_H*NDS_LCD_W*2*4)

#define SE_NUM_CHEATS 32
#define SE_MAX_CHEAT_NAME_SIZE 32
#define SE_MAX_CHEAT_CODE_SIZE 256

#define SE_THEME_DARK 0
#define SE_THEME_LIGHT 1
#define SE_THEME_BLACK 2
#define SE_THEME_CUSTOM 3

#define SE_MENU_BAR_HEIGHT 24
#define SE_MENU_BAR_BUTTON_WIDTH 30
#define SE_TOGGLE_WIDTH 35
#define SE_VOLUME_SLIDER_WIDTH 100

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

typedef struct{
  uint32_t addr;
  const char * name;
  struct{
    uint8_t start;
    uint8_t size;
    const char* name; 
  } bits[32]; 
}mmio_reg_t; 

typedef struct{
  char path[SE_MAX_BIOS_FILES][SE_FILE_PATH_SIZE];
  char name[SE_MAX_BIOS_FILES][SE_BIOS_NAME_SIZE];
  bool success[SE_MAX_BIOS_FILES];
}se_bios_info_t;

typedef struct{
  uint16_t start_pixel;
  uint16_t end_pixel;
  uint8_t resize_control;
  uint8_t screen_control;
  uint8_t gamepad_control;
}se_control_point_t;

typedef struct{
  char save[SE_FILE_PATH_SIZE];
  char bios[SE_FILE_PATH_SIZE];
  char cheat_codes[SE_FILE_PATH_SIZE];
  char theme[SE_FILE_PATH_SIZE];
  char custom_font[SE_FILE_PATH_SIZE];
  char padding[3][SE_FILE_PATH_SIZE];
}se_search_paths_t;
_Static_assert(sizeof(se_search_paths_t)==SE_FILE_PATH_SIZE*8, "se_search_paths_t must contain 8 paths");

//Reserve space for extra keybinds/analog binds so that adding them in new versions don't break
//a users settings.
#define SE_NUM_BINDS_ALLOC 64

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
  char path[SE_FILE_PATH_SIZE];
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
  uint32_t padding[228];
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

static void se_join_path(char * dest_path, int dest_size, const char * base_path, const char* file_name, const char* add_extension){
  const char * seperator = base_path[0]==0? "" : "/"; 
  if(strlen(base_path)!=0){
    char last_base_char = base_path[strlen(base_path)-1];
    if(last_base_char=='/'||last_base_char=='\\')seperator="";
  }
  if(add_extension){
    const char * ext_sep = add_extension[0]=='.' ? "": ".";
    snprintf(dest_path,dest_size,"%s%s%s%s%s",base_path, seperator, file_name,ext_sep,add_extension);
  }else snprintf(dest_path,dest_size,"%s%s%s",base_path, seperator, file_name);
  dest_path[dest_size-1]=0;
}
bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t * data, size_t data_size);

