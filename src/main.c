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

#include "gba.h"
#include "nds.h"
#include "gb.h"
#include "capstone/include/capstone/capstone.h"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

#include "sokol_app.h"
#include "sokol_audio.h"
#include "sokol_gfx.h"
#include "sokol_time.h"
#include "sokol_glue.h"
#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "sokol_imgui.h"
#include "karla.h"
#include "forkawesome.h"
#include "IconsForkAwesome.h"

#ifdef USE_TINY_FILE_DIALOGS
#include "tinyfiledialogs.h"
#endif

#include "SDL.h"

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
#define SE_NUM_KEYBINDS 14

const static char* se_keybind_names[]={
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
  "Fold Screen",
  "Pen Down"
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
#define SE_NUM_RECENT_PATHS 16
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
  SDL_Joystick * sdl_joystick; 
  SDL_GameController * sdl_gc; 
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
  uint32_t padding[254];
}persistent_settings_t; 
_Static_assert(sizeof(persistent_settings_t)==1024, "persistent_settings_t must be exactly 1024 bytes");
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
    bool sidebar_open;
    se_keybind_state_t key;
    se_controller_state_t controller;
    se_game_info_t recently_loaded_games[SE_NUM_RECENT_PATHS];
    persistent_settings_t settings;
    persistent_settings_t last_saved_settings;
} gui_state_t;

void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha);
void se_load_rom_overlay(bool visible);
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h);
void se_reset_save_states();
void se_set_new_controller(se_controller_state_t* cont, int index);

static const char* se_get_pref_path(){
#ifdef EMSCRIPTEN
  return "/offline/";
#else
  return SDL_GetPrefPath("Sky","SkyEmu");
#endif
}

static float se_dpi_scale(){
  float dpi_scale = sapp_dpi_scale();
  if(dpi_scale<=0)dpi_scale=1.;
  return dpi_scale;
}
const char* se_keycode_to_string(int keycode){
  switch(keycode){
    default:           return "Unknown";
    case SAPP_KEYCODE_SPACE:         return "SPACE";
    case SAPP_KEYCODE_APOSTROPHE:    return "APOSTROPHE";
    case SAPP_KEYCODE_COMMA:         return "COMMA";
    case SAPP_KEYCODE_MINUS:         return "MINUS";
    case SAPP_KEYCODE_PERIOD:        return "PERIOD";
    case SAPP_KEYCODE_SLASH:         return "SLASH";
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
    case SAPP_KEYCODE_SEMICOLON:     return "SEMICOLON";
    case SAPP_KEYCODE_EQUAL:         return "EQUAL";
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
    case SAPP_KEYCODE_LEFT_BRACKET:  return "LEFT_BRACKET";
    case SAPP_KEYCODE_BACKSLASH:     return "BACKSLASH";
    case SAPP_KEYCODE_RIGHT_BRACKET: return "RIGHT_BRACKET";
    case SAPP_KEYCODE_GRAVE_ACCENT:  return "GRAVE_ACCENT";
    case SAPP_KEYCODE_WORLD_1:       return "WORLD_1";
    case SAPP_KEYCODE_WORLD_2:       return "WORLD_2";
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
    case SAPP_KEYCODE_PAGE_UP:       return "PAGE_UP";
    case SAPP_KEYCODE_PAGE_DOWN:     return "PAGE_DOWN";
    case SAPP_KEYCODE_HOME:          return "HOME";
    case SAPP_KEYCODE_END:           return "END";
    case SAPP_KEYCODE_CAPS_LOCK:     return "CAPS_LOCK";
    case SAPP_KEYCODE_SCROLL_LOCK:   return "SCROLL_LOCK";
    case SAPP_KEYCODE_NUM_LOCK:      return "NUM_LOCK";
    case SAPP_KEYCODE_PRINT_SCREEN:  return "PRINT_SCREEN";
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
    case SAPP_KEYCODE_KP_0:          return "KP_0";
    case SAPP_KEYCODE_KP_1:          return "KP_1";
    case SAPP_KEYCODE_KP_2:          return "KP_2";
    case SAPP_KEYCODE_KP_3:          return "KP_3";
    case SAPP_KEYCODE_KP_4:          return "KP_4";
    case SAPP_KEYCODE_KP_5:          return "KP_5";
    case SAPP_KEYCODE_KP_6:          return "KP_6";
    case SAPP_KEYCODE_KP_7:          return "KP_7";
    case SAPP_KEYCODE_KP_8:          return "KP_8";
    case SAPP_KEYCODE_KP_9:          return "KP_9";
    case SAPP_KEYCODE_KP_DECIMAL:    return "KP_DECIMAL";
    case SAPP_KEYCODE_KP_DIVIDE:     return "KP_DIVIDE";
    case SAPP_KEYCODE_KP_MULTIPLY:   return "KP_MULTIPLY";
    case SAPP_KEYCODE_KP_SUBTRACT:   return "KP_SUBTRACT";
    case SAPP_KEYCODE_KP_ADD:        return "KP_ADD";
    case SAPP_KEYCODE_KP_ENTER:      return "KP_ENTER";
    case SAPP_KEYCODE_KP_EQUAL:      return "KP_EQUAL";
    case SAPP_KEYCODE_LEFT_SHIFT:    return "LEFT_SHIFT";
    case SAPP_KEYCODE_LEFT_CONTROL:  return "LEFT_CONTROL";
    case SAPP_KEYCODE_LEFT_ALT:      return "LEFT_ALT";
    case SAPP_KEYCODE_LEFT_SUPER:    return "LEFT_SUPER";
    case SAPP_KEYCODE_RIGHT_SHIFT:   return "RIGHT_SHIFT";
    case SAPP_KEYCODE_RIGHT_CONTROL: return "RIGHT_CONTROL";
    case SAPP_KEYCODE_RIGHT_ALT:     return "RIGHT_ALT";
    case SAPP_KEYCODE_RIGHT_SUPER:   return "RIGHT_SUPER";
    case SAPP_KEYCODE_MENU:          return "MENU";
  }
}

#define SE_REWIND_BUFFER_SIZE (1024*1024)
#define SE_REWIND_SEGMENT_SIZE 64
#define SE_LAST_DELTA_IN_TX (1<<31)

#define SE_NUM_SAVE_STATES 4
#define SE_MAX_SCREENSHOT_SIZE (NDS_LCD_H*NDS_LCD_W*2*3)

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
  se_core_state_t state;
  uint8_t screenshot[SE_MAX_SCREENSHOT_SIZE];
  int screenshot_width; 
  int screenshot_height; 
  int system;
  bool valid;
}se_save_state_t; 

se_core_state_t core;
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

gui_state_t gui_state={}; 
static void se_emscripten_flush_fs(){
#if defined(EMSCRIPTEN)
    EM_ASM( FS.syncfs(function (err) {}););
#endif
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
  if(keycode>SAPP_MAX_KEYCODES)return false;
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
void se_draw_arm_state(const char* label, arm7_t *arm, emu_byte_read_t read){
  const char* reg_names[]={"R0","R1","R2","R3","R4","R5","R6","R7","R8","R9 (SB)","R10 (SL)","R11 (FP)","R12 (IP)","R13 (SP)","R14 (LR)","R15 (" ICON_FK_BUG ")","CPSR","SPSR",NULL};
  int r = 0; 
  igText(ICON_FK_SERVER " Registers");
  igSeparator();
  int w= igGetWindowWidth();
  while(reg_names[r]){
    int value = arm7_reg_read(arm,r);
    if(r%2){
      igSetNextItemWidth(-50);
      igSameLine(w*0.5,0);
    }else igSetNextItemWidth((w-100)*0.5);

    if(igInputInt(reg_names[r],&value, 0,0,ImGuiInputTextFlags_CharsHexadecimal)){
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
    igCheckbox(flag_names[i],&v);
    cpsr&=~(1<<b);
    cpsr|= ((int)v)<<b;
  }
  arm7_reg_write(arm,CPSR,cpsr);
  unsigned pc = arm7_reg_read(arm,PC);
  bool thumb = arm7_get_thumb_bit(arm);
  pc-=thumb? 4: 8;
  uint8_t buffer[64];
  int buffer_size = sizeof(buffer);
  if(thumb)buffer_size/=2;
  int off = buffer_size/2;
  if(pc<off)off=pc;
  for(int i=0;i<buffer_size;++i)buffer[i]=read(pc-off+i);
  igText(ICON_FK_LIST_OL " Disassembly");
  igSeparator();
  csh handle;
  if (cs_open(CS_ARCH_ARM, thumb? CS_MODE_THUMB: CS_MODE_ARM, &handle) == CS_ERR_OK){
    cs_insn *insn;
    int count = cs_disasm(handle, buffer, buffer_size, pc-off, 0, &insn);
    size_t j;
    for (j = 0; j < count; j++) {
      char instr_str[80];
      
      if(insn[j].address==pc){
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
        igText("PC " ICON_FK_ARROW_RIGHT);
        igSameLine(40,0);
        snprintf(instr_str,80,"0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        igText(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(130,0);
        igText(instr_str);
        igPopStyleColor(1);
      }else{
        snprintf(instr_str,80,"0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        igText("");
        igSameLine(40,0);
        igText(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(130,0);
        igText(instr_str);
      }
    }  
  }
}
void se_draw_mem_debug_state(const char* label, gui_state_t* gui, emu_byte_read_t read,emu_byte_write_t write){
  igText(ICON_FK_EXCHANGE " Read/Write Memory Address");
  igSeparator();
  igInputInt("address",&gui->mem_view_address, 1,5,ImGuiInputTextFlags_CharsHexadecimal);
  igSeparator();
  int v = se_read32(read,gui->mem_view_address);
  if(igInputInt("data (32 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    se_write32(write,gui->mem_view_address,v);
  }
  v = se_read16(read,gui->mem_view_address);
  if(igInputInt("data (16 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    se_write16(write,gui->mem_view_address,v);
  }
  v = (*read)(gui->mem_view_address);
  if(igInputInt("data (8 bit)",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
    (*write)(gui->mem_view_address,v);
  }
  v = se_read32(read,gui->mem_view_address);
  if(igInputInt("data (signed 32b)",&v, 1,5,ImGuiInputTextFlags_None)){
    se_write32(write,gui->mem_view_address,v);
  }
  v = se_read16(read,gui->mem_view_address);
  if(igInputInt("data (signed 16b)",&v, 1,5,ImGuiInputTextFlags_None)){
    se_write16(write,gui->mem_view_address,v);
  }
  v = (*read)(gui->mem_view_address);
  if(igInputInt("data (signed 8b)",&v, 1,5,ImGuiInputTextFlags_None)){
    (*write)(gui->mem_view_address,v);
  }
}
void se_draw_io_state(const char * label, mmio_reg_t* mmios, int mmios_size, emu_byte_read_t read, emu_byte_write_t write){
  for(int i = 0; i<mmios_size;++i){
    uint32_t addr = mmios[i].addr;
    uint32_t data = se_read32(read, addr);
    bool has_fields = false;
    igPushIDInt(i);
    char lab[80];
    snprintf(lab,80,"0x%08x: %s",addr,mmios[i].name);
    if (igTreeNodeStr(lab)){
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
            edit=igCheckbox("",&v);
            data &= ~mask;
            data |= (v<<start)&mask; 
          }else{
            int v = field_data;
            igPushItemWidth(100);
            edit = igInputInt("",&v, 1,5,ImGuiInputTextFlags_CharsDecimal);
            data &= ~mask;
            data |= (v<<start)&mask;
            igPopItemWidth();
          }
          if(edit){
            se_write32(write,addr,data);
          }
          igSameLine(0,2);
          if(size>1)igText("%s (Bits [%d:%d])",mmios[i].bits[f].name,start, start+size-1);
          else igText("%s (Bit %d)",mmios[i].bits[f].name,start);
        }
        igPopID();
      }
      if(!has_fields){
        int v = data; 
        igPushIDInt(0);
        igPushItemWidth(150);
        if(igInputInt("",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
          se_write32(write,addr,v);
        }
        igSameLine(0,2);
        igText("Data");
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
static const char* valid_rom_file_types[] = { "*.gb", "*.gba","*.gbc" ,"*.nds"};

void se_load_rom(const char *filename){
  se_reset_rewind_buffer(&rewind_buffer);
  se_reset_save_states();
  if(emu_state.rom_loaded){
    if(emu_state.system==SYSTEM_NDS)nds_unload(&core.nds);
    else if(emu_state.system==SYSTEM_GBA)gba_unload(&core.gba);
  }
  char save_file[4096]; 
  save_file[0] = '\0';
  const char* base, *c, *ext; 
  sb_breakup_path(filename,&base, &c, &ext);
#if defined(EMSCRIPTEN)
    snprintf(save_file,4096,"/offline/%s.sav",c);
#else
    snprintf(save_file,4096,"%s/%s.sav",base, c);
#endif
  printf("Loading ROM: %s\n", filename); 
  emu_state.rom_loaded = false; 
  if(gba_load_rom(&core.gba, filename,save_file)){
    emu_state.system = SYSTEM_GBA;
    emu_state.rom_loaded = true;
  }else if(sb_load_rom(&core.gb, &emu_state,filename,save_file)){
    emu_state.system = SYSTEM_GB;
    emu_state.rom_loaded = true; 
  }else if(nds_load_rom(&core.nds,filename,save_file)){
    emu_state.system = SYSTEM_NDS;
    emu_state.rom_loaded = true; 
  }
  if(emu_state.rom_loaded==false)printf("ERROR: Unknown ROM type: %s\n", filename);
  else{
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
  return; 
}
static bool se_sync_save_to_disk(){
  bool saved = false;
  if(emu_state.system== SYSTEM_GB){
    if(core.gb.cart.ram_is_dirty){
      saved=true;
      if(sb_save_file_data(core.gb.cart.save_file_path,core.gb.cart.ram_data,core.gb.cart.ram_size)){
      }else printf("Failed to write out save file: %s\n",core.gb.cart.save_file_path);
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
        if(sb_save_file_data(core.gba.cart.save_file_path,core.gba.mem.cart_backup,size)){
        }else printf("Failed to write out save file: %s\n",core.gba.cart.save_file_path);
      }
      core.gba.cart.backup_is_dirty=false;
    }
  }
  return saved;
}
static double se_get_sim_fps(){
  double sim_fps=1.0;
  if(emu_state.system==SYSTEM_GB)sim_fps = 59.727;
  else if(emu_state.system == SYSTEM_GBA) sim_fps = 59.727;
  else if(emu_state.system == SYSTEM_NDS) sim_fps = 59.727;
  return sim_fps;
}
static void se_emulate_single_frame(){
  if(emu_state.system == SYSTEM_GB)sb_tick(&emu_state,&core.gb);
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &core.gba);
  else if(emu_state.system == SYSTEM_NDS)nds_tick(&emu_state, &core.nds);
  
}
static void se_reset_core(){
  if(emu_state.system == SYSTEM_GB)sb_reset(&core.gb);
  else if(emu_state.system == SYSTEM_GBA)gba_reset(&core.gba);
  else if(emu_state.system == SYSTEM_NDS)nds_reset(&core.nds);
}
static void se_screenshot(uint8_t * output_buffer, int * out_width, int * out_height){
  *out_height=*out_width=0;
  // output_bufer is always SE_MAX_SCREENSHOT_SIZE bytes. RGB8
  if(emu_state.system==SYSTEM_GBA){
    *out_width = GBA_LCD_W;
    *out_height = GBA_LCD_H;
    memcpy(output_buffer,core.gba.framebuffer,GBA_LCD_W*GBA_LCD_H*3);
  }else if (emu_state.system==SYSTEM_NDS){
    *out_width = NDS_LCD_W;
    *out_height = NDS_LCD_H*2;
    memcpy(output_buffer,core.nds.framebuffer_top,NDS_LCD_W*NDS_LCD_H*3);
    memcpy(output_buffer+NDS_LCD_W*NDS_LCD_H*3,core.nds.framebuffer_bottom,NDS_LCD_W*NDS_LCD_H*3);
  }else if (emu_state.system==SYSTEM_GB){
    *out_width = SB_LCD_W;
    *out_height = SB_LCD_H;
    memcpy(output_buffer,core.gb.lcd.framebuffer,SB_LCD_W*SB_LCD_H*3);
  }
}
static void se_draw_emulated_system_screen(){
  int lcd_render_x = 0, lcd_render_y = 0; 
  int lcd_render_w = 0, lcd_render_h = 0; 

  float lcd_aspect = SB_LCD_H/(float)SB_LCD_W;
  if(emu_state.system==SYSTEM_GBA){
    lcd_aspect= GBA_LCD_H/(float)GBA_LCD_W;
  }else if(emu_state.system==SYSTEM_NDS){
    lcd_aspect= NDS_LCD_H*2/(float)NDS_LCD_W;
  }
  // Square Screen
  float scr_w = igGetWindowWidth();
  float scr_h = igGetWindowHeight();
  float height = scr_h;
  float extra_space=0;
  if(scr_w*lcd_aspect>height){
    //Too wide
    extra_space = scr_w-height/lcd_aspect;
    //lcd_rect = (Rectangle){extra_space*0.5, panel_height, height/lcd_aspect,height};
    lcd_render_x = extra_space*0.5;
    lcd_render_w = scr_h/lcd_aspect;
    lcd_render_h = height;
  }else{
    //Too tall
    extra_space = height-scr_w*lcd_aspect;
    lcd_render_y = extra_space*0.5;
    lcd_render_w = scr_w;
    lcd_render_h = scr_w*lcd_aspect;
  }

  int controller_h = scr_h; 
  if(lcd_render_h*1.8<scr_h){
    lcd_render_y = extra_space*0.05;
    controller_h = scr_h-lcd_render_h-lcd_render_y;
  }
  ImVec2 v;
  igGetWindowPos(&v);
  lcd_render_x+=v.x*se_dpi_scale();
  lcd_render_y+=v.y*se_dpi_scale();
  if(emu_state.system==SYSTEM_GBA){
    se_draw_image(core.gba.framebuffer,GBA_LCD_W,GBA_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }else if (emu_state.system==SYSTEM_NDS){
    se_draw_image(core.nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h*0.5,false);
    se_draw_image(core.nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lcd_render_x,lcd_render_y+lcd_render_h*0.5, lcd_render_w, lcd_render_h*0.5,false);
  }else if (emu_state.system==SYSTEM_GB){
    se_draw_image(core.gb.lcd.framebuffer,SB_LCD_W,SB_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }
  sb_draw_onscreen_controller(&emu_state, controller_h);
}
static uint8_t gba_byte_read(uint64_t address){return gba_read8(&core.gba,address);}
static void gba_byte_write(uint64_t address, uint8_t data){gba_store8(&core.gba,address,data);}
static uint8_t gb_byte_read(uint64_t address){return sb_read8(&core.gb,address);}
static void gb_byte_write(uint64_t address, uint8_t data){sb_store8(&core.gb,address,data);}

static uint8_t nds9_byte_read(uint64_t address){return nds9_read8(&core.nds,address);}
static void nds9_byte_write(uint64_t address, uint8_t data){nds9_write8(&core.nds,address,data);}
static uint8_t nds7_byte_read(uint64_t address){return nds7_read8(&core.nds,address);}
static void nds7_byte_write(uint64_t address, uint8_t data){nds7_write8(&core.nds,address,data);}
typedef struct{
  const char* short_label;
  const char* label;
  void (*function)();
  bool visible;
}se_debug_tool_desc_t; 

void gba_memory_debugger(){se_draw_mem_debug_state("GBA MEM", &gui_state, &gba_byte_read, &gba_byte_write); }
void gba_cpu_debugger(){se_draw_arm_state("CPU",&core.gba.cpu,&gba_byte_read);}
void gba_mmio_debugger(){se_draw_io_state("GBA MMIO", gba_io_reg_desc,sizeof(gba_io_reg_desc)/sizeof(mmio_reg_t), &gba_byte_read, &gba_byte_write);}

void gb_mmio_debugger(){se_draw_io_state("GB MMIO", gb_io_reg_desc,sizeof(gb_io_reg_desc)/sizeof(mmio_reg_t), &gb_byte_read, &gb_byte_write);}
void gb_memory_debugger(){se_draw_mem_debug_state("GB MEM", &gui_state, &gb_byte_read, &gb_byte_write);}

void nds7_mmio_debugger(){se_draw_io_state("NDS7 MMIO", nds7_io_reg_desc,sizeof(nds7_io_reg_desc)/sizeof(mmio_reg_t), &nds7_byte_read, &nds7_byte_write); }
void nds9_mmio_debugger(){se_draw_io_state("NDS9 MMIO", nds9_io_reg_desc,sizeof(nds9_io_reg_desc)/sizeof(mmio_reg_t), &nds9_byte_read, &nds9_byte_write); }
void nds7_mem_debugger(){se_draw_mem_debug_state("NDS9 MEM",&gui_state, &nds9_byte_read, &nds9_byte_write); }
void nds9_mem_debugger(){se_draw_mem_debug_state("NDS7_MEM",&gui_state, &nds7_byte_read, &nds7_byte_write);}
void nds7_cpu_debugger(){se_draw_arm_state("ARM7",&core.nds.arm7,&nds7_byte_read); }
void nds9_cpu_debugger(){se_draw_arm_state("ARM9",&core.nds.arm9,&nds9_byte_read);}
se_debug_tool_desc_t gba_debug_tools[]={
  {ICON_FK_TELEVISION, ICON_FK_TELEVISION " CPU", gba_cpu_debugger},
  {ICON_FK_SITEMAP, ICON_FK_SITEMAP " MMIO", gba_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O, ICON_FK_PENCIL_SQUARE_O " Memory",gba_memory_debugger},
  {NULL,NULL,NULL}
};
se_debug_tool_desc_t gb_debug_tools[]={
  {ICON_FK_SITEMAP, ICON_FK_SITEMAP " MMIO", gb_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O, ICON_FK_PENCIL_SQUARE_O " Memory",gb_memory_debugger},
  {NULL,NULL,NULL}
};
se_debug_tool_desc_t nds_debug_tools[]={
  {ICON_FK_TELEVISION " 7", ICON_FK_TELEVISION " ARM7 CPU", nds7_cpu_debugger},
  {ICON_FK_TELEVISION " 9", ICON_FK_TELEVISION " ARM9 CPU", nds9_cpu_debugger},
  {ICON_FK_SITEMAP " 7", ICON_FK_SITEMAP " ARM7 MMIO", nds7_mmio_debugger},
  {ICON_FK_SITEMAP " 9", ICON_FK_SITEMAP " ARM9 MMIO", nds9_mmio_debugger},
  {ICON_FK_PENCIL_SQUARE_O " 7", ICON_FK_PENCIL_SQUARE_O " ARM7 Memory",nds7_mem_debugger},
  {ICON_FK_PENCIL_SQUARE_O " 9", ICON_FK_PENCIL_SQUARE_O " ARM9 Memory",nds9_mem_debugger},
  {NULL,NULL,NULL}
};
static se_debug_tool_desc_t* se_get_debug_description(){
  se_debug_tool_desc_t *desc = NULL;
  if(emu_state.system ==SYSTEM_GBA)desc = gba_debug_tools;
  if(emu_state.system ==SYSTEM_GB)desc = gb_debug_tools;
  if(emu_state.system ==SYSTEM_NDS)desc = nds_debug_tools;
  return desc; 
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
}
void se_reset_save_states(){
  for(int i=0;i<SE_NUM_SAVE_STATES;++i)save_states[i].valid = false;
}
static void se_draw_debug_menu(){
  se_debug_tool_desc_t* desc=se_get_debug_description();
  if(!desc)return;
  ImGuiStyle* style = igGetStyle();
  int id = 10;

  while(desc->label){
    igPushIDInt(id++);
    if(desc->visible){
      igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(igButton(desc->short_label,(ImVec2){0, 0})){desc->visible=!desc->visible;}
      igPopStyleColor(1);
    }else{
      if(igButton(desc->short_label,(ImVec2){0, 0})){desc->visible=!desc->visible;}
    }
    desc++;
    igPopID();
  }
}
static float se_draw_debug_panels(float screen_x, float sidebar_w, float y, float height){
  se_debug_tool_desc_t* desc= se_get_debug_description();
  if(!desc)return screen_x;
  while(desc->label){
    if(desc->visible){
      igSetNextWindowPos((ImVec2){screen_x,y}, ImGuiCond_Always, (ImVec2){0,0});
      igSetNextWindowSize((ImVec2){sidebar_w, height}, ImGuiCond_Always);
      igBegin(desc->label,&desc->visible, ImGuiWindowFlags_NoCollapse);
      desc->function();
      igEnd();
      screen_x+=sidebar_w;
    }
    desc++;
  }
  return screen_x;
}
void se_set_default_keybind(gui_state_t *gui){
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
}
void sb_poll_controller_input(sb_joy_t* joy){
  joy->left  |= 0.5<(gui_state.key.value[SE_KEY_LEFT]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_LEFT]));
  joy->right |= 0.5<(gui_state.key.value[SE_KEY_RIGHT]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_RIGHT]));
  joy->up    |= 0.5<(gui_state.key.value[SE_KEY_UP]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_UP]));
  joy->down  |= 0.5<(gui_state.key.value[SE_KEY_DOWN]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_DOWN]));
  joy->a |= 0.5<(gui_state.key.value[SE_KEY_A]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_A]));
  joy->b |= 0.5<(gui_state.key.value[SE_KEY_B]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_B]));
  joy->start |= 0.5<(gui_state.key.value[SE_KEY_START]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_START]));
  joy->select |= 0.5<(gui_state.key.value[SE_KEY_SELECT]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_SELECT]));
  joy->l |= 0.5<(gui_state.key.value[SE_KEY_L]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_L]));
  joy->r |= 0.5<(gui_state.key.value[SE_KEY_R]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_R]));
  joy->x |= 0.5<(gui_state.key.value[SE_KEY_X]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_X]));
  joy->y |= 0.5<(gui_state.key.value[SE_KEY_Y]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_Y]));
  joy->screen_folded |= !(0.5<(gui_state.key.value[SE_KEY_FOLD_SCREEN]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_FOLD_SCREEN])));
  joy->pen_down |=  0.5<(gui_state.key.value[SE_KEY_PEN_DOWN]=se_key_is_pressed(gui_state.key.bound_id[SE_KEY_PEN_DOWN]));

}
void se_reset_joy(sb_joy_t*joy){
  joy->left  = 
  joy->right = 
  joy->up    = 
  joy->down  = 
  joy->a = 
  joy->b = 
  joy->start = 
  joy->select = 
  joy->l = 
  joy->r = 
  joy->x = 
  joy->y = 
  joy->screen_folded =
  joy->pen_down = false;
}

void se_draw_image_opacity(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha,float opacity){
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

  sg_image *image = se_get_image();
  if(!image)return; 
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
void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
  return se_draw_image_opacity(data,im_width,im_height,x,y,render_width,render_height,has_alpha,1.0);
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
    igText("%s",button_labels[k]);
    float active = (state->value[k])>0.4;
    igSameLine(100,0);
    if(state->bind_being_set==k)active=true;
    if(active)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
    const char* button_label = "Not bound"; 
    char buff[32];
    if(state->bound_id[k]!=-1){
      switch(keybind_type){
        case SE_BIND_KEYBOARD: button_label=se_keycode_to_string(state->bound_id[k]);break;
        case SE_BIND_KEY: 
          snprintf(buff, sizeof(buff),"Key %d", state->bound_id[k]);button_label=buff;
          button_label=buff;
          break;
        case SE_BIND_ANALOG: 
          snprintf(buff, sizeof(buff),"Analog %d (%0.2f)", state->bound_id[k],state->value[k]);button_label=buff;
          button_label=buff;
          break;
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
    if(igButton(button_label,(ImVec2){-1, 0})){
      state->bind_being_set = k;
      state->rebind_start_time = se_time();
    }
    if(active)igPopStyleColor(1);
    igPopID();
  } 
  igPopID();
  return settings_changed;
}
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h){
  if(state->run_mode!=SB_MODE_RUN)return;
  controller_h/=se_dpi_scale();
  float win_w = igGetWindowWidth()/se_dpi_scale();
  float win_h = igGetWindowHeight()/se_dpi_scale();
  ImVec2 pos; 
  igGetWindowPos(&pos);
  float win_x = pos.x;
  float win_y = pos.y+win_h-controller_h;
  win_h=controller_h;
  float size_scalar = win_w;
  if(controller_h*1.4<win_w)size_scalar=controller_h*1.4;
  size_scalar*=1.2;

  int button_padding =0.02*size_scalar; 
  int button_h = win_h*0.1;

  int face_button_h = win_h;
  int face_button_y = 0;

  ImU32 line_color = 0xffffff;
  ImU32 line_color2 =0x000000;
  ImU32 sel_color =0x000000;

  float opacity = 5.-gui_state.last_touch_time;
  if(opacity<=0){opacity=0;return;}
  if(opacity>1)opacity=1;

  line_color|=(int)(opacity*0x48)<<24;
  line_color2|=(int)(opacity*0x48)<<24;
  sel_color|=(int)(opacity*0x48)<<24;

  int line_w0 = 1;
  int line_w1 = 3; 
  float button_r = size_scalar*0.0815;

  float dpad_sz0 = size_scalar*0.051;
  float dpad_sz1 = size_scalar*0.180;

  float a_pos[2] = {win_w-button_r*1.5,face_button_h*0.48+face_button_y};
  float b_pos[2] = {win_w-button_r*3.8,face_button_h*0.54+face_button_y};
  float dpad_pos[2] = {dpad_sz1+button_padding*2,face_button_h*0.5+face_button_y};

  a_pos[0]+=win_x;
  b_pos[0]+=win_x;
  dpad_pos[0]+=win_x;

  a_pos[1]+=win_y;
  b_pos[1]+=win_y;
  dpad_pos[1]+=win_y;

  bool a=false,b=false,up=false,down=false,left=false,right=false,start=false,select=false;
 
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

  ImDrawList*dl= igGetWindowDrawList();
  if(a)  ImDrawList_AddCircleFilled(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,sel_color,128);
  ImDrawList_AddCircle(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,line_color2,128,line_w1);
  ImDrawList_AddCircle(dl,(ImVec2){a_pos[0],a_pos[1]},button_r,line_color,128,line_w0);

  if(b)ImDrawList_AddCircleFilled(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,line_color2,128);
  ImDrawList_AddCircle(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,line_color2,128,line_w1);
  ImDrawList_AddCircle(dl,(ImVec2){b_pos[0],b_pos[1]},button_r,line_color,128,line_w0);

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

  char * button_name[] ={"Start", "Select"};
  int num_buttons =  sizeof(button_name)/sizeof(button_name[0]);
  int button_press=0;           
  int button_x_off = button_padding;
  int button_w = (win_w-(num_buttons+1)*button_padding)/num_buttons;
  int button_y = win_y+win_h-button_h-button_padding;
  for(int b=0;b<num_buttons;++b){                                           
    int state = 0;
    int button_x =button_x_off+(button_w+button_padding)*b;
   
    int x_min = button_x; 
    int x_max = dpad_pos[0]+dpad_sz1;
    if(b){
      x_min = b_pos[0]-button_r;
      x_max =win_w-button_padding;
    }
    for(int i = 0;i<p;++i){
      int dx = points[i][0]-x_min;
      int dy = points[i][1]-button_y;
      if(dx>=-(x_max-x_min)*0.05 && dx<=(x_max-x_min)*1.05 && dy>=0 && dy<=button_h ){
        button_press|=1<<b; 
        ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawCornerFlags_None);  
      }
    }
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawCornerFlags_None,line_w1);  
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color,0,ImDrawCornerFlags_None,line_w0);  
  }
  button_y=win_y+button_padding;
  for(int b=0;b<num_buttons;++b){                                           
    int state = 0;
    int button_x =button_x_off+(button_w+button_padding)*b;
   
    int x_min = button_x; 
    int x_max = dpad_pos[0]+dpad_sz1;
    if(b){
      x_min = b_pos[0]-button_r;
      x_max =win_w-button_padding;
    }
    for(int i = 0;i<p;++i){
      int dx = points[i][0]-x_min;
      int dy = points[i][1]-button_y;
      if(dx>=-(x_max-x_min)*0.05 && dx<=(x_max-x_min)*1.05 && dy>=0 && dy<=button_h ){
        button_press|=1<<(b+2); 
        ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawCornerFlags_None);  
      }
    }
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawCornerFlags_None,line_w1);  
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color,0,ImDrawCornerFlags_None,line_w0); 
  }
  state->joy.left  |= left;
  state->joy.right |= right;
  state->joy.up    |= up;
  state->joy.down  |= down;
  state->joy.a |= a;
  state->joy.b |= b;
  state->joy.start |= SB_BFE(button_press,0,1);
  state->joy.select |= SB_BFE(button_press,1,1);
  state->joy.l |= SB_BFE(button_press,2,1);
  state->joy.r |= SB_BFE(button_press,3,1);
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
  igText(text);
  igSetCursorPos(backup_cursor);
}
bool se_selectable_with_box(const char * first_label, const char* second_label, const char* box){
  int item_height = 40; 
  int padding = 4; 
  int box_h = item_height-padding*2;
  int box_w = box_h;
  bool clicked = false;
  igPushIDStr(second_label);
  ImVec2 curr_pos; 
  igGetCursorPos(&curr_pos);
  curr_pos.y+=padding; 
  curr_pos.x+=padding;
  if(igSelectableBool("",false,ImGuiSelectableFlags_None, (ImVec2){igGetWindowContentRegionWidth(),item_height}))clicked=true;
  ImVec2 next_pos;
  igGetCursorPos(&next_pos);
  igSetCursorPos(curr_pos);
  ImVec2 rect_p = (ImVec2){0,0};
  se_text_centered_in_box((ImVec2){0,0}, (ImVec2){box_w,box_h},box);
  igSetCursorPosY(curr_pos.y-padding*0.5);
  igSetCursorPosX(curr_pos.x+box_w);
  igBeginChildFrame(igGetIDStr(first_label),(ImVec2){igGetWindowContentRegionWidth()-box_w-padding,item_height},ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoScrollbar|ImGuiWindowFlags_NoScrollWithMouse|ImGuiWindowFlags_NoBackground|ImGuiWindowFlags_NoInputs);
  igText(first_label);
  igTextDisabled(second_label);
  igEndChildFrame();
  igSetCursorPos(next_pos);
  igPopID();
  return clicked; 
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
  igBegin(ICON_FK_FILE_O " Load Game",NULL,ImGuiWindowFlags_NoCollapse);
  if(se_selectable_with_box("Load ROM from file (.gb, .gbc, .gba)", "You can also drag & drop a ROM to load it",ICON_FK_FOLDER_OPEN)){
    #ifdef USE_TINY_FILE_DIALOGS
      char *outPath= tinyfd_openFileDialog("Open ROM","", sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]),
                                          valid_rom_file_types,NULL,0);
      if (outPath){
          se_load_rom(outPath);
      }
    #endif
  }
  float list_y_off = igGetWindowHeight(); 
  #ifdef EMSCRIPTEN
    int x, y, w,  h;
    ImVec2 win_p,win_size;
    igGetWindowPos(&win_p);
    igGetWindowSize(&win_size);
    x = win_p.x;
    y = win_p.y;
    w = win_size.x;
    h = win_size.y;
      char * new_path = (char*)EM_ASM_INT({
      var input = document.getElementById('fileInput');
      input.style.left = $0 +'px';
      input.style.top = $1 +'px';
      input.style.width = $2 +'px';
      input.style.height= $3 +'px';
      input.style.visibility = 'visible';
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

  #endif 
  igEnd();
  ImVec2 child_size; 
  child_size.x = w_size.x;
  child_size.y = w_size.y-list_y_off;
  igSetNextWindowSize(child_size,ImGuiCond_Always);
  igSetNextWindowPos((ImVec2){(w_pos.x),list_y_off+w_pos.y},ImGuiCond_Always,(ImVec2){0,0});
  igSetNextWindowBgAlpha(0.9);
  igBegin(ICON_FK_CLOCK_O " Load Recently Played Game",NULL,ImGuiWindowFlags_NoCollapse);
  int num_entries=0;
  for(int i=0;i<SE_NUM_RECENT_PATHS;++i){
    se_game_info_t *info = gui_state.recently_loaded_games+i;
    if(strcmp(info->path,"")==0)break;
    const char* base, *file_name, *ext; 
    sb_breakup_path(info->path,&base,&file_name,&ext);
    char ext_upper[8]={0};
    for(int i=0;i<7&&ext[i];++i)ext_upper[i]=toupper(ext[i]);
    if(se_selectable_with_box(file_name,info->path,ext_upper)){
      se_load_rom(info->path);
    }
    igSeparator();
    num_entries++;
  }
  if(num_entries==0)igText("No recently played games");
  igEnd();
  return;
}
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
        }
        break;      
      }
  }
  if(cont->sdl_joystick){
    for(int k= 0; k<SE_NUM_KEYBINDS;++k){
      int key = cont->key.bound_id[k];
      bool val = false; 
      if(key<SDL_JoystickNumButtons(cont->sdl_joystick)&&key!=-1){
        val = SDL_JoystickGetButton(cont->sdl_joystick,key);
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

    emu_state.joy.left  |= cont->key.value[SE_KEY_LEFT]>0.5;
    emu_state.joy.right |= cont->key.value[SE_KEY_RIGHT]>0.5;
    emu_state.joy.up    |= cont->key.value[SE_KEY_UP]>0.5;
    emu_state.joy.down  |= cont->key.value[SE_KEY_DOWN]>0.5;
    emu_state.joy.a |= cont->key.value[SE_KEY_A]>0.5;
    emu_state.joy.b |= cont->key.value[SE_KEY_B]>0.5;
    emu_state.joy.start |= cont->key.value[SE_KEY_START]>0.5;
    emu_state.joy.select |= cont->key.value[SE_KEY_SELECT]>0.5;
    emu_state.joy.l |= cont->key.value[SE_KEY_L]>0.5;
    emu_state.joy.r |= cont->key.value[SE_KEY_R]>0.5;
    emu_state.joy.x |= cont->key.value[SE_KEY_X]>0.5;
    emu_state.joy.y |= cont->key.value[SE_KEY_Y]>0.5;

    emu_state.joy.left  |= cont->analog.value[SE_ANALOG_LEFT_RIGHT]<-0.3;
    emu_state.joy.right |= cont->analog.value[SE_ANALOG_LEFT_RIGHT]> 0.3;
    emu_state.joy.up    |= cont->analog.value[SE_ANALOG_UP_DOWN]<-0.3;
    emu_state.joy.down  |= cont->analog.value[SE_ANALOG_UP_DOWN]>0.3;

    emu_state.joy.l  |= cont->analog.value[SE_ANALOG_L]>0.1;
    emu_state.joy.r |= cont->analog.value[SE_ANALOG_R]>0.1;
  }
}
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
    if(fabs(curr_time-simulation_time)>0.5||emu_state.run_mode==SB_MODE_PAUSE)simulation_time = curr_time-sim_time_increment*2;
    if(unlocked_mode){
      sim_time_increment=0;
      max_frames_per_tick=1000;
      simulation_time=curr_time+1./50.;
    }
    while(max_frames_per_tick--){
      double error = curr_time-simulation_time;
      if(unlocked_mode){
        if(simulation_time<curr_time&&emu_state.frame){break;}
      }else{
        if(emu_state.frame==0&&simulation_time>curr_time)break;
        if(emu_state.frame&&curr_time-simulation_time<sim_time_increment*0.8){break;}
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
        if(emu_state.frames_since_rewind_push>7 ){
          se_push_rewind_state(&core,&rewind_buffer);
          emu_state.frames_since_rewind_push=0;
        }
        simulation_time+=sim_time_increment;
      }
      emu_state.frame++;
      emu_state.render_frame = false;
      curr_time = se_time();
    }
  }else if(emu_state.run_mode == SB_MODE_STEP) emu_state.run_mode = SB_MODE_PAUSE; 
  emu_state.avg_frame_time = 1.0/se_fps_counter(emu_state.frame);
  bool mute = emu_state.run_mode != SB_MODE_RUN;
  se_reset_joy(&emu_state.joy);
  se_draw_emulated_system_screen();
}
void se_imgui_theme()
{
  ImVec4* colors = igGetStyle()->Colors;
  colors[ImGuiCol_Text]                   = (ImVec4){1.00f, 1.00f, 1.00f, 1.00f};
  colors[ImGuiCol_TextDisabled]           = (ImVec4){0.6f, 0.6f, 0.6f, 1.f};
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
  colors[ImGuiCol_PlotLines]              = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_PlotLinesHovered]       = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
  colors[ImGuiCol_PlotHistogram]          = (ImVec4){1.00f, 0.00f, 0.00f, 1.00f};
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

  ImGuiStyle* style = igGetStyle();
  style->WindowPadding                     = (ImVec2){8.00f, 8.00f};
  style->FramePadding                      = (ImVec2){5.00f, 2.00f};
  //style->CellPadding                       = (ImVec2){6.00f, 6.00f};
  style->ItemSpacing                       = (ImVec2){6.00f, 6.00f};
  //style->ItemInnerSpacing                  = (ImVec2){6.00f, 6.00f};
  //style->TouchExtraPadding                 = (ImVec2){0.00f, 0.00f};
  style->IndentSpacing                     = 25;
  style->ScrollbarSize                     = 15;
  style->GrabMinSize                       = 10;
  style->WindowBorderSize                  = 1;
  style->ChildBorderSize                   = 0;
  style->PopupBorderSize                   = 1;
  style->FrameBorderSize                   = 0;
  style->TabBorderSize                     = 1;
  style->WindowRounding                    = 0;
  style->ChildRounding                     = 4;
  style->FrameRounding                     = 0;
  style->PopupRounding                     = 4;
  style->ScrollbarRounding                 = 9;
  style->GrabRounding                      = 3;
  style->LogSliderDeadzone                 = 4;
  style->TabRounding                       = 4;
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
int se_get_sdl_key_bind(SDL_GameController* gc, int button){
  SDL_GameControllerButtonBind bind = SDL_GameControllerGetBindForButton(gc, button);
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
  igText(ICON_FK_GAMEPAD " Controllers");
  igSeparator();
  ImGuiStyle* style = igGetStyle();
  se_controller_state_t *cont = &gui->controller;
  const char* cont_name = "No Controller";
  if(cont->sdl_joystick){
    cont_name = SDL_JoystickName(cont->sdl_joystick);
  }
  if(igBeginCombo("Controller", cont_name, ImGuiComboFlags_None)){
    {
      bool is_selected=cont->sdl_joystick==NULL;
      if(igSelectableBool("No Controller",is_selected,ImGuiSelectableFlags_None, (ImVec2){0,0})){
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
  if(igButton("Reset Default Controller Bindings",(ImVec2){0,0})){
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

  if(SDL_JoystickHasRumble(cont->sdl_joystick)){igText("Rumble Supported");
  }else igText("Rumble Not Supported");
}
void se_draw_menu_panel(){
  ImGuiStyle *style = igGetStyle();
  igText(ICON_FK_FLOPPY_O " Save States");
  igSeparator();

  int win_w = igGetWindowContentRegionWidth();
  ImDrawList*dl= igGetWindowDrawList();
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
    igText("Save Slot %d",i);
    if(igButton("Capture",(ImVec2){button_w,0}))se_capture_state(&core, save_states+i);
    if(igButton("Restore",(ImVec2){button_w,0}))se_restore_state(&core, save_states+i);
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
                    screen_x*se_dpi_scale(),screen_y*se_dpi_scale(),screen_w*se_dpi_scale(),screen_h*se_dpi_scale(), false);

    }else{
      screen_h*=0.85;
      screen_x+=button_w+(slot_w-screen_w-button_w)*0.5;
      screen_y+=(slot_h-screen_h)*0.5-style->FramePadding.y;
      ImU32 color = igColorConvertFloat4ToU32(style->Colors[ImGuiCol_MenuBarBg]);
      ImDrawList_AddRectFilled(igGetWindowDrawList(),(ImVec2){screen_x,screen_y},(ImVec2){screen_x+screen_w,screen_y+screen_h},color,0,ImDrawCornerFlags_None);
    }
    igEndChildFrame();
  }
  igText(ICON_FK_GAMEPAD " Keybinds");
  igSeparator();
  bool value= true; 
  bool modified = se_handle_keybind_settings(SE_BIND_KEYBOARD,&gui_state.key);
  if(igButton("Reset Default Keybinds",(ImVec2){0,0})){
    se_set_default_keybind(&gui_state);
    modified=true;
  }

  if(modified){
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%skeyboard-bindings.bin",se_get_pref_path());
    sb_save_file_data(settings_path,(uint8_t*)gui_state.key.bound_id,sizeof(gui_state.key.bound_id));
    se_emscripten_flush_fs();
  }
  se_draw_controller_config(&gui_state);
  igText(ICON_FK_WRENCH " Advanced");
  igSeparator();
  const char * deb_tool_string = gui_state.settings.draw_debug_menu? ICON_FK_BUG " Hide Debug Tools": ICON_FK_BUG " Show Debug Tools";
  if(igButton(deb_tool_string,(ImVec2){0, 0}))gui_state.settings.draw_debug_menu=!gui_state.settings.draw_debug_menu;

  /* TODO: Implement these later 
  if(igButton(ICON_FK_REPEAT " Reset",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RESET;}
  igSameLine(0,2);
  if(igButton(ICON_FK_FAST_BACKWARD " Rewind Frame",(ImVec2){0, 0})){}
  igSameLine(0,2);
  if(igButton(ICON_FK_FAST_FORWARD " Advance Frame",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_STEP;}
  */
}

static void frame(void) {
  sb_poll_controller_input(&emu_state.joy);
  se_poll_sdl();
  const int width = sapp_width();
  const int height = sapp_height();
  const double delta_time = stm_sec(stm_round_to_common_refresh_rate(stm_laptime(&gui_state.laptime)));
  gui_state.last_touch_time+=delta_time;
  gui_state.screen_width=width;
  gui_state.screen_height=height;
  simgui_new_frame(width, height, delta_time);
  float menu_height = 0; 
  /*=== UI CODE STARTS HERE ===*/
  igPushStyleVarVec2(ImGuiStyleVar_FramePadding,(ImVec2){5,5});
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0,5});
  ImGuiStyle* style = igGetStyle();
  if (igBeginMainMenuBar())
  {
    int orig_x = igGetCursorPosX();
    igSetCursorPosX((width/se_dpi_scale())-100);
    igPushItemWidth(-0.01);
    int v = (int)(gui_state.settings.volume*100); 
    igSliderInt("",&v,0,100,"%d%% "ICON_FK_VOLUME_UP,ImGuiSliderFlags_AlwaysClamp);
    gui_state.settings.volume=v*0.01;
    igPopItemWidth();
    igSetCursorPosX(orig_x);

    if(gui_state.sidebar_open){
      igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(igButton(ICON_FK_TIMES,(ImVec2){0, 0})){gui_state.sidebar_open=!gui_state.sidebar_open;}
      igPopStyleColor(1);
    }else{
      if(igButton(ICON_FK_BARS,(ImVec2){0, 0})){gui_state.sidebar_open=!gui_state.sidebar_open;}
    }

    if(gui_state.settings.draw_debug_menu)se_draw_debug_menu();

    if(emu_state.run_mode==SB_MODE_RUN) igText("%.0f FPS",se_fps_counter(0));
    else igText("SkyEmu", (ImVec2){0, 0});


    
    int num_toggles = 5;
    int sel_width =35;
    igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
    int toggle_x = (width/2)/se_dpi_scale()-sel_width*num_toggles/2;
    if(toggle_x<igGetCursorPosX())toggle_x=igGetCursorPosX();
    igSetCursorPosX(toggle_x);
    igPushItemWidth(sel_width);


    int curr_toggle = 3;
    if(emu_state.run_mode==SB_MODE_REWIND&&emu_state.step_frames==2)curr_toggle=0;
    if(emu_state.run_mode==SB_MODE_REWIND&&emu_state.step_frames==1)curr_toggle=1;
    if(emu_state.run_mode==SB_MODE_PAUSE)curr_toggle=3;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==1)curr_toggle=2;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==2)curr_toggle=3;
    if(emu_state.run_mode==SB_MODE_RUN && emu_state.step_frames==-1)curr_toggle=4;
    const char* toggle_labels[]={ICON_FK_FAST_BACKWARD, ICON_FK_BACKWARD, ICON_FK_PAUSE, ICON_FK_FORWARD,ICON_FK_FAST_FORWARD};
    if(curr_toggle!=2)toggle_labels[2]=ICON_FK_PLAY;
    int next_toggle_id = -1; 
    for(int i=0;i<num_toggles;++i){
      bool active_button = i==curr_toggle;
      if(active_button)igPushStyleColorVec4(ImGuiCol_Button, style->Colors[ImGuiCol_ButtonActive]);
      if(igButton(toggle_labels[i],(ImVec2){sel_width, 0}))next_toggle_id = i;
      if(active_button)igPopStyleColor(1);

      if(i==num_toggles-1)igPopStyleVar(1);
    }
    switch(next_toggle_id){
      case 0: {emu_state.run_mode=SB_MODE_REWIND;emu_state.step_frames=2;} ;break;
      case 1: {emu_state.run_mode=SB_MODE_REWIND;emu_state.step_frames=1;} ;break;
      case 2: {emu_state.run_mode=curr_toggle==2?SB_MODE_PAUSE: SB_MODE_RUN;emu_state.step_frames=1;} ;break;
      case 3: {emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=2;} ;break;
      case 4: {emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=-1;} ;break;
    }
    igPopItemWidth();
    
    
    menu_height= igGetWindowHeight();
    igEndMainMenuBar();
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
  if(gui_state.sidebar_open){
    igSetNextWindowPos((ImVec2){0,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
    igSetNextWindowSize((ImVec2){sidebar_w, (height-menu_height*se_dpi_scale())/se_dpi_scale()}, ImGuiCond_Always);
    igBegin("Menu",&gui_state.sidebar_open, ImGuiWindowFlags_NoCollapse);
    se_draw_menu_panel();
    igEnd();
    screen_x = sidebar_w;
    screen_width -=screen_x*se_dpi_scale(); 
    gui_state.key.last_bind_activitiy = -1;
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

  igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
  igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0.0f);
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
  igPushStyleColorVec4(ImGuiCol_WindowBg, (ImVec4){0,0,0,1.});

  igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration
    |ImGuiWindowFlags_NoBringToFrontOnFocus);
 
  se_update_frame();
  igPopStyleVar(2);
  igPopStyleColor(1);
  igEnd();
  bool draw_click_region = emu_state.run_mode!=SB_MODE_RUN&&emu_state.run_mode!=SB_MODE_REWIND && !draw_sidebars_over_screen;
  if(draw_click_region){
    igSetNextWindowPos((ImVec2){screen_x,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
    igSetNextWindowSize((ImVec2){screen_width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
    igBegin("##ClickRegion",NULL,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoBackground);
  }
  se_load_rom_overlay(draw_click_region);
  if(draw_click_region)igEnd();

  /*=== UI CODE ENDS HERE ===*/

  sg_begin_default_pass(&gui_state.pass_action, width, height);
  simgui_render();
  sg_end_pass();
  static bool init=false;
  if(!init){
    init=true;
    ImFontAtlas* atlas = igGetIO()->Fonts;    
    ImFont* font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
      atlas,karla_compressed_data,karla_compressed_size,13*se_dpi_scale(),NULL,NULL);
   ImFontAtlas_Build(atlas);

    static const ImWchar icons_ranges[] = { ICON_MIN_FK, ICON_MAX_FK, 0 }; // Will not be copied by AddFont* so keep in scope.
    ImFontConfig config=*ImFontConfig_ImFontConfig();
    config.MergeMode = true;
    config.GlyphMinAdvanceX = 13.0f;
    ImFont* font2 =ImFontAtlas_AddFontFromMemoryCompressedTTF(atlas,
      forkawesome_compressed_data,forkawesome_compressed_size,13*se_dpi_scale(),&config,icons_ranges);
    int built = 0;
 

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
    img_desc.min_filter = SG_FILTER_LINEAR;
    img_desc.mag_filter = SG_FILTER_LINEAR;
    img_desc.data.subimage[0][0].ptr = font_pixels;
    img_desc.data.subimage[0][0].size = (size_t)(font_width * font_height) * sizeof(uint32_t);
    img_desc.label = "sokol-imgui-font";
    atlas->TexID = (ImTextureID)(uintptr_t) sg_make_image(&img_desc).id;
    igGetIO()->FontDefault=font2;
    igGetIO()->Fonts=atlas;
    igGetIO()->FontGlobalScale/=se_dpi_scale();
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
    if(sb_ring_buffer_size(&emu_state.audio_ring_buff)<=samples_to_push)break;
    for(int i=0;i<samples_to_push;++i){
      int16_t data = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE];
      audio_buff[i]=data*volume_sq;
      ++pushed;
      average_volume+=fabs(audio_buff[i]);
    }
    //printf("Samples pushed: %d average_volue %f\n",pushed,average_volume/pushed);
    saudio_push(audio_buff, samples_to_push/2);
  }
  se_free_all_images();
  if(memcmp(&gui_state.last_saved_settings, &gui_state.settings,sizeof(gui_state.settings))){
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%suser_settings.bin",se_get_pref_path());
    sb_save_file_data(settings_path,(uint8_t*)&gui_state.settings,sizeof(gui_state.settings));
    se_emscripten_flush_fs();
    gui_state.last_saved_settings=gui_state.settings;
  }
}
void se_load_settings(){
  se_load_recent_games_list();
  {
    char keybind_path[SB_FILE_PATH_SIZE];
    snprintf(keybind_path,SB_FILE_PATH_SIZE,"%skeyboard-bindings.bin",se_get_pref_path());
    if(!sb_load_file_data_into_buffer(keybind_path,(uint8_t*)gui_state.key.bound_id,sizeof(gui_state.key.bound_id))){
      se_set_default_keybind(&gui_state);
    }
  }
  se_load_controller_settings(&gui_state.controller);
  {
    char settings_path[SB_FILE_PATH_SIZE];
    snprintf(settings_path,SB_FILE_PATH_SIZE,"%suser_settings.bin",se_get_pref_path());
    if(!sb_load_file_data_into_buffer(settings_path,(void*)&gui_state.settings,sizeof(gui_state.settings))){
      gui_state.settings.volume=0.8;
      gui_state.settings.draw_debug_menu = false; 
    }
    gui_state.last_saved_settings=gui_state.settings;
  }
}
static void init(void) {
  if(SDL_Init(SDL_INIT_GAMECONTROLLER)){
    printf("Failed to init SDL: %s\n",SDL_GetError());
  }
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
      .colors[0] = { .action = SG_ACTION_CLEAR, .value = { 0.0f, 0.5f, 1.0f, 1.0 } }
  };
  gui_state.last_touch_time=1e5;
  saudio_setup(&(saudio_desc){
    .sample_rate=SE_AUDIO_SAMPLE_RATE,
    .num_channels=2,
    .num_packets=4,
    .buffer_frames=1024*2,
    .packet_frames=1024
  });
  if(emu_state.cmd_line_arg_count>=2){
    se_load_rom(emu_state.cmd_line_args[1]);
  }
}
static void cleanup(void) {
  simgui_shutdown();
  se_free_all_images();
  sg_shutdown();
  saudio_shutdown();
  SDL_Quit();
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
    uint32_t size = sapp_html5_get_dropped_file_size(0);
    uint8_t * buffer = (uint8_t*)malloc(size);
    char *rom_file=(char*)malloc(4096); 
    snprintf(rom_file,4096,"/%s",sapp_get_dropped_file_path(0));

    sapp_html5_fetch_dropped_file(&(sapp_html5_fetch_request){
      .dropped_file_index = 0,
                .callback = emsc_load_callback,
                .buffer_ptr = buffer,
                .buffer_size = size,
                .user_data=rom_file});
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
    }
    gui_state.last_touch_time=0;
  }
}
sapp_desc sokol_main(int argc, char* argv[]) {
  emu_state.cmd_line_arg_count =argc;
  emu_state.cmd_line_args =argv;
  #if defined(EMSCRIPTEN)
    em_init_fs();  
  #endif
  return (sapp_desc){
      .init_cb = init,
      .frame_cb = frame,
      .cleanup_cb = cleanup,
      .event_cb = event,
      .window_title = "SkyEmu",
      .width = 1280,
      .height = 720,
      .enable_dragndrop = true,
      .enable_clipboard =true,
      .high_dpi = true,
      .max_dropped_file_path_length = 8192,
      .swap_interval=0
  };
}
