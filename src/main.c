/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#define SE_AUDIO_SAMPLE_RATE 44100
#define SE_AUDIO_BUFF_SAMPLES 4096
#define SE_AUDIO_BUFF_CHANNELS 2
#include "gba.h"

#include "gb.h"
#define SB_NUM_SAVE_STATES 5

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
#define STBI_ONLY_PNG
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "load_rom_png.h"

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


//TODO: Clean this up to use unions...
sb_emu_state_t emu_state = {.pc_breakpoint = -1};
sb_gb_t gb_state = {};
gba_t gba; 

sb_gb_t sb_save_states[SB_NUM_SAVE_STATES];
int sb_valid_save_states = 0;
unsigned sb_save_state_index=0;

double se_fps_counter(int tick){
  static int call = -1;
  static uint64_t last_t = 0;
  static double fps = 60; 
  if(call==-1){
    call = 0;
    last_t = stm_now();
  }
  call+=tick;
  
  if(call>=5){
    uint64_t t = stm_now();
    fps = ((double)call)/stm_sec(stm_diff(t,last_t));
    call=0;
    last_t = t;
  }
  return fps; 
}


void sb_pop_save_state(sb_gb_t* gb){
  if(sb_valid_save_states>0){
    --sb_valid_save_states;
    --sb_save_state_index;
    *gb = sb_save_states[sb_save_state_index%SB_NUM_SAVE_STATES];
  }
}
void sb_push_save_state(sb_gb_t* gb){
  ++sb_valid_save_states;
  if(sb_valid_save_states>SB_NUM_SAVE_STATES)sb_valid_save_states = SB_NUM_SAVE_STATES;
  ++sb_save_state_index;
  sb_save_states[sb_save_state_index%SB_NUM_SAVE_STATES] = *gb;
}

#define GUI_MAX_IMAGES_PER_FRAME 16
typedef struct {
    uint64_t laptime;
    sg_pass_action pass_action;
    sg_image image_stack[GUI_MAX_IMAGES_PER_FRAME];
    int current_image; 
    int screen_width;
    int screen_height;
    int button_state[SAPP_MAX_KEYCODES];
    float volume; 
    bool show_settings; 
    bool show_developer;
    struct{
      bool active;
      float pos[2];
    }touch_points[SAPP_MAX_TOUCHPOINTS];
    float last_touch_time;
    bool draw_debug_menu;
} gui_state_t;
gui_state_t gui_state={.volume=1.0}; 
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


bool sb_load_rom(const char* file_path, const char* save_file){
  if(!sb_path_has_file_ext(file_path,".gb") && 
     !sb_path_has_file_ext(file_path,".gbc")) return false; 
  size_t bytes = 0;
  uint8_t *data = sb_load_file_data(file_path, &bytes);
  if(bytes+1>MAX_CARTRIDGE_SIZE)bytes = MAX_CARTRIDGE_SIZE;
  printf("Loaded File: %s, %zu bytes\n", file_path, bytes);
  for (size_t i = 0; i < bytes; ++i) {
    gb_state.cart.data[i] = data[i];
  }
  for(size_t i = 0; i< 32*1024;++i)gb_state.mem.data[i] = gb_state.cart.data[i];
  // Copy Header
  for (int i = 0; i < 11; ++i) {
    gb_state.cart.title[i] = gb_state.cart.data[i + 0x134];
  }
  gb_state.cart.title[12] ='\0';
  // TODO PGB Mode(Values with Bit 7 set, and either Bit 2 or 3 set)
  gb_state.cart.game_boy_color =
      SB_BFE(gb_state.cart.data[0x143], 7, 1) == 1;
  gb_state.cart.type = gb_state.cart.data[0x147];

  switch(gb_state.cart.type){
    case 0: gb_state.cart.mbc_type = SB_MBC_NO_MBC; break;

    case 1:
    case 2:
    case 3: gb_state.cart.mbc_type = SB_MBC_MBC1; break;

    case 5:
    case 6: gb_state.cart.mbc_type = SB_MBC_MBC2; break;

    case 0x0f:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13: gb_state.cart.mbc_type = SB_MBC_MBC3; break;

    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x1C:
    case 0x1D:
    case 0x1E:gb_state.cart.mbc_type = SB_MBC_MBC5; break;

    case 0x20:gb_state.cart.mbc_type = SB_MBC_MBC6; break;
    case 0x22:gb_state.cart.mbc_type = SB_MBC_MBC7; break;

  }
  switch (gb_state.cart.data[0x148]) {
    case 0x0: gb_state.cart.rom_size = 32 * 1024;  break;
    case 0x1: gb_state.cart.rom_size = 64 * 1024;  break;
    case 0x2: gb_state.cart.rom_size = 128 * 1024; break;
    case 0x3: gb_state.cart.rom_size = 256 * 1024; break;
    case 0x4: gb_state.cart.rom_size = 512 * 1024; break;
    case 0x5: gb_state.cart.rom_size = 1024 * 1024;     break;
    case 0x6: gb_state.cart.rom_size = 2 * 1024 * 1024; break;
    case 0x7: gb_state.cart.rom_size = 4 * 1024 * 1024; break;
    case 0x8: gb_state.cart.rom_size = 8 * 1024 * 1024; break;
    case 0x52: gb_state.cart.rom_size = 1.1 * 1024 * 1024; break;
    case 0x53: gb_state.cart.rom_size = 1.2 * 1024 * 1024; break;
    case 0x54: gb_state.cart.rom_size = 1.5 * 1024 * 1024; break;
    default: gb_state.cart.rom_size = 32 * 1024; break;
  }

  switch (gb_state.cart.data[0x149]) {
    case 0x0: gb_state.cart.ram_size = 0; break;
    case 0x1: gb_state.cart.ram_size = 2*1024; break;
    case 0x2: gb_state.cart.ram_size = 8 * 1024; break;
    case 0x3: gb_state.cart.ram_size = 32 * 1024; break;
    case 0x4: gb_state.cart.ram_size = 128 * 1024; break;
    case 0x5: gb_state.cart.ram_size = 64 * 1024; break;
    default: gb_state.cart.ram_size = 0; break;
  }
  emu_state.run_mode = SB_MODE_RESET;
  emu_state.rom_loaded = true;
  sb_free_file_data(data);

  strncpy(gb_state.cart.save_file_path,save_file,SB_FILE_PATH_SIZE);
  gb_state.cart.save_file_path[SB_FILE_PATH_SIZE-1]=0;
  data = sb_load_file_data(save_file, &bytes);
  if(data){
    printf("Loaded save file: %s, bytes: %zu\n",save_file,bytes);

    if(bytes!=gb_state.cart.ram_size){
      printf("Warning save file size(%zu) doesn't match size expected(%d) for the cartridge type", bytes, gb_state.cart.ram_size);
    }
    if(bytes>gb_state.cart.ram_size){
      bytes = gb_state.cart.ram_size;
    }
    memcpy(gb_state.cart.ram_data, data, bytes);
    sb_free_file_data(data);
  }else{
    printf("Could not find save file: %s\n",save_file);
    memset(gb_state.cart.ram_data,0,MAX_CARTRIDGE_RAM);
  }
  return true; 
}

void se_load_rom(const char *filename){
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
  if(gba_load_rom(&gba, filename,save_file)){
    emu_state.system = SYSTEM_GBA;
    emu_state.rom_loaded = true;
  }
  if(sb_load_rom(filename,save_file)){
    emu_state.system = SYSTEM_GB;
    emu_state.rom_loaded = true; 
  }
  if(emu_state.rom_loaded==false)printf("Unknown ROM type: %s\n", filename);
  else emu_state.run_mode= SB_MODE_RESET;
  return; 
}
void sb_poll_controller_input(sb_joy_t* joy){
  
  joy->left  = gui_state.button_state[SAPP_KEYCODE_A];
  joy->right = gui_state.button_state[SAPP_KEYCODE_D];
  joy->up    = gui_state.button_state[SAPP_KEYCODE_W];
  joy->down  = gui_state.button_state[SAPP_KEYCODE_S];
  joy->a = gui_state.button_state[SAPP_KEYCODE_J];
  joy->b = gui_state.button_state[SAPP_KEYCODE_K];
  joy->start = gui_state.button_state[SAPP_KEYCODE_ENTER];
  joy->select = gui_state.button_state[SAPP_KEYCODE_APOSTROPHE];
  joy->l = gui_state.button_state[SAPP_KEYCODE_U];
  joy->r = gui_state.button_state[SAPP_KEYCODE_I];
}
void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
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
  float dpi_scale = sapp_dpi_scale();
  ImDrawList_AddImage(igGetWindowDrawList(),
    (ImTextureID)(uintptr_t)image->id,
    (ImVec2){x/dpi_scale,y/dpi_scale},
    (ImVec2){(x+render_width)/dpi_scale,(y+render_height)/dpi_scale},
    (ImVec2){0,0},(ImVec2){1,1},
    0xffffffff);
  if(has_alpha==false)free(rgba8_data);
}

float sb_distance(float * a, float* b, int dims){
  float v = 0;
  for(int i=0;i<dims;++i)v+=(a[i]-b[i])*(a[i]-b[i]);
  return sqrtf(v);
}
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h){
  if(state->run_mode!=SB_MODE_RUN)return;
  controller_h/=sapp_dpi_scale();
  float win_w = igGetWindowWidth()/sapp_dpi_scale();
  float win_h = igGetWindowHeight()/sapp_dpi_scale();
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
      points[p][0]=gui_state.touch_points[i].pos[0]/sapp_dpi_scale();
      points[p][1]=gui_state.touch_points[i].pos[1]/sapp_dpi_scale();
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
   
    /*for(int i = 0;i<p;++i){
      int dx = points[i].x-bounds.x;
      int dy = points[i].y-bounds.y;
      if(dx>=-bounds.width*0.05 && dx<=bounds.width*1.05 && dy>=0 && dy<=bounds.height ){
        button_press|=1<<b; 
        state =1;
      }
    }
    */
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
   
    /*for(int i = 0;i<p;++i){
      int dx = points[i].x-bounds.x;
      int dy = points[i].y-bounds.y;
      if(dx>=-bounds.width*0.05 && dx<=bounds.width*1.05 && dy>=0 && dy<=bounds.height ){
        button_press|=1<<b; 
        state =1;
      }
    }
    */
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

void se_load_rom_click_region(int x,int y, int w, int h, bool visible){
  x/=sapp_dpi_scale();
  y/=sapp_dpi_scale();
  w/=sapp_dpi_scale();
  h/=sapp_dpi_scale();
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

  static bool loaded = false;
  static uint8_t * load_rom_image;
  static int load_rom_im_w, load_rom_im_h;
  if(!loaded){
    loaded=true;
    int c;
    load_rom_image = stbi_load_from_memory(load_rom_png,load_rom_png_len,&load_rom_im_w,&load_rom_im_h,&c, 4);
  }
 
 #if defined(EMSCRIPTEN)
 
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
  //printf("Open: %s\n",file_name);
  //free(file_name);
#endif
  w*=sapp_dpi_scale();
  h*=sapp_dpi_scale();
  x*=sapp_dpi_scale();
  y*=sapp_dpi_scale();
  int x_off = (w-load_rom_im_w)*0.5;
  int y_off = (h-load_rom_im_h)*0.5;
  se_draw_image(load_rom_image,load_rom_im_w,load_rom_im_h,x+x_off,y+y_off,load_rom_im_w,load_rom_im_h,true);


}


void se_update_frame() {
  static unsigned frames_since_last_save = 0; 
  frames_since_last_save++;
  if(emu_state.system== SYSTEM_GB){
    if(gb_state.cart.ram_is_dirty && frames_since_last_save>10){
      frames_since_last_save = 0; 
      if(sb_save_file_data(gb_state.cart.save_file_path,gb_state.cart.ram_data,gb_state.cart.ram_size)){
   #if defined(EMSCRIPTEN)
        // Don't forget to sync to make sure you store it to IndexedDB
      EM_ASM( FS.syncfs(function (err) {}); );
   #endif
        printf("Saved %s\n", gb_state.cart.save_file_path);
      }else printf("Failed to write out save file: %s\n",gb_state.cart.save_file_path);
      gb_state.cart.ram_is_dirty=false;
    }
  }else if(emu_state.system ==SYSTEM_GBA){
    if(gba.cart.backup_is_dirty && frames_since_last_save>10){
      frames_since_last_save = 0; 
      int size = 0; 
      switch(gba.cart.backup_type){
        case GBA_BACKUP_NONE       : size = 0;       break;
        case GBA_BACKUP_EEPROM     : size = 8*1024;  break;
        case GBA_BACKUP_EEPROM_512B: size = 512;     break;
        case GBA_BACKUP_EEPROM_8KB : size = 8*1024;  break;
        case GBA_BACKUP_SRAM       : size = 32*1024; break;
        case GBA_BACKUP_FLASH_64K  : size = 64*1024; break;
        case GBA_BACKUP_FLASH_128K : size = 128*1024;break;
      }
      if(size){
        if(sb_save_file_data(gba.cart.save_file_path,gba.mem.cart_backup,size)){
          #if defined(EMSCRIPTEN)
              EM_ASM( FS.syncfs(function (err) {}););
          #endif
          printf("Saved %s\n", gba.cart.save_file_path);
        }else printf("Failed to write out save file: %s\n",gba.cart.save_file_path);
      }
      gba.cart.backup_is_dirty=false;
    }
  }
  emu_state.frame=0;
  if(emu_state.system == SYSTEM_GB)sb_tick(&emu_state,&gb_state);
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &gba);
 
  emu_state.avg_frame_time = 1.0/se_fps_counter(emu_state.frame);
  bool mute = emu_state.run_mode != SB_MODE_RUN;

  sb_poll_controller_input(&emu_state.joy);
  int lcd_render_x = 0, lcd_render_y = 0; 
  int lcd_render_w = 0, lcd_render_h = 0; 


  float lcd_aspect = SB_LCD_H/(float)SB_LCD_W;
  if(emu_state.system==SYSTEM_GBA){
    lcd_aspect= GBA_LCD_H/(float)GBA_LCD_W;
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
  lcd_render_x+=v.x*sapp_dpi_scale();
  lcd_render_y+=v.y*sapp_dpi_scale();
  if(emu_state.system==SYSTEM_GBA){
    se_draw_image(gba.framebuffer,GBA_LCD_W,GBA_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }else{
    se_draw_image(gb_state.lcd.framebuffer,SB_LCD_W,SB_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }
  se_load_rom_click_region(lcd_render_x,lcd_render_y,lcd_render_w,lcd_render_h,emu_state.run_mode!=SB_MODE_RUN);
  sb_draw_onscreen_controller(&emu_state, controller_h);

}

void gba_draw_io_state(gba_t* gba){
  igBegin("MMIO", 0,0);
  for(int i = 0; i<sizeof(gba_io_reg_desc)/sizeof(gba_io_reg_desc[0]);++i){
    uint32_t addr = gba_io_reg_desc[i].addr;
    uint16_t data = gba_read16(gba, addr);
    bool has_fields = false;
    igPushIDInt(i);
    if (igTreeNodeStrStr("%s(%08x): %04x",gba_io_reg_desc[i].name,addr,data)){
      for(int f = 0; f<sizeof(gba_io_reg_desc[i].bits)/sizeof(gba_io_reg_desc[i].bits[0]);++f){
        igPushIDInt(f);
        uint32_t start = gba_io_reg_desc[i].bits[f].start; 
        uint32_t size = gba_io_reg_desc[i].bits[f].size; 
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
            gba_store16(gba,addr,data);
          }
          igSameLine(0,2);
          if(size>1)igText("%s (Bits [%d:%d])",gba_io_reg_desc[i].bits[f].name,start, start+size-1);
          else igText("%s (Bit %d)",gba_io_reg_desc[i].bits[f].name,start);
        }
        igPopID();
      }
      if(!has_fields){
        int v = data; 
        igPushIDInt(0);
        igPushItemWidth(150);
        if(igInputInt("",&v, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
          gba_store16(gba,addr,v);
        }
        igSameLine(0,2);
        igText("Data");
        igPopID();
      }
      igTreePop();
    }
    igPopID();

    /*
    for(int f = 0; f<sizeof(gba_io_reg_desc[i].bits)/sizeof(gba_io_reg_desc[i].bits[0]);++f){
      uint32_t start = gba_io_reg_desc[i].bits[f].start; 
      uint32_t size = gba_io_reg_desc[i].bits[f].size; 
      if(size){
        uint32_t field_data = SB_BFE(data,start,size);
        has_fields=true;
        Rectangle r2 = r; 
        if(size>1)r=sb_draw_label(r, TextFormat("[%d:%d]:", start, start+size-1));
        else r=sb_draw_label(r, TextFormat("%d:", start));

        r2.x+=30; 
        sb_draw_label(r2, TextFormat("%2d",field_data));
        r2.x+=25; 
        sb_draw_label(r2, TextFormat("%s",gba_io_reg_desc[i].bits[f].name));
      }
    }
    Rectangle state_rect, adv_rect;
    GuiGroupBox(state_rect, TextFormat("%s(%08x): %04x", gba_io_reg_desc[i].name, addr,data)); 
    rect=adv_rect;*/
  }
  igEnd();
}

static void init(void) {

  #if defined(EMSCRIPTEN)
   //Setup the offline file system
    EM_ASM(
        // Make a directory other than '/'
        FS.mkdir('/offline');
        // Then mount with IDBFS type
        FS.mount(IDBFS, {}, '/offline');
        // Then sync
        FS.syncfs(true, function (err) {});
    );
  #endif
  sg_setup(&(sg_desc){
      .context = sapp_sgcontext()
  });
  stm_setup();
  simgui_setup(&(simgui_desc_t){ .dpi_scale= sapp_dpi_scale()});

  // initial clear color
  gui_state.pass_action = (sg_pass_action) {
      .colors[0] = { .action = SG_ACTION_CLEAR, .value = { 0.0f, 0.5f, 1.0f, 1.0 } }
  };
  gui_state.last_touch_time=1e5;
  saudio_setup(&(saudio_desc){
    .sample_rate=SE_AUDIO_SAMPLE_RATE,
    .num_channels=2,
    .num_packets=16,
    .packet_frames=512
  });
}

static void frame(void) {
  
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
  if (igBeginMainMenuBar())
  {
    igText("SkyEmu", (ImVec2){0, 0});
    
    if(igButton("Reset",(ImVec2){0, 0})){emu_state.run_mode = SB_MODE_RESET;}
    if(emu_state.run_mode!=SB_MODE_RUN){
      if(igButton("Play",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames = 1;}
      if(igButton("Step Frame",(ImVec2){0, 0}))emu_state.run_mode=SB_MODE_STEP;
    }else{
      igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
      if(igButton("Pause",(ImVec2){0, 0}))emu_state.run_mode=SB_MODE_PAUSE;
      if(igButton("1x",(ImVec2){0, 0}))emu_state.step_frames=1; 
      if(igButton("2x",(ImVec2){0, 0}))emu_state.step_frames=2;
      igPopStyleVar(1);
      if(igButton("10x",(ImVec2){0, 0}))emu_state.step_frames=10;
    }
    //igCheckbox("Show Settings",&gui_state.show_settings);
    //igCheckbox("Show Developer",&gui_state.show_developer);
    igPushItemWidth(100);
    igSliderFloat("",&gui_state.volume,0,1,"Volume: %.02f",ImGuiSliderFlags_AlwaysClamp);
    igPopItemWidth();
    if(emu_state.run_mode==SB_MODE_RUN) igText("%.01fFPS",se_fps_counter(0));
    menu_height= igGetWindowHeight();
    igEndMainMenuBar();
  }
  igPopStyleVar(1);

  igSetNextWindowPos((ImVec2){0,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){width, height-menu_height*sapp_dpi_scale()}, ImGuiCond_Always);
  igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0.0f);
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
  igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration
    |ImGuiWindowFlags_NoBringToFrontOnFocus);
 
  se_update_frame();
  igPopStyleVar(2);
  igEnd();
  if(gui_state.draw_debug_menu)gba_draw_io_state(&gba); 

  /*=== UI CODE ENDS HERE ===*/

  sg_begin_default_pass(&gui_state.pass_action, width, height);
  simgui_render();
  sg_end_pass();
  static bool init=false;
  if(!init){
    init=true;
    ImFontAtlas* atlas = igGetIO()->Fonts;    
    ImFont* font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
      atlas,karla_compressed_data,karla_compressed_size,13*sapp_dpi_scale(),NULL,NULL);
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
    printf("Font: %p %d\n",igGetIO()->FontDefault,built);
    igGetIO()->FontDefault=font;
    igGetIO()->Fonts=atlas;
    igGetIO()->FontGlobalScale/=sapp_dpi_scale();
  }
  sg_commit();

  int num_samples_to_push = saudio_expect()*2;
  enum{samples_to_push=128};
  float volume_sq = gui_state.volume*gui_state.volume/32768.;
  for(int s = 0; s<num_samples_to_push;s+=samples_to_push){
    float audio_buff[samples_to_push];
    int pushed = 0; 
    if(sb_ring_buffer_size(&emu_state.audio_ring_buff)<=samples_to_push)break;
    for(int i=0;i<samples_to_push;++i){
      int16_t data = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE];
      audio_buff[i]=data*volume_sq;
    }
    saudio_push(audio_buff, samples_to_push/2);
  }
  se_free_all_images();
}

static void cleanup(void) {
  simgui_shutdown();
  se_free_all_images();
  sg_shutdown();
  saudio_shutdown();
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
    if(ev->key_code ==SAPP_KEYCODE_F1)gui_state.draw_debug_menu=!gui_state.draw_debug_menu;
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
  (void)argc;
  (void)argv;
  return (sapp_desc){
      .init_cb = init,
      .frame_cb = frame,
      .cleanup_cb = cleanup,
      .event_cb = event,
      .window_title = "SkyEmu",
      .width = 800,
      .height = 600,
      .enable_dragndrop = true,
      .enable_clipboard =true,
      .high_dpi = true,
      .max_dropped_file_path_length = 8192,
  };
}
