/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#define SE_AUDIO_BUFF_SAMPLES 4096
#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
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
#define STBI_ONLY_PNG
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#include "load_rom_png.h"
#ifdef USE_TINY_FILE_DIALOGS
#include "tinyfiledialogs.h"
#endif

void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha);
void se_load_rom_click_region(int x,int y, int w, int h, bool visible);
void sb_draw_onscreen_controller(sb_emu_state_t*state, int controller_h);

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


se_core_state_t core;
se_core_rewind_buffer_t rewind_buffer;

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
  static uint64_t last_t = 0;
  static double fps = 1.0/60.0; 
  if(!tick)return 1.0/fps;
  if(call==-1){
    call = 0;
    last_t = stm_now();
    fps = 1.0/60;
  }else{
    call+=tick;
    uint64_t t = stm_now();
    double delta = stm_sec(stm_diff(t,last_t));
    if(delta>0.5){
      fps=delta/call;
      last_t = t;
      call=0;
    }
    
  }
  return 1.0/fps; 
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
    int mem_view_address;
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
  igBegin(label, 0,0);
  const char* reg_names[]={"R0","R1","R2","R3","R4","R5","R6","R7","R8","R9 (SB)","R10 (SL)","R11 (FP)","R12 (IP)","R13 (SP)","R14 (LR)","R15 (PC)","CPSR","SPSR",NULL};
  int r = 0; 
  while(reg_names[r]){
    int value = arm7_reg_read(arm,r);
    if(igInputInt(reg_names[r],&value, 1,5,ImGuiInputTextFlags_CharsHexadecimal)){
      arm7_reg_write(arm,r,value);
    }
    ++r;
  }
  unsigned pc = arm7_reg_read(arm,PC);
  bool thumb = arm7_get_thumb_bit(arm);
  pc-=thumb? 4: 8;
  uint8_t buffer[64];
  int buffer_size = sizeof(buffer);
  if(thumb)buffer_size/=2;
  int off = buffer_size/2;
  if(pc<off)off=pc;
  for(int i=0;i<buffer_size;++i)buffer[i]=read(pc-off+i);
  csh handle;
  if (cs_open(CS_ARCH_ARM, thumb? CS_MODE_THUMB: CS_MODE_ARM, &handle) == CS_ERR_OK){
    cs_insn *insn;
    int count = cs_disasm(handle, buffer, buffer_size, pc-off, 0, &insn);
    size_t j;
    for (j = 0; j < count; j++) {
      char instr_str[80];
      
      if(insn[j].address==pc){
        igPushStyleColorVec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
        snprintf(instr_str,80,"PC ->0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        igText(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(0,2);
        igText(instr_str);
        igPopStyleColor(1);
      }else{
        snprintf(instr_str,80,"0x%08x:", (int)insn[j].address);
        instr_str[79]=0;
        igText(instr_str);
        snprintf(instr_str,80,"%s %s\n", insn[j].mnemonic,insn[j].op_str);
        instr_str[79]=0;
        igSameLine(0,2);
        igText(instr_str);
      }
  
    }  
  }

  igEnd();
}
void se_draw_mem_debug_state(const char* label, gui_state_t* gui, emu_byte_read_t read,emu_byte_write_t write){
  igBegin(label, 0,0);
  igInputInt("address",&gui->mem_view_address, 1,5,ImGuiInputTextFlags_CharsHexadecimal);
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
  igEnd();
}
void se_draw_io_state(const char * label, mmio_reg_t* mmios, int mmios_size, emu_byte_read_t read, emu_byte_write_t write){
  igBegin(label, 0,0);
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
  igEnd();
}
/////////////////////////////////
// BEGIN UPDATE FOR NEW SYSTEM //
/////////////////////////////////

// Used for file loading dialogs
static const char* valid_rom_file_types[] = { "*.gb", "*.gba","*.gbc" ,"*.nds"};

void se_load_rom(const char *filename){
  se_reset_rewind_buffer(&rewind_buffer);
  if(emu_state.rom_loaded){
    if(emu_state.system==SYSTEM_NDS)nds_unload(&core.nds);
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
  else emu_state.run_mode= SB_MODE_RESET;
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
  se_reset_rewind_buffer(&rewind_buffer);
  if(emu_state.system == SYSTEM_GB)sb_reset(&core.gb);
  else if(emu_state.system == SYSTEM_GBA)gba_reset(&core.gba);
  else if(emu_state.system == SYSTEM_NDS)nds_reset(&core.nds);
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
  bool draw_click_region = emu_state.run_mode!=SB_MODE_RUN&&emu_state.run_mode!=SB_MODE_REWIND;
  se_load_rom_click_region(lcd_render_x,lcd_render_y,lcd_render_w,lcd_render_h,draw_click_region);
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

static void se_draw_debug(){
  if(emu_state.system ==SYSTEM_GBA){
    se_draw_io_state("GBA MMIO", gba_io_reg_desc,sizeof(gba_io_reg_desc)/sizeof(mmio_reg_t), &gba_byte_read, &gba_byte_write); 
    se_draw_mem_debug_state("GBA MEM", &gui_state, &gba_byte_read, &gba_byte_write); 
    se_draw_arm_state("CPU",&core.gba.cpu,&gba_byte_read); 
  }else if(emu_state.system ==SYSTEM_GB){
    se_draw_io_state("GB MMIO", gb_io_reg_desc,sizeof(gb_io_reg_desc)/sizeof(mmio_reg_t), &gb_byte_read, &gb_byte_write); 
    se_draw_mem_debug_state("GB MEM", &gui_state, &gb_byte_read, &gb_byte_write); 
  }else if(emu_state.system ==SYSTEM_NDS){
    se_draw_io_state("NDS7 MMIO", nds7_io_reg_desc,sizeof(nds7_io_reg_desc)/sizeof(mmio_reg_t), &nds7_byte_read, &nds7_byte_write); 
    se_draw_io_state("NDS9 MMIO", nds9_io_reg_desc,sizeof(nds9_io_reg_desc)/sizeof(mmio_reg_t), &nds9_byte_read, &nds9_byte_write); 
    se_draw_mem_debug_state("NDS9 MEM",&gui_state, &nds9_byte_read, &nds9_byte_write); 
    se_draw_mem_debug_state("NDS7_MEM",&gui_state, &nds7_byte_read, &nds7_byte_write);
    se_draw_arm_state("ARM7",&core.nds.arm7,&nds7_byte_read); 
    se_draw_arm_state("ARM9",&core.nds.arm9,&nds9_byte_read); 
  }
}
///////////////////////////////
// END UPDATE FOR NEW SYSTEM //
///////////////////////////////

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
  joy->x = gui_state.button_state[SAPP_KEYCODE_N];
  joy->y = gui_state.button_state[SAPP_KEYCODE_M];
  joy->screen_folded = !gui_state.button_state[SAPP_KEYCODE_B];
  joy->pen_down =  gui_state.button_state[SAPP_KEYCODE_V];

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

void se_load_rom_click_region(int x,int y, int w, int h, bool visible){
  x/=se_dpi_scale();
  y/=se_dpi_scale();
  w/=se_dpi_scale();
  h/=se_dpi_scale();
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
  w*=se_dpi_scale();
  h*=se_dpi_scale();
  x*=se_dpi_scale();
  y*=se_dpi_scale();
  int x_off = (w-load_rom_im_w)*0.5;
  int y_off = (h-load_rom_im_h)*0.5;
  if(se_draw_image_button(load_rom_image,load_rom_im_w,load_rom_im_h,x+x_off,y+y_off,load_rom_im_w,load_rom_im_h,true)){
    #ifdef USE_TINY_FILE_DIALOGS
      char *outPath= tinyfd_openFileDialog("Open ROM","", sizeof(valid_rom_file_types)/sizeof(valid_rom_file_types[0]),
                                          valid_rom_file_types,NULL,0);
      if (outPath){
          se_load_rom(outPath);
      }
    #endif
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
      #if defined(EMSCRIPTEN)
        EM_ASM( FS.syncfs(function (err) {}););
      #endif
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

    if(fabs(se_time()-simulation_time)>0.5||emu_state.run_mode==SB_MODE_PAUSE&&!unlocked_mode)simulation_time = se_time()-sim_time_increment*2;
    if(unlocked_mode){
      sim_time_increment=0;
      simulation_time=se_time()+1.0/60;
      max_frames_per_tick=1000;
    }
    int samples_per_buffer = SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS;
    while(max_frames_per_tick--){
      double error = se_time()-simulation_time;
      if(unlocked_mode){
        if(simulation_time<se_time()){break;}
      }else{
        if(emu_state.frame==0&&simulation_time>se_time())break;
        if(emu_state.frame&&se_time()-simulation_time<sim_time_increment*0.8){break;}
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
    }
  }else if(emu_state.run_mode == SB_MODE_STEP) emu_state.run_mode = SB_MODE_PAUSE; 
  emu_state.avg_frame_time = 1.0/se_fps_counter(emu_state.frame);
  bool mute = emu_state.run_mode != SB_MODE_RUN;
  sb_poll_controller_input(&emu_state.joy);
  se_draw_emulated_system_screen();
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
  simgui_setup(&(simgui_desc_t){ .dpi_scale= se_dpi_scale()});

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
  if(emu_state.cmd_line_arg_count>=2){
    se_load_rom(emu_state.cmd_line_args[1]);
  }
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
    if(emu_state.run_mode!=SB_MODE_RUN&&emu_state.run_mode!=SB_MODE_REWIND){
      if(igButton("Play",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames = 1;}
      if(igButton("Step Frame",(ImVec2){0, 0}))emu_state.run_mode=SB_MODE_STEP;
    }else{
      igPushStyleVarVec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
      if(igButton("<|<|",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_REWIND;emu_state.step_frames=1;}
      if(igButton("||",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_PAUSE;emu_state.step_frames=1;}
      if(igButton("|>",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=1;}
      if(igButton("|>|>",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=2;}
      igPopStyleVar(1);
      if(igButton("|>|>|>",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames=-1;}
    }

    igPushItemWidth(100);
    igSliderFloat("",&gui_state.volume,0,1,"Volume: %.02f",ImGuiSliderFlags_AlwaysClamp);
    igPopItemWidth();
    if(emu_state.run_mode==SB_MODE_RUN) igText("%.0f FPS",se_fps_counter(0));
    menu_height= igGetWindowHeight();
    igEndMainMenuBar();
  }
  igPopStyleVar(1);

  igSetNextWindowPos((ImVec2){0,menu_height}, ImGuiCond_Always, (ImVec2){0,0});
  igSetNextWindowSize((ImVec2){width, height-menu_height*se_dpi_scale()}, ImGuiCond_Always);
  igPushStyleVarFloat(ImGuiStyleVar_WindowBorderSize, 0.0f);
  igPushStyleVarVec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
  igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration
    |ImGuiWindowFlags_NoBringToFrontOnFocus);
 
  se_update_frame();
  igPopStyleVar(2);
  igEnd();
  if(gui_state.draw_debug_menu)se_draw_debug();
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
    igGetIO()->FontDefault=font;
    igGetIO()->Fonts=atlas;
    igGetIO()->FontGlobalScale/=se_dpi_scale();
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
  emu_state.cmd_line_arg_count =argc;
  emu_state.cmd_line_args =argv;

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
