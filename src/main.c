/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#define SE_AUDIO_BUFF_SAMPLES 2048
#define SE_AUDIO_SAMPLE_RATE 48000
#define SE_AUDIO_BUFF_CHANNELS 2
#include "gba.h"
#include "nds.h"
#include "gb.h"
#include "capstone/include/capstone/capstone.h"

#if defined(EMSCRIPTEN)
#include <emscripten.h>
#endif

#include <SDL.h>
#include <SDL_scancode.h>
#if defined(IMGUI_IMPL_OPENGL_ES2)
  #include <SDL_opengles2.h>
#else
  #include <SDL_opengl.h>
#endif

#define CIMGUI_DEFINE_ENUMS_AND_STRUCTS
#include "cimgui.h"
#include "cimgui_sdl_ogl3_backend.h"

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

//TODO: Clean this up to use unions...
sb_emu_state_t emu_state = {.pc_breakpoint = -1};
sb_gb_t gb_state = { 0 };
gba_t gba = { 0 };  
nds_t nds = { 0 };

double se_time(){
  return (double)(SDL_GetPerformanceCounter())/(double)SDL_GetPerformanceFrequency();
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

#define GUI_MAX_IMAGES_PER_FRAME 16
#define SE_MAX_KEYCODES 256
#define SE_MAX_TOUCHPOINTS 10
typedef struct {
    uint64_t laptime;
    GLuint image_stack[GUI_MAX_IMAGES_PER_FRAME];
    int current_image; 
    int screen_width;
    int screen_height;
    float volume; 
    bool show_settings; 
    bool show_developer;
    struct{
      bool active;
      float pos[2];
    }touch_points[SE_MAX_TOUCHPOINTS];
    double last_touch_time;
    bool draw_debug_menu;
    int mem_view_address;
    double dpi_scale;
    bool init_fonts;
} gui_state_t;
gui_state_t gui_state={.volume=1.0}; 
static float se_dpi_scale(){ return gui_state.dpi_scale;}

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
        igPushStyleColor_Vec4(ImGuiCol_Text, (ImVec4){1.f, 0.f, 0.f, 1.f});
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
    igPushID_Int(i);
    char lab[80];
    snprintf(lab,80,"0x%08x: %s",addr,mmios[i].name);
    if (igTreeNode_Str(lab)){
      for(int f = 0; f<sizeof(mmios[i].bits)/sizeof(mmios[i].bits[0]);++f){
        igPushID_Int(f);
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
        igPushID_Int(0);
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
  if(emu_state.rom_loaded){
    if(emu_state.system==SYSTEM_NDS)nds_unload(&nds);
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
  if(gba_load_rom(&gba, filename,save_file)){
    emu_state.system = SYSTEM_GBA;
    emu_state.rom_loaded = true;
  }else if(sb_load_rom(&gb_state, &emu_state,filename,save_file)){
    emu_state.system = SYSTEM_GB;
    emu_state.rom_loaded = true; 
  }else if(nds_load_rom(&nds,filename,save_file)){
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
    if(gb_state.cart.ram_is_dirty){
      saved=true;
      if(sb_save_file_data(gb_state.cart.save_file_path,gb_state.cart.ram_data,gb_state.cart.ram_size)){
      }else printf("Failed to write out save file: %s\n",gb_state.cart.save_file_path);
      gb_state.cart.ram_is_dirty=false;
    }
  }else if(emu_state.system ==SYSTEM_GBA){
    if(gba.cart.backup_is_dirty){
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
        saved =true;
        if(sb_save_file_data(gba.cart.save_file_path,gba.mem.cart_backup,size)){
        }else printf("Failed to write out save file: %s\n",gba.cart.save_file_path);
      }
      gba.cart.backup_is_dirty=false;
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
  if(emu_state.system == SYSTEM_GB)sb_tick(&emu_state,&gb_state);
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &gba);
  else if(emu_state.system == SYSTEM_NDS)nds_tick(&emu_state, &nds);
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
    se_draw_image(gba.framebuffer,GBA_LCD_W,GBA_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }else if (emu_state.system==SYSTEM_NDS){
    se_draw_image(nds.framebuffer_top,NDS_LCD_W,NDS_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h*0.5,false);
    se_draw_image(nds.framebuffer_bottom,NDS_LCD_W,NDS_LCD_H,lcd_render_x,lcd_render_y+lcd_render_h*0.5, lcd_render_w, lcd_render_h*0.5,false);
  }else{
    se_draw_image(gb_state.lcd.framebuffer,SB_LCD_W,SB_LCD_H,lcd_render_x,lcd_render_y, lcd_render_w, lcd_render_h,false);
  }
  se_load_rom_click_region(lcd_render_x,lcd_render_y,lcd_render_w,lcd_render_h,emu_state.run_mode!=SB_MODE_RUN);
  sb_draw_onscreen_controller(&emu_state, controller_h);
}
static uint8_t gba_byte_read(uint64_t address){return gba_read8(&gba,address);}
static void gba_byte_write(uint64_t address, uint8_t data){gba_store8(&gba,address,data);}
static uint8_t gb_byte_read(uint64_t address){return sb_read8(&gb_state,address);}
static void gb_byte_write(uint64_t address, uint8_t data){sb_store8(&gb_state,address,data);}

static uint8_t nds9_byte_read(uint64_t address){return nds9_read8(&nds,address);}
static void nds9_byte_write(uint64_t address, uint8_t data){nds9_write8(&nds,address,data);}
static uint8_t nds7_byte_read(uint64_t address){return nds7_read8(&nds,address);}
static void nds7_byte_write(uint64_t address, uint8_t data){nds7_write8(&nds,address,data);}

static void se_draw_debug(){
  if(emu_state.system ==SYSTEM_GBA){
    se_draw_io_state("GBA MMIO", gba_io_reg_desc,sizeof(gba_io_reg_desc)/sizeof(mmio_reg_t), &gba_byte_read, &gba_byte_write); 
    se_draw_mem_debug_state("GBA MEM", &gui_state, &gba_byte_read, &gba_byte_write); 
    se_draw_arm_state("CPU",&gba.cpu,&gba_byte_read); 
  }else if(emu_state.system ==SYSTEM_GB){
    se_draw_io_state("GB MMIO", gb_io_reg_desc,sizeof(gb_io_reg_desc)/sizeof(mmio_reg_t), &gb_byte_read, &gb_byte_write); 
    se_draw_mem_debug_state("GB MEM", &gui_state, &gb_byte_read, &gb_byte_write); 
  }else if(emu_state.system ==SYSTEM_NDS){
    se_draw_io_state("NDS7 MMIO", nds7_io_reg_desc,sizeof(nds7_io_reg_desc)/sizeof(mmio_reg_t), &nds7_byte_read, &nds7_byte_write); 
    se_draw_io_state("NDS9 MMIO", nds9_io_reg_desc,sizeof(nds9_io_reg_desc)/sizeof(mmio_reg_t), &nds9_byte_read, &nds9_byte_write); 
    se_draw_mem_debug_state("NDS9 MEM",&gui_state, &nds9_byte_read, &nds9_byte_write); 
    se_draw_mem_debug_state("NDS7_MEM",&gui_state, &nds7_byte_read, &nds7_byte_write);
    se_draw_arm_state("ARM7",&nds.arm7,&nds7_byte_read); 
    se_draw_arm_state("ARM9",&nds.arm9,&nds9_byte_read); 
  }
}
///////////////////////////////
// END UPDATE FOR NEW SYSTEM //
///////////////////////////////

void sb_poll_controller_input(sb_joy_t* joy){
  /*
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
  */

}
static GLuint se_get_image(){
  if(gui_state.current_image<GUI_MAX_IMAGES_PER_FRAME){
    gui_state.current_image++;
  }
  GLuint tex =  gui_state.image_stack[gui_state.current_image]; 
  if(tex==0){
    glGenTextures(1,&gui_state.image_stack[gui_state.current_image]);
    tex = gui_state.image_stack[gui_state.current_image];
  }
  return tex;
}
static void se_free_all_images(){
  for(int i=0;i<gui_state.current_image;++i){
    if(gui_state.image_stack[i]){
      glDeleteTextures(1,&gui_state.image_stack[i]);
      gui_state.image_stack[i]=0; 
    }
  }
  gui_state.current_image=0;
}

void se_draw_image_opacity(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha,float opacity){
  GLuint image = se_get_image();
  if(!image)return; 
  glBindTexture(GL_TEXTURE_2D,image); 
  glTexImage2D(GL_TEXTURE_2D,0, has_alpha? GL_RGBA : GL_RGB, im_width,im_height,0,has_alpha? GL_RGBA: GL_RGB,GL_UNSIGNED_BYTE,data);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);;
  float dpi_scale = se_dpi_scale();
  unsigned tint = opacity*0xff;
  tint*=0x010101;
  tint|=0xff000000;
  ImDrawList_AddImage(igGetWindowDrawList(),
    (ImTextureID)image,
    (ImVec2){x/dpi_scale,y/dpi_scale},
    (ImVec2){(x+render_width)/dpi_scale,(y+render_height)/dpi_scale},
    (ImVec2){0,0},(ImVec2){1,1},
    tint);
}
void se_draw_image(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
  return se_draw_image_opacity(data,im_width,im_height,x,y,render_width,render_height,has_alpha,1.0);
}
bool se_draw_image_button(uint8_t *data, int im_width, int im_height,int x, int y, int render_width, int render_height, bool has_alpha){
  float dpi_scale = se_dpi_scale();
  igPushStyleColor_Vec4(ImGuiCol_Button, (ImVec4){0.f, 0.f, 0.f, 0.f});
  igPushStyleColor_Vec4(ImGuiCol_ButtonActive, (ImVec4){0.f, 0.f, 0.f, 0.0f});
  igPushStyleColor_Vec4(ImGuiCol_ButtonHovered, (ImVec4){0.f, 0.f, 0.f, 0.0f});
  igSetCursorScreenPos((ImVec2){x/dpi_scale,y/dpi_scale});
  bool clicked = igButtonEx("##",
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
  double delta = se_time()-gui_state.last_touch_time;
  float opacity = 5.-delta;
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

  for(int i=0; i<SE_MAX_TOUCHPOINTS;++i){
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
  
  if(down) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]+dpad_sz1},sel_color,0,ImDrawFlags_RoundCornersNone);
  if(up)   ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]-dpad_sz1},(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},sel_color,0,ImDrawFlags_RoundCornersNone);

  if(left) ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]-dpad_sz1,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]-dpad_sz0,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawFlags_RoundCornersNone);
  if(right)ImDrawList_AddRectFilled(dl,(ImVec2){dpad_pos[0]+dpad_sz0,dpad_pos[1]-dpad_sz0},(ImVec2){dpad_pos[0]+dpad_sz1,dpad_pos[1]+dpad_sz0},sel_color,0,ImDrawFlags_RoundCornersNone);

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
        ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawFlags_RoundCornersNone);  
      }
    }
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawFlags_RoundCornersNone,line_w1);  
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color,0,ImDrawFlags_RoundCornersNone,line_w0);  
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
        ImDrawList_AddRectFilled(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},sel_color,0,ImDrawFlags_RoundCornersNone);  
      }
    }
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color2,0,ImDrawFlags_RoundCornersNone,line_w1);  
    ImDrawList_AddRect(dl,(ImVec2){x_min,button_y},(ImVec2){x_max,button_y+button_h},line_color,0,ImDrawFlags_RoundCornersNone,line_w0); 
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
  emu_state.frame=0;
  int max_frames_per_tick =2+ emu_state.step_frames;

  emu_state.render_frame = true;

  static double simulation_time = -1;
  static double display_time = 0;
  if(emu_state.step_frames==0)emu_state.step_frames=1;

  double sim_fps= se_get_sim_fps();
  double sim_time_increment = 1./sim_fps/emu_state.step_frames;
  bool unlocked_mode = emu_state.step_frames<0;

  if(unlocked_mode){
    sim_time_increment=0;
    max_frames_per_tick=1000;
    simulation_time = se_time()+1.0/60;
  }else if(fabs(se_time()-simulation_time)>0.5||emu_state.run_mode!=SB_MODE_RUN)simulation_time = se_time()-sim_time_increment*2;
  int samples_per_buffer = SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS;
  while(max_frames_per_tick--){
    double error = se_time()-simulation_time;
    if(unlocked_mode){
      if(simulation_time<se_time()){break;}
    }else{
      if(emu_state.frame==0&&simulation_time>se_time())break;
      if(emu_state.frame&&se_time()-simulation_time<sim_time_increment*0.8){break;}
    }
    se_emulate_single_frame();
    emu_state.frame++;
    simulation_time+=sim_time_increment;
    emu_state.render_frame = false;
  }
  emu_state.avg_frame_time = 1.0/se_fps_counter(1);
  bool mute = emu_state.run_mode != SB_MODE_RUN;

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
  gui_state.last_touch_time=0;
  if(emu_state.cmd_line_arg_count>=2){
    se_load_rom(emu_state.cmd_line_args[1]);
  }
}

static void se_init_karla(){
  ImFontAtlas* atlas = igGetIO()->Fonts;    
  ImFont* font =ImFontAtlas_AddFontFromMemoryCompressedTTF(
    atlas,karla_compressed_data,karla_compressed_size,13*se_dpi_scale(),NULL,NULL);
  int built = 0;
  unsigned char* font_pixels;
  int font_width, font_height;
  int bytes_per_pixel;
  ImFontAtlas_GetTexDataAsRGBA32(atlas, &font_pixels, &font_width, &font_height, &bytes_per_pixel);
  GLuint tex;
  glGenTextures(1,&tex);
  glBindTexture(GL_TEXTURE_2D,tex); 
  glTexImage2D(GL_TEXTURE_2D,0, GL_RGBA, font_width,font_height,0,GL_RGBA,GL_UNSIGNED_BYTE,font_pixels);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);

  atlas->TexID = (ImTextureID)(uintptr_t) tex;
  igGetIO()->FontDefault=font;
  igGetIO()->Fonts=atlas;
  igGetIO()->FontGlobalScale/=se_dpi_scale();
}
static void frame(void) {
  int height = gui_state.screen_height;
  int width = gui_state.screen_width;
  float menu_height = 0; 
  /*=== UI CODE STARTS HERE ===*/
  igPushStyleVar_Vec2(ImGuiStyleVar_FramePadding,(ImVec2){5,5});
  if (igBeginMainMenuBar())
  {
    igText("SkyEmu", (ImVec2){0, 0});
    
    if(igButton("Reset",(ImVec2){0, 0})){emu_state.run_mode = SB_MODE_RESET;}
    if(emu_state.run_mode!=SB_MODE_RUN){
      if(igButton("Play",(ImVec2){0, 0})){emu_state.run_mode=SB_MODE_RUN;emu_state.step_frames = 1;}
      if(igButton("Step Frame",(ImVec2){0, 0}))emu_state.run_mode=SB_MODE_STEP;
    }else{
      igPushStyleVar_Vec2(ImGuiStyleVar_ItemSpacing,(ImVec2){1,1});
      if(igButton("||",(ImVec2){0, 0}))emu_state.run_mode=SB_MODE_PAUSE;
      if(igButton("|>",(ImVec2){0, 0}))emu_state.step_frames=1; 
      if(igButton("|>|>",(ImVec2){0, 0}))emu_state.step_frames=2;
      igPopStyleVar(1);
      if(igButton("|>|>|>",(ImVec2){0, 0}))emu_state.step_frames=-1;
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
  igPushStyleVar_Float(ImGuiStyleVar_WindowBorderSize, 0.0f);
  igPushStyleVar_Vec2(ImGuiStyleVar_WindowPadding,(ImVec2){0});
  igBegin("Screen", 0,ImGuiWindowFlags_NoDecoration|ImGuiWindowFlags_NoBringToFrontOnFocus);
  se_update_frame();
  igPopStyleVar(2);
  igEnd();
  if(gui_state.draw_debug_menu)se_draw_debug();
}
void sdl2_audio_callback(void *unused, uint8_t *str, int len) {
  int16_t* stream = (int16_t*)str;
  int num_samples_to_push = len/(2);
  float volume_sq = gui_state.volume*gui_state.volume;
  for(int s = 0; s<num_samples_to_push;s+=1){
    float value =0; 
    if(sb_ring_buffer_size(&emu_state.audio_ring_buff)>=0){
      int16_t data = emu_state.audio_ring_buff.data[(emu_state.audio_ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE];
      value=data*volume_sq;
    }
    *(stream++)=value;
  }
}
static void cleanup(void) {
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
static void se_update_joypad(int scancode, bool pressed){
  sb_joy_t*joy = &emu_state.joy;
  if(scancode==SDL_SCANCODE_A)joy->left  = pressed;
  if(scancode==SDL_SCANCODE_D)joy->right = pressed;
  if(scancode==SDL_SCANCODE_W)joy->up    = pressed;
  if(scancode==SDL_SCANCODE_S)joy->down  = pressed;
  if(scancode==SDL_SCANCODE_J)joy->a = pressed;
  if(scancode==SDL_SCANCODE_K)joy->b = pressed;
  if(scancode==SDL_SCANCODE_RETURN)joy->start = pressed;
  if(scancode==SDL_SCANCODE_APOSTROPHE)joy->select = pressed;
  if(scancode==SDL_SCANCODE_U)joy->l = pressed;
  if(scancode==SDL_SCANCODE_I)joy->r = pressed;
  if(scancode==SDL_SCANCODE_N)joy->x = pressed;
  if(scancode==SDL_SCANCODE_M)joy->y = pressed;
  if(scancode==SDL_SCANCODE_B)joy->screen_folded = !pressed;
  if(scancode==SDL_SCANCODE_V)joy->pen_down =  pressed;
}
static void se_process_event(const SDL_Event*ev) {
  igImplSDL2_ProcessEvent(ev);
  if(ev->type==SDL_DROPFILE)se_load_rom(ev->drop.file);
  else if (ev->type == SDL_KEYDOWN) {
    int scancode = ev->key.keysym.scancode; 
    se_update_joypad(scancode,true);
    if(scancode ==SDL_SCANCODE_F1)gui_state.draw_debug_menu=!gui_state.draw_debug_menu;

  }
  else if (ev->type == SDL_KEYUP) {
    int scancode = ev->key.keysym.scancode; 
    se_update_joypad(scancode,false);
  }
  /*else if(ev->type==SAPP_EVENTTYPE_TOUCHES_BEGAN||
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
    gui_state.last_touch_time=se_time();
  }*/
}
// Main code
int main(int argc , char*argv[])
{
  // Setup SDL
  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_GAMECONTROLLER|SDL_INIT_AUDIO) != 0)
  {
    printf("Error: %s\n", SDL_GetError());
    return -1;
  }

  // Decide GL+GLSL versions
#if defined(IMGUI_IMPL_OPENGL_ES2)
  // GL ES 2.0 + GLSL 100
  const char* glsl_version = "#version 100";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_ES);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 2);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#elif defined(__APPLE__)
  // GL 3.2 Core + GLSL 150
  const char* glsl_version = "#version 150";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG); // Always required on Mac
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 2);
#else
  // GL 3.0 + GLSL 130
  const char* glsl_version = "#version 130";
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_FLAGS, 0);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_PROFILE_MASK, SDL_GL_CONTEXT_PROFILE_CORE);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MAJOR_VERSION, 3);
  SDL_GL_SetAttribute(SDL_GL_CONTEXT_MINOR_VERSION, 0);
#endif

  // Create window with graphics context
  SDL_GL_SetAttribute(SDL_GL_DOUBLEBUFFER, 1);
  SDL_GL_SetAttribute(SDL_GL_DEPTH_SIZE, 0);
  SDL_GL_SetAttribute(SDL_GL_STENCIL_SIZE, 0);
  SDL_WindowFlags window_flags = (SDL_WindowFlags)(SDL_WINDOW_OPENGL | SDL_WINDOW_RESIZABLE | SDL_WINDOW_ALLOW_HIGHDPI);
  SDL_Window* window = SDL_CreateWindow("SkyEmu", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 1280, 720, window_flags);
  SDL_GLContext gl_context = SDL_GL_CreateContext(window);
  SDL_GL_MakeCurrent(window, gl_context);
  SDL_GL_SetSwapInterval(0); // Enable vsync

  // Setup Dear ImGui context
  igCreateContext(NULL);
  ImGuiIO* io = igGetIO();
  io->ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;       // Enable Keyboard Controls
  io->ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
  io->ConfigFlags |= ImGuiConfigFlags_DockingEnable;           // Enable Docking
  io->ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;         // Enable Multi-Viewport / Platform Windows
  //io->ConfigViewportsNoAutoMerge = true;
  //io.ConfigViewportsNoTaskBarIcon = true;

  igStyleColorsDark(NULL);

  // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
  ImGuiStyle* style = igGetStyle();
  if (io->ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
  {
    style->WindowRounding = 0.0f;
    style->Colors[ImGuiCol_WindowBg].w = 1.0f;
  }

  // Setup Platform/Renderer backends
  igImplSDL2_InitForOpenGL(window, gl_context);
  igImplOpenGL3_Init(glsl_version);

  SDL_AudioSpec as;
  as.freq = SE_AUDIO_SAMPLE_RATE;
  as.format = AUDIO_S16;
  as.samples = SE_AUDIO_BUFF_SAMPLES;
  as.callback=sdl2_audio_callback;
  as.channels = SE_AUDIO_BUFF_CHANNELS;
  SDL_AudioSpec as_got;

  SDL_AudioDeviceID audio_dev = SDL_OpenAudioDevice(NULL,false, &as,&as_got,0);
  SDL_PauseAudioDevice(audio_dev,0);
  // Main loop
  bool done = false;
  while (!done){
    // Poll and handle events (inputs, window resize, etc.)
    // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
    // - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
    // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
    // Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
    SDL_Event event;
    while (SDL_PollEvent(&event)){
      if (event.type == SDL_QUIT)
          done = true;
      if (event.type == SDL_WINDOWEVENT && event.window.event == SDL_WINDOWEVENT_CLOSE && event.window.windowID == SDL_GetWindowID(window))
          done = true;
      se_process_event(&event);
    }
    if(gui_state.init_fonts==false){
      glViewport(0, 0, (int)io->DisplaySize.x, (int)io->DisplaySize.y);
      SDL_GL_GetDrawableSize(window,&gui_state.screen_width,&gui_state.screen_height);
      int win_w = gui_state.screen_width, win_h=gui_state.screen_height; 
      SDL_GetWindowSize(window, &win_w, &win_h);
      gui_state.dpi_scale = (float)gui_state.screen_width/(float)win_w;
      se_init_karla();
      gui_state.init_fonts=true;
    }
    glClearColor(0,0,0,1);
    glClear(GL_COLOR_BUFFER_BIT);
    // Start the Dear ImGui frame
    igImplOpenGL3_NewFrame();
    igImplSDL2_NewFrame();

    igNewFrame();
    frame();    
    // Rendering
    igRender();
    igImplOpenGL3_RenderDrawData(igGetDrawData());

    // Update and Render additional Platform Windows
    // (Platform functions may change the current OpenGL context, so we save/restore it to make it easier to paste this code elsewhere.
    //  For this specific demo app we could also call SDL_GL_MakeCurrent(window, gl_context) directly)
    if (io->ConfigFlags & ImGuiConfigFlags_ViewportsEnable){
      SDL_Window* backup_current_window = SDL_GL_GetCurrentWindow();
      SDL_GLContext backup_current_context = SDL_GL_GetCurrentContext();
      igUpdatePlatformWindows();
      igRenderPlatformWindowsDefault(NULL,NULL);
      SDL_GL_MakeCurrent(backup_current_window, backup_current_context);
    }
    SDL_GL_SwapWindow(window);
    se_free_all_images();
  }

  // Cleanup
  igImplOpenGL3_Shutdown();
  igImplSDL2_Shutdown();
  igDestroyContext(NULL);

  SDL_GL_DeleteContext(gl_context);
  SDL_DestroyWindow(window);
  SDL_Quit();

  return 0;
}
