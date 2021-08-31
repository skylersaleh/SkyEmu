#ifndef SE_GBA_H
#define SE_GBA_H 1

#include "sb_types.h"
#include <string.h>

#include "arm7.h"
//Should be power of 2 for perf, 8192 samples gives ~85ms maximal latency for 48kHz
#define SB_AUDIO_RING_BUFFER_SIZE (2048*8)
#define LR 14
#define PC 15
#define CPSR 16
#define SPSR 17       
#define GBA_LCD_W 240
#define GBA_LCD_H 160

#define GBA_DISPCNT  0x4000000
#define GBA_DISPSTAT 0x4000004
#define GBA_VCOUNT   0x4000006
#define GBA_BG_PALETTE 0x5000000      

typedef struct {     
  uint8_t bios[16*1024];
  uint8_t wram0[256*1024];
  uint8_t wram1[32*1024];
  uint8_t io[1024];
  uint8_t palette[1024];
  uint8_t vram[96*1024];
  uint8_t oam[1024];
  uint8_t cart_rom[32*1024*1024];
  uint8_t cart_sram[64*1024];
  uint32_t openbus_dword; 
} gba_mem_t;

typedef struct {
  char title[13];
  char save_file_path[SB_FILE_PATH_SIZE];  
  unsigned rom_size; 
} gba_cartridge_t;
typedef struct{
  bool up,down,left,right;
  bool a, b, start, select;
  bool l,r;
} gba_joy_t;
typedef struct{
  int scan_clock; 
}gba_ppu_t;
typedef struct {
  gba_mem_t mem;
  arm7_t cpu;
  gba_cartridge_t cart;
  gba_joy_t joy;       
  gba_ppu_t ppu;
  uint8_t framebuffer[GBA_LCD_W*GBA_LCD_H*3];
} gba_t; 
                              
// Returns a pointer to the data backing the baddr (when not DWORD aligned, it
// ignores the lowest 2 bits. 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr);
inline uint32_t gba_read32(gba_t*gba, unsigned baddr){return *gba_dword_lookup(gba,baddr);}
inline uint16_t gba_read16(gba_t*gba, unsigned baddr){
  uint32_t* val = gba_dword_lookup(gba,baddr&0xfffffffC);
  int offset = SB_BFE(baddr,1,1);
  return ((uint16_t*)val)[offset];
}
inline uint16_t gba_read8(gba_t*gba, unsigned baddr){
  uint32_t* val = gba_dword_lookup(gba,baddr&0xfffffffC);
  int offset = SB_BFE(baddr,0,2);
  return ((uint8_t*)val)[offset];
}            
inline void gba_store32(gba_t*gba, unsigned baddr, uint32_t data){*gba_dword_lookup(gba,baddr) = data;}
inline void gba_store16(gba_t*gba, unsigned baddr, uint32_t data){
  uint32_t* val = gba_dword_lookup(gba,baddr);
  int offset = SB_BFE(baddr,1,1);
  ((uint16_t*)val)[offset]=data; 
}
inline void gba_store8(gba_t*gba, unsigned baddr, uint32_t data){
  uint32_t *val = gba_dword_lookup(gba,baddr);
  int offset = SB_BFE(baddr,0,2);
  ((uint8_t*)val)[offset]=data; 
} 

// Memory IO functions for the emulated CPU
static uint32_t arm7_read32(void* user_data, uint32_t address){ 
  uint32_t value = gba_read32((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x3)*8);
}
static uint32_t arm7_read16(void* user_data, uint32_t address){
  uint32_t value = gba_read16((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x1)*8);
}
static uint8_t arm7_read8(void* user_data, uint32_t address){return gba_read8((gba_t*)user_data,address);}
static void arm7_write32(void* user_data, uint32_t address, uint32_t data){gba_store32((gba_t*)user_data,address,data);}
static void arm7_write16(void* user_data, uint32_t address, uint16_t data){gba_store16((gba_t*)user_data,address,data);}
static void arm7_write8(void* user_data, uint32_t address, uint8_t data)  {gba_store8((gba_t*)user_data,address,data);}
// Try to load a GBA rom, return false on invalid rom
bool gba_load_rom(gba_t* gba, const char * filename);
void gba_reset(gba_t*gba);
 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr){
  baddr&=0xfffffffc;
  if(baddr<0x4000)return (uint32_t*)(gba->mem.bios+baddr-0x0);
  else if(baddr>=0x2000000 && baddr<=0x203FFFF )return (uint32_t*)(gba->mem.wram0+baddr-0x2000000);
  else if(baddr>=0x3000000 && baddr<=0x3007FFF )return (uint32_t*)(gba->mem.wram1+baddr-0x3000000);
  else if(baddr>=0x4000000 && baddr<=0x40003FE )return (uint32_t*)(gba->mem.io+baddr-0x4000000);
  else if(baddr>=0x5000000 && baddr<=0x50003FF )return (uint32_t*)(gba->mem.palette+baddr-0x5000000);
  else if(baddr>=0x6000000 && baddr<=0x6017FFF )return (uint32_t*)(gba->mem.vram+baddr-0x6000000);
  else if(baddr>=0x7000000 && baddr<=0x70003FF )return (uint32_t*)(gba->mem.oam+baddr-0x7000000);
  else if(baddr>=0x8000000 && baddr<=0x9FFFFFF )return (uint32_t*)(gba->mem.cart_rom+baddr-0x8000000);
  else if(baddr>=0xA000000 && baddr<=0xBFFFFFF )return (uint32_t*)(gba->mem.cart_rom+baddr-0xA000000);
  else if(baddr>=0xC000000 && baddr<=0xDFFFFFF )return (uint32_t*)(gba->mem.cart_rom+baddr-0xC000000);
  else if(baddr>=0xE000000 && baddr<=0xE00FFFF )return (uint32_t*)(gba->mem.cart_sram+baddr-0xE000000);

  //printf("Access to openbus memory region: %x\n",baddr);
  return gba_dword_lookup(gba,gba->cpu.registers[PC]+4);
}

bool gba_load_rom(gba_t* gba, const char* filename){

  if(!IsFileExtension(filename, ".gba")){
    return false; 
  }
  unsigned int bytes = 0;                                                       
  unsigned char *data = LoadFileData(filename, &bytes);
  if(bytes>32*1024*1024){
    printf("ROMs with sizes >32MB (%d bytes) are too big for the GBA\n",bytes); 
    return false;
  }                 
  gba_reset(gba);
  memcpy(gba->mem.cart_rom, data, bytes);
  UnloadFileData(data);
  gba->cart.rom_size = bytes; 

  const char * c = GetFileNameWithoutExt(filename);
#if defined(PLATFORM_WEB)
  const char * save_file = TextFormat("/offline/%s.sav",c);
#else
  const char * save_file = TextFormat("%s.sav",c);
#endif
  strncpy(gba->cart.save_file_path,save_file,SB_FILE_PATH_SIZE);
  gba->cart.save_file_path[SB_FILE_PATH_SIZE-1]=0;

  memcpy(gba->cart.title,gba->mem.cart_rom+0x0A0,12);
  gba->cart.title[12]=0;
  // TODO: Saves are a future Sky problem. 
  for(int i=0;i<sizeof(gba->mem.cart_sram);++i) gba->mem.cart_sram[i]=0;
  return true; 
}  

    
void gba_tick_ppu(gba_t* gba, int cycles){
  // TODO: This is a STUB
  gba->ppu.scan_clock+=cycles;
  while(gba->ppu.scan_clock>280896) gba->ppu.scan_clock-=280896;
  //Make LCD-y increment during h-blank (fixes BEEG.gba)
  int lcd_y = (gba->ppu.scan_clock+272)/1232;
  int lcd_x = (gba->ppu.scan_clock%1232)/4;

  uint16_t disp_stat = gba_read16(gba, GBA_DISPSTAT)&~0xffff;
  uint16_t vcount_cmp = SB_BFE(disp_stat,8,8);
  bool vblank = lcd_y>=160&& lcd_y>=227;
  bool hblank = lcd_x>=240;
  disp_stat|= vblank ? 0x1: 0; 
  disp_stat|= hblank ? 0x2: 0;      
  disp_stat|= lcd_y==vcount_cmp ? 0x4: 0;   

  gba_store16(gba,GBA_DISPSTAT,disp_stat);
  gba_store16(gba,GBA_VCOUNT,lcd_y);   

  uint32_t dispcnt = gba_read32(gba, GBA_DISPCNT);
  int bg_mode = SB_BFE(dispcnt,0,3);
  int frame_sel = SB_BFE(dispcnt,4,1);
  int p = lcd_x+lcd_y*240;
  bool visible = lcd_x<240 && lcd_y<160;
  if(visible){
    if(bg_mode==3){
      int addr = 0x06000000+p*2; 
      uint16_t data = gba_read16(gba,addr);
      int r = SB_BFE(data,0,5)*7;
      int g = SB_BFE(data,5,5)*7;
      int b = SB_BFE(data,10,5)*7;
      gba->framebuffer[p*3+0] = r;
      gba->framebuffer[p*3+1] = g;
      gba->framebuffer[p*3+2] = b;
    }else if(bg_mode==4){
      int addr = 0x06000000+p*1+0xA000; 
      uint8_t pallete_id = gba_read8(gba,addr);
      uint16_t pallete = gba_read16(gba, GBA_BG_PALETTE+pallete_id*2);

      int r = SB_BFE(pallete,0,5)*7;
      int g = SB_BFE(pallete,5,5)*7;
      int b = SB_BFE(pallete,10,5)*7;

      gba->framebuffer[p*3+0] = r;
      gba->framebuffer[p*3+1] = g;
      gba->framebuffer[p*3+2] = b;
    }else if(bg_mode!=0) printf("Unsupported background mode: %d\n",bg_mode);
  }
}
void gba_tick(sb_emu_state_t* emu, gba_t* gba){
  if(emu->run_mode == SB_MODE_RESET){
    emu->run_mode = SB_MODE_PAUSE;
  }
  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    int max_instructions = 10000;
    if(emu->step_instructions) max_instructions = emu->step_instructions;
    for(int i = 0;i<max_instructions;++i){
      arm7_exec_instruction(&gba->cpu); 
      gba_tick_ppu(gba,1);
      bool breakpoint = gba->cpu.registers[PC]== emu->pc_breakpoint;
      breakpoint |= gba->cpu.trigger_breakpoint;
      gba->cpu.trigger_breakpoint=false;
      if(breakpoint){emu->run_mode = SB_MODE_PAUSE; break;}
    }
  }                  
  
  if(emu->run_mode == SB_MODE_STEP) emu->run_mode = SB_MODE_PAUSE; 
}

void gba_reset(gba_t*gba){
  *gba = (gba_t){0};
  gba->cpu = arm7_init(gba);
  gba->cpu.registers[13] = 0x03007f00;
  gba->cpu.registers[R13_irq] = 0x03007FA0;
  gba->cpu.registers[R13_svc] = 0x03007FE0;
  gba->cpu.registers[R13_und] = 0x03007FF0;
  gba->cpu.registers[PC]= 0x8000000; 
  gba->cpu.registers[CPSR]= 0x000000df; 
}

#endif
