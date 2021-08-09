#ifndef SE_GBA_H
#define SE_GBA_H 1

#include "sb_types.h"
#include <string.h>

//Should be power of 2 for perf, 8192 samples gives ~85ms maximal latency for 48kHz
#define SB_AUDIO_RING_BUFFER_SIZE (2048*8)
#define PC 15
#define CPSR 16
#define SPSR 17       
#define GBA_LCD_W 240
#define GBA_LCD_H 160
typedef struct {
  // Registers
  /*
  0-15: R0-R15
  16: CPSR
  17-23: R8_fiq-R14_fiq
  24-25: R13_irq-R14_irq
  26-27: R13_svc-R14_svc
  28-29: R13_abt-R14_abt
  30-31: R13_und-R14_und
  32: SPSR_fiq
  33: SPSR_irq
  34: SPSR_svc
  35: SPSR_abt
  36: SPSR_und
  */
  uint32_t registers[37];
  bool trigger_breakpoint;
} arm7tdmi_t;       

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

typedef struct {
  gba_mem_t mem;
  arm7tdmi_t cpu;
  gba_cartridge_t cart;
  gba_joy_t joy;
  uint8_t framebuffer[GBA_LCD_W*GBA_LCD_H*3];
} gba_t; 
                              

// Returns mapping of an ARM register to the register array in the CPU struct
unsigned arm7_reg_index(arm7tdmi_t* cpu, unsigned reg);
uint32_t arm7_reg_read(arm7tdmi_t*cpu, unsigned reg);
void arm7_reg_write(arm7tdmi_t*cpu, unsigned reg, uint32_t value);
uint32_t arm7_read_reg(arm7tdmi_t* cpu, unsigned reg);
// Returns a pointer to the data backing the baddr (when not DWORD aligned, it
// ignores the lowest 2 bits. 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr);
inline uint32_t gba_read32(gba_t*gba, unsigned baddr){return *gba_dword_lookup(gba,baddr);}
inline uint16_t gba_read16(gba_t*gba, unsigned baddr){
  uint32_t* val = gba_dword_lookup(gba,baddr&0xfffffffC);
  int offset = SB_BFE(baddr,1,1);
  return ((*val)>>(16*offset))&0xffff;
}
inline void gba_store32(gba_t*gba, unsigned baddr, uint32_t data){*gba_dword_lookup(gba,baddr) = data;}
inline void gba_store16(gba_t*gba, unsigned baddr, uint32_t data){
  uint32_t* val = gba_dword_lookup(gba,baddr);
  int offset = SB_BFE(baddr,1,1);
  *val&= ~(0xffff<<(offset*16));
  *val|= (data&0xffff)<<(offset*16);
}
inline void gba_store8(gba_t*gba, unsigned baddr, uint32_t data){
  uint32_t *val = gba_dword_lookup(gba,baddr);
  int offset = SB_BFE(baddr,0,2);
  *val&= (0xff<<(offset*8));
  *val|= (data&0xff)<<(offset*8);
} 
// Try to load a GBA rom, return false on invalid rom
bool gba_load_rom(gba_t* gba, const char * filename);
void gba_reset(gba_t*gba);

#include "gba_tables.h"

unsigned arm7_reg_index(arm7tdmi_t* cpu, unsigned reg){
  if(reg<8 ||reg == 15 || reg==16)return reg;
  int mode = SB_BFE(cpu->registers[CPSR],5,0);
  if(mode == 0x10)mode=0;      // User
  else if(mode == 0x11)mode=1; // FIQ
  else if(mode == 0x12)mode=2; // IRQ
  else if(mode == 0x13)mode=3; // Supervisor
  else if(mode == 0x17)mode=4; // Abort
  else if(mode == 0x1b)mode=5; // Undefined
  else if(mode == 0x1f)mode=6; // System
  else {
    printf("Undefined ARM mode: %d\n",mode);
    return 0; 
  }
  // System and User mapping
  if(mode == 0 ||mode ==6) return reg; 
  // FIQ specific registers
  if(mode == 1 && reg<15) return reg+17-8; 
  // SPSR
  if(reg==SPSR)return 32+mode-1;
  // 13 && 14
  if(reg==13 || reg ==14 )return 17+mode*2 + (reg-13);

  printf("Undefined register: %d for ARM mode: %d\n",reg,mode);
  return 0; 
}
void arm7_reg_write(arm7tdmi_t*cpu, unsigned reg, uint32_t value){
  cpu->registers[arm7_reg_index(cpu,reg)] = value;
} 
uint32_t arm7_reg_read(arm7tdmi_t*cpu, unsigned reg){
  return cpu->registers[arm7_reg_index(cpu,reg)];
}
 
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
  return &gba->mem.openbus_dword;
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
bool arm7_check_cond_code(gba_t*gba, uint32_t opcode){
  uint32_t cond_code = SB_BFE(opcode,28,4);
  if(cond_code==0xE)return true;
  // TODO: Fix this...
  return true;
  uint32_t cpsr = gba->cpu.registers[CPSR];
  bool N = SB_BFE(cpsr,31,1);
  bool Z = SB_BFE(cpsr,30,1);
  bool C = SB_BFE(cpsr,29,1);
  bool V = SB_BFE(cpsr,28,1);
  switch(cond_code){
    case 0x0: return Z;  
    case 0x1: return !Z; 
    case 0x2: return C;  
    case 0x3: return !C; 
    case 0x4: return N;  
    case 0x5: return !N; 
    case 0x6: return V;  
    case 0x7: return !V; 
    case 0x8: return C && !Z;
    case 0x9: return !C || Z;
    case 0xA: return N==V;
    case 0xB: return N!=V;
    case 0xC: return !Z&&(N==V);
    case 0xD: return Z||(N!=V);
  };
  return false; 
}

void gba_tick(sb_emu_state_t* emu, gba_t* gba){
  if(emu->run_mode == SB_MODE_RESET){
    emu->run_mode = SB_MODE_PAUSE;
  }
  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    int max_instructions = 100;
    if(emu->step_instructions) max_instructions = emu->step_instructions;
    for(int i = 0;i<max_instructions;++i){
      unsigned oldpc = gba->cpu.registers[PC]; 
      uint32_t opcode = gba_read32(gba,oldpc);
      uint32_t cond_code = SB_BFE(opcode,28,4);
      if(arm7_check_cond_code(gba,opcode)) gba_execute_instr(gba, opcode);
      bool breakpoint = gba->cpu.registers[PC]== emu->pc_breakpoint;
      breakpoint |= gba->cpu.trigger_breakpoint;
      if(gba->cpu.registers[PC] == oldpc) gba->cpu.registers[PC] += 4; 
      if(breakpoint){emu->run_mode = SB_MODE_PAUSE; break;}
    }
  }
  for(int p = 0; p< GBA_LCD_W*GBA_LCD_H;++p){
    int addr = 0x06000000+p*2; 
    uint16_t data = gba_read16(gba,addr);
    int r = SB_BFE(data,0,5)*8;
    int g = SB_BFE(data,5,5)*8;
    int b = SB_BFE(data,10,5)*8;
    gba->framebuffer[p*3+0] = r;
    gba->framebuffer[p*3+1] = g;
    gba->framebuffer[p*3+2] = b;
  }
  if(emu->run_mode == SB_MODE_STEP) emu->run_mode = SB_MODE_PAUSE; 
}

void gba_reset(gba_t*gba){
  *gba = (gba_t){0};
  gba->cpu.registers[PC]= 0x8000000; 
}
#undef PC
#undef CPSR
#undef SPSR
#endif
