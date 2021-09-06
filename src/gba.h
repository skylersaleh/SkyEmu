#ifndef SE_GBA_H
#define SE_GBA_H 1

#include "sb_types.h"
#include <string.h>

#include "arm7.h"
#include "gba_bios.h"
//Should be power of 2 for perf, 8192 samples gives ~85ms maximal latency for 48kHz
#define SB_AUDIO_RING_BUFFER_SIZE (2048*8)
#define LR 14
#define PC 15
#define CPSR 16
#define SPSR 17       
#define GBA_LCD_W 240
#define GBA_LCD_H 160

//////////////////////////////////////////////////////////////////////////////////////////
// MMIO Register listing from GBATEK (https://problemkaputt.de/gbatek.htm#gbamemorymap) //
//////////////////////////////////////////////////////////////////////////////////////////
// LCD MMIO Registers
#define  GBA_DISPCNT  0x4000000  /* R/W LCD Control */
#define  GBA_GREENSWP 0x4000002  /* R/W Undocumented - Green Swap */
#define  GBA_DISPSTAT 0x4000004  /* R/W General LCD Status (STAT,LYC) */
#define  GBA_VCOUNT   0x4000006  /* R   Vertical Counter (LY) */
#define  GBA_BG0CNT   0x4000008  /* R/W BG0 Control */
#define  GBA_BG1CNT   0x400000A  /* R/W BG1 Control */
#define  GBA_BG2CNT   0x400000C  /* R/W BG2 Control */
#define  GBA_BG3CNT   0x400000E  /* R/W BG3 Control */
#define  GBA_BG0HOFS  0x4000010  /* W   BG0 X-Offset */
#define  GBA_BG0VOFS  0x4000012  /* W   BG0 Y-Offset */
#define  GBA_BG1HOFS  0x4000014  /* W   BG1 X-Offset */
#define  GBA_BG1VOFS  0x4000016  /* W   BG1 Y-Offset */
#define  GBA_BG2HOFS  0x4000018  /* W   BG2 X-Offset */
#define  GBA_BG2VOFS  0x400001A  /* W   BG2 Y-Offset */
#define  GBA_BG3HOFS  0x400001C  /* W   BG3 X-Offset */
#define  GBA_BG3VOFS  0x400001E  /* W   BG3 Y-Offset */
#define  GBA_BG2PA    0x4000020  /* W   BG2 Rotation/Scaling Parameter A (dx) */
#define  GBA_BG2PB    0x4000022  /* W   BG2 Rotation/Scaling Parameter B (dmx) */
#define  GBA_BG2PC    0x4000024  /* W   BG2 Rotation/Scaling Parameter C (dy) */
#define  GBA_BG2PD    0x4000026  /* W   BG2 Rotation/Scaling Parameter D (dmy) */
#define  GBA_BG2X     0x4000028  /* W   BG2 Reference Point X-Coordinate */
#define  GBA_BG2Y     0x400002C  /* W   BG2 Reference Point Y-Coordinate */
#define  GBA_BG3PA    0x4000030  /* W   BG3 Rotation/Scaling Parameter A (dx) */
#define  GBA_BG3PB    0x4000032  /* W   BG3 Rotation/Scaling Parameter B (dmx) */
#define  GBA_BG3PC    0x4000034  /* W   BG3 Rotation/Scaling Parameter C (dy) */
#define  GBA_BG3PD    0x4000036  /* W   BG3 Rotation/Scaling Parameter D (dmy) */
#define  GBA_BG3X     0x4000038  /* W   BG3 Reference Point X-Coordinate */
#define  GBA_BG3Y     0x400003C  /* W   BG3 Reference Point Y-Coordinate */
#define  GBA_WIN0H    0x4000040  /* W   Window 0 Horizontal Dimensions */
#define  GBA_WIN1H    0x4000042  /* W   Window 1 Horizontal Dimensions */
#define  GBA_WIN0V    0x4000044  /* W   Window 0 Vertical Dimensions */
#define  GBA_WIN1V    0x4000046  /* W   Window 1 Vertical Dimensions */
#define  GBA_WININ    0x4000048  /* R/W Inside of Window 0 and 1 */
#define  GBA_WINOUT   0x400004A  /* R/W Inside of OBJ Window & Outside of Windows */
#define  GBA_MOSAIC   0x400004C  /* W   Mosaic Size */
#define  GBA_BLDCNT   0x4000050  /* R/W Color Special Effects Selection */
#define  GBA_BLDALPHA 0x4000052  /* R/W Alpha Blending Coefficients */
#define  GBA_BLDY     0x4000054  /* W   Brightness (Fade-In/Out) Coefficient */

// Sound Registers
#define GBA_SOUND1CNT_L 0x4000060  /* R/W   Channel 1 Sweep register       (NR10) */
#define GBA_SOUND1CNT_H 0x4000062  /* R/W   Channel 1 Duty/Length/Envelope (NR11, NR12) */
#define GBA_SOUND1CNT_X 0x4000064  /* R/W   Channel 1 Frequency/Control    (NR13, NR14) */
#define GBA_SOUND2CNT_L 0x4000068  /* R/W   Channel 2 Duty/Length/Envelope (NR21, NR22) */
#define GBA_SOUND2CNT_H 0x400006C  /* R/W   Channel 2 Frequency/Control    (NR23, NR24) */
#define GBA_SOUND3CNT_L 0x4000070  /* R/W   Channel 3 Stop/Wave RAM select (NR30) */
#define GBA_SOUND3CNT_H 0x4000072  /* R/W   Channel 3 Length/Volume        (NR31, NR32) */
#define GBA_SOUND3CNT_X 0x4000074  /* R/W   Channel 3 Frequency/Control    (NR33, NR34) */
#define GBA_SOUND4CNT_L 0x4000078  /* R/W   Channel 4 Length/Envelope      (NR41, NR42) */
#define GBA_SOUND4CNT_H 0x400007C  /* R/W   Channel 4 Frequency/Control    (NR43, NR44) */
#define GBA_SOUNDCNT_L  0x4000080  /* R/W   Control Stereo/Volume/Enable   (NR50, NR51) */
#define GBA_SOUNDCNT_H  0x4000082  /* R/W   Control Mixing/DMA Control */
#define GBA_SOUNDCNT_X  0x4000084  /* R/W   Control Sound on/off           (NR52) */
#define GBA_SOUNDBIAS   0x4000088  /* BIOS  Sound PWM Control */
#define GBA_WAVE_RAM    0x4000090  /* R/W Channel 3 Wave Pattern RAM (2 banks!!) */
#define GBA_FIFO_A      0x40000A0  /* W   Channel A FIFO, Data 0-3 */
#define GBA_FIFO_B      0x40000A4  /* W   Channel B FIFO, Data 0-3 */

// DMA Transfer Channels
#define GBA_DMA0SAD    0x40000B0   /* W    DMA 0 Source Address */
#define GBA_DMA0DAD    0x40000B4   /* W    DMA 0 Destination Address */
#define GBA_DMA0CNT_L  0x40000B8   /* W    DMA 0 Word Count */
#define GBA_DMA0CNT_H  0x40000BA   /* R/W  DMA 0 Control */
#define GBA_DMA1SAD    0x40000BC   /* W    DMA 1 Source Address */
#define GBA_DMA1DAD    0x40000C0   /* W    DMA 1 Destination Address */
#define GBA_DMA1CNT_L  0x40000C4   /* W    DMA 1 Word Count */
#define GBA_DMA1CNT_H  0x40000C6   /* R/W  DMA 1 Control */
#define GBA_DMA2SAD    0x40000C8   /* W    DMA 2 Source Address */
#define GBA_DMA2DAD    0x40000CC   /* W    DMA 2 Destination Address */
#define GBA_DMA2CNT_L  0x40000D0   /* W    DMA 2 Word Count */
#define GBA_DMA2CNT_H  0x40000D2   /* R/W  DMA 2 Control */
#define GBA_DMA3SAD    0x40000D4   /* W    DMA 3 Source Address */
#define GBA_DMA3DAD    0x40000D8   /* W    DMA 3 Destination Address */
#define GBA_DMA3CNT_L  0x40000DC   /* W    DMA 3 Word Count */
#define GBA_DMA3CNT_H  0x40000DE   /* R/W  DMA 3 Control */

// Timer Registers
#define GBA_TM0CNT_L   0x4000100   /* R/W   Timer 0 Counter/Reload */
#define GBA_TM0CNT_H   0x4000102   /* R/W   Timer 0 Control */
#define GBA_TM1CNT_L   0x4000104   /* R/W   Timer 1 Counter/Reload */
#define GBA_TM1CNT_H   0x4000106   /* R/W   Timer 1 Control */
#define GBA_TM2CNT_L   0x4000108   /* R/W   Timer 2 Counter/Reload */
#define GBA_TM2CNT_H   0x400010A   /* R/W   Timer 2 Control */
#define GBA_TM3CNT_L   0x400010C   /* R/W   Timer 3 Counter/Reload */
#define GBA_TM3CNT_H   0x400010E   /* R/W   Timer 3 Control */

// Serial Communication (1)
#define GBA_SIODATA32    0x4000120 /*R/W   SIO Data (Normal-32bit Mode; shared with below) */
#define GBA_SIOMULTI0    0x4000120 /*R/W   SIO Data 0 (Parent)    (Multi-Player Mode) */
#define GBA_SIOMULTI1    0x4000122 /*R/W   SIO Data 1 (1st Child) (Multi-Player Mode) */
#define GBA_SIOMULTI2    0x4000124 /*R/W   SIO Data 2 (2nd Child) (Multi-Player Mode) */
#define GBA_SIOMULTI3    0x4000126 /*R/W   SIO Data 3 (3rd Child) (Multi-Player Mode) */
#define GBA_SIOCNT       0x4000128 /*R/W   SIO Control Register */
#define GBA_SIOMLT_SEND  0x400012A /*R/W   SIO Data (Local of MultiPlayer; shared below) */
#define GBA_SIODATA8     0x400012A /*R/W   SIO Data (Normal-8bit and UART Mode) */

// Keypad Input
#define GBA_KEYINPUT  0x4000130    /* R      Key Status */
#define GBA_KEYCNT    0x4000132    /* R/W    Key Interrupt Control */

// Serial Communication (2)
#define GBA_RCNT      0x4000134    /* R/W  SIO Mode Select/General Purpose Data */
#define GBA_IR        0x4000136    /* -    Ancient - Infrared Register (Prototypes only) */
#define GBA_JOYCNT    0x4000140    /* R/W  SIO JOY Bus Control */
#define GBA_JOY_RECV  0x4000150    /* R/W  SIO JOY Bus Receive Data */
#define GBA_JOY_TRANS 0x4000154    /* R/W  SIO JOY Bus Transmit Data */
#define GBA_JOYSTAT   0x4000158    /* R/?  SIO JOY Bus Receive Status */

// Interrupt, Waitstate, and Power-Down Control
#define GBA_IE      0x4000200      /* R/W  IE        Interrupt Enable Register */
#define GBA_IF      0x4000202      /* R/W  IF        Interrupt Request Flags / IRQ Acknowledge */
#define GBA_WAITCNT 0x4000204      /* R/W  WAITCNT   Game Pak Waitstate Control */
#define GBA_IME     0x4000208      /* R/W  IME       Interrupt Master Enable Register */
#define GBA_POSTFLG 0x4000300      /* R/W  POSTFLG   Undocumented - Post Boot Flag */
#define GBA_HALTCNT 0x4000301      /* W    HALTCNT   Undocumented - Power Down Control */
// #define GBA_?       0x4000410      /* ?    ?         Undocumented - Purpose Unknown / Bug ??? 0FFh */
// #define GBA_?       0x4000800      /* R/W  ?         Undocumented - Internal Memory Control (R/W) */
// #define GBA_?       0x4xx0800      /* R/W  ?         Mirrors of 4000800h (repeated each 64K) */
// #define GBA_(3DS)   0x4700000      /* W    (3DS)     Disable ARM7 bootrom overlay (3DS only) */

// Interrupt sources
#define GBA_INT_LCD_VBLANK 0   
#define GBA_INT_LCD_HBLANK 1     
#define GBA_INT_LCD_VCOUNT 2     
#define GBA_INT_TIMER0     3     
#define GBA_INT_TIMER1     4     
#define GBA_INT_TIMER2     5     
#define GBA_INT_TIMER3     6     
#define GBA_INT_SERIAL     7     
#define GBA_INT_DMA0       8     
#define GBA_INT_DMA1       9     
#define GBA_INT_DMA2       10    
#define GBA_INT_DMA3       11    
#define GBA_INT_KEYPAD     12    
#define GBA_INT_GAMEPAK    13    

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
  uint32_t* openbus_word; 
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
  bool last_vblank;
  bool last_hblank;
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
inline uint8_t gba_read8(gba_t*gba, unsigned baddr){
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
static inline uint32_t arm7_read32(void* user_data, uint32_t address){ 
  uint32_t value = gba_read32((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x3)*8);
}
static inline uint32_t arm7_read16(void* user_data, uint32_t address){
  uint16_t value = gba_read16((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x1)*8);
}
//Used to process special behavior triggered by MMIO write
static bool gba_process_mmio_write(gba_t *gba, uint32_t address, uint32_t data, int req_size_bytes);
static uint8_t arm7_read8(void* user_data, uint32_t address){return gba_read8((gba_t*)user_data,address);}
static void arm7_write32(void* user_data, uint32_t address, uint32_t data){
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,4))return;
  }
  gba_store32((gba_t*)user_data,address,data);
}
static void arm7_write16(void* user_data, uint32_t address, uint16_t data){
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,2))return; 
  }
  gba_store16((gba_t*)user_data,address,data);
}
static void arm7_write8(void* user_data, uint32_t address, uint8_t data)  {
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,1))return; 
  }
  gba_store8((gba_t*)user_data,address,data);
}
// Try to load a GBA rom, return false on invalid rom
bool gba_load_rom(gba_t* gba, const char * filename);
void gba_reset(gba_t*gba);
 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr){
  baddr&=0xfffffffc;
  uint32_t *ret = gba->mem.openbus_word;
  if(baddr<0x4000)return (uint32_t*)(gba->mem.bios+baddr-0x0);
  else if(baddr>=0x2000000 && baddr<=0x203FFFF )ret = (uint32_t*)(gba->mem.wram0+(baddr&0x3ffff));
  else if(baddr>=0x3000000 && baddr<=0x3007FFF )ret = (uint32_t*)(gba->mem.wram1+(baddr&0x7fff));
  else if(baddr>=0x4000000 && baddr<=0x40003FE )ret = (uint32_t*)(gba->mem.io+baddr-0x4000000);
  else if(baddr>=0x5000000 && baddr<=0x50003FF )ret = (uint32_t*)(gba->mem.palette+(baddr&0x3ff));
  else if(baddr>=0x6000000 && baddr<=0x6017FFF )ret = (uint32_t*)(gba->mem.vram+(baddr&0x1ffff));
  else if(baddr>=0x7000000 && baddr<=0x70003FF )ret = (uint32_t*)(gba->mem.oam+(baddr&0x3ff));
  else if(baddr>=0x8000000 && baddr<=0x9FFFFFF )ret = (uint32_t*)(gba->mem.cart_rom+baddr-0x8000000);
  else if(baddr>=0xA000000 && baddr<=0xBFFFFFF )ret = (uint32_t*)(gba->mem.cart_rom+baddr-0xA000000);
  else if(baddr>=0xC000000 && baddr<=0xDFFFFFF )ret = (uint32_t*)(gba->mem.cart_rom+baddr-0xC000000);
  else if(baddr>=0xE000000 && baddr<=0xE00FFFF )ret = (uint32_t*)(gba->mem.cart_sram+baddr-0xE000000);

  return gba->mem.openbus_word=ret;
}
static bool gba_process_mmio_write(gba_t *gba, uint32_t address, uint32_t data, int req_size_bytes){
  uint32_t address_u32 = address&~3; 
  uint32_t address_u16 = address&~1; 
  uint32_t dword_mask = 0xffffffff;
  uint32_t dword_data = data; 
  if(req_size_bytes==2){
    dword_data<<= (address&2)*8;
    dword_mask =0x0000ffff<< ((address&2)*8);
  }else if(req_size_bytes==1){
    dword_data<<= (address&3)*8;
    dword_mask =0x000000ff<< ((address&2)*8);
  }

  dword_data&=dword_mask;

  if(address_u32== GBA_IF){
    uint32_t r = gba_read32(gba,GBA_IF);
    // Writing to IF actually clears the bits set to 1
    r &= ~(dword_data);
    gba_store32(gba,GBA_IF,r);
    return true; 
  }

  return false;
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
      int addr = 0x06000000+p*1+0xA000*frame_sel; 
      uint8_t pallete_id = gba_read8(gba,addr);
      uint16_t pallete = gba_read16(gba, GBA_BG_PALETTE+pallete_id*2);

      int r = SB_BFE(pallete,0,5)*7;
      int g = SB_BFE(pallete,5,5)*7;
      int b = SB_BFE(pallete,10,5)*7;

      gba->framebuffer[p*3+0] = r;
      gba->framebuffer[p*3+1] = g;
      gba->framebuffer[p*3+2] = b;
    }else if(bg_mode==6 ||bg_mode==7){
      uint8_t pallete_id = 0;
      uint16_t pallete = gba_read16(gba, GBA_BG_PALETTE+pallete_id*2);

      int r = SB_BFE(pallete,0,5)*7;
      int g = SB_BFE(pallete,5,5)*7;
      int b = SB_BFE(pallete,10,5)*7;

      gba->framebuffer[p*3+0] = r;
      gba->framebuffer[p*3+1] = g;
      gba->framebuffer[p*3+2] = b;
    }else if(bg_mode!=0) printf("Unsupported background mode: %d\n",bg_mode);
  }
  uint32_t new_if = gba_read32(gba,GBA_IF); 
  uint32_t int_en = gba_read32(gba,GBA_IE);
  if(vblank!=gba->ppu.last_vblank){
    if(vblank&& SB_BFE(int_en,GBA_INT_LCD_VBLANK,1)) new_if|= 1<< GBA_INT_LCD_VBLANK; 
  }
  if(hblank!=gba->ppu.last_hblank){
    if(hblank&& SB_BFE(int_en,GBA_INT_LCD_HBLANK,1)) new_if|= 1<< GBA_INT_LCD_HBLANK; 
  }
  gba->ppu.last_vblank = vblank;
  gba->ppu.last_hblank = hblank;
  gba_store32(gba,GBA_IF,new_if);

}
void gba_tick_keypad(sb_joy_t*joy, gba_t* gba){
  uint16_t reg_value = 0;
  reg_value|= !(joy->a)     <<0;
  reg_value|= !(joy->b)     <<1;
  reg_value|= !(joy->select)<<2;
  reg_value|= !(joy->start) <<3;
  reg_value|= !(joy->right) <<4;
  reg_value|= !(joy->left)  <<5;
  reg_value|= !(joy->up)    <<6;
  reg_value|= !(joy->down)  <<7;
  reg_value|= !(joy->r)     <<8;
  reg_value|= !(joy->l)     <<9;
  gba_store16(gba, GBA_KEYINPUT, reg_value);
}
void gba_tick(sb_emu_state_t* emu, gba_t* gba){
  if(emu->run_mode == SB_MODE_RESET){
    emu->run_mode = SB_MODE_PAUSE;
  }
  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    gba_tick_keypad(&emu->joy,gba);
    int max_instructions = 280896;
    if(emu->step_instructions) max_instructions = emu->step_instructions;
    for(int i = 0;i<max_instructions;++i){
      uint32_t int_if = gba_read32(gba,GBA_IF);
      arm7_process_interrupts(&gba->cpu, int_if);
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
  memcpy(gba->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  gba->mem.openbus_word = (uint32_t*)&gba->mem.cart_rom[0];
}

#endif
