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

#define GBA_BG_PALETTE  0x05000000                    
#define GBA_OBJ_PALETTE 0x05000200                    
#define GBA_OBJ_TILES   0x06010000
#define GBA_OAM         0x07000000

  
typedef struct {     
  uint8_t bios[16*1024];
  uint8_t wram0[256*1024];
  uint8_t wram1[32*1024];
  uint8_t io[1024];
  uint8_t palette[1024];
  uint8_t vram[128*1024];
  uint8_t oam[1024];
  uint8_t cart_rom[32*1024*1024];
  uint8_t cart_sram[128*1024];
  uint32_t openbus_word; 
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
  int source_addr;
  int dest_addr;
  int length;
  int current_word;
  bool last_enable;
  bool last_vblank;
  bool last_hblank;
} gba_dma_t; 
typedef struct{
  int scan_clock; 
  bool last_vblank;
  bool last_hblank;
  int last_lcd_y; 
}gba_ppu_t;
typedef struct{
  bool last_enable; 
  uint16_t reload_value; 
  uint16_t prescaler_timer;
}gba_timer_t;
typedef struct {
  gba_mem_t mem;
  arm7_t cpu;
  gba_cartridge_t cart;
  gba_joy_t joy;       
  gba_ppu_t ppu;
  gba_dma_t dma[4]; 
  gba_timer_t timers[4];
  uint8_t scanline_priority[GBA_LCD_W]; //Used to handle priority settings
  uint8_t framebuffer[GBA_LCD_W*GBA_LCD_H*3];
} gba_t; 
                              
// Returns a pointer to the data backing the baddr (when not DWORD aligned, it
// ignores the lowest 2 bits. 
static uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr, bool * read_only);
static inline uint32_t gba_read32(gba_t*gba, unsigned baddr){bool read_only;return *gba_dword_lookup(gba,baddr,&read_only);}
static inline uint16_t gba_read16(gba_t*gba, unsigned baddr){
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr&0xfffffffC,&read_only);
  int offset = SB_BFE(baddr,1,1);
  return ((uint16_t*)val)[offset];
}
static inline uint8_t gba_read8(gba_t*gba, unsigned baddr){
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr&0xfffffffC,&read_only);
  int offset = SB_BFE(baddr,0,2);
  return ((uint8_t*)val)[offset];
}            
static inline void gba_store32(gba_t*gba, unsigned baddr, uint32_t data){
  bool read_only;
  uint32_t *val=gba_dword_lookup(gba,baddr,&read_only);
  if(!read_only)*val= data;
}
static inline void gba_store16(gba_t*gba, unsigned baddr, uint32_t data){
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,1,1);
  if(!read_only)((uint16_t*)val)[offset]=data; 
}
static inline void gba_store8(gba_t*gba, unsigned baddr, uint32_t data){
  bool read_only;
  uint32_t *val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,0,2);
  if(!read_only)((uint8_t*)val)[offset]=data; 
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
 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr,bool*read_only){
  baddr&=0xfffffffc;
  uint32_t *ret = &gba->mem.openbus_word;
  *read_only= false; 
  if(baddr<0x4000){ *read_only=true;ret= (uint32_t*)(gba->mem.bios+baddr-0x0);}
  else if(baddr>=0x2000000 && baddr<=0x203FFFF )ret = (uint32_t*)(gba->mem.wram0+(baddr&0x3ffff));
  else if(baddr>=0x3000000 && baddr<=0x3ffffff )ret = (uint32_t*)(gba->mem.wram1+(baddr&0x7fff));
  else if(baddr>=0x4000000 && baddr<=0x40003FE )ret = (uint32_t*)(gba->mem.io+baddr-0x4000000);
  else if(baddr>=0x5000000 && baddr<=0x5ffffff )ret = (uint32_t*)(gba->mem.palette+(baddr&0x3ff));
  else if(baddr>=0x6000000 && baddr<=0x6ffffff )ret = (uint32_t*)(gba->mem.vram+(baddr&0x1ffff));
  else if(baddr>=0x7000000 && baddr<=0x7ffffff )ret = (uint32_t*)(gba->mem.oam+(baddr&0x3ff));
  else if(baddr>=0x8000000 && baddr<=0x9FFFFFF ){*read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+baddr-0x8000000);}
  else if(baddr>=0xA000000 && baddr<=0xBFFFFFF ){*read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+baddr-0xA000000);}
  else if(baddr>=0xC000000 && baddr<=0xDFFFFFF ){*read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+baddr-0xC000000);}
  else if(baddr>=0xE000000 && baddr<=0xEffffff )ret = (uint32_t*)(gba->mem.cart_sram+(baddr&0x1ffff));
  gba->mem.openbus_word=*ret;
  return ret;
}
static bool gba_process_mmio_write(gba_t *gba, uint32_t address, uint32_t data, int req_size_bytes){
  uint32_t address_u32 = address&~3; 
  uint32_t address_u16 = address&~1; 
  uint32_t word_mask = 0xffffffff;
  uint32_t word_data = data; 
  if(req_size_bytes==2){
    word_data<<= (address&2)*8;
    word_mask =0x0000ffff<< ((address&2)*8);
  }else if(req_size_bytes==1){
    word_data<<= (address&3)*8;
    word_mask =0x000000ff<< ((address&3)*8);
  }

  word_data&=word_mask;

  if(address_u32== GBA_IE){
    uint16_t IE = gba_read16(gba,GBA_IE);
    uint16_t IF = gba_read16(gba,GBA_IF);
  
    IE = ((IE&~word_mask)|(word_data&word_mask))>>0;
    IF &= ~((word_data)>>16);
    gba_store16(gba,GBA_IE,IE);
    gba_store16(gba,GBA_IF,IF);

    return true; 
  }else if(address_u32 == GBA_TM0CNT_L||address_u32==GBA_TM1CNT_L||address_u32==GBA_TM2CNT_L||address_u32==GBA_TM3CNT_L){
    if(word_mask&0xffff){
      int timer_off = (address_u32-GBA_TM0CNT_L)/4;
      gba->timers[timer_off+0].reload_value &=~(word_mask&0xffff);
    }
    if(word_mask&0xffff0000){
      gba_store16(gba,address_u32+2,(word_data>>16)&0xffff);
    }
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
  if(gba->ppu.scan_clock%4)return;
  //Make LCD-y increment during h-blank (fixes BEEG.gba)
  int lcd_y = (gba->ppu.scan_clock+46)/1232;
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

  uint16_t dispcnt = gba_read16(gba, GBA_DISPCNT);
  int bg_mode = SB_BFE(dispcnt,0,3);
  int frame_sel = SB_BFE(dispcnt,4,1);
  int obj_vram_map_2d = !SB_BFE(dispcnt,6,1);
  int p = lcd_x+lcd_y*240;
  bool visible = lcd_x<240 && lcd_y<160;
  if(visible){
    uint16_t pallete = gba_read16(gba, GBA_BG_PALETTE+0*2);

    int r = SB_BFE(pallete,0,5)*7;
    int g = SB_BFE(pallete,5,5)*7;
    int b = SB_BFE(pallete,10,5)*7; 
    int bg_priority=4;
    if(bg_mode==3){
      int addr = 0x06000000+p*2; 
      uint16_t data = gba_read16(gba,addr);
      r = SB_BFE(data,0,5)*7;
      g = SB_BFE(data,5,5)*7;
      b = SB_BFE(data,10,5)*7;
    }else if(bg_mode==4){
      int addr = 0x06000000+p*1+0xA000*frame_sel; 
      uint8_t pallete_id = gba_read8(gba,addr);
      uint16_t pallete = gba_read16(gba, GBA_BG_PALETTE+pallete_id*2);

      r = SB_BFE(pallete,0,5)*7;
      g = SB_BFE(pallete,5,5)*7;
      b = SB_BFE(pallete,10,5)*7;
    }else if(bg_mode==6 ||bg_mode==7){
      //Palette 0 is taken as the background
    }else if (bg_mode<3){              
      for(int bg = 3; bg>=0;--bg){
        bool rot_scale = false;
        if(bg_mode>=1&&bg>=2)rot_scale = true;
        if((bg<2&&bg_mode==2)||(bg==3&&bg_mode==1))continue;
        bool bg_en = SB_BFE(dispcnt,8+bg,1);
        if(!bg_en)continue;
        uint16_t bgcnt = gba_read16(gba, GBA_BG0CNT+bg*2);
        int priority = SB_BFE(bgcnt,0,2);
        if(priority>bg_priority)continue;
        int character_base = SB_BFE(bgcnt,2,2);
        bool mosaic = SB_BFE(bgcnt,6,1);
        bool colors = SB_BFE(bgcnt,7,1);
        int screen_base = SB_BFE(bgcnt,8,5);
        bool display_overflow =SB_BFE(bgcnt,13,1);
        int screen_size = SB_BFE(bgcnt,14,2);

        int screen_base_addr =    0x6000000 + screen_base*2048;
        int character_base_addr = 0x6000000 + character_base*16*1024;

        int screen_size_x = (screen_size&1)?512:256;
        int screen_size_y = (screen_size>=2)?512:256;
                            
        
        uint16_t hoff = gba_read16(gba,GBA_BG0HOFS+bg*4)&0x1ff;
        uint16_t voff = gba_read16(gba,GBA_BG0VOFS+bg*4)&0x1ff;
        
        if(rot_scale){
          switch(screen_size){
            case 0: screen_size_x=screen_size_y=16*8;break;
            case 1: screen_size_x=screen_size_y=32*8;break;
            case 2: screen_size_x=screen_size_y=64*8;break;
            case 3: screen_size_x=screen_size_y=128*8;break;
          }
          colors = true;
        }
        int bg_x = (hoff+lcd_x);
        int bg_y = (voff+lcd_y);
        if(bg<2||display_overflow==1){
          bg_x = bg_x%screen_size_x;
          bg_y = bg_y%screen_size_y;
        }
        if(bg_x<0||bg_x>screen_size_x||bg_y<0||bg_y>screen_size_y)continue;
        if(rot_scale){
          int32_t bgx = gba_read32(gba,GBA_BG2X+(bg-2)*0x10);
          int32_t bgy = gba_read32(gba,GBA_BG2Y+(bg-2)*0x10);
          
          //Convert signed magnitude to 2's complement
          bgx = SB_BFE(bgx,0,27)*(SB_BFE(bgx,27,1)?-1:1);
          bgy = SB_BFE(bgy,0,27)*(SB_BFE(bgy,27,1)?-1:1);

          int32_t a = gba_read16(gba,GBA_BG2PA+(bg-2)*0x10);
          int32_t b = gba_read16(gba,GBA_BG2PB+(bg-2)*0x10);
          int32_t c = gba_read16(gba,GBA_BG2PC+(bg-2)*0x10);
          int32_t d = gba_read16(gba,GBA_BG2PD+(bg-2)*0x10);
 
          //Convert signed magnitude to 2's complement
          a = SB_BFE(a,0,15)*(SB_BFE(a,15,1)?-1:1);
          b = SB_BFE(b,0,15)*(SB_BFE(b,15,1)?-1:1);
          c = SB_BFE(c,0,15)*(SB_BFE(c,15,1)?-1:1);
          d = SB_BFE(d,0,15)*(SB_BFE(d,15,1)?-1:1);

          // Shift lcd_coords into fixed point
          int64_t x1 = lcd_x<<8;
          int64_t y1 = lcd_y<<8;
          int64_t x2 = a*(x1-bgx) + b*(y1-bgy) + (bgx<<8);
          int64_t y2 = c*(x1-bgx) + d*(y1-bgy) + (bgy<<8);

          bg_x = (x2>>16)%screen_size_x;
          bg_y = (y2>>16)%screen_size_y;

          bg_x = (x1+bgx)>>8;
          bg_y = (y1+bgy)>>8;
                                              
        }
        int bg_tile_x = bg_x/8;
        int bg_tile_y = bg_y/8;

        int tile_off = bg_tile_y*(screen_size_x/8)+bg_tile_x;

        uint16_t tile_data =0;
        if(rot_scale)tile_data=gba_read8(gba,screen_base_addr+tile_off);
        else{
          int tile_off = (bg_tile_y%32)*32+(bg_tile_x%32);
          if(bg_tile_x>=32)tile_off+=32*32;
          if(bg_tile_y>=32)tile_off+=32*32*2;
          tile_data=gba_read16(gba,screen_base_addr+tile_off*2);
        }
        int tile_id = SB_BFE(tile_data,0,10);
        int h_flip = SB_BFE(tile_data,10,1);
        int v_flip = SB_BFE(tile_data,11,1);
        int palette = SB_BFE(tile_data,12,4);

        int px = bg_x%8;
        int py = bg_y%8;
        
        if(h_flip)px=7-px;
        if(v_flip)py=7-py;

        uint8_t tile_d=tile_id;
        if(colors==false){
          tile_d=gba_read8(gba,character_base_addr+tile_id*8*4+px/2+py*4);
          tile_d= (tile_d>>((px&1)?4:0))&0xf;
          if(tile_d==0)continue;
          tile_d+=palette*16;
        }else{
          tile_d=gba_read8(gba,character_base_addr+tile_id*8*8+px+py*8);
        }

        uint8_t pallete_id = tile_d;
        if(pallete_id==0)continue;
        uint16_t col = gba_read16(gba, GBA_BG_PALETTE+pallete_id*2);
                        
        bg_priority = priority;
        r = SB_BFE(col,0,5)*7;
        g = SB_BFE(col,5,5)*7;
        b = SB_BFE(col,10,5)*7;
      }
    }else if(bg_mode!=0){
      printf("Unsupported background mode: %d\n",bg_mode);
    }
    gba->scanline_priority[lcd_x] = bg_priority;      
    gba->framebuffer[p*3+0] = r;
    gba->framebuffer[p*3+1] = g;
    gba->framebuffer[p*3+2] = b;  
  }
  //Render sprites over scanline when it completes
  if(lcd_y<160 && lcd_x == 240){
    // Slowest OBJ code in the west
    for(int o=127;o>=0;--o){
      uint16_t attr0 = gba_read16(gba, GBA_OAM+o*8+0);
      uint16_t attr1 = gba_read16(gba, GBA_OAM+o*8+2);
      uint16_t attr2 = gba_read16(gba, GBA_OAM+o*8+4);
      //Attr0
      uint8_t y_coord = SB_BFE(attr0,0,8);
      bool rot_scale =  SB_BFE(attr0,8,1);
      bool double_size = SB_BFE(attr0,9,1)&&rot_scale;
      bool obj_disable = SB_BFE(attr0,9,1)&&!rot_scale;
      if(obj_disable) continue; 
      int obj_mode = SB_BFE(attr0,10,2); //(0=Normal, 1=Semi-Transparent, 2=OBJ Window, 3=Prohibited)
      bool mosaic  = SB_BFE(attr0,12,1);
      bool colors_or_palettes = SB_BFE(attr0,13,1);
      int obj_shape = SB_BFE(attr0,14,2);//(0=Square,1=Horizontal,2=Vertical,3=Prohibited)
      //Attr1
      int16_t x_coord = SB_BFE(attr1,0,9);
      
      if (SB_BFE(x_coord,8,1))x_coord|=0xfe00;

      int rotscale_param = SB_BFE(attr1,9,5);
      bool h_flip = SB_BFE(attr1,12,1)&&!rot_scale;
      bool v_flip = SB_BFE(attr1,13,1)&&!rot_scale;
      int obj_size = SB_BFE(attr1,14,2);
      // Size  Square   Horizontal  Vertical
      // 0     8x8      16x8        8x16
      // 1     16x16    32x8        8x32
      // 2     32x32    32x16       16x32
      // 3     64x64    64x32       32x64
      int xsize_lookup[4][4]={
        {8,16,8,0},
        {16,32,8,0},
        {32,32,16,0},
        {64,64,32,0}
      };
      int ysize_lookup[4][4]={
        {8,8,16,0},
        {16,8,32,0},
        {32,16,32,0},
        {64,32,64,0}
      }; 

      int x_size = xsize_lookup[obj_size][obj_shape];
      int y_size = ysize_lookup[obj_size][obj_shape];
      //Attr2
      int tile_base = SB_BFE(attr2,0,10);
      // Always place sprites as the highest priority
      int priority = SB_BFE(attr2,10,2);
      int palette = SB_BFE(attr2,12,4);

      if(lcd_y>=y_coord && lcd_y<y_coord+y_size){
        int x_start = x_coord>=0?x_coord:0;
        int x_end   = x_coord+x_size<240?x_coord+x_size:240;
        for(int x = x_start; x< x_end;++x){
          int tiles_width = x_size/8;
          int tiles_height= y_size/8;
          int sx = x-x_coord;
          int sy = lcd_y-y_coord;
          
          if(h_flip)sx=x_size-sx-1;
          if(v_flip)sy=y_size-sy-1;
                      
          int tx = sx%8;
          int ty = sy%8;
          
          int y_tile_stride = obj_vram_map_2d? 32 : x_size/8;
          int tile = tile_base + sx/8+(sy/8)*y_tile_stride;
          uint8_t palette_id;
          if(colors_or_palettes==false){
            palette_id=gba_read8(gba,GBA_OBJ_TILES+tile*8*4+tx/2+ty*4);
            palette_id= (palette_id>>((tx&1)?4:0))&0xf;
            if(palette_id==0)continue;
            palette_id+=palette*16;
          }else{
            palette_id=gba_read8(gba,GBA_OBJ_TILES+tile*8*8+tx+ty*8);
          }

          if(palette_id==0)continue;
          uint16_t col = gba_read16(gba, GBA_OBJ_PALETTE+palette_id*2);

          int r = SB_BFE(col,0,5)*7;
          int g = SB_BFE(col,5,5)*7;
          int b = SB_BFE(col,10,5)*7;           
          int p = x+lcd_y*240; 
          if(gba->scanline_priority[x]<priority)continue; 
          gba->framebuffer[p*3+0] = r;
          gba->framebuffer[p*3+1] = g;
          gba->framebuffer[p*3+2] = b;  
        }
      }
    }
  }
  uint32_t new_if = gba_read16(gba,GBA_IF); 
  uint32_t int_en = gba_read16(gba,GBA_IE);
  if(vblank!=gba->ppu.last_vblank){
    if(vblank&& SB_BFE(int_en,GBA_INT_LCD_VBLANK,1)) new_if|= 1<< GBA_INT_LCD_VBLANK; 
  }
  if(hblank!=gba->ppu.last_hblank){
    if(hblank&& SB_BFE(int_en,GBA_INT_LCD_HBLANK,1)) new_if|= 1<< GBA_INT_LCD_HBLANK; 
  }
  if(lcd_y != gba->ppu.last_lcd_y){
    if(lcd_y==vcount_cmp) new_if |= 1<<GBA_INT_LCD_VCOUNT;
  }
  gba->ppu.last_vblank = vblank;
  gba->ppu.last_hblank = hblank;
  gba->ppu.last_lcd_y  = lcd_y;

  gba_store16(gba,GBA_IF,new_if&int_en);

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
bool gba_tick_dma(gba_t*gba){
  bool skip_cpu = false;
  for(int i=0;i<4;++i){
    uint16_t cnt_h=gba_read16(gba, GBA_DMA0CNT_H+12*i);
    bool enable = SB_BFE(cnt_h,15,1);
    if(enable){
      uint32_t src = gba_read32(gba,GBA_DMA0SAD+12*i);
      uint32_t dst = gba_read32(gba,GBA_DMA0DAD+12*i);
      uint32_t cnt = gba_read16(gba,GBA_DMA0CNT_L+12*i);
      if(i!=3)cnt&=0x3fff;
      if(cnt==0)cnt = i==3? 0x10000: 0x4000;
      int  dst_addr_ctl = SB_BFE(cnt_h,5,2); // 0: incr 1: decr 2: fixed 3: incr reload
      int  src_addr_ctl = SB_BFE(cnt_h,7,2); // 0: incr 1: decr 2: fixed 3: not allowed
      bool dma_repeat = SB_BFE(cnt_h,9,1); 
      bool type = SB_BFE(cnt_h,10,1); // 0: 16b 1:32b
      int  mode = SB_BFE(cnt_h,12,2);
      bool irq_enable = SB_BFE(cnt_h,14,1);

      int transfer_bytes = type? 4:2; 
      if(gba->dma[i].last_enable==false&&dst_addr_ctl==3){    
        dst +=cnt*transfer_bytes;
        gba_store32(gba,GBA_DMA0DAD+12*i,dst);
      }
      bool last_vblank = gba->dma[i].last_vblank;
      bool last_hblank = gba->dma[i].last_hblank;
      gba->dma[i].last_vblank = gba->ppu.last_vblank;
      gba->dma[i].last_hblank = gba->ppu.last_hblank;
      if(mode ==1 && !(gba->ppu.last_vblank&&!last_vblank)) continue; 
      if(mode ==2 && !(gba->ppu.last_hblank&&!last_hblank)) continue; 

      int src_dir = 1;
      if(src_addr_ctl==1)src_dir=-1;
      if(src_addr_ctl==2)src_dir=0;
      
      int dst_dir = 1;
      if(dst_addr_ctl==1)dst_dir=-1;
      if(dst_addr_ctl==2)dst_dir=0;
       
      //printf("DMA%d: src:%08x dst:%08x len:%04x type:%d mode:%d repeat:%d irq:%d dstct:%d srcctl:%d\n",i,src,dst,cnt, type,mode,dma_repeat,irq_enable,dst_addr_ctl,src_addr_ctl);
      for(int x=0;x<cnt;++x){
        if(type)gba_store32(gba,dst+x*4*dst_dir,gba_read32(gba,src+x*4*src_dir));
        else gba_store16(gba,dst+x*2*dst_dir,gba_read16(gba,src+x*2*src_dir));
      }
      if(dst_addr_ctl==0)     dst+=cnt*transfer_bytes;
      else if(dst_addr_ctl==1)dst-=cnt*transfer_bytes;
      if(src_addr_ctl==0)     src+=cnt*transfer_bytes;
      else if(src_addr_ctl==1)src-=cnt*transfer_bytes;
       
      
      gba_store32(gba,GBA_DMA0DAD+12*i,dst);
      gba_store32(gba,GBA_DMA0SAD+12*i,src);
      
      if(irq_enable){
        uint16_t if_val = gba_read16(gba,GBA_IF);
        uint16_t ie_val = gba_read16(gba,GBA_IE);
        uint16_t if_bit = 1<<(GBA_INT_DMA0+i);
        if(ie_val & if_bit){
          if_val |= if_bit;
          gba_store16(gba,GBA_IF,if_val);
        }
      }
      if(!dma_repeat||mode==0||mode==3){
        cnt_h&=0x7fff;
      }
      skip_cpu = true;
      //gba_store16(gba, GBA_DMA0CNT_L+12*i,0);
      gba_store16(gba, GBA_DMA0CNT_H+12*i,cnt_h);
    }
    gba->dma[i].last_enable = enable;
  }
  return skip_cpu; 
}                                              
void gba_tick_timers(gba_t* gba){
  bool last_timer_overflow = false; 
  for(int t=0;t<4;++t){ 
    uint16_t tm_cnt_h = gba_read16(gba,GBA_TM0CNT_H+t*4);
    bool enable = SB_BFE(tm_cnt_h,7,1);
    if(enable){
      uint16_t prescale = SB_BFE(tm_cnt_h,0,2);
      bool count_up     = SB_BFE(tm_cnt_h,2,1);
      bool irq_en       = SB_BFE(tm_cnt_h,6,1);
      uint16_t value = gba_read16(gba,GBA_TM0CNT_L+t*4);
      if(enable!=gba->timers[t].last_enable){
        value = gba->timers[t].reload_value;
        gba->timers[t].prescaler_timer = 0; 
      }
      
      if(count_up){
        if(last_timer_overflow){
          value+=1;
          last_timer_overflow =value==0;
        }
      }else{
        last_timer_overflow=false;
        const int prescaler_lookup[]={1,64,256,1024};
        int prescaler_compare = prescaler_lookup[prescale];
        if(gba->timers[t].prescaler_timer>=prescaler_compare){
          gba->timers[t].prescaler_timer = 0; 
          if(value==0){
            last_timer_overflow=true;
            value = gba->timers[t].reload_value;
          }else --value;
        }
        gba->timers[t].prescaler_timer++;
      }
      if(last_timer_overflow && irq_en){
        
        uint16_t if_val = gba_read16(gba,GBA_IF);
        uint16_t ie_val = gba_read16(gba,GBA_IE);
        uint16_t if_bit = 1<<(GBA_INT_TIMER0+t);
        if(ie_val & if_bit){
          if_val |= if_bit;
          gba_store16(gba,GBA_IF,if_val);
        }
      }
      gba_store16(gba,GBA_TM0CNT_L+t*4,value);
    }else last_timer_overflow=false;
  }
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
      bool tick_dma = gba_tick_dma(gba);
      if(!tick_dma){
        uint32_t ime = gba_read32(gba,GBA_IME);
        uint16_t int_if = gba_read16(gba,GBA_IF);
        uint16_t int_ie = gba_read16(gba,GBA_IE);
        if(SB_BFE(ime,0,1)==1){
          arm7_process_interrupts(&gba->cpu, int_if&int_ie);
        }

        uint8_t haltcnt = gba_read8(gba,GBA_HALTCNT);
        if(SB_BFE(haltcnt,7,1)){
          if(int_if&int_ie)gba_store8(gba,GBA_HALTCNT,haltcnt&0x7f);
        }else{
          //flash stub
          gba_store8(gba,0x0E000001,0x13);
          gba_store8(gba,0x0E000000,0x62);
          arm7_exec_instruction(&gba->cpu);
        }
      }
      gba_tick_ppu(gba,1);
      gba_tick_timers(gba);
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
  gba->cpu.registers[R13_und] = 0x00000000;
  gba->cpu.registers[PC]= 0x8000000; 
  gba->cpu.registers[CPSR]= 0x000000df; 
  memcpy(gba->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  gba->mem.openbus_word = gba->mem.cart_rom[0];
  
  gba_store16(gba,0x04000088,512);
  gba_store32(gba,0x040000DC,0x84000000);
}

#endif
