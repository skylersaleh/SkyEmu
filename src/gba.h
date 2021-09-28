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
#define GBA_BG_PALETTE  0x00000000                    
#define GBA_OBJ_PALETTE 0x00000200                    
#define GBA_OBJ_TILES0_2   0x00010000
#define GBA_OBJ_TILES3_5   0x00014000
#define GBA_OAM         0x07000000

#define GBA_BACKUP_NONE        0
#define GBA_BACKUP_EEPROM      1
#define GBA_BACKUP_EEPROM_512B 2
#define GBA_BACKUP_EEPROM_8KB  3
#define GBA_BACKUP_SRAM        4
#define GBA_BACKUP_FLASH_64K   5 
#define GBA_BACKUP_FLASH_128K  6  

typedef struct {     
  uint8_t bios[16*1024];
  uint8_t wram0[256*1024];
  uint8_t wram1[32*1024];
  uint8_t io[1024];
  uint8_t palette[1024];
  uint8_t vram[128*1024];
  uint8_t oam[1024];
  uint8_t cart_rom[32*1024*1024];
  uint8_t cart_backup[128*1024];
  uint8_t flash_chip_id[4];
  uint32_t openbus_word;
  uint32_t eeprom_word; 
  uint32_t eeprom_state; 
  uint32_t requests;
  uint32_t last_bios_data;
  uint32_t cartopen_bus; 
} gba_mem_t;

typedef struct {
  char title[13];
  char save_file_path[SB_FILE_PATH_SIZE];  
  unsigned rom_size; 
  uint8_t backup_type;
  bool backup_is_dirty;
  bool in_chip_id_mode; 
  int flash_state;
  int flash_bank; 
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
  uint32_t mmio_deferred_ticks; 
  uint32_t master_timer; 
  bool halt; 
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
static inline void gba_process_flash_state_machine(gba_t* gba, unsigned baddr, uint8_t data){
  #define FLASH_DEFAULT 0x0
  #define FLASH_RECV_AA 0x1
  #define FLASH_RECV_55 0x2
  #define FLASH_ERASE_RECV_AA 0x3
  #define FLASH_ERASE_RECV_55 0x4

  #define FLASH_ENTER_CHIP_ID 0x90 
  #define FLASH_EXIT_CHIP_ID  0xF0 
  #define FLASH_PREP_ERASE    0x80
  #define FLASH_ERASE_CHIP 0x10 
  #define FLASH_ERASE_4KB 0x30 
  #define FLASH_WRITE_BYTE 0xA0
  #define FLASH_SET_BANK 0xB0
  int state = gba->cart.flash_state;
  if(state!=FLASH_DEFAULT) printf("Flash state %02x\n",gba->cart.flash_state);

  gba->cart.flash_state=FLASH_DEFAULT;
  baddr&=0xffff;
  switch(state){
    default: 
      printf("Unknown flash state %02x\n",gba->cart.flash_state);
    case FLASH_DEFAULT:
      if(baddr==0x5555 && data == 0xAA) gba->cart.flash_state = FLASH_RECV_AA;
      break;
    case FLASH_RECV_AA:
      if(baddr==0x2AAA && data == 0x55) gba->cart.flash_state = FLASH_RECV_55;
      break;
    case FLASH_RECV_55:
      if(baddr==0x5555){
        // Process command
        switch(data){
          case FLASH_ENTER_CHIP_ID:gba->cart.in_chip_id_mode = true; break;
          case FLASH_EXIT_CHIP_ID: gba->cart.in_chip_id_mode = false; break;
          case FLASH_PREP_ERASE:   gba->cart.flash_state = FLASH_PREP_ERASE; break;
          case FLASH_WRITE_BYTE:   gba->cart.flash_state = FLASH_WRITE_BYTE; break;
          case FLASH_SET_BANK:     gba->cart.flash_state = FLASH_SET_BANK; break;
          default: printf("Unknown flash command: %02x\n",data);break;
        }
      }
      break;
    case FLASH_PREP_ERASE:
      if(baddr==0x5555 && data == 0xAA) gba->cart.flash_state = FLASH_ERASE_RECV_AA;
      break;
    case FLASH_ERASE_RECV_AA:
      if(baddr==0x2AAA && data == 0x55) gba->cart.flash_state = FLASH_ERASE_RECV_55;
      break;
    case FLASH_ERASE_RECV_55:
      if(baddr==0x5555|| data ==FLASH_ERASE_4KB){
        int size = gba->cart.backup_type == GBA_BACKUP_FLASH_64K? 64*1024 : 128*1024;
        int erase_4k_off = gba->cart.flash_bank*64*1024+SB_BFE(baddr,12,4)*4096;
        // Process command
        switch(data){
          case FLASH_ERASE_CHIP:for(int i=0;i<size;++i)gba->mem.cart_backup[i]=0xff; break;
          case FLASH_ERASE_4KB:for(int i=0;i<4096;++i)gba->mem.cart_backup[erase_4k_off+i]=0xff; break;
          default: printf("Unknown flash erase command: %02x\n",data);break;
        }
        gba->cart.backup_is_dirty=true;
      }
      break;
    case FLASH_WRITE_BYTE:
      gba->mem.cart_backup[gba->cart.flash_bank*64*1024+baddr] &= data; 
      gba->cart.backup_is_dirty=true;
      break;
    case FLASH_SET_BANK:
      gba->cart.flash_bank = data&1; 
      break;
  }
}
static inline void gba_process_backup_write(gba_t*gba, unsigned baddr, uint32_t data){
  if(gba->cart.backup_type==GBA_BACKUP_FLASH_64K||gba->cart.backup_type==GBA_BACKUP_FLASH_128K){
    gba_process_flash_state_machine(gba,baddr,data);
  }else if(gba->cart.backup_type==GBA_BACKUP_SRAM){
    if(gba->mem.cart_backup[baddr&0x7fff]!=(data&0xff)){
      gba->mem.cart_backup[baddr&0x7fff]=data&0xff; 
      gba->cart.backup_is_dirty=true;
    }
  }
}
static inline void gba_store32(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t *val=gba_dword_lookup(gba,baddr,&read_only);
  if(!read_only)*val= data;
}
static inline void gba_store16(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,1,1);
  if(!read_only)((uint16_t*)val)[offset]=data; 
}
static inline void gba_store8(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t *val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,0,2);
  if(!read_only)((uint8_t*)val)[offset]=data; 
} 
static inline void gba_io_store8(gba_t*gba, unsigned baddr, uint8_t data){gba->mem.io[baddr&0xffff]=data;}
static inline void gba_io_store16(gba_t*gba, unsigned baddr, uint16_t data){*(uint16_t*)(gba->mem.io+(baddr&0xffff))=data;}
static inline void gba_io_store32(gba_t*gba, unsigned baddr, uint32_t data){*(uint32_t*)(gba->mem.io+(baddr&0xffff))=data;}

static inline uint8_t  gba_io_read8(gba_t*gba, unsigned baddr) {return gba->mem.io[baddr&0xffff];}
static inline uint16_t gba_io_read16(gba_t*gba, unsigned baddr){return *(uint16_t*)(gba->mem.io+(baddr&0xffff));}
static inline uint32_t gba_io_read32(gba_t*gba, unsigned baddr){return *(uint32_t*)(gba->mem.io+(baddr&0xffff));}

static inline void gba_compute_access_cycles(void*user_data, uint32_t address,int request_size/*0: 1B,1: 2B,3: 4B*/){
  // TODO: Make the waitstate for the ROM configureable 
  const int wait_state_table[16*3]={
    1,1,1, //0x00 (bios)
    1,1,1, //0x01 (bios)
    3,3,6, //0x02 (256k WRAM)
    1,1,1, //0x03 (32k WRAM)
    1,1,1, //0x04 (IO)
    1,1,2, //0x05 (BG/OBJ Palette)
    1,1,2, //0x06 (VRAM)
    1,1,1, //0x07 (OAM)
    5,5,8, //0x08 (GAMEPAK ROM)
    5,5,8, //0x09 (GAMEPAK ROM)
    5,5,8, //0x0A (GAMEPAK ROM)
    5,5,8, //0x0B (GAMEPAK ROM)
    5,5,8, //0x0C (GAMEPAK ROM)
    5,5,8, //0x0D (GAMEPAK ROM)
    5,5,5, //0x0E (GAMEPAK SRAM)
    1,1,1, //0x0F (unused)
  };
  ((gba_t*)user_data)->mem.requests+=wait_state_table[SB_BFE(address,24,4)*3+request_size];
}
// Memory IO functions for the emulated CPU                  
static inline uint32_t arm7_read32(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,2);
  uint32_t value = gba_read32((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x3)*8);
}
static inline uint32_t arm7_read16(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,1);
  uint16_t value = gba_read16((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x1)*8);
}
//Used to process special behavior triggered by MMIO write
static bool gba_process_mmio_write(gba_t *gba, uint32_t address, uint32_t data, int req_size_bytes);

static uint8_t arm7_read8(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,0);
  return gba_read8((gba_t*)user_data,address);
}
static void arm7_write32(void* user_data, uint32_t address, uint32_t data){
  gba_compute_access_cycles(user_data,address,2);
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,4))return;
  }
  gba_store32((gba_t*)user_data,address,data);
}
static void arm7_write16(void* user_data, uint32_t address, uint16_t data){
  gba_compute_access_cycles(user_data,address,1);
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,2))return; 
  }
  gba_store16((gba_t*)user_data,address,data);
}
static void arm7_write8(void* user_data, uint32_t address, uint8_t data)  {
  gba_compute_access_cycles(user_data,address,0);
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,1))return; 
  }
  gba_store8((gba_t*)user_data,address,data);
}
// Try to load a GBA rom, return false on invalid rom
bool gba_load_rom(gba_t* gba, const char * filename, const char* save_file);
void gba_reset(gba_t*gba);
 
uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr,bool*read_only){
  baddr&=0xfffffffc;
  uint32_t *ret = &gba->mem.openbus_word;
  *read_only= false; 
  if(baddr<0x4000){ *read_only=true;ret= (uint32_t*)(gba->mem.bios+baddr-0x0);}
  else if(baddr>=0x2000000 && baddr<=0x2FFFFFF )ret = (uint32_t*)(gba->mem.wram0+(baddr&0x3ffff));
  else if(baddr>=0x3000000 && baddr<=0x3ffffff )ret = (uint32_t*)(gba->mem.wram1+(baddr&0x7fff));
  else if(baddr>=0x4000000 && baddr<=0x40003FE ){
    ret = (uint32_t*)(gba->mem.io+baddr-0x4000000);
  }else if(baddr>=0x5000000 && baddr<=0x5ffffff )ret = (uint32_t*)(gba->mem.palette+(baddr&0x3ff));
  else if(baddr>=0x6000000 && baddr<=0x6ffffff ){
    if(baddr&0x10000)ret = (uint32_t*)(gba->mem.vram+(baddr&0x07fff)+0x10000);
    else ret = (uint32_t*)(gba->mem.vram+(baddr&0x1ffff));
  }else if(baddr>=0x7000000 && baddr<=0x7ffffff )ret = (uint32_t*)(gba->mem.oam+(baddr&0x3ff));
  else if(baddr>=0x8000000 && baddr<=0xDFFFFFF ){
    int addr = baddr&0x1ffffff;
    *read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+addr);
    if(addr>gba->cart.rom_size){
      ret = (uint32_t*)(&gba->mem.cartopen_bus);
      *ret = ((addr/2)&0xffff)|(((addr/2+1)&0xffff)<<16);
    }
    if(addr>=gba->cart.rom_size||addr>=0x01ffff00){
      if(addr>=0x01000000&&gba->cart.backup_type>=GBA_BACKUP_EEPROM&&gba->cart.backup_type<=GBA_BACKUP_EEPROM_8KB){
        ret = (uint32_t*)&gba->mem.eeprom_word;
        gba->mem.eeprom_word=0xffffffff;
      }
    }
  }
  else if(baddr>=0xE000000 && baddr<=0xEffffff ){
    if(gba->cart.backup_type==GBA_BACKUP_SRAM) ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0x7fff));
    else if(gba->cart.backup_type==GBA_BACKUP_EEPROM) ret = (uint32_t*)&gba->mem.eeprom_word;
    else{
      //Flash
      if(gba->cart.in_chip_id_mode&&baddr<=0xE000001) ret = (uint32_t*)(gba->mem.flash_chip_id);
      else ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0xffff)+gba->cart.flash_bank*64*1024);
    }
    
  }
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
    uint16_t IE = gba_io_read16(gba,GBA_IE);
    uint16_t IF = gba_io_read16(gba,GBA_IF);
  
    IE = ((IE&~word_mask)|(word_data&word_mask))>>0;
    IF &= ~((word_data)>>16);
    gba_io_store16(gba,GBA_IE,IE);
    gba_io_store16(gba,GBA_IF,IF);

    return true; 
  }else if(address_u32 == GBA_TM0CNT_L||address_u32==GBA_TM1CNT_L||address_u32==GBA_TM2CNT_L||address_u32==GBA_TM3CNT_L){
    if(word_mask&0xffff){
      int timer_off = (address_u32-GBA_TM0CNT_L)/4;
      gba->timers[timer_off+0].reload_value =word_data&(word_mask&0xffff);
    }
    if(word_mask&0xffff0000){
      gba_store16(gba,address_u32+2,(word_data>>16)&0xffff);
    }
    return true;
  }else if(address==GBA_HALTCNT){
    gba->halt = true;
  }
  return false;
}
bool gba_search_rom_for_string(gba_t* gba, const char* str){
  for(int b = 0; b< gba->cart.rom_size;++b){
    int str_off = 0; 
    bool matches = true; 
    while(str[str_off] && matches){
      if(str[str_off]!=gba->mem.cart_rom[b+str_off])matches = false;
      if(b+str_off>=gba->cart.rom_size)matches=false; 
      ++str_off;
    }
    if(matches)return true;
  }
  return false; 
}
bool gba_load_rom(gba_t* gba, const char* filename, const char* save_file){

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

  strncpy(gba->cart.save_file_path,save_file,SB_FILE_PATH_SIZE);
  gba->cart.save_file_path[SB_FILE_PATH_SIZE-1]=0;

  memcpy(gba->cart.title,gba->mem.cart_rom+0x0A0,12);
  gba->cart.title[12]=0;

  gba->cart.backup_type = GBA_BACKUP_NONE;
  if(gba_search_rom_for_string(gba,"EEPROM_"))  gba->cart.backup_type = GBA_BACKUP_EEPROM;
  if(gba_search_rom_for_string(gba,"SRAM_"))    gba->cart.backup_type = GBA_BACKUP_SRAM;
  if(gba_search_rom_for_string(gba,"FLASH_"))   gba->cart.backup_type = GBA_BACKUP_FLASH_64K;
  if(gba_search_rom_for_string(gba,"FLASH512_"))gba->cart.backup_type = GBA_BACKUP_FLASH_64K;
  if(gba_search_rom_for_string(gba,"FLASH1M_")) gba->cart.backup_type = GBA_BACKUP_FLASH_128K;

  // Load save if available
  if(FileExists(save_file)){
    unsigned int bytes=0;
    unsigned char* data = LoadFileData(save_file,&bytes);
    printf("Loaded save file: %s, bytes: %d\n",save_file,bytes);
    if(bytes>=128*1024)bytes=128*1024;
    memcpy(gba->mem.cart_backup, data, bytes);
    UnloadFileData(data);
  }else{
    printf("Could not find save file: %s\n",save_file);
    for(int i=0;i<sizeof(gba->mem.cart_backup);++i) gba->mem.cart_backup[i]=0;
  }

  // Setup flash chip id (this is not used if the cartridge does not have flash backup storage)
  gba->mem.flash_chip_id[1]=0x13;
  gba->mem.flash_chip_id[0]=0x62;
  return true; 
}  
    
void gba_tick_ppu(gba_t* gba, int cycles, bool skip_render){
  gba->ppu.scan_clock+=cycles;
  if(gba->ppu.scan_clock%4)return;
  if(gba->ppu.scan_clock>=280896)gba->ppu.scan_clock-=280896;

  //Make LCD-y increment during h-blank (fixes BEEG.gba)
  int lcd_y = (gba->ppu.scan_clock+46)/1232;
  int lcd_x = (gba->ppu.scan_clock%1232)/4;
  if(lcd_x==262||lcd_x==0||lcd_x==240){
    uint16_t disp_stat = gba_io_read16(gba, GBA_DISPSTAT)&~0x7;
    uint16_t vcount_cmp = SB_BFE(disp_stat,8,8);
    bool vblank = lcd_y>=160&&lcd_y<=227;
    bool hblank = lcd_x>=240&&lcd_y<160;
    disp_stat |= vblank ? 0x1: 0; 
    disp_stat |= hblank ? 0x2: 0;      
    disp_stat |= lcd_y==vcount_cmp ? 0x4: 0;   

    gba_io_store16(gba,GBA_DISPSTAT,disp_stat);
    uint32_t new_if = 0;
    if(hblank!=gba->ppu.last_hblank){
      gba->ppu.last_hblank = hblank;
      if(hblank) new_if|= (1<< GBA_INT_LCD_HBLANK); 
    }
    if(lcd_y != gba->ppu.last_lcd_y){
      if(vblank!=gba->ppu.last_vblank){
        gba->ppu.last_vblank = vblank;
        if(vblank) new_if|= (1<< GBA_INT_LCD_VBLANK); 
      }
      gba_io_store16(gba,GBA_VCOUNT,lcd_y);   
      gba->ppu.last_lcd_y  = lcd_y;
      if(lcd_y==vcount_cmp) {
        new_if |= (1<<GBA_INT_LCD_VCOUNT);
      }
    }
    if(new_if){
      new_if &= gba_io_read16(gba,GBA_IE);
      new_if |= gba_io_read16(gba,GBA_IF); 
      gba_io_store16(gba,GBA_IF,new_if);
    }
  }
  if(skip_render)return; 

  uint16_t dispcnt = gba_io_read16(gba, GBA_DISPCNT);
  int bg_mode = SB_BFE(dispcnt,0,3);
  int frame_sel = SB_BFE(dispcnt,4,1);
  int obj_vram_map_2d = !SB_BFE(dispcnt,6,1);
  int p = lcd_x+lcd_y*240;
  bool visible = lcd_x<240 && lcd_y<160;
  if(visible){
    uint16_t col = *(uint16_t*)(gba->mem.palette + GBA_BG_PALETTE+0*2);
    int bg_priority=4;
    if(bg_mode==6 ||bg_mode==7){
      //Palette 0 is taken as the background
    }else if (bg_mode<5){              
      for(int bg = 3; bg>=0;--bg){
        if((bg<2&&bg_mode==2)||(bg==3&&bg_mode==1)||(bg!=2&&bg_mode>=3))continue;
        bool bg_en = SB_BFE(dispcnt,8+bg,1);
        if(!bg_en)continue;
        bool rot_scale = bg_mode>=1&&bg>=2;
        uint16_t bgcnt = gba_io_read16(gba, GBA_BG0CNT+bg*2);
        int priority = SB_BFE(bgcnt,0,2);
        if(priority>bg_priority)continue;
        int character_base = SB_BFE(bgcnt,2,2);
        bool mosaic = SB_BFE(bgcnt,6,1);
        bool colors = SB_BFE(bgcnt,7,1);
        int screen_base = SB_BFE(bgcnt,8,5);
        bool display_overflow =SB_BFE(bgcnt,13,1);
        int screen_size = SB_BFE(bgcnt,14,2);

        int screen_size_x = (screen_size&1)?512:256;
        int screen_size_y = (screen_size>=2)?512:256;
        
        if(rot_scale){
          switch(screen_size){
            case 0: screen_size_x=screen_size_y=16*8;break;
            case 1: screen_size_x=screen_size_y=32*8;break;
            case 2: screen_size_x=screen_size_y=64*8;break;
            case 3: screen_size_x=screen_size_y=128*8;break;
          }
          if(bg_mode==3||bg_mode==4){
            screen_size_x=240;
            screen_size_y=160;
          }
          colors = true;
        }
        int bg_x = 0;
        int bg_y = 0;
        
        if(rot_scale){
          int32_t bgx = gba_io_read32(gba,GBA_BG2X+(bg-2)*0x10);
          int32_t bgy = gba_io_read32(gba,GBA_BG2Y+(bg-2)*0x10);
          
          bgx = SB_BFE(bgx,0,28);
          bgy = SB_BFE(bgy,0,28);

          bgx = (bgx<<4)>>4;
          bgy = (bgy<<4)>>4;

          int32_t a = (int16_t)gba_io_read16(gba,GBA_BG2PA+(bg-2)*0x10);
          int32_t b = (int16_t)gba_io_read16(gba,GBA_BG2PB+(bg-2)*0x10);
          int32_t c = (int16_t)gba_io_read16(gba,GBA_BG2PC+(bg-2)*0x10);
          int32_t d = (int16_t)gba_io_read16(gba,GBA_BG2PD+(bg-2)*0x10);

          // Shift lcd_coords into fixed point
          int64_t x1 = lcd_x<<8;
          int64_t y1 = lcd_y<<8;
          int64_t x2 = a*(x1-bgx) + b*(y1-bgy) + (bgx<<8)*2;
          int64_t y2 = c*(x1-bgx) + d*(y1-bgy) + (bgy<<8)*2;

          bg_x = (x2>>16);
          bg_y = (y2>>16);

          if(display_overflow==0){
            if(bg_x<0||bg_x>screen_size_x||bg_y<0||bg_y>screen_size_y)continue; 
          }else{
            bg_x%=screen_size_x;
            bg_y%=screen_size_y;
          }
                              
        }else{
          int16_t hoff = gba_io_read16(gba,GBA_BG0HOFS+bg*4)&0x1ff;
          int16_t voff = gba_io_read16(gba,GBA_BG0VOFS+bg*4)&0x1ff;
          
          hoff |= (hoff&0x100)?0xff00:0;
          voff |= (voff&0x100)?0xff00:0;
          bg_x = (hoff+lcd_x);
          bg_y = (voff+lcd_y);
        }
        if(bg_mode==3){
          int p = bg_x+bg_y*240;
          int addr = p*2; 
          col  = *(uint16_t*)(gba->mem.vram+addr);
        }else if(bg_mode==4){
          int p = bg_x+bg_y*240;
          int addr = p*1+0xA000*frame_sel; 
          uint8_t pallete_id = gba->mem.vram[addr];
          col = *(uint16_t*)(gba->mem.palette+GBA_BG_PALETTE+pallete_id*2);
        }else{
          bg_x = bg_x&(screen_size_x-1);
          bg_y = bg_y&(screen_size_y-1);
          int bg_tile_x = bg_x/8;
          int bg_tile_y = bg_y/8;

          int tile_off = bg_tile_y*(screen_size_x/8)+bg_tile_x;

          int screen_base_addr =    screen_base*2048;
          int character_base_addr = character_base*16*1024;

          uint16_t tile_data =0;

          int px = bg_x%8;
          int py = bg_y%8;

          if(rot_scale)tile_data=gba->mem.vram[screen_base_addr+tile_off];
          else{
            int tile_off = (bg_tile_y%32)*32+(bg_tile_x%32);
            if(bg_tile_x>=32)tile_off+=32*32;
            if(bg_tile_y>=32)tile_off+=32*32*(screen_size==3?2:1);
            tile_data=*(uint16_t*)(gba->mem.vram+screen_base_addr+tile_off*2);

            int h_flip = SB_BFE(tile_data,10,1);
            int v_flip = SB_BFE(tile_data,11,1);
            if(h_flip)px=7-px;
            if(v_flip)py=7-py;
          }
          int tile_id = SB_BFE(tile_data,0,10);
          int palette = SB_BFE(tile_data,12,4);

          uint8_t tile_d=tile_id;
          if(colors==false){
            tile_d=gba->mem.vram[character_base_addr+tile_id*8*4+px/2+py*4];
            tile_d= (tile_d>>((px&1)?4:0))&0xf;
            if(tile_d==0)continue;
            tile_d+=palette*16;
          }else{
            tile_d=gba->mem.vram[character_base_addr+tile_id*8*8+px+py*8];
          }
          uint8_t pallete_id = tile_d;
          if(pallete_id==0)continue;
          col = *(uint16_t*)(gba->mem.palette+GBA_BG_PALETTE+pallete_id*2);
        }          
        bg_priority = priority;
      }
    }else if(bg_mode!=0){
      printf("Unsupported background mode: %d\n",bg_mode);
    }
    gba->scanline_priority[lcd_x] = bg_priority;      
    gba->framebuffer[p*3+0] = SB_BFE(col,0,5)*7;
    gba->framebuffer[p*3+1] = SB_BFE(col,5,5)*7;
    gba->framebuffer[p*3+2] = SB_BFE(col,10,5)*7;  
  }
  //Render sprites over scanline when it completes
  if(lcd_y<160 && lcd_x == 240){
    // Slowest OBJ code in the west
    for(int o=127;o>=0;--o){
      uint16_t attr0 = *(uint16_t*)(gba->mem.oam+o*8+0);
      uint16_t attr1 = *(uint16_t*)(gba->mem.oam+o*8+2);
      uint16_t attr2 = *(uint16_t*)(gba->mem.oam+o*8+4);
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
      const int xsize_lookup[16]={
        8,16,8,0,
        16,32,8,0,
        32,32,16,0,
        64,64,32,0
      };
      const int ysize_lookup[16]={
        8,8,16,0,
        16,8,32,0,
        32,16,32,0,
        64,32,64,0
      }; 

      int x_size = xsize_lookup[obj_size*4+obj_shape];
      int y_size = ysize_lookup[obj_size*4+obj_shape];

      //Attr2
      int tile_base = SB_BFE(attr2,0,10);
      // Always place sprites as the highest priority
      int priority = SB_BFE(attr2,10,2);
      int palette = SB_BFE(attr2,12,4);

      if(((lcd_y-y_coord)&0xff) <y_size*(double_size?2:1)){
        int x_start = x_coord>=0?x_coord:0;
        int x_end   = x_coord+x_size*(double_size?2:1);
        if(x_end>=240)x_end=239;
        for(int x = x_start; x< x_end;++x){
          if(gba->scanline_priority[x]<priority)continue; 
          int sx = (x-x_coord);
          int sy = (lcd_y-y_coord)&0xff;
          if(rot_scale){
            uint32_t param_base = rotscale_param*0x20; 
            int32_t a = *(int16_t*)(gba->mem.oam+param_base+0x6);
            int32_t b = *(int16_t*)(gba->mem.oam+param_base+0xe);
            int32_t c = *(int16_t*)(gba->mem.oam+param_base+0x16);
            int32_t d = *(int16_t*)(gba->mem.oam+param_base+0x1e);
 
            int64_t x1 = sx<<8;
            int64_t y1 = sy<<8;
            int64_t objref_x = (x_size<<(double_size?8:7));
            int64_t objref_y = (y_size<<(double_size?8:7));
            
            int64_t x2 = a*(x1-objref_x) + b*(y1-objref_y)+(x_size<<15);
            int64_t y2 = c*(x1-objref_x) + d*(y1-objref_y)+(y_size<<15);

            sx = (x2>>16);
            sy = (y2>>16);
               
          }else{
            if(h_flip)sx=x_size-sx-1;
            if(v_flip)sy=y_size-sy-1;
          }
          if(sx>=x_size||sy>=y_size||sx<0||sy<0)continue;
          int tx = sx%8;
          int ty = sy%8;
                    
          int y_tile_stride = obj_vram_map_2d? colors_or_palettes? 16:32 : x_size/8;
          int tile = (colors_or_palettes? tile_base/2 : tile_base) + ((sx/8))+(sy/8)*y_tile_stride;
          
          uint8_t palette_id;
          int obj_tile_base = bg_mode<3? GBA_OBJ_TILES0_2 : GBA_OBJ_TILES3_5;
          if(colors_or_palettes==false){
            palette_id= gba->mem.vram[obj_tile_base+tile*8*4+tx/2+ty*4];
            palette_id= (palette_id>>((tx&1)?4:0))&0xf;
            if(palette_id==0)continue;
            palette_id+=palette*16;
          }else{
            palette_id=gba->mem.vram[obj_tile_base+tile*8*8+tx+ty*8];
          }

          if(palette_id==0)continue;
          uint16_t col = *(uint16_t*)(gba->mem.palette+GBA_OBJ_PALETTE+palette_id*2);

          int r = SB_BFE(col,0,5)*7;
          int g = SB_BFE(col,5,5)*7;
          int b = SB_BFE(col,10,5)*7;   

          int p = x+lcd_y*240; 
          gba->framebuffer[p*3+0] = r;
          gba->framebuffer[p*3+1] = g;
          gba->framebuffer[p*3+2] = b;  
        }
      }
    }
  }
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
  gba_io_store16(gba, GBA_KEYINPUT, reg_value);
}
int gba_tick_dma(gba_t*gba){
  int ticks =0;
  for(int i=0;i<4;++i){
    uint16_t cnt_h=gba_io_read16(gba, GBA_DMA0CNT_H+12*i);
    bool enable = SB_BFE(cnt_h,15,1);
    if(enable){
      
      int  dst_addr_ctl = SB_BFE(cnt_h,5,2); // 0: incr 1: decr 2: fixed 3: incr reload
      int  src_addr_ctl = SB_BFE(cnt_h,7,2); // 0: incr 1: decr 2: fixed 3: not allowed
      bool dma_repeat = SB_BFE(cnt_h,9,1); 
      bool type = SB_BFE(cnt_h,10,1); // 0: 16b 1:32b
      int  mode = SB_BFE(cnt_h,12,2);
      bool irq_enable = SB_BFE(cnt_h,14,1);
        
      int transfer_bytes = type? 4:2; 
      
      bool last_vblank = gba->dma[i].last_vblank;
      bool last_hblank = gba->dma[i].last_hblank;
      gba->dma[i].last_vblank = gba->ppu.last_vblank;
      gba->dma[i].last_hblank = gba->ppu.last_hblank;
      if(mode ==1 && !(gba->ppu.last_vblank&&!last_vblank)) continue; 
      if(mode ==2 && !(gba->ppu.last_hblank&&!last_hblank)) continue; 
    
      //if(mode==2){printf("Trigger Hblank DMA: %d->%d\n",last_hblank,gba->ppu.last_hblank);}
      int src_dir = 1;
      if(src_addr_ctl==1)src_dir=-1;
      else if(src_addr_ctl==2)src_dir=0;
      
      int dst_dir = 1;
      if(dst_addr_ctl==1)dst_dir=-1;
      else if(dst_addr_ctl==2)dst_dir=0;

      uint32_t src = gba_io_read32(gba,GBA_DMA0SAD+12*i);
      uint32_t dst = gba_io_read32(gba,GBA_DMA0DAD+12*i);
      uint32_t cnt = gba_io_read16(gba,GBA_DMA0CNT_L+12*i);

      if(i!=3)cnt&=0x3fff;
      if(cnt==0)cnt = i==3? 0x10000: 0x4000;

      //GBA Suite says that these need to be force aligned
      if(type){
        dst&=~3;
        src&=~3;
      }else{
        dst&=~1;
        src&=~1;
      }
       
      //printf("DMA%d: src:%08x dst:%08x len:%04x type:%d mode:%d repeat:%d irq:%d dstct:%d srcctl:%d\n",i,src,dst,cnt, type,mode,dma_repeat,irq_enable,dst_addr_ctl,src_addr_ctl);
      if(mode!=3){
        for(int x=0;x<cnt;++x){
          if(type)gba_store32(gba,dst+x*4*dst_dir,gba_read32(gba,src+x*4*src_dir));
          else gba_store16(gba,dst+x*2*dst_dir,gba_read16(gba,src+x*2*src_dir));
        }
      }
      ticks+=cnt;
      if(dst_addr_ctl==0)     dst+=cnt*transfer_bytes*dst_dir;
      else if(dst_addr_ctl==1)dst-=cnt*transfer_bytes;
      if(src_addr_ctl==0)     src+=cnt*transfer_bytes*src_dir;
      else if(src_addr_ctl==1)src-=cnt*transfer_bytes;
      
      gba_io_store32(gba,GBA_DMA0DAD+12*i,dst);
      gba_io_store32(gba,GBA_DMA0SAD+12*i,src);
      
      if(irq_enable){
        uint16_t if_val = gba_io_read16(gba,GBA_IF);
        uint16_t ie_val = gba_io_read16(gba,GBA_IE);
        uint16_t if_bit = 1<<(GBA_INT_DMA0+i);
        if(ie_val & if_bit){
          if_val |= if_bit;
          gba_io_store16(gba,GBA_IF,if_val);
        }
      }
      if(!dma_repeat||mode==0||mode==3){
        cnt_h&=0x7fff;
        gba_io_store16(gba, GBA_DMA0CNT_L+12*i,0);
      }
      gba_io_store16(gba, GBA_DMA0CNT_H+12*i,cnt_h);
    }
    gba->dma[i].last_enable = enable;
  }
  return ticks; 
}                                              
static void gba_tick_sio(gba_t* gba){
  //Just a stub for now;
  uint16_t siocnt = gba_io_read16(gba,GBA_SIOCNT);
  bool active = SB_BFE(siocnt,7,1);
  bool irq_enabled = SB_BFE(siocnt,14,1);
  if(active){
   
    if(irq_enabled){
      uint16_t if_val = gba_io_read16(gba,GBA_IF);
      uint16_t ie_val = gba_io_read16(gba,GBA_IE);
      uint16_t if_bit = 1<<(GBA_INT_SERIAL);
      if(ie_val & if_bit){
        if_val |= if_bit;
        gba_io_store16(gba,GBA_IF,if_val);
      }
    }
    siocnt&= ~(1<<7);
    gba_io_store16(gba,GBA_SIOCNT,siocnt);
  }
}
void gba_tick_timers(gba_t* gba, int ticks){
  int last_timer_overflow = 0; 
  for(int t=0;t<4;++t){ 
    uint16_t tm_cnt_h = gba_io_read16(gba,GBA_TM0CNT_H+t*4);
    bool enable = SB_BFE(tm_cnt_h,7,1);
    if(enable){
      uint16_t prescale = SB_BFE(tm_cnt_h,0,2);
      bool count_up     = SB_BFE(tm_cnt_h,2,1);
      bool irq_en       = SB_BFE(tm_cnt_h,6,1);
      uint16_t value = gba_io_read16(gba,GBA_TM0CNT_L+t*4);
      if(enable!=gba->timers[t].last_enable){
        value = gba->timers[t].reload_value;
        gba->timers[t].prescaler_timer = 0; 
        gba->timers[t].last_enable = enable;
      }
      
      if(count_up){
        if(last_timer_overflow){
          uint32_t old_value = value;
          value+=last_timer_overflow;
          last_timer_overflow =(old_value+last_timer_overflow)>>16;
        }
      }else{
        last_timer_overflow=0;
        int prescale_time = gba->timers[t].prescaler_timer;
        prescale_time+=ticks;
        const int prescaler_lookup[]={0,5,7,9};
        int prescale_duty = prescaler_lookup[prescale];

        int increment = prescale_time>>prescale_duty;
        prescale_time = prescale_time&((1<<prescale_duty)-1);
        int v = value+increment;
        while(v>0xffff){
          v=(v+gba->timers[t].reload_value)-0xffff;
          last_timer_overflow++;
        }
        value = v; 
        gba->timers[t].prescaler_timer=prescale_time;
      }
      if(last_timer_overflow && irq_en){
        uint16_t if_val = gba_io_read16(gba,GBA_IF);
        uint16_t ie_val = gba_io_read16(gba,GBA_IE);
        uint16_t if_bit = 1<<(GBA_INT_TIMER0+t);
        if(if_val){
          if_val |= if_bit&ie_val;
          gba_io_store16(gba,GBA_IF,if_val);
        }
      }
      gba_io_store16(gba,GBA_TM0CNT_L+t*4,value);
    }else last_timer_overflow=0;
  }
}
void gba_tick(sb_emu_state_t* emu, gba_t* gba){
  if(emu->run_mode == SB_MODE_RESET){
    emu->run_mode = SB_MODE_PAUSE;
  }
  int frames_to_render= gba->ppu.last_vblank?1:2; 

  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    gba_tick_keypad(&emu->joy,gba);
    int max_instructions = 280896;
    if(emu->step_instructions) max_instructions = emu->step_instructions;
    bool prev_vblank = gba->ppu.last_vblank; 
    for(int i = 0;i<max_instructions;++i){
      int ticks = gba_tick_dma(gba);
      if(!ticks){
        uint16_t int_if = gba_io_read16(gba,GBA_IF);
        uint16_t int_ie = gba_io_read16(gba,GBA_IE);

        if(gba->halt){
          if(int_if&int_ie)gba->halt = false;
          ticks=4;
        }else{
          uint32_t ime = gba_io_read32(gba,GBA_IME);
          if(SB_BFE(ime,0,1)==1)arm7_process_interrupts(&gba->cpu, int_if&int_ie);
          gba->mem.requests=1;
          arm7_exec_instruction(&gba->cpu);
          ticks = gba->mem.requests; 
        }
      }
      for(int t = 0;t<ticks;++t){
        gba_tick_ppu(gba,1,frames_to_render<=0);
        gba_tick_sio(gba);
      }
      gba_tick_timers(gba,ticks);

      bool breakpoint = gba->cpu.registers[PC]== emu->pc_breakpoint;
      breakpoint |= gba->cpu.trigger_breakpoint;
      if(breakpoint){emu->run_mode = SB_MODE_PAUSE; gba->cpu.trigger_breakpoint=false; break;}

      if(gba->ppu.last_vblank && !prev_vblank){
        emu->frame++;
        frames_to_render--;
        if(emu->step_instructions==0)break;
      }
      prev_vblank = gba->ppu.last_vblank;
    }
  }                  
  
  if(emu->run_mode == SB_MODE_STEP) emu->run_mode = SB_MODE_PAUSE; 
}

void gba_reset(gba_t*gba){
  *gba = (gba_t){0};
  gba->cpu = arm7_init(gba);
  bool skip_bios = true;
  if(skip_bios){
    gba->cpu.registers[13] = 0x03007f00;
    gba->cpu.registers[R13_irq] = 0x03007FA0;
    gba->cpu.registers[R13_svc] = 0x03007FE0;
    gba->cpu.registers[R13_und] = 0x00000000;
    gba->cpu.registers[CPSR]= 0x000000df; 
    gba->cpu.registers[PC]  = 0x08000000; 

  }else{
    gba->cpu.registers[PC]  = 0x0000000; 
    gba->cpu.registers[CPSR]= 0x000000d3; 
  }
  memcpy(gba->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  gba->mem.openbus_word = gba->mem.cart_rom[0];
  
  for(int bg = 2;bg<4;++bg){
    gba_io_store16(gba,GBA_BG2PA+(bg-2)*0x10,1<<8);
    gba_io_store16(gba,GBA_BG2PB+(bg-2)*0x10,0<<8);
    gba_io_store16(gba,GBA_BG2PC+(bg-2)*0x10,0<<8);
    gba_io_store16(gba,GBA_BG2PD+(bg-2)*0x10,1<<8);
  }
  gba_store32(gba,GBA_DISPCNT,0xe92d0000);
  gba_store16(gba,0x04000088,512);
  gba_store32(gba,0x040000DC,0x84000000);
}

#endif
