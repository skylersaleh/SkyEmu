#ifndef SE_GBA_H
#define SE_GBA_H 1

#include "sb_types.h"
#include <string.h>
#include <math.h>

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
#define GBA_SWAPCHAIN_SIZE 4 

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

typedef struct{
  uint32_t addr;
  const char * name;
  struct{
    uint8_t start;
    uint8_t size;
    const char* name; 
  } bits[16]; 
}mmio_reg_t; 

mmio_reg_t gba_io_reg_desc[]={
  // Interrupt, Waitstate, and Power-Down Control
  { GBA_IE     , "IE", {
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 7 , 1, "Serial Communication" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "Game Pak (ext)" },
  } },      /* R/W  IE        Interrupt Enable Register */
  { GBA_IF     , "IF", {
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 7 , 1, "Serial Communication" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "Game Pak (ext)" },
  } },      /* R/W  IF        Interrupt Request Flags / IRQ Acknowledge */
  { GBA_WAITCNT, "WAITCNT", {
    { 0,2,  "SRAM Wait Control (0..3 = 4,3,2,8 cycles)" },
    { 2,2,  "Wait State 0 First Access (0..3 = 4,3,2,8 cycles)" },
    { 4,1,  "Wait State 0 Second Access (0..1 = 2,1 cycles)" },
    { 5,2,  "Wait State 1 First Access (0..3 = 4,3,2,8 cycles)" },
    { 7,1,  "Wait State 1 Second Access (0..1 = 4,1 cycles)" },
    { 8,2,  "Wait State 2 First Access (0..3 = 4,3,2,8 cycles)" },
    { 10,1, "Wait State 2 Second Access (0..1 = 8,1 cycles)" },
    { 11,2, "PHI Terminal Output (0..3 = Disable, 4.19MHz, 8.38MHz, 16.78MHz)" },
    { 14,1, "Game Pak Prefetch Buffer (0=Disable, 1=Enable)" },
    { 15,1, "Game Pak Type Flag (0=GBA, 1=CGB) (IN35 signal)" },
  } },      /* R/W  WAITCNT   Game Pak Waitstate Control */
  { GBA_IME    , "IME", {} },      /* R/W  IME       Interrupt Master Enable Register */
  { GBA_POSTFLG, "POSTFLG", {} },      /* R/W  POSTFLG   Undocumented - Post Boot Flag */
  { GBA_HALTCNT, "HALTCNT", {} }, 

  { GBA_DISPCNT , "DISPCNT ", { 
    { 0, 3, "BG Mode (0-5=Video Mode 0-5, 6-7=Prohibited)"},
    { 3 ,1, "Reserved / CGB Mode (0=GBA, 1=CGB)"},
    { 4 ,1, "Display Frame Select (0-1=Frame 0-1)"},
    { 5 ,1, "H-Blank Interval Free (1=Allow access to OAM during H-Blank)"},
    { 6 ,1, "OBJ Character VRAM Mapping (0=2D, 1=1D"},
    { 7 ,1, "Forced Blank (1=Allow FAST VRAM,Palette,OAM)"},
    { 8 ,1, "Screen Display BG0 (0=Off, 1=On)"},
    { 9 ,1, "Screen Display BG1 (0=Off, 1=On)"},
    { 10,1, "Screen Display BG2 (0=Off, 1=On)"},
    { 11,1, "Screen Display BG3 (0=Off, 1=On)"},
    { 12,1, "Screen Display OBJ (0=Off, 1=On)"},
    { 13,1, "Window 0 Display Flag (0=Off, 1=On)"},
    { 14,1, "Window 1 Display Flag (0=Off, 1=On)"},
    { 15,1, "OBJ Window Display Flag (0=Off, 1=On)"},
  } },
  { GBA_GREENSWP, "GREENSWP", { {0, 1, "Green Swap  (0=Normal, 1=Swap)" }} }, /* R/W Undocumented - Green Swap */
  { GBA_DISPSTAT, "DISPSTAT", { 
    { 0,1, "V-Blank flag (1=VBlank) (set in line 160..226; not 227",},
    { 1,1, "H-Blank flag (1=HBlank) (toggled in all lines, 0..227",},
    { 2,1, "V-Counter flag (1=Match) (set in selected line)",},
    { 3,1, "V-Blank IRQ Enable (1=Enable)",},
    { 4,1, "H-Blank IRQ Enable (1=Enable)",},
    { 5,1, "V-Counter IRQ Enable (1=Enable)",},
    { 6,1, "DSi: LCD Initialization Ready (0=Busy, 1=Ready",},
    { 7,1, "NDS: MSB of V-Vcount Setting (LYC.Bit8) (0..262",},
    { 8,8, "V-Count Setting (LYC) (0..227)",},

  } }, /* R/W General LCD Status (STAT,LYC) */
  { GBA_VCOUNT  , "VCOUNT  ", { } }, /* R   Vertical Counter (LY) */
  { GBA_BG0CNT  , "BG0CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,2 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 4,2 , "NDS: MSBs of char base"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,1, "Screen Size (0-3)"},
  } }, /* R/W BG0 Control */
  { GBA_BG1CNT  , "BG1CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,2 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 4,2 , "NDS: MSBs of char base"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,1, "Screen Size (0-3)"},
  } }, /* R/W BG1 Control */
  { GBA_BG2CNT  , "BG2CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,2 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 4,2 , "NDS: MSBs of char base"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,1, "Screen Size (0-3)"},
  } }, /* R/W BG2 Control */
  { GBA_BG3CNT  , "BG3CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,2 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 4,2 , "NDS: MSBs of char base"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,1, "Screen Size (0-3)"},
  } }, /* R/W BG3 Control */
  { GBA_BG0HOFS , "BG0HOFS", { } }, /* W   BG0 X-Offset */
  { GBA_BG0VOFS , "BG0VOFS", { } }, /* W   BG0 Y-Offset */
  { GBA_BG1HOFS , "BG1HOFS", { } }, /* W   BG1 X-Offset */
  { GBA_BG1VOFS , "BG1VOFS", { } }, /* W   BG1 Y-Offset */
  { GBA_BG2HOFS , "BG2HOFS", { } }, /* W   BG2 X-Offset */
  { GBA_BG2VOFS , "BG2VOFS", { } }, /* W   BG2 Y-Offset */
  { GBA_BG3HOFS , "BG3HOFS", { } }, /* W   BG3 X-Offset */
  { GBA_BG3VOFS , "BG3VOFS", { } }, /* W   BG3 Y-Offset */
  { GBA_BG2PA   , "BG2PA", { } }, /* W   BG2 Rotation/Scaling Parameter A (dx) */
  { GBA_BG2PB   , "BG2PB", { } }, /* W   BG2 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG2PC   , "BG2PC", { } }, /* W   BG2 Rotation/Scaling Parameter C (dy) */
  { GBA_BG2PD   , "BG2PD", { } }, /* W   BG2 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG2X    , "BG2X", { } }, /* W   BG2 Reference Point X-Coordinate */
  { GBA_BG2Y    , "BG2Y", { } }, /* W   BG2 Reference Point Y-Coordinate */
  { GBA_BG3PA   , "BG3PA", { } }, /* W   BG3 Rotation/Scaling Parameter A (dx) */
  { GBA_BG3PB   , "BG3PB", { } }, /* W   BG3 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG3PC   , "BG3PC", { } }, /* W   BG3 Rotation/Scaling Parameter C (dy) */
  { GBA_BG3PD   , "BG3PD", { } }, /* W   BG3 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG3X    , "BG3X", { } }, /* W   BG3 Reference Point X-Coordinate */
  { GBA_BG3Y    , "BG3Y", { } }, /* W   BG3 Reference Point Y-Coordinate */
  { GBA_WIN0H   , "WIN0H", {  
    { 0, 8, "X2, Rightmost coordinate of window, plus 1 " },
    { 8, 8,  "X1, Leftmost coordinate of window"}, 
  } }, /* W   Window 0 Horizontal Dimensions */
  { GBA_WIN1H   , "WIN1H", { 
    { 0, 8, "X2, Rightmost coordinate of window, plus 1 " },
    { 8, 8, "X1, Leftmost coordinate of window"}, 
  } }, /* W   Window 1 Horizontal Dimensions */
  { GBA_WIN0V   , "WIN0V", { 
    {0, 8,  "Y2, Bottom-most coordinate of window, plus 1" },
    {8, 8,  "Y1, Top-most coordinate of window" },
  } }, /* W   Window 0 Vertical Dimensions */
  { GBA_WIN1V   , "WIN1V", { 
    {0, 8,  "Y2, Bottom-most coordinate of window, plus 1" },
    {8, 8,  "Y1, Top-most coordinate of window" },
  } }, /* W   Window 1 Vertical Dimensions */
  { GBA_WININ   , "WININ", {
    { 0 , 1,  "Window 0 BG0 Enable Bits (0=No Display, 1=Display)"},
    { 1 , 1,  "Window 0 BG1 Enable Bits (0=No Display, 1=Display)"},
    { 2 , 1,  "Window 0 BG2 Enable Bits (0=No Display, 1=Display)"},
    { 3 , 1,  "Window 0 BG3 Enable Bits (0=No Display, 1=Display)"},
    { 4 , 1,  "Window 0 OBJ Enable Bit (0=No Display, 1=Display)"},
    { 5 , 1,  "Window 0 Color Special Effect (0=Disable, 1=Enable)"},
    { 8 , 1,  "Window 1 BG0 Enable Bits (0=No Display, 1=Display)"},
    { 9 , 1,  "Window 1 BG1 Enable Bits (0=No Display, 1=Display)"},
    { 10, 1,  "Window 1 BG2 Enable Bits (0=No Display, 1=Display)"},
    { 11, 1,  "Window 1 BG3 Enable Bits (0=No Display, 1=Display)"},
    { 12, 1,  "Window 1 OBJ Enable Bit (0=No Display, 1=Display)"},
    { 13, 1,  "Window 1 Color Special Effect (0=Disable, 1=Enable)"},
  } }, /* R/W Inside of Window 0 and 1 */
  { GBA_WINOUT  , "WINOUT", { 
    { 0 , 1,  "Window 0 BG0 Enable Bits (0=No Display, 1=Display)"},
    { 1 , 1,  "Window 0 BG1 Enable Bits (0=No Display, 1=Display)"},
    { 2 , 1,  "Window 0 BG2 Enable Bits (0=No Display, 1=Display)"},
    { 3 , 1,  "Window 0 BG3 Enable Bits (0=No Display, 1=Display)"},
    { 4 , 1,  "Window 0 OBJ Enable Bit (0=No Display, 1=Display)"},
    { 5 , 1,  "Window 0 Color Special Effect (0=Disable, 1=Enable)"},
    { 8 , 1,  "Window 1 BG0 Enable Bits (0=No Display, 1=Display)"},
    { 9 , 1,  "Window 1 BG1 Enable Bits (0=No Display, 1=Display)"},
    { 10, 1,  "Window 1 BG2 Enable Bits (0=No Display, 1=Display)"},
    { 11, 1,  "Window 1 BG3 Enable Bits (0=No Display, 1=Display)"},
    { 12, 1,  "Window 1 OBJ Enable Bit (0=No Display, 1=Display)"},
    { 13, 1,  "Window 1 Color Special Effect (0=Disable, 1=Enable)"},
  } }, /* R/W Inside of OBJ Window & Outside of Windows */
  { GBA_MOSAIC  , "MOSAIC", { 
    { 0, 4, "BG Mosaic H-Size (minus 1)" },
    { 4, 4, "BG Mosaic V-Size (minus 1)" },
    { 8, 4, "OBJ Mosaic H-Size (minus 1)" },
    { 12,4, "OBJ Mosaic V-Size (minus 1)" },
  } }, /* W   Mosaic Size */
  { GBA_BLDCNT  , "BLDCNT", { 
    { 0 , 1, "BG0 1st Target Pixel (Background 0)" },
    { 1 , 1, "BG1 1st Target Pixel (Background 1)" },
    { 2 , 1, "BG2 1st Target Pixel (Background 2)" },
    { 3 , 1, "BG3 1st Target Pixel (Background 3)" },
    { 4 , 1, "OBJ 1st Target Pixel (Top-most OBJ pixel)" },
    { 5 , 1, "BD  1st Target Pixel (Backdrop)" },
    { 6 , 2, "Color Effect (0: None 1: Alpha 2: Lighten 3: Darken)" },
    { 8 , 1, "BG0 2nd Target Pixel (Background 0)" },
    { 9 , 1, "BG1 2nd Target Pixel (Background 1)" },
    { 10, 1, "BG2 2nd Target Pixel (Background 2)" },
    { 11, 1, "BG3 2nd Target Pixel (Background 3)" },
    { 12, 1, "OBJ 2nd Target Pixel (Top-most OBJ pixel)" },
    { 13, 1, "BD  2nd Target Pixel (Backdrop)" },
  } }, /* R/W Color Special Effects Selection */
  { GBA_BLDALPHA, "BLDALPHA", { 
    {0, 4, "EVA Coef. (1st Target) (0..16 = 0/16..16/16, 17..31=16/16)"},
    {8, 4, "EVB Coef. (2nd Target) (0..16 = 0/16..16/16, 17..31=16/16)"},
  } }, /* R/W Alpha Blending Coefficients */
  { GBA_BLDY    , "BLDY", { } }, /* W   Brightness (Fade-In/Out) Coefficient */  

  // Sound Registers
  { GBA_SOUND1CNT_L, "SOUND1CNT_L", {
    {0,3, "Number of sweep shift (n=0-7)"},
    {3,1, "Sweep Frequency Direction (0=Increase, 1=Decrease)"},
    {4,3, "Sweep Time; units of 7.8ms (0-7, min=7.8ms, max=54.7ms)"},
  } }, /* R/W   Channel 1 Sweep register       (NR10) */
  { GBA_SOUND1CNT_H, "SOUND1CNT_H", {
    { 0,6, "Sound length; units of (64-n)/256s (0-63)"},
    { 6,2, "Wave Pattern Duty (0-3, see below)"},
    { 8,3, "Envelope Step-Time; units of n/64s (1-7, 0=No Envelope)"},
    { 11,1, "Envelope Direction (0=Decrease, 1=Increase)"},
    { 12,4, "Initial Volume of envelope (1-15, 0=No Sound)"},
  } }, /* R/W   Channel 1 Duty/Length/Envelope (NR11, NR12) */
  { GBA_SOUND1CNT_X, "SOUND1CNT_X", {
    { 0,11, "Frequency; 131072/(2048-n)Hz (0-2047)"},
    { 14,1,  "Length Flag (1=Stop output when length in NR11 expires)"},
    { 15,1,  "Initial (1=Restart Sound)"},
  } }, /* R/W   Channel 1 Frequency/Control    (NR13, NR14) */
  { GBA_SOUND2CNT_L, "SOUND2CNT_L", {
    { 0,6, "Sound length; units of (64-n)/256s (0-63)"},
    { 6,2, "Wave Pattern Duty (0-3, see below)"},
    { 8,3, "Envelope Step-Time; units of n/64s (1-7, 0=No Envelope)"},
    { 11,1, "Envelope Direction (0=Decrease, 1=Increase)"},
    { 12,4, "Initial Volume of envelope (1-15, 0=No Sound)"},
  } }, /* R/W   Channel 2 Duty/Length/Envelope (NR21, NR22) */
  { GBA_SOUND2CNT_H, "SOUND2CNT_H", {
    { 0 ,11, "Frequency; 131072/(2048-n)Hz (0-2047)"},
    { 14,1,  "Length Flag (1=Stop output when length in NR11 expires)"},
    { 15,1,  "Initial (1=Restart Sound)"},
  } }, /* R/W   Channel 2 Frequency/Control    (NR23, NR24) */
  { GBA_SOUND3CNT_L, "SOUND3CNT_L", {
    { 5, 1, "Wave RAM Dimension (0=One bank, 1=Two banks)" },
    { 6, 1, "Wave RAM Bank Number (0-1, see below)" },
    { 7, 1, "Sound Channel 3 Off (0=Stop, 1=Playback)" },
  } }, /* R/W   Channel 3 Stop/Wave RAM select (NR30) */
  { GBA_SOUND3CNT_H, "SOUND3CNT_H", {
    { 0,8, "Sound length; units of (256-n)/256s (0-255)"},
    { 13,2, "Sound Volume (0=Mute/Zero, 1=100%, 2=50%, 3=25%)"},
    { 15,1, "Force Volume (0=Use above, 1=Force 75% regardless of above)"},
  } }, /* R/W   Channel 3 Length/Volume        (NR31, NR32) */
  { GBA_SOUND3CNT_X, "SOUND3CNT_X", {
    { 0,11, "Sample Rate; 2097152/(2048-n) Hz (0-2047)" }, 
    { 14,1, "Length Flag (1=Stop output when length in NR31 expires)" }, 
    { 15,1, "Initial (1=Restart Sound)" }, 
  } }, /* R/W   Channel 3 Frequency/Control    (NR33, NR34) */
  { GBA_SOUND4CNT_L, "SOUND4CNT_L", {
    { 0, 6, "Sound length; units of (64-n)/256s (0-63)" },
    { 8, 3, "Envelope Step-Time; units of n/64s (1-7, 0=No Envelope)" },
    { 11, 1, "Envelope Direction (0=Decrease, 1=Increase)" },
    { 12, 4, "Initial Volume of envelope (1-15, 0=No Sound)" },
  } }, /* R/W   Channel 4 Length/Envelope      (NR41, NR42) */
  { GBA_SOUND4CNT_H, "SOUND4CNT_H", {
    { 0, 1, "Dividing Ratio of Frequencies (r)"},
    { 3, 1, "Counter Step/Width (0=15 bits, 1=7 bits)"},
    { 4, 1, "Shift Clock Frequency (s)"},
    { 14, 1, "Length Flag (1=Stop output when length in NR41 expires)"},
    { 15, 1, "Initial (1=Restart Sound)"},
  } }, /* R/W   Channel 4 Frequency/Control    (NR43, NR44) */
  { GBA_SOUNDCNT_L , "SOUNDCNT_L", {
    { 0,1, "Sound 1 Master Volume RIGHT" },
    { 1,1, "Sound 2 Master Volume RIGHT" },
    { 2,1, "Sound 3 Master Volume RIGHT" },
    { 3,1, "Sound 4 Master Volume RIGHT" },
    { 4,1, "Sound 1 Master Volume LEFT" },
    { 5,1, "Sound 2 Master Volume LEFT" },
    { 6,1, "Sound 3 Master Volume LEFT" },
    { 7,1, "Sound 4 Master Volume LEFT" },

    { 8,1, "Sound 1 Enable RIGHT" },
    { 9,1, "Sound 2 Enable RIGHT" },
    { 10,1, "Sound 3 Enable RIGHT" },
    { 11,1, "Sound 4 Enable RIGHT" },
    { 12,1, "Sound 1 Enable LEFT" },
    { 13,1, "Sound 2 Enable LEFT" },
    { 14,1, "Sound 3 Enable LEFT" },
    { 15,1, "Sound 4 Enable LEFT" },
  } }, /* R/W   Control Stereo/Volume/Enable   (NR50, NR51) */
  { GBA_SOUNDCNT_H , "SOUNDCNT_H", {
    { 0 ,2, "Sound # 1-4 Volume (0=25%, 1=50%, 2=100%, 3=Prohibited)" },
    { 2 ,1, "DMA Sound A Volume (0=50%, 1=100%)" },
    { 3 ,1, "DMA Sound B Volume (0=50%, 1=100%)" },
    { 8 ,1, "DMA Sound A Enable RIGHT (0=Disable, 1=Enable)" },
    { 9 ,1, "DMA Sound A Enable LEFT (0=Disable, 1=Enable)" },
    { 10,1, "DMA Sound A Timer Select (0=Timer 0, 1=Timer 1)" },
    { 11,1, "DMA Sound A Reset FIFO (1=Reset)" },
    { 12,1, "DMA Sound B Enable RIGHT (0=Disable, 1=Enable)" },
    { 13,1, "DMA Sound B Enable LEFT (0=Disable, 1=Enable)" },
    { 14,1, "DMA Sound B Timer Select (0=Timer 0, 1=Timer 1)" },
    { 15,1, "DMA Sound B Reset FIFO (1=Reset)" },
  } }, /* R/W   Control Mixing/DMA Control */
  { GBA_SOUNDCNT_X , "SOUNDCNT_X", {
    {0, 1, "Sound 1 ON flag (Read Only)" },
    {1, 1, "Sound 2 ON flag (Read Only)" },
    {2, 1, "Sound 3 ON flag (Read Only)" },
    {3, 1, "Sound 4 ON flag (Read Only)" },
    {7, 1, "PSG/FIFO Master Enable (0=Disable, 1=Enable) (Read/Write)" },
  } }, /* R/W   Control Sound on/off           (NR52) */
  { GBA_SOUNDBIAS  , "SOUNDBIAS", {
   { 1,9,"Bias Level (Default=100h, converting signed samples into unsigned)"},
   { 14,2,"Amplitude Resolution/Sampling Cycle (Default=0, see below)"},
  } }, /* BIOS  Sound PWM Control */
  { GBA_WAVE_RAM   , "WAVE_RAM", {} }, /* R/W Channel 3 Wave Pattern RAM (2 banks!!) */
  { GBA_FIFO_A     , "FIFO_A", {} }, /* W   Channel A FIFO, Data 0-3 */
  { GBA_FIFO_B     , "FIFO_B", {} }, /* W   Channel B FIFO, Data 0-3 */  

  // DMA Transfer Channels
  { GBA_DMA0SAD  , "DMA0SAD", {} },   /* W    DMA 0 Source Address */
  { GBA_DMA0DAD  , "DMA0DAD", {} },   /* W    DMA 0 Destination Address */
  { GBA_DMA0CNT_L, "DMA0CNT_L", {} },   /* W    DMA 0 Word Count */
  { GBA_DMA0CNT_H, "DMA0CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Prohibited)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 0 Control */
  { GBA_DMA1SAD  , "DMA1SAD", {} },   /* W    DMA 1 Source Address */
  { GBA_DMA1DAD  , "DMA1DAD", {} },   /* W    DMA 1 Destination Address */
  { GBA_DMA1CNT_L, "DMA1CNT_L", {} },   /* W    DMA 1 Word Count */
  { GBA_DMA1CNT_H, "DMA1CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 1 Control */
  { GBA_DMA2SAD  , "DMA2SAD", {} },   /* W    DMA 2 Source Address */
  { GBA_DMA2DAD  , "DMA2DAD", {} },   /* W    DMA 2 Destination Address */
  { GBA_DMA2CNT_L, "DMA2CNT_L", {} },   /* W    DMA 2 Word Count */
  { GBA_DMA2CNT_H, "DMA2CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 2 Control */
  { GBA_DMA3SAD  , "DMA3SAD", {} },   /* W    DMA 3 Source Address */
  { GBA_DMA3DAD  , "DMA3DAD", {} },   /* W    DMA 3 Destination Address */
  { GBA_DMA3CNT_L, "DMA3CNT_L", {} },   /* W    DMA 3 Word Count */
  { GBA_DMA3CNT_H, "DMA3CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 11, 1,  "Game Pak DRQ (0=Normal, 1=DRQ <from> Game Pak, DMA3)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Video Capture)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 3 Control */  

  // Timer Registers
  { GBA_TM0CNT_L, "TM0CNT_L", {} },   /* R/W   Timer 0 Counter/Reload */
  { GBA_TM0CNT_H, "TM0CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 0 Control */
  { GBA_TM1CNT_L, "TM1CNT_L", {} },   /* R/W   Timer 1 Counter/Reload */
  { GBA_TM1CNT_H, "TM1CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 1 Control */
  { GBA_TM2CNT_L, "TM2CNT_L", {} },   /* R/W   Timer 2 Counter/Reload */
  { GBA_TM2CNT_H, "TM2CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 2 Control */
  { GBA_TM3CNT_L, "TM3CNT_L", {} },   /* R/W   Timer 3 Counter/Reload */
  { GBA_TM3CNT_H, "TM3CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 3 Control */  

  // Serial Communication (1)
  { GBA_SIODATA32  , "SIODATA32", {} }, /*R/W   SIO Data (Normal-32bit Mode; shared with below) */
  { GBA_SIOMULTI0  , "SIOMULTI0", {} }, /*R/W   SIO Data 0 (Parent)    (Multi-Player Mode) */
  { GBA_SIOMULTI1  , "SIOMULTI1", {} }, /*R/W   SIO Data 1 (1st Child) (Multi-Player Mode) */
  { GBA_SIOMULTI2  , "SIOMULTI2", {} }, /*R/W   SIO Data 2 (2nd Child) (Multi-Player Mode) */
  { GBA_SIOMULTI3  , "SIOMULTI3", {} }, /*R/W   SIO Data 3 (3rd Child) (Multi-Player Mode) */
  { GBA_SIOCNT     , "SIOCNT", {} }, /*R/W   SIO Control Register */
  { GBA_SIOMLT_SEND, "SIOMLT_SEND", {} }, /*R/W   SIO Data (Local of MultiPlayer; shared below) */
  { GBA_SIODATA8   , "SIODATA8", {} }, /*R/W   SIO Data (Normal-8bit and UART Mode) */  

  // Keypad Input
  { GBA_KEYINPUT, "GBA_KEYINPUT", {
    { 0, 1, "Button A" },
    { 1, 1, "Button B" },
    { 2, 1, "Select" },
    { 3, 1, "Start" },
    { 4, 1, "Right" },
    { 5, 1, "Left" },
    { 6, 1, "Up" },
    { 7, 1, "Down" },
    { 8, 1, "Button R" },
    { 9, 1, "Button L" },
  } },    /* R      Key Status */
  { GBA_KEYCNT  , "GBA_KEYCNT", {
    { 0, 1, "Button A" },
    { 1, 1, "Button B" },
    { 2, 1, "Select" },
    { 3, 1, "Start" },
    { 4, 1, "Right" },
    { 5, 1, "Left" },
    { 6, 1, "Up" },
    { 7, 1, "Down" },
    { 8, 1, "Button R" },
    { 9, 1, "Button L" },
    { 14,1, "Button IRQ Enable (0=Disable, 1=Enable)" },
    { 15,1, "Button IRQ Condition (0=OR, 1=AND)"},
  } },    /* R/W    Key Interrupt Control */  

  // Serial Communication (2)
  { GBA_RCNT     , "RCNT", {} },     /* R/W  SIO Mode Select/General Purpose Data */
  { GBA_IR       , "IR", {} },     /* -    Ancient - Infrared Register (Prototypes only) */
  { GBA_JOYCNT   , "JOYCNT", {} },     /* R/W  SIO JOY Bus Control */
  { GBA_JOY_RECV , "JOY_RECV", {} },     /* R/W  SIO JOY Bus Receive Data */
  { GBA_JOY_TRANS, "JOY_TRANS", {} },     /* R/W  SIO JOY Bus Transmit Data */
  { GBA_JOYSTAT  , "JOYSTAT", {} },     /* R/?  SIO JOY Bus Receive Status */  
};

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
  uint32_t eeprom_addr; 
  uint32_t prefetch_en; 
  uint32_t prefetch_size; 
  uint32_t requests;
  uint32_t bios_word;
  uint32_t cartopen_bus; 
  uint8_t wait_state_table[16*4];
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
  int current_transaction;
  bool last_enable;
  bool last_vblank;
  bool last_hblank;
  uint32_t latched_transfer;
} gba_dma_t; 
typedef struct{
  int scan_clock; 
  bool last_vblank;
  bool last_hblank;
  int last_lcd_y; 
  struct {
    int32_t internal_bgx;
    int32_t internal_bgy;
  }aff[2];
  uint16_t dispcnt_pipeline[3];
}gba_ppu_t;
typedef struct{
  bool last_enable; 
  uint16_t reload_value; 
  uint16_t prescaler_timer;
  uint16_t elapsed_audio_samples;
}gba_timer_t;
typedef struct{
  struct{
    int8_t data[64];
    int read_ptr; 
    int write_ptr; 
    bool request_dma_fill;
  }fifo[2];
}gba_audio_t; 
typedef struct {
  gba_mem_t mem;
  arm7_t cpu;
  gba_cartridge_t cart;
  gba_joy_t joy;       
  gba_ppu_t ppu;
  gba_dma_t dma[4]; 
  bool activate_dmas; 
  gba_timer_t timers[4];
  uint32_t timer_ticks_before_event;
  uint32_t deferred_timer_ticks;
  gba_audio_t audio;
  bool halt; 
  bool prev_key_interrupt;
  uint32_t first_target_buffer[GBA_LCD_W];
  uint32_t second_target_buffer[GBA_LCD_W];
  uint8_t window[GBA_LCD_W];
  uint8_t framebuffer[GBA_LCD_W*GBA_LCD_H*3];
} gba_t; 

static void gba_tick_keypad(sb_joy_t*joy, gba_t* gba); 
static FORCE_INLINE void gba_tick_timers(gba_t* gba, int ticks, bool force_recalculate);

// Returns a pointer to the data backing the baddr (when not DWORD aligned, it
// ignores the lowest 2 bits. 
static FORCE_INLINE uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr, bool * read_only);
static FORCE_INLINE uint32_t gba_read32(gba_t*gba, unsigned baddr){bool read_only;return *gba_dword_lookup(gba,baddr,&read_only);}
static FORCE_INLINE uint16_t gba_read16(gba_t*gba, unsigned baddr){
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,1,1);
  return ((uint16_t*)val)[offset];
}
static FORCE_INLINE uint8_t gba_read8(gba_t*gba, unsigned baddr){
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,0,2);
  return ((uint8_t*)val)[offset];
}            
static FORCE_INLINE void gba_process_flash_state_machine(gba_t* gba, unsigned baddr, uint8_t data){
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
static FORCE_INLINE void gba_process_backup_write(gba_t*gba, unsigned baddr, uint32_t data){
  if(gba->cart.backup_type==GBA_BACKUP_FLASH_64K||gba->cart.backup_type==GBA_BACKUP_FLASH_128K){
    gba_process_flash_state_machine(gba,baddr,data);
  }else if(gba->cart.backup_type==GBA_BACKUP_SRAM){
    if(gba->mem.cart_backup[baddr&0x7fff]!=(data&0xff)){
      gba->mem.cart_backup[baddr&0x7fff]=data&0xff; 
      gba->cart.backup_is_dirty=true;
    }
  }
}
static FORCE_INLINE void gba_store32(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t *val=gba_dword_lookup(gba,baddr,&read_only);
  if(!read_only)*val= data;
}
static FORCE_INLINE void gba_store16(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t* val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,1,1);
  if(!read_only)((uint16_t*)val)[offset]=data; 
}
static FORCE_INLINE void gba_store8(gba_t*gba, unsigned baddr, uint32_t data){
  if((baddr&0xE000000)==0xE000000)return gba_process_backup_write(gba,baddr,data);
  bool read_only;
  uint32_t *val = gba_dword_lookup(gba,baddr,&read_only);
  int offset = SB_BFE(baddr,0,2);
  if(!read_only)((uint8_t*)val)[offset]=data; 
} 
static FORCE_INLINE void gba_io_store8(gba_t*gba, unsigned baddr, uint8_t data){gba->mem.io[baddr&0xffff]=data;}
static FORCE_INLINE void gba_io_store16(gba_t*gba, unsigned baddr, uint16_t data){*(uint16_t*)(gba->mem.io+(baddr&0xffff))=data;}
static FORCE_INLINE void gba_io_store32(gba_t*gba, unsigned baddr, uint32_t data){*(uint32_t*)(gba->mem.io+(baddr&0xffff))=data;}

static FORCE_INLINE uint8_t  gba_io_read8(gba_t*gba, unsigned baddr) {return gba->mem.io[baddr&0xffff];}
static FORCE_INLINE uint16_t gba_io_read16(gba_t*gba, unsigned baddr){return *(uint16_t*)(gba->mem.io+(baddr&0xffff));}
static FORCE_INLINE uint32_t gba_io_read32(gba_t*gba, unsigned baddr){return *(uint32_t*)(gba->mem.io+(baddr&0xffff));}

static FORCE_INLINE void gba_recompute_waitstate_table(gba_t* gba,uint16_t waitcnt){
  // TODO: Make the waitstate for the ROM configureable 
  const int wait_state_table[16*4]={
    1,1,1,1, //0x00 (bios)
    1,1,1,1, //0x01 (bios)
    3,3,6,6, //0x02 (256k WRAM)
    1,1,1,1, //0x03 (32k WRAM)
    1,1,1,1, //0x04 (IO)
    1,1,2,2, //0x05 (BG/OBJ Palette)
    1,1,2,2, //0x06 (VRAM)
    1,1,1,1, //0x07 (OAM)
    4,4,8,8, //0x08 (GAMEPAK ROM 0)
    4,4,8,8, //0x09 (GAMEPAK ROM 0)
    4,4,8,8, //0x0A (GAMEPAK ROM 1)
    4,4,8,8, //0x0B (GAMEPAK ROM 1)
    4,4,8,8, //0x0C (GAMEPAK ROM 2)
    4,4,8,8, //0x0D (GAMEPAK ROM 2)
    4,4,4,4, //0x0E (GAMEPAK SRAM)
    1,1,1,1, //0x0F (unused)
  };
  for(int i=0;i<16*4;++i){
    gba->mem.wait_state_table[i]=wait_state_table[i];
  }
  uint8_t sram_wait = SB_BFE(waitcnt,0,2);
  uint8_t wait_first[3];
  uint8_t wait_second[3];

  wait_first[0]  = SB_BFE(waitcnt,2,2);
  wait_second[0] = SB_BFE(waitcnt,4,1);
  wait_first[1]  = SB_BFE(waitcnt,5,2);
  wait_second[1] = SB_BFE(waitcnt,7,1);
  wait_first[2]  = SB_BFE(waitcnt,8,2);
  wait_second[2] = SB_BFE(waitcnt,10,1);
  uint8_t prefetch_en = SB_BFE(waitcnt,14,1);

  int primary_table[4]={4,3,2,8};

  //Each waitstate is two entries in table
  for(int ws=0;ws<3;++ws){
    for(int i=0;i<2;++i){
      uint8_t w_first = primary_table[wait_first[ws]];
      uint8_t w_second = wait_second[ws]?1:2;
      if(ws==1)w_second = wait_second[ws]?1:4;
      if(ws==2)w_second = wait_second[ws]?1:8;
      w_first+=1;w_second+=1;
      //Wait 0
      int wait16b = w_second; 
      int wait32b = w_second*2; 

      int wait16b_nonseq = w_first; 
      int wait32b_nonseq = w_first+w_second;

      gba->mem.wait_state_table[(0x08+i+ws*2)*4+0] = wait16b;
      gba->mem.wait_state_table[(0x08+i+ws*2)*4+1] = wait16b_nonseq;
      gba->mem.wait_state_table[(0x08+i+ws*2)*4+2] = wait32b;
      gba->mem.wait_state_table[(0x08+i+ws*2)*4+3] = wait32b_nonseq;
    }
  }
  gba->mem.prefetch_en = prefetch_en;
  gba->mem.prefetch_size = 0;

  //SRAM
  gba->mem.wait_state_table[(0x0E*4)+0]= 1+primary_table[sram_wait];
  gba->mem.wait_state_table[(0x0E*4)+1]= 1+primary_table[sram_wait];
  gba->mem.wait_state_table[(0x0E*4)+2]= 1+primary_table[sram_wait];
  gba->mem.wait_state_table[(0x0E*4)+3]= 1+primary_table[sram_wait];
  waitcnt&=(1<<15); // Force cartridge to report as GBA cart
  gba_io_store16(gba,GBA_WAITCNT,waitcnt);
}
static FORCE_INLINE void gba_compute_access_cycles(void*user_data, uint32_t address,int request_size/*0: 1B,1: 2B,3: 4B*/){
  int bank = SB_BFE(address,24,4);
  gba_t * gba = ((gba_t*)user_data); 
  uint32_t wait = gba->mem.wait_state_table[bank*4+request_size];
  if(bank>=0x08&&bank<=0x0D){
    if((request_size&1)||!gba->mem.prefetch_en){
      //Non sequential->reset prefetch buffer
      gba->mem.prefetch_size = 0;
    }else{
      //Sequential fetch from prefetch buffer based on available wait states
      if(gba->mem.prefetch_size>=wait){
        gba->mem.prefetch_size-=wait; 
        wait = 1; 
        gba->mem.prefetch_size++;
      }else{
        wait -= gba->mem.prefetch_size;
        gba->mem.prefetch_size =0;
      }
    }
  }else gba->mem.prefetch_size+=wait; 
  
  gba->mem.requests+=wait;
}
static FORCE_INLINE void gba_process_mmio_read(gba_t *gba, uint32_t address, int req_size_bytes);
// Memory IO functions for the emulated CPU                  
static FORCE_INLINE uint32_t arm7_read32(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,3);
  if(address>=0x4000000 && address<=0x40003FE){
    gba_process_mmio_read((gba_t*)user_data,address,4);
  }
  uint32_t value = gba_read32((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x3)*8);
}
static FORCE_INLINE uint32_t arm7_read16(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,1);
  if(address>=0x4000000 && address<=0x40003FE){
    gba_process_mmio_read((gba_t*)user_data,address,4);
  }
  uint16_t value = gba_read16((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x1)*8);
}
static FORCE_INLINE uint32_t arm7_read32_seq(void* user_data, uint32_t address, bool seq){
  gba_compute_access_cycles(user_data,address,seq?2:3);
  if(address>=0x4000000 && address<=0x40003FE){
    gba_process_mmio_read((gba_t*)user_data,address,4);
  }
  uint32_t value = gba_read32((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x3)*8);
}
static FORCE_INLINE uint32_t arm7_read16_seq(void* user_data, uint32_t address, bool seq){
  gba_compute_access_cycles(user_data,address,seq?0:1);
  if(address>=0x4000000 && address<=0x40003FE){
    gba_process_mmio_read((gba_t*)user_data,address,4);
  }
  uint16_t value = gba_read16((gba_t*)user_data,address);
  return arm7_rotr(value,(address&0x1)*8);
}
//Used to process special behavior triggered by MMIO write
static bool gba_process_mmio_write(gba_t *gba, uint32_t address, uint32_t data, int req_size_bytes);

static FORCE_INLINE uint8_t arm7_read8(void* user_data, uint32_t address){
  gba_compute_access_cycles(user_data,address,1);
  if(address>=0x4000000 && address<=0x40003FE){
    gba_process_mmio_read((gba_t*)user_data,address,4);
  }
  return gba_read8((gba_t*)user_data,address);
}
static FORCE_INLINE void arm7_write32(void* user_data, uint32_t address, uint32_t data){
  gba_compute_access_cycles(user_data,address,3); 
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,4))return;
  }
  gba_store32((gba_t*)user_data,address,data);
}
static FORCE_INLINE void arm7_write16(void* user_data, uint32_t address, uint16_t data){
  gba_compute_access_cycles(user_data,address,1); 
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,2))return; 
  }
  gba_store16((gba_t*)user_data,address,data);
}
static FORCE_INLINE void arm7_write8(void* user_data, uint32_t address, uint8_t data)  {
  gba_compute_access_cycles(user_data,address,1); 
  if(address>=0x4000000 && address<=0x40003FE){
    if(gba_process_mmio_write((gba_t*)user_data,address,data,1))return; 
  }
  gba_store8((gba_t*)user_data,address,data);
}
// Try to load a GBA rom, return false on invalid rom
bool gba_load_rom(gba_t* gba, const char * filename, const char* save_file);
void gba_reset(gba_t*gba);
 
static FORCE_INLINE uint32_t * gba_dword_lookup(gba_t* gba,unsigned baddr,bool*read_only){
  baddr&=0x0fffffffc;
  uint32_t *ret = &gba->mem.openbus_word;

  *read_only= false; 
  switch(baddr>>24){
    case 0x0: if(baddr<0x4000){
      *read_only=true;

      if(gba->cpu.registers[15]<0x4000)gba->mem.bios_word = *(uint32_t*)(gba->mem.bios+baddr);
      else gba->mem.bios_word=0;
      ret=&gba->mem.bios_word;
     } break;
    case 0x1: break;
    case 0x2: ret = (uint32_t*)(gba->mem.wram0+(baddr&0x3ffff)); break;
    case 0x3: ret = (uint32_t*)(gba->mem.wram1+(baddr&0x7fff)); break;
    case 0x4: if(baddr<=0x40003FE ){ret = (uint32_t*)(gba->mem.io+(baddr&0x3ff));} break;
    case 0x5: ret = (uint32_t*)(gba->mem.palette+(baddr&0x3ff)); break;
    case 0x6: 
      if(baddr&0x10000)ret = (uint32_t*)(gba->mem.vram+(baddr&0x07fff)+0x10000);
      else ret = (uint32_t*)(gba->mem.vram+(baddr&0x1ffff));
      break;
    case 0x7: ret = (uint32_t*)(gba->mem.oam+(baddr&0x3ff)); break;
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
    case 0xC:
    case 0xD:{
        int addr = baddr&0x1ffffff;
        *read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+addr);
        if(addr>=gba->cart.rom_size){
          ret = (uint32_t*)(&gba->mem.cartopen_bus);
          *ret = ((addr/2)&0xffff)|(((addr/2+1)&0xffff)<<16);
          
        }
        if((addr>=0x1FFFF00||addr>=gba->cart.rom_size)&&gba->cart.backup_type==GBA_BACKUP_EEPROM){
            ret = (uint32_t*)&gba->mem.eeprom_word;
            *ret = 1;
        }
      }
      break;
    case 0xE:
      if(gba->cart.backup_type==GBA_BACKUP_SRAM) ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0x7fff));
      else if(gba->cart.backup_type==GBA_BACKUP_EEPROM) ret = (uint32_t*)&gba->mem.eeprom_word;
      else{
        //Flash
        if(gba->cart.in_chip_id_mode&&baddr<=0xE000001) ret = (uint32_t*)(gba->mem.flash_chip_id);
        else ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0xffff)+gba->cart.flash_bank*64*1024);
      }
      break;
    case 0xF: break;

  }
  /*if(baddr>=0x8000000 && baddr<=0xDFFFFFF ){
    int addr = baddr&0x1ffffff;
    *read_only=true; ret = (uint32_t*)(gba->mem.cart_rom+addr);
    if(addr>gba->cart.rom_size){
      ret = (uint32_t*)(&gba->mem.cartopen_bus);
      *ret = ((addr/2)&0xffff)|(((addr/2+1)&0xffff)<<16);
    }
  }
  else if(baddr>=0x2000000 && baddr<=0x2FFFFFF )ret = (uint32_t*)(gba->mem.wram0+(baddr&0x3ffff));
  else if(baddr>=0x3000000 && baddr<=0x3ffffff )ret = (uint32_t*)(gba->mem.wram1+(baddr&0x7fff));
  else if(baddr>=0x4000000 && baddr<=0x40003FE ){
    ret = (uint32_t*)(gba->mem.io+baddr-0x4000000);
  }else if(baddr>=0x5000000 && baddr<=0x5ffffff )ret = (uint32_t*)(gba->mem.palette+(baddr&0x3ff));
  else if(baddr>=0x6000000 && baddr<=0x6ffffff ){
    if(baddr&0x10000)ret = (uint32_t*)(gba->mem.vram+(baddr&0x07fff)+0x10000);
    else ret = (uint32_t*)(gba->mem.vram+(baddr&0x1ffff));
  }else if(baddr>=0x7000000 && baddr<=0x7ffffff )ret = (uint32_t*)(gba->mem.oam+(baddr&0x3ff));
  else if(baddr>=0xE000000 && baddr<=0xEffffff ){
    if(gba->cart.backup_type==GBA_BACKUP_SRAM) ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0x7fff));
    else if(gba->cart.backup_type==GBA_BACKUP_EEPROM) ret = (uint32_t*)&gba->mem.eeprom_word;
    else{
      //Flash
      if(gba->cart.in_chip_id_mode&&baddr<=0xE000001) ret = (uint32_t*)(gba->mem.flash_chip_id);
      else ret = (uint32_t*)(gba->mem.cart_backup+(baddr&0xffff)+gba->cart.flash_bank*64*1024);
    }
    
  }else if(baddr<0x4000){ *read_only=true;ret= (uint32_t*)(gba->mem.bios+baddr-0x0);}
  */
  gba->mem.openbus_word=*ret;
  return ret;
}
static FORCE_INLINE void gba_audio_fifo_push(gba_t*gba, int fifo, int8_t data){
  int free_entries = (gba->audio.fifo[fifo].write_ptr+1-gba->audio.fifo[fifo].read_ptr)&0x1f; 
  if(free_entries){
    gba->audio.fifo[fifo].write_ptr = (gba->audio.fifo[fifo].write_ptr+1)&0x1f;
    gba->audio.fifo[fifo].data[gba->audio.fifo[fifo].write_ptr]= data; 
  }else{
    gba->audio.fifo[fifo].write_ptr=gba->audio.fifo[fifo].read_ptr = 0; 
    printf("Tried to push audio samples to full fifo\n");
  }
}
static FORCE_INLINE void gba_process_mmio_read(gba_t *gba, uint32_t address, int req_size_bytes){
  // Force recomputing timers on timer read
  if(address+req_size_bytes>= GBA_TM0CNT_L&&address<=GBA_TM3CNT_H)gba_tick_timers(gba,0,true);
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
    gba_tick_timers(gba,0,true);
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
  /*
  Ignore these for now since it is causing audio pops in Metroid Zero
  }else if(address_u32==GBA_FIFO_A){
    // See: https://github.com/mgba-emu/mgba/issues/1847
    for(int i=0;i<4;++i){
      if(word_mask&(0xff<<(8*i)))gba_audio_fifo_push(gba,0,SB_BFE(word_data,8*i,8));
      else gba_audio_fifo_push(gba,0,gba->audio.fifo[0].data[(gba->audio.fifo[0].write_ptr)&0x1f]);
    }
  }else if(address_u32==GBA_FIFO_B){
    for(int i=0;i<4;++i){
      if(word_mask&(0xff<<(8*i)))gba_audio_fifo_push(gba,1,SB_BFE(word_data,8*i,8));
      else gba_audio_fifo_push(gba,1,gba->audio.fifo[1].data[(gba->audio.fifo[1].write_ptr)&0x1f]);
    }
  */
  }else if(address_u32>=GBA_BG2X &&address_u32<=GBA_BG3Y){
    int aff_bg = (address_u32-GBA_BG2X)/32;
    if(address_u32==GBA_BG2X||address_u32==GBA_BG3X){
      gba->ppu.aff[aff_bg].internal_bgx&= ~word_mask;
      gba->ppu.aff[aff_bg].internal_bgx|= word_data;
    }
    if(address_u32==GBA_BG2Y||address_u32==GBA_BG3Y){
      gba->ppu.aff[aff_bg].internal_bgy&= ~word_mask;
      gba->ppu.aff[aff_bg].internal_bgy|= word_data;
    }
  }else if(address_u32==GBA_DMA0CNT_L||address_u32==GBA_DMA1CNT_L||
           address_u32==GBA_DMA2CNT_L||address_u32==GBA_DMA3CNT_L){
    gba->activate_dmas=true;
  }else if (address_u32==GBA_WAITCNT){
     uint16_t waitcnt = gba_io_read16(gba,GBA_WAITCNT);
     waitcnt = ((waitcnt&~word_mask)|(word_data&word_mask));
     gba_recompute_waitstate_table(gba,waitcnt);
  }else if(address_u32==GBA_KEYINPUT){
    if(word_mask&0xffff0000){
      gba_store16(gba,GBA_KEYINPUT,(word_data>>16)&0xffff);
    }
    gba_tick_keypad(NULL,gba);
  }
  return false;
}
int gba_search_rom_for_backup_string(gba_t* gba){
  for(int b = 0; b< gba->cart.rom_size;++b){
    const char* strings[]={"EEPROM_", "SRAM_", "FLASH_","FLASH512_","FLASH1M_"};
    int backup_type[]= {GBA_BACKUP_EEPROM,GBA_BACKUP_SRAM,GBA_BACKUP_FLASH_64K, GBA_BACKUP_FLASH_64K, GBA_BACKUP_FLASH_128K};
    for(int type = 0; type<sizeof(strings)/sizeof(strings[0]);++type){
      int str_off = 0; 
      bool matches = true; 
      const char* str = strings[type];
      while(str[str_off] && matches){
        if(str[str_off]!=gba->mem.cart_rom[b+str_off])matches = false;
        if(b+str_off>=gba->cart.rom_size)matches=false; 
        ++str_off;
      }
      if(matches)return backup_type[type];
    }
  }
  return GBA_BACKUP_NONE; 
}
bool gba_load_rom(gba_t* gba, const char* filename, const char* save_file){

  if(!sb_path_has_file_ext(filename, ".gba")){
    return false; 
  }
  size_t bytes = 0;                                                       
  uint8_t *data = sb_load_file_data(filename, &bytes);
  if(bytes>32*1024*1024){
    printf("ROMs with sizes >32MB (%zu bytes) are too big for the GBA\n",bytes); 
    return false;
  }  
  *gba = (gba_t){0};               
  gba_reset(gba);
  memcpy(gba->mem.cart_rom, data, bytes);
  sb_free_file_data(data);
  gba->cart.rom_size = bytes; 

  strncpy(gba->cart.save_file_path,save_file,SB_FILE_PATH_SIZE);
  gba->cart.save_file_path[SB_FILE_PATH_SIZE-1]=0;

  memcpy(gba->cart.title,gba->mem.cart_rom+0x0A0,12);
  gba->cart.title[12]=0;

  gba->cart.backup_type = gba_search_rom_for_backup_string(gba);

  data = sb_load_file_data(save_file,&bytes);
  if(data){
    printf("Loaded save file: %s, bytes: %zu\n",save_file,bytes);
    if(bytes>=128*1024)bytes=128*1024;
    memcpy(gba->mem.cart_backup, data, bytes);
    sb_free_file_data(data);
  }else{
    printf("Could not find save file: %s\n",save_file);
    for(int i=0;i<sizeof(gba->mem.cart_backup);++i) gba->mem.cart_backup[i]=0;
  }

  // Setup flash chip id (this is not used if the cartridge does not have flash backup storage)
  gba->mem.flash_chip_id[1]=0x13;
  gba->mem.flash_chip_id[0]=0x62;
  return true; 
}  
    
static FORCE_INLINE void gba_tick_ppu(gba_t* gba, int cycles, bool skip_render){
  gba->ppu.scan_clock+=cycles;
  if(gba->ppu.scan_clock%4)return;
  if(gba->ppu.scan_clock>=280896)gba->ppu.scan_clock-=280896;

  int lcd_y = (gba->ppu.scan_clock)/1232;
  int lcd_x = (gba->ppu.scan_clock%1232)/4;
  if(lcd_x==262||lcd_x==0||lcd_x==240||lcd_x==296){
    uint16_t disp_stat = gba_io_read16(gba, GBA_DISPSTAT)&~0x7;
    uint16_t vcount_cmp = SB_BFE(disp_stat,8,8);
    bool vblank = lcd_y>=160&&lcd_y<227;
    bool hblank = lcd_x>=240&&lcd_x< 296;
    disp_stat |= vblank ? 0x1: 0; 
    disp_stat |= hblank ? 0x2: 0;      
    disp_stat |= lcd_y==vcount_cmp ? 0x4: 0;   
    gba_io_store16(gba,GBA_VCOUNT,lcd_y);   
    gba_io_store16(gba,GBA_DISPSTAT,disp_stat);
    uint32_t new_if = 0;
    if(hblank!=gba->ppu.last_hblank){
      gba->ppu.last_hblank = hblank;
      bool hblank_irq_en = SB_BFE(disp_stat,4,1);
      if(hblank&&hblank_irq_en) new_if|= (1<< GBA_INT_LCD_HBLANK); 
      gba->activate_dmas=true;
      if(!hblank){
        gba->ppu.dispcnt_pipeline[0]=gba->ppu.dispcnt_pipeline[1];
        gba->ppu.dispcnt_pipeline[1]=gba->ppu.dispcnt_pipeline[2];
        gba->ppu.dispcnt_pipeline[2]=gba_io_read16(gba, GBA_DISPCNT);
      }else{
        uint16_t dispcnt = gba->ppu.dispcnt_pipeline[0];

        int bg_mode = SB_BFE(dispcnt,0,3);

        // From Mirei: Affine registers are only incremented when bg_mode is not 0
        // and the bg is enabled.
        if(bg_mode!=0){
          for(int aff=0;aff<2;++aff){
            bool bg_en = SB_BFE(dispcnt,8+aff+2,1);
            if(!bg_en)continue;
            int32_t b = (int16_t)gba_io_read16(gba,GBA_BG2PB+(aff)*0x10);
            int32_t d = (int16_t)gba_io_read16(gba,GBA_BG2PD+(aff)*0x10);
            gba->ppu.aff[aff].internal_bgx+=b;
            gba->ppu.aff[aff].internal_bgy+=d;
          }
        }
      }
    }
    if(lcd_y != gba->ppu.last_lcd_y){
      if(vblank!=gba->ppu.last_vblank){
        gba->ppu.last_vblank = vblank;
        bool vblank_irq_en = SB_BFE(disp_stat,3,1);
        if(vblank&&vblank_irq_en) new_if|= (1<< GBA_INT_LCD_VBLANK); 
        gba->activate_dmas=true;
      }
      gba->ppu.last_lcd_y  = lcd_y;
      if(lcd_y==vcount_cmp) {
        bool vcnt_irq_en = SB_BFE(disp_stat,5,1);
        if(vcnt_irq_en)new_if |= (1<<GBA_INT_LCD_VCOUNT);
      }
      //Latch BGX and BGY registers
      if(lcd_y==0){
        for(int aff=0;aff<2;++aff){
          gba->ppu.aff[aff].internal_bgx=gba_io_read32(gba,GBA_BG2X+(aff)*0x10);
          gba->ppu.aff[aff].internal_bgy=gba_io_read32(gba,GBA_BG2Y+(aff)*0x10);

          gba->ppu.aff[aff].internal_bgx = SB_BFE(gba->ppu.aff[aff].internal_bgx,0,28);
          gba->ppu.aff[aff].internal_bgy = SB_BFE(gba->ppu.aff[aff].internal_bgy,0,28);

          gba->ppu.aff[aff].internal_bgx = (gba->ppu.aff[aff].internal_bgx<<4)>>4;
          gba->ppu.aff[aff].internal_bgy = (gba->ppu.aff[aff].internal_bgy<<4)>>4;
        }
      }
    }
    if(new_if){
      new_if |= gba_io_read16(gba,GBA_IF); 
      gba_io_store16(gba,GBA_IF,new_if);
    }
  }

  if(skip_render)return; 

  uint16_t dispcnt = gba_io_read16(gba, GBA_DISPCNT);
  int bg_mode = SB_BFE(dispcnt,0,3);
  int obj_vram_map_2d = !SB_BFE(dispcnt,6,1);
  int forced_blank = SB_BFE(dispcnt,7,1);
  if(forced_blank)return;
  bool visible = lcd_x<240 && lcd_y<160;
  //Render sprites over scanline when it completes
  if(lcd_y<160 && lcd_x == 0){
    
    //Render sprites over scanline when it completes
    uint8_t default_window_control =0x3f;//bitfield [0-3:bg0-bg3 enable 4:obj enable, 5: special effect enable]
    bool winout_enable = SB_BFE(dispcnt,13,3)!=0;
    uint16_t WINOUT = gba_io_read16(gba, GBA_WINOUT);
    if(winout_enable)default_window_control = SB_BFE(WINOUT,0,8);
  
    for(int x=0;x<240;++x){gba->window[x] = default_window_control;}
    uint8_t obj_window_control = default_window_control;
    bool obj_window_enable = SB_BFE(dispcnt,15,1);
    if(obj_window_enable)obj_window_control = SB_BFE(WINOUT,8,6);
    
    for(int o=0;o<128;++o){
      uint16_t attr0 = *(uint16_t*)(gba->mem.oam+o*8+0);
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
      uint16_t attr1 = *(uint16_t*)(gba->mem.oam+o*8+2);

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

      int y_size = ysize_lookup[obj_size*4+obj_shape];

      if(((lcd_y-y_coord)&0xff) <y_size*(double_size?2:1)){
        int16_t x_coord = SB_BFE(attr1,0,9);
        if (SB_BFE(x_coord,8,1))x_coord|=0xfe00;

        int x_size = xsize_lookup[obj_size*4+obj_shape];
        int x_start = x_coord>=0?x_coord:0;
        int x_end   = x_coord+x_size*(double_size?2:1);
        if(x_end>=240)x_end=240;
        //Attr2
        //Skip objects disabled by window
        uint16_t attr2 = *(uint16_t*)(gba->mem.oam+o*8+4);
        int tile_base = SB_BFE(attr2,0,10);
        // Always place sprites as the highest priority
        int priority = SB_BFE(attr2,10,2);
        int palette = SB_BFE(attr2,12,4);
        for(int x = x_start; x< x_end;++x){
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
            if(sx>=x_size||sy>=y_size||sx<0||sy<0)continue;
          }else{
            if(h_flip)sx=x_size-sx-1;
            if(v_flip)sy=y_size-sy-1;
          }
          int tx = sx%8;
          int ty = sy%8;
                    
          int y_tile_stride = obj_vram_map_2d? colors_or_palettes? 16:32 : x_size/8;
          int tile = (colors_or_palettes? tile_base/2 : tile_base) + ((sx/8))+(sy/8)*y_tile_stride;
          
          uint8_t palette_id;
          int obj_tile_base = GBA_OBJ_TILES0_2;
          if(colors_or_palettes==false){
            palette_id= gba->mem.vram[obj_tile_base+tile*8*4+tx/2+ty*4];
            palette_id= (palette_id>>((tx&1)*4))&0xf;
            if(palette_id==0)continue;
            palette_id+=palette*16;
          }else{
            palette_id=gba->mem.vram[obj_tile_base+tile*8*8+tx+ty*8];
            if(palette_id==0)continue;
          }

          uint32_t col = *(uint16_t*)(gba->mem.palette+GBA_OBJ_PALETTE+palette_id*2);
          //Handle window objects(not displayed but control the windowing of other things)
          if(obj_mode==2){gba->window[x]=obj_window_control; 
          }else if(obj_mode!=3){
            int type =4;
            col=col|(type<<17)|((5-priority)<<28)|((0x7)<<25);
            if(obj_mode==1)col|=1<<16;
            if((col>>17)>(gba->first_target_buffer[x]>>17))gba->first_target_buffer[x]=col;
          }  
        }
      }
    }
    int enabled_windows = SB_BFE(dispcnt,13,3); // [0: win0, 1:win1, 2: objwin]
    if(enabled_windows){
      for(int win=1;win>=0;--win){
        bool win_enable = SB_BFE(dispcnt,13+win,1);
        if(!win_enable)continue;
        uint16_t WINH = gba_io_read16(gba, GBA_WIN0H+2*win);
        uint16_t WINV = gba_io_read16(gba, GBA_WIN0V+2*win);
        int win_xmin = SB_BFE(WINH,8,8);
        int win_xmax = SB_BFE(WINH,0,8);
        int win_ymin = SB_BFE(WINV,8,8);
        int win_ymax = SB_BFE(WINV,0,8);
        // Garbage values of X2>240 or X1>X2 are interpreted as X2=240.
        // Garbage values of Y2>160 or Y1>Y2 are interpreted as Y2=160. 
        if(win_xmin>win_xmax)win_xmax=240;
        if(win_ymin>win_ymax)win_ymax=160;
        if(lcd_y<win_ymin||lcd_y>=win_ymax)continue;
        uint16_t winin = gba_io_read16(gba,GBA_WININ);
        uint8_t win_value = SB_BFE(winin,win*8,6);
        for(int x=win_xmin;x<win_xmax;++x)gba->window[x] = win_value;
      }
      int backdrop_type = 5;
      uint32_t backdrop_col = (*(uint16_t*)(gba->mem.palette + GBA_BG_PALETTE+0*2))|(backdrop_type<<17);
      for(int x=0;x<240;++x){
        uint8_t window_control = gba->window[x];
        if(SB_BFE(window_control,4,1)==0)gba->first_target_buffer[x]=backdrop_col;
      }
    }
  }

  if(visible){
    uint8_t window_control =gba->window[lcd_x];
    if(bg_mode==6 ||bg_mode==7){
      //Palette 0 is taken as the background
    }else if (bg_mode<5){     
      for(int bg = 3; bg>=0;--bg){
        uint32_t col =0;         
        if((bg<2&&bg_mode==2)||(bg==3&&bg_mode==1)||(bg!=2&&bg_mode>=3))continue;
        bool bg_en = SB_BFE(dispcnt,8+bg,1)&&SB_BFE(gba->ppu.dispcnt_pipeline[0],8+bg,1);
        if(!bg_en || SB_BFE(window_control,bg,1)==0)continue;

        bool rot_scale = bg_mode>=1&&bg>=2;
        uint16_t bgcnt = gba_io_read16(gba, GBA_BG0CNT+bg*2);
        int priority = SB_BFE(bgcnt,0,2);
        int character_base = SB_BFE(bgcnt,2,2);
        bool mosaic = SB_BFE(bgcnt,6,1);
        bool colors = SB_BFE(bgcnt,7,1);
        int screen_base = SB_BFE(bgcnt,8,5);
        bool display_overflow =SB_BFE(bgcnt,13,1);
        int screen_size = SB_BFE(bgcnt,14,2);

        int screen_size_x = (screen_size&1)?512:256;
        int screen_size_y = (screen_size>=2)?512:256;
        
        int bg_x = 0;
        int bg_y = 0;
        
        if(rot_scale){
          screen_size_x = screen_size_y = (16*8)<<screen_size;
          if(bg_mode==3||bg_mode==4){
            screen_size_x=240;
            screen_size_y=160;
          }
          colors = true;

          int32_t bgx = gba->ppu.aff[bg-2].internal_bgx;
          int32_t bgy = gba->ppu.aff[bg-2].internal_bgy;

          int32_t a = (int16_t)gba_io_read16(gba,GBA_BG2PA+(bg-2)*0x10);
          int32_t c = (int16_t)gba_io_read16(gba,GBA_BG2PC+(bg-2)*0x10);

          // Shift lcd_coords into fixed point
          int64_t x2 = a*lcd_x + (((int64_t)bgx));
          int64_t y2 = c*lcd_x + (((int64_t)bgy));

          bg_x = (x2>>8);
          bg_y = (y2>>8);

          if(display_overflow==0){
            if(bg_x<0||bg_x>=screen_size_x||bg_y<0||bg_y>=screen_size_y)continue; 
          }else{
            bg_x%=screen_size_x;
            bg_y%=screen_size_y;
          }
                              
        }else{
          int16_t hoff = gba_io_read16(gba,GBA_BG0HOFS+bg*4);
          int16_t voff = gba_io_read16(gba,GBA_BG0VOFS+bg*4);
          hoff=(hoff<<7)>>7;
          voff=(voff<<7)>>7;
          bg_x = (hoff+lcd_x);
          bg_y = (voff+lcd_y);
        }
        if(bg_mode==3){
          int p = bg_x+bg_y*240;
          int addr = p*2; 
          col  = *(uint16_t*)(gba->mem.vram+addr);
        }else if(bg_mode==4){
          int p = bg_x+bg_y*240;
          int frame_sel = SB_BFE(dispcnt,4,1);
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
            tile_d= (tile_d>>((px&1)*4))&0xf;
            if(tile_d==0)continue;
            tile_d+=palette*16;
          }else{
            tile_d=gba->mem.vram[character_base_addr+tile_id*8*8+px+py*8];
            if(tile_d==0)continue;
          }
          uint8_t pallete_id = tile_d;
          col = *(uint16_t*)(gba->mem.palette+GBA_BG_PALETTE+pallete_id*2);
        }
        col |= (bg<<17) | ((5-priority)<<28)|((4-bg)<<25);
        if(col>gba->first_target_buffer[lcd_x]){
          uint32_t t = gba->first_target_buffer[lcd_x];
          gba->first_target_buffer[lcd_x]=col;
          col = t;
        }
        if(col>gba->second_target_buffer[lcd_x])gba->second_target_buffer[lcd_x]=col;          
      }
    }else if(bg_mode!=0){
      printf("Unsupported background mode: %d\n",bg_mode);
    }
    uint32_t col = gba->first_target_buffer[lcd_x];
    int r = SB_BFE(col,0,5);
    int g = SB_BFE(col,5,5);
    int b = SB_BFE(col,10,5);
    uint32_t type = SB_BFE(col,17,3);

    bool effect_enable = SB_BFE(window_control,5,1);
    uint16_t bldcnt = gba_io_read16(gba,GBA_BLDCNT);
    int mode = SB_BFE(bldcnt,6,2);

    //Semitransparent objects are always selected for blending
    if(SB_BFE(col,16,1)){
      uint32_t col2 = gba->second_target_buffer[lcd_x];
      uint32_t type2 = SB_BFE(col2,17,3);
      bool blend = SB_BFE(bldcnt,8+type2,1);
      if(blend){mode=1;effect_enable=true;}
      else effect_enable &= SB_BFE(bldcnt,type,1);
    }else effect_enable &= SB_BFE(bldcnt,type,1);
    if(effect_enable){
      uint16_t bldy = gba_io_read16(gba,GBA_BLDY);
      float evy = SB_BFE(bldy,0,5)/16.;
      if(evy>1.0)evy=1;
      switch(mode){
        case 0: break; //None
        case 1: {
          uint32_t col2 = gba->second_target_buffer[lcd_x];
          uint32_t type2 = SB_BFE(col2,17,3);
          bool blend = SB_BFE(bldcnt,8+type2,1);
          if(blend){
            uint16_t bldalpha= gba_io_read16(gba,GBA_BLDALPHA);
            int r2 = SB_BFE(col2,0,5);
            int g2 = SB_BFE(col2,5,5);
            int b2 = SB_BFE(col2,10,5);
            int eva = SB_BFE(bldalpha,0,5);
            int evb = SB_BFE(bldalpha,8,5);
            if(eva>16)eva=16;
            if(evb>16)evb=16;
            r = (r*eva+r2*evb)/16;
            g = (g*eva+g2*evb)/16;
            b = (b*eva+b2*evb)/16;
            if(r>31)r = 31;
            if(g>31)g = 31;
            if(b>31)b = 31;
          }
        }break; //Alpha Blend
        case 2: //Lighten
          r = r+(31-r)*evy;
          g = g+(31-g)*evy;
          b = b+(31-b)*evy;  
          break; 
        case 3: //Darken
          r = r-(r)*evy;
          g = g-(g)*evy;
          b = b-(b)*evy;         
          break; 
      }
    }
    int p = (lcd_x+lcd_y*240)*3;
    gba->framebuffer[p+0] = r*7;
    gba->framebuffer[p+1] = g*7;
    gba->framebuffer[p+2] = b*7;  
    int backdrop_type = 5;
    uint32_t backdrop_col = (*(uint16_t*)(gba->mem.palette + GBA_BG_PALETTE+0*2))|(backdrop_type<<17);
    gba->first_target_buffer[lcd_x] = backdrop_col;
    gba->second_target_buffer[lcd_x] = backdrop_col;
  }
}
static void gba_tick_keypad(sb_joy_t*joy, gba_t* gba){
  uint16_t reg_value = 0;
  //Null joy updates are used to tick the joypad when mmios are set
  if(joy){
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
  }else reg_value = gba_io_read16(gba, GBA_KEYINPUT);

  uint16_t keycnt = gba_io_read16(gba,GBA_KEYCNT);
  bool irq_enable = SB_BFE(keycnt,14,1);
  bool irq_condition = SB_BFE(keycnt,15,1);//[0: any key, 1: all keys]
  int if_bit = 0;
  if(irq_enable){
    uint16_t pressed = SB_BFE(reg_value,0,10);
    uint16_t mask = SB_BFE(keycnt,0,10);

    if(irq_condition&&((pressed&mask)==mask))if_bit|= 1<<GBA_INT_KEYPAD;
    if(!irq_condition&&((pressed&mask)!=0))if_bit|= 1<<GBA_INT_KEYPAD;

    if(if_bit&&!gba->prev_key_interrupt){
      if_bit |= gba_io_read16(gba,GBA_IF); 
      gba_io_store16(gba,GBA_IF,if_bit);
    }
  }
  gba->prev_key_interrupt = if_bit!=0;

}
uint64_t gba_read_eeprom_bitstream(gba_t *gba, uint32_t source_address, int offset, int size, int elem_size, int dir){
  uint64_t data = 0; 
  for(int i=0;i<size;++i){
    data|= ((uint64_t)(gba_read16(gba,source_address+(i+offset)*elem_size*dir)&1))<<(size-i-1);
  }
  return data; 
}
void gba_store_eeprom_bitstream(gba_t *gba, uint32_t source_address, int offset, int size, int elem_size, int dir,uint64_t data){
  for(int i=0;i<size;++i){
    gba_store16(gba,source_address+(i+offset)*elem_size*dir,data>>(size-i-1)&1);
  }
}
static FORCE_INLINE int gba_tick_dma(gba_t*gba){
  int ticks =0;
  for(int i=0;i<4;++i){
    uint16_t cnt_h=gba_io_read16(gba, GBA_DMA0CNT_H+12*i);
    bool enable = SB_BFE(cnt_h,15,1);
    if(enable){
      bool type = SB_BFE(cnt_h,10,1); // 0: 16b 1:32b

      if(!gba->dma[i].last_enable){
        gba->dma[i].last_enable = enable;
        gba->dma[i].source_addr=gba_io_read32(gba,GBA_DMA0SAD+12*i);
        gba->dma[i].dest_addr=gba_io_read32(gba,GBA_DMA0DAD+12*i);
        //GBA Suite says that these need to be force aligned
        if(type){
          gba->dma[i].dest_addr&=~3;
          gba->dma[i].source_addr&=~3;
        }else{
          gba->dma[i].dest_addr&=~1;
          gba->dma[i].source_addr&=~1;
        }
        gba->dma[i].current_transaction=0;
        ticks+=2;
      }
      int  dst_addr_ctl = SB_BFE(cnt_h,5,2); // 0: incr 1: decr 2: fixed 3: incr reload
      int  src_addr_ctl = SB_BFE(cnt_h,7,2); // 0: incr 1: decr 2: fixed 3: not allowed
      bool dma_repeat = SB_BFE(cnt_h,9,1); 
      int  mode = SB_BFE(cnt_h,12,2);
      bool irq_enable = SB_BFE(cnt_h,14,1);
      uint32_t cnt = gba_io_read16(gba,GBA_DMA0CNT_L+12*i);
        
      int src_dir = 1;
      if(src_addr_ctl==1)src_dir=-1;
      else if(src_addr_ctl==2)src_dir=0;
      
      int dst_dir = 1;
      if(dst_addr_ctl==1)dst_dir=-1;
      else if(dst_addr_ctl==2)dst_dir=0;

      int transfer_bytes = type? 4:2; 
      uint32_t src = gba->dma[i].source_addr;
      uint32_t dst = gba->dma[i].dest_addr;

      if(gba->dma[i].current_transaction==0){
        uint32_t src_end=src+cnt*transfer_bytes*src_dir;
        uint32_t dst_end=dst+cnt*transfer_bytes*dst_dir;

        bool last_vblank = gba->dma[i].last_vblank;
        bool last_hblank = gba->dma[i].last_hblank;
        gba->dma[i].last_vblank = gba->ppu.last_vblank;
        gba->dma[i].last_hblank = gba->ppu.last_hblank;
        if(mode ==1 && !(gba->ppu.last_vblank&&!last_vblank)) continue; 
        uint16_t vcount = gba_io_read16(gba,GBA_VCOUNT);
        if(mode==2){
          if(vcount>=160||!(gba->ppu.last_hblank&&!last_hblank))continue;
        }
        //Video dma
        if(mode==3 && i ==3){
          if(!(gba->ppu.last_hblank&&!last_hblank))continue;
          //Video dma starts at scanline 2
          if(vcount<2)continue;
          if(vcount==161)dma_repeat=false;
        }
      }
      //if(mode==2){printf("Trigger Hblank DMA: %d->%d\n",last_hblank,gba->ppu.last_hblank);}


      if(i!=3)cnt&=0x3fff;
      if(cnt==0)cnt = i==3? 0x10000: 0x4000;

      gba->mem.requests=0; 
      bool skip_dma = false;
      // EEPROM DMA transfers
      if(i==3 && gba->cart.backup_type==GBA_BACKUP_EEPROM){
        int src_in_eeprom = (src&0x1ffffff)>=gba->cart.rom_size||(src&0x1ffffff)>=0x01ffff00;
        int dst_in_eeprom = (dst&0x1ffffff)>=gba->cart.rom_size||(dst&0x1ffffff)>=0x01ffff00;
        src_in_eeprom &= src>=0x8000000 && src<=0xDFFFFFF;
        dst_in_eeprom &= dst>=0x8000000 && dst<=0xDFFFFFF;
        skip_dma = src_in_eeprom || dst_in_eeprom;
        if(dst_in_eeprom){
          if(cnt==73){
            // Write data 6 bit address
            uint32_t addr = gba_read_eeprom_bitstream(gba, src, 2, 6, type?4:2, src_dir);
            uint64_t data = gba_read_eeprom_bitstream(gba, src, 2+6, 64, type?4:2, src_dir); 
            ((uint64_t*)gba->mem.cart_backup)[addr]=data;
            gba->cart.backup_is_dirty=true;
          }else if(cnt==81){
            // Write data 14 bit address
            uint32_t addr = gba_read_eeprom_bitstream(gba, src, 2, 14, type?4:2, src_dir)&0x3ff;
            uint64_t data = gba_read_eeprom_bitstream(gba, src, 2+14, 64, type?4:2, src_dir); 
            ((uint64_t*)gba->mem.cart_backup)[addr]=data;
            gba->cart.backup_is_dirty=true;
          }else if(cnt==9){
            // 2 bits "11" (Read Request)
            // 6 bits eeprom address (MSB first)
            // 1 bit "0"
            // Write data 6 bit address
            gba->mem.eeprom_addr = gba_read_eeprom_bitstream(gba, src, 2, 6, type?4:2, src_dir);
          }else if(cnt==17){
            // 2 bits "11" (Read Request)
            // 14 bits eeprom address (MSB first)
            // 1 bit "0"
            // Write data 6 bit address
            gba->mem.eeprom_addr = gba_read_eeprom_bitstream(gba, src, 2, 14, type?4:2, src_dir)&0x3ff;
          }else{
            printf("Bad cnt: %d for eeprom write\n",cnt);
          }
          gba->dma[i].current_transaction=cnt;
        }
        if(src_in_eeprom){
          if(cnt==68){
            uint64_t data = ((uint64_t*)gba->mem.cart_backup)[gba->mem.eeprom_addr];
            gba_store_eeprom_bitstream(gba, dst, 4, 64, type?4:2, dst_dir,data);
          }else{
            printf("Bad cnt: %d for eeprom read\n",cnt);
          }
          gba->dma[i].current_transaction=cnt;
        }
      }
      bool audio_dma = (mode==3) && (i==1||i==2);
      if(audio_dma){
        int fifo = -1;
        dst&=~3;
        src&=~3;
        if(dst == GBA_FIFO_A)fifo =0; 
        if(dst == GBA_FIFO_B)fifo =1; 
        if(fifo == -1)continue;
        int size = (gba->audio.fifo[fifo].write_ptr-gba->audio.fifo[fifo].read_ptr)&0x1f;
        if(size>=16)continue;
        //printf("Fill DMA %d (size:%d w:%d r:%d) :%08x\n",fifo,size,gba->audio.fifo[fifo].write_ptr,gba->audio.fifo[fifo].read_ptr,src);
        for(int x=0;x<4;++x){
          uint32_t data = arm7_read32_seq(gba,src+x*4*src_dir,x!=0);
          gba_audio_fifo_push(gba,fifo,SB_BFE(data,0,8));
          gba_audio_fifo_push(gba,fifo,SB_BFE(data,8,8));
          gba_audio_fifo_push(gba,fifo,SB_BFE(data,16,8));
          gba_audio_fifo_push(gba,fifo,SB_BFE(data,24,8));
        }
        dma_repeat=true;
        dst_addr_ctl= 2; 
        transfer_bytes=4;
        cnt=4;
        skip_dma=true;
        gba->dma[i].current_transaction=cnt;
      }
      //printf("DMA%d: src:%08x dst:%08x len:%04x type:%d mode:%d repeat:%d irq:%d dstct:%d srcctl:%d\n",i,src,dst,cnt, type,mode,dma_repeat,irq_enable,dst_addr_ctl,src_addr_ctl);
      if(!skip_dma){
        // This code is complicated to handle the per channel DMA latches that are present
        // Correct implementation is needed to pass latch.gba, Pokemon Pinball (intro explosion),
        // and the text in Lufia
        // TODO: There in theory should be separate latches per DMA, but that breaks Hello Kitty
        // and Tomb Raider
        if(gba->dma[i].current_transaction<cnt){
          int x = gba->dma[i].current_transaction++;
          if(type){
            int src_addr = (src+x*4*src_dir)&0x0fffffff;
            if((i!=0||src_addr<0x08000000)&&(src_addr>=0x02000000)){
              gba->dma[i].latched_transfer = arm7_read32_seq(gba,src_addr,x!=0);
            }
            arm7_write32(gba,dst+x*4*dst_dir,gba->dma[i].latched_transfer);
          }else{
            int src_addr = (src+x*2*src_dir)&0x0fffffff;
            int dst_addr = dst+x*2*dst_dir;
            int v = 0;
            if((i!=0||src_addr<0x08000000)&&(src_addr>=0x02000000)){
              v= gba->dma[i].latched_transfer = (arm7_read16_seq(gba,src_addr,x!=0))&0xffff;
              gba->dma[i].latched_transfer |= gba->dma[i].latched_transfer<<16;
            }else v = gba->dma[i].latched_transfer>>(((dst_addr)&0x3)*8);
            arm7_write16(gba,dst_addr,v&0xffff);
          }
        }
      }
      
      ticks+=gba->mem.requests;
      if(gba->dma[i].current_transaction>=cnt){
        if(dst_addr_ctl==0)     dst+=cnt*transfer_bytes;
        else if(dst_addr_ctl==1)dst-=cnt*transfer_bytes;
        if(src_addr_ctl==0)     src+=cnt*transfer_bytes;
        else if(src_addr_ctl==1)src-=cnt*transfer_bytes;
        
        gba->dma[i].source_addr=src;
        gba->dma[i].dest_addr=dst;
      
        if(irq_enable){
          uint16_t if_val = gba_io_read16(gba,GBA_IF);
          uint16_t if_bit = 1<<(GBA_INT_DMA0+i);
          if(if_bit){
            if_val |= if_bit;
            gba_io_store16(gba,GBA_IF,if_val);
          }
        }
        if(!dma_repeat||mode==0){
          cnt_h&=0x7fff;
          //gba_io_store16(gba, GBA_DMA0CNT_L+12*i,0);
          //Reload on incr reload     
          enable =false;
        }else{
          gba->dma[i].current_transaction=0;
          if(dst_addr_ctl==3){
            gba->dma[i].dest_addr=gba_io_read32(gba,GBA_DMA0DAD+12*i);
            //GBA Suite says that these need to be force aligned
            if(type) gba->dma[i].dest_addr&=~3;
            else gba->dma[i].dest_addr&=~1;
          }
        }
      }
      gba_io_store16(gba, GBA_DMA0CNT_H+12*i,cnt_h);
    }
    gba->dma[i].last_enable = enable;
    if(ticks)break;
  }
  gba->activate_dmas=ticks!=0;
  return ticks; 
}                                              
static FORCE_INLINE void gba_tick_sio(gba_t* gba){
  //Just a stub for now;
  uint16_t siocnt = gba_io_read16(gba,GBA_SIOCNT);
  bool active = SB_BFE(siocnt,7,1);
  bool irq_enabled = SB_BFE(siocnt,14,1);
  if(active){
   
    if(irq_enabled){
      uint16_t if_val = gba_io_read16(gba,GBA_IF);
      uint16_t if_bit = 1<<(GBA_INT_SERIAL);
      if(if_bit){
        if_val |= if_bit;
        gba_io_store16(gba,GBA_IF,if_val);
      }
    }
    siocnt&= ~(1<<7);
    gba_io_store16(gba,GBA_SIOCNT,siocnt);
  }
}
static FORCE_INLINE void gba_tick_timers(gba_t* gba, int ticks, bool force_recalculate){
  gba->deferred_timer_ticks+=ticks;
  if(gba->deferred_timer_ticks<gba->timer_ticks_before_event&&force_recalculate==false)return; 
  ticks = gba->deferred_timer_ticks; 
  gba->deferred_timer_ticks=0;
  int last_timer_overflow = 0; 
  int timer_ticks_before_event = 32768; 
  for(int t=0;t<4;++t){ 
    uint16_t tm_cnt_h = gba_io_read16(gba,GBA_TM0CNT_H+t*4);
    bool enable = SB_BFE(tm_cnt_h,7,1);
    if(enable){
      uint16_t prescale = SB_BFE(tm_cnt_h,0,2);
      bool count_up     = SB_BFE(tm_cnt_h,2,1);
      bool irq_en       = SB_BFE(tm_cnt_h,6,1);
      uint16_t value = gba_io_read16(gba,GBA_TM0CNT_L+t*4);
      if(enable!=gba->timers[t].last_enable&&enable){
        value = gba->timers[t].reload_value;
        gba->timers[t].last_enable = enable;
        gba->timers[t].prescaler_timer=0;
      }
      
      if(count_up){
        if(last_timer_overflow){
          uint32_t v= value;
          v+=last_timer_overflow;
          last_timer_overflow=0;
          while(v>0xffff){
            v=(v+gba->timers[t].reload_value)-0x10000;
            last_timer_overflow++;
            gba->timers[t].elapsed_audio_samples++;
          }
          value=v;
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
          v=(v+gba->timers[t].reload_value)-0x10000;
          last_timer_overflow++;
          gba->timers[t].elapsed_audio_samples++;
        }
        value = v; 
        gba->timers[t].prescaler_timer=prescale_time*2;
        int ticks_before_overflow = (int)(0xffff-value)<<(prescale_duty);
        if(ticks_before_overflow<timer_ticks_before_event)timer_ticks_before_event=ticks_before_overflow;
      }
      if(last_timer_overflow && irq_en){
        uint16_t if_bit = 1<<(GBA_INT_TIMER0+t);
        if(if_bit){
          uint16_t if_val = gba_io_read16(gba,GBA_IF);
          if_val |= if_bit;
          gba_io_store16(gba,GBA_IF,if_val);
        }
      }
      
      gba_io_store16(gba,GBA_TM0CNT_L+t*4,value);
    }else last_timer_overflow=0;
    gba->timers[t].last_enable = enable;
  }
  gba->timer_ticks_before_event=timer_ticks_before_event;
}
static FORCE_INLINE float gba_compute_vol_env_slope(int length_of_step,int dir){
  float step_time = length_of_step/64.0;
  float slope = 1./step_time;
  if(dir==0)slope*=-1;
  if(length_of_step==0)slope=0;
  return slope/16.;
} 
static FORCE_INLINE float gba_polyblep(float t,float dt){
  if(t<=dt){    
    t = t/dt;
    return t+t-t*t-1.0;;
  }else if (t >= 1-dt){
    t=(t-1.0)/dt;
    return t*t+t+t+1.0;
  }else return 0; 
}
static FORCE_INLINE float gba_bandlimited_square(float t, float duty_cycle,float dt){
  float t2 = t - duty_cycle;
  if(t2< 0.0)t2 +=1.0;
  float y = t < duty_cycle ? -1 : 1;
  y -= gba_polyblep(t,dt);
  y += gba_polyblep(t2,dt);
  return y;
}
static FORCE_INLINE void gba_tick_audio(gba_t *gba, sb_emu_state_t*emu, double delta_time){
  
  static double current_sim_time = 0;
  static double current_sample_generated_time = 0;

  current_sim_time +=delta_time;
  if(current_sample_generated_time >current_sim_time)return; 
  //TODO: Move these into a struct
  static float chan_t[4] = {0,0,0,0};
  static float length_t[4]={1e6,1e6,1e6,1e6};
  float freq_hz[4] = {0,0,0,0}, length[4]= {0,0,0,0}, volume[4]={0,0,0,0};
  float volume_env[4]={0,0,0,0};
  static float last_noise_value = 0;

  current_sample_generated_time -= (int)(current_sim_time);
  current_sim_time -= (int)(current_sim_time);

  static float capacitor_r = 0.0;
  static float capacitor_l = 0.0;

  const static float duty_lookup[]={0.125,0.25,0.5,0.75};

  float sample_delta_t = 1.0/SE_AUDIO_SAMPLE_RATE;

  uint8_t freq_sweep1 = gba_io_read8(gba, GBA_SOUND1CNT_L);
  float freq_sweep_n1 = SB_BFE(freq_sweep1, 0,3);
  float freq_sweep_sign1 = SB_BFE(freq_sweep1, 3,1)? -1. : 1;
  float freq_sweep_time_mul1 = SB_BFE(freq_sweep1, 4, 3)/128.;

  if(SB_BFE(freq_sweep1,0,3)==0){freq_sweep_sign1=0;freq_sweep_time_mul1=0;}

  float duty[2] = {0,0};

  for(int i=0;i<2;++i){
    uint16_t soundcnt_h = gba_io_read16(gba, i==0? GBA_SOUND1CNT_H : GBA_SOUND2CNT_L);
    length[i] = (64.-SB_BFE(soundcnt_h,0,6))/256.;
    duty[i] = duty_lookup[SB_BFE(soundcnt_h,6,2)];
    volume_env[i] = gba_compute_vol_env_slope(SB_BFE(soundcnt_h, 8, 3), SB_BFE(soundcnt_h, 11, 1));
    volume[i] = SB_BFE(soundcnt_h,12,4)/15.f;

    uint16_t soundcnt_x = gba_io_read16(gba, i==0? GBA_SOUND1CNT_X : GBA_SOUND2CNT_H);
    freq_hz[i] = 131072.0/(2048.-SB_BFE(soundcnt_x,0,11));
    if(SB_BFE(soundcnt_x,14,1)==0){length[i] = 1.0e9;}
    if(SB_BFE(soundcnt_x,15,1)){length_t[i] = 0;}

    soundcnt_x&=0x7fff;
    gba_io_store16(gba, i==0? GBA_SOUND1CNT_X : GBA_SOUND2CNT_H,soundcnt_x);

  }

  /*
  4000070h - SOUND3CNT_L (NR30) - Channel 3 Stop/Wave RAM select (R/W)

    Bit        Expl.
    0-4   -    Not used
    5     R/W  Wave RAM Dimension   (0=One bank/32 digits, 1=Two banks/64 digits)
    6     R/W  Wave RAM Bank Number (0-1, see below)
    7     R/W  Sound Channel 3 Off  (0=Stop, 1=Playback)
    8-15  -    Not used

  The currently selected Bank Number (Bit 6) will be played back, while reading/writing to/from wave RAM will address the other (not selected) bank. When dimension is set to two banks, output will start by replaying the currently selected bank.

  4000072h - SOUND3CNT_H (NR31, NR32) - Channel 3 Length/Volume (R/W)

    Bit        Expl.
    0-7   W    Sound length; units of (256-n)/256s  (0-255)
    8-12  -    Not used.
    13-14 R/W  Sound Volume  (0=Mute/Zero, 1=100%, 2=50%, 3=25%)
    15    R/W  Force Volume  (0=Use above, 1=Force 75% regardless of above)

  The Length value is used only if Bit 6 in NR34 is set.

  4000074h - SOUND3CNT_X (NR33, NR34) - Channel 3 Frequency/Control (R/W)

    Bit        Expl.
    0-10  W    Sample Rate; 2097152/(2048-n) Hz   (0-2047)
    11-13 -    Not used
    14    R/W  Length Flag  (1=Stop output when length in NR31 expires)
    15    W    Initial      (1=Restart Sound)
    16-31 -    Not used
  */
  uint16_t sound3cnt_l = gba_io_read8(gba,GBA_SOUND3CNT_L);
  int wave_sample_entries = SB_BFE(sound3cnt_l,5,1) ? 32: 64;
  int wave_sample_offset = SB_BFE(sound3cnt_l,6,1)? 0 : 32;
  volume[2] = SB_BFE(sound3cnt_l,7,1);

  uint16_t sound3cnt_h = gba_io_read16(gba,GBA_SOUND3CNT_H);
  float volume_lookup[8]={0,1,0.5,0.25,0.75,0.75,0.75,0.75};
  length[2] = (256.-SB_BFE(sound3cnt_h,0,8))/256.;
  volume[2]*= volume_lookup[SB_BFE(sound3cnt_h,13,3)];

  uint16_t sound3cnt_x = gba_io_read16(gba,GBA_SOUND3CNT_X);
  freq_hz[2] = (65536.0)/(2048.-SB_BFE(sound3cnt_x,0,11));
  if(SB_BFE(sound3cnt_x,14,1)==0){length[2] = 1.0e9;}
  if(SB_BFE(sound3cnt_x,15,1)){length_t[2] = 0;}
  sound3cnt_x&=0x7fff;
  gba_io_store16(gba, GBA_SOUND3CNT_X ,sound3cnt_x);

  uint16_t soundcnt4_l = gba_io_read16(gba, GBA_SOUND4CNT_L);
  length[3] = (64.-SB_BFE(soundcnt4_l,0,6))/256.;
  volume_env[3] = gba_compute_vol_env_slope(SB_BFE(soundcnt4_l, 8, 3), SB_BFE(soundcnt4_l, 11, 1));
  volume[3] = SB_BFE(soundcnt4_l,12,4)/15.f;

  uint16_t soundcnt4_h = gba_io_read16(gba, GBA_SOUND4CNT_H);
  float r4 = SB_BFE(soundcnt4_h,0,3);
  uint8_t s4 = SB_BFE(soundcnt4_h,4,4);
  if(r4==0)r4=0.5;
  freq_hz[3] =  524288.0/r4/pow(2.0,s4+1);
  if(SB_BFE(soundcnt4_l,14,1)==0){length[3] = 1.0e9;}
  if(SB_BFE(soundcnt4_l,15,1)){length_t[3] = 0;}
  soundcnt4_h&=0x7fff;
  gba_io_store16(gba, GBA_SOUND4CNT_H,soundcnt4_h);



  //These are type int to allow them to be multiplied to enable/disable
  float chan_l[6],chan_r[6];
  uint16_t chan_sel = gba_io_read16(gba,GBA_SOUNDCNT_L);
  uint16_t soundcnt_h = gba_io_read16(gba,GBA_SOUNDCNT_H);
  /* soundcnth 
  0-1   R/W  Sound # 1-4 Volume   (0=25%, 1=50%, 2=100%, 3=Prohibited)
  2     R/W  DMA Sound A Volume   (0=50%, 1=100%)
  3     R/W  DMA Sound B Volume   (0=50%, 1=100%)
  4-7   -    Not used
  8     R/W  DMA Sound A Enable RIGHT (0=Disable, 1=Enable)
  9     R/W  DMA Sound A Enable LEFT  (0=Disable, 1=Enable)
  10    R/W  DMA Sound A Timer Select (0=Timer 0, 1=Timer 1)
  11    W?   DMA Sound A Reset FIFO   (1=Reset)
  12    R/W  DMA Sound B Enable RIGHT (0=Disable, 1=Enable)
  13    R/W  DMA Sound B Enable LEFT  (0=Disable, 1=Enable)
  14    R/W  DMA Sound B Timer Select (0=Timer 0, 1=Timer 1)
  15    W?   DMA Sound B Reset FIFO   (1=Reset)*/ 
  float psg_volume_lookup[4]={0.25,0.5,1.0,0.};
  float psg_volume = psg_volume_lookup[SB_BFE(soundcnt_h,0,2)]*0.25;

  float r_vol = SB_BFE(chan_sel,0,3)/7.*psg_volume;
  float l_vol = SB_BFE(chan_sel,4,3)/7.*psg_volume;
  for(int i=0;i<4;++i){
    chan_r[i] = SB_BFE(chan_sel,8+i,1)*r_vol;
    chan_l[i] = SB_BFE(chan_sel,12+i,1)*l_vol;
  }
  // Channel volume for each FIFO
  for(int i=0;i<2;++i){
    // Volume
    chan_r[i+4]=chan_l[i+4]= SB_BFE(soundcnt_h,2+i,1)? 1.0: 0.5;
    chan_r[i+4]*= SB_BFE(soundcnt_h,8+i*4,1);
    chan_l[i+4]*= SB_BFE(soundcnt_h,9+i*4,1);
    int timer = SB_BFE(soundcnt_h,10+i*4,1);
    bool reset = SB_BFE(soundcnt_h,11+i*4,1);
    if(reset){
      gba->audio.fifo[i].read_ptr=gba->audio.fifo[i].write_ptr=0;  
      for(int d=0;d<32;++d)gba->audio.fifo[i].data[d]=0;
      gba->activate_dmas=true;
    }
    int samples_to_pop = gba->timers[timer].elapsed_audio_samples;
    //if(chan_r[i+4]||chan_l[i+4])printf("Chan %d: audio_samples: %d \n", i, samples_to_pop);
    while(samples_to_pop>0&& ((gba->audio.fifo[i].write_ptr-gba->audio.fifo[i].read_ptr)&0x1f)){
      gba->audio.fifo[i].read_ptr=(gba->audio.fifo[i].read_ptr+1)&0x1f;
      samples_to_pop--;
      gba->activate_dmas=true;
    }
  }
  gba_io_store16(gba,GBA_SOUNDCNT_H,soundcnt_h&~((1<<11)|(1<<15)));


  /*printf("0R: %d, 0W: %d, 1R: %d, 1W: %d elapsed0: %d elapsed1: %d\n", gba->audio.fifo[0].read_ptr,gba->audio.fifo[0].write_ptr,
                                             gba->audio.fifo[1].read_ptr,gba->audio.fifo[1].write_ptr,
                                             gba->timers[0].elapsed_audio_samples,gba->timers[1].elapsed_audio_samples);
  */
  gba->timers[0].elapsed_audio_samples= 0;
  gba->timers[1].elapsed_audio_samples= 0;
  
  float freq1_hz_base = freq_hz[0];

  while(current_sample_generated_time < current_sim_time){

    current_sample_generated_time+=1.0/SE_AUDIO_SAMPLE_RATE;
    
    if((sb_ring_buffer_size(&emu->audio_ring_buff)+3>SB_AUDIO_RING_BUFFER_SIZE)) continue;

    //Advance each channel    
    freq_hz[0] = freq1_hz_base*pow((1.+freq_sweep_sign1*pow(2.,-freq_sweep_n1)),length_t[0]/freq_sweep_time_mul1);
    for(int i=0;i<4;++i)chan_t[i]  +=sample_delta_t*freq_hz[i];
    for(int i=0;i<4;++i)length_t[i]+=sample_delta_t;
    for(int i=0;i<4;++i)if(length_t[i]>length[i]){volume[i]=0;volume_env[i]=0;}

    //Generate new noise value if needed
    if(chan_t[3]>=1.0)last_noise_value = sb_random_float(0,1)*2.-1.;
    
    //Loop back
    for(int i=0;i<4;++i){
      chan_t[i]-=(int)chan_t[i];
    }
    
    //Compute and clamp Volume Envelopes
    float v[4];
    for(int i=0;i<4;++i)v[i] = volume_env[i]*length_t[i]+volume[i];
    for(int i=0;i<4;++i)v[i] = v[i]>1.0? 1.0 : (v[i]<0.0? 0.0 : v[i]); 
    v[2]=volume[2]; //Wave channel doesn't have a volume envelop 
    
    //Lookup wave table value TODO: Implement wave table banking
    unsigned wav_samp = (((unsigned)(chan_t[2]*32))%32);
    int dat =gba_io_read8(gba,GBA_WAVE_RAM+wav_samp/2);
    int offset = (wav_samp&1)? 0:4;
    dat = (dat>>offset)&0xf;
    

    float channels[6] = {0,0,0,0,0,0};
    channels[0] = gba_bandlimited_square(chan_t[0],duty[0],sample_delta_t*freq_hz[0])*v[0];
    channels[1] = gba_bandlimited_square(chan_t[1],duty[1],sample_delta_t*freq_hz[1])*v[1];
    channels[2] = (dat)*v[2]/16.;
    channels[3] = last_noise_value*v[3];

    for(int i=0;i<2;++i)
      channels[4+i] = gba->audio.fifo[i].data[gba->audio.fifo[i].read_ptr&0x1f]/128.;
    
    //Mix channels
    
    float sample_volume_l = 0;
    float sample_volume_r = 0;
    
    for(int i=0;i<6;++i){
      sample_volume_l+=channels[i]*chan_l[i];
      sample_volume_r+=channels[i]*chan_r[i];
    }
    
    sample_volume_l*=0.25;
    sample_volume_r*=0.25;

    const float lowpass_coef = 0.999;
    emu->mix_l_volume = emu->mix_l_volume*lowpass_coef + fabs(sample_volume_l)*(1.0-lowpass_coef);
    emu->mix_r_volume = emu->mix_r_volume*lowpass_coef + fabs(sample_volume_r)*(1.0-lowpass_coef); 
    
    for(int i=0;i<6;++i){
      emu->audio_channel_output[i] = emu->audio_channel_output[i]*lowpass_coef 
                                  + fabs(channels[i]*(chan_l[i]+chan_r[i])*0.5)*(1.0-lowpass_coef); 
    }
    // Clipping
    if(sample_volume_l>1.0)sample_volume_l=1;
    if(sample_volume_r>1.0)sample_volume_r=1;
    if(sample_volume_l<-1.0)sample_volume_l=-1;
    if(sample_volume_r<-1.0)sample_volume_r=-1;
    float out_l = sample_volume_l-capacitor_l;
    float out_r = sample_volume_r-capacitor_r;
    capacitor_l = (sample_volume_l-out_l)*0.996;
    capacitor_r = (sample_volume_r-out_r)*0.996;
    // Quantization
    unsigned write_entry0 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
    unsigned write_entry1 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;

    emu->audio_ring_buff.data[write_entry0] = out_l*32760;
    emu->audio_ring_buff.data[write_entry1] = out_r*32760;
    uint16_t soundcnt_x = gba_io_read16(gba,GBA_SOUNDCNT_X)&~0xf;
    //Compute enable flags
    for(int i=0;i<4;++i){
      if(length_t[i]<length[i])soundcnt_x|= 1<<i;
    }
    gba_io_store16(gba,GBA_SOUNDCNT_X,soundcnt_x);
  }
}
void gba_tick(sb_emu_state_t* emu, gba_t* gba){

  if(emu->run_mode == SB_MODE_RESET){
    gba_reset(gba);
    emu->run_mode = SB_MODE_RUN;
  }
  int frames_to_render= gba->ppu.last_vblank?1:2;

  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    //printf("New frame\n");
    gba_tick_keypad(&emu->joy,gba);
    int max_instructions = 2808960;
    if(emu->step_frames)max_instructions*=emu->step_frames;
    if(emu->step_instructions) max_instructions = emu->step_instructions;
    bool prev_vblank = gba->ppu.last_vblank; 
    //Skip emulation of a frame if we get too far ahead the audio playback

    gba->cpu.print_instructions = emu->run_mode ==SB_MODE_STEP;

    for(int i = 0;i<max_instructions;++i){
      int ticks = gba->activate_dmas? gba_tick_dma(gba) :0;
      if(!ticks){
        uint16_t int_if = gba_io_read16(gba,GBA_IF);
        if(int_if)int_if &= gba_io_read16(gba,GBA_IE);
        if(gba->halt){
          if(int_if)gba->halt = false;
          ticks=4;
        }else{
          if(int_if){
            uint32_t ime = gba_io_read32(gba,GBA_IME);
            if(SB_BFE(ime,0,1)==1)arm7_process_interrupts(&gba->cpu, int_if);
          }
          gba->mem.requests=0;
          arm7_exec_instruction(&gba->cpu);
          if(gba->mem.prefetch_en){
            gba->mem.prefetch_size += gba->cpu.i_cycles;
            if(gba->mem.prefetch_size>8)gba->mem.prefetch_size = 8; 
          }
          ticks = gba->mem.requests+gba->cpu.i_cycles; 
          if(gba->cpu.i_cycles&&gba->mem.prefetch_en==false){
            uint32_t pc = gba->cpu.registers[15];
            // The GBA CPU has a bug that causes all fetches after i_cycles to be non-sequential
            uint32_t bank = SB_BFE(pc,24,4);
            gba->mem.prefetch_size = 0;
            ticks+=gba->mem.wait_state_table[bank*4+3]-gba->mem.wait_state_table[bank*4+2];
          }
        }
        bool breakpoint = gba->cpu.registers[PC]== emu->pc_breakpoint;
        breakpoint |= gba->cpu.trigger_breakpoint;
        if(breakpoint){emu->run_mode = SB_MODE_PAUSE; gba->cpu.trigger_breakpoint=false; break;}
      }
      for(int t = 0;t<ticks;++t){
        gba_tick_ppu(gba,1,frames_to_render<=0);
      }
      gba_tick_sio(gba);
      gba_tick_timers(gba,ticks,false);

      double delta_t = ((double)ticks)/(16*1024*1024);
      gba_tick_audio(gba, emu,delta_t);

      if(gba->ppu.last_vblank && !prev_vblank){
        emu->frame++;
        if(emu->frame>=emu->step_frames&&emu->step_frames>1)break;
        frames_to_render--;
        //if(emu->step_instructions==0)break;
      }
      int size = sb_ring_buffer_size(&emu->audio_ring_buff);
      int samples_per_buffer = SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS;
      if(((size>1.5*samples_per_buffer&&emu->frame>=1&&gba->ppu.last_vblank)||
          (size>3*samples_per_buffer&&gba->ppu.last_hblank))&&emu->step_instructions==0&&emu->step_frames<=1)break;

      prev_vblank = gba->ppu.last_vblank;
    }
  }                  
  
  if(emu->run_mode == SB_MODE_STEP) emu->run_mode = SB_MODE_PAUSE; 
}

void gba_reset(gba_t*gba){
  gba->cpu = arm7_init(gba);
  memcpy(gba->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  gba->mem.openbus_word = gba->mem.cart_rom[0];
  memset(gba->mem.io,0,sizeof(gba->mem.io));
  memset(gba->mem.wram0,0,sizeof(gba->mem.wram0));
  memset(gba->mem.wram1,0,sizeof(gba->mem.wram1));
  for(int bg = 2;bg<4;++bg){
    gba_io_store16(gba,GBA_BG2PA+(bg-2)*0x10,1<<8);
    gba_io_store16(gba,GBA_BG2PB+(bg-2)*0x10,0<<8);
    gba_io_store16(gba,GBA_BG2PC+(bg-2)*0x10,0<<8);
    gba_io_store16(gba,GBA_BG2PD+(bg-2)*0x10,1<<8);
  }
  //gba_store32(gba,GBA_DISPCNT,0xe92d0000);
  gba_store16(gba,0x04000088,512);
  gba_store32(gba,0x040000DC,0x84000000);
  gba_recompute_waitstate_table(gba,0);
  gba->halt =false;
  gba->activate_dmas=false;
  gba->deferred_timer_ticks=0;
  gba->cart.in_chip_id_mode=false; 
  gba->cart.flash_state=0;
  gba->cart.flash_bank=0; 

  bool skip_bios = true;
  if(skip_bios){
    gba->cpu.registers[13] = 0x03007f00;
    gba->cpu.registers[R13_irq] = 0x03007FA0;
    gba->cpu.registers[R13_svc] = 0x03007FE0;
    gba->cpu.registers[R13_und] = 0x00000000;
    gba->cpu.registers[CPSR]= 0x000000df; 
    gba->cpu.registers[PC]  = 0x08000000; 
    gba_store32(gba,GBA_IE,0x1);
    gba_store16(gba,GBA_DISPCNT,0x9140);
  }else{
    gba->cpu.registers[PC]  = 0x0000000; 
    gba->cpu.registers[CPSR]= 0x000000d3; 
  }
}

#endif
