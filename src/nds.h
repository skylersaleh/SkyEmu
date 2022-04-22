#ifndef SE_NDS_H
#define SE_NDS_H 1

#include "sb_types.h"


typedef enum{
  kARM7,
  kARM9,
}nds_arm_mode_t;
//////////////////////////////////////////////////////////////////////////////////////////
// MMIO Register listing from GBATEK (https://problemkaputt.de/gbatek.htm#dsiomaps)     //
//////////////////////////////////////////////////////////////////////////////////////////

// There is a bit of a remapping here:
/*
- ARM7 registers > #define NDS_IO_MAP_SPLIT_ADDRESS  are or'd by NDS_IO_MAP_SPLIT_OFFSET 
- 0x04100000-0x041ffffff > are or'd by NDS_IO_MAP_041_OFFSET
*/
//////////////////
// GBA I/O Map //
//////////////////

#define GBA_DISPCNT  0x4000000  /* R/W LCD Control */
#define GBA_GREENSWP 0x4000002  /* R/W Undocumented - Green Swap */
#define GBA_DISPSTAT 0x4000004  /* R/W General LCD Status (STAT,LYC) */
#define GBA_VCOUNT   0x4000006  /* R   Vertical Counter (LY) */
#define GBA_BG0CNT   0x4000008  /* R/W BG0 Control */
#define GBA_BG1CNT   0x400000A  /* R/W BG1 Control */
#define GBA_BG2CNT   0x400000C  /* R/W BG2 Control */
#define GBA_BG3CNT   0x400000E  /* R/W BG3 Control */
#define GBA_BG0HOFS  0x4000010  /* W   BG0 X-Offset */
#define GBA_BG0VOFS  0x4000012  /* W   BG0 Y-Offset */
#define GBA_BG1HOFS  0x4000014  /* W   BG1 X-Offset */
#define GBA_BG1VOFS  0x4000016  /* W   BG1 Y-Offset */
#define GBA_BG2HOFS  0x4000018  /* W   BG2 X-Offset */
#define GBA_BG2VOFS  0x400001A  /* W   BG2 Y-Offset */
#define GBA_BG3HOFS  0x400001C  /* W   BG3 X-Offset */
#define GBA_BG3VOFS  0x400001E  /* W   BG3 Y-Offset */
#define GBA_BG2PA    0x4000020  /* W   BG2 Rotation/Scaling Parameter A (dx) */
#define GBA_BG2PB    0x4000022  /* W   BG2 Rotation/Scaling Parameter B (dmx) */
#define GBA_BG2PC    0x4000024  /* W   BG2 Rotation/Scaling Parameter C (dy) */
#define GBA_BG2PD    0x4000026  /* W   BG2 Rotation/Scaling Parameter D (dmy) */
#define GBA_BG2X     0x4000028  /* W   BG2 Reference Point X-Coordinate */
#define GBA_BG2Y     0x400002C  /* W   BG2 Reference Point Y-Coordinate */
#define GBA_BG3PA    0x4000030  /* W   BG3 Rotation/Scaling Parameter A (dx) */
#define GBA_BG3PB    0x4000032  /* W   BG3 Rotation/Scaling Parameter B (dmx) */
#define GBA_BG3PC    0x4000034  /* W   BG3 Rotation/Scaling Parameter C (dy) */
#define GBA_BG3PD    0x4000036  /* W   BG3 Rotation/Scaling Parameter D (dmy) */
#define GBA_BG3X     0x4000038  /* W   BG3 Reference Point X-Coordinate */
#define GBA_BG3Y     0x400003C  /* W   BG3 Reference Point Y-Coordinate */
#define GBA_WIN0H    0x4000040  /* W   Window 0 Horizontal Dimensions */
#define GBA_WIN1H    0x4000042  /* W   Window 1 Horizontal Dimensions */
#define GBA_WIN0V    0x4000044  /* W   Window 0 Vertical Dimensions */
#define GBA_WIN1V    0x4000046  /* W   Window 1 Vertical Dimensions */
#define GBA_WININ    0x4000048  /* R/W Inside of Window 0 and 1 */
#define GBA_WINOUT   0x400004A  /* R/W Inside of OBJ Window & Outside of Windows */
#define GBA_MOSAIC   0x400004C  /* W   Mosaic Size */
#define GBA_BLDCNT   0x4000050  /* R/W Color Special Effects Selection */
#define GBA_BLDALPHA 0x4000052  /* R/W Alpha Blending Coefficients */
#define GBA_BLDY     0x4000054  /* W   Brightness (Fade-In/Out) Coefficient */
#define NDS_DISP3DCNT       0x04000060  /* 3D Display Control Register (R/W) */
#define NDS_DISPCAPCNT      0x04000064  /* Display Capture Control Register (R/W) */
#define NDS_DISP_MMEM_FIFO  0x04000068  /* Main Memory Display FIFO (R?/W) */
#define NDS_A_MASTER_BRIGHT 0x0400006C  /* Master Brightness Up/Down */

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

//////////////////
// ARM9 I/O Map //
//////////////////

// ARM9 IPC/ROM

#define NDS9_IPCSYNC     0x04000180   /*IPC Synchronize Register (R/W)*/
#define NDS9_IPCFIFOCNT  0x04000184   /*IPC Fifo Control Register (R/W)*/
#define NDS9_IPCFIFOSEND 0x04000188   /*IPC Send Fifo (W)*/
#define NDS9_AUXSPICNT   0x040001A0   /*Gamecard ROM and SPI Control*/
#define NDS9_AUXSPIDATA  0x040001A2   /*Gamecard SPI Bus Data/Strobe*/
#define NDS9_GC_BUS_CTL  0x040001A4   /*Gamecard bus timing/control*/
#define NDS9_GC_BUS_DAT  0x040001A8   /*Gamecard bus 8-byte command out*/
#define NDS9_GC_ENC0_LO  0x040001B0   /*Gamecard Encryption Seed 0 Lower 32bit*/
#define NDS9_GC_ENC1_LO  0x040001B4   /*Gamecard Encryption Seed 1 Lower 32bit*/
#define NDS9_GC_ENC0_HI  0x040001B8   /*Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused)*/
#define NDS9_GC_ENC1_HI  0x040001BA   /*Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused)*/

// ARM9 Memory and IRQ Control

#define NDS9_EXMEMCNT  0x04000204 /* External Memory Control (R/W) */
#define NDS9_IME       0x04000208 /* Interrupt Master Enable (R/W) */
#define NDS9_IE        0x04000210 /* Interrupt Enable (R/W) */
#define NDS9_IF        0x04000214 /* Interrupt Request Flags (R/W) */
#define NDS9_VRAMCNT_A 0x04000240 /* VRAM-A (128K) Bank Control (W) */
#define NDS9_VRAMCNT_B 0x04000241 /* VRAM-B (128K) Bank Control (W) */
#define NDS9_VRAMCNT_C 0x04000242 /* VRAM-C (128K) Bank Control (W) */
#define NDS9_VRAMCNT_D 0x04000243 /* VRAM-D (128K) Bank Control (W) */
#define NDS9_VRAMCNT_E 0x04000244 /* VRAM-E (64K) Bank Control (W) */
#define NDS9_VRAMCNT_F 0x04000245 /* VRAM-F (16K) Bank Control (W) */
#define NDS9_VRAMCNT_G 0x04000246 /* VRAM-G (16K) Bank Control (W) */
#define NDS9_WRAMCNT   0x04000247 /* WRAM Bank Control (W) */
#define NDS9_VRAMCNT_H 0x04000248 /* VRAM-H (32K) Bank Control (W) */
#define NDS9_VRAMCNT_I 0x04000249 /* VRAM-I (16K) Bank Control (W) */

// ARM9 Maths

#define NDS9_DIVCNT        0x04000280 /* Division Control (R/W) */
#define NDS9_DIV_NUMER     0x04000290 /* Division Numerator (R/W) */
#define NDS9_DIV_DENOM     0x04000298 /* Division Denominator (R/W) */
#define NDS9_DIV_RESULT    0x040002A0 /* Division Quotient (=Numer/Denom) (R) */
#define NDS9_DIVREM_RESULT 0x040002A8 /* Division Remainder (=Numer MOD Denom) (R) */
#define NDS9_SQRTCNT       0x040002B0 /* Square Root Control (R/W) */
#define NDS9_SQRT_RESULT   0x040002B4 /* Square Root Result (R) */
#define NDS9_SQRT_PARAM    0x040002B8 /* Square Root Parameter Input (R/W) */
#define NDS9_POSTFLG       0x04000300 /* Undoc */
#define NDS9_POWCNT1       0x04000304 /* Graphics Power Control Register (R/W) */

// ARM9 3D Display Engine
#define NDS9_RDLINES_COUNT   0x04000320 /* Rendered Line Count Register (R) */
#define NDS9_EDGE_COLOR      0x04000330 /* Edge Colors 0..7 (W) */
#define NDS9_ALPHA_TEST_REF  0x04000340 /* Alpha-Test Comparision Value (W) */
#define NDS9_CLEAR_COLOR     0x04000350 /* Clear Color Attribute Register (W) */
#define NDS9_CLEAR_DEPTH     0x04000354 /* Clear Depth Register (W) */
#define NDS9_CLRIMAGE_OFFSET 0x04000356 /* Rear-plane Bitmap Scroll Offsets (W) */
#define NDS9_FOG_COLOR       0x04000358 /* Fog Color (W) */
#define NDS9_FOG_OFFSET      0x0400035C /* Fog Depth Offset (W) */
#define NDS9_FOG_TABLE       0x04000360 /* Fog Density Table, 32 entries (W) */
#define NDS9_TOON_TABLE      0x04000380 /* Toon Table, 32 colors (W) */

#define NDS9_GXFIFO          0x04000400 /* Geometry Command FIFO (W) */

#define NDS9_MTX_MODE        0x04000440 /* Set Matrix Mode (W) */ 
#define NDS9_MTX_PUSH        0x04000444 /* Push Current Matrix on Stack (W) */ 
#define NDS9_MTX_POP         0x04000448 /* Pop Current Matrix from Stack (W) */ 
#define NDS9_MTX_STORE       0x0400044C /* Store Current Matrix on Stack (W) */ 
#define NDS9_MTX_RESTORE     0x04000450 /* Restore Current Matrix from Stack (W) */ 
#define NDS9_MTX_IDENTITY    0x04000454 /* Load Unit Matrix to Current Matrix (W) */ 
#define NDS9_MTX_LOAD_4x4    0x04000458 /* Load 4x4 Matrix to Current Matrix (W) */ 
#define NDS9_MTX_LOAD_4x3    0x0400045C /* Load 4x3 Matrix to Current Matrix (W) */ 
#define NDS9_MTX_MULT_4x4    0x04000460 /* Multiply Current Matrix by 4x4 Matrix (W) */ 
#define NDS9_MTX_MULT_4x3    0x04000464 /* Multiply Current Matrix by 4x3 Matrix (W) */ 
#define NDS9_MTX_MULT_3x3    0x04000468 /* Multiply Current Matrix by 3x3 Matrix (W) */ 
#define NDS9_MTX_SCALE       0x0400046C /* Multiply Current Matrix by Scale Matrix (W) */ 
#define NDS9_MTX_TRANS       0x04000470 /* Mult. Curr. Matrix by Translation Matrix (W) */ 
#define NDS9_COLOR           0x04000480 /* Directly Set Vertex Color (W) */ 
#define NDS9_NORMAL          0x04000484 /* Set Normal Vector (W) */ 
#define NDS9_TEXCOORD        0x04000488 /* Set Texture Coordinates (W) */ 
#define NDS9_VTX_16          0x0400048C /* Set Vertex XYZ Coordinates (W) */ 
#define NDS9_VTX_10          0x04000490 /* Set Vertex XYZ Coordinates (W) */ 
#define NDS9_VTX_XY          0x04000494 /* Set Vertex XY Coordinates (W) */ 
#define NDS9_VTX_XZ          0x04000498 /* Set Vertex XZ Coordinates (W) */ 
#define NDS9_VTX_YZ          0x0400049C /* Set Vertex YZ Coordinates (W) */ 
#define NDS9_VTX_DIFF        0x040004A0 /* Set Relative Vertex Coordinates (W) */ 
#define NDS9_POLYGON_ATTR    0x040004A4 /* Set Polygon Attributes (W) */ 
#define NDS9_TEXIMAGE_PARAM  0x040004A8 /* Set Texture Parameters (W) */ 
#define NDS9_PLTT_BASE       0x040004AC /* Set Texture Palette Base Address (W) */ 
#define NDS9_DIF_AMB         0x040004C0 /* MaterialColor0 - Diffuse/Ambient Reflect. (W) */ 
#define NDS9_SPE_EMI         0x040004C4 /* MaterialColor1 - Specular Ref. & Emission (W) */ 
#define NDS9_LIGHT_VECTOR    0x040004C8 /* Set Light's Directional Vector (W) */ 
#define NDS9_LIGHT_COLOR     0x040004CC /* Set Light Color (W) */ 
#define NDS9_SHININESS       0x040004D0 /* Specular Reflection Shininess Table (W) */ 
#define NDS9_BEGIN_VTXS      0x04000500 /* Start of Vertex List (W) */ 
#define NDS9_END_VTXS        0x04000504 /* End of Vertex List (W) */ 
#define NDS9_SWAP_BUFFERS    0x04000540 /* Swap Rendering Engine Buffer (W) */ 
#define NDS9_VIEWPORT        0x04000580 /* Set Viewport (W) */ 
#define NDS9_BOX_TEST        0x040005C0 /* Test if Cuboid Sits inside View Volume (W) */ 
#define NDS9_POS_TEST        0x040005C4 /* Set Position Coordinates for Test (W) */ 
#define NDS9_VEC_TEST        0x040005C8 /* Set Directional Vector for Test (W) */ 

#define NDS9_GXSTAT          0x04000600 /* Geometry Engine Status Register (R and R/W) */
#define NDS9_RAM_COUNT       0x04000604 /* Polygon List & Vertex RAM Count Register (R) */
#define NDS9_DISP_1DOT_DEPTH 0x04000610 /* 1-Dot Polygon Display Boundary Depth (W) */
#define NDS9_POS_RESULT      0x04000620 /* Position Test Results (R) */
#define NDS9_VEC_RESULT      0x04000630 /* Vector Test Results (R) */
#define NDS9_CLIPMTX_RESULT  0x04000640 /* Read Current Clip Coordinates Matrix (R) */
#define NDS9_VECMTX_RESULT   0x04000680 /* Read Current Directional Vector Matrix (R) */

// DS 3D I/O Map
// ARM9 Display Engine B
#define NDS9_B_DISPCNT        0x04001000  /* R/W LCD Control */
#define NDS9_B_BG0CNT         0x04001008  /* R/W BG0 Control */
#define NDS9_B_BG1CNT         0x0400100A  /* R/W BG1 Control */
#define NDS9_B_BG2CNT         0x0400100C  /* R/W BG2 Control */
#define NDS9_B_BG3CNT         0x0400100E  /* R/W BG3 Control */
#define NDS9_B_BG0HOFS        0x04001010  /* W   BG0 X-Offset */
#define NDS9_B_BG0VOFS        0x04001012  /* W   BG0 Y-Offset */
#define NDS9_B_BG1HOFS        0x04001014  /* W   BG1 X-Offset */
#define NDS9_B_BG1VOFS        0x04001016  /* W   BG1 Y-Offset */
#define NDS9_B_BG2HOFS        0x04001018  /* W   BG2 X-Offset */
#define NDS9_B_BG2VOFS        0x0400101A  /* W   BG2 Y-Offset */
#define NDS9_B_BG3HOFS        0x0400101C  /* W   BG3 X-Offset */
#define NDS9_B_BG3VOFS        0x0400101E  /* W   BG3 Y-Offset */
#define NDS9_B_BG2PA          0x04001020  /* W   BG2 Rotation/Scaling Parameter A (dx) */
#define NDS9_B_BG2PB          0x04001022  /* W   BG2 Rotation/Scaling Parameter B (dmx) */
#define NDS9_B_BG2PC          0x04001024  /* W   BG2 Rotation/Scaling Parameter C (dy) */
#define NDS9_B_BG2PD          0x04001026  /* W   BG2 Rotation/Scaling Parameter D (dmy) */
#define NDS9_B_BG2X           0x04001028  /* W   BG2 Reference Point X-Coordinate */
#define NDS9_B_BG2Y           0x0400102C  /* W   BG2 Reference Point Y-Coordinate */
#define NDS9_B_BG3PA          0x04001030  /* W   BG3 Rotation/Scaling Parameter A (dx) */
#define NDS9_B_BG3PB          0x04001032  /* W   BG3 Rotation/Scaling Parameter B (dmx) */
#define NDS9_B_BG3PC          0x04001034  /* W   BG3 Rotation/Scaling Parameter C (dy) */
#define NDS9_B_BG3PD          0x04001036  /* W   BG3 Rotation/Scaling Parameter D (dmy) */
#define NDS9_B_BG3X           0x04001038  /* W   BG3 Reference Point X-Coordinate */
#define NDS9_B_BG3Y           0x0400103C  /* W   BG3 Reference Point Y-Coordinate */
#define NDS9_B_WIN0H          0x04001040  /* W   Window 0 Horizontal Dimensions */
#define NDS9_B_WIN1H          0x04001042  /* W   Window 1 Horizontal Dimensions */
#define NDS9_B_WIN0V          0x04001044  /* W   Window 0 Vertical Dimensions */
#define NDS9_B_WIN1V          0x04001046  /* W   Window 1 Vertical Dimensions */
#define NDS9_B_WININ          0x04001048  /* R/W Inside of Window 0 and 1 */
#define NDS9_B_WINOUT         0x0400104A  /* R/W Inside of OBJ Window & Outside of Windows */
#define NDS9_B_MOSAIC         0x0400104C  /* W   Mosaic Size */
#define NDS9_B_BLDCNT         0x04001050  /* R/W Color Special Effects Selection */
#define NDS9_B_BLDALPHA       0x04001052  /* R/W Alpha Blending Coefficients */
#define NDS9_B_BLDY           0x04001054  /* W   Brightness (Fade-In/Out) Coefficient */

#define NDS9_B_MASTER_BRIGHT  0x0400106C  /* Master Brightness Up/Down */

// ARM9 IPC/ROM

//Note: These are remapped to 
#define NDS_IPCFIFORECV  (0x04100000|NDS_IO_MAP_041_OFFSET) /* IPC Receive Fifo (R)*/
#define NDS_GC_BUS       (0x04100010|NDS_IO_MAP_041_OFFSET) /* Gamecard bus 4-byte data in, for manual or dma read (R) (or W) */
#define NDS_IPCSYNC      0x04000180 /* IPC Synchronize Register (R/W) */
#define NDS_IPCFIFOCNT   0x04000184 /* IPC Fifo Control Register (R/W) */
#define NDS_IPCFIFOSEND  0x04000188 /* IPC Send Fifo (W) */

//Main Memory Control

#define NDS9_MEM_CTRL 0x027FFFFE /* Main Memory Control*/ 

//////////////////
// ARM7 I/O Map //
//////////////////

#define NDS7_DEBUG_RCNT     0x04000134 /* Debug RCNT */
#define NDS7_EXTKEYIN       0x04000136 /* EXTKEYIN */
#define NDS7_RTC_BUS        0x04000138 /* RTC Realtime Clock Bus */
#define NDS7_AUXSPICNT      0x040001A0 /* Gamecard ROM and SPI Control */
#define NDS7_AUXSPIDATA     0x040001A2 /* Gamecard SPI Bus Data/Strobe */
#define NDS7_GCBUS_CTL      0x040001A4 /* Gamecard bus timing/control */
#define NDS7_GCBUS_CMD      0x040001A8 /* Gamecard bus 8-byte command out */
#define NDS7_GCBUS_SEED0_LO 0x040001B0 /* Gamecard Encryption Seed 0 Lower 32bit */
#define NDS7_GCBUS_SEED1_LO 0x040001B4 /* Gamecard Encryption Seed 1 Lower 32bit */
#define NDS7_GCBUS_SEED0_HI 0x040001B8 /* Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused) */
#define NDS7_GCBUS_SEED1_HI 0x040001BA /* Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused) */
#define NDS7_SPI_BUS_CTL    0x040001C0 /* SPI bus Control (Firmware, Touchscreen, Powerman) */
#define NDS7_SPI_BUS_DATA   0x040001C2 /* SPI bus Data */

// ARM7 Memory and IRQ Control
#define NDS7_EXMEMSTAT   0x04000204 /* EXMEMSTAT - External Memory Status */
#define NDS7_WIFIWAITCNT 0x04000206 /* WIFIWAITCNT */
#define NDS7_IME         0x04000208 /* IME - Interrupt Master Enable (R/W) */
#define NDS7_IE          0x04000210 /* IE  - Interrupt Enable (R/W) */
#define NDS7_IF          0x04000214 /* IF  - Interrupt Request Flags (R/W) */
#define NDS7_VRAMSTAT    0x04000240 /* VRAMSTAT - VRAM-C,D Bank Status (R) */
#define NDS7_WRAMSTAT    0x04000241 /* WRAMSTAT - WRAM Bank Status (R) */
#define NDS7_POSTFLG     0x04000300 /* POSTFLG */
#define NDS7_HALTCNT     0x04000301 /* HALTCNT (different bits than on GBA) (plus NOP delay) */
#define NDS7_POWCNT2     0x04000304 /* POWCNT2  Sound/Wifi Power Control Register (R/W) */
#define NDS7_BIOSPROT    0x04000308 /* BIOSPROT - Bios-data-read-protection address */

// ARM7 Sound Registers (Sound Channel 0..15 (10h bytes each)) 
#define NDS7_SOUND0_CNT 0x04000400 /* Sound Channel 0 Control Register (R/W) */
#define NDS7_SOUND0_SAD 0x04000404 /* Sound Channel 0 Data Source Register (W) */
#define NDS7_SOUND0_TMR 0x04000408 /* Sound Channel 0 Timer Register (W) */
#define NDS7_SOUND0_PNT 0x0400040A /* Sound Channel 0 Loopstart Register (W) */
#define NDS7_SOUND0_LEN 0x0400040C /* Sound Channel 0 Length Register (W) */
#define NDS7_SOUND1_CNT 0x04001400 /* Sound Channel 1 Control Register (R/W) */
#define NDS7_SOUND1_SAD 0x04001404 /* Sound Channel 1 Data Source Register (W) */
#define NDS7_SOUND1_TMR 0x04001408 /* Sound Channel 1 Timer Register (W) */
#define NDS7_SOUND1_PNT 0x0400140A /* Sound Channel 1 Loopstart Register (W) */
#define NDS7_SOUND1_LEN 0x0400140C /* Sound Channel 1 Length Register (W) */
#define NDS7_SOUND2_CNT 0x04002400 /* Sound Channel 2 Control Register (R/W) */
#define NDS7_SOUND2_SAD 0x04002404 /* Sound Channel 2 Data Source Register (W) */
#define NDS7_SOUND2_TMR 0x04002408 /* Sound Channel 2 Timer Register (W) */
#define NDS7_SOUND2_PNT 0x0400240A /* Sound Channel 2 Loopstart Register (W) */
#define NDS7_SOUND2_LEN 0x0400240C /* Sound Channel 2 Length Register (W) */
#define NDS7_SOUND3_CNT 0x04003400 /* Sound Channel 3 Control Register (R/W) */
#define NDS7_SOUND3_SAD 0x04003404 /* Sound Channel 3 Data Source Register (W) */
#define NDS7_SOUND3_TMR 0x04003408 /* Sound Channel 3 Timer Register (W) */
#define NDS7_SOUND3_PNT 0x0400340A /* Sound Channel 3 Loopstart Register (W) */
#define NDS7_SOUND3_LEN 0x0400340C /* Sound Channel 3 Length Register (W) */
#define NDS7_SOUND4_CNT 0x04004400 /* Sound Channel 4 Control Register (R/W) */
#define NDS7_SOUND4_SAD 0x04004404 /* Sound Channel 4 Data Source Register (W) */
#define NDS7_SOUND4_TMR 0x04004408 /* Sound Channel 4 Timer Register (W) */
#define NDS7_SOUND4_PNT 0x0400440A /* Sound Channel 4 Loopstart Register (W) */
#define NDS7_SOUND4_LEN 0x0400440C /* Sound Channel 4 Length Register (W) */
#define NDS7_SOUND5_CNT 0x04005400 /* Sound Channel 5 Control Register (R/W) */
#define NDS7_SOUND5_SAD 0x04005404 /* Sound Channel 5 Data Source Register (W) */
#define NDS7_SOUND5_TMR 0x04005408 /* Sound Channel 5 Timer Register (W) */
#define NDS7_SOUND5_PNT 0x0400540A /* Sound Channel 5 Loopstart Register (W) */
#define NDS7_SOUND5_LEN 0x0400540C /* Sound Channel 5 Length Register (W) */
#define NDS7_SOUND6_CNT 0x04006400 /* Sound Channel 6 Control Register (R/W) */
#define NDS7_SOUND6_SAD 0x04006404 /* Sound Channel 6 Data Source Register (W) */
#define NDS7_SOUND6_TMR 0x04006408 /* Sound Channel 6 Timer Register (W) */
#define NDS7_SOUND6_PNT 0x0400640A /* Sound Channel 6 Loopstart Register (W) */
#define NDS7_SOUND6_LEN 0x0400640C /* Sound Channel 6 Length Register (W) */
#define NDS7_SOUND7_CNT 0x04007400 /* Sound Channel 7 Control Register (R/W) */
#define NDS7_SOUND7_SAD 0x04007404 /* Sound Channel 7 Data Source Register (W) */
#define NDS7_SOUND7_TMR 0x04007408 /* Sound Channel 7 Timer Register (W) */
#define NDS7_SOUND7_PNT 0x0400740A /* Sound Channel 7 Loopstart Register (W) */
#define NDS7_SOUND7_LEN 0x0400740C /* Sound Channel 7 Length Register (W) */
#define NDS7_SOUND8_CNT 0x04008400 /* Sound Channel 8 Control Register (R/W) */
#define NDS7_SOUND8_SAD 0x04008404 /* Sound Channel 8 Data Source Register (W) */
#define NDS7_SOUND8_TMR 0x04008408 /* Sound Channel 8 Timer Register (W) */
#define NDS7_SOUND8_PNT 0x0400840A /* Sound Channel 8 Loopstart Register (W) */
#define NDS7_SOUND8_LEN 0x0400840C /* Sound Channel 8 Length Register (W) */
#define NDS7_SOUND9_CNT 0x04009400 /* Sound Channel 9 Control Register (R/W) */
#define NDS7_SOUND9_SAD 0x04009404 /* Sound Channel 9 Data Source Register (W) */
#define NDS7_SOUND9_TMR 0x04009408 /* Sound Channel 9 Timer Register (W) */
#define NDS7_SOUND9_PNT 0x0400940A /* Sound Channel 9 Loopstart Register (W) */
#define NDS7_SOUND9_LEN 0x0400940C /* Sound Channel 9 Length Register (W) */
#define NDS7_SOUNDA_CNT 0x0400A400 /* Sound Channel 10 Control Register (R/W) */
#define NDS7_SOUNDA_SAD 0x0400A404 /* Sound Channel 10 Data Source Register (W) */
#define NDS7_SOUNDA_TMR 0x0400A408 /* Sound Channel 10 Timer Register (W) */
#define NDS7_SOUNDA_PNT 0x0400A40A /* Sound Channel 10 Loopstart Register (W) */
#define NDS7_SOUNDA_LEN 0x0400A40C /* Sound Channel 10 Length Register (W) */
#define NDS7_SOUNDB_CNT 0x0400B400 /* Sound Channel 11 Control Register (R/W) */
#define NDS7_SOUNDB_SAD 0x0400B404 /* Sound Channel 11 Data Source Register (W) */
#define NDS7_SOUNDB_TMR 0x0400B408 /* Sound Channel 11 Timer Register (W) */
#define NDS7_SOUNDB_PNT 0x0400B40A /* Sound Channel 11 Loopstart Register (W) */
#define NDS7_SOUNDB_LEN 0x0400B40C /* Sound Channel 11 Length Register (W) */
#define NDS7_SOUNDC_CNT 0x0400C400 /* Sound Channel 12 Control Register (R/W) */
#define NDS7_SOUNDC_SAD 0x0400C404 /* Sound Channel 12 Data Source Register (W) */
#define NDS7_SOUNDC_TMR 0x0400C408 /* Sound Channel 12 Timer Register (W) */
#define NDS7_SOUNDC_PNT 0x0400C40A /* Sound Channel 12 Loopstart Register (W) */
#define NDS7_SOUNDC_LEN 0x0400C40C /* Sound Channel 12 Length Register (W) */
#define NDS7_SOUNDD_CNT 0x0400D400 /* Sound Channel 13 Control Register (R/W) */
#define NDS7_SOUNDD_SAD 0x0400D404 /* Sound Channel 13 Data Source Register (W) */
#define NDS7_SOUNDD_TMR 0x0400D408 /* Sound Channel 13 Timer Register (W) */
#define NDS7_SOUNDD_PNT 0x0400D40A /* Sound Channel 13 Loopstart Register (W) */
#define NDS7_SOUNDD_LEN 0x0400D40C /* Sound Channel 13 Length Register (W) */
#define NDS7_SOUNDE_CNT 0x0400E400 /* Sound Channel 14 Control Register (R/W) */
#define NDS7_SOUNDE_SAD 0x0400E404 /* Sound Channel 14 Data Source Register (W) */
#define NDS7_SOUNDE_TMR 0x0400E408 /* Sound Channel 14 Timer Register (W) */
#define NDS7_SOUNDE_PNT 0x0400E40A /* Sound Channel 14 Loopstart Register (W) */
#define NDS7_SOUNDE_LEN 0x0400E40C /* Sound Channel 14 Length Register (W) */
#define NDS7_SOUNDF_CNT 0x0400F400 /* Sound Channel 15 Control Register (R/W) */
#define NDS7_SOUNDF_SAD 0x0400F404 /* Sound Channel 15 Data Source Register (W) */
#define NDS7_SOUNDF_TMR 0x0400F408 /* Sound Channel 15 Timer Register (W) */
#define NDS7_SOUNDF_PNT 0x0400F40A /* Sound Channel 15 Loopstart Register (W) */
#define NDS7_SOUNDF_LEN 0x0400F40C /* Sound Channel 15 Length Register (W) */

#define NDS7_SOUNDCNT   0x04000500 /* Sound Control Register (R/W) */
#define NDS7_SOUNDBIAS  0x04000504 /* Sound Bias Register (R/W) */
#define NDS7_SNDCAP0CNT 0x04000508 /* Sound Capture 0 Control Register (R/W) */
#define NDS7_SNDCAP1CNT 0x04000509 /* Sound Capture 1 Control Register (R/W) */
#define NDS7_SNDCAP0DAD 0x04000510 /* Sound Capture 0 Destination Address (R/W) */
#define NDS7_SNDCAP0LEN 0x04000514 /* Sound Capture 0 Length (W) */
#define NDS7_SNDCAP1DAD 0x04000518 /* Sound Capture 1 Destination Address (R/W) */
#define NDS7_SNDCAP1LEN 0x0400051C /* Sound Capture 1 Length (W) */


mmio_reg_t nds9_io_reg_desc[]={
  { GBA_DISPCNT , "DISPCNT ", { 
    { 0, 3, "BG Mode (0-5=Video Mode 0-5, 6-7=Prohibited)"},
    { 3 ,1, "BG0 2D/3D Selection"},
    { 4 ,1, "Tile OBJ Mapping        (0=2D; max 32KB, 1=1D; max 32KB..256KB)"},
    { 5 ,1, "Bitmap OBJ 2D-Dimension (0=128x512 dots, 1=256x256 dots)"},
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
    { 16,2, "Display Mode (0..3)"},
    { 18,2, "VRAM block (0..3=VRAM A..D) (For Capture & above Display Mode=2)"},
    { 20,2, "Tile OBJ 1D-Boundary   (see Bit4)"},
    { 22,1, "Bitmap OBJ 1D-Boundary (see Bit5-6)"},
    { 23,1, "OBJ Processing during H-Blank (was located in Bit5 on GBA)"},
    { 24,3, "Character Base (in 64K steps) (merged with 16K step in BGxCNT)"},
    { 27,3, "Screen Base (in 64K steps) (merged with 2K step in BGxCNT)"},
    { 30,1, "BG Extended Palettes   (0=Disable, 1=Enable)"},
    { 31,1, "OBJ Extended Palettes  (0=Disable, 1=Enable)"}
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
  { GBA_VCOUNT  , "VCOUNT  ", { 0 } }, /* R   Vertical Counter (LY) */
  { GBA_BG0CNT  , "BG0CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG0 Control */
  { GBA_BG1CNT  , "BG1CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG1 Control */
  { GBA_BG2CNT  , "BG2CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG2 Control */
  { GBA_BG3CNT  , "BG3CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG3 Control */
  { GBA_BG0HOFS , "BG0HOFS", { 0 } }, /* W   BG0 X-Offset */
  { GBA_BG0VOFS , "BG0VOFS", { 0 } }, /* W   BG0 Y-Offset */
  { GBA_BG1HOFS , "BG1HOFS", { 0 } }, /* W   BG1 X-Offset */
  { GBA_BG1VOFS , "BG1VOFS", { 0 } }, /* W   BG1 Y-Offset */
  { GBA_BG2HOFS , "BG2HOFS", { 0 } }, /* W   BG2 X-Offset */
  { GBA_BG2VOFS , "BG2VOFS", { 0 } }, /* W   BG2 Y-Offset */
  { GBA_BG3HOFS , "BG3HOFS", { 0 } }, /* W   BG3 X-Offset */
  { GBA_BG3VOFS , "BG3VOFS", { 0 } }, /* W   BG3 Y-Offset */
  { GBA_BG2PA   , "BG2PA", { 0 } }, /* W   BG2 Rotation/Scaling Parameter A (dx) */
  { GBA_BG2PB   , "BG2PB", { 0 } }, /* W   BG2 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG2PC   , "BG2PC", { 0 } }, /* W   BG2 Rotation/Scaling Parameter C (dy) */
  { GBA_BG2PD   , "BG2PD", { 0 } }, /* W   BG2 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG2X    , "BG2X", { 0 } }, /* W   BG2 Reference Point X-Coordinate */
  { GBA_BG2Y    , "BG2Y", { 0 } }, /* W   BG2 Reference Point Y-Coordinate */
  { GBA_BG3PA   , "BG3PA", { 0 } }, /* W   BG3 Rotation/Scaling Parameter A (dx) */
  { GBA_BG3PB   , "BG3PB", { 0 } }, /* W   BG3 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG3PC   , "BG3PC", { 0 } }, /* W   BG3 Rotation/Scaling Parameter C (dy) */
  { GBA_BG3PD   , "BG3PD", { 0 } }, /* W   BG3 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG3X    , "BG3X", { 0 } }, /* W   BG3 Reference Point X-Coordinate */
  { GBA_BG3Y    , "BG3Y", { 0 } }, /* W   BG3 Reference Point Y-Coordinate */
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
  { GBA_BLDY    , "BLDY", { 0 } }, /* W   Brightness (Fade-In/Out) Coefficient */  
  { NDS_DISP3DCNT,       "DISP3DCNT",       { 0 } }, /* 3D Display Control Register (R/W) */
  { NDS_DISPCAPCNT,      "DISPCAPCNT",      { 0 } }, /* Display Capture Control Register (R/W) */
  { NDS_DISP_MMEM_FIFO,  "DISP_MMEM_FIFO",  { 0 } }, /* Main Memory Display FIFO (R?/W) */
  { NDS_A_MASTER_BRIGHT, "A_MASTER_BRIGHT", { 0 } }, /* Master Brightness Up/Down */

  // DMA Transfer Channels
  { GBA_DMA0SAD  , "DMA0SAD", { 0 } },   /* W    DMA 0 Source Address */
  { GBA_DMA0DAD  , "DMA0DAD", { 0 } },   /* W    DMA 0 Destination Address */
  { GBA_DMA0CNT_L, "DMA0CNT_L", { 0 } },   /* W    DMA 0 Word Count */
  { GBA_DMA0CNT_H, "DMA0CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Prohibited)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 0 Control */
  { GBA_DMA1SAD  , "DMA1SAD", { 0 } },   /* W    DMA 1 Source Address */
  { GBA_DMA1DAD  , "DMA1DAD", { 0 } },   /* W    DMA 1 Destination Address */
  { GBA_DMA1CNT_L, "DMA1CNT_L", { 0 } },   /* W    DMA 1 Word Count */
  { GBA_DMA1CNT_H, "DMA1CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 1 Control */
  { GBA_DMA2SAD  , "DMA2SAD", { 0 } },   /* W    DMA 2 Source Address */
  { GBA_DMA2DAD  , "DMA2DAD", { 0 } },   /* W    DMA 2 Destination Address */
  { GBA_DMA2CNT_L, "DMA2CNT_L", { 0 } },   /* W    DMA 2 Word Count */
  { GBA_DMA2CNT_H, "DMA2CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 2 Control */
  { GBA_DMA3SAD  , "DMA3SAD", { 0 } },   /* W    DMA 3 Source Address */
  { GBA_DMA3DAD  , "DMA3DAD", { 0 } },   /* W    DMA 3 Destination Address */
  { GBA_DMA3CNT_L, "DMA3CNT_L", { 0 } },   /* W    DMA 3 Word Count */
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
  { GBA_TM0CNT_L, "TM0CNT_L", {0} },   /* R/W   Timer 0 Counter/Reload */
  { GBA_TM0CNT_H, "TM0CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 0 Control */
  { GBA_TM1CNT_L, "TM1CNT_L", {0} },   /* R/W   Timer 1 Counter/Reload */
  { GBA_TM1CNT_H, "TM1CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 1 Control */
  { GBA_TM2CNT_L, "TM2CNT_L", {0} },   /* R/W   Timer 2 Counter/Reload */
  { GBA_TM2CNT_H, "TM2CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 2 Control */
  { GBA_TM3CNT_L, "TM3CNT_L", {0} },   /* R/W   Timer 3 Counter/Reload */
  { GBA_TM3CNT_H, "TM3CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 3 Control */  

  // Serial Communication (1)
  { GBA_SIODATA32  , "SIODATA32", {0} }, /*R/W   SIO Data (Normal-32bit Mode; shared with below) */
  { GBA_SIOMULTI0  , "SIOMULTI0", {0} }, /*R/W   SIO Data 0 (Parent)    (Multi-Player Mode) */
  { GBA_SIOMULTI1  , "SIOMULTI1", {0} }, /*R/W   SIO Data 1 (1st Child) (Multi-Player Mode) */
  { GBA_SIOMULTI2  , "SIOMULTI2", {0} }, /*R/W   SIO Data 2 (2nd Child) (Multi-Player Mode) */
  { GBA_SIOMULTI3  , "SIOMULTI3", {0} }, /*R/W   SIO Data 3 (3rd Child) (Multi-Player Mode) */
  { GBA_SIOCNT     , "SIOCNT", {0} }, /*R/W   SIO Control Register */
  { GBA_SIOMLT_SEND, "SIOMLT_SEND", {0} }, /*R/W   SIO Data (Local of MultiPlayer; shared below) */
  { GBA_SIODATA8   , "SIODATA8", {0} }, /*R/W   SIO Data (Normal-8bit and UART Mode) */  

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
  { GBA_RCNT     , "RCNT", {0} },     /* R/W  SIO Mode Select/General Purpose Data */
  { GBA_IR       , "IR", {0} },     /* -    Ancient - Infrared Register (Prototypes only) */
  { GBA_JOYCNT   , "JOYCNT", {0} },     /* R/W  SIO JOY Bus Control */
  { GBA_JOY_RECV , "JOY_RECV", {0} },     /* R/W  SIO JOY Bus Receive Data */
  { GBA_JOY_TRANS, "JOY_TRANS", {0} },     /* R/W  SIO JOY Bus Transmit Data */
  { GBA_JOYSTAT  , "JOYSTAT", {0} },     /* R/?  SIO JOY Bus Receive Status */  

  { NDS_IPCSYNC     , "IPCSYNC",     { 0 } }, /*IPC Synchronize Register (R/W)*/
  { NDS_IPCFIFOCNT  , "IPCFIFOCNT",  { 0 } }, /*IPC Fifo Control Register (R/W)*/
  { NDS_IPCFIFOSEND , "IPCFIFOSEND", { 0 } }, /*IPC Send Fifo (W)*/
  { NDS9_AUXSPICNT   , "AUXSPICNT",   { 0 } }, /*Gamecard ROM and SPI Control*/
  { NDS9_AUXSPIDATA  , "AUXSPIDATA",  { 0 } }, /*Gamecard SPI Bus Data/Strobe*/
  { NDS9_GC_BUS_CTL  , "GC_BUS_CTL",  { 0 } }, /*Gamecard bus timing/control*/
  { NDS9_GC_BUS_DAT  , "GC_BUS_DAT",  { 0 } }, /*Gamecard bus 8-byte command out*/
  { NDS9_GC_ENC0_LO  , "GC_ENC0_LO",  { 0 } }, /*Gamecard Encryption Seed 0 Lower 32bit*/
  { NDS9_GC_ENC1_LO  , "GC_ENC1_LO",  { 0 } }, /*Gamecard Encryption Seed 1 Lower 32bit*/
  { NDS9_GC_ENC0_HI  , "GC_ENC0_HI",  { 0 } }, /*Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused)*/
  { NDS9_GC_ENC1_HI  , "GC_ENC1_HI",  { 0 } }, /*Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused)*/
  
  // ARM9 Memory and IRQ Control
  { NDS9_EXMEMCNT , "EXMEMCNT",  { 0 } }, /* External Memory Control (R/W) */
  { NDS9_IME      , "IME",       { 0 } }, /* Interrupt Master Enable (R/W) */
  { NDS9_IE       , "IE",        { 0 } }, /* Interrupt Enable (R/W) */
  { NDS9_IF       , "IF",        { 0 } }, /* Interrupt Request Flags (R/W) */
  { NDS9_VRAMCNT_A, "VRAMCNT_A", { 
     { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-A (128K) Bank Control (W) */
  { NDS9_VRAMCNT_B, "VRAMCNT_B", { 
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-B (128K) Bank Control (W) */
  { NDS9_VRAMCNT_C, "VRAMCNT_C", {  
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-C (128K) Bank Control (W) */
  { NDS9_VRAMCNT_D, "VRAMCNT_D", {  
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-D (128K) Bank Control (W) */
  { NDS9_VRAMCNT_E, "VRAMCNT_E", {  
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-E (64K) Bank Control (W) */
  { NDS9_VRAMCNT_F, "VRAMCNT_F", {  
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-F (16K) Bank Control (W) */
  { NDS9_VRAMCNT_G, "VRAMCNT_G", {  
    { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-G (16K) Bank Control (W) */
  { NDS9_WRAMCNT  , "WRAMCNT",   { 0 } }, /* WRAM Bank Control (W) */
  { NDS9_VRAMCNT_H, "VRAMCNT_H", { 0 } }, /* VRAM-H (32K) Bank Control (W) */
  { NDS9_VRAMCNT_I, "VRAMCNT_I", { 0 } }, /* VRAM-I (16K) Bank Control (W) */
  
  // ARM9 Maths
  { NDS9_DIVCNT,        "DIVCNT",        { 0 } }, /* Division Control (R/W) */
  { NDS9_DIV_NUMER,     "DIV_NUMER",     { 0 } }, /* Division Numerator (R/W) */
  { NDS9_DIV_DENOM,     "DIV_DENOM",     { 0 } }, /* Division Denominator (R/W) */
  { NDS9_DIV_RESULT,    "DIV_RESULT",    { 0 } }, /* Division Quotient (=Numer/Denom) (R) */
  { NDS9_DIVREM_RESULT, "DIVREM_RESULT", { 0 } }, /* Division Remainder (=Numer MOD Denom) (R) */
  { NDS9_SQRTCNT,       "SQRTCNT",       { 0 } }, /* Square Root Control (R/W) */
  { NDS9_SQRT_RESULT,   "SQRT_RESULT",   { 0 } }, /* Square Root Result (R) */
  { NDS9_SQRT_PARAM,    "SQRT_PARAM",    { 0 } }, /* Square Root Parameter Input (R/W) */
  { NDS9_POSTFLG,       "POSTFLG",       { 0 } }, /* Undoc */
  { NDS9_POWCNT1,       "POWCNT1",       { 0 } }, /* Graphics Power Control Register (R/W) */

  // ARM9 3D Display Engine
  { NDS9_RDLINES_COUNT,   "RDLINES_COUNT",   { 0 } }, /* Rendered Line Count Register (R) */
  { NDS9_EDGE_COLOR,      "EDGE_COLOR",      { 0 } }, /* Edge Colors 0..7 (W) */
  { NDS9_ALPHA_TEST_REF,  "ALPHA_TEST_REF",  { 0 } }, /* Alpha-Test Comparision Value (W) */
  { NDS9_CLEAR_COLOR,     "CLEAR_COLOR",     { 0 } }, /* Clear Color Attribute Register (W) */
  { NDS9_CLEAR_DEPTH,     "CLEAR_DEPTH",     { 0 } }, /* Clear Depth Register (W) */
  { NDS9_CLRIMAGE_OFFSET, "CLRIMAGE_OFFSET", { 0 } }, /* Rear-plane Bitmap Scroll Offsets (W) */
  { NDS9_FOG_COLOR,       "FOG_COLOR",       { 0 } }, /* Fog Color (W) */
  { NDS9_FOG_OFFSET,      "FOG_OFFSET",      { 0 } }, /* Fog Depth Offset (W) */
  { NDS9_FOG_TABLE,       "FOG_TABLE",       { 0 } }, /* Fog Density Table, 32 entries (W) */
  { NDS9_TOON_TABLE,      "TOON_TABLE",      { 0 } }, /* Toon Table, 32 colors (W) */
  { NDS9_GXFIFO,          "GXFIFO",          { 0 } }, /* Geometry Command FIFO (W) */
  { NDS9_MTX_MODE,        "MTX_MODE",        { 0 } }, /* Set Matrix Mode (W) */ 
  { NDS9_MTX_PUSH,        "MTX_PUSH",        { 0 } }, /* Push Current Matrix on Stack (W) */ 
  { NDS9_MTX_POP,         "MTX_POP",         { 0 } }, /* Pop Current Matrix from Stack (W) */ 
  { NDS9_MTX_STORE,       "MTX_STORE",       { 0 } }, /* Store Current Matrix on Stack (W) */ 
  { NDS9_MTX_RESTORE,     "MTX_RESTORE",     { 0 } }, /* Restore Current Matrix from Stack (W) */ 
  { NDS9_MTX_IDENTITY,    "MTX_IDENTITY",    { 0 } }, /* Load Unit Matrix to Current Matrix (W) */ 
  { NDS9_MTX_LOAD_4x4,    "MTX_LOAD_4x4",    { 0 } }, /* Load 4x4 Matrix to Current Matrix (W) */ 
  { NDS9_MTX_LOAD_4x3,    "MTX_LOAD_4x3",    { 0 } }, /* Load 4x3 Matrix to Current Matrix (W) */ 
  { NDS9_MTX_MULT_4x4,    "MTX_MULT_4x4",    { 0 } }, /* Multiply Current Matrix by 4x4 Matrix (W) */ 
  { NDS9_MTX_MULT_4x3,    "MTX_MULT_4x3",    { 0 } }, /* Multiply Current Matrix by 4x3 Matrix (W) */ 
  { NDS9_MTX_MULT_3x3,    "MTX_MULT_3x3",    { 0 } }, /* Multiply Current Matrix by 3x3 Matrix (W) */ 
  { NDS9_MTX_SCALE,       "MTX_SCALE",       { 0 } }, /* Multiply Current Matrix by Scale Matrix (W) */ 
  { NDS9_MTX_TRANS,       "MTX_TRANS",       { 0 } }, /* Mult. Curr. Matrix by Translation Matrix (W) */ 
  { NDS9_COLOR,           "COLOR",           { 0 } }, /* Directly Set Vertex Color (W) */ 
  { NDS9_NORMAL,          "NORMAL",          { 0 } }, /* Set Normal Vector (W) */ 
  { NDS9_TEXCOORD,        "TEXCOORD",        { 0 } }, /* Set Texture Coordinates (W) */ 
  { NDS9_VTX_16,          "VTX_16",          { 0 } }, /* Set Vertex XYZ Coordinates (W) */ 
  { NDS9_VTX_10,          "VTX_10",          { 0 } }, /* Set Vertex XYZ Coordinates (W) */ 
  { NDS9_VTX_XY,          "VTX_XY",          { 0 } }, /* Set Vertex XY Coordinates (W) */ 
  { NDS9_VTX_XZ,          "VTX_XZ",          { 0 } }, /* Set Vertex XZ Coordinates (W) */ 
  { NDS9_VTX_YZ,          "VTX_YZ",          { 0 } }, /* Set Vertex YZ Coordinates (W) */ 
  { NDS9_VTX_DIFF,        "VTX_DIFF",        { 0 } }, /* Set Relative Vertex Coordinates (W) */ 
  { NDS9_POLYGON_ATTR,    "POLYGON_ATTR",    { 0 } }, /* Set Polygon Attributes (W) */ 
  { NDS9_TEXIMAGE_PARAM,  "TEXIMAGE_PARAM",  { 0 } }, /* Set Texture Parameters (W) */ 
  { NDS9_PLTT_BASE,       "PLTT_BASE",       { 0 } }, /* Set Texture Palette Base Address (W) */ 
  { NDS9_DIF_AMB,         "DIF_AMB",         { 0 } }, /* MaterialColor0 - Diffuse/Ambient Reflect. (W) */ 
  { NDS9_SPE_EMI,         "SPE_EMI",         { 0 } }, /* MaterialColor1 - Specular Ref. & Emission (W) */ 
  { NDS9_LIGHT_VECTOR,    "LIGHT_VECTOR",    { 0 } }, /* Set Light's Directional Vector (W) */ 
  { NDS9_LIGHT_COLOR,     "LIGHT_COLOR",     { 0 } }, /* Set Light Color (W) */ 
  { NDS9_SHININESS,       "SHININESS",       { 0 } }, /* Specular Reflection Shininess Table (W) */ 
  { NDS9_BEGIN_VTXS,      "BEGIN_VTXS",      { 0 } }, /* Start of Vertex List (W) */ 
  { NDS9_END_VTXS,        "END_VTXS",        { 0 } }, /* End of Vertex List (W) */ 
  { NDS9_SWAP_BUFFERS,    "SWAP_BUFFERS",    { 0 } }, /* Swap Rendering Engine Buffer (W) */ 
  { NDS9_VIEWPORT,        "VIEWPORT",        { 0 } }, /* Set Viewport (W) */ 
  { NDS9_BOX_TEST,        "BOX_TEST",        { 0 } }, /* Test if Cuboid Sits inside View Volume (W) */ 
  { NDS9_POS_TEST,        "POS_TEST",        { 0 } }, /* Set Position Coordinates for Test (W) */ 
  { NDS9_VEC_TEST,        "VEC_TEST",        { 0 } }, /* Set Directional Vector for Test (W) */ 
  { NDS9_GXSTAT,          "GXSTAT",          { 0 } }, /* Geometry Engine Status Register (R and R/W) */
  { NDS9_RAM_COUNT,       "RAM_COUNT",       { 0 } }, /* Polygon List & Vertex RAM Count Register (R) */
  { NDS9_DISP_1DOT_DEPTH, "DISP_1DOT_DEPTH", { 0 } }, /* 1-Dot Polygon Display Boundary Depth (W) */
  { NDS9_POS_RESULT,      "POS_RESULT",      { 0 } }, /* Position Test Results (R) */
  { NDS9_VEC_RESULT,      "VEC_RESULT",      { 0 } }, /* Vector Test Results (R) */
  { NDS9_CLIPMTX_RESULT,  "CLIPMTX_RESULT",  { 0 } }, /* Read Current Clip Coordinates Matrix (R) */
  { NDS9_VECMTX_RESULT,   "VECMTX_RESULT",   { 0 } }, /* Read Current Directional Vector Matrix (R) */
  { NDS9_B_DISPCNT , "(2D-B)DISPCNT ", { 
    { 0, 3, "BG Mode (0-5=Video Mode 0-5, 6-7=Prohibited)"},
    { 3 ,1, "Reserved / CGB Mode (0=GBA, 1=CGB)"},
    { 4 ,1, "Display Frame Select (0-1=Frame 0-1)"},
    { 5 ,1, "Bitmap OBJ 2D-Dimension (0=128x512 dots, 1=256x256 dots)"},
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
    { 16,2, "Display Mode (0..1)"},
    { 18,2, "VRAM block (0..3=VRAM A..D) (For Capture & above Display Mode=2)"},
    { 20,2, "Tile OBJ 1D-Boundary   (see Bit4)"},
    { 23,1, "OBJ Processing during H-Blank (was located in Bit5 on GBA)"},
    { 24,3, "Character Base (in 64K steps) (merged with 16K step in BGxCNT)"},
    { 30,1,  "BG Extended Palettes   (0=Disable, 1=Enable)"},
    { 31,1,  "OBJ Extended Palettes  (0=Disable, 1=Enable)"}
  } },
  // ARM9 Display Engine B
  { NDS9_B_BG0CNT  , "(2D-B) BG0CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG0 Control */
  { NDS9_B_BG1CNT  , "(2D-B) BG1CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG1 Control */
  { NDS9_B_BG2CNT  , "(2D-B) BG2CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG2 Control */
  { NDS9_B_BG3CNT  , "(2D-B) BG3CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG3 Control */
  { NDS9_B_BG0HOFS , "(2D-B) BG0HOFS", { 0 } }, /* W   BG0 X-Offset */
  { NDS9_B_BG0VOFS , "(2D-B) BG0VOFS", { 0 } }, /* W   BG0 Y-Offset */
  { NDS9_B_BG1HOFS , "(2D-B) BG1HOFS", { 0 } }, /* W   BG1 X-Offset */
  { NDS9_B_BG1VOFS , "(2D-B) BG1VOFS", { 0 } }, /* W   BG1 Y-Offset */
  { NDS9_B_BG2HOFS , "(2D-B) BG2HOFS", { 0 } }, /* W   BG2 X-Offset */
  { NDS9_B_BG2VOFS , "(2D-B) BG2VOFS", { 0 } }, /* W   BG2 Y-Offset */
  { NDS9_B_BG3HOFS , "(2D-B) BG3HOFS", { 0 } }, /* W   BG3 X-Offset */
  { NDS9_B_BG3VOFS , "(2D-B) BG3VOFS", { 0 } }, /* W   BG3 Y-Offset */
  { NDS9_B_BG2PA   , "(2D-B) BG2PA", { 0 } }, /* W   BG2 Rotation/Scaling Parameter A (dx) */
  { NDS9_B_BG2PB   , "(2D-B) BG2PB", { 0 } }, /* W   BG2 Rotation/Scaling Parameter B (dmx) */
  { NDS9_B_BG2PC   , "(2D-B) BG2PC", { 0 } }, /* W   BG2 Rotation/Scaling Parameter C (dy) */
  { NDS9_B_BG2PD   , "(2D-B) BG2PD", { 0 } }, /* W   BG2 Rotation/Scaling Parameter D (dmy) */
  { NDS9_B_BG2X    , "(2D-B) BG2X", { 0 } }, /* W   BG2 Reference Point X-Coordinate */
  { NDS9_B_BG2Y    , "(2D-B) BG2Y", { 0 } }, /* W   BG2 Reference Point Y-Coordinate */
  { NDS9_B_BG3PA   , "(2D-B) BG3PA", { 0 } }, /* W   BG3 Rotation/Scaling Parameter A (dx) */
  { NDS9_B_BG3PB   , "(2D-B) BG3PB", { 0 } }, /* W   BG3 Rotation/Scaling Parameter B (dmx) */
  { NDS9_B_BG3PC   , "(2D-B) BG3PC", { 0 } }, /* W   BG3 Rotation/Scaling Parameter C (dy) */
  { NDS9_B_BG3PD   , "(2D-B) BG3PD", { 0 } }, /* W   BG3 Rotation/Scaling Parameter D (dmy) */
  { NDS9_B_BG3X    , "(2D-B) BG3X", { 0 } }, /* W   BG3 Reference Point X-Coordinate */
  { NDS9_B_BG3Y    , "(2D-B) BG3Y", { 0 } }, /* W   BG3 Reference Point Y-Coordinate */
  { NDS9_B_WIN0H   , "(2D-B) WIN0H", {  
    { 0, 8, "X2, Rightmost coordinate of window, plus 1 " },
    { 8, 8,  "X1, Leftmost coordinate of window"}, 
  } }, /* W   Window 0 Horizontal Dimensions */
  { NDS9_B_WIN1H   , "(2D-B) WIN1H", { 
    { 0, 8, "X2, Rightmost coordinate of window, plus 1 " },
    { 8, 8, "X1, Leftmost coordinate of window"}, 
  } }, /* W   Window 1 Horizontal Dimensions */
  { NDS9_B_WIN0V   , "(2D-B) WIN0V", { 
    {0, 8,  "Y2, Bottom-most coordinate of window, plus 1" },
    {8, 8,  "Y1, Top-most coordinate of window" },
  } }, /* W   Window 0 Vertical Dimensions */
  { NDS9_B_WIN1V   , "(2D-B) WIN1V", { 
    {0, 8,  "Y2, Bottom-most coordinate of window, plus 1" },
    {8, 8,  "Y1, Top-most coordinate of window" },
  } }, /* W   Window 1 Vertical Dimensions */
  { NDS9_B_WININ   , "(2D-B) WININ", {
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
  { NDS9_B_WINOUT  , "(2D-B) WINOUT", { 
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
  { NDS9_B_MOSAIC  , "(2D-B) MOSAIC", { 
    { 0, 4, "BG Mosaic H-Size (minus 1)" },
    { 4, 4, "BG Mosaic V-Size (minus 1)" },
    { 8, 4, "OBJ Mosaic H-Size (minus 1)" },
    { 12,4, "OBJ Mosaic V-Size (minus 1)" },
  } }, /* W   Mosaic Size */
  { NDS9_B_BLDCNT  , "(2D-B) BLDCNT", { 
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
  { NDS9_B_BLDALPHA, "(2D-B) BLDALPHA", { 
    {0, 4, "EVA Coef. (1st Target) (0..16 = 0/16..16/16, 17..31=16/16)"},
    {8, 4, "EVB Coef. (2nd Target) (0..16 = 0/16..16/16, 17..31=16/16)"},
  } }, /* R/W Alpha Blending Coefficients */
  { NDS9_B_BLDY    , "(2D-B) BLDY", { 0 } }, /* W   Brightness (Fade-In/Out) Coefficient */  

  { NDS9_B_MASTER_BRIGHT  ,"(2D-B) MASTER_BRIGHT",  { 0 } }, /* Master Brightness Up/Down */
};

mmio_reg_t nds7_io_reg_desc[]={
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
  { GBA_VCOUNT  , "VCOUNT  ", { 0 } }, /* R   Vertical Counter (LY) */
  { GBA_BG0CNT  , "BG0CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG0 Control */
  { GBA_BG1CNT  , "BG1CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG1 Control */
  { GBA_BG2CNT  , "BG2CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG2 Control */
  { GBA_BG3CNT  , "BG3CNT  ", { 
    { 0,2 , "BG Priority (0-3, 0=Highest)"},
    { 2,4 , "Character Base Block (0-3, in units of 16 KBytes) (=BG Tile Data)"},
    { 6,1 , "Mosaic (0=Disable, 1=Enable)"},
    { 7,1 , "Colors/Palettes (0=16/16, 1=256/1)"},
    { 8,5 , "Screen Base Block (0-31, in units of 2 KBytes) (=BG Map Data)"},
    { 13,1, "BG0/BG1: (NDS: Ext Palette ) BG2/BG3: Overflow (0=Transp, 1=Wrap)"},
    { 14,2, "Screen Size (0-3)"},
  } }, /* R/W BG3 Control */
  { GBA_BG0HOFS , "BG0HOFS", { 0 } }, /* W   BG0 X-Offset */
  { GBA_BG0VOFS , "BG0VOFS", { 0 } }, /* W   BG0 Y-Offset */
  { GBA_BG1HOFS , "BG1HOFS", { 0 } }, /* W   BG1 X-Offset */
  { GBA_BG1VOFS , "BG1VOFS", { 0 } }, /* W   BG1 Y-Offset */
  { GBA_BG2HOFS , "BG2HOFS", { 0 } }, /* W   BG2 X-Offset */
  { GBA_BG2VOFS , "BG2VOFS", { 0 } }, /* W   BG2 Y-Offset */
  { GBA_BG3HOFS , "BG3HOFS", { 0 } }, /* W   BG3 X-Offset */
  { GBA_BG3VOFS , "BG3VOFS", { 0 } }, /* W   BG3 Y-Offset */
  { GBA_BG2PA   , "BG2PA", { 0 } }, /* W   BG2 Rotation/Scaling Parameter A (dx) */
  { GBA_BG2PB   , "BG2PB", { 0 } }, /* W   BG2 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG2PC   , "BG2PC", { 0 } }, /* W   BG2 Rotation/Scaling Parameter C (dy) */
  { GBA_BG2PD   , "BG2PD", { 0 } }, /* W   BG2 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG2X    , "BG2X", { 0 } }, /* W   BG2 Reference Point X-Coordinate */
  { GBA_BG2Y    , "BG2Y", { 0 } }, /* W   BG2 Reference Point Y-Coordinate */
  { GBA_BG3PA   , "BG3PA", { 0 } }, /* W   BG3 Rotation/Scaling Parameter A (dx) */
  { GBA_BG3PB   , "BG3PB", { 0 } }, /* W   BG3 Rotation/Scaling Parameter B (dmx) */
  { GBA_BG3PC   , "BG3PC", { 0 } }, /* W   BG3 Rotation/Scaling Parameter C (dy) */
  { GBA_BG3PD   , "BG3PD", { 0 } }, /* W   BG3 Rotation/Scaling Parameter D (dmy) */
  { GBA_BG3X    , "BG3X", { 0 } }, /* W   BG3 Reference Point X-Coordinate */
  { GBA_BG3Y    , "BG3Y", { 0 } }, /* W   BG3 Reference Point Y-Coordinate */
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
  { GBA_BLDY    , "BLDY", { 0 } }, /* W   Brightness (Fade-In/Out) Coefficient */  
  { NDS_DISP3DCNT,       "DISP3DCNT",       { 0 } }, /* 3D Display Control Register (R/W) */
  { NDS_DISPCAPCNT,      "DISPCAPCNT",      { 0 } }, /* Display Capture Control Register (R/W) */
  { NDS_DISP_MMEM_FIFO,  "DISP_MMEM_FIFO",  { 0 } }, /* Main Memory Display FIFO (R?/W) */
  { NDS_A_MASTER_BRIGHT, "A_MASTER_BRIGHT", { 0 } }, /* Master Brightness Up/Down */

  // DMA Transfer Channels
  { GBA_DMA0SAD  , "DMA0SAD", { 0 } },   /* W    DMA 0 Source Address */
  { GBA_DMA0DAD  , "DMA0DAD", { 0 } },   /* W    DMA 0 Destination Address */
  { GBA_DMA0CNT_L, "DMA0CNT_L", { 0 } },   /* W    DMA 0 Word Count */
  { GBA_DMA0CNT_H, "DMA0CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Prohibited)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 0 Control */
  { GBA_DMA1SAD  , "DMA1SAD", { 0 } },   /* W    DMA 1 Source Address */
  { GBA_DMA1DAD  , "DMA1DAD", { 0 } },   /* W    DMA 1 Destination Address */
  { GBA_DMA1CNT_L, "DMA1CNT_L", { 0 } },   /* W    DMA 1 Word Count */
  { GBA_DMA1CNT_H, "DMA1CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 1 Control */
  { GBA_DMA2SAD  , "DMA2SAD", { 0 } },   /* W    DMA 2 Source Address */
  { GBA_DMA2DAD  , "DMA2DAD", { 0 } },   /* W    DMA 2 Destination Address */
  { GBA_DMA2CNT_L, "DMA2CNT_L", { 0 } },   /* W    DMA 2 Word Count */
  { GBA_DMA2CNT_H, "DMA2CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 12, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Sound)" },
    { 14, 1,  "IRQ upon end of Word Count (0=Disable, 1=Enable)" },
    { 15, 1,  "DMA Enable (0=Off, 1=On)" },
  } },   /* R/W  DMA 2 Control */
  { GBA_DMA3SAD  , "DMA3SAD", { 0 } },   /* W    DMA 3 Source Address */
  { GBA_DMA3DAD  , "DMA3DAD", { 0 } },   /* W    DMA 3 Destination Address */
  { GBA_DMA3CNT_L, "DMA3CNT_L", { 0 } },   /* W    DMA 3 Word Count */
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
  { GBA_TM0CNT_L, "TM0CNT_L", {0} },   /* R/W   Timer 0 Counter/Reload */
  { GBA_TM0CNT_H, "TM0CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 0 Control */
  { GBA_TM1CNT_L, "TM1CNT_L", {0} },   /* R/W   Timer 1 Counter/Reload */
  { GBA_TM1CNT_H, "TM1CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 1 Control */
  { GBA_TM2CNT_L, "TM2CNT_L", {0} },   /* R/W   Timer 2 Counter/Reload */
  { GBA_TM2CNT_H, "TM2CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 2 Control */
  { GBA_TM3CNT_L, "TM3CNT_L", {0} },   /* R/W   Timer 3 Counter/Reload */
  { GBA_TM3CNT_H, "TM3CNT_H", {
    { 0 ,2, "Prescaler Selection (0=F/1, 1=F/64, 2=F/256, 3=F/1024)" },
    { 2 ,1, "Count-up (0=Normal, 1=Incr. on prev. Timer overflow)" },
    { 6 ,1, "Timer IRQ Enable (0=Disable, 1=IRQ on Timer overflow)" },
    { 7 ,1, "Timer Start/Stop (0=Stop, 1=Operate)" },
  } },   /* R/W   Timer 3 Control */  

  // Serial Communication (1)
  { GBA_SIODATA32  , "SIODATA32", {0} }, /*R/W   SIO Data (Normal-32bit Mode; shared with below) */
  { GBA_SIOMULTI0  , "SIOMULTI0", {0} }, /*R/W   SIO Data 0 (Parent)    (Multi-Player Mode) */
  { GBA_SIOMULTI1  , "SIOMULTI1", {0} }, /*R/W   SIO Data 1 (1st Child) (Multi-Player Mode) */
  { GBA_SIOMULTI2  , "SIOMULTI2", {0} }, /*R/W   SIO Data 2 (2nd Child) (Multi-Player Mode) */
  { GBA_SIOMULTI3  , "SIOMULTI3", {0} }, /*R/W   SIO Data 3 (3rd Child) (Multi-Player Mode) */
  { GBA_SIOCNT     , "SIOCNT", {0} }, /*R/W   SIO Control Register */
  { GBA_SIOMLT_SEND, "SIOMLT_SEND", {0} }, /*R/W   SIO Data (Local of MultiPlayer; shared below) */
  { GBA_SIODATA8   , "SIODATA8", {0} }, /*R/W   SIO Data (Normal-8bit and UART Mode) */  

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
  { GBA_RCNT     , "RCNT", {0} },     /* R/W  SIO Mode Select/General Purpose Data */
  { GBA_IR       , "IR", {0} },     /* -    Ancient - Infrared Register (Prototypes only) */
  { GBA_JOYCNT   , "JOYCNT", {0} },     /* R/W  SIO JOY Bus Control */
  { GBA_JOY_RECV , "JOY_RECV", {0} },     /* R/W  SIO JOY Bus Receive Data */
  { GBA_JOY_TRANS, "JOY_TRANS", {0} },     /* R/W  SIO JOY Bus Transmit Data */
  { GBA_JOYSTAT  , "JOYSTAT", {0} },     /* R/?  SIO JOY Bus Receive Status */  

  { NDS7_DEBUG_RCNT,      "DEBUG_RCNT",     { 0 } }, /* Debug RCNT */
  { NDS7_EXTKEYIN,        "EXTKEYIN",       { 0 } }, /* EXTKEYIN */
  { NDS7_RTC_BUS,         "RTC_BUS",        { 0 } }, /* RTC Realtime Clock Bus */
  { NDS_IPCSYNC,         "IPCSYNC",        { 0 } }, /* IPC Synchronize Register (R/W) */
  { NDS_IPCFIFOCNT,      "IPCFIFOCNT",     { 0 } }, /* IPC Fifo Control Register (R/W) */
  { NDS_IPCFIFOSEND,     "IPCFIFOSEND",    { 0 } }, /* IPC Send Fifo (W) */
  { NDS7_AUXSPICNT,       "AUXSPICNT",      { 0 } }, /* Gamecard ROM and SPI Control */
  { NDS7_AUXSPIDATA,      "AUXSPIDATA",     { 0 } }, /* Gamecard SPI Bus Data/Strobe */
  { NDS7_GCBUS_CTL,       "GCBUS_CTL",      { 0 } }, /* Gamecard bus timing/control */
  { NDS7_GCBUS_CMD,       "GCBUS_CMD",      { 0 } }, /* Gamecard bus 8-byte command out */
  { NDS7_GCBUS_SEED0_LO,  "GCBUS_SEED0_LO", { 0 } }, /* Gamecard Encryption Seed 0 Lower 32bit */
  { NDS7_GCBUS_SEED1_LO,  "GCBUS_SEED1_LO", { 0 } }, /* Gamecard Encryption Seed 1 Lower 32bit */
  { NDS7_GCBUS_SEED0_HI,  "GCBUS_SEED0_HI", { 0 } }, /* Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused) */
  { NDS7_GCBUS_SEED1_HI,  "GCBUS_SEED1_HI", { 0 } }, /* Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused) */
  { NDS7_SPI_BUS_CTL,     "SPI_BUS_CTL",    { 0 } }, /* SPI bus Control (Firmware, Touchscreen, Powerman) */
  { NDS7_SPI_BUS_DATA,    "SPI_BUS_DATA",   { 0 } }, /* SPI bus Data */
  // ARM7 Memory and IRQ Control
  { NDS7_EXMEMSTAT,   "EXMEMSTAT",   { 0 }}, /* EXMEMSTAT - External Memory Status */
  { NDS7_WIFIWAITCNT, "WIFIWAITCNT", { 0 }}, /* WIFIWAITCNT */
  { NDS7_IME,         "IME",         { 0 }}, /* IME - Interrupt Master Enable (R/W) */
  { NDS7_IE,          "IE",          { 0 }}, /* IE  - Interrupt Enable (R/W) */
  { NDS7_IF,          "IF",          { 0 }}, /* IF  - Interrupt Request Flags (R/W) */
  { NDS7_VRAMSTAT,    "VRAMSTAT",    { 
    { 0, 1, "VRAM C enabled and allocated to NDS7  (0=No, 1=Yes)"},
    { 1, 1, "VRAM D enabled and allocated to NDS7  (0=No, 1=Yes)"},
  }}, /* VRAMSTAT - VRAM-C,D Bank Status (R) */
  { NDS7_WRAMSTAT,    "WRAMSTAT",    { 0 }}, /* WRAMSTAT - WRAM Bank Status (R) */
  { NDS7_POSTFLG,     "POSTFLG",     { 0 }}, /* POSTFLG */
  { NDS7_HALTCNT,     "HALTCNT",     { 0 }}, /* HALTCNT (different bits than on GBA) (plus NOP delay) */
  { NDS7_POWCNT2,     "POWCNT2",     { 0 }}, /* POWCNT2  Sound/Wifi Power Control Register (R/W) */
  { NDS7_BIOSPROT,    "BIOSPROT",    { 0 }}, /* BIOSPROT - Bios-data-read-protection address */

  // ARM7 Sound Registers (Sound Channel 0..15 (10h bytes each)) 
  { NDS7_SOUND0_CNT, "SOUND0_CNT", { 0 }}, /* Sound Channel 0 Control Register (R/W) */
  { NDS7_SOUND0_SAD, "SOUND0_SAD", { 0 }}, /* Sound Channel 0 Data Source Register (W) */
  { NDS7_SOUND0_TMR, "SOUND0_TMR", { 0 }}, /* Sound Channel 0 Timer Register (W) */
  { NDS7_SOUND0_PNT, "SOUND0_PNT", { 0 }}, /* Sound Channel 0 Loopstart Register (W) */
  { NDS7_SOUND0_LEN, "SOUND0_LEN", { 0 }}, /* Sound Channel 0 Length Register (W) */
  { NDS7_SOUND1_CNT, "SOUND1_CNT", { 0 }}, /* Sound Channel 1 Control Register (R/W) */
  { NDS7_SOUND1_SAD, "SOUND1_SAD", { 0 }}, /* Sound Channel 1 Data Source Register (W) */
  { NDS7_SOUND1_TMR, "SOUND1_TMR", { 0 }}, /* Sound Channel 1 Timer Register (W) */
  { NDS7_SOUND1_PNT, "SOUND1_PNT", { 0 }}, /* Sound Channel 1 Loopstart Register (W) */
  { NDS7_SOUND1_LEN, "SOUND1_LEN", { 0 }}, /* Sound Channel 1 Length Register (W) */
  { NDS7_SOUND2_CNT, "SOUND2_CNT", { 0 }}, /* Sound Channel 2 Control Register (R/W) */
  { NDS7_SOUND2_SAD, "SOUND2_SAD", { 0 }}, /* Sound Channel 2 Data Source Register (W) */
  { NDS7_SOUND2_TMR, "SOUND2_TMR", { 0 }}, /* Sound Channel 2 Timer Register (W) */
  { NDS7_SOUND2_PNT, "SOUND2_PNT", { 0 }}, /* Sound Channel 2 Loopstart Register (W) */
  { NDS7_SOUND2_LEN, "SOUND2_LEN", { 0 }}, /* Sound Channel 2 Length Register (W) */
  { NDS7_SOUND3_CNT, "SOUND3_CNT", { 0 }}, /* Sound Channel 3 Control Register (R/W) */
  { NDS7_SOUND3_SAD, "SOUND3_SAD", { 0 }}, /* Sound Channel 3 Data Source Register (W) */
  { NDS7_SOUND3_TMR, "SOUND3_TMR", { 0 }}, /* Sound Channel 3 Timer Register (W) */
  { NDS7_SOUND3_PNT, "SOUND3_PNT", { 0 }}, /* Sound Channel 3 Loopstart Register (W) */
  { NDS7_SOUND3_LEN, "SOUND3_LEN", { 0 }}, /* Sound Channel 3 Length Register (W) */
  { NDS7_SOUND4_CNT, "SOUND4_CNT", { 0 }}, /* Sound Channel 4 Control Register (R/W) */
  { NDS7_SOUND4_SAD, "SOUND4_SAD", { 0 }}, /* Sound Channel 4 Data Source Register (W) */
  { NDS7_SOUND4_TMR, "SOUND4_TMR", { 0 }}, /* Sound Channel 4 Timer Register (W) */
  { NDS7_SOUND4_PNT, "SOUND4_PNT", { 0 }}, /* Sound Channel 4 Loopstart Register (W) */
  { NDS7_SOUND4_LEN, "SOUND4_LEN", { 0 }}, /* Sound Channel 4 Length Register (W) */
  { NDS7_SOUND5_CNT, "SOUND5_CNT", { 0 }}, /* Sound Channel 5 Control Register (R/W) */
  { NDS7_SOUND5_SAD, "SOUND5_SAD", { 0 }}, /* Sound Channel 5 Data Source Register (W) */
  { NDS7_SOUND5_TMR, "SOUND5_TMR", { 0 }}, /* Sound Channel 5 Timer Register (W) */
  { NDS7_SOUND5_PNT, "SOUND5_PNT", { 0 }}, /* Sound Channel 5 Loopstart Register (W) */
  { NDS7_SOUND5_LEN, "SOUND5_LEN", { 0 }}, /* Sound Channel 5 Length Register (W) */
  { NDS7_SOUND6_CNT, "SOUND6_CNT", { 0 }}, /* Sound Channel 6 Control Register (R/W) */
  { NDS7_SOUND6_SAD, "SOUND6_SAD", { 0 }}, /* Sound Channel 6 Data Source Register (W) */
  { NDS7_SOUND6_TMR, "SOUND6_TMR", { 0 }}, /* Sound Channel 6 Timer Register (W) */
  { NDS7_SOUND6_PNT, "SOUND6_PNT", { 0 }}, /* Sound Channel 6 Loopstart Register (W) */
  { NDS7_SOUND6_LEN, "SOUND6_LEN", { 0 }}, /* Sound Channel 6 Length Register (W) */
  { NDS7_SOUND7_CNT, "SOUND7_CNT", { 0 }}, /* Sound Channel 7 Control Register (R/W) */
  { NDS7_SOUND7_SAD, "SOUND7_SAD", { 0 }}, /* Sound Channel 7 Data Source Register (W) */
  { NDS7_SOUND7_TMR, "SOUND7_TMR", { 0 }}, /* Sound Channel 7 Timer Register (W) */
  { NDS7_SOUND7_PNT, "SOUND7_PNT", { 0 }}, /* Sound Channel 7 Loopstart Register (W) */
  { NDS7_SOUND7_LEN, "SOUND7_LEN", { 0 }}, /* Sound Channel 7 Length Register (W) */
  { NDS7_SOUND8_CNT, "SOUND8_CNT", { 0 }}, /* Sound Channel 8 Control Register (R/W) */
  { NDS7_SOUND8_SAD, "SOUND8_SAD", { 0 }}, /* Sound Channel 8 Data Source Register (W) */
  { NDS7_SOUND8_TMR, "SOUND8_TMR", { 0 }}, /* Sound Channel 8 Timer Register (W) */
  { NDS7_SOUND8_PNT, "SOUND8_PNT", { 0 }}, /* Sound Channel 8 Loopstart Register (W) */
  { NDS7_SOUND8_LEN, "SOUND8_LEN", { 0 }}, /* Sound Channel 8 Length Register (W) */
  { NDS7_SOUND9_CNT, "SOUND9_CNT", { 0 }}, /* Sound Channel 9 Control Register (R/W) */
  { NDS7_SOUND9_SAD, "SOUND9_SAD", { 0 }}, /* Sound Channel 9 Data Source Register (W) */
  { NDS7_SOUND9_TMR, "SOUND9_TMR", { 0 }}, /* Sound Channel 9 Timer Register (W) */
  { NDS7_SOUND9_PNT, "SOUND9_PNT", { 0 }}, /* Sound Channel 9 Loopstart Register (W) */
  { NDS7_SOUND9_LEN, "SOUND9_LEN", { 0 }}, /* Sound Channel 9 Length Register (W) */
  { NDS7_SOUNDA_CNT, "SOUNDA_CNT", { 0 }}, /* Sound Channel 10 Control Register (R/W) */
  { NDS7_SOUNDA_SAD, "SOUNDA_SAD", { 0 }}, /* Sound Channel 10 Data Source Register (W) */
  { NDS7_SOUNDA_TMR, "SOUNDA_TMR", { 0 }}, /* Sound Channel 10 Timer Register (W) */
  { NDS7_SOUNDA_PNT, "SOUNDA_PNT", { 0 }}, /* Sound Channel 10 Loopstart Register (W) */
  { NDS7_SOUNDA_LEN, "SOUNDA_LEN", { 0 }}, /* Sound Channel 10 Length Register (W) */
  { NDS7_SOUNDB_CNT, "SOUNDB_CNT", { 0 }}, /* Sound Channel 11 Control Register (R/W) */
  { NDS7_SOUNDB_SAD, "SOUNDB_SAD", { 0 }}, /* Sound Channel 11 Data Source Register (W) */
  { NDS7_SOUNDB_TMR, "SOUNDB_TMR", { 0 }}, /* Sound Channel 11 Timer Register (W) */
  { NDS7_SOUNDB_PNT, "SOUNDB_PNT", { 0 }}, /* Sound Channel 11 Loopstart Register (W) */
  { NDS7_SOUNDB_LEN, "SOUNDB_LEN", { 0 }}, /* Sound Channel 11 Length Register (W) */
  { NDS7_SOUNDC_CNT, "SOUNDC_CNT", { 0 }}, /* Sound Channel 12 Control Register (R/W) */
  { NDS7_SOUNDC_SAD, "SOUNDC_SAD", { 0 }}, /* Sound Channel 12 Data Source Register (W) */
  { NDS7_SOUNDC_TMR, "SOUNDC_TMR", { 0 }}, /* Sound Channel 12 Timer Register (W) */
  { NDS7_SOUNDC_PNT, "SOUNDC_PNT", { 0 }}, /* Sound Channel 12 Loopstart Register (W) */
  { NDS7_SOUNDC_LEN, "SOUNDC_LEN", { 0 }}, /* Sound Channel 12 Length Register (W) */
  { NDS7_SOUNDD_CNT, "SOUNDD_CNT", { 0 }}, /* Sound Channel 13 Control Register (R/W) */
  { NDS7_SOUNDD_SAD, "SOUNDD_SAD", { 0 }}, /* Sound Channel 13 Data Source Register (W) */
  { NDS7_SOUNDD_TMR, "SOUNDD_TMR", { 0 }}, /* Sound Channel 13 Timer Register (W) */
  { NDS7_SOUNDD_PNT, "SOUNDD_PNT", { 0 }}, /* Sound Channel 13 Loopstart Register (W) */
  { NDS7_SOUNDD_LEN, "SOUNDD_LEN", { 0 }}, /* Sound Channel 13 Length Register (W) */
  { NDS7_SOUNDE_CNT, "SOUNDE_CNT", { 0 }}, /* Sound Channel 14 Control Register (R/W) */
  { NDS7_SOUNDE_SAD, "SOUNDE_SAD", { 0 }}, /* Sound Channel 14 Data Source Register (W) */
  { NDS7_SOUNDE_TMR, "SOUNDE_TMR", { 0 }}, /* Sound Channel 14 Timer Register (W) */
  { NDS7_SOUNDE_PNT, "SOUNDE_PNT", { 0 }}, /* Sound Channel 14 Loopstart Register (W) */
  { NDS7_SOUNDE_LEN, "SOUNDE_LEN", { 0 }}, /* Sound Channel 14 Length Register (W) */
  { NDS7_SOUNDF_CNT, "SOUNDF_CNT", { 0 }}, /* Sound Channel 15 Control Register (R/W) */
  { NDS7_SOUNDF_SAD, "SOUNDF_SAD", { 0 }}, /* Sound Channel 15 Data Source Register (W) */
  { NDS7_SOUNDF_TMR, "SOUNDF_TMR", { 0 }}, /* Sound Channel 15 Timer Register (W) */
  { NDS7_SOUNDF_PNT, "SOUNDF_PNT", { 0 }}, /* Sound Channel 15 Loopstart Register (W) */
  { NDS7_SOUNDF_LEN, "SOUNDF_LEN", { 0 }}, /* Sound Channel 15 Length Register (W) */

  { NDS7_SOUNDCNT,   "SOUNDCNT",   { 0 }}, /* Sound Control Register (R/W) */
  { NDS7_SOUNDBIAS,  "SOUNDBIAS",  { 0 }}, /* Sound Bias Register (R/W) */
  { NDS7_SNDCAP0CNT, "SNDCAP0CNT", { 0 }}, /* Sound Capture 0 Control Register (R/W) */
  { NDS7_SNDCAP1CNT, "SNDCAP1CNT", { 0 }}, /* Sound Capture 1 Control Register (R/W) */
  { NDS7_SNDCAP0DAD, "SNDCAP0DAD", { 0 }}, /* Sound Capture 0 Destination Address (R/W) */
  { NDS7_SNDCAP0LEN, "SNDCAP0LEN", { 0 }}, /* Sound Capture 0 Length (W) */
  { NDS7_SNDCAP1DAD, "SNDCAP1DAD", { 0 }}, /* Sound Capture 1 Destination Address (R/W) */
  { NDS7_SNDCAP1LEN, "SNDCAP1LEN", { 0 }}, /* Sound Capture 1 Length (W) */

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

#define NDS_INT_IPC_SYNC         16  /* IPC Sync */
#define NDS_INT_IPC_FIFO_SEND    17  /* IPC Send FIFO Empty */
#define NDS_INT_IPC_FIFO_RECV    18  /* IPC Recv FIFO Not Empty */
#define NDS_INT_GC_TRANSFER_DONE 19  /* NDS-Slot Game Card Data Transfer Completion */
#define NDS_INT_GC_IREQ_MC       20  /* NDS-Slot Game Card IREQ_MC */
#define NDS9_INT_GX_FIFO         21  /* NDS9 only: Geometry Command FIFO */
#define NDS7_INT_SCREEN_FOLD     22  /* NDS7 only: Screens unfolding */
#define NDS7_INT_SPI             23  /* NDS7 only: SPI bus */
#define NDS7_WIFI                24  /* NDS7 only: Wifi    / DSi9: XpertTeak DSP */
#define NDSi9_DSP                24  /* NDS7 only: Wifi    / DSi9: XpertTeak DSP */

#define NDSi9_CAMERA             25  /* Not used           / DSi9: Camera */
#define NDSi9_UNDOC              26  /* Not used           / DSi9: Undoc, IF.26 set on FFh-filling 40021Axh */
#define NDSi_IREQ_MC             27  /* Not used           / DSi:  Maybe IREQ_MC for 2nd gamecard? */
#define NDSi_DMA0                28  /* Not used           / DSi: NewDMA0 */
#define NDSi_DMA1                29  /* Not used           / DSi: NewDMA1 */
#define NDSi_DMA2                30  /* Not used           / DSi: NewDMA2 */
#define NDSi_DMA3                31  /* Not used           / DSi: NewDMA3 */

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

#define GBA_REQ_1B    0x01
#define GBA_REQ_2B    0x02
#define GBA_REQ_4B    0x04
#define GBA_REQ_READ  0x40
#define GBA_REQ_WRITE 0x80

#define NDS_LCD_W 256
#define NDS_LCD_H 192

#define NDS_IO_MAP_SPLIT_ADDRESS 0x0400006C
#define NDS_IO_MAP_SPLIT_OFFSET  0x2000
#define NDS_IO_MAP_041_OFFSET    0x4000

#define NDS_VRAM_SLOT0 0x06900000
#define NDS_ARM9 1
#define NDS_ARM7 0

typedef struct {     
  uint8_t ram[4*1024*1024]; /*4096KB Main RAM (8192KB in debug version)*/
  uint8_t wram[96*1024];    /*96KB   WRAM (64K mapped to NDS7, plus 32K mappable to NDS7 or NDS9)*/
  /* TCM/Cache (TCM: 16K Data, 32K Code) (Cache: 4K Data, 8K Code) */
  uint8_t code_tcm[32*1024];
  uint8_t data_tcm[16*1024];
  uint8_t code_cache[8*1024];
  uint8_t data_cache[4*1024];
  uint8_t vram[656*1024];    /* VRAM (allocateable as BG/OBJ/2D/3D/Palette/Texture/WRAM memory) */
  uint8_t palette[2*1024];   

  uint8_t oam[4*1024];       /* OAM/PAL (2K OBJ Attribute Memory, 2K Standard Palette RAM) */
  /* BIOS ROM (4K NDS9, 16K NDS7, 16K GBA) */
  uint8_t nds7_bios[16*1024];
  uint8_t nds9_bios[4*1024];
  /* Firmware FLASH (512KB in iQue variant, with chinese charset) */
  uint8_t firmware[256*1024];
  uint8_t io[64*1024];

  uint8_t *card_data;
  size_t card_size;

  uint8_t wait_state_table[16*4];
  bool prefetch_en;
  int prefetch_size;
  uint32_t requests;
  uint32_t openbus_word;
  uint32_t arm7_bios_word;
  uint32_t dtcm_start_address;
  uint32_t dtcm_end_address;
  uint32_t itcm_start_address;
  uint32_t itcm_end_address;
  bool dtcm_load_mode;
  bool itcm_load_mode;
  bool dtcm_enable;
  bool itcm_enable;
} nds_mem_t;

typedef struct {
  //Bytes 0..31
  uint8_t title[12];   /* Game Title  (Uppercase ASCII, padded with 00h) */
  uint8_t gamecode[4];  /* Gamecode    (Uppercase ASCII, NTR-<code>)        (0=homebrew) */
  uint8_t makercode[2]; /* Makercode   (Uppercase ASCII, eg. "01"=Nintendo) (0=homebrew) */
  uint8_t unitcode;     /* Unitcode    (00h=NDS, 02h=NDS+DSi, 03h=DSi) (bit1=DSi) */
  uint8_t seed_sel;        /* Encryption Seed Select (00..07h, usually 00h) */
  uint8_t device_capacity; /* Devicecapacity         (Chipsize = 128KB SHL nn) (eg. 7 = 16MB) */
  uint8_t reserved[8];
  uint8_t region;          /* NDS Region  (00h=Normal, 80h=China, 40h=Korea) (other on DSi) */
  uint8_t rom_version;     /* ROM Version (usually 00h) */
  uint8_t autostart;       /* Autostart (Bit2: Skip "Press Button" after Health and Safety) */
  //Byte 32..63
  uint32_t arm9_rom_offset; /* ARM9 rom_offset    (4000h and up, align 1000h) */
  uint32_t arm9_entrypoint; /* ARM9 entry_address (2000000h..23BFE00h) */
  uint32_t arm9_ram_address;/* ARM9 ram_address   (2000000h..23BFE00h) */
  uint32_t arm9_size;       /* ARM9 size          (max 3BFE00h) (3839.5KB) */

  uint32_t arm7_rom_offset;  /* ARM7 rom_offset    (8000h and up) */
  uint32_t arm7_entrypoint;  /* ARM7 entry_address (2000000h..23BFE00h, or 37F8000h..3807E00h) */
  uint32_t arm7_ram_address; /* ARM7 ram_address   (2000000h..23BFE00h, or 37F8000h..3807E00h) */
  uint32_t arm7_size;        /* ARM7 size          (max 3BFE00h, or FE00h) (3839.5KB, 63.5KB) */
  
  //Byte 64..95
  uint32_t fnt_offset; /* File Name Table (FNT) offset */
  uint32_t fnt_size;   /* File Name Table (FNT) size */
  uint32_t fat_offset; /* File Allocation Table (FAT) offset */
  uint32_t fat_size;   /* File Allocation Table (FAT) size */
  uint32_t arm9_overlay_offset; /* File ARM9 overlay_offset */
  uint32_t arm9_overlay_size;   /* File ARM9 overlay_size */
  uint32_t arm7_overlay_offset; /* File ARM7 overlay_offset */
  uint32_t arm7_overlay_size;   /* File ARM7 overlay_size */
  //Byte 96..127
  uint32_t port0; /* Port 40001A4h setting for normal commands (usually 00586000h) */
  uint32_t port1; /* Port 40001A4h setting for KEY1 commands   (usually 001808F8h) */
  uint32_t icon_title_offset; /* Icon/Title offset (0=None) (8000h and up) */
  uint16_t sec_checksum;  /* Secure Area Checksum, CRC-16 of [[020h]..00007FFFh] */
  uint16_t sec_delay; /* Secure Area Delay (in 131kHz units) (051Eh=10ms or 0D7Eh=26ms) */
  uint32_t arm9_autoload; /* ARM9 Auto Load List Hook RAM Address (?) ;\endaddr of auto-load */
  uint32_t arm7_autoload; /* ARM7 Auto Load List Hook RAM Address (?) ;/functions */
  uint8_t sec_disable[8]; /* Secure Area Disable (by encrypted "NmMdOnly") (usually zero) */
  //Byte 128..159
  uint32_t rom_size_used; /* Total Used ROM size (remaining/unused bytes usually FFh-padded) */
  uint32_t rom_header_size;  /* ROM Header Size (4000h) */
  uint8_t reserved2[24];
} nds_card_t;
typedef struct{
  bool up,down,left,right;
  bool a, b, start, select;
  bool l,r;
  bool x,y;
  float touch_x;
  float touch_y;
} nds_input_t;
typedef struct{
  int source_addr;
  int dest_addr;
  int length;
  int current_transaction;
  bool last_enable;
  bool last_vblank;
  bool last_hblank;
  uint32_t latched_transfer;
  int startup_delay; 
  bool activate_audio_dma;
} nds_dma_t; 
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
  uint32_t first_target_buffer[NDS_LCD_W];
  uint32_t second_target_buffer[NDS_LCD_W];
  uint8_t window[NDS_LCD_W];
  uint32_t bg_vram_base;
  uint32_t obj_vram_base; 
}nds_ppu_t;
typedef struct{
  bool last_enable; 
  uint16_t reload_value; 
  uint16_t pending_reload_value; 
  uint16_t prescaler_timer;
  uint16_t elapsed_audio_samples;
  int startup_delay;
}nds_timer_t;
typedef struct{
  uint32_t serial_state;
  uint32_t serial_bits_clocked;
  uint64_t input_register;
  uint64_t output_register;
  uint32_t state;
  uint8_t status_register;
  uint16_t year;
  uint8_t month;
  uint8_t day;
  uint8_t day_of_week;
  uint8_t hour;
  uint8_t minute;
  uint8_t second;
}nds_rtc_t;
typedef struct{
  uint32_t fifo[16];
  uint32_t read_ptr;
  uint32_t write_ptr;
  uint32_t sync_data;
  bool error; 
}nds_ipc_t;
typedef struct{
  //[Cn][Cm][Cp]
  uint32_t reg[16][16][8]; 
}nds_system_control_processor;
typedef struct{
  uint64_t div_last_update_clock;
  uint64_t sqrt_last_update_clock;
}nds_math_t;

typedef struct{
  nds_mem_t mem;
  arm7_t arm7;
  arm7_t arm9;

  nds_card_t card;
  nds_input_t joy;       
  nds_ppu_t ppu[2];
  nds_rtc_t rtc;
  nds_dma_t dma[2][4]; 
  nds_ipc_t ipc[2];
  nds_system_control_processor cp15;
  nds_math_t math; 
  //There is a 2 cycle penalty when the CPU takes over from the DMA
  bool last_transaction_dma; 
  bool activate_dmas; 
  nds_timer_t timers[4];
  uint32_t timer_ticks_before_event;
  uint32_t deferred_timer_ticks;
  bool halt; 
  bool prev_key_interrupt;
  // Some HW has up to a 4 cycle delay before its IF propagates. 
  // This array acts as a FIFO to keep track of that. 
  uint32_t nds9_pipelined_if[5];
  uint32_t nds7_pipelined_if[5];
  int active_if_pipe_stages; 
  char save_file_path[SB_FILE_PATH_SIZE];

  uint8_t framebuffer_top[NDS_LCD_W*NDS_LCD_H*3];
  uint8_t framebuffer_bottom[NDS_LCD_W*NDS_LCD_H*3];
  uint64_t current_clock;
} nds_t; 

static void nds_tick_keypad(sb_joy_t*joy, nds_t* nds); 
static FORCE_INLINE void nds_tick_timers(nds_t* nds);
static void nds_compute_timers(nds_t* nds); 
static void FORCE_INLINE nds9_send_interrupt(nds_t*nds,int delay,int if_bit){
  nds->active_if_pipe_stages|=1<<delay;
  nds->nds9_pipelined_if[delay]|= if_bit;
}
static void FORCE_INLINE nds7_send_interrupt(nds_t*nds,int delay,int if_bit){
  nds->active_if_pipe_stages|=1<<delay;
  nds->nds7_pipelined_if[delay]|= if_bit;
}
static void FORCE_INLINE nds_send_interrupt(nds_t*nds,int delay,int if_bit){
  nds->active_if_pipe_stages|=1<<delay;
  nds->nds7_pipelined_if[delay]|= if_bit;
  nds->nds9_pipelined_if[delay]|= if_bit;
}
       
static uint64_t nds_rev_bits(uint64_t data, int bits){
  uint64_t out = 0;
  for(int i=0;i<bits;++i){
    out<<=1;
    out|=data&1;
    data>>=1;
  }
  return out;
}
static FORCE_INLINE void nds9_io_store8(nds_t*nds, unsigned baddr, uint8_t data){nds->mem.io[baddr&0xffff]=data;}
static FORCE_INLINE void nds9_io_store16(nds_t*nds, unsigned baddr, uint16_t data){*(uint16_t*)(nds->mem.io+(baddr&0xffff))=data;}
static FORCE_INLINE void nds9_io_store32(nds_t*nds, unsigned baddr, uint32_t data){*(uint32_t*)(nds->mem.io+(baddr&0xffff))=data;}

static FORCE_INLINE uint8_t  nds9_io_read8(nds_t*nds, unsigned baddr) {return nds->mem.io[baddr&0xffff];}
static FORCE_INLINE uint16_t nds9_io_read16(nds_t*nds, unsigned baddr){return *(uint16_t*)(nds->mem.io+(baddr&0xffff));}
static FORCE_INLINE uint32_t nds9_io_read32(nds_t*nds, unsigned baddr){return *(uint32_t*)(nds->mem.io+(baddr&0xffff));}

static FORCE_INLINE void nds7_io_store8(nds_t*nds, unsigned baddr, uint8_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  nds->mem.io[baddr&0xffff]=data;
}
static FORCE_INLINE void nds7_io_store16(nds_t*nds, unsigned baddr, uint16_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint16_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE void nds7_io_store32(nds_t*nds, unsigned baddr, uint32_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint32_t*)(nds->mem.io+(baddr&0xffff))=data;
}

static FORCE_INLINE uint8_t  nds7_io_read8(nds_t*nds, unsigned baddr) {
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return nds->mem.io[baddr&0xffff];
}
static FORCE_INLINE uint16_t nds7_io_read16(nds_t*nds, unsigned baddr){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint16_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE uint32_t nds7_io_read32(nds_t*nds, unsigned baddr){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint32_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE void nds_io_store8(nds_t*nds,int cpu_id, unsigned baddr, uint8_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  nds->mem.io[baddr&0xffff]=data;
}
static FORCE_INLINE void nds_io_store16(nds_t*nds,int cpu_id, unsigned baddr, uint16_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint16_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE void nds_io_store32(nds_t*nds,int cpu_id, unsigned baddr, uint32_t data){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint32_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE uint8_t  nds_io_read8(nds_t*nds,int cpu_id, unsigned baddr) {
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return nds->mem.io[baddr&0xffff];
}
static FORCE_INLINE uint16_t nds_io_read16(nds_t*nds,int cpu_id, unsigned baddr){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint16_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE uint32_t nds_io_read32(nds_t*nds,int cpu_id, unsigned baddr){
  if(baddr>=NDS_IO_MAP_SPLIT_ADDRESS&&cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint32_t*)(nds->mem.io+(baddr&0xffff));
}

#define NDS_MEM_1B 0x0
#define NDS_MEM_2B 0x1
#define NDS_MEM_4B 0x2

#define NDS_MEM_WRITE 0x10
#define NDS_MEM_SEQ   0x20
#define NDS_MEM_ARM7  0x40
#define NDS_MEM_ARM9  0x80
static uint32_t nds_apply_mem_op(uint8_t * memory,uint32_t address, uint32_t data, int transaction_type){
  if(transaction_type&NDS_MEM_4B){
    address&=~3;
    if(transaction_type&NDS_MEM_WRITE)*(uint32_t*)(memory+address)=data;
    else data = *(uint32_t*)(memory+address);
  }else if(transaction_type&NDS_MEM_2B){
    address&=~1;
    if(transaction_type&NDS_MEM_WRITE)*(uint16_t*)(memory+address)=data;
    else data = *(uint16_t*)(memory+address);
  }else{
    if(transaction_type&NDS_MEM_WRITE)memory[address]=data;
    else data = memory[address];
  }
  return data; 
}
static uint32_t nds_apply_vram_mem_op(nds_t *nds,uint32_t address, uint32_t data, int transaction_type){
  const static int bank_size[9]={
    128*1024, //A
    128*1024, //B
    128*1024, //C
    128*1024, //D
    64*1024,  //E
    16*1024,  //F
    16*1024,  //G
    32*1024,  //H
    16*1024,  //I
  };
  uint32_t offset_table[6][5]={
    {0,0,0,0}, //Offset ignored
    {0x20000*0, 0x20000*1, 0x20000*2,0x20000*3}, //(0x20000*OFS)
    {0x0, 0x4000, 0x10000,0x14000}, //(4000h*OFS.0)+(10000h*OFS.1)
    {0x20000*0, 0x20000*0, 0x20000*0,0x20000*0}, // Slot 0-3 (mirrored)
    {0x20000*0, 0x20000*2, 0x20000*0,0x20000*2}, // Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
    {0x20000*0, 0x20000*1, 0x20000*4,0x20000*5}, // Slot (OFS.0*1)+(OFS.1*4)
  };
  typedef struct vram_bank_info_t{
    int transaction_mask; // Block transactions of these types
    int offset_table;
    uint32_t mem_address_start;
  }vram_bank_info_t;

  const static vram_bank_info_t bank_info[9][8]={
    { //Bank A 
      {NDS_MEM_ARM7, 0, 0x06800000}, //MST 0 6800000h-681FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM7, 1, 0x06400000}, //MST 2 6400000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06800000}, //MST 4
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 5 
      {NDS_MEM_ARM7, 1, 0x06400000}, //MST 6 
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 7
    },{ //Bank B
      {NDS_MEM_ARM7, 0, 0x06820000}, //MST 0 6820000h-683FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM7, 1, 0x06400000}, //MST 2 6400000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06820000}, //MST 4
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 5 
      {NDS_MEM_ARM7, 1, 0x06400000}, //MST 6 
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 7
    },{ //Bank C
      {NDS_MEM_ARM7, 0, 0x06840000}, //MST 0 6840000h-685FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM9, 1, 0x06000000}, //MST 2 6000000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 4 6200000h
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank D
      {NDS_MEM_ARM7, 0, 0x06860000}, //MST 0 6860000h-687FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM9, 1, 0x06000000}, //MST 2 6000000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 1, NDS_VRAM_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 4 6600000h
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank E
      {NDS_MEM_ARM7, 0, 0x06880000}, //MST 0 6880000h-688FFFFh
      {NDS_MEM_ARM7, 0, 0x06000000}, //MST 1 6000000h
      {NDS_MEM_ARM7, 0, 0x06400000}, //MST 2 6400000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 3, NDS_VRAM_SLOT0}, //MST 3 Slots 0-3;OFS=don't care
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 3, NDS_VRAM_SLOT0}, //MST 4 (64K Slot 0-3  ;only lower 32K used)
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank F
      {NDS_MEM_ARM7, 0, 0x06890000}, //MST 0 6890000h-6893FFFh
      {NDS_MEM_ARM7, 2, 0x06000000}, //MST 1 6000000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7, 2, 0x06400000}, //MST 2 6400000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 5, NDS_VRAM_SLOT0}, //MST 3 Slot (OFS.0*1)+(OFS.1*4)  ;ie. Slot 0, 1, 4, or 5
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 4, NDS_VRAM_SLOT0}, //MST 4 0..1  Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
      {NDS_MEM_ARM7, 0, NDS_VRAM_SLOT0}, //MST 5 Slot 0  ;16K each (only lower 8K used)
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank G
      {NDS_MEM_ARM7, 0, 0x06894000}, //MST 0 6894000h-6897FFFh
      {NDS_MEM_ARM7, 2, 0x06000000}, //MST 1 6000000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7, 2, 0x06400000}, //MST 2 6400000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 5, NDS_VRAM_SLOT0}, //MST3 Slot (OFS.0*1)+(OFS.1*4)  ;ie. Slot 0, 1, 4, or 5
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 4, NDS_VRAM_SLOT0}, //MST 4 0..1  Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
      {NDS_MEM_ARM7, 0, NDS_VRAM_SLOT0}, //MST 5 Slot 0  ;16K each (only lower 8K used)
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank H
      {NDS_MEM_ARM7, 0, 0x06898000}, //MST 0 6898000h-689FFFFh
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 1 6200000h
      {NDS_MEM_ARM7, 3, NDS_VRAM_SLOT0}, //MST 2 Slot 0-3
      {0xffffffff, 0, 0x0}, // MST 3 INVALID
      {NDS_MEM_ARM7, 0, 0x06898000}, //MST 4 6898000h-689FFFFh
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 5 6200000h
      {NDS_MEM_ARM7, 3, NDS_VRAM_SLOT0}, //MST 6 Slot 0-3
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank I
      {NDS_MEM_ARM7, 0, 0x068A0000}, //MST 0 68A0000h-68A3FFFh
      {NDS_MEM_ARM7, 0, 0x06208000}, //MST 1 6208000h
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 2 6600000h
      {NDS_MEM_ARM7, 0, NDS_VRAM_SLOT0}, //MST 3 Slot 0  ;16K each (only lower 8K used)
      {NDS_MEM_ARM7, 0, 0x068A0000}, //MST 4 68A0000h-68A3FFFh
      {NDS_MEM_ARM7, 0, 0x06208000}, //MST 5 6208000h
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 6 6600000h
      {NDS_MEM_ARM7, 0, NDS_VRAM_SLOT0}, //MST 7 Slot 0  ;16K each (only lower 8K used)
    }
  };
  if(!(transaction_type&NDS_MEM_WRITE))data=0;
  int total_banks = 9;
  int vram_offset = 0; 

  //1Byte writes are ignored from the ARM9
  if((transaction_type&NDS_MEM_WRITE)&&(transaction_type&NDS_MEM_1B)&&(transaction_type&NDS_MEM_ARM9))return 0;
  for(int b = 0; b<total_banks;++b){
    int vram_off = vram_offset;
    vram_offset +=bank_size[b];
    uint8_t vramcnt = nds9_io_read8(nds,NDS9_VRAMCNT_A+b);
    bool enable = SB_BFE(vramcnt,7,1);
    if(!enable)continue;
    int mst = SB_BFE(vramcnt,0,3);
    int off = SB_BFE(vramcnt,3,2);

    vram_bank_info_t bank = bank_info[b][mst];
    if(transaction_type& bank.transaction_mask)continue;
    int base = bank.mem_address_start;
    base += offset_table[bank.offset_table][off];
    if(address<base)continue;

    int bank_offset = address-base; 
    if(bank_offset>=bank_size[b])continue;
    int vram_addr = bank_offset+vram_off;
    if(transaction_type&NDS_MEM_4B){
      vram_addr&=~3;
      if(transaction_type&NDS_MEM_WRITE)*(uint32_t*)(nds->mem.vram+vram_addr)=data;
      else data |= *(uint32_t*)(nds->mem.vram+vram_addr);
    }else if(transaction_type&NDS_MEM_2B){
      vram_addr&=~1;
      if(transaction_type&NDS_MEM_WRITE)*(uint16_t*)(nds->mem.vram+vram_addr)=data;
      else data |= *(uint16_t*)(nds->mem.vram+vram_addr);
    }else{
      if(transaction_type&NDS_MEM_WRITE)nds->mem.vram[vram_addr]=data;
      else data |= nds->mem.vram[vram_addr];
    }
  }
  return data; 
}
static void nds_preprocess_mmio_read(nds_t * nds, uint32_t addr, int transaction_type);
static void nds_postprocess_mmio_write(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type);
static uint32_t nds_process_memory_transaction(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type){
  uint32_t *ret = &nds->mem.openbus_word;
  *ret=0;
  if(transaction_type&NDS_MEM_ARM9){
    if(addr>=nds->mem.dtcm_start_address&&addr<nds->mem.dtcm_end_address){
      if(nds->mem.dtcm_enable&&(!nds->mem.dtcm_load_mode||(transaction_type&NDS_MEM_WRITE))){
        nds->mem.openbus_word = nds_apply_mem_op(nds->mem.data_tcm,(addr-nds->mem.dtcm_start_address)&(16*1024-1),data,transaction_type);
        return *ret; 
      }
    }
    if(addr>=nds->mem.itcm_start_address&&addr<nds->mem.itcm_end_address){
      if(nds->mem.itcm_enable&&(!nds->mem.itcm_load_mode||(transaction_type&NDS_MEM_WRITE))){
        nds->mem.openbus_word = nds_apply_mem_op(nds->mem.code_tcm,(addr-nds->mem.itcm_start_address)&(32*1024-1),data,transaction_type);
        return *ret; 
      }
    }
  }
  switch(addr>>24){
      case 0x0: //BIOS(NDS7), TCM(NDS9)
      if(transaction_type&NDS_MEM_ARM7){
        if(addr<0x4000){
          if(nds->arm7.registers[PC]<0x4000)
            nds->mem.arm7_bios_word = nds_apply_mem_op(nds->mem.nds7_bios,addr,data,transaction_type&~NDS_MEM_WRITE);
          //else nds->mem.bios_word=0;
          nds->mem.openbus_word=nds->mem.arm7_bios_word;
        } 
       }
       break;
    case 0x2: //Main RAM
      addr&=4*1024*1024-1;
      *ret = nds_apply_mem_op(nds->mem.ram, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
    case 0x3: //Shared WRAM 
      {
        uint32_t orig_addr = addr;
        uint8_t cnt = nds9_io_read8(nds,NDS9_WRAMCNT)&0x3;
        if(transaction_type&NDS_MEM_ARM9){
          const int offset[4]={0,16*1024,0,0};
          const int mask[4]={32*1024-1,16*1024-1,16*1024-1,0};
          addr=(addr&mask[cnt])+offset[cnt];
        }else {
          if(addr<0x037FFFFF){
            const int offset[4]={0,0,16*1024,0};
            const int mask[4]={0,16*1024-1,16*1024-1,32*1024-1};
            if(mask[cnt]==0)addr= 32*1024+((addr-0x03800000)&(64*1024-1));
            else            addr=(addr&mask[cnt])+offset[cnt];
          }else addr= 32*1024+((addr-0x03800000)&(64*1024-1));
        }
        *ret = nds_apply_mem_op(nds->mem.wram, addr, data, transaction_type); 
        nds->mem.openbus_word=*ret;
      }
      break;
    case 0x4: 
        if(addr >=0x04100000&&addr <0x04200000){addr|=NDS_IO_MAP_041_OFFSET;}
        nds_preprocess_mmio_read(nds,addr,transaction_type);
        int baddr =addr;
        if(transaction_type&NDS_MEM_ARM7&& addr >=NDS_IO_MAP_SPLIT_ADDRESS){baddr|=NDS_IO_MAP_SPLIT_OFFSET;}
        baddr&=0xffff;
        *ret = nds_apply_mem_op(nds->mem.io, baddr, data, transaction_type); 
        nds->mem.openbus_word=*ret;
        if(transaction_type&NDS_MEM_WRITE)nds_postprocess_mmio_write(nds,addr,data,transaction_type);
      break;
    case 0x5: //Palette 
      addr&=2*1024-1;
      *ret = nds_apply_mem_op(nds->mem.palette, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
    case 0x6: //VRAM(NDS9) WRAM(NDS7)
      *ret = nds_apply_vram_mem_op(nds, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
    case 0x7: 
      addr&=2*1024-1;
      *ret = nds_apply_mem_op(nds->mem.oam, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
    case 0x8:
    case 0x9:
    case 0xA:
    case 0xB:
    case 0xC:
    case 0xD:
    case 0xE: 
    case 0xF: break;
    case 0xFF: 
      if(addr>=0xFFFF0000&& (transaction_type& NDS_MEM_ARM9)){
        addr&=4*1024-1;
        *ret = nds_apply_mem_op(nds->mem.nds9_bios, addr, data, transaction_type&~NDS_MEM_WRITE); 
      }
      break;
  }
  return *ret; 
}
/* Only simulates a small subset of the RTC needed to make time events work in the pokemon games. */
//static FORCE_INLINE void nds_process_rtc_state_machine(nds_t* nds){
//  uint32_t data = nds->cart.gpio_data;
//  bool clk  = SB_BFE(data,0,1);
//  bool io_dat = SB_BFE(data,1,1);
//  bool cs   = SB_BFE(data,2,1);
//  #define SERIAL_INIT 0 
//  #define SERIAL_CLK_LOW 1
//  #define SERIAL_CLK_HIGH 2  //

//  #define RTC_RECV_CMD -1
//  #define RTC_RESET     0
//  #define RTC_STATUS    1
//  #define RTC_DATE_TIME 2    
//  #define RTC_TIME      3//

//  nds->rtc.status_register &= ~((1<<7));
//  nds->rtc.status_register |= 0x40;//

//  if(cs==0){
//    nds->rtc.serial_state=SERIAL_INIT;
//    nds->rtc.serial_bits_clocked=0;
//    nds->rtc.state = RTC_RECV_CMD;
//  }//

//  if(cs!=0){
//    bool new_bit = false; 
//    
//    if(nds->rtc.serial_state==SERIAL_CLK_LOW&&clk){
//      nds->rtc.input_register<<=1;
//      nds->rtc.input_register|=((uint64_t)io_dat);
//      new_bit = true;
//    
//      bool out_bit = (nds->rtc.output_register&1);
//      nds->mem.cart_rom[0x0000C4] = (nds->cart.gpio_data&~2)|(out_bit<<1);
//      nds->rtc.output_register>>=1;
//    }
//    
//    nds->rtc.serial_state= clk? SERIAL_CLK_HIGH: SERIAL_CLK_LOW;//

//    if(new_bit){
//      nds->rtc.serial_bits_clocked++;
//      if(nds->rtc.serial_bits_clocked==8) nds->rtc.state= SB_BFE(nds->rtc.input_register,0,4);
//      int  cmd = SB_BFE(nds->rtc.state,1,3);
//      bool read = SB_BFE(nds->rtc.state,0,1);
//      switch(cmd){
//        case RTC_RECV_CMD:break;
//        case RTC_STATUS:{
//          if(nds->rtc.serial_bits_clocked==8) nds->rtc.output_register = nds->rtc.status_register;
//          if(nds->rtc.serial_bits_clocked==16){
//            if(!read)nds->rtc.status_register=SB_BFE(nds->rtc.input_register,0,8);
//            nds->rtc.state= RTC_RECV_CMD;
//            nds->rtc.serial_bits_clocked=0;
//          }
//          break;
//        }
//        case RTC_DATE_TIME:{
//          if(nds->rtc.serial_bits_clocked==8) nds->rtc.output_register =
//            ((uint64_t)(nds->rtc.year&0xff)       <<(0*8))|
//            ((uint64_t)(nds->rtc.month&0xff)      <<(1*8))|
//            ((uint64_t)(nds->rtc.day&0xff)        <<(2*8))|
//            ((uint64_t)(nds->rtc.day_of_week&0xff)<<(3*8))|
//            ((uint64_t)(nds->rtc.hour&0xff)       <<(4*8))|
//            ((uint64_t)(nds->rtc.minute&0xff)     <<(5*8))|
//            ((uint64_t)(nds->rtc.second&0xff)     <<(6*8));
//          if(nds->rtc.serial_bits_clocked==8*8){
//            if(!read){
//              nds->rtc.year  = SB_BFE(nds->rtc.input_register,6*8,8);
//              nds->rtc.month = SB_BFE(nds->rtc.input_register,5*8,8);
//              nds->rtc.day   = SB_BFE(nds->rtc.input_register,4*8,8);
//              nds->rtc.day_of_week = SB_BFE(nds->rtc.input_register,3*8,8);
//              nds->rtc.hour   = SB_BFE(nds->rtc.input_register,2*8,8);
//              nds->rtc.minute = SB_BFE(nds->rtc.input_register,1*8,8);
//              nds->rtc.second = SB_BFE(nds->rtc.input_register,0*8,8);
//            }
//            nds->rtc.state= RTC_RECV_CMD;
//            nds->rtc.serial_bits_clocked=0;
//          }
//          break;
//        }
//        case RTC_TIME:{
//          if(nds->rtc.serial_bits_clocked==8) nds->rtc.output_register = 
//            ((uint64_t)(nds->rtc.hour&0xff)<<(0*8))|
//            ((uint64_t)(nds->rtc.minute&0xff)<<(1*8))|
//            ((uint64_t)(nds->rtc.second&0xff)<<(2*8));
//          if(nds->rtc.serial_bits_clocked==4*8){
//            if(!read){
//              nds->rtc.hour   = SB_BFE(nds->rtc.input_register,0*8,8);
//              nds->rtc.minute = SB_BFE(nds->rtc.input_register,1*8,8);
//              nds->rtc.second = SB_BFE(nds->rtc.input_register,2*8,8);
//            }
//            nds->rtc.state= RTC_RECV_CMD;
//            nds->rtc.serial_bits_clocked=0;
//          }
//          break;
//        }
//      }
//    }
//  }
//}
//static FORCE_INLINE void nds_process_backup_write(nds_t*nds, unsigned baddr, uint32_t data){
//  if(nds->cart.backup_type==GBA_BACKUP_FLASH_64K||nds->cart.backup_type==GBA_BACKUP_FLASH_128K){
//    nds_process_flash_state_machine(nds,baddr,data);
//  }else if(nds->cart.backup_type==GBA_BACKUP_SRAM){
//    if(nds->mem.cart_backup[baddr&0x7fff]!=(data&0xff)){
//      nds->mem.cart_backup[baddr&0x7fff]=data&0xff; 
//      nds->cart.backup_is_dirty=true;
//    }
//  }
//}
static FORCE_INLINE void nds9_write32(nds_t*nds, unsigned baddr, uint32_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_4B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write32(nds_t*nds, unsigned baddr, uint32_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_4B|NDS_MEM_ARM7);
}
static FORCE_INLINE void nds9_write16(nds_t*nds, unsigned baddr, uint16_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_2B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write16(nds_t*nds, unsigned baddr, uint16_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_2B|NDS_MEM_ARM7);
}
static FORCE_INLINE void nds9_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM7);
}


static FORCE_INLINE uint32_t nds9_read32(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_4B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint32_t nds7_read32(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_4B|NDS_MEM_ARM7);
}
static FORCE_INLINE uint16_t nds9_read16(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_2B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint16_t nds7_read16(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_2B|NDS_MEM_ARM7);
}
static FORCE_INLINE uint8_t nds9_read8(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint8_t nds7_read8(nds_t*nds, unsigned baddr){
  return nds_process_memory_transaction(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM7);
}

uint32_t nds9_arm_read32(void* user_data, uint32_t address){return nds9_read32((nds_t*)user_data,address);}
uint32_t nds9_arm_read16(void* user_data, uint32_t address){return nds9_read16((nds_t*)user_data,address);}
uint32_t nds9_arm_read32_seq(void* user_data, uint32_t address,bool is_sequential){return nds9_read32((nds_t*)user_data,address);}
uint32_t nds9_arm_read16_seq(void* user_data, uint32_t address,bool is_sequential){return nds9_read16((nds_t*)user_data,address);}
uint8_t nds9_arm_read8(void* user_data, uint32_t address){return nds9_read8((nds_t*)user_data,address);}
void nds9_arm_write32(void* user_data, uint32_t address, uint32_t data){nds9_write32((nds_t*)user_data,address,data);}
void nds9_arm_write16(void* user_data, uint32_t address, uint16_t data){nds9_write16((nds_t*)user_data,address,data);}
void nds9_arm_write8(void* user_data, uint32_t address, uint8_t data){nds9_write8((nds_t*)user_data,address,data);}

uint32_t nds7_arm_read32(void* user_data, uint32_t address){return nds7_read32((nds_t*)user_data,address);}
uint32_t nds7_arm_read16(void* user_data, uint32_t address){return nds7_read16((nds_t*)user_data,address);}
uint32_t nds7_arm_read32_seq(void* user_data, uint32_t address,bool is_sequential){return nds7_read32((nds_t*)user_data,address);}
uint32_t nds7_arm_read16_seq(void* user_data, uint32_t address,bool is_sequential){return nds7_read16((nds_t*)user_data,address);}
uint8_t nds7_arm_read8(void* user_data, uint32_t address){return nds7_read8((nds_t*)user_data,address);}
void nds7_arm_write32(void* user_data, uint32_t address, uint32_t data){nds7_write32((nds_t*)user_data,address,data);}
void nds7_arm_write16(void* user_data, uint32_t address, uint16_t data){nds7_write16((nds_t*)user_data,address,data);}
void nds7_arm_write8(void* user_data, uint32_t address, uint8_t data){nds7_write8((nds_t*)user_data,address,data);}

static FORCE_INLINE void nds_recompute_waitstate_table(nds_t* nds,uint16_t waitcnt){
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
    nds->mem.wait_state_table[i]=wait_state_table[i];
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

      nds->mem.wait_state_table[(0x08+i+ws*2)*4+0] = wait16b;
      nds->mem.wait_state_table[(0x08+i+ws*2)*4+1] = wait16b_nonseq;
      nds->mem.wait_state_table[(0x08+i+ws*2)*4+2] = wait32b;
      nds->mem.wait_state_table[(0x08+i+ws*2)*4+3] = wait32b_nonseq;
    }
  }
  nds->mem.prefetch_en = prefetch_en;
  nds->mem.prefetch_size = 0;

  //SRAM
  nds->mem.wait_state_table[(0x0E*4)+0]= 1+primary_table[sram_wait];
  nds->mem.wait_state_table[(0x0E*4)+1]= 1+primary_table[sram_wait];
  nds->mem.wait_state_table[(0x0E*4)+2]= 1+primary_table[sram_wait];
  nds->mem.wait_state_table[(0x0E*4)+3]= 1+primary_table[sram_wait];
  waitcnt&=(1<<15); // Force cartridge to report as GBA cart
  nds9_io_store16(nds,GBA_WAITCNT,waitcnt);
}
static FORCE_INLINE void nds_compute_access_cycles(nds_t *nds, uint32_t address,int request_size/*0: 1B,1: 2B,3: 4B*/){
//  int bank = SB_BFE(address,24,4);
//  bool prefetch_en= nds->mem.prefetch_en;
//  if(!prefetch_en){
//    if(nds->cpu.i_cycles)request_size|=1;
//    if(request_size&1)nds->cpu.next_fetch_sequential =false;
//    nds->mem.prefetch_size = 0;
//  }
//  uint32_t wait = nds->mem.wait_state_table[bank*4+request_size];
//  if(prefetch_en){        
//    nds->mem.prefetch_size+=nds->cpu.i_cycles;
//    if(bank>=0x08&&bank<=0x0D){
//      if((request_size&1)){
//        //Non sequential->reset prefetch buffer
//        nds->mem.prefetch_size = 0;
//        // Check if the bubble made it to the execute stage before being squashed, 
//        // and apply the bubble cycle if it was not squashed. 
//        // Note, only a single pipeline bubble is tracked using this infrastructure. 
//        if(nds->mem.pipeline_bubble_shift_register){
//          wait+=1;
//          nds->mem.pipeline_bubble_shift_register=0;
//        }
//        nds->cpu.next_fetch_sequential =false;
//      }else{
//        nds->mem.pipeline_bubble_shift_register>>=wait;
//        //Sequential fetch from prefetch buffer based on available wait states
//        if(nds->mem.prefetch_size>=wait){
//          nds->mem.prefetch_size-=wait-1; 
//          wait = 1; 
//        }else{
//          wait -= nds->mem.prefetch_size;
//          nds->mem.prefetch_size=0;
//        }
//      }
//    }else {
//      nds->mem.pipeline_bubble_shift_register=((bank==0x03||bank==0x07||bank<=0x01)&& (request_size&1))*4; 
//      nds->mem.prefetch_size+=wait; 
//    }
//  }
  uint32_t wait = 1; 
  //wait+=nds->cpu.i_cycles;
  //nds->cpu.i_cycles=0;
  nds->mem.requests+=wait;
}
static FORCE_INLINE uint32_t nds_compute_access_cycles_dma(nds_t *nds, uint32_t address,int request_size/*0: 1B,1: 2B,3: 4B*/){
  int bank = SB_BFE(address,24,4);
  uint32_t wait = nds->mem.wait_state_table[bank*4+request_size];
  return wait;
}


// Try to load a GBA rom, return false on invalid rom
bool nds_load_rom(nds_t* nds, const char * filename, const char* save_file);
void nds_reset(nds_t*nds);
 
static void nds_recompute_mmio_mask_table(nds_t* nds){
//  for(int io_reg = 0; io_reg<256;io_reg++){
//    uint32_t dword_address = 0x04000000+io_reg*4;
//    uint32_t data_mask =0xffffffff;
//    bool valid = true;
//    if(dword_address==0x4000008)data_mask&=0xdfffdfff;
//    else if(dword_address==0x4000048)data_mask &= 0x3f3f3f3f;
//    else if(dword_address==0x4000050)data_mask &= 0x1F1F3FFF;
//    else if(dword_address==0x4000060)data_mask &= 0xFFC0007F;
//    else if(dword_address==0x4000064||dword_address==0x400006C||dword_address==0x4000074)data_mask &= 0x4000;
//    else if(dword_address==0x4000068)data_mask &= 0xFFC0;
//    else if(dword_address==0x4000070)data_mask &= 0xE00000E0;
//    else if(dword_address==0x4000078)data_mask &= 0xff00;
//    else if(dword_address==0x400007C)data_mask &= 0x40FF;
//    else if(dword_address==0x4000080)data_mask &= 0x770FFF77;
//    else if(dword_address==0x4000084)data_mask &= 0x0080;
//    else if(dword_address==0x4000088)data_mask = 0x0000ffff;
//    else if(dword_address==0x40000B8||dword_address==0x40000C4||dword_address==0x40000D0)data_mask&=0xf7e00000;
//    else if(dword_address==0x40000DC)data_mask&=0xFFE00000; 
//    else if((dword_address>=0x4000010&& dword_address<=0x4000046) ||
//            (dword_address==0x400004C) ||
//            (dword_address>=0x4000054&& dword_address<=0x400005E)||
//            (dword_address==0x400008C)||
//            (dword_address>=0x40000A0&&dword_address<=0x40000B6)||
//            (dword_address>=0x40000BC&&dword_address<=0x40000C2)||
//            (dword_address>=0x40000C8&&dword_address<=0x40000CE)||
//            (dword_address>=0x40000D4&&dword_address<=0x40000DA)||
//            (dword_address>=0x40000E0&&dword_address<=0x40000FE)||
//            (dword_address==0x400100C))valid = false;
//    nds->mem.mmio_data_mask_lookup[io_reg]=data_mask;
//    nds->mem.mmio_reg_valid_lookup[io_reg]=valid;
//  }
}

static FORCE_INLINE void nds_process_mmio_read(nds_t *nds, uint32_t address){
  // Force recomputing timers on timer read
  if(address>= GBA_TM0CNT_L&&address<=GBA_TM3CNT_H)nds_compute_timers(nds);
}

int nds_search_rom_for_backup_string(nds_t* nds){
//  for(int b = 0; b< nds->cart.rom_size;++b){
//    const char* strings[]={"EEPROM_", "SRAM_", "FLASH_","FLASH512_","FLASH1M_"};
//    int backup_type[]= {GBA_BACKUP_EEPROM,GBA_BACKUP_SRAM,GBA_BACKUP_FLASH_64K, GBA_BACKUP_FLASH_64K, GBA_BACKUP_FLASH_128K};
//    for(int type = 0; type<sizeof(strings)/sizeof(strings[0]);++type){
//      int str_off = 0; 
//      bool matches = true; 
//      const char* str = strings[type];
//      while(str[str_off] && matches){
//        if(str[str_off]!=nds->mem.cart_rom[b+str_off])matches = false;
//        if(b+str_off>=nds->cart.rom_size)matches=false; 
//        ++str_off;
//      }
//      if(matches)return backup_type[type];
//    }
//  }
  return GBA_BACKUP_NONE; 
}
bool nds_load_rom(nds_t* nds, const char* filename, const char* save_file){

  if(!sb_path_has_file_ext(filename, ".nds")){
    return false; 
  }
  size_t bytes = 0;                                                       
  uint8_t *data = sb_load_file_data(filename, &bytes);
  if(bytes>512*1024*1024){
    printf("ROMs with sizes >512MB (%zu bytes) are too big for the NDS\n",bytes); 
    return false;
  }  
  if(bytes<1024){
    printf("ROMs with sizes <1024B (%zu bytes) are too small for the NDS\n",bytes); 
    return false;
  }

  strncpy(nds->save_file_path,save_file,SB_FILE_PATH_SIZE);
  nds->save_file_path[SB_FILE_PATH_SIZE-1]=0;

  nds_reset(nds);
  memcpy(&nds->card,data,sizeof(nds_card_t));
  nds->card.title[11]=0;
  nds->mem.card_data=data;
  nds->mem.card_size = bytes;
  
//  nds->cart.backup_type = nds_search_rom_for_backup_string(nds);
//
//  data = sb_load_file_data(save_file,&bytes);
//  if(data){
//    printf("Loaded save file: %s, bytes: %zu\n",save_file,bytes);
//    if(bytes>=128*1024)bytes=128*1024;
//    memcpy(nds->mem.cart_backup, data, bytes);
//    sb_free_file_data(data);
//  }else{
//    printf("Could not find save file: %s\n",save_file);
//    for(int i=0;i<sizeof(nds->mem.cart_backup);++i) nds->mem.cart_backup[i]=0;
//  }
//
//  // Setup flash chip id (this is not used if the cartridge does not have flash backup storage)
//  nds->mem.flash_chip_id[1]=0x13;
//  nds->mem.flash_chip_id[0]=0x62;
  return true; 
}  
static void nds_unload(nds_t* nds){
  if(nds->arm7.log_cmp_file){fclose(nds->arm7.log_cmp_file);nds->arm7.log_cmp_file=NULL;};
  if(nds->arm9.log_cmp_file){fclose(nds->arm9.log_cmp_file);nds->arm9.log_cmp_file=NULL;};
  printf("Unloading DS data\n");
  sb_free_file_data(nds->mem.card_data);
}
uint32_t nds_sqrt_u64(uint64_t value){
  uint32_t res = 0;
  for(uint64_t b=0;b<32;++b){
    uint64_t test = res | (1ull<<(31-b));
    if(test*test<=value)res = test;
  }
  return res; 
}
    
static void nds_preprocess_mmio_read(nds_t * nds, uint32_t addr, int transaction_type){
  if(addr>= GBA_TM0CNT_L&&addr<=GBA_TM3CNT_H)nds_compute_timers(nds);
  int cpu = (transaction_type&NDS_MEM_ARM9)? NDS_ARM9: NDS_ARM7;
 
  switch(addr){
    case NDS7_VRAMSTAT:{
      if(cpu==NDS_ARM9)return;
      uint8_t vramcntc = nds9_io_read8(nds,NDS9_VRAMCNT_C);
      uint8_t vramcntd = nds9_io_read8(nds,NDS9_VRAMCNT_D);
      bool en_c = SB_BFE(vramcntc,7,1);
      bool en_d = SB_BFE(vramcntd,7,1);
      int mst_c = SB_BFE(vramcntc,0,3);
      int mst_d = SB_BFE(vramcntd,0,3);
      bool mapped_c = en_c&& mst_c==2;
      bool mapped_d = en_d&& mst_d==2;
      uint8_t vramstat = mapped_c|(mapped_d<<1);
      nds7_io_store8(nds,NDS7_VRAMSTAT,vramstat);

    }break;
    case NDS_IPCSYNC:{
      uint32_t sync =nds_io_read16(nds,cpu,NDS_IPCSYNC);
      sync&=0x4f00;
      sync|=nds->ipc[cpu].sync_data;
      nds_io_store16(nds,cpu,NDS_IPCSYNC,sync);
    }break;
    case NDS_IPCFIFOCNT:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS9_IPCFIFOCNT);
      int send_size = (nds->ipc[!cpu].write_ptr-nds->ipc[!cpu].read_ptr)&0x1f;
      int recv_size = (nds->ipc[ cpu].write_ptr-nds->ipc[ cpu].read_ptr)&0x1f;

      bool send_fifo_empty = send_size ==0;
      bool send_fifo_full  = send_size ==16;
      bool recv_fifo_empty = recv_size ==0;
      bool recv_fifo_full  = recv_size ==16;
      cnt &=0xbc0c;
      cnt |= (send_fifo_empty<<0)|(send_fifo_full<<1)|(recv_fifo_empty<<8)|(recv_fifo_full<<9);
      cnt |= (nds->ipc[cpu].error<<14);
      nds_io_store16(nds,cpu,NDS_IPCFIFOCNT,cnt);
    }break;
    case NDS_IPCFIFORECV:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS9_IPCFIFOCNT);
      bool enabled = SB_BFE(cnt,15,1);
      if(!enabled)return; 

      int size = (nds->ipc[cpu].write_ptr-nds->ipc[cpu].read_ptr)&0x1f;
      // Read empty error
      if(size==0){
        nds->ipc[cpu].error=true;
        return; 
      }
      uint32_t data = nds->ipc[cpu].fifo[(nds->ipc[cpu].read_ptr++)&0xf];
      nds_io_store32(nds,cpu,NDS_IPCFIFORECV,data);
      if(size==1){
        int other_cnt = nds_io_read16(nds,!cpu,NDS9_IPCFIFOCNT);
        bool fifo_empty_irq = SB_BFE(other_cnt,2,1);
        if(fifo_empty_irq){
          if(cpu==NDS_ARM7)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
          else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
        }
      }
    }break;
    case NDS9_DIVCNT:case NDS9_DIV_RESULT: case NDS9_DIVREM_RESULT:case NDS9_DIV_RESULT+4: case NDS9_DIVREM_RESULT+4:{
      uint32_t cnt = nds9_io_read32(nds,NDS9_DIVCNT);
      int mode = SB_BFE(cnt,0,2);
      int64_t numer = nds9_io_read32(nds,NDS9_DIV_NUMER+4);
      numer<<=32ll;
      numer|= nds9_io_read32(nds,NDS9_DIV_NUMER);
      bool busy= true; 

      int64_t denom = nds9_io_read32(nds,NDS9_DIV_DENOM+4);
      denom<<=32ll;
      denom|= nds9_io_read32(nds,NDS9_DIV_DENOM);
      bool div_zero = denom==0; 
      int64_t result = 0; 
      int64_t mod_result = 0;
      switch(mode){
        case 0:{
          busy = nds->current_clock-nds->math.div_last_update_clock <= 18; 
          numer = (int32_t)numer;
          denom = (int32_t)denom;
          break; 
        }
        case 1: case 3:{
          busy = nds->current_clock-nds->math.div_last_update_clock <= 34; 
          numer = (int64_t)numer;
          denom = (int32_t)denom;
          break; 
        }
        case 2: {
          busy = nds->current_clock-nds->math.div_last_update_clock <= 34; 
          numer = (int64_t)numer;
          denom = (int64_t)denom;
          break; 
        }
      }
      result = (numer)/(denom);
      mod_result = (numer)%(denom);
      if(denom==0){
        mod_result = numer;
        result = numer>-1?-1:1;
        if(mode==0)result^=0xffffffff00000000ull;
      }
      cnt&=3;
      cnt|= (busy<<15)|(div_zero<<14);
      nds9_io_store32(nds,NDS9_DIVCNT,cnt);
      if(!busy){
        nds9_io_store32(nds,NDS9_DIV_RESULT,SB_BFE(result,0,32));
        nds9_io_store32(nds,NDS9_DIV_RESULT+4,SB_BFE(result,32,32));
        nds9_io_store32(nds,NDS9_DIVREM_RESULT,SB_BFE(mod_result,0,32));
        nds9_io_store32(nds,NDS9_DIVREM_RESULT+4,SB_BFE(mod_result,32,32));
      }
    }break;
    case NDS9_SQRTCNT:case NDS9_SQRT_RESULT:case NDS9_SQRT_RESULT+4:{
      uint32_t cnt = nds9_io_read32(nds,NDS9_SQRTCNT);
      int mode = SB_BFE(cnt,0,1);
      int64_t numer = nds9_io_read32(nds,NDS9_SQRT_PARAM+4);
      numer<<=32ll;
      numer|= nds9_io_read32(nds,NDS9_SQRT_PARAM);
      bool busy= nds->current_clock-nds->math.sqrt_last_update_clock<=13; 
      uint64_t result = 0; 
      switch(mode){
        case 0:result = nds_sqrt_u64((uint32_t)numer);break;
        case 1:result = nds_sqrt_u64(numer);break;
      }
      cnt&=1;
      cnt|= (busy<<15);
      nds9_io_store32(nds,NDS9_SQRTCNT,cnt);
      if(!busy){
        nds9_io_store32(nds,NDS9_SQRT_RESULT,SB_BFE(result,0,32));
      }
    }break;
  }
}
static FORCE_INLINE uint32_t nds_align_data(uint32_t addr, uint32_t data, int transaction_type){
  if(transaction_type&NDS_MEM_2B)data= (data&0xffff)<<((addr&3)*8);
  if(transaction_type&NDS_MEM_1B)data= (data&0xff)<<((addr&3)*8);
  return data; 
}
static void nds_postprocess_mmio_write(nds_t * nds, uint32_t baddr, uint32_t data,int transaction_type){
  uint32_t addr=baddr&~3;
  uint32_t mmio= (transaction_type&NDS_MEM_ARM9)? nds9_io_read32(nds,addr): nds7_io_read32(nds,addr);
  int cpu = (transaction_type&NDS_MEM_ARM9)? NDS_ARM9: NDS_ARM7; 
  switch(addr){
    case NDS9_IF: /*case NDS7_IF: <- duplicate address*/ 
      data = nds_align_data(baddr,data,transaction_type);
      mmio&=~data;
      nds_io_store32(nds,cpu,addr,mmio);
      break;
    case NDS_IPCSYNC:{
      int data_out = SB_BFE(mmio,8,4);
      bool send_irq = SB_BFE(mmio,13,1);
      nds->ipc[!cpu].sync_data = data_out;
      uint32_t sync =nds_io_read16(nds,!cpu,NDS_IPCSYNC);
      bool recv_interrupt = SB_BFE(sync,14,1);
      if(send_irq && recv_interrupt){
        if(cpu==NDS_ARM7)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_SYNC);
        else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_SYNC);
      }
      mmio&=0x4f0f;
      nds_io_store32(nds,cpu,addr,mmio);
    }break;
    case NDS_IPCFIFOSEND:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS9_IPCFIFOCNT);
      bool enabled = SB_BFE(cnt,15,1);
      if(!enabled)return; 

      int size = (nds->ipc[!cpu].write_ptr-nds->ipc[!cpu].read_ptr)&0x1f;
      // Send full error
      if(size>=16){
        nds->ipc[cpu].error=true;
        return; 
      }
      nds->ipc[!cpu].fifo[(nds->ipc[!cpu].write_ptr++)&0xf] = mmio; 
      if(size==0){
        int other_cnt = nds_io_read16(nds,!cpu,NDS9_IPCFIFOCNT);
        bool fifo_not_empty_irq = SB_BFE(other_cnt,10,1);
        if(fifo_not_empty_irq){
          if(cpu==NDS_ARM7)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
          else         nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
        }
      }
    }break;
    case NDS_IPCFIFOCNT:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS9_IPCFIFOCNT);
      bool clear = SB_BFE(cnt,3,1);
      if(clear){
        nds->ipc[!cpu].write_ptr=nds->ipc[!cpu].read_ptr=0;
        nds->ipc[cpu].error=false;
        cnt&=~(1<<3);
      }
      bool error = SB_BFE(cnt,14,1);
      //Storing a 1 in the error bit clears it(rockwrestler) 
      if(error)nds->ipc[cpu].error=false;
      nds_io_store16(nds,cpu,NDS_IPCFIFOCNT,cnt);
    }break;
    case NDS9_VRAMCNT_E:{
      if(cpu==NDS_ARM9){
        nds7_io_store8(nds,NDS7_WRAMSTAT,SB_BFE(mmio,24,8));
      }
    }break;
    case NDS9_DIVCNT:case NDS9_DIV_DENOM:case NDS9_DIV_DENOM+4:case NDS9_DIV_NUMER:case NDS9_DIV_NUMER+4:
      nds->math.div_last_update_clock= nds->current_clock;
      break;

    case NDS9_SQRTCNT:case NDS9_SQRT_PARAM:case NDS9_SQRT_PARAM+4:
      nds->math.sqrt_last_update_clock= nds->current_clock;
      break;
  }
}

static FORCE_INLINE void nds_tick_ppu(nds_t* nds, int ppu_id, bool render){
  nds_ppu_t * ppu = nds->ppu+ppu_id;
  ppu->scan_clock+=1;
  if(ppu->scan_clock%6)return;
  int clocks_per_frame = 355*263*6;
  if(ppu->scan_clock>=clocks_per_frame)ppu->scan_clock-=clocks_per_frame;

  int reg_offset = ppu_id==0? 0: 0x00001000;

  int clocks_per_line = 355*6;
  int lcd_y = (ppu->scan_clock+44)/clocks_per_line;
  int lcd_x = ((ppu->scan_clock)%clocks_per_line)/6;
  if(lcd_x==0||lcd_x==NDS_LCD_W||lcd_x==296||true){
    uint16_t disp_stat = nds9_io_read16(nds, GBA_DISPSTAT|reg_offset)&~0x7;
    uint16_t vcount_cmp = SB_BFE(disp_stat,8,8);
    bool vblank = lcd_y>=NDS_LCD_H&&lcd_y<227;
    bool hblank = lcd_x>=NDS_LCD_W&&lcd_x< 296;
    disp_stat |= vblank ? 0x1: 0; 
    disp_stat |= hblank ? 0x2: 0;      
    disp_stat |= lcd_y==vcount_cmp ? 0x4: 0;   
    nds9_io_store16(nds,GBA_VCOUNT,lcd_y);   
    nds9_io_store16(nds,GBA_DISPSTAT|reg_offset,disp_stat);
    uint32_t new_if = 0;
    if(hblank!=ppu->last_hblank){
      ppu->last_hblank = hblank;
      bool hblank_irq_en = SB_BFE(disp_stat,4,1);
      if(hblank&&hblank_irq_en) new_if|= (1<< GBA_INT_LCD_HBLANK); 
      nds->activate_dmas=true;
      if(!hblank){
        ppu->dispcnt_pipeline[0]=ppu->dispcnt_pipeline[1];
        ppu->dispcnt_pipeline[1]=ppu->dispcnt_pipeline[2];
        ppu->dispcnt_pipeline[2]=nds9_io_read16(nds, GBA_DISPCNT+reg_offset);
      }else{
        uint16_t dispcnt = ppu->dispcnt_pipeline[0];

        int bg_mode = SB_BFE(dispcnt,0,3);

        // From Mirei: Affine registers are only incremented when bg_mode is not 0
        // and the bg is enabled.
        if(bg_mode!=0){
          for(int aff=0;aff<2;++aff){
            bool bg_en = SB_BFE(dispcnt,8+aff+2,1);
            if(!bg_en)continue;
            int32_t b = (int16_t)nds9_io_read16(nds,GBA_BG2PB+(aff)*0x10+reg_offset);
            int32_t d = (int16_t)nds9_io_read16(nds,GBA_BG2PD+(aff)*0x10+reg_offset);
            uint16_t bgcnt = nds9_io_read16(nds, GBA_BG2CNT+aff*2+reg_offset);
            bool mosaic = SB_BFE(bgcnt,6,1);
            if(mosaic){
              uint16_t mos_reg = nds9_io_read16(nds,GBA_MOSAIC+reg_offset);
              int mos_y = SB_BFE(mos_reg,4,4)+1;
              if((lcd_y%mos_y)==0){
                ppu->aff[aff].internal_bgx+=b*mos_y;
                ppu->aff[aff].internal_bgy+=d*mos_y;
              }
            }else{
              ppu->aff[aff].internal_bgx+=b;
              ppu->aff[aff].internal_bgy+=d;
            }
          }
        }
      }
    }
    if(lcd_y != ppu->last_lcd_y){
      if(vblank!=ppu->last_vblank){
        ppu->last_vblank = vblank;
        bool vblank_irq_en = SB_BFE(disp_stat,3,1);
        if(vblank&&vblank_irq_en) new_if|= (1<< GBA_INT_LCD_VBLANK); 
        nds->activate_dmas=true;
      }
      ppu->last_lcd_y  = lcd_y;
      if(lcd_y==vcount_cmp) {
        bool vcnt_irq_en = SB_BFE(disp_stat,5,1);
        if(vcnt_irq_en)new_if |= (1<<GBA_INT_LCD_VCOUNT);
      }
      //Latch BGX and BGY registers
      if(lcd_y==0){
        for(int aff=0;aff<2;++aff){
          ppu->aff[aff].internal_bgx=nds9_io_read32(nds,GBA_BG2X+(aff)*0x10+reg_offset);
          ppu->aff[aff].internal_bgy=nds9_io_read32(nds,GBA_BG2Y+(aff)*0x10+reg_offset);

          ppu->aff[aff].internal_bgx = SB_BFE(ppu->aff[aff].internal_bgx,0,28);
          ppu->aff[aff].internal_bgy = SB_BFE(ppu->aff[aff].internal_bgy,0,28);

          ppu->aff[aff].internal_bgx = (ppu->aff[aff].internal_bgx<<4)>>4;
          ppu->aff[aff].internal_bgy = (ppu->aff[aff].internal_bgy<<4)>>4;
        }
      }
    }
    nds_send_interrupt(nds,3,new_if);
  }

  if(!render)return; 
  
  uint32_t dispcnt = nds9_io_read32(nds, GBA_DISPCNT+reg_offset);
  int bg_mode = SB_BFE(dispcnt,0,3);
  int obj_vram_map_2d = !SB_BFE(dispcnt,6,1);
  int forced_blank = SB_BFE(dispcnt,7,1);
  if(forced_blank)return;
  bool visible = lcd_x<NDS_LCD_W && lcd_y<NDS_LCD_H;
  //Render sprites over scanline when it completes
  if(lcd_y<NDS_LCD_H && lcd_x == 0){
  
    //Render sprites over scanline when it completes
    uint8_t default_window_control =0x3f;//bitfield [0-3:bg0-bg3 enable 4:obj enable, 5: special effect enable]
    bool winout_enable = SB_BFE(dispcnt,13,3)!=0;
    uint16_t WINOUT = nds9_io_read16(nds, GBA_WINOUT+reg_offset);
    if(winout_enable)default_window_control = SB_BFE(WINOUT,0,8);

    for(int x=0;x<NDS_LCD_W;++x){ppu->window[x] = default_window_control;}
    uint8_t obj_window_control = default_window_control;
    bool obj_window_enable = SB_BFE(dispcnt,15,1);
    if(obj_window_enable)obj_window_control = SB_BFE(WINOUT,8,6);
    bool display_obj = SB_BFE(dispcnt,12,1);
    if(display_obj){
      for(int o=0;o<128;++o){
        uint16_t attr0 = *(uint16_t*)(nds->mem.oam+o*8+0);
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
        uint16_t attr1 = *(uint16_t*)(nds->mem.oam+o*8+2);

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
          if(x_end>=NDS_LCD_W)x_end=NDS_LCD_W;
          //Attr2
          //Skip objects disabled by window
          uint16_t attr2 = *(uint16_t*)(nds->mem.oam+o*8+4);
          int tile_base = SB_BFE(attr2,0,10);
          // Always place sprites as the highest priority
          int priority = SB_BFE(attr2,10,2);
          int palette = SB_BFE(attr2,12,4);
          for(int x = x_start; x< x_end;++x){
            int sx = (x-x_coord);
            int sy = (lcd_y-y_coord)&0xff;
            if(mosaic){
              uint16_t mos_reg = nds9_io_read16(nds,GBA_MOSAIC+reg_offset);
              int mos_x = SB_BFE(mos_reg,8,4)+1;
              int mos_y = SB_BFE(mos_reg,12,4)+1;
              sx = ((x/mos_x)*mos_x-x_coord);
              sy = (((lcd_y/mos_y)*mos_y-y_coord)&0xff);
            }
            if(rot_scale){
              uint32_t param_base = rotscale_param*0x20; 
              int32_t a = *(int16_t*)(nds->mem.oam+param_base+0x6);
              int32_t b = *(int16_t*)(nds->mem.oam+param_base+0xe);
              int32_t c = *(int16_t*)(nds->mem.oam+param_base+0x16);
              int32_t d = *(int16_t*)(nds->mem.oam+param_base+0x1e);
 
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
                    
            int y_tile_stride = obj_vram_map_2d? 32 : x_size/8*(colors_or_palettes? 2:1);
            int tile = tile_base + ((sx/8))*(colors_or_palettes? 2:1)+(sy/8)*y_tile_stride;
            //Tiles >511 are not rendered in bg_mode3-5 since that memory is used to store the bitmap graphics. 
            if(tile<512&&bg_mode>=3&&bg_mode<=5)continue;
            uint8_t palette_id;
            int obj_tile_base = GBA_OBJ_TILES0_2;
            if(colors_or_palettes==false){
              palette_id= nds->mem.vram[obj_tile_base+tile*8*4+tx/2+ty*4];
              palette_id= (palette_id>>((tx&1)*4))&0xf;
              if(palette_id==0)continue;
              palette_id+=palette*16;
            }else{
              palette_id=nds->mem.vram[obj_tile_base+tile*8*4+tx+ty*8];
              if(palette_id==0)continue;
            }

            uint32_t col = *(uint16_t*)(nds->mem.palette+GBA_OBJ_PALETTE+palette_id*2);
            //Handle window objects(not displayed but control the windowing of other things)
            if(obj_mode==2){ppu->window[x]=obj_window_control; 
            }else if(obj_mode!=3){
              int type =4;
              col=col|(type<<17)|((5-priority)<<28)|((0x7)<<25);
              if(obj_mode==1)col|=1<<16;
              if((col>>17)>(ppu->first_target_buffer[x]>>17))ppu->first_target_buffer[x]=col;
            }  
          }
        }
      }
    }
    int enabled_windows = SB_BFE(dispcnt,13,3); // [0: win0, 1:win1, 2: objwin]
    if(enabled_windows){
      for(int win=1;win>=0;--win){
        bool win_enable = SB_BFE(dispcnt,13+win,1);
        if(!win_enable)continue;
        uint16_t WINH = nds9_io_read16(nds, GBA_WIN0H+2*win+reg_offset);
        uint16_t WINV = nds9_io_read16(nds, GBA_WIN0V+2*win+reg_offset);
        int win_xmin = SB_BFE(WINH,8,8);
        int win_xmax = SB_BFE(WINH,0,8);
        int win_ymin = SB_BFE(WINV,8,8);
        int win_ymax = SB_BFE(WINV,0,8);
        // Garbage values of X2>240 or X1>X2 are interpreted as X2=240.
        // Garbage values of Y2>160 or Y1>Y2 are interpreted as Y2=160. 
        if(win_xmin>win_xmax)win_xmax=240;
        if(win_ymin>win_ymax)win_ymax=161;
        if(win_xmax>240)win_xmax=240;
        if(lcd_y<win_ymin||lcd_y>=win_ymax)continue;
        uint16_t winin = nds9_io_read16(nds,GBA_WININ+reg_offset);
        uint8_t win_value = SB_BFE(winin,win*8,6);
        for(int x=win_xmin;x<win_xmax;++x)ppu->window[x] = win_value;
      }
      int backdrop_type = 5;
      uint32_t backdrop_col = (*(uint16_t*)(nds->mem.palette + GBA_BG_PALETTE+0*2))|(backdrop_type<<17);
      for(int x=0;x<240;++x){
        uint8_t window_control = ppu->window[x];
        if(SB_BFE(window_control,4,1)==0)ppu->first_target_buffer[x]=backdrop_col;
      }
    }
  }

  if(visible){
    uint8_t window_control =ppu->window[lcd_x];
    int display_mode = SB_BFE(dispcnt,16,2);
    if(display_mode==2){
      int vram_block = SB_BFE(dispcnt,18,2);
      ppu->first_target_buffer[lcd_x] = ((uint16_t*)nds->mem.vram)[lcd_x+lcd_y*NDS_LCD_W+vram_block*128*1024];
    }else if(display_mode==0){
      ppu->first_target_buffer[lcd_x] = 0xffffffff;
    }else if(bg_mode==6 ||bg_mode==7){
      //Palette 0 is taken as the background
    }else if (bg_mode<=5){     
      for(int bg = 3; bg>=0;--bg){
        uint32_t col =0;         
        if((bg<2&&bg_mode==2)||(bg==3&&bg_mode==1)||(bg!=3&&bg_mode>=3))continue;
        bool bg_en = SB_BFE(dispcnt,8+bg,1)&&SB_BFE(ppu->dispcnt_pipeline[0],8+bg,1);
        if(!bg_en || SB_BFE(window_control,bg,1)==0)continue;

        bool rot_scale = bg_mode>=1&&bg>=2;
        uint16_t bgcnt = nds9_io_read16(nds, GBA_BG0CNT+bg*2+reg_offset);
        int priority = SB_BFE(bgcnt,0,2);
        int character_base = SB_BFE(bgcnt,2,4);
        bool mosaic = SB_BFE(bgcnt,6,1);
        bool colors = SB_BFE(bgcnt,7,1);
        int screen_base = SB_BFE(bgcnt,8,5);
        bool display_overflow =SB_BFE(bgcnt,13,1);
        int screen_size = SB_BFE(bgcnt,14,2);

        int screen_size_x = (screen_size&1)?512:256;
        int screen_size_y = (screen_size>=2)?512:256;
      
        int bg_x = 0;
        int bg_y = 0;
        uint32_t pallete_offset = ppu_id?0x400:0; 
      
        if(rot_scale){
          screen_size_x = screen_size_y = (16*8)<<screen_size;
          if(bg_mode==3||bg_mode==4){
            screen_size_x=240;
            screen_size_y=160;
          }else if(bg_mode==5){
            screen_size_x=256;
            screen_size_y=256;
          }
          colors = true;

          int32_t bgx = ppu->aff[bg-2].internal_bgx;
          int32_t bgy = ppu->aff[bg-2].internal_bgy;

          int32_t a = (int16_t)nds9_io_read16(nds,GBA_BG2PA+(bg-2)*0x10+reg_offset);
          int32_t c = (int16_t)nds9_io_read16(nds,GBA_BG2PC+(bg-2)*0x10+reg_offset);

          // Shift lcd_coords into fixed point
          int64_t x2 = a*lcd_x + (((int64_t)bgx));
          int64_t y2 = c*lcd_x + (((int64_t)bgy));
          if(mosaic){
            int16_t mos_reg = nds9_io_read16(nds,GBA_MOSAIC+reg_offset);
            int mos_x = SB_BFE(mos_reg,0,4)+1;
            x2 = a*((lcd_x/mos_x)*mos_x) + (((int64_t)bgx));
            y2 = c*((lcd_x/mos_x)*mos_x) + (((int64_t)bgy));
          }


          bg_x = (x2>>8);
          bg_y = (y2>>8);

          if(display_overflow==0){
            if(bg_x<0||bg_x>=screen_size_x||bg_y<0||bg_y>=screen_size_y)continue; 
          }else{
            bg_x%=screen_size_x;
            bg_y%=screen_size_y;
          }
        }else{
          int16_t hoff = nds9_io_read16(nds,GBA_BG0HOFS+bg*4+reg_offset);
          int16_t voff = nds9_io_read16(nds,GBA_BG0VOFS+bg*4+reg_offset);
          hoff=(hoff<<7)>>7;
          voff=(voff<<7)>>7;
          bg_x = (hoff+lcd_x);
          bg_y = (voff+lcd_y);
          if(mosaic){
            uint16_t mos_reg = nds9_io_read16(nds,GBA_MOSAIC+reg_offset);
            int mos_x = SB_BFE(mos_reg,0,4)+1;
            int mos_y = SB_BFE(mos_reg,4,4)+1;
            bg_x = hoff+(lcd_x/mos_x)*mos_x;
            bg_y = voff+(lcd_y/mos_y)*mos_y;
          }
        }
        int screen_base_addr    = screen_base*2*1024;

        int32_t bg_base = ppu_id? 0x06200000:0x06000000;
        if(bg_mode==3){
          int p = bg_x+bg_y*240;
          int addr = p*2; 
          col  = nds9_read16(nds,bg_base+screen_base_addr+addr);
        }else if(bg_mode==4){
          int p = bg_x+bg_y*240;
          int frame_sel = SB_BFE(dispcnt,4,1);
          int addr = p*1+0xA000*frame_sel; 
          uint8_t pallete_id = nds->mem.vram[addr];
          if(pallete_id==0)continue;
          col = *(uint16_t*)(nds->mem.palette+pallete_offset+pallete_id*2);
        }else if(bg_mode==5){
          int screen_base_addr = screen_base*16*1024;
          int p = bg_x+bg_y*256;
          int frame_sel = SB_BFE(dispcnt,4,1);
          int addr = p*2+screen_base_addr; 
          col  = nds9_read16(nds,bg_base+addr);
        }else{
          bg_x = bg_x&(screen_size_x-1);
          bg_y = bg_y&(screen_size_y-1);
          int bg_tile_x = bg_x/8;
          int bg_tile_y = bg_y/8;

          int tile_off = bg_tile_y*(screen_size_x/8)+bg_tile_x;

          int character_base_addr = character_base*16*1024;

          //engine A screen base: BGxCNT.bits*2K + DISPCNT.bits*64K
          //engine A char base: BGxCNT.bits*16K + DISPCNT.bits*64K
          if(ppu_id==0){
            character_base+=SB_BFE(dispcnt,24,3)*64*1024;
            screen_base+=SB_BFE(dispcnt,27,3)*64*1024;
          }

          uint16_t tile_data =0;

          int px = bg_x%8;
          int py = bg_y%8;


          if(rot_scale)tile_data=nds9_read8(nds,bg_base+screen_base_addr+tile_off);
          else{
            int tile_off = (bg_tile_y%32)*32+(bg_tile_x%32);
            if(bg_tile_x>=32)tile_off+=32*32;
            if(bg_tile_y>=32)tile_off+=32*32*(screen_size==3?2:1);
            tile_data=nds9_read16(nds,bg_base+screen_base_addr+tile_off*2);
            //printf("tx:%d ty:%d tile_off:%08x data:%08x\n",bg_tile_x,bg_tile_y,bg_base+screen_base_addr+tile_off,tile_data);
            int h_flip = SB_BFE(tile_data,10,1);
            int v_flip = SB_BFE(tile_data,11,1);
            if(h_flip)px=7-px;
            if(v_flip)py=7-py;
          }
          int tile_id = SB_BFE(tile_data,0,10);
          int palette = SB_BFE(tile_data,12,4);

          uint8_t tile_d=tile_id;
          if(colors==false){
            tile_d=nds9_read8(nds,bg_base+character_base_addr+tile_id*8*4+px/2+py*4);
            tile_d= (tile_d>>((px&1)*4))&0xf;
            if(tile_d==0)continue;
            tile_d+=palette*16;
          }else{
            tile_d=nds9_read8(nds,bg_base+character_base_addr+tile_id*8*8+px+py*8);
            if(tile_d==0)continue;
          }
          uint8_t pallete_id = tile_d;
          col = *(uint16_t*)(nds->mem.palette+pallete_offset+pallete_id*2);
        }
        col |= (bg<<17) | ((5-priority)<<28)|((4-bg)<<25);
        if(col>ppu->first_target_buffer[lcd_x]){
          uint32_t t = ppu->first_target_buffer[lcd_x];
          ppu->first_target_buffer[lcd_x]=col;
          col = t;
        }
        if(col>ppu->second_target_buffer[lcd_x])ppu->second_target_buffer[lcd_x]=col;          
      }
    }
    uint32_t col = ppu->first_target_buffer[lcd_x];
    int r = SB_BFE(col,0,5);
    int g = SB_BFE(col,5,5);
    int b = SB_BFE(col,10,5);
    uint32_t type = SB_BFE(col,17,3);

    bool effect_enable = SB_BFE(window_control,5,1);
    uint16_t bldcnt = nds9_io_read16(nds,GBA_BLDCNT+reg_offset);
    int mode = SB_BFE(bldcnt,6,2);

    //Semitransparent objects are always selected for blending
    if(SB_BFE(col,16,1)){
      uint32_t col2 = ppu->second_target_buffer[lcd_x];
      uint32_t type2 = SB_BFE(col2,17,3);
      bool blend = SB_BFE(bldcnt,8+type2,1);
      if(blend){mode=1;effect_enable=true;}
      else effect_enable &= SB_BFE(bldcnt,type,1);
    }else effect_enable &= SB_BFE(bldcnt,type,1);
    if(effect_enable){
      uint16_t bldy = nds9_io_read16(nds,GBA_BLDY+reg_offset);
      float evy = SB_BFE(bldy,0,5)/16.;
      if(evy>1.0)evy=1;
      switch(mode){
        case 0: break; //None
        case 1: {
          uint32_t col2 = ppu->second_target_buffer[lcd_x];
          uint32_t type2 = SB_BFE(col2,17,3);
          bool blend = SB_BFE(bldcnt,8+type2,1);
          if(blend){
            uint16_t bldalpha= nds9_io_read16(nds,GBA_BLDALPHA);
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
    int p = (lcd_x+lcd_y*NDS_LCD_W)*3;
    float screen_blend_factor = 0.7;
    uint8_t *framebuffer = ppu_id==0?nds->framebuffer_top: nds->framebuffer_bottom;
    framebuffer[p+0] = r*7*screen_blend_factor+framebuffer[p+0]*(1.0-screen_blend_factor);
    framebuffer[p+1] = g*7*screen_blend_factor+framebuffer[p+1]*(1.0-screen_blend_factor);
    framebuffer[p+2] = b*7*screen_blend_factor+framebuffer[p+2]*(1.0-screen_blend_factor); 
    int backdrop_type = 5;
    uint32_t backdrop_col = (*(uint16_t*)(nds->mem.palette + GBA_BG_PALETTE+0*2))|(backdrop_type<<17);
    ppu->first_target_buffer[lcd_x] = backdrop_col;
    ppu->second_target_buffer[lcd_x] = backdrop_col;
  }
}
static void nds_tick_keypad(sb_joy_t*joy, nds_t* nds){
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
    nds9_io_store16(nds, GBA_KEYINPUT, reg_value);
  }else reg_value = nds9_io_read16(nds, GBA_KEYINPUT);

  uint16_t keycnt = nds9_io_read16(nds,GBA_KEYCNT);
  bool irq_enable = SB_BFE(keycnt,14,1);
  bool irq_condition = SB_BFE(keycnt,15,1);//[0: any key, 1: all keys]
  int if_bit = 0;
  if(irq_enable){
    uint16_t pressed = SB_BFE(reg_value,0,10)^0x3ff;
    uint16_t mask = SB_BFE(keycnt,0,10);

    if(irq_condition&&((pressed&mask)==mask))if_bit|= 1<<GBA_INT_KEYPAD;
    if(!irq_condition&&((pressed&mask)!=0))if_bit|= 1<<GBA_INT_KEYPAD;

    if(if_bit&&!nds->prev_key_interrupt){
      nds_send_interrupt(nds,4,if_bit);
      nds->prev_key_interrupt = true;
    }else nds->prev_key_interrupt = false;

  }

}
/*uint64_t nds_read_eeprom_bitstream(nds_t *nds, uint32_t source_address, int offset, int size, int elem_size, int dir){
  uint64_t data = 0; 
  for(int i=0;i<size;++i){
    data|= ((uint64_t)(nds_read16(nds,source_address+(i+offset)*elem_size*dir)&1))<<(size-i-1);
  }
  return data; 
}
void nds_store_eeprom_bitstream(nds_t *nds, uint32_t source_address, int offset, int size, int elem_size, int dir,uint64_t data){
  for(int i=0;i<size;++i){
    nds_store16(nds,source_address+(i+offset)*elem_size*dir,data>>(size-i-1)&1);
  }
}*/
static FORCE_INLINE int nds_tick_dma(nds_t*nds, int last_tick){
  int ticks =0;
  nds->activate_dmas=false;
  for(int cpu = 0;cpu<2;++cpu){
    for(int i=0;i<4;++i){
      uint16_t cnt_h=nds_io_read16(nds,cpu, GBA_DMA0CNT_H+12*i);
      bool enable = SB_BFE(cnt_h,15,1);
      if(enable){
        bool type = SB_BFE(cnt_h,10,1); // 0: 16b 1:32b

        if(!nds->dma[cpu][i].last_enable){
          nds->dma[cpu][i].last_enable = enable;
          nds->dma[cpu][i].source_addr=nds_io_read32(nds,cpu,GBA_DMA0SAD+12*i);
          nds->dma[cpu][i].dest_addr=nds_io_read32(nds,cpu,GBA_DMA0DAD+12*i);
          //GBA Suite says that these need to be force aligned
          if(type){
            nds->dma[cpu][i].dest_addr&=~3;
            nds->dma[cpu][i].source_addr&=~3;
          }else{
            nds->dma[cpu][i].dest_addr&=~1;
            nds->dma[cpu][i].source_addr&=~1;
          }
          nds->dma[cpu][i].current_transaction=0;
          nds->dma[cpu][i].startup_delay=0;
        }
        int  dst_addr_ctl = SB_BFE(cnt_h,5,2); // 0: incr 1: decr 2: fixed 3: incr reload
        int  src_addr_ctl = SB_BFE(cnt_h,7,2); // 0: incr 1: decr 2: fixed 3: not allowed
        bool dma_repeat = SB_BFE(cnt_h,9,1); 
        int  mode = SB_BFE(cnt_h,11,3);
        bool irq_enable = SB_BFE(cnt_h,14,1);
        bool force_first_write_sequential = false;
        int transfer_bytes = type? 4:2; 
        bool skip_dma = false;
        if(nds->dma[cpu][i].current_transaction==0){
          if(mode==3 && i ==0)continue;
          if(nds->dma[cpu][i].startup_delay>=0){
            nds->dma[cpu][i].startup_delay-=last_tick; 
            if(nds->dma[cpu][i].startup_delay>=0){
              nds->activate_dmas=true;
              continue;
            }
            nds->dma[cpu][i].startup_delay=-1;
          }
          if(dst_addr_ctl==3){        
            nds->dma[cpu][i].dest_addr=nds_io_read32(nds,cpu,GBA_DMA0DAD+12*i);
          }
          bool last_vblank = nds->dma[cpu][i].last_vblank;
          bool last_hblank = nds->dma[cpu][i].last_hblank;
          nds->dma[cpu][i].last_vblank = nds->ppu[0].last_vblank;
          nds->dma[cpu][i].last_hblank = nds->ppu[0].last_hblank;
          if(mode ==1 && (!nds->ppu[0].last_vblank||last_vblank)) continue; 
          if(mode==2){
            uint16_t vcount = nds_io_read16(nds,cpu,GBA_VCOUNT);
            if(vcount>=160||!nds->ppu[0].last_hblank||last_hblank)continue;
          }
          //Video dma
          if(mode==3 && i ==3){
            uint16_t vcount = nds_io_read16(nds,cpu,GBA_VCOUNT);
            if(!nds->ppu[0].last_hblank||last_hblank)continue;
            //Video dma starts at scanline 2
            if(vcount<2)continue;
            if(vcount==161)dma_repeat=false;
          }
          if(dst_addr_ctl==3){
            nds->dma[cpu][i].dest_addr=nds_io_read32(nds,cpu,GBA_DMA0DAD+12*i);
            //GBA Suite says that these need to be force aligned
            if(type) nds->dma[cpu][i].dest_addr&=~3;
            else nds->dma[cpu][i].dest_addr&=~1;
          }
          if(nds->dma[cpu][i].source_addr>=0x08000000&&nds->dma[cpu][i].dest_addr>=0x08000000){
            force_first_write_sequential=true;
          }else{
            if(nds->dma[cpu][i].dest_addr>=0x08000000){
              // Allow the in process prefetech to finish before starting DMA
              if(!nds->mem.prefetch_size&&nds->mem.prefetch_en)ticks+=nds_compute_access_cycles_dma(nds,nds->dma[cpu][i].dest_addr,2)>4;
            }
          }
          if(nds->dma[cpu][i].source_addr>=0x08000000){
              if(nds->mem.prefetch_en)ticks+=nds_compute_access_cycles_dma(nds,nds->dma[cpu][i].source_addr,2)<=4;
          }
          nds->last_transaction_dma=true;
          uint32_t cnt = nds_io_read16(nds,cpu,GBA_DMA0CNT_L+12*i);

          cnt&=0x1FFFFF;
          if(cnt==0)cnt =0x200000;

          static const uint32_t src_mask[] = { 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
          static const uint32_t dst_mask[] = { 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
          //nds->dma[cpu][i].source_addr&=src_mask[i];
          //nds->dma[cpu][i].dest_addr  &=dst_mask[i];
          nds_io_store16(nds,cpu,GBA_DMA0CNT_L+12*i,cnt);
          printf("DMA[%d][%d]: Src: 0x%08x DST: 0x%08x Cnt:%d mode: %d\n",cpu,i,nds->dma[cpu][i].source_addr,nds->dma[cpu][i].dest_addr,cnt,mode);
        }
        const static int dir_lookup[4]={1,-1,0,1};
        int src_dir = dir_lookup[src_addr_ctl];
        int dst_dir = dir_lookup[dst_addr_ctl];

        uint32_t src = nds->dma[cpu][i].source_addr;
        uint32_t dst = nds->dma[cpu][i].dest_addr;
        uint32_t cnt = nds_io_read16(nds,cpu,GBA_DMA0CNT_L+12*i);

        // ROM ignores direction and always increments
        if(src>=0x08000000&&src<0x0e000000) src_dir=1;
        if(dst>=0x08000000&&dst<0x0e000000) dst_dir=1;

        if(!skip_dma){
          // This code is complicated to handle the per channel DMA latches that are present
          // Correct implementation is needed to pass latch.gba, Pokemon Pinball (intro explosion),
          // and the text in Lufia
          // TODO: There in theory should be separate latches per DMA, but that breaks Hello Kitty
          // and Tomb Raider
          if(nds->dma[cpu][i].current_transaction<cnt){
            int x = nds->dma[cpu][i].current_transaction++;
            int dst_addr = dst+x*transfer_bytes*dst_dir;
            int src_addr = src+x*transfer_bytes*src_dir;
            if(type){
              if(src_addr>=0x02000000){
                if(cpu==NDS_ARM7)nds->dma[cpu][i].latched_transfer = nds7_read32(nds,src_addr);
                else nds->dma[cpu][i].latched_transfer = nds9_read32(nds,src_addr);
                ticks+=nds_compute_access_cycles_dma(nds, src_addr, x!=0? 2:3);
              }
              if(cpu==NDS_ARM7)nds7_write32(nds,dst_addr,nds->dma[cpu][i].latched_transfer);
              else nds9_write32(nds,dst_addr,nds->dma[cpu][i].latched_transfer);
              ticks+=nds_compute_access_cycles_dma(nds, dst_addr, x!=0||force_first_write_sequential? 2:3);
            }else{
              int v = 0;
              if(src_addr>=0x02000000){
                if(cpu==NDS_ARM7)v=nds->dma[cpu][i].latched_transfer = nds7_read16(nds,src_addr)&0xffff;
                else v=nds->dma[cpu][i].latched_transfer = nds9_read16(nds,src_addr)&0xffff;
                nds->dma[cpu][i].latched_transfer |= nds->dma[cpu][i].latched_transfer<<16;
                ticks+=nds_compute_access_cycles_dma(nds, src_addr, x!=0? 0:1);
              }else v = nds->dma[cpu][i].latched_transfer>>(((dst_addr)&0x3)*8);
              if(cpu==NDS_ARM7)nds7_write16(nds,dst_addr,nds->dma[cpu][i].latched_transfer);
              else nds9_write16(nds,dst_addr,nds->dma[cpu][i].latched_transfer);
              ticks+=nds_compute_access_cycles_dma(nds, dst_addr, x!=0||force_first_write_sequential? 0:1);
            }
          }
        }
      //
        if(nds->dma[cpu][i].current_transaction>=cnt){
          if(dst_addr_ctl==0||dst_addr_ctl==3)     dst+=cnt*transfer_bytes;
          else if(dst_addr_ctl==1)dst-=cnt*transfer_bytes;
          if(src_addr_ctl==0)     src+=cnt*transfer_bytes;
          else if(src_addr_ctl==1)src-=cnt*transfer_bytes;
        //
          nds->dma[cpu][i].source_addr=src;
          nds->dma[cpu][i].dest_addr=dst;

          if(irq_enable){
            uint16_t if_bit = 1<<(GBA_INT_DMA0+i);
            if(cpu==NDS_ARM7)nds7_send_interrupt(nds,4,if_bit);
            else if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,if_bit);
          }
          if(!dma_repeat||mode==0){
            cnt_h&=0x7fff;
            //Reload on incr reload     
            enable =false;
            nds_io_store16(nds, cpu, GBA_DMA0CNT_H+12*i,cnt_h);
          }else{
            nds->dma[cpu][i].current_transaction=0;
          }
        }
      }
      nds->dma[cpu][i].last_enable = enable;
      if(ticks)break;
    }
    nds->activate_dmas|=ticks!=0;

    if(nds->last_transaction_dma&&ticks==0){
      ticks+=2; 
      nds->last_transaction_dma=false;
    }
  }
  return ticks; 
}                                              
static FORCE_INLINE void nds_tick_sio(nds_t* nds){
  //Just a stub for now;
  uint16_t siocnt = nds9_io_read16(nds,GBA_SIOCNT);
  bool active = SB_BFE(siocnt,7,1);
  bool irq_enabled = SB_BFE(siocnt,14,1);
  if(active){
   
    if(irq_enabled){
      uint16_t if_bit = 1<<(GBA_INT_SERIAL);
      nds_send_interrupt(nds,4,if_bit);
    }
    siocnt&= ~(1<<7);
    nds9_io_store16(nds,GBA_SIOCNT,siocnt);
  }
}
static FORCE_INLINE void nds_tick_timers(nds_t* nds){
  nds->deferred_timer_ticks+=1;
  if(nds->deferred_timer_ticks>=nds->timer_ticks_before_event)nds_compute_timers(nds); 
}
static void nds_compute_timers(nds_t* nds){

//  int ticks = nds->deferred_timer_ticks; 
//  nds->deferred_timer_ticks=0;
//  int last_timer_overflow = 0; 
//  int timer_ticks_before_event = 32768; 
//  for(int t=0;t<4;++t){ 
//    uint16_t tm_cnt_h = nds_io_read16(nds,GBA_TM0CNT_H+t*4);
//    bool enable = SB_BFE(tm_cnt_h,7,1);
//    if(enable){
//      int compensated_ticks = ticks;
//      uint16_t prescale = SB_BFE(tm_cnt_h,0,2);
//      bool count_up     = SB_BFE(tm_cnt_h,2,1)&&t!=0;
//      bool irq_en       = SB_BFE(tm_cnt_h,6,1);
//      uint16_t value = nds_io_read16(nds,GBA_TM0CNT_L+t*4);
//      if(enable!=nds->timers[t].last_enable&&enable){
//        nds->timers[t].startup_delay=2;
//        value = nds->timers[t].reload_value;
//        nds_io_store16(nds,GBA_TM0CNT_L+t*4,value);
//      }
//      if(nds->timers[t].startup_delay>=0){
//        nds->timers[t].startup_delay-=ticks; 
//        nds->timers[t].last_enable = enable;
//        if(nds->timers[t].startup_delay>=0){
//          if(nds->timers[t].startup_delay<timer_ticks_before_event)timer_ticks_before_event=nds->timers[t].startup_delay;
//          continue;
//        }
//        compensated_ticks=-nds->timers[t].startup_delay;
//        nds->timers[t].startup_delay=-1;
//        nds->timers[t].prescaler_timer=0;
//      }
//
//      if(count_up){
//        if(last_timer_overflow){
//          uint32_t v= value;
//          v+=last_timer_overflow;
//          last_timer_overflow=0;
//          while(v>0xffff){
//            v=(v+nds->timers[t].reload_value)-0x10000;
//            last_timer_overflow++;
//            nds->timers[t].elapsed_audio_samples++;
//          }
//          value=v;
//        }
//      }else{
//        last_timer_overflow=0;
//        int prescale_time = nds->timers[t].prescaler_timer;
//        prescale_time+=compensated_ticks;
//        const int prescaler_lookup[]={0,6,8,10};
//        int prescale_duty = prescaler_lookup[prescale];
//
//        int increment = prescale_time>>prescale_duty;
//        prescale_time = prescale_time&((1<<prescale_duty)-1);
//        int v = value+increment;
//        while(v>0xffff){
//          v=(v+nds->timers[t].reload_value)-0x10000;
//          last_timer_overflow++;
//          nds->timers[t].elapsed_audio_samples++;
//        }
//        value = v; 
//        nds->timers[t].prescaler_timer=prescale_time;
//        int ticks_before_overflow = (int)(0xffff-value)<<(prescale_duty);
//        if(ticks_before_overflow<timer_ticks_before_event)timer_ticks_before_event=ticks_before_overflow;
//      }
//      nds->timers[t].reload_value=nds->timers[t].pending_reload_value;
//      if(last_timer_overflow && irq_en){
//        uint16_t if_bit = 1<<(GBA_INT_TIMER0+t);
//        nds_send_interrupt(nds,4,if_bit);        
//      }
//      nds_io_store16(nds,GBA_TM0CNT_L+t*4,value);
//    }else last_timer_overflow=0;
//    nds->timers[t].last_enable = enable;
//  }
//  nds->timer_ticks_before_event=timer_ticks_before_event;
}
static FORCE_INLINE float nds_compute_vol_env_slope(int length_of_step,int dir){
  float step_time = length_of_step/64.0;
  float slope = 1./step_time;
  if(dir==0)slope*=-1;
  if(length_of_step==0)slope=0;
  return slope/16.;
} 
static FORCE_INLINE float nds_polyblep(float t,float dt){
  if(t<=dt){    
    t = t/dt;
    return t+t-t*t-1.0;;
  }else if (t >= 1-dt){
    t=(t-1.0)/dt;
    return t*t+t+t+1.0;
  }else return 0; 
}
static FORCE_INLINE float nds_bandlimited_square(float t, float duty_cycle,float dt){
  float t2 = t - duty_cycle;
  if(t2< 0.0)t2 +=1.0;
  float y = t < duty_cycle ? -1 : 1;
  y -= nds_polyblep(t,dt);
  y += nds_polyblep(t2,dt);
  return y;
}
static FORCE_INLINE void nds_tick_interrupts(nds_t*nds){
  if(nds->active_if_pipe_stages){
    uint32_t if_bit = nds->nds9_pipelined_if[0];
    if(if_bit){
      uint32_t if_val = nds9_io_read32(nds,NDS9_IF);
      if_val |= if_bit;
      uint32_t ie_val = nds9_io_read32(nds,NDS9_IE);
      uint16_t ime = nds9_io_read16(nds,NDS9_IME); 
      nds9_io_store32(nds,NDS9_IF,if_val);
    }
    if_bit = nds->nds7_pipelined_if[0];
    if(if_bit){
      uint32_t if_val = nds7_io_read32(nds,NDS7_IF);
      uint32_t ie_val = nds7_io_read32(nds,NDS7_IE);
      uint16_t ime = nds7_io_read16(nds,NDS7_IME); 
      if_val |= if_bit;
      nds7_io_store32(nds,NDS7_IF,if_val);
    }
    nds->nds9_pipelined_if[0]=nds->nds9_pipelined_if[1];
    nds->nds9_pipelined_if[1]=nds->nds9_pipelined_if[2];
    nds->nds9_pipelined_if[2]=nds->nds9_pipelined_if[3];
    nds->nds9_pipelined_if[3]=nds->nds9_pipelined_if[4];
    nds->nds9_pipelined_if[4]=0;

    nds->nds7_pipelined_if[0]=nds->nds7_pipelined_if[1];
    nds->nds7_pipelined_if[1]=nds->nds7_pipelined_if[2];
    nds->nds7_pipelined_if[2]=nds->nds7_pipelined_if[3];
    nds->nds7_pipelined_if[3]=nds->nds7_pipelined_if[4];
    nds->nds7_pipelined_if[4]=0;

    nds->active_if_pipe_stages>>=1;
  }
}
static uint8_t nds_bin_to_bcd(uint8_t bin){
  bin%=100;
  return (bin%10)|((bin/10)<<4);
}
void nds_tick_rtc(nds_t*nds){
  time_t time_secs= time(NULL);
  struct tm * tm = localtime(&time_secs);
  nds->rtc.second = nds_bin_to_bcd(tm->tm_sec);
  nds->rtc.minute = nds_bin_to_bcd(tm->tm_min);
  nds->rtc.hour  = nds_bin_to_bcd(tm->tm_hour);
  nds->rtc.day   = nds_bin_to_bcd(tm->tm_mday);
  nds->rtc.month = nds_bin_to_bcd(tm->tm_mon+1);
  nds->rtc.year  = nds_bin_to_bcd(tm->tm_year%100);
  nds->rtc.day_of_week=nds_bin_to_bcd(tm->tm_wday);
}
void nds_tick(sb_emu_state_t* emu, nds_t* nds){
  if(emu->run_mode == SB_MODE_RESET){
    nds_reset(nds);
    emu->run_mode = SB_MODE_RUN;
  }
  if(emu->run_mode == SB_MODE_STEP||emu->run_mode == SB_MODE_RUN){
    nds_tick_rtc(nds);
    nds_tick_keypad(&emu->joy,nds);
    //bool prev_vblank = nds->ppu.last_vblank; 
    //Skip emulation of a frame if we get too far ahead the audio playback
    static int last_tick =0;
    static bool prev_vblank=false;
    while(true){
      int ticks = nds_tick_dma(nds,last_tick);
      if(!ticks){
        uint32_t int7_if = nds7_io_read32(nds,NDS7_IF);
        uint32_t int9_if = nds9_io_read32(nds,NDS9_IF);
        if(nds->halt){
          ticks=2;
          if(int7_if|int9_if){nds->halt = false;}
        }else{
          nds->mem.requests=0;
          if(int7_if){
            uint32_t ie = nds7_io_read32(nds,NDS7_IE);
            uint32_t ime = nds7_io_read32(nds,NDS7_IME);
            if(SB_BFE(ime,0,1)==1) arm7_process_interrupts(&nds->arm7, int7_if&ie);
          }
          if(nds->arm7.registers[PC]== emu->pc_breakpoint)nds->arm7.trigger_breakpoint=true;
          else if(!ticks){
            arm7_exec_instruction(&nds->arm7);
            ticks = nds->mem.requests; 
          }

          if(int9_if){
            int9_if &= nds9_io_read32(nds,NDS9_IE);
            uint32_t ime = nds9_io_read32(nds,NDS9_IME);
            if(SB_BFE(ime,0,1)==1&&int9_if) arm7_process_interrupts(&nds->arm9, int9_if);
          }
          if(nds->arm9.registers[PC]== emu->pc_breakpoint)nds->arm9.trigger_breakpoint=true;
          else if(!ticks){
            arm9_exec_instruction(&nds->arm9);
            ticks = nds->mem.requests; 
          }
        }
        if(nds->arm7.trigger_breakpoint){emu->run_mode = SB_MODE_PAUSE; nds->arm7.trigger_breakpoint=false; break;}
        if(nds->arm9.trigger_breakpoint){emu->run_mode = SB_MODE_PAUSE; nds->arm9.trigger_breakpoint=false; break;}
      }
      ticks=2;
      last_tick=ticks;
      nds_tick_sio(nds);

      double delta_t = ((double)ticks)/(16*1024*1024);

      for(int t = 0;t<ticks;++t){
        nds_tick_interrupts(nds);
        nds_tick_timers(nds);
        nds_tick_ppu(nds,0,emu->render_frame);
        nds_tick_ppu(nds,1,emu->render_frame);
        nds->current_clock++;
      }
      
      if(nds->ppu[0].last_vblank && !prev_vblank){
        prev_vblank = nds->ppu[0].last_vblank;
        break;
      }
      prev_vblank = nds->ppu[0].last_vblank;
      
    }
  }                  
  
  if(emu->run_mode == SB_MODE_STEP) emu->run_mode = SB_MODE_PAUSE; 
}
void nds9_copy_card_region_to_ram(nds_t* nds, const char* region_name, uint32_t rom_offset, uint32_t ram_offset, uint32_t size){
  printf("Copy %s: Card[0x%x]-> RAM[0x%x] Size: %d Card Size:%zu\n",region_name,rom_offset,ram_offset,size,nds->mem.card_size);
  for(int i=0;i<size;++i){
    if(rom_offset+i<nds->mem.card_size) nds9_write8(nds,ram_offset+i,nds->mem.card_data[rom_offset+i]);
  }
}
void nds7_copy_card_region_to_ram(nds_t* nds, const char* region_name, uint32_t rom_offset, uint32_t ram_offset, uint32_t size){
  printf("Copy %s: Card[0x%x]-> RAM[0x%x] Size: %d Card Size:%zu\n",region_name,rom_offset,ram_offset,size,nds->mem.card_size);
  for(int i=0;i<size;++i){
    if(rom_offset+i<nds->mem.card_size) nds7_write8(nds,ram_offset+i,nds->mem.card_data[rom_offset+i]);
  }
}
// See: http://merry.usamimi.org/archex/SysReg_v84A_xml-00bet7/enc_index.xml#mcr_mrc_32
uint32_t nds_coprocessor_read(void* user_data, int coproc,int opcode,int Cn, int Cm,int Cp){
  if(coproc!=15){
    printf("Coprocessor read from unsupported coprocessor:%d\n",coproc);
    return 0; 
  }
  if(opcode!=0)printf("Unsupported opcode(%x) for coproc %d\n",opcode,coproc);
  nds_t * nds = (nds_t*)(user_data);
  return nds->cp15.reg[Cn][Cm][Cp]; 
}
void nds_coprocessor_write(void* user_data, int coproc,int opcode,int Cn, int Cm,int Cp,uint32_t data){
  if(coproc!=15){
    printf("Coprocessor write to unsupported coprocessor:%d\n",coproc);
    return; 
  }
  if(opcode!=0)printf("Unsupported opcode(%x) for coproc %d\n",opcode,coproc);
  nds_t * nds = (nds_t*)(user_data);
  nds->cp15.reg[Cn][Cm][Cp]=data;
  //C9,C1,0 - Data TCM Size/Base (R/W)
  //C9,C1,1 - Instruction TCM Size/Base (R/W)
  if(Cn==1&&Cm==0){
    //C1,C0,0 - Control Register (R/W, or R=Fixed)
    nds->mem.dtcm_enable   = SB_BFE(data, 16,1); 
    nds->mem.dtcm_load_mode= SB_BFE(data, 17,1); 
    nds->mem.itcm_enable   = SB_BFE(data, 18,1); 
    nds->mem.itcm_load_mode= SB_BFE(data, 19,1); 
  }else if(Cn==9&&Cm==1){
    int size = SB_BFE(data,1,5);
    int base = SB_BFE(data,12,20);
    if(Cp==0){
      nds->mem.dtcm_start_address = base<<12; 
      nds->mem.dtcm_end_address = nds->mem.dtcm_start_address+ (512<<size); 
    }else if(Cp==1){
      base = 0; 
      //ITCM base is read only on the NDS
      nds->cp15.reg[Cn][Cm][Cp]=data&(0x3f);

      nds->mem.itcm_start_address = base<<12; 
      nds->mem.itcm_end_address = nds->mem.itcm_start_address+ (512<<size); 
      printf("ITCM Start:0x%08x End: 0x%08x\n",nds->mem.itcm_start_address,nds->mem.itcm_end_address);
    }
  }else if(Cn==7){
    int size = SB_BFE(data,1,5);
    int base = SB_BFE(data,12,20);
    if((Cm==0&&Cp==4)||(Cm==8&&Cp==2)){
      nds->arm9.wait_for_interrupt = true; 
    }
  }else{
    printf("Unhandled: Cn:%d Cm:%d Cp:%d\n",Cn,Cm,Cp);
  }
}

void nds_reset(nds_t*nds){
  uint8_t* card_data = nds->mem.card_data;
  size_t card_size = nds->mem.card_size;
  memset(&nds->mem,0,sizeof(nds->mem));
  nds->mem.card_data=card_data;
  nds->mem.card_size=card_size;
  for(int i=0;i<NDS_LCD_H*NDS_LCD_W;++i){
    nds->framebuffer_top[i*3]= 0;
    nds->framebuffer_top[i*3+1]= 255;
    nds->framebuffer_top[i*3+2]= 0;

    nds->framebuffer_bottom[i*3]= 0;
    nds->framebuffer_bottom[i*3+1]= 0;
    nds->framebuffer_bottom[i*3+2]= 255;
  }
  nds->arm7 = arm7_init(nds);
  nds->arm7.read8      = nds7_arm_read8;
  nds->arm7.read16     = nds7_arm_read16;
  nds->arm7.read32     = nds7_arm_read32;
  nds->arm7.read16_seq = nds7_arm_read16_seq;
  nds->arm7.read32_seq = nds7_arm_read32_seq;
  nds->arm7.write8     = nds7_arm_write8;
  nds->arm7.write16    = nds7_arm_write16;
  nds->arm7.write32    = nds7_arm_write32;
  nds->arm9 = arm7_init(nds);
  nds->arm9.read8      = nds9_arm_read8;
  nds->arm9.read16     = nds9_arm_read16;
  nds->arm9.read32     = nds9_arm_read32;
  nds->arm9.read16_seq = nds9_arm_read16_seq;
  nds->arm9.read32_seq = nds9_arm_read32_seq;
  nds->arm9.write8     = nds9_arm_write8;
  nds->arm9.write16    = nds9_arm_write16;
  nds->arm9.write32    = nds9_arm_write32;
  
  for(int bg = 2;bg<4;++bg){
    nds9_io_store16(nds,GBA_BG2PA+(bg-2)*0x10,1<<8);
    nds9_io_store16(nds,GBA_BG2PB+(bg-2)*0x10,0<<8);
    nds9_io_store16(nds,GBA_BG2PC+(bg-2)*0x10,0<<8);
    nds9_io_store16(nds,GBA_BG2PD+(bg-2)*0x10,1<<8);
  }
  //nds_store32(nds,GBA_DISPCNT,0xe92d0000);
  nds9_write16(nds,0x04000088,512);
  nds9_write32(nds,0x040000DC,0x84000000);
  nds_recompute_waitstate_table(nds,0);
  nds_recompute_mmio_mask_table(nds);
  nds->halt =false;
  nds->activate_dmas=false;
  nds->deferred_timer_ticks=0;
  bool loaded_bios= true;
  if(nds->mem.card_data)memcpy(&nds->card,nds->mem.card_data,sizeof(nds->card));
  loaded_bios&= se_load_bios_file("NDS7 BIOS", nds->save_file_path, "nds7.bin", nds->mem.nds7_bios,sizeof(nds->mem.nds7_bios));
  loaded_bios&= se_load_bios_file("NDS9 BIOS", nds->save_file_path, "nds9.bin", nds->mem.nds9_bios,sizeof(nds->mem.nds9_bios));
  loaded_bios&= se_load_bios_file("NDS Firmware", nds->save_file_path, "firmware.bin", nds->mem.firmware,sizeof(nds->mem.firmware));

  if(!loaded_bios){
    printf("FATAL: Failed to load required bios\n");
  }

  //memcpy(nds->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  const uint32_t initial_regs[37]={
    0x00000000,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x0380fd80,0x0000000,0x8000000,
    0xdf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0380ff80,0x0,0x0380ffc0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,
  };

  const uint32_t initial_regs_arm9[37]={
    0x00000000,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,0x03002f7c,0x0000000,0x8000000,
    0xdf,0x0,0x0,0x0,0x0,0x0,0x0,0x0,
    0x03003f80,0x0,0x03003fc0,0x0,0x0,0x0,0x0,0x0,
    0x0,0x0,0x0,0x0,0x0,
  };
  for(int i=0;i<37;++i)nds->arm7.registers[i]=initial_regs[i];
  for(int i=0;i<37;++i)nds->arm9.registers[i]=initial_regs_arm9[i];
  const uint32_t initial_mmio_writes[]={
    0x4000000,0x80,
    0x4000004,0x7e0000,
    0x4000020,0x100,
    0x4000024,0x1000000,
    0x4000030,0x100,
    0x4000034,0x1000000,
    0x4000080,0xe0000,
    0x4000084,0xf,
    0x4000088,0x200,
    0x4000100,0xff8a,
    0x4000130,0x3ff,
    0x4000134,0x8000,
    0x4000300,0x1,
  };
  for(int i=0;i<sizeof(initial_mmio_writes)/sizeof(uint32_t);i+=2){
    uint32_t addr=initial_mmio_writes[i+0];
    uint32_t data=initial_mmio_writes[i+1];
    arm7_write32(nds, addr,data);
  }
  nds9_write32(nds,GBA_IE,0x1);
  nds9_write16(nds,GBA_DISPCNT,0x9140);
  //C9,C1,0 - Data TCM Size/Base (R/W) (32KB)
  //C9,C1,1 - Instruction TCM Size/Base (R/W)

  uint32_t init_itcm = 0x00000000|(16<<1);
  uint32_t init_dtcm = 0x0300000a;
  uint32_t init_C1C00 =0x0005707d; //Enable ITCM and DTCM
  nds_coprocessor_write(nds, 15,0,9,1,0,init_dtcm);
  nds_coprocessor_write(nds, 15,0,9,1,1,0x00000020);
  nds_coprocessor_write(nds, 15,0,1,0,0,init_C1C00);
  nds_coprocessor_write(nds, 15,0,0,0,1, 0x0F0D2112);

  printf("Game Name: %s\n",nds->card.title);
  nds9_copy_card_region_to_ram(nds,"ARM9 Executable",nds->card.arm9_rom_offset,nds->card.arm9_ram_address,nds->card.arm9_size);
  nds7_copy_card_region_to_ram(nds,"ARM7 Executable",nds->card.arm7_rom_offset,nds->card.arm7_ram_address,nds->card.arm7_size);
  nds->arm9.registers[PC] = nds->card.arm9_entrypoint;
  nds->arm9.irq_table_address = 0xFFFF0000;
  nds->arm7.registers[PC] = nds->card.arm7_entrypoint;
  nds->arm9.coprocessor_read =  nds->arm7.coprocessor_read =nds_coprocessor_read;
  nds->arm9.coprocessor_write=  nds->arm7.coprocessor_write=nds_coprocessor_write;
  printf("ARM9 Entry:0x%x ARM7 Entry:0x%x\n",nds->card.arm9_entrypoint,nds->card.arm7_entrypoint);

  if(nds->arm7.log_cmp_file){fclose(nds->arm7.log_cmp_file);nds->arm7.log_cmp_file=NULL;};
  if(nds->arm9.log_cmp_file){fclose(nds->arm9.log_cmp_file);nds->arm9.log_cmp_file=NULL;};
  //nds->arm7.log_cmp_file =se_load_log_file(nds->save_file_path, "log7.bin");
  nds->arm9.log_cmp_file =se_load_log_file(nds->save_file_path, "log9.bin");
}

#endif
