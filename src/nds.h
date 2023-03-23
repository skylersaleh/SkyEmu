#ifndef SE_NDS_H
#define SE_NDS_H 1

#include "sb_types.h"
#include "nds_rom_database.h"


typedef enum{
  kARM7,
  kARM9,
}nds_arm_mode_t;
//////////////////////////////////////////////////////////////////////////////////////////
// MMIO Register listing from GBATEK (https://problemkaputt.de/gbatek.htm#dsiomaps)     //
//////////////////////////////////////////////////////////////////////////////////////////

// There is a bit of a remapping here:
/*
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
#define NDS_GCBUS_CTL      0x040001A4 /* Gamecard bus timing/control */
#define NDS_GCBUS_CMD      0x040001A8 /* Gamecard bus 8-byte command out */
#define NDS_GCBUS_SEED0_LO 0x040001B0 /* Gamecard Encryption Seed 0 Lower 32bit */
#define NDS_GCBUS_SEED1_LO 0x040001B4 /* Gamecard Encryption Seed 1 Lower 32bit */
#define NDS_GCBUS_SEED0_HI 0x040001B8 /* Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused) */
#define NDS_GCBUS_SEED1_HI 0x040001BA /* Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused) */
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
#define NDS7_SOUND1_CNT 0x04000410 /* Sound Channel 1 Control Register (R/W) */
#define NDS7_SOUND1_SAD 0x04000414 /* Sound Channel 1 Data Source Register (W) */
#define NDS7_SOUND1_TMR 0x04000418 /* Sound Channel 1 Timer Register (W) */
#define NDS7_SOUND1_PNT 0x0400041A /* Sound Channel 1 Loopstart Register (W) */
#define NDS7_SOUND1_LEN 0x0400041C /* Sound Channel 1 Length Register (W) */
#define NDS7_SOUND2_CNT 0x04000420 /* Sound Channel 2 Control Register (R/W) */
#define NDS7_SOUND2_SAD 0x04000424 /* Sound Channel 2 Data Source Register (W) */
#define NDS7_SOUND2_TMR 0x04000428 /* Sound Channel 2 Timer Register (W) */
#define NDS7_SOUND2_PNT 0x0400042A /* Sound Channel 2 Loopstart Register (W) */
#define NDS7_SOUND2_LEN 0x0400042C /* Sound Channel 2 Length Register (W) */
#define NDS7_SOUND3_CNT 0x04000430 /* Sound Channel 3 Control Register (R/W) */
#define NDS7_SOUND3_SAD 0x04000434 /* Sound Channel 3 Data Source Register (W) */
#define NDS7_SOUND3_TMR 0x04000438 /* Sound Channel 3 Timer Register (W) */
#define NDS7_SOUND3_PNT 0x0400043A /* Sound Channel 3 Loopstart Register (W) */
#define NDS7_SOUND3_LEN 0x0400043C /* Sound Channel 3 Length Register (W) */
#define NDS7_SOUND4_CNT 0x04000440 /* Sound Channel 4 Control Register (R/W) */
#define NDS7_SOUND4_SAD 0x04000444 /* Sound Channel 4 Data Source Register (W) */
#define NDS7_SOUND4_TMR 0x04000448 /* Sound Channel 4 Timer Register (W) */
#define NDS7_SOUND4_PNT 0x0400044A /* Sound Channel 4 Loopstart Register (W) */
#define NDS7_SOUND4_LEN 0x0400044C /* Sound Channel 4 Length Register (W) */
#define NDS7_SOUND5_CNT 0x04000450 /* Sound Channel 5 Control Register (R/W) */
#define NDS7_SOUND5_SAD 0x04000454 /* Sound Channel 5 Data Source Register (W) */
#define NDS7_SOUND5_TMR 0x04000458 /* Sound Channel 5 Timer Register (W) */
#define NDS7_SOUND5_PNT 0x0400045A /* Sound Channel 5 Loopstart Register (W) */
#define NDS7_SOUND5_LEN 0x0400045C /* Sound Channel 5 Length Register (W) */
#define NDS7_SOUND6_CNT 0x04000460 /* Sound Channel 6 Control Register (R/W) */
#define NDS7_SOUND6_SAD 0x04000464 /* Sound Channel 6 Data Source Register (W) */
#define NDS7_SOUND6_TMR 0x04000468 /* Sound Channel 6 Timer Register (W) */
#define NDS7_SOUND6_PNT 0x0400046A /* Sound Channel 6 Loopstart Register (W) */
#define NDS7_SOUND6_LEN 0x0400046C /* Sound Channel 6 Length Register (W) */
#define NDS7_SOUND7_CNT 0x04000470 /* Sound Channel 7 Control Register (R/W) */
#define NDS7_SOUND7_SAD 0x04000474 /* Sound Channel 7 Data Source Register (W) */
#define NDS7_SOUND7_TMR 0x04000478 /* Sound Channel 7 Timer Register (W) */
#define NDS7_SOUND7_PNT 0x0400047A /* Sound Channel 7 Loopstart Register (W) */
#define NDS7_SOUND7_LEN 0x0400047C /* Sound Channel 7 Length Register (W) */
#define NDS7_SOUND8_CNT 0x04000480 /* Sound Channel 8 Control Register (R/W) */
#define NDS7_SOUND8_SAD 0x04000484 /* Sound Channel 8 Data Source Register (W) */
#define NDS7_SOUND8_TMR 0x04000488 /* Sound Channel 8 Timer Register (W) */
#define NDS7_SOUND8_PNT 0x0400048A /* Sound Channel 8 Loopstart Register (W) */
#define NDS7_SOUND8_LEN 0x0400048C /* Sound Channel 8 Length Register (W) */
#define NDS7_SOUND9_CNT 0x04000490 /* Sound Channel 9 Control Register (R/W) */
#define NDS7_SOUND9_SAD 0x04000494 /* Sound Channel 9 Data Source Register (W) */
#define NDS7_SOUND9_TMR 0x04000498 /* Sound Channel 9 Timer Register (W) */
#define NDS7_SOUND9_PNT 0x0400049A /* Sound Channel 9 Loopstart Register (W) */
#define NDS7_SOUND9_LEN 0x0400049C /* Sound Channel 9 Length Register (W) */
#define NDS7_SOUNDA_CNT 0x040004A0 /* Sound Channel 10 Control Register (R/W) */
#define NDS7_SOUNDA_SAD 0x040004A4 /* Sound Channel 10 Data Source Register (W) */
#define NDS7_SOUNDA_TMR 0x040004A8 /* Sound Channel 10 Timer Register (W) */
#define NDS7_SOUNDA_PNT 0x040004AA /* Sound Channel 10 Loopstart Register (W) */
#define NDS7_SOUNDA_LEN 0x040004AC /* Sound Channel 10 Length Register (W) */
#define NDS7_SOUNDB_CNT 0x040004B0 /* Sound Channel 11 Control Register (R/W) */
#define NDS7_SOUNDB_SAD 0x040004B4 /* Sound Channel 11 Data Source Register (W) */
#define NDS7_SOUNDB_TMR 0x040004B8 /* Sound Channel 11 Timer Register (W) */
#define NDS7_SOUNDB_PNT 0x040004BA /* Sound Channel 11 Loopstart Register (W) */
#define NDS7_SOUNDB_LEN 0x040004BC /* Sound Channel 11 Length Register (W) */
#define NDS7_SOUNDC_CNT 0x040004C0 /* Sound Channel 12 Control Register (R/W) */
#define NDS7_SOUNDC_SAD 0x040004C4 /* Sound Channel 12 Data Source Register (W) */
#define NDS7_SOUNDC_TMR 0x040004C8 /* Sound Channel 12 Timer Register (W) */
#define NDS7_SOUNDC_PNT 0x040004CA /* Sound Channel 12 Loopstart Register (W) */
#define NDS7_SOUNDC_LEN 0x040004CC /* Sound Channel 12 Length Register (W) */
#define NDS7_SOUNDD_CNT 0x040004D0 /* Sound Channel 13 Control Register (R/W) */
#define NDS7_SOUNDD_SAD 0x040004D4 /* Sound Channel 13 Data Source Register (W) */
#define NDS7_SOUNDD_TMR 0x040004D8 /* Sound Channel 13 Timer Register (W) */
#define NDS7_SOUNDD_PNT 0x040004DA /* Sound Channel 13 Loopstart Register (W) */
#define NDS7_SOUNDD_LEN 0x040004DC /* Sound Channel 13 Length Register (W) */
#define NDS7_SOUNDE_CNT 0x040004E0 /* Sound Channel 14 Control Register (R/W) */
#define NDS7_SOUNDE_SAD 0x040004E4 /* Sound Channel 14 Data Source Register (W) */
#define NDS7_SOUNDE_TMR 0x040004E8 /* Sound Channel 14 Timer Register (W) */
#define NDS7_SOUNDE_PNT 0x040004EA /* Sound Channel 14 Loopstart Register (W) */
#define NDS7_SOUNDE_LEN 0x040004EC /* Sound Channel 14 Length Register (W) */
#define NDS7_SOUNDF_CNT 0x040004F0 /* Sound Channel 15 Control Register (R/W) */
#define NDS7_SOUNDF_SAD 0x040004F4 /* Sound Channel 15 Data Source Register (W) */
#define NDS7_SOUNDF_TMR 0x040004F8 /* Sound Channel 15 Timer Register (W) */
#define NDS7_SOUNDF_PNT 0x040004FA /* Sound Channel 15 Loopstart Register (W) */
#define NDS7_SOUNDF_LEN 0x040004FC /* Sound Channel 15 Length Register (W) */

#define NDS7_SOUNDCNT   0x04000500 /* Sound Control Register (R/W) */
#define NDS7_SOUNDBIAS  0x04000504 /* Sound Bias Register (R/W) */
#define NDS7_SNDCAP0CNT 0x04000508 /* Sound Capture 0 Control Register (R/W) */
#define NDS7_SNDCAP1CNT 0x04000509 /* Sound Capture 1 Control Register (R/W) */
#define NDS7_SNDCAP0DAD 0x04000510 /* Sound Capture 0 Destination Address (R/W) */
#define NDS7_SNDCAP0LEN 0x04000514 /* Sound Capture 0 Length (W) */
#define NDS7_SNDCAP1DAD 0x04000518 /* Sound Capture 1 Destination Address (R/W) */
#define NDS7_SNDCAP1LEN 0x0400051C /* Sound Capture 1 Length (W) */

#define NDS_SPI_POWER 0 
#define NDS_SPI_FIRMWARE 1
#define NDS_SPI_TOUCH 2

#define NDS_FIRMWARE_SIZE (256*1024)

#define NDS_IO_MAP_SPLIT_OFFSET  0x2000
#define NDS_IO_MAP_041_OFFSET    0x4000



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
  { GBA_VCOUNT  , "VCOUNT  ", {  
    {0,8,"LCD-Y"}
  } }, /* R   Vertical Counter (LY) */
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
  { NDS_DISP3DCNT,       "DISP3DCNT",       { 
    {0   ,1, "Texture Mapping      (0=Disable, 1=Enable)"},
    {1   ,1, "PolygonAttr Shading  (0=Toon Shading, 1=Highlight Shading)"},
    {2   ,1, "Alpha-Test           (0=Disable, 1=Enable) (see ALPHA_TEST_REF)"},
    {3   ,1, "Alpha-Blending       (0=Disable, 1=Enable) (see various Alpha values)"},
    {4   ,1, "Anti-Aliasing        (0=Disable, 1=Enable)"},
    {5   ,1, "Edge-Marking         (0=Disable, 1=Enable) (see EDGE_COLOR)"},
    {6   ,1, "Fog Color/Alpha Mode (0=Alpha and Color, 1=Only Alpha) (see FOG_COLOR)"},
    {7   ,1, "Fog Master Enable    (0=Disable, 1=Enable)"},
    {8   ,4, "Fog Depth Shift      (FOG_STEP=400h shr FOG_SHIFT) (see FOG_OFFSET)"},
    {12  ,1, "Color Buffer RDLINES Underflow (0=None, 1=Underflow/Acknowledge)"},
    {13  ,1, "Polygon/Vertex RAM Overflow    (0=None, 1=Overflow/Acknowledge)"},
    {14  ,1, "Rear-Plane Mode                (0=Blank, 1=Bitmap)"},
  } }, /* 3D Display Control Register (R/W) */
  { NDS_DISPCAPCNT,      "DISPCAPCNT",      { 
    { 0  ,5, "EVA               (0..16 = Blending Factor for Source A)"},
    { 8  ,5, "EVB               (0..16 = Blending Factor for Source B)"},
    { 16 ,2, "VRAM Write Block  (0..3 = VRAM A..D) (VRAM must be allocated to LCDC)"},
    { 18 ,2, "VRAM Write Offset (0=00000h, 0=08000h, 0=10000h, 0=18000h)"},
    { 20 ,2, "Capture Size      (0=128x128, 1=256x64, 2=256x128, 3=256x192 dots)"},
    { 24 ,1, "Source A          (0=Graphics Screen BG+3D+OBJ, 1=3D Screen)"},
    { 25 ,1, "Source B          (0=VRAM, 1=Main Memory Display FIFO)"},
    { 26 ,2, "VRAM Read Offset  (0=00000h, 0=08000h, 0=10000h, 0=18000h)"},
    { 29 ,2, "Capture Source    (0=Source A, 1=Source B, 2/3=Sources A+B blended)"},
    { 31 ,1, "Capture Enable    (0=Disable/Ready, 1=Enable/Busy)"},
  } }, /* Display Capture Control Register (R/W) */
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
    { 11, 3,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Video, 4=Main memory display, 5=DS Cartridge Slot, 6=GBA Cartridge Slot, 7=Geometry Command FIFO)" },
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
    { 11, 3,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Video, 4=Main memory display, 5=DS Cartridge Slot, 6=GBA Cartridge Slot, 7=Geometry Command FIFO)" },
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
    { 11, 3,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Video, 4=Main memory display, 5=DS Cartridge Slot, 6=GBA Cartridge Slot, 7=Geometry Command FIFO)" },
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
    { 11, 3,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=HBlank, 3=Video, 4=Main memory display, 5=DS Cartridge Slot, 6=GBA Cartridge Slot, 7=Geometry Command FIFO)" },
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
  { GBA_JOYCNT   , "JOYCNT", {0} },     /* R/W  SIO JOY Bus Control */
  { GBA_JOY_RECV , "JOY_RECV", {0} },     /* R/W  SIO JOY Bus Receive Data */
  { GBA_JOY_TRANS, "JOY_TRANS", {0} },     /* R/W  SIO JOY Bus Transmit Data */
  { GBA_JOYSTAT  , "JOYSTAT", {0} },     /* R/?  SIO JOY Bus Receive Status */  

  { NDS_IPCSYNC     , "IPCSYNC",     { 
    { 0 ,4,"Data input from IPCSYNC Bit8-11 of remote CPU (00h..0Fh)"},
    { 8  ,4,"Data output to IPCSYNC Bit0-3 of remote CPU   (00h..0Fh)"},
    { 13 ,1,"Send IRQ to remote CPU      (0=None, 1=Send IRQ)"},
    { 14 ,1,"Enable IRQ from remote CPU  (0=Disable, 1=Enable)"},
  } }, /*IPC Synchronize Register (R/W)*/
  { NDS_IPCFIFOCNT  , "IPCFIFOCNT",  { 
    { 0    ,1, "Send Fifo Empty Status      (0=Not Empty, 1=Empty)"},
    { 1    ,1, "Send Fifo Full Status       (0=Not Full, 1=Full)"},
    { 2    ,1, "Send Fifo Empty IRQ         (0=Disable, 1=Enable)"},
    { 3    ,1, "Send Fifo Clear             (0=Nothing, 1=Flush Send Fifo)"},
    { 8    ,1, "Receive Fifo Empty          (0=Not Empty, 1=Empty)"},
    { 9    ,1, "Receive Fifo Full           (0=Not Full, 1=Full)"},
    { 10   ,1, "Receive Fifo Not Empty IRQ  (0=Disable, 1=Enable)"},
    { 14   ,1, "Error, Read Empty/Send Full (0=No Error, 1=Error/Acknowledge)"},
    { 15   ,1, "Enable Send/Receive Fifo    (0=Disable, 1=Enable)"},
  } }, /*IPC Fifo Control Register (R/W)*/
  { NDS_IPCFIFOSEND , "IPCFIFOSEND", { 0 } }, /*IPC Send Fifo (W)*/
  { NDS_IPCFIFORECV, "IPCFIFORECV", { 0 }}, /* Sound Capture 1 Length (W) */
  { NDS9_AUXSPICNT   , "AUXSPICNT",   { 
    { 0    ,2,"SPI Baudrate        (0=4MHz/Default, 1=2MHz, 2=1MHz, 3=512KHz)" },
    { 6    ,1,"SPI Hold Chipselect (0=Deselect after transfer, 1=Keep selected)" },
    { 7    ,1,"SPI Busy            (0=Ready, 1=Busy) (presumably Read-only)" },
    { 13   ,1,"NDS Slot Mode       (0=Parallel/ROM, 1=Serial/SPI-Backup)" },
    { 14   ,1,"Transfer Ready IRQ  (0=Disable, 1=Enable) (for ROM, not for AUXSPI)" },
    { 15   ,1,"NDS Slot Enable     (0=Disable, 1=Enable) (for both ROM and AUXSPI)" },
  } }, /*Gamecard ROM and SPI Control*/
  { NDS9_AUXSPIDATA  , "AUXSPIDATA",  { 0 } }, /*Gamecard SPI Bus Data/Strobe*/
  { NDS_GCBUS_CTL  , "GC_BUS_CTL",  { 
    { 0    ,13,"KEY1 gap1 length  (0-1FFFh) (forced min 08F8h by BIOS) (leading gap)" },
    { 13   ,1, "KEY2 encrypt data (0=Disable, 1=Enable KEY2 Encryption for Data)" },
    { 14   ,1, "Unknown (SE)" },
    { 15   ,1, "KEY2 Apply Seed   (0=No change, 1=Apply Encryption Seed) (Write only)" },
    { 16   ,6, "KEY1 gap2 length  (0-3Fh)   (forced min 18h by BIOS) (200h-byte gap)" },
    { 22   ,1, "KEY2 encrypt cmd  (0=Disable, 1=Enable KEY2 Encryption for Commands)" },
    { 23   ,1, "Data-Word Status  (0=Busy, 1=Ready/DRQ) (Read-only)" },
    { 24   ,3, "Data Block size   (0=None, 1..6=100h SHL (1..6) bytes, 7=4 bytes)" },
    { 27   ,1, "Transfer CLK rate (0=6.7MHz=33.51MHz/5, 1=4.2MHz=33.51MHz/8)" },
    { 28   ,1, "KEY1 Gap CLKs (0=Hold CLK High during gaps, 1=Output Dummy CLK Pulses)" },
    { 29   ,1, "RESB Release Reset  (0=Reset, 1=Release) (cannot be cleared once set)" },
    { 30   ,1, "Data Direction 'WR' (0=Normal/read, 1=Write, for FLASH/NAND carts)" },
    { 31   ,1, "Block Start/Status  (0=Ready, 1=Start/Busy) (IRQ See 40001A0h/Bit14)" },
  } }, /*Gamecard bus timing/control*/
  { NDS_GCBUS_CMD  , "GC_BUS_CMD",  { 0 } }, /*Gamecard bus 8-byte command out*/
  { NDS9_GC_ENC0_LO  , "GC_ENC0_LO",  { 0 } }, /*Gamecard Encryption Seed 0 Lower 32bit*/
  { NDS9_GC_ENC1_LO  , "GC_ENC1_LO",  { 0 } }, /*Gamecard Encryption Seed 1 Lower 32bit*/
  { NDS9_GC_ENC0_HI  , "GC_ENC0_HI",  { 0 } }, /*Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused)*/
  { NDS9_GC_ENC1_HI  , "GC_ENC1_HI",  { 0 } }, /*Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused)*/
  
  // ARM9 Memory and IRQ Control
  { NDS9_EXMEMCNT , "EXMEMCNT",  { 
    {0,2,"32-pin GBA Slot SRAM Access Time    (0-3 = 10, 8, 6, 18 cycles)"},
    {2,2,"32-pin GBA Slot ROM 1st Access Time (0-3 = 10, 8, 6, 18 cycles)"},
    {4,1,"32-pin GBA Slot ROM 2nd Access Time (0-1 = 6, 4 cycles)"},
    {6 ,2, "32-pin GBA Slot PHI-pin out   (0-3 = Low, 4.19MHz, 8.38MHz, 16.76MHz)"},
    {7   ,1, "32-pin GBA Slot Access Rights     (0=ARM9, 1=ARM7)"},
    {11  ,1, "17-pin NDS Slot Access Rights     (0=ARM9, 1=ARM7)"},
    {13  ,1, "NDS:Always set?  ;set/tested by DSi bootcode: Main RAM enable, CE2 pin?"},
    {14  ,1, "Main Memory Interface Mode Switch (0=Async/GBA/Reserved, 1=Synchronous)"},
    {15  ,1, "Main Memory Access Priority       (0=ARM9 Priority, 1=ARM7 Priority)"},
  } }, /* External Memory Control (R/W) */
  { NDS9_IME      , "IME",       { 0 } }, /* Interrupt Master Enable (R/W) */
  { NDS9_IE       , "IE",        { 
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "GBA-Slot (external IRQ source) / DSi: None such" },
    { 16, 1, "IPC Sync" },
    { 17, 1, "IPC Send FIFO Empty" },
    { 18, 1, "IPC Recv FIFO Not Empty" },
    { 19, 1, "NDS-Slot Game Card Data Transfer Completion" },
    { 20, 1, "NDS-Slot Game Card IREQ_MC" },
    { 21, 1, "NDS9 only: Geometry Command FIFO" },
    { 22, 1, "NDS7 only: Screens unfolding" },
    { 23, 1, "NDS7 only: SPI bus" },
    { 24, 1, "NDS7 only: Wifi DSi9: XpertTeak DSP" },
    { 25, 1, "DSi9: Camera" },
    { 26, 1, "DSi9: Undoc, IF.26 set on FFh-filling 40021Axh" },
    { 27, 1, "DSi:  Maybe IREQ_MC for 2nd gamecard?" },
    { 28, 1, "DSi: NewDMA0" },
    { 29, 1, "DSi: NewDMA1" },
    { 30, 1, "DSi: NewDMA2" },
    { 31, 1, "DSi: NewDMA3" },
  } }, /* Interrupt Enable (R/W) */
  { NDS9_IF       , "IF",        { 
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "GBA-Slot (external IRQ source) / DSi: None such" },
    { 16, 1, "IPC Sync" },
    { 17, 1, "IPC Send FIFO Empty" },
    { 18, 1, "IPC Recv FIFO Not Empty" },
    { 19, 1, "NDS-Slot Game Card Data Transfer Completion" },
    { 20, 1, "NDS-Slot Game Card IREQ_MC" },
    { 21, 1, "NDS9 only: Geometry Command FIFO" },
    { 22, 1, "NDS7 only: Screens unfolding" },
    { 23, 1, "NDS7 only: SPI bus" },
    { 24, 1, "NDS7 only: Wifi DSi9: XpertTeak DSP" },
    { 25, 1, "DSi9: Camera" },
    { 26, 1, "DSi9: Undoc, IF.26 set on FFh-filling 40021Axh" },
    { 27, 1, "DSi:  Maybe IREQ_MC for 2nd gamecard?" },
    { 28, 1, "DSi: NewDMA0" },
    { 29, 1, "DSi: NewDMA1" },
    { 30, 1, "DSi: NewDMA2" },
    { 31, 1, "DSi: NewDMA3" },
  } }, /* Interrupt Request Flags (R/W) */
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
  { NDS9_VRAMCNT_H, "VRAMCNT_H", { 
     { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-H (32K) Bank Control (W) */
  { NDS9_VRAMCNT_I, "VRAMCNT_I", { 
     { 0, 3, "VRAM MST              ;Bit2 not used by VRAM-A,B,H,I" },
     { 3, 2, "VRAM Offset (0-3)     ;Offset not used by VRAM-E,H,I" },
     { 5, 2, "Not used" },
     { 7, 1, "VRAM Enable (0=Disable, 1=Enable)" },
  } }, /* VRAM-I (16K) Bank Control (W) */
  { NDS9_WRAMCNT  , "WRAMCNT",   { 
      {0,2, "WRAM Mode ARM9/ARM7 (0-3 = 32K/0K, 2nd 16K/1st 16K, 1st 16K/2nd 16K, 0K/32K)"}
  } }, /* WRAM Bank Control (W) */

  // ARM9 Maths
  { NDS9_DIVCNT,        "DIVCNT",        { 
      {0,2,    "Division Mode    (0-2=See below) (3=Reserved; same as Mode 1)"},
      {14,1,   "Division by zero (0=Okay, 1=Division by zero error; 64bit Denom=0)"},
      {15,1,   "Busy             (0=Ready, 1=Busy) (Execution time see below)"},
  } }, /* Division Control (R/W) */
  { NDS9_DIV_NUMER,     "DIV_NUMER",     { 0 } }, /* Division Numerator (R/W) */
  { NDS9_DIV_DENOM,     "DIV_DENOM",     { 0 } }, /* Division Denominator (R/W) */
  { NDS9_DIV_RESULT,    "DIV_RESULT",    { 0 } }, /* Division Quotient (=Numer/Denom) (R) */
  { NDS9_DIVREM_RESULT, "DIVREM_RESULT", { 0 } }, /* Division Remainder (=Numer MOD Denom) (R) */
  { NDS9_SQRTCNT,       "SQRTCNT",       { 
      {0 ,1, "Mode (0=32bit input, 1=64bit input)"},
      {15,1, "Busy (0=Ready, 1=Busy) (Execution time is 13 clks, in either Mode)"},
  } }, /* Square Root Control (R/W) */
  { NDS9_SQRT_RESULT,   "SQRT_RESULT",   { 0 } }, /* Square Root Result (R) */
  { NDS9_SQRT_PARAM,    "SQRT_PARAM",    { 0 } }, /* Square Root Parameter Input (R/W) */
  { NDS9_POSTFLG,       "POSTFLG",       { 
     { 0, 1, "First Boot Flag  (0=First, 1=Further)" },
  } }, /* Undoc */
  { NDS9_POWCNT1,       "POWCNT1",       { 
    { 0 , 1, "Enable Flag for both LCDs (0=Disable) (Prohibited, see notes)"},
    { 1 , 1, "2D Graphics Engine A      (0=Disable) (Ports 008h-05Fh, Pal 5000000h)"},
    { 2 , 1, "3D Rendering Engine       (0=Disable) (Ports 320h-3FFh)"},
    { 3 , 1, "3D Geometry Engine        (0=Disable) (Ports 400h-6FFh)"},
    { 9 , 1, "2D Graphics Engine B      (0=Disable) (Ports 1008h-105Fh, Pal 5000400h)"},
    { 15, 1, "Display Swap (0=Send Display A to Lower Screen, 1=To Upper Screen)"},
   } }, /* Graphics Power Control Register (R/W) */

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
  { NDS9_VTX_16,          "VTX_16(param 0)",          { 
    {0, 16,  "(Param 1)X Coord 1.3.12 fixed point"},
    {16, 16, "(Param 1)Y Coord 1.3.12 fixed point"},
    {0, 16,  "(Param 2)Z Coord 1.3.12 fixed point"}
  } }, /* Set Vertex XYZ Coordinates (W) */ 
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
  { NDS9_BEGIN_VTXS,      "BEGIN_VTXS",      { 
    {0,2,"Primitive Type(0=Triangles, 1=Quads, 2=Tri Strips, 3=Quad Strips"},
  } }, /* Start of Vertex List (W) */ 
  { NDS9_END_VTXS,        "END_VTXS",        { 0 } }, /* End of Vertex List (W) */ 
  { NDS9_SWAP_BUFFERS,    "SWAP_BUFFERS",    { 0 } }, /* Swap Rendering Engine Buffer (W) */ 
  { NDS9_VIEWPORT,        "VIEWPORT",        { 0 } }, /* Set Viewport (W) */ 
  { NDS9_BOX_TEST,        "BOX_TEST",        { 0 } }, /* Test if Cuboid Sits inside View Volume (W) */ 
  { NDS9_POS_TEST,        "POS_TEST",        { 0 } }, /* Set Position Coordinates for Test (W) */ 
  { NDS9_VEC_TEST,        "VEC_TEST",        { 0 } }, /* Set Directional Vector for Test (W) */ 
  { NDS9_GXSTAT,          "GXSTAT",          { 
    { 0    , 1, "BoxTest,PositionTest,VectorTest Busy (0=Ready, 1=Busy)" },
    { 1    , 1, "BoxTest Result  (0=All Outside View, 1=Parts or Fully Inside View)" },
    { 8    , 5, "Position & Vector Matrix Stack Level (0..31) (lower 5bit of 6bit value)" },
    { 13   , 1, "Projection Matrix Stack Level        (0..1)" },
    { 14   , 1, "Matrix Stack Busy (0=No, 1=Yes; Currently executing a Push/Pop command)" },
    { 15   , 1, "Matrix Stack Overflow/Underflow Error (0=No, 1=Error/Acknowledge/Reset)" },
    { 16   , 9, "Number of 40bit-entries in Command FIFO  (0..256)" },
    { 25   , 1, "Command FIFO Less Than Half Full  (0=No, 1=Yes; Less than Half-full)" },
    { 26   , 1, "Command FIFO Empty                (0=No, 1=Yes; Empty)" },
    { 27   , 1, "Geometry Engine Busy (0=No, 1=Yes; Busy; Commands are executing)" },
    { 30   , 2, "Command FIFO IRQ (0=Never, 1=Less than half full, 2=Empty, 3=Reserved)" },
  } }, /* Geometry Engine Status Register (R and R/W) */
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
  { GBA_VCOUNT  , "VCOUNT  ", { 
    {0,8,"LCD-Y"}
  } }, /* R   Vertical Counter (LY) */

  // DMA Transfer Channels
  { GBA_DMA0SAD  , "DMA0SAD", { 0 } },   /* W    DMA 0 Source Address */
  { GBA_DMA0DAD  , "DMA0DAD", { 0 } },   /* W    DMA 0 Destination Address */
  { GBA_DMA0CNT_L, "DMA0CNT_L", { 0 } },   /* W    DMA 0 Word Count */
  { GBA_DMA0CNT_H, "DMA0CNT_H", {
    { 5,  2,  "Dest Addr Control (0=Incr,1=Decr,2=Fixed,3=Incr/Reload)" },
    { 7,  2,  "Source Adr Control (0=Incr,1=Decr,2=Fixed,3=Prohibited)" },
    { 9,  1,  "DMA Repeat (0=Off, 1=On) (Must be zero if Bit 11 set)" },
    { 10, 1,  "DMA Transfer Type (0=16bit, 1=32bit)" },
    { 11, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=DS Cartridge Slot, 3=Wireless interrupt" },
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
    { 11, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=DS Cartridge Slot, 3=GBA Cartridge Slot" },
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
    { 11, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=DS Cartridge Slot, 3=Wireless interrupt" },
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
    { 11, 2,  "DMA Start Timing (0=Immediately, 1=VBlank, 2=DS Cartridge Slot, 3=GBA Cartridge Slot" },
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
  { GBA_JOYCNT   , "JOYCNT", {0} },     /* R/W  SIO JOY Bus Control */
  { GBA_JOY_RECV , "JOY_RECV", {0} },     /* R/W  SIO JOY Bus Receive Data */
  { GBA_JOY_TRANS, "JOY_TRANS", {0} },     /* R/W  SIO JOY Bus Transmit Data */
  { GBA_JOYSTAT  , "JOYSTAT", {0} },     /* R/?  SIO JOY Bus Receive Status */  

  { NDS7_DEBUG_RCNT,      "DEBUG_RCNT",     { 0 } }, /* Debug RCNT */
  { NDS7_EXTKEYIN,        "EXTKEYIN",       { 
    { 0,1, "Button X     (0=Pressed, 1=Released)"},
    { 1,1, "Button Y     (0=Pressed, 1=Released)"},
    { 3,1, "DEBUG button (0=Pressed, 1=Released/None such)"},
    { 6,1, "Pen down     (0=Pressed, 1=Released/Disabled) (always 0 in DSi mode)"},
    { 7,1, "Hinge/folded (0=Open, 1=Closed)"},
  } }, /* EXTKEYIN */
  { NDS7_RTC_BUS,         "RTC_BUS",        { 0 } }, /* RTC Realtime Clock Bus */
  { NDS_IPCSYNC,         "IPCSYNC",        { 
    { 0 ,4,"Data input from IPCSYNC Bit8-11 of remote CPU (00h..0Fh)"},
    { 8  ,4,"Data output to IPCSYNC Bit0-3 of remote CPU   (00h..0Fh)"},
    { 13 ,1,"Send IRQ to remote CPU      (0=None, 1=Send IRQ)"},
    { 14 ,1,"Enable IRQ from remote CPU  (0=Disable, 1=Enable)"},
  } }, /* IPC Synchronize Register (R/W) */
  { NDS_IPCFIFOCNT,      "IPCFIFOCNT",     { 
    { 0    ,1, "Send Fifo Empty Status      (0=Not Empty, 1=Empty)"},
    { 1    ,1, "Send Fifo Full Status       (0=Not Full, 1=Full)"},
    { 2    ,1, "Send Fifo Empty IRQ         (0=Disable, 1=Enable)"},
    { 3    ,1, "Send Fifo Clear             (0=Nothing, 1=Flush Send Fifo)"},
    { 8    ,1, "Receive Fifo Empty          (0=Not Empty, 1=Empty)"},
    { 9    ,1, "Receive Fifo Full           (0=Not Full, 1=Full)"},
    { 10   ,1, "Receive Fifo Not Empty IRQ  (0=Disable, 1=Enable)"},
    { 14   ,1, "Error, Read Empty/Send Full (0=No Error, 1=Error/Acknowledge)"},
    { 15   ,1, "Enable Send/Receive Fifo    (0=Disable, 1=Enable)"},
  } }, /* IPC Fifo Control Register (R/W) */
  { NDS_IPCFIFOSEND,     "IPCFIFOSEND",    { 0 } }, /* IPC Send Fifo (W) */
  { NDS_IPCFIFORECV, "IPCFIFORECV", { 0 }}, /* Sound Capture 1 Length (W) */
  { NDS7_AUXSPICNT,       "AUXSPICNT",      { 
    { 0    ,2,"SPI Baudrate        (0=4MHz/Default, 1=2MHz, 2=1MHz, 3=512KHz)" },
    { 6    ,1,"SPI Hold Chipselect (0=Deselect after transfer, 1=Keep selected)" },
    { 7    ,1,"SPI Busy            (0=Ready, 1=Busy) (presumably Read-only)" },
    { 13   ,1,"NDS Slot Mode       (0=Parallel/ROM, 1=Serial/SPI-Backup)" },
    { 14   ,1,"Transfer Ready IRQ  (0=Disable, 1=Enable) (for ROM, not for AUXSPI)" },
    { 15   ,1,"NDS Slot Enable     (0=Disable, 1=Enable) (for both ROM and AUXSPI)" },
  } }, /* Gamecard ROM and SPI Control */
  { NDS7_AUXSPIDATA,      "AUXSPIDATA",     { 0 } }, /* Gamecard SPI Bus Data/Strobe */
  { NDS_GCBUS_CTL,       "GCBUS_CTL",      { 
    { 0    ,13,"KEY1 gap1 length  (0-1FFFh) (forced min 08F8h by BIOS) (leading gap)" },
    { 13   ,1, "KEY2 encrypt data (0=Disable, 1=Enable KEY2 Encryption for Data)" },
    { 14   ,1, "Unknown (SE)" },
    { 15   ,1, "KEY2 Apply Seed   (0=No change, 1=Apply Encryption Seed) (Write only)" },
    { 16   ,6, "KEY1 gap2 length  (0-3Fh)   (forced min 18h by BIOS) (200h-byte gap)" },
    { 22   ,1, "KEY2 encrypt cmd  (0=Disable, 1=Enable KEY2 Encryption for Commands)" },
    { 23   ,1, "Data-Word Status  (0=Busy, 1=Ready/DRQ) (Read-only)" },
    { 24   ,3, "Data Block size   (0=None, 1..6=100h SHL (1..6) bytes, 7=4 bytes)" },
    { 27   ,1, "Transfer CLK rate (0=6.7MHz=33.51MHz/5, 1=4.2MHz=33.51MHz/8)" },
    { 28   ,1, "KEY1 Gap CLKs (0=Hold CLK High during gaps, 1=Output Dummy CLK Pulses)" },
    { 29   ,1, "RESB Release Reset  (0=Reset, 1=Release) (cannot be cleared once set)" },
    { 30   ,1, "Data Direction 'WR' (0=Normal/read, 1=Write, for FLASH/NAND carts)" },
    { 31   ,1, "Block Start/Status  (0=Ready, 1=Start/Busy) (IRQ See 40001A0h/Bit14)" },
  } }, /* Gamecard bus timing/control */
  { NDS_GCBUS_CMD,       "GCBUS_CMD",      { 0 } }, /* Gamecard bus 8-byte command out */
  { NDS_GCBUS_SEED0_LO,  "GCBUS_SEED0_LO", { 0 } }, /* Gamecard Encryption Seed 0 Lower 32bit */
  { NDS_GCBUS_SEED1_LO,  "GCBUS_SEED1_LO", { 0 } }, /* Gamecard Encryption Seed 1 Lower 32bit */
  { NDS_GCBUS_SEED0_HI,  "GCBUS_SEED0_HI", { 0 } }, /* Gamecard Encryption Seed 0 Upper 7bit (bit7-15 unused) */
  { NDS_GCBUS_SEED1_HI,  "GCBUS_SEED1_HI", { 0 } }, /* Gamecard Encryption Seed 1 Upper 7bit (bit7-15 unused) */
  { NDS7_SPI_BUS_CTL,     "SPI_BUS_CTL",    { 
    { 0    , 2,"Baudrate (0=4MHz/Firmware, 1=2MHz/Touchscr, 2=1MHz/Powerman., 3=512KHz)"},
    { 2    , 1,"DSi: Baudrate MSB   (4=8MHz, 5..7=None/0Hz) (when SCFG_EXT7.bit9=1)"},
    { 7    , 1,"Busy Flag           (0=Ready, 1=Busy) (presumably Read-only)"},
    { 8    , 2,"Device Select       (0=Powerman., 1=Firmware, 2=Touchscr, 3=Reserved)"},
    { 10   , 1,"Transfer Size       (0=8bit/Normal, 1=16bit/Bugged)"},
    { 11   , 1,"Chipselect Hold     (0=Deselect after transfer, 1=Keep selected)"},
    { 14   , 1,"Interrupt Request   (0=Disable, 1=Enable)"},
    { 15   , 1,"SPI Bus Enable      (0=Disable, 1=Enable)"},
  } }, /* SPI bus Control (Firmware, Touchscreen, Powerman) */
  { NDS7_SPI_BUS_DATA,    "SPI_BUS_DATA",   { 0 } }, /* SPI bus Data */
  // ARM7 Memory and IRQ Control
  { NDS7_EXMEMSTAT,   "EXMEMSTAT",   { 
    {0,2,"32-pin GBA Slot SRAM Access Time    (0-3 = 10, 8, 6, 18 cycles)"},
    {2,2,"32-pin GBA Slot ROM 1st Access Time (0-3 = 10, 8, 6, 18 cycles)"},
    {4,1,"32-pin GBA Slot ROM 2nd Access Time (0-1 = 6, 4 cycles)"},
    {6 ,2, "32-pin GBA Slot PHI-pin out   (0-3 = Low, 4.19MHz, 8.38MHz, 16.76MHz)"},
    {7   ,1, "32-pin GBA Slot Access Rights     (0=ARM9, 1=ARM7)"},
    {11  ,1, "17-pin NDS Slot Access Rights     (0=ARM9, 1=ARM7)"},
    {13  ,1, "NDS:Always set?  ;set/tested by DSi bootcode: Main RAM enable, CE2 pin?"},
    {14  ,1, "Main Memory Interface Mode Switch (0=Async/GBA/Reserved, 1=Synchronous)"},
    {15  ,1, "Main Memory Access Priority       (0=ARM9 Priority, 1=ARM7 Priority)"},
  }}, /* EXMEMSTAT - External Memory Status */
  { NDS7_WIFIWAITCNT, "WIFIWAITCNT", { 0 }}, /* WIFIWAITCNT */
  { NDS7_IME,         "IME",         { 0 }}, /* IME - Interrupt Master Enable (R/W) */
  { NDS7_IE,          "IE",          { 
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 7 , 1, "SIO/RCNT/RTC (Real Time Clock)" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "GBA-Slot (external IRQ source) / DSi: None such" },
    { 16, 1, "IPC Sync" },
    { 17, 1, "IPC Send FIFO Empty" },
    { 18, 1, "IPC Recv FIFO Not Empty" },
    { 19, 1, "NDS-Slot Game Card Data Transfer Completion" },
    { 20, 1, "NDS-Slot Game Card IREQ_MC" },
    { 21, 1, "NDS9 only: Geometry Command FIFO" },
    { 22, 1, "NDS7 only: Screens unfolding" },
    { 23, 1, "NDS7 only: SPI bus" },
    { 24, 1, "NDS7 only: Wifi DSi9: XpertTeak DSP" },
    { 25, 1, "DSi9: Camera" },
    { 26, 1, "DSi9: Undoc, IF.26 set on FFh-filling 40021Axh" },
    { 27, 1, "DSi:  Maybe IREQ_MC for 2nd gamecard?" },
    { 28, 1, "DSi: NewDMA0" },
    { 29, 1, "DSi: NewDMA1" },
    { 30, 1, "DSi: NewDMA2" },
    { 31, 1, "DSi: NewDMA3" },
  }}, /* IE  - Interrupt Enable (R/W) */
  { NDS7_IF,          "IF",          { 
    { 0 , 1, "LCD V-Blank" },
    { 1 , 1, "LCD H-Blank" },
    { 2 , 1, "LCD V-Counter Match" },
    { 3 , 1, "Timer 0 Overflow" },
    { 4 , 1, "Timer 1 Overflow" },
    { 5 , 1, "Timer 2 Overflow" },
    { 6 , 1, "Timer 3 Overflow" },
    { 7 , 1, "SIO/RCNT/RTC (Real Time Clock)" },
    { 8 , 1, "DMA 0" },
    { 9 , 1, "DMA 1" },
    { 10, 1, "DMA 2" },
    { 11, 1, "DMA 3" },
    { 12, 1, "Keypad" },
    { 13, 1, "GBA-Slot (external IRQ source) / DSi: None such" },
    { 16, 1, "IPC Sync" },
    { 17, 1, "IPC Send FIFO Empty" },
    { 18, 1, "IPC Recv FIFO Not Empty" },
    { 19, 1, "NDS-Slot Game Card Data Transfer Completion" },
    { 20, 1, "NDS-Slot Game Card IREQ_MC" },
    { 21, 1, "NDS9 only: Geometry Command FIFO" },
    { 22, 1, "NDS7 only: Screens unfolding" },
    { 23, 1, "NDS7 only: SPI bus" },
    { 24, 1, "NDS7 only: Wifi DSi9: XpertTeak DSP" },
    { 25, 1, "DSi9: Camera" },
    { 26, 1, "DSi9: Undoc, IF.26 set on FFh-filling 40021Axh" },
    { 27, 1, "DSi:  Maybe IREQ_MC for 2nd gamecard?" },
    { 28, 1, "DSi: NewDMA0" },
    { 29, 1, "DSi: NewDMA1" },
    { 30, 1, "DSi: NewDMA2" },
    { 31, 1, "DSi: NewDMA3" },

  }}, /* IF  - Interrupt Request Flags (R/W) */
  { NDS7_VRAMSTAT,    "VRAMSTAT",    { 
    { 0, 1, "VRAM C enabled and allocated to NDS7  (0=No, 1=Yes)"},
    { 1, 1, "VRAM D enabled and allocated to NDS7  (0=No, 1=Yes)"},
  }}, /* VRAMSTAT - VRAM-C,D Bank Status (R) */
  { NDS7_WRAMSTAT,    "WRAMSTAT",    { 
      {0,2, "WRAM Mode ARM9/ARM7 (0-3 = 32K/0K, 2nd 16K/1st 16K, 1st 16K/2nd 16K, 0K/32K)"}
  }}, /* WRAMSTAT - WRAM Bank Status (R) */
  { NDS7_POSTFLG,     "POSTFLG",     {
    { 0, 1, "First Boot Flag  (0=First, 1=Further)" },
  }}, /* POSTFLG */
  { NDS7_HALTCNT,     "HALTCNT",     { 
    { 0, 2, " Power Down Mode  (0=No function, 1=Enter GBA Mode, 2=Halt, 3=Sleep)" },
  }}, /* HALTCNT (different bits than on GBA) (plus NOP delay) */
  { NDS7_POWCNT2,     "POWCNT2",     { 
    { 0, 1, "Sound Speakers (0=Disable, 1=Enable) (Initial setting = 1)" },
    { 1, 1, "Wifi           (0=Disable, 1=Enable) (Initial setting = 0)" },
  }}, /* POWCNT2  Sound/Wifi Power Control Register (R/W) */
  { NDS7_BIOSPROT,    "BIOSPROT",    { 0 }}, /* BIOSPROT - Bios-data-read-protection address */

  // ARM7 Sound Registers (Sound Channel 0..15 (10h bytes each)) 
  { NDS7_SOUND0_CNT, "SOUND0_CNT", { 
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 0 Control Register (R/W) */
  { NDS7_SOUND0_SAD, "SOUND0_SAD", { 0 }}, /* Sound Channel 0 Data Source Register (W) */
  { NDS7_SOUND0_TMR, "SOUND0_TMR", { 0 }}, /* Sound Channel 0 Timer Register (W) */
  { NDS7_SOUND0_PNT, "SOUND0_PNT", { 0 }}, /* Sound Channel 0 Loopstart Register (W) */
  { NDS7_SOUND0_LEN, "SOUND0_LEN", { 0 }}, /* Sound Channel 0 Length Register (W) */
  { NDS7_SOUND1_CNT, "SOUND1_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 1 Control Register (R/W) */
  { NDS7_SOUND1_SAD, "SOUND1_SAD", { 0 }}, /* Sound Channel 1 Data Source Register (W) */
  { NDS7_SOUND1_TMR, "SOUND1_TMR", { 0 }}, /* Sound Channel 1 Timer Register (W) */
  { NDS7_SOUND1_PNT, "SOUND1_PNT", { 0 }}, /* Sound Channel 1 Loopstart Register (W) */
  { NDS7_SOUND1_LEN, "SOUND1_LEN", { 0 }}, /* Sound Channel 1 Length Register (W) */
  { NDS7_SOUND2_CNT, "SOUND2_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 2 Control Register (R/W) */
  { NDS7_SOUND2_SAD, "SOUND2_SAD", { 0 }}, /* Sound Channel 2 Data Source Register (W) */
  { NDS7_SOUND2_TMR, "SOUND2_TMR", { 0 }}, /* Sound Channel 2 Timer Register (W) */
  { NDS7_SOUND2_PNT, "SOUND2_PNT", { 0 }}, /* Sound Channel 2 Loopstart Register (W) */
  { NDS7_SOUND2_LEN, "SOUND2_LEN", { 0 }}, /* Sound Channel 2 Length Register (W) */
  { NDS7_SOUND3_CNT, "SOUND3_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 3 Control Register (R/W) */
  { NDS7_SOUND3_SAD, "SOUND3_SAD", { 0 }}, /* Sound Channel 3 Data Source Register (W) */
  { NDS7_SOUND3_TMR, "SOUND3_TMR", { 0 }}, /* Sound Channel 3 Timer Register (W) */
  { NDS7_SOUND3_PNT, "SOUND3_PNT", { 0 }}, /* Sound Channel 3 Loopstart Register (W) */
  { NDS7_SOUND3_LEN, "SOUND3_LEN", { 0 }}, /* Sound Channel 3 Length Register (W) */
  { NDS7_SOUND4_CNT, "SOUND4_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 4 Control Register (R/W) */
  { NDS7_SOUND4_SAD, "SOUND4_SAD", { 0 }}, /* Sound Channel 4 Data Source Register (W) */
  { NDS7_SOUND4_TMR, "SOUND4_TMR", { 0 }}, /* Sound Channel 4 Timer Register (W) */
  { NDS7_SOUND4_PNT, "SOUND4_PNT", { 0 }}, /* Sound Channel 4 Loopstart Register (W) */
  { NDS7_SOUND4_LEN, "SOUND4_LEN", { 0 }}, /* Sound Channel 4 Length Register (W) */
  { NDS7_SOUND5_CNT, "SOUND5_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 5 Control Register (R/W) */
  { NDS7_SOUND5_SAD, "SOUND5_SAD", { 0 }}, /* Sound Channel 5 Data Source Register (W) */
  { NDS7_SOUND5_TMR, "SOUND5_TMR", { 0 }}, /* Sound Channel 5 Timer Register (W) */
  { NDS7_SOUND5_PNT, "SOUND5_PNT", { 0 }}, /* Sound Channel 5 Loopstart Register (W) */
  { NDS7_SOUND5_LEN, "SOUND5_LEN", { 0 }}, /* Sound Channel 5 Length Register (W) */
  { NDS7_SOUND6_CNT, "SOUND6_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 6 Control Register (R/W) */
  { NDS7_SOUND6_SAD, "SOUND6_SAD", { 0 }}, /* Sound Channel 6 Data Source Register (W) */
  { NDS7_SOUND6_TMR, "SOUND6_TMR", { 0 }}, /* Sound Channel 6 Timer Register (W) */
  { NDS7_SOUND6_PNT, "SOUND6_PNT", { 0 }}, /* Sound Channel 6 Loopstart Register (W) */
  { NDS7_SOUND6_LEN, "SOUND6_LEN", { 0 }}, /* Sound Channel 6 Length Register (W) */
  { NDS7_SOUND7_CNT, "SOUND7_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 7 Control Register (R/W) */
  { NDS7_SOUND7_SAD, "SOUND7_SAD", { 0 }}, /* Sound Channel 7 Data Source Register (W) */
  { NDS7_SOUND7_TMR, "SOUND7_TMR", { 0 }}, /* Sound Channel 7 Timer Register (W) */
  { NDS7_SOUND7_PNT, "SOUND7_PNT", { 0 }}, /* Sound Channel 7 Loopstart Register (W) */
  { NDS7_SOUND7_LEN, "SOUND7_LEN", { 0 }}, /* Sound Channel 7 Length Register (W) */
  { NDS7_SOUND8_CNT, "SOUND8_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 8 Control Register (R/W) */
  { NDS7_SOUND8_SAD, "SOUND8_SAD", { 0 }}, /* Sound Channel 8 Data Source Register (W) */
  { NDS7_SOUND8_TMR, "SOUND8_TMR", { 0 }}, /* Sound Channel 8 Timer Register (W) */
  { NDS7_SOUND8_PNT, "SOUND8_PNT", { 0 }}, /* Sound Channel 8 Loopstart Register (W) */
  { NDS7_SOUND8_LEN, "SOUND8_LEN", { 0 }}, /* Sound Channel 8 Length Register (W) */
  { NDS7_SOUND9_CNT, "SOUND9_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 9 Control Register (R/W) */
  { NDS7_SOUND9_SAD, "SOUND9_SAD", { 0 }}, /* Sound Channel 9 Data Source Register (W) */
  { NDS7_SOUND9_TMR, "SOUND9_TMR", { 0 }}, /* Sound Channel 9 Timer Register (W) */
  { NDS7_SOUND9_PNT, "SOUND9_PNT", { 0 }}, /* Sound Channel 9 Loopstart Register (W) */
  { NDS7_SOUND9_LEN, "SOUND9_LEN", { 0 }}, /* Sound Channel 9 Length Register (W) */
  { NDS7_SOUNDA_CNT, "SOUNDA_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 10 Control Register (R/W) */
  { NDS7_SOUNDA_SAD, "SOUNDA_SAD", { 0 }}, /* Sound Channel 10 Data Source Register (W) */
  { NDS7_SOUNDA_TMR, "SOUNDA_TMR", { 0 }}, /* Sound Channel 10 Timer Register (W) */
  { NDS7_SOUNDA_PNT, "SOUNDA_PNT", { 0 }}, /* Sound Channel 10 Loopstart Register (W) */
  { NDS7_SOUNDA_LEN, "SOUNDA_LEN", { 0 }}, /* Sound Channel 10 Length Register (W) */
  { NDS7_SOUNDB_CNT, "SOUNDB_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 11 Control Register (R/W) */
  { NDS7_SOUNDB_SAD, "SOUNDB_SAD", { 0 }}, /* Sound Channel 11 Data Source Register (W) */
  { NDS7_SOUNDB_TMR, "SOUNDB_TMR", { 0 }}, /* Sound Channel 11 Timer Register (W) */
  { NDS7_SOUNDB_PNT, "SOUNDB_PNT", { 0 }}, /* Sound Channel 11 Loopstart Register (W) */
  { NDS7_SOUNDB_LEN, "SOUNDB_LEN", { 0 }}, /* Sound Channel 11 Length Register (W) */
  { NDS7_SOUNDC_CNT, "SOUNDC_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 12 Control Register (R/W) */
  { NDS7_SOUNDC_SAD, "SOUNDC_SAD", { 0 }}, /* Sound Channel 12 Data Source Register (W) */
  { NDS7_SOUNDC_TMR, "SOUNDC_TMR", { 0 }}, /* Sound Channel 12 Timer Register (W) */
  { NDS7_SOUNDC_PNT, "SOUNDC_PNT", { 0 }}, /* Sound Channel 12 Loopstart Register (W) */
  { NDS7_SOUNDC_LEN, "SOUNDC_LEN", { 0 }}, /* Sound Channel 12 Length Register (W) */
  { NDS7_SOUNDD_CNT, "SOUNDD_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 13 Control Register (R/W) */
  { NDS7_SOUNDD_SAD, "SOUNDD_SAD", { 0 }}, /* Sound Channel 13 Data Source Register (W) */
  { NDS7_SOUNDD_TMR, "SOUNDD_TMR", { 0 }}, /* Sound Channel 13 Timer Register (W) */
  { NDS7_SOUNDD_PNT, "SOUNDD_PNT", { 0 }}, /* Sound Channel 13 Loopstart Register (W) */
  { NDS7_SOUNDD_LEN, "SOUNDD_LEN", { 0 }}, /* Sound Channel 13 Length Register (W) */
  { NDS7_SOUNDE_CNT, "SOUNDE_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 14 Control Register (R/W) */
  { NDS7_SOUNDE_SAD, "SOUNDE_SAD", { 0 }}, /* Sound Channel 14 Data Source Register (W) */
  { NDS7_SOUNDE_TMR, "SOUNDE_TMR", { 0 }}, /* Sound Channel 14 Timer Register (W) */
  { NDS7_SOUNDE_PNT, "SOUNDE_PNT", { 0 }}, /* Sound Channel 14 Loopstart Register (W) */
  { NDS7_SOUNDE_LEN, "SOUNDE_LEN", { 0 }}, /* Sound Channel 14 Length Register (W) */
  { NDS7_SOUNDF_CNT, "SOUNDF_CNT", {  
    { 0, 7, "Volume Mul (0..127=silent..loud)" },
    { 7, 1, "Not used (always zero)" },
    { 8, 2, "Volume Div (0=Normal, 1=Div2, 2=Div4, 3=Div16)" },
    { 10,5, "Not used (always zero)" },
    { 15,1, "Hold (0=Normal, 1=Hold last sample after one-shot sound)" },
    { 16,7, "Panning (0..127=left..right) (64=half volume on both speakers)" },
    { 23,1, "Not used (always zero)" },
    { 24,3, "Wave Duty (0..7) ;HIGH=(N+1)*12.5%, LOW=(7-N)*12.5% (PSG only)" },
    { 27,2, "Repeat Mode (0=Manual, 1=Loop Infinite, 2=One-Shot, 3=Prohibited)" },
    { 29,2, "Format (0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise)" },
    { 31,1, "Start/Status (0=Stop, 1=Start/Busy)" },
  }}, /* Sound Channel 15 Control Register (R/W) */
  { NDS7_SOUNDF_SAD, "SOUNDF_SAD", { 0 }}, /* Sound Channel 15 Data Source Register (W) */
  { NDS7_SOUNDF_TMR, "SOUNDF_TMR", { 0 }}, /* Sound Channel 15 Timer Register (W) */
  { NDS7_SOUNDF_PNT, "SOUNDF_PNT", { 0 }}, /* Sound Channel 15 Loopstart Register (W) */
  { NDS7_SOUNDF_LEN, "SOUNDF_LEN", { 0 }}, /* Sound Channel 15 Length Register (W) */

  { NDS7_SOUNDCNT,   "SOUNDCNT",   { 0 }}, /* Sound Control Register (R/W) */
  { NDS7_SOUNDBIAS,  "SOUNDBIAS",  { 0 }}, /* Sound Bias Register (R/W) */
  { NDS7_SNDCAP0CNT, "SNDCAP0CNT", {
    {0,1, "Output Sound Channel 1 (0=As is, 1=Add to Channel 0)"},
    {1,1, "Capture 0 Source (0=Left Mixer, 1=Channel 0/Bugged)"},
    {2,1, "Capture Repeat        (0=Loop, 1=One-shot)"},
    {3,1, "Capture Format        (0=PCM16, 1=PCM8)"},
    {7,1, "Capture Start/Status  (0=Stop, 1=Start/Busy)"},
  }}, /* Sound Capture 0 Control Register (R/W) */
  { NDS7_SNDCAP1CNT, "SNDCAP1CNT", { 
    {0,1, "Output Sound Channel 3 (0=As is, 1=Add to Channel 2)"},
    {1,1, "Capture 1 Source (0=Left Mixer, 1=Channel 0/Bugged)"},
    {2,1, "Capture Repeat        (0=Loop, 1=One-shot)"},
    {3,1, "Capture Format        (0=PCM16, 1=PCM8)"},
    {7,1, "Capture Start/Status  (0=Stop, 1=Start/Busy)"},
  }}, /* Sound Capture 1 Control Register (R/W) */
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

#define NDS_VRAM_BGA_SLOT0 0x06900000
#define NDS_VRAM_BGB_SLOT0 0x06A00000
#define NDS_VRAM_OBJA_SLOT0 0x06B00000
#define NDS_VRAM_OBJB_SLOT0 0x06C00000
#define NDS_VRAM_TEX_SLOT0  0x06D00000
#define NDS_VRAM_TEX_SLOT1  (0x06D00000 + 128*1024)
#define NDS_VRAM_TEX_PAL_SLOT0  0x06E00000

#define NDS_VRAM_SLOT_OFF    0x20000
#define NDS_ARM9 1
#define NDS_ARM7 0

#define NDS_GXFIFO_SIZE 256
#define NDS_GXFIFO_STORAGE 512
#define NDS_GXFIFO_MASK 0x1ff
#define NDS_GPU_MAX_PARAM 64
#define NDS_GX_DMA_THRESHOLD 128

typedef struct {     
  uint8_t ram[4*1024*1024]; /*4096KB Main RAM (8192KB in debug version)*/
  uint8_t wram[96*1024];    /*96KB   WRAM (64K mapped to NDS7, plus 32K mappable to NDS7 or NDS9)*/
  /* TCM/Cache (TCM: 16K Data, 32K Code) (Cache: 4K Data, 8K Code) */
  uint8_t code_tcm[32*1024];
  uint8_t data_tcm[16*1024];
  uint8_t code_cache[8*1024];
  uint8_t data_cache[4*1024];
  uint8_t vram[1024*1024];    /* VRAM (allocateable as BG/OBJ/2D/3D/Palette/Texture/WRAM memory) */
  uint64_t vram_translation_cache[1024];
  uint8_t palette[2*1024];   
  uint8_t *save_data;

  uint8_t oam[4*1024];       /* OAM/PAL (2K OBJ Attribute Memory, 2K Standard Palette RAM) */
  /* BIOS ROM (4K NDS9, 16K NDS7, 16K GBA) */
  uint8_t *nds7_bios;
  uint8_t *nds9_bios;
  /* Firmware FLASH (512KB in iQue variant, with chinese charset) */
  uint8_t *firmware;
  uint8_t io[64*1024];
  uint8_t mmio_debug_access_buffer[16*1024];

  uint8_t *card_data;
  size_t card_size;
  uint8_t card_transfer_data[0x1000];
  uint32_t card_chip_id;
  int card_read_offset;
  int card_transfer_bytes;
  int transfer_id;
  uint8_t wait_state_table[16*4];
  bool prefetch_en;
  int prefetch_size;
  uint64_t curr_vram_translation_key; 
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
typedef struct{
  uint8_t nds7_bios[16*1024];
  uint8_t nds9_bios[4*1024];
  /* Firmware FLASH (512KB in iQue variant, with chinese charset) */
  uint8_t firmware[NDS_FIRMWARE_SIZE];
  uint8_t save_data[8*1024*1024];
  uint8_t framebuffer_top[NDS_LCD_W*NDS_LCD_H*4];
  uint8_t framebuffer_bottom[NDS_LCD_W*NDS_LCD_H*4];
  float framebuffer_3d_depth[NDS_LCD_W*NDS_LCD_H];
  uint8_t framebuffer_3d[NDS_LCD_W*NDS_LCD_H*4];
  uint8_t framebuffer_3d_disp[NDS_LCD_W*NDS_LCD_H*4];
}nds_scratch_t; 

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
  uint32_t gx_dma_subtransfer; 
  uint16_t trigger_mode; 
} nds_dma_t; 
typedef struct{
  int scan_clock; 
  bool last_vblank;
  bool last_hblank;
  bool last_vcmp;
  bool last_vcmp7;
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
  bool new_frame;
}nds_ppu_t;
typedef struct{
  bool last_enable; 
  uint16_t reload_value; 
  uint16_t pending_reload_value; 
  uint16_t prescaler_timer;
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
  uint8_t last_device;
}nds_spi_t;
typedef struct{
  uint8_t state; 
  uint8_t cmd;
  uint32_t addr;
  bool write_enable;
}nds_flash_t;
typedef struct{
  nds_flash_t flash;
  uint8_t command[8];
  uint32_t backup_type; 
  int command_offset; 
  bool write_enable;
  uint8_t status_reg;
  bool is_dirty;
}nds_card_backup_t;
typedef struct{
  uint16_t x_reg, y_reg; 
  uint16_t tx_reg; 
}nds_touch_t; 
typedef struct{
  double current_sim_time;
  double current_sample_generated_time;
  uint32_t cycles_since_tick;
  struct{
    uint32_t timer;
    uint32_t sample;
    int32_t adpcm_sample;
    int32_t adpcm_index;
  }channel[16];

}nds_audio_t; 

#define NDS_MATRIX_PROJ 0
#define NDS_MATRIX_MV 1
#define NDS_MATRIX_TBD 2 //<- TODO: Future Sky problem
#define NDS_MATRIX_TEX 3

#define NDS_MAX_VERTS 8192*16

typedef struct{
  float pos[4];
  float clip_pos[3];
  uint8_t color[3];
  float tex[2];
}nds_vert_t;
typedef struct{
  uint32_t fifo_data[NDS_GXFIFO_STORAGE];
  uint8_t fifo_cmd[NDS_GXFIFO_STORAGE];
  uint32_t fifo_read_ptr, fifo_write_ptr;
  nds_vert_t vert_buffer[NDS_MAX_VERTS];
  uint32_t curr_vert; 
  uint32_t curr_draw_vert; 
  uint32_t prim_type;

  float proj_matrix[16];
  float tex_matrix[16];
  float mv_matrix[16];
  float normal_matrix[16];

  float proj_matrix_stack[16*2];
  float tex_matrix_stack[16*2];
  float mv_matrix_stack[16*32];
  float normal_matrix_stack[16*32];
  uint8_t curr_color[4];
  uint8_t curr_ambient_color[3];
  uint8_t curr_diffuse_color[3];
  int16_t curr_tex_coord[2];
  int16_t last_vertex_pos[3];
  int matrix_mode; 
  int mv_matrix_stack_ptr;
  int proj_matrix_stack_ptr;
  int tex_matrix_stack_ptr;
  uint32_t cmd_busy_cycles;
  uint32_t packed_cmd; 
  uint8_t packed_cmd_param;
  bool matrix_stack_error;
  uint32_t tex_image_param;
  uint32_t tex_plt_base;
  uint32_t poly_attr;
  uint32_t poly_ram_offset;
  bool pending_swap;
  uint32_t rendered_primitive_tracker; 
}nds_gpu_t; 

typedef struct{
  nds_mem_t mem;
  arm7_t arm7;
  arm7_t arm9;
  nds_card_t card;
  nds_input_t joy;       
  nds_ppu_t ppu[2];
  nds_gpu_t gpu;
  nds_rtc_t rtc;
  nds_dma_t dma[2][4]; 
  nds_ipc_t ipc[2];
  nds_system_control_processor cp15;
  nds_math_t math; 
  nds_spi_t spi; 
  nds_flash_t firmware;
  nds_touch_t touch;
  nds_audio_t audio;
  nds_card_backup_t backup;
  //There is a 2 cycle penalty when the CPU takes over from the DMA
  bool last_transaction_dma; 
  bool activate_dmas; 
  bool dma_wait_gx;
  bool dma_wait_ppu;
  bool dma_processed[2];
  bool display_flip;
  nds_timer_t timers[2][4];
  uint32_t timer_ticks_before_event;
  uint32_t deferred_timer_ticks;
  bool prev_key_interrupt;
  // Some HW has up to a 4 cycle delay before its IF propagates. 
  // This array acts as a FIFO to keep track of that. 
  uint32_t nds9_pipelined_if[5];
  uint32_t nds7_pipelined_if[5];
  int active_if_pipe_stages; 
  char save_file_path[SB_FILE_PATH_SIZE];

  uint8_t *framebuffer_top;
  uint8_t *framebuffer_bottom;
  float *framebuffer_3d_depth;
  uint8_t *framebuffer_3d;
  uint8_t *framebuffer_3d_disp;
  uint64_t current_clock;
  float ghosting_strength;
  int ppu_fast_forward_ticks;
  FILE * gx_log;
  FILE * io9_log;
  FILE * io7_log;
  FILE * gc_log;
  FILE * dma_log;
  FILE * vert_log;
} nds_t; 

static void nds_tick_keypad(sb_joy_t*joy, nds_t* nds); 
static void nds_tick_touch(sb_joy_t*joy, nds_t* nds); 
static FORCE_INLINE void nds_tick_timers(nds_t* nds);
static FORCE_INLINE int nds_cycles_till_vblank(nds_t*nds);
static void nds_compute_timers(nds_t* nds); 
static uint32_t nds_get_save_size(nds_t*nds);
static uint8_t nds_process_flash_write(nds_t *nds, uint8_t write_data, nds_flash_t* flash, uint8_t *flash_data, uint32_t flash_size);

static void FORCE_INLINE nds9_send_interrupt(nds_t*nds,int delay,int if_bit){
  nds->active_if_pipe_stages|=1<<delay;
  nds->nds9_pipelined_if[delay]|= if_bit;
}
static void FORCE_INLINE nds7_send_interrupt(nds_t*nds,int delay,int if_bit){
  nds->active_if_pipe_stages|=1<<delay;
  nds->nds7_pipelined_if[delay]|= if_bit;
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
static FORCE_INLINE uint32_t nds7_read32(nds_t*nds, unsigned baddr);
static FORCE_INLINE uint32_t nds9_read32(nds_t*nds, unsigned baddr);

static FORCE_INLINE sb_debug_mmio_access_t nds_debug_mmio_access(nds_t*nds, int cpu, unsigned baddr, int trigger_breakpoint){
  if(baddr>=0x04100000)baddr+=NDS_IO_MAP_041_OFFSET;
  if(cpu==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  baddr&=0xffff;
  baddr/=4;

  if(trigger_breakpoint!=-1){
    nds->mem.mmio_debug_access_buffer[baddr]&=0x7f;
    if(trigger_breakpoint!=0)nds->mem.mmio_debug_access_buffer[baddr]|=0x80;
  }
  uint8_t flag = nds->mem.mmio_debug_access_buffer[baddr];

  sb_debug_mmio_access_t access; 
  access.read_since_reset = flag&0x1;
  access.read_in_tick = flag&0x2;

  access.write_since_reset = flag&0x10;
  access.write_in_tick = flag&0x20;
  access.trigger_breakpoint = flag&0x80;
  return access; 
}
static FORCE_INLINE void nds7_io_store8(nds_t*nds, unsigned baddr, uint8_t data){
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  nds->mem.io[baddr&0xffff]=data;
}
static FORCE_INLINE void nds7_io_store16(nds_t*nds, unsigned baddr, uint16_t data){
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint16_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE void nds7_io_store32(nds_t*nds, unsigned baddr, uint32_t data){
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint32_t*)(nds->mem.io+(baddr&0xffff))=data;
}

static FORCE_INLINE uint8_t  nds7_io_read8(nds_t*nds, unsigned baddr) {
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return nds->mem.io[baddr&0xffff];
}
static FORCE_INLINE uint16_t nds7_io_read16(nds_t*nds, unsigned baddr){
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint16_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE uint32_t nds7_io_read32(nds_t*nds, unsigned baddr){
  baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint32_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE void nds_io_store8(nds_t*nds,int cpu_id, unsigned baddr, uint8_t data){
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  nds->mem.io[baddr&0xffff]=data;
}
static FORCE_INLINE void nds_io_store16(nds_t*nds,int cpu_id, unsigned baddr, uint16_t data){
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint16_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE void nds_io_store32(nds_t*nds,int cpu_id, unsigned baddr, uint32_t data){
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  *(uint32_t*)(nds->mem.io+(baddr&0xffff))=data;
}
static FORCE_INLINE uint8_t  nds_io_read8(nds_t*nds,int cpu_id, unsigned baddr) {
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return nds->mem.io[baddr&0xffff];
}
static FORCE_INLINE uint16_t nds_io_read16(nds_t*nds,int cpu_id, unsigned baddr){
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint16_t*)(nds->mem.io+(baddr&0xffff));
}
static FORCE_INLINE uint32_t nds_io_read32(nds_t*nds,int cpu_id, unsigned baddr){
  if(cpu_id==NDS_ARM7)baddr+=NDS_IO_MAP_SPLIT_OFFSET;
  return *(uint32_t*)(nds->mem.io+(baddr&0xffff));
}

#define NDS_MEM_1B 0x1
#define NDS_MEM_2B 0x2
#define NDS_MEM_4B 0x4

#define NDS_MEM_WRITE 0x10
#define NDS_MEM_SEQ   0x20
#define NDS_MEM_ARM7  0x40
#define NDS_MEM_ARM9  0x80
#define NDS_MEM_PPU   0x100
#define NDS_MEM_DEBUG 0x200
#define NDS_MEM_CPU   0x400

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
  //1Byte writes are ignored from the ARM9
  const int ignore_write_mask = (NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM9);
  if((transaction_type&ignore_write_mask)==ignore_write_mask)return 0;

  int lookup_addr = SB_BFE(address,14,10);
  uint64_t key = nds->mem.vram_translation_cache[lookup_addr];
  if((key&~(1023))==nds->mem.curr_vram_translation_key){
    int vram_addr = ((key&1023)*16*1024)+SB_BFE(address,0,14);
    if(transaction_type&NDS_MEM_4B){
      vram_addr&=~3;
      if(transaction_type&NDS_MEM_WRITE)return *(uint32_t*)(nds->mem.vram+vram_addr)=data;
      return *(uint32_t*)(nds->mem.vram+vram_addr);
    }else if(transaction_type&NDS_MEM_2B){
      vram_addr&=~1;
      if(transaction_type&NDS_MEM_WRITE)return *(uint16_t*)(nds->mem.vram+vram_addr)=data;
      return *(uint16_t*)(nds->mem.vram+vram_addr);
    }else{
      if(transaction_type&NDS_MEM_WRITE)return nds->mem.vram[vram_addr]=data;
      return nds->mem.vram[vram_addr];
    }
  }
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
  const uint32_t offset_table[10][5]={
    {0,0,0,0}, //Offset ignored
    {0x20000*0, 0x20000*1, 0x20000*2,0x20000*3}, //(0x20000*OFS)
    {0x0, 0x4000, 0x10000,0x14000}, //(4000h*OFS.0)+(10000h*OFS.1)
    {NDS_VRAM_SLOT_OFF*0, NDS_VRAM_SLOT_OFF*1, NDS_VRAM_SLOT_OFF*2,NDS_VRAM_SLOT_OFF*3}, // Slot 0-3 (mirrored)
    {NDS_VRAM_SLOT_OFF*0, NDS_VRAM_SLOT_OFF*2, NDS_VRAM_SLOT_OFF*0,NDS_VRAM_SLOT_OFF*2}, // Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
    {NDS_VRAM_SLOT_OFF*0, NDS_VRAM_SLOT_OFF*1, NDS_VRAM_SLOT_OFF*4,NDS_VRAM_SLOT_OFF*5}, // Slot (OFS.0*1)+(OFS.1*4)
    {0x20000*0, 0x20000*1, 0x20000*2,0x20000*3}, //(0x20000*OFS)
    {0x10000*0, 0x10000*1, 0x10000*2,0x10000*3}, //   E       64K   4    -     Slot 0-3  ;only lower 32K used 
    {0x4000*0, 0x4000*1, 0x4000*0,0x4000*1}, // 16KB slot
    {16*1024*0, 16*1024*1, 16*1024*4,16*1024*5}, // Slot (OFS.0*1)+(OFS.1*4)
  };
  typedef struct vram_bank_info_t{
    int transaction_mask; // Block transactions of these types
    int offset_table;
    uint32_t mem_address_start;
    int size; 
  }vram_bank_info_t;

  const static vram_bank_info_t bank_info[9][8]={
    { //Bank A 
      {NDS_MEM_ARM7, 0, 0x06800000}, //MST 0 6800000h-681FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM7, 6, 0x06400000}, //MST 2 6400000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06800000}, //MST 4
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 5 
      {NDS_MEM_ARM7, 6, 0x06400000}, //MST 6 
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 7
    },{ //Bank B
      {NDS_MEM_ARM7, 0, 0x06820000}, //MST 0 6820000h-683FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM7, 6, 0x06400000}, //MST 2 6400000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06820000}, //MST 4
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 5 
      {NDS_MEM_ARM7, 6, 0x06400000}, //MST 6 
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 7
    },{ //Bank C
      {NDS_MEM_ARM7, 0, 0x06840000}, //MST 0 6840000h-685FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM9|NDS_MEM_PPU, 6, 0x06000000}, //MST 2 6000000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 4 6200000h
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank D
      {NDS_MEM_ARM7, 0, 0x06860000}, //MST 0 6860000h-687FFFFh
      {NDS_MEM_ARM7, 1, 0x06000000}, //MST 1 6000000h+(20000h*OFS)
      {NDS_MEM_ARM9|NDS_MEM_PPU, 6, 0x06000000}, //MST 2 6000000h+(20000h*OFS.0)  ;OFS.1 must be zero
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 6, NDS_VRAM_TEX_SLOT0}, //MST 3 Slot OFS(0-3)   ;(Slot2-3: Texture, or Rear-plane)
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 4 6600000h
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank E
      {NDS_MEM_ARM7, 0, 0x06880000}, //MST 0 6880000h-688FFFFh
      {NDS_MEM_ARM7, 0, 0x06000000}, //MST 1 6000000h
      {NDS_MEM_ARM7, 0, 0x06400000}, //MST 2 6400000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_TEX_PAL_SLOT0}, //MST 3 Slots 0-3;OFS=don't care
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_BGA_SLOT0}, //MST 4 (64K Slot 0-3  ;only lower 32K used)
      {0xffffffff, 0, 0x0}, // MST 5 INVALID
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank F
      {NDS_MEM_ARM7, 0, 0x06890000}, //MST 0 6890000h-6893FFFh
      {NDS_MEM_ARM7, 2, 0x06000000}, //MST 1 6000000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7, 2, 0x06400000}, //MST 2 6400000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 9, NDS_VRAM_TEX_PAL_SLOT0}, //MST 3 Slot (OFS.0*1)+(OFS.1*4)  ;ie. Slot 0, 1, 4, or 5
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 8, NDS_VRAM_BGA_SLOT0}, //MST 4 0..1  Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_OBJA_SLOT0}, //MST 5 Slot 0  ;16K each (only lower 8K used)
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank G
      {NDS_MEM_ARM7, 0, 0x06894000}, //MST 0 6894000h-6897FFFh
      {NDS_MEM_ARM7, 2, 0x06000000}, //MST 1 6000000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7, 2, 0x06400000}, //MST 2 6400000h+(4000h*OFS.0)+(10000h*OFS.1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 9, NDS_VRAM_TEX_PAL_SLOT0}, //MST3 Slot (OFS.0*1)+(OFS.1*4)  ;ie. Slot 0, 1, 4, or 5
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 8, NDS_VRAM_BGA_SLOT0}, //MST 4 0..1  Slot 0-1 (OFS=0), Slot 2-3 (OFS=1)
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_OBJA_SLOT0}, //MST 5 Slot 0  ;16K each (only lower 8K used)
      {0xffffffff, 0, 0x0}, // MST 6 INVALID
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank H
      {NDS_MEM_ARM7, 0, 0x06898000}, //MST 0 6898000h-689FFFFh
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 1 6200000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_BGB_SLOT0}, //MST 2 Slot 0-3
      {0xffffffff, 0, 0x0}, // MST 3 INVALID
      {NDS_MEM_ARM7, 0, 0x06898000}, //MST 4 6898000h-689FFFFh
      {NDS_MEM_ARM7, 0, 0x06200000}, //MST 5 6200000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_BGB_SLOT0}, //MST 6 Slot 0-3
      {0xffffffff, 0, 0x0}, // MST 7 INVALID
    },{ //Bank I
      {NDS_MEM_ARM7, 0, 0x068A0000}, //MST 0 68A0000h-68A3FFFh
      {NDS_MEM_ARM7, 0, 0x06208000}, //MST 1 6208000h
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 2 6600000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_OBJB_SLOT0}, //MST 3 Slot 0  ;16K each (only lower 8K used)
      {NDS_MEM_ARM7, 0, 0x068A0000}, //MST 4 68A0000h-68A3FFFh
      {NDS_MEM_ARM7, 0, 0x06208000}, //MST 5 6208000h
      {NDS_MEM_ARM7, 0, 0x06600000}, //MST 6 6600000h
      {NDS_MEM_ARM7|NDS_MEM_ARM9, 0, NDS_VRAM_OBJB_SLOT0}, //MST 7 Slot 0  ;16K each (only lower 8K used)
    }
  };
  int total_banks = 9;
  int vram_offset = 0; 

  bool special_case_multiple_found = false;
  uint32_t ret_data=0;

  for(int b = 0; b<total_banks;++b){
    int vram_off = vram_offset;
    vram_offset +=bank_size[b];
    const static int vram_cnt_array[]={
      NDS9_VRAMCNT_A,
      NDS9_VRAMCNT_B,
      NDS9_VRAMCNT_C,
      NDS9_VRAMCNT_D,
      NDS9_VRAMCNT_E,
      NDS9_VRAMCNT_F,
      NDS9_VRAMCNT_G,
      NDS9_VRAMCNT_H, //These are not contiguous
      NDS9_VRAMCNT_I, //These are not contiguous
    };
    uint8_t vramcnt = nds9_io_read8(nds,vram_cnt_array[b]);
    bool enable = SB_BFE(vramcnt,7,1);
    int mst = SB_BFE(vramcnt,0,3);
    int off = SB_BFE(vramcnt,3,2);
    if(!enable)continue;

    const vram_bank_info_t bank = bank_info[b][mst];
    if(transaction_type& bank.transaction_mask)continue;

    int base = bank.mem_address_start;
    base += offset_table[bank.offset_table][off];
    if(address<base)continue;

    int bank_offset = address-base; 
    if(bank_offset>=bank_size[b])continue;

    int vram_addr = bank_offset+vram_off;

    if(special_case_multiple_found)nds->mem.vram_translation_cache[lookup_addr]=0;
    else nds->mem.vram_translation_cache[lookup_addr] = nds->mem.curr_vram_translation_key | SB_BFE(vram_addr,14,10);
  
    special_case_multiple_found = true;
    
    if(transaction_type&NDS_MEM_4B){
      vram_addr&=~3;
      if(transaction_type&NDS_MEM_WRITE)*(uint32_t*)(nds->mem.vram+vram_addr)=data;
      else ret_data |= *(uint32_t*)(nds->mem.vram+vram_addr);
    }else if(transaction_type&NDS_MEM_2B){
      vram_addr&=~1;
      if(transaction_type&NDS_MEM_WRITE)*(uint16_t*)(nds->mem.vram+vram_addr)=data;
      else ret_data |= *(uint16_t*)(nds->mem.vram+vram_addr);
    }else{
      if(transaction_type&NDS_MEM_WRITE)nds->mem.vram[vram_addr]=data;
      else ret_data |= nds->mem.vram[vram_addr];
    }
  }
  return ret_data; 
}

static bool nds_preprocess_mmio(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type);
static void nds_postprocess_mmio_write(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type);
static uint32_t nds9_process_memory_transaction(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type){
  uint32_t *ret = &nds->mem.openbus_word;
  switch(addr>>24){
    case 0x2: //Main RAM
      addr&=4*1024*1024-1;
      *ret = nds_apply_mem_op(nds->mem.ram, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
    case 0x3: //Shared WRAM 
      {
        uint32_t orig_addr = addr;
        uint8_t cnt = nds9_io_read8(nds,NDS9_WRAMCNT)&0x3;
        const int offset[4]={0,16*1024,0,0};
        const int mask[4]={32*1024-1,16*1024-1,16*1024-1,0};
        if(cnt==3)break;
        addr=(addr&mask[cnt])+offset[cnt];
        *ret = nds_apply_mem_op(nds->mem.wram, addr, data, transaction_type); 
        nds->mem.openbus_word=*ret;
      }
      break;
    case 0x4: 
        if((addr&0xffff)>=0x2000||addr>=0x04200000){*ret = 0; return *ret;}
        if(addr >=0x04100000&&addr <0x04200000){addr|=NDS_IO_MAP_041_OFFSET;}
        bool process_write = nds_preprocess_mmio(nds,addr,data,transaction_type);
        int baddr =addr&0xffff;
        if(process_write)*ret = nds_apply_mem_op(nds->mem.io, baddr, data, transaction_type); 
        if(!(transaction_type&NDS_MEM_DEBUG)){
          nds->mem.mmio_debug_access_buffer[baddr/4]|=(transaction_type&NDS_MEM_WRITE)?0x70:0xf;
          if(nds->mem.mmio_debug_access_buffer[baddr/4]&0x80)nds->arm7.trigger_breakpoint =true;
        }
        nds->mem.openbus_word=*ret;
        if((transaction_type&NDS_MEM_WRITE)){
          nds_postprocess_mmio_write(nds,addr,data,transaction_type);
        }
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
    case 0xFF: 
      if(addr>=0xFFFF0000){
        addr&=4*1024-1;
        *ret = nds_apply_mem_op(nds->mem.nds9_bios, addr, data, transaction_type&~NDS_MEM_WRITE); 
      }
      break;
  }
  return *ret; 
}
static uint32_t nds9_process_memory_transaction_cpu(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type){
  uint32_t *ret = &nds->mem.openbus_word;
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
  return nds9_process_memory_transaction(nds,addr,data,transaction_type);
}
static uint32_t nds7_process_memory_transaction(nds_t * nds, uint32_t addr, uint32_t data, int transaction_type){
  uint32_t *ret = &nds->mem.openbus_word;
  switch(addr>>24){
      case 0x0: //BIOS(NDS7), TCM(NDS9)
      if(addr<0x4000){
        if(nds->arm7.registers[PC]<0x4000)
          nds->mem.arm7_bios_word = nds_apply_mem_op(nds->mem.nds7_bios,addr,data,transaction_type&~NDS_MEM_WRITE);
        //else nds->mem.bios_word=0;
        *ret = nds->mem.openbus_word=nds->mem.arm7_bios_word;
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
        if(addr<=0x037FFFFF){
          const int offset[4]={0,0,16*1024,0};
          const int mask[4]={0,16*1024-1,16*1024-1,32*1024-1};
          if(mask[cnt]==0)addr= 32*1024+((addr)&(64*1024-1));
          else            addr=(addr&mask[cnt])+offset[cnt];
        }else addr= 32*1024+((addr-0x03800000)&(64*1024-1));
        *ret = nds_apply_mem_op(nds->mem.wram, addr, data, transaction_type); 
        nds->mem.openbus_word=*ret;
      }
      break;
    case 0x4: 
        if((addr&0xffff)>=0x2000){*ret = 0; return *ret;}
        if(addr >=0x04100000&&addr <0x04200000){addr|=NDS_IO_MAP_041_OFFSET;}
        if(addr>=0x04200000)break;
        bool process_write = nds_preprocess_mmio(nds,addr,data,transaction_type);
        int baddr =addr|NDS_IO_MAP_SPLIT_OFFSET;
        baddr&=0xffff;
        if(process_write)*ret = nds_apply_mem_op(nds->mem.io, baddr, data, transaction_type); 
        if(!(transaction_type&NDS_MEM_DEBUG)){
          nds->mem.mmio_debug_access_buffer[baddr/4]|=(transaction_type&NDS_MEM_WRITE)?0x70:0xf;
          if(nds->mem.mmio_debug_access_buffer[baddr/4]&0x80)nds->arm7.trigger_breakpoint =true;
        }
        nds->mem.openbus_word=*ret;
        if((transaction_type&NDS_MEM_WRITE)){
          nds_postprocess_mmio_write(nds,addr,data,transaction_type);
        }
        if(SB_UNLIKELY(nds->io7_log)){
          if(addr!=0x04000180){
            const char* dir = (transaction_type&NDS_MEM_WRITE)? "W":"R";
            uint32_t io_data = (transaction_type&NDS_MEM_WRITE)?data:*ret;
            fprintf(nds->io7_log,"%s %08x %08x\n",dir,addr,io_data);
          }
        }
      break;
    case 0x6: //VRAM(NDS9) WRAM(NDS7)
      *ret = nds_apply_vram_mem_op(nds, addr, data, transaction_type); 
      nds->mem.openbus_word=*ret;
      break;
  }
  return *ret; 
}

static FORCE_INLINE void nds9_write32(nds_t*nds, unsigned baddr, uint32_t data){
  nds9_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_4B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write32(nds_t*nds, unsigned baddr, uint32_t data){
  nds7_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_4B|NDS_MEM_ARM7);
}
static FORCE_INLINE void nds9_write16(nds_t*nds, unsigned baddr, uint16_t data){
  nds9_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_2B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write16(nds_t*nds, unsigned baddr, uint16_t data){
  nds7_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_2B|NDS_MEM_ARM7);
}
static FORCE_INLINE void nds9_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds9_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM9);
}
static FORCE_INLINE void nds7_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds7_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM7);
}
static FORCE_INLINE void nds9_debug_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds9_process_memory_transaction_cpu(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM9|NDS_MEM_DEBUG);
}
static FORCE_INLINE void nds7_debug_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds7_process_memory_transaction(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM7|NDS_MEM_DEBUG);
}

static FORCE_INLINE uint32_t nds9_cpu_read32(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction_cpu(nds,baddr,0,NDS_MEM_4B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE uint16_t nds9_cpu_read16(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction_cpu(nds,baddr,0,NDS_MEM_2B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE uint8_t nds9_cpu_read8(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction_cpu(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE void nds9_cpu_write32(nds_t*nds, unsigned baddr, uint32_t data){
  nds9_process_memory_transaction_cpu(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_4B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE void nds9_cpu_write16(nds_t*nds, unsigned baddr, uint16_t data){
  nds9_process_memory_transaction_cpu(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_2B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE void nds9_cpu_write8(nds_t*nds, unsigned baddr, uint8_t data){
  nds9_process_memory_transaction_cpu(nds,baddr,data,NDS_MEM_WRITE|NDS_MEM_1B|NDS_MEM_ARM9|NDS_MEM_CPU);
}
static FORCE_INLINE uint32_t nds9_read32(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction(nds,baddr,0,NDS_MEM_4B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint32_t nds7_read32(nds_t*nds, unsigned baddr){
  return nds7_process_memory_transaction(nds,baddr,0,NDS_MEM_4B|NDS_MEM_ARM7);
}
static FORCE_INLINE uint16_t nds9_read16(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction(nds,baddr,0,NDS_MEM_2B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint16_t nds7_read16(nds_t*nds, unsigned baddr){
  return nds7_process_memory_transaction(nds,baddr,0,NDS_MEM_2B|NDS_MEM_ARM7);
}
static FORCE_INLINE uint8_t nds9_read8(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM9);
}
static FORCE_INLINE uint8_t nds7_read8(nds_t*nds, unsigned baddr){
  return nds7_process_memory_transaction(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM7);
}

static FORCE_INLINE uint8_t nds9_debug_read8(nds_t*nds, unsigned baddr){
  return nds9_process_memory_transaction_cpu(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM9|NDS_MEM_DEBUG);
}
static FORCE_INLINE uint8_t nds7_debug_read8(nds_t*nds, unsigned baddr){
  return nds7_process_memory_transaction(nds,baddr,0,NDS_MEM_1B|NDS_MEM_ARM7|NDS_MEM_DEBUG);
}
static uint32_t nds_apply_vram_mem_op(nds_t *nds,uint32_t address, uint32_t data, int transaction_type);

static FORCE_INLINE uint8_t nds_ppu_read8(nds_t*nds, unsigned baddr){
  return nds_apply_vram_mem_op(nds,baddr,0,NDS_MEM_1B|NDS_MEM_PPU);
}
static FORCE_INLINE uint16_t nds_ppu_read16(nds_t*nds, unsigned baddr){
  return nds_apply_vram_mem_op(nds,baddr,0,NDS_MEM_2B|NDS_MEM_PPU);
}
static FORCE_INLINE uint32_t nds_ppu_read32(nds_t*nds, unsigned baddr){
  return nds_apply_vram_mem_op(nds,baddr,0,NDS_MEM_4B|NDS_MEM_PPU);
}
uint32_t nds9_arm_read32(void* user_data, uint32_t address){return nds9_cpu_read32((nds_t*)user_data,address);}
uint32_t nds9_arm_read16(void* user_data, uint32_t address){return nds9_cpu_read16((nds_t*)user_data,address);}
uint32_t nds9_arm_read32_seq(void* user_data, uint32_t address,bool is_sequential){return nds9_cpu_read32((nds_t*)user_data,address);}
uint32_t nds9_arm_read16_seq(void* user_data, uint32_t address,bool is_sequential){return nds9_cpu_read16((nds_t*)user_data,address);}
uint8_t nds9_arm_read8(void* user_data, uint32_t address){return nds9_cpu_read8((nds_t*)user_data,address);}
void nds9_arm_write32(void* user_data, uint32_t address, uint32_t data){nds9_cpu_write32((nds_t*)user_data,address,data);}
void nds9_arm_write16(void* user_data, uint32_t address, uint16_t data){nds9_cpu_write16((nds_t*)user_data,address,data);}
void nds9_arm_write8(void* user_data, uint32_t address, uint8_t data){nds9_cpu_write8((nds_t*)user_data,address,data);}

uint32_t nds7_arm_read32(void* user_data, uint32_t address){return nds7_read32((nds_t*)user_data,address);}
uint32_t nds7_arm_read16(void* user_data, uint32_t address){return nds7_read16((nds_t*)user_data,address);}
uint32_t nds7_arm_read32_seq(void* user_data, uint32_t address,bool is_sequential){return nds7_read32((nds_t*)user_data,address);}
uint32_t nds7_arm_read16_seq(void* user_data, uint32_t address,bool is_sequential){return nds7_read16((nds_t*)user_data,address);}
uint8_t nds7_arm_read8(void* user_data, uint32_t address){return nds7_read8((nds_t*)user_data,address);}
void nds7_arm_write32(void* user_data, uint32_t address, uint32_t data){nds7_write32((nds_t*)user_data,address,data);}
void nds7_arm_write16(void* user_data, uint32_t address, uint16_t data){nds7_write16((nds_t*)user_data,address,data);}
void nds7_arm_write8(void* user_data, uint32_t address, uint8_t data){nds7_write8((nds_t*)user_data,address,data);}

uint32_t nds_coprocessor_read(void* user_data, int coproc,int opcode,int Cn, int Cm,int Cp);
void nds_coprocessor_write(void* user_data, int coproc,int opcode,int Cn, int Cm,int Cp,uint32_t data);

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
  return 1;
  int bank = SB_BFE(address,24,4);
  uint32_t wait = nds->mem.wait_state_table[bank*4+request_size];
  return wait;
}


// Try to load a GBA rom, return false on invalid rom
bool nds_load_rom(sb_emu_state_t*emu,nds_t* nds, nds_scratch_t* scratch);
static void nds_reset_gpu(nds_t*nds);
void nds_reset(nds_t*nds);
 
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
int nds_rom_db_compare_func(const void* a, const void *b){
  return ((nds_rom_entry_t*)a)->GameCode-*(uint32_t*)b;
}
static void nds_update_vram_mapping(nds_t*nds){
  const static int vram_cnt_array[]={
    NDS9_VRAMCNT_A,
    NDS9_VRAMCNT_B,
    NDS9_VRAMCNT_C,
    NDS9_VRAMCNT_D,
    NDS9_VRAMCNT_E,
    NDS9_VRAMCNT_F,
    NDS9_VRAMCNT_G,
    NDS9_VRAMCNT_H, //These are not contiguous
    NDS9_VRAMCNT_I, //These are not contiguous
  };
  //Recompute VRAM translation key
  nds->mem.curr_vram_translation_key=0; 
  for(int b =0;b<sizeof(vram_cnt_array)/sizeof(vram_cnt_array[0]);++b){
    uint8_t bank_settings = nds9_io_read8(nds,vram_cnt_array[b]);
    uint64_t bank_key = SB_BFE(bank_settings,0,5);
    bank_key|= SB_BFE(bank_settings,7,1)<<5;
    nds->mem.curr_vram_translation_key|= bank_key<<(b*6+10);
  }
  nds->mem.curr_vram_translation_key|=(1ull)<<63;
}
bool nds_load_rom(sb_emu_state_t*emu,nds_t* nds,nds_scratch_t*scratch){
  if(!sb_path_has_file_ext(emu->rom_path, ".nds"))return false; 

  if(emu->rom_size>512*1024*1024){
    printf("ROMs with sizes >512MB (%zu bytes) are too big for the NDS\n",emu->rom_size); 
    return false;
  }  
  if(emu->rom_size<1024){
    printf("ROMs with sizes <1024B (%zu bytes) are too small for the NDS\n",emu->rom_size); 
    return false;
  }
  memset(nds,0,sizeof(nds_t));

  strncpy(nds->save_file_path,emu->save_file_path,SB_FILE_PATH_SIZE);
  nds->save_file_path[SB_FILE_PATH_SIZE-1]=0;
  memset(&nds->mem,0,sizeof(nds->mem));

  nds->mem.card_data=emu->rom_data;
  nds->mem.card_size=emu->rom_size;
  nds->mem.save_data = scratch->save_data;

  memcpy(&nds->card,emu->rom_data,sizeof(nds_card_t));
  nds->card.title[11]=0;

  nds->arm7 = arm7_init(nds);
  nds->arm9 = arm7_init(nds);
  
  for(int bg = 2;bg<4;++bg){
    nds9_io_store16(nds,GBA_BG2PA+(bg-2)*0x10,1<<8);
    nds9_io_store16(nds,GBA_BG2PB+(bg-2)*0x10,0<<8);
    nds9_io_store16(nds,GBA_BG2PC+(bg-2)*0x10,0<<8);
    nds9_io_store16(nds,GBA_BG2PD+(bg-2)*0x10,1<<8);
  }
  //nds_store32(nds,GBA_DISPCNT,0xe92d0000);
  nds9_write16(nds,0x04000088,512);
  nds_recompute_waitstate_table(nds,0);
  nds->activate_dmas=false;
  nds->deferred_timer_ticks=0;
  bool loaded_bios= true;
  if(nds->mem.card_data)memcpy(&nds->card,nds->mem.card_data,sizeof(nds->card));
  loaded_bios&= se_load_bios_file("NDS7 BIOS", nds->save_file_path, "nds7.bin", scratch->nds7_bios,sizeof(scratch->nds7_bios));
  loaded_bios&= se_load_bios_file("NDS9 BIOS", nds->save_file_path, "nds9.bin", scratch->nds9_bios,sizeof(scratch->nds9_bios));
  loaded_bios&= se_load_bios_file("NDS Firmware", nds->save_file_path, "firmware.bin", scratch->firmware,sizeof(scratch->firmware));

  if(!loaded_bios){
    printf("FATAL: Failed to load required bios\n");
  }

  //memcpy(nds->mem.bios,gba_bios_bin,sizeof(gba_bios_bin));
  bool fast_boot =true;
  if(fast_boot){
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
      nds9_write32(nds, addr,data);
    }
    nds7_write32(nds,GBA_DISPSTAT,0x7e0000);
    nds7_write32(nds,GBA_DISPSTAT,0x7e0000);
    nds9_write16(nds,GBA_DISPCNT,0x9140);
    nds9_write8(nds,NDS9_WRAMCNT,0x3);
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
    nds->arm7.registers[PC] = nds->card.arm7_entrypoint;
    
    printf("ARM9 Entry:0x%x ARM7 Entry:0x%x\n",nds->card.arm9_entrypoint,nds->card.arm7_entrypoint);

    //Copy NDS Header into 27FFE00h..27FFF6F
    int header_size = 0x27FFF70-0x27FFE00;
    for(int i=0;i<header_size;i+=4){
      nds9_write32(nds,0x027FFE00+i, *(uint32_t*)(((uint8_t*)&nds->card)+i));
    }
    //Default initialize these values for a direct boot to a cartridge
    const uint32_t arm9_init[]={
      0x027FF800, 0x1FC2, // Chip ID 1
      0x027FF804, 0x1FC2, // Chip ID 2
      0x027FF850, 0x5835, // ARM7 BIOS CRC
      0x027FF880, 0x0007, // Message from ARM9 to ARM7
      0x027FF884, 0x0006, // ARM7 boot task
      0x027FFC00, 0x1FC2, // Copy of chip ID 1
      0x027FFC04, 0x1FC2, // Copy of chip ID 2
      0x027FFC10, 0x5835, // Copy of ARM7 BIOS CRC
      0x027FFC40, 0x0001, // Boot indicator
    };
    for(int i=0;i<sizeof(arm9_init)/sizeof(uint32_t);i+=2){
      uint32_t addr=arm9_init[i+0];
      uint32_t data=arm9_init[i+1];
      nds9_write32(nds, addr,data);
    }
    nds9_io_store16(nds,NDS9_POSTFLG,1);
    nds7_io_store16(nds,NDS7_POSTFLG,1);
  }else{
    nds->arm9.registers[PC] = 0xFFFF0000;
    nds->arm7.registers[PC] = 0;
  }
  
  nds->arm9.irq_table_address = 0xFFFF0000;
  nds->mem.card_chip_id= 0x1FC2;

  if(nds->arm7.log_cmp_file){fclose(nds->arm7.log_cmp_file);nds->arm7.log_cmp_file=NULL;};
  if(nds->arm9.log_cmp_file){fclose(nds->arm9.log_cmp_file);nds->arm9.log_cmp_file=NULL;};
  nds->arm7.log_cmp_file =se_load_log_file(nds->save_file_path, "log7.bin");
  nds->arm9.log_cmp_file =se_load_log_file(nds->save_file_path, "log9.bin");


  //Preload user settings
  uint8_t* firm_data = scratch->firmware;
  uint32_t user_data_off = ((firm_data[0x21]<<8)|(firm_data[0x20]))*8;
  for(int i=0;i<0x070;++i)nds9_write8(nds,i+0x27FFC80,firm_data[(user_data_off+i)&(sizeof(scratch->firmware)-1)]);
  nds_reset_gpu(nds);

  uint32_t game_code = (nds->card.gamecode[0]<<0)|(nds->card.gamecode[1]<<8)|(nds->card.gamecode[2]<<16)|(nds->card.gamecode[3]<<24);
  nds_rom_entry_t* rom_entry = (nds_rom_entry_t*)bsearch(&game_code, nds_rom_database,
                                sizeof(nds_rom_database)/sizeof(nds_rom_database[0]),sizeof(nds_rom_database[0]),
                                nds_rom_db_compare_func);
  if(rom_entry&&rom_entry->GameCode==game_code){
    nds->backup.backup_type = rom_entry->SaveMemType;
  }else{
    printf("Save type could not be looked up in the database. A default will be assumed");
    nds->backup.backup_type = NDS_BACKUP_EEPROM_128KB;
  } 
  printf("NDS Save Type: %d\n",nds->backup.backup_type);

  size_t bytes=0;
  uint8_t*data = sb_load_file_data(emu->save_file_path,&bytes);
  if(data){
    printf("Loaded save file: %s, bytes: %zu\n",emu->save_file_path,bytes);
    if(bytes>=nds_get_save_size(nds))bytes=nds_get_save_size(nds);
    memcpy(nds->mem.save_data, data, bytes);
    sb_free_file_data(data);
  }else{
    printf("Could not find save file: %s\n",emu->save_file_path);
    for(int i=0;i<sizeof(nds->mem.save_data);++i) nds->mem.save_data[i]=0;
  }
  nds_update_vram_mapping(nds);

  //nds->gx_log = fopen("gxlog.txt","wb");
  //nds->io7_log = fopen("io7log.txt","wb");
  //nds->io9_log = fopen("io9log.txt","wb");
  //nds->vert_log = fopen("vertlog.txt","wb");
  //nds->gc_log = fopen("gclog.txt","wb");
  //nds->dma_log = fopen("dmalog.txt","wb");

  return true; 
}  
static void nds_unload(nds_t* nds, nds_scratch_t* scratch){
  if(nds->arm7.log_cmp_file){fclose(nds->arm7.log_cmp_file);nds->arm7.log_cmp_file=NULL;};
  if(nds->arm9.log_cmp_file){fclose(nds->arm9.log_cmp_file);nds->arm9.log_cmp_file=NULL;};
  printf("Unloading DS data\n");
}
uint32_t nds_sqrt_u64(uint64_t value){
  uint32_t res = 0;
  for(uint64_t b=0;b<32;++b){
    uint64_t test = res | (1ull<<(31-b));
    if(test*test<=value)res = test;
  }
  return res; 
}
#define NDS_CARD_MAIN_DATA_READ 0xB7
#define NDS_CARD_CHIP_ID_READ 0xB8
static void nds_process_gc_bus_read(nds_t*nds, int cpu_id){
  if(nds->mem.card_transfer_bytes<=0)return;
  nds->activate_dmas=true;
  uint16_t exmemcnt = nds9_io_read16(nds,NDS9_EXMEMCNT);
  bool arm7_has_slot = SB_BFE(exmemcnt,11,1);
  if(cpu_id==arm7_has_slot)return;
  
  uint8_t data[4]; 
  int bank = nds->mem.card_read_offset&~0xfff;
  int bank_off = nds->mem.card_read_offset&0xfff;
  data[0]= nds->mem.card_transfer_data[(bank_off++)&0xfff];
  data[1]= nds->mem.card_transfer_data[(bank_off++)&0xfff];
  data[2]= nds->mem.card_transfer_data[(bank_off++)&0xfff];
  data[3]= nds->mem.card_transfer_data[(bank_off++)&0xfff];
  uint32_t data_out = *(uint32_t*)(data);
  if(nds->gc_log)fprintf(nds->gc_log,"Data: %08x\n",data_out);
  //printf("data[%08x]: %08x\n",nds->mem.card_read_offset,data_out);
  nds_io_store32(nds,cpu_id,NDS_GC_BUS,data_out);
  nds->mem.card_read_offset = bank|(bank_off&0xfff);
    
  nds->mem.card_transfer_bytes-=4;
  nds->activate_dmas=true;
  if(nds->mem.card_transfer_bytes<=0){
    uint32_t gcbus_ctl = nds_io_read32(nds,cpu_id,NDS_GCBUS_CTL);
    gcbus_ctl&=~((1<<31)|(1<<23));// Clear data ready and busy bit 
    nds_io_store32(nds,cpu_id,NDS_GCBUS_CTL,gcbus_ctl);
  }else{
    uint16_t auxspi = nds_io_read16(nds,cpu_id,NDS9_AUXSPICNT);
    bool transfer_ready_irq = SB_BFE(auxspi,14,1);
    if(transfer_ready_irq){
      if(cpu_id==NDS_ARM7)nds7_send_interrupt(nds,4,1<<NDS_INT_GC_TRANSFER_DONE);
      else nds9_send_interrupt(nds,4,1<<NDS_INT_GC_TRANSFER_DONE);
    }
  }
}

static void nds_process_gc_bus_ctl(nds_t*nds, int cpu_id){
  uint16_t exmemcnt = nds9_io_read16(nds,NDS9_EXMEMCNT);
  bool arm7_has_slot = SB_BFE(exmemcnt,11,1);
  if(arm7_has_slot&&cpu_id!=NDS_ARM7)return;
  nds->activate_dmas=true;
  uint32_t gcbus_ctl = nds_io_read32(nds,cpu_id,NDS_GCBUS_CTL);
  bool start_transfer = SB_BFE(gcbus_ctl,31,1);
  //printf("NDS GCBUS: 0x%08x\n",gcbus_ctl);
  gcbus_ctl&=~((1u<<31)|(1u<<23));// Clear data ready and start bit 
  gcbus_ctl|=(1u<<23);
  if(start_transfer){
    //Mask out start bit;
    uint8_t commands[8];
    for(int i=0;i<7;++i)commands[i]=nds9_io_read8(nds,NDS_GCBUS_CMD+i);
    if(nds->gc_log)fprintf(nds->gc_log,"GCBUS CMD: %02x %02x %02x%02x %02x%02x %02x%02x\n",commands[0],commands[1],commands[2],commands[3]
      ,commands[4],commands[5],commands[6],commands[7]);
    switch(commands[0]){
      case NDS_CARD_MAIN_DATA_READ:{
        //Encrypted data read;
        int read_off = (((int)commands[1])<<24)|(((int)commands[2])<<16)|(((int)commands[3])<<8)|(((int)commands[4])<<0);
        if(read_off<=0x7FFF)read_off=0x8000+(read_off &0x1FF);
        nds->mem.card_read_offset=read_off;
        int data_block_size = SB_BFE(gcbus_ctl,24,3);
        const int transfer_size_map[8]={0, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000, 4};
        for(int i=0;i<0x1000;++i){
          nds->mem.card_transfer_data[i]=nds->mem.card_data[(i+(read_off&~0xfff))%nds->mem.card_size];
        }
        nds->mem.card_transfer_bytes=transfer_size_map[data_block_size];
        if(nds->gc_log)fprintf(nds->gc_log,"Encrypted Read: 0x%08x transfer_size: %08x transfer:%d\n",read_off,nds->mem.card_transfer_bytes,nds->mem.transfer_id++);
        gcbus_ctl|=(1<<23)|(1<<31);//Set data_ready bit and busy
      }break; 
      case NDS_CARD_CHIP_ID_READ:{
        //Encrypted data read;
        nds->mem.card_read_offset=0;
        nds->mem.card_transfer_data[0]=SB_BFE(nds->mem.card_chip_id,0,8);
        nds->mem.card_transfer_data[1]=SB_BFE(nds->mem.card_chip_id,8,8);
        nds->mem.card_transfer_data[2]=SB_BFE(nds->mem.card_chip_id,16,8);
        nds->mem.card_transfer_data[3]=SB_BFE(nds->mem.card_chip_id,24,8);
        nds->mem.card_transfer_bytes=4;
        if(nds->gc_log)fprintf(nds->gc_log,"CHIPID Read transfer:%d\n",nds->mem.transfer_id++);
        gcbus_ctl|=(1<<23)|(1<<31);//Set data_ready bit and busy
      }break; 
      default: printf("Unknown cmd: %02x\n",commands[0]);break;
    }
    uint16_t auxspi = nds_io_read16(nds,cpu_id,NDS9_AUXSPICNT);
    bool transfer_ready_irq = SB_BFE(auxspi,14,1);
    if(transfer_ready_irq&&(gcbus_ctl&(1<<23))){
      if(cpu_id==NDS_ARM7)nds7_send_interrupt(nds,4,1<<NDS_INT_GC_TRANSFER_DONE);
      else nds9_send_interrupt(nds,4,1<<NDS_INT_GC_TRANSFER_DONE);
    }
  }
  nds->activate_dmas=true;
  nds_io_store32(nds,cpu_id,NDS_GCBUS_CTL,gcbus_ctl);
}    
/* Only simulates a small subset of the RTC needed to make time events work in the pokemon games. */
static FORCE_INLINE void nds_process_rtc_state_machine(nds_t* nds){
  uint8_t data = nds7_io_read8(nds,NDS7_RTC_BUS);
  bool clk  = !SB_BFE(data,1,1);
  bool io_dat = SB_BFE(data,0,1);
  bool cs   = SB_BFE(data,2,1);
  #define SERIAL_INIT 0 
  #define SERIAL_CLK_LOW 1
  #define SERIAL_CLK_HIGH 2  

  #define RTC_RECV_CMD -1
  #define RTC_RESET     0
  #define RTC_STATUS    1
  #define RTC_DATE_TIME 2    
  #define RTC_TIME      3

  nds_rtc_t * rtc = &(nds->rtc);

  rtc->status_register &= ~((1<<7));
  rtc->status_register |= 0x40;

  if(cs==0){
    rtc->serial_state=SERIAL_INIT;
    rtc->serial_bits_clocked=0;
    rtc->state = RTC_RECV_CMD;
  }

  if(cs!=0){
    bool new_bit = false; 
    
    if(nds->rtc.serial_state==SERIAL_CLK_LOW&&clk){
      nds->rtc.input_register<<=1;
      nds->rtc.input_register|=((uint64_t)io_dat);
      new_bit = true;
    
      bool out_bit = (rtc->output_register&1);
      data&=~1;
      data|=out_bit&1;
      nds7_io_store8(nds,NDS7_RTC_BUS,data);
      rtc->output_register>>=1;
    }
    
    nds->rtc.serial_state= clk? SERIAL_CLK_HIGH: SERIAL_CLK_LOW;

    if(new_bit){
      nds->rtc.serial_bits_clocked++;
      if(nds->rtc.serial_bits_clocked==8) nds->rtc.state= SB_BFE(nds->rtc.input_register,0,4);
      int  cmd = SB_BFE(rtc->state,1,3);
      bool read = SB_BFE(rtc->state,0,1);
      switch(cmd){
        case RTC_RECV_CMD:break;
        case RTC_STATUS:{
          if(rtc->serial_bits_clocked==8) rtc->output_register = rtc->status_register;
          if(rtc->serial_bits_clocked==16){
            if(!read)rtc->status_register=SB_BFE(rtc->input_register,0,8);
            rtc->state= RTC_RECV_CMD;
            rtc->serial_bits_clocked=0;
          }
          break;
        }
        case RTC_DATE_TIME:{
          if(rtc->serial_bits_clocked==8) rtc->output_register =
            ((uint64_t)(rtc->year&0xff)       <<(0*8))|
            ((uint64_t)(rtc->month&0xff)      <<(1*8))|
            ((uint64_t)(rtc->day&0xff)        <<(2*8))|
            ((uint64_t)(rtc->day_of_week&0xff)<<(3*8))|
            ((uint64_t)(rtc->hour&0xff)       <<(4*8))|
            ((uint64_t)(rtc->minute&0xff)     <<(5*8))|
            ((uint64_t)(rtc->second&0xff)     <<(6*8));
          if(rtc->serial_bits_clocked==8*8){
            if(!read){
              rtc->year  = SB_BFE(rtc->input_register,6*8,8);
              rtc->month = SB_BFE(rtc->input_register,5*8,8);
              rtc->day   = SB_BFE(rtc->input_register,4*8,8);
              rtc->day_of_week = SB_BFE(rtc->input_register,3*8,8);
              rtc->hour   = SB_BFE(rtc->input_register,2*8,8);
              rtc->minute = SB_BFE(rtc->input_register,1*8,8);
              rtc->second = SB_BFE(rtc->input_register,0*8,8);
            }
            rtc->state= RTC_RECV_CMD;
            rtc->serial_bits_clocked=0;
          }
          break;
        }
        case RTC_TIME:{
          if(rtc->serial_bits_clocked==8) rtc->output_register = 
            ((uint64_t)(rtc->hour&0xff)<<(0*8))|
            ((uint64_t)(rtc->minute&0xff)<<(1*8))|
            ((uint64_t)(rtc->second&0xff)<<(2*8));
          if(rtc->serial_bits_clocked==4*8){
            if(!read){
              rtc->hour   = SB_BFE(rtc->input_register,0*8,8);
              rtc->minute = SB_BFE(rtc->input_register,1*8,8);
              rtc->second = SB_BFE(rtc->input_register,2*8,8);
            }
            rtc->state= RTC_RECV_CMD;
            rtc->serial_bits_clocked=0;
          }
          break;
        }
      }
    }
  }
}
static uint32_t nds_get_save_size(nds_t*nds){
  uint32_t save_size = 0; 
  nds_card_backup_t * bak = &nds->backup;
  switch (bak->backup_type){
    case NDS_BACKUP_NONE        :save_size = 0; break;   
    case NDS_BACKUP_EEPROM_512B :save_size = 512; break;  
    case NDS_BACKUP_EEPROM_8KB  :save_size = 8*1024; break;  
    case NDS_BACKUP_EEPROM_64KB :save_size = 64*1024; break;  
    case NDS_BACKUP_EEPROM_128KB:save_size = 128*1024; break;  
    case NDS_BACKUP_FLASH_256KB :save_size = 256*1024; break;  
    case NDS_BACKUP_FLASH_512KB :save_size = 512*1024; break;  
    case NDS_BACKUP_FLASH_1MB   :save_size = 1024*1024; break;  
    case NDS_BACKUP_NAND_8MB    :save_size = 8*1024*1024; break;  
    case NDS_BACKUP_NAND_16MB   :save_size = 16*1024*1024; break;  
    case NDS_BACKUP_NAND_64MB   :save_size = 64*1024*1024; break;  
  }
  return save_size;
}
static uint32_t nds_get_curr_backup_address(nds_t*nds){
  uint32_t save_size = nds_get_save_size(nds); 
  nds_card_backup_t * bak = &nds->backup;
  if(bak->backup_type==NDS_BACKUP_EEPROM_512B){
    uint32_t base_addr = nds->backup.command[1]; 
    if(bak->command_offset<3)return 0xffffffff;
    //Handle high address commands
    if(bak->command[0]==0x0B||bak->command[0]==0x0A)base_addr|=0x100;
    return (base_addr+bak->command_offset-3)%save_size;
  }
  if(bak->backup_type>=NDS_BACKUP_EEPROM_8KB&&bak->backup_type<=NDS_BACKUP_EEPROM_64KB){
    uint32_t base_addr = (nds->backup.command[1]<<8)|(nds->backup.command[2]); 
    if(bak->command_offset<4)return 0xffffffff;
    return (base_addr+bak->command_offset-4)%save_size;
  }
  if(bak->backup_type==NDS_BACKUP_EEPROM_128KB){
    uint32_t base_addr = (nds->backup.command[1]<<16)|(nds->backup.command[2]<<8)|(nds->backup.command[3]); 
    if(bak->command_offset<5)return 0xffffffff;
    return (base_addr+bak->command_offset-5)%save_size;
  }
  if(bak->backup_type==NDS_BACKUP_NONE)return 0xffffffff;
  printf("Unhandled backup_type: %d\n",bak->backup_type);
  return 0xffffffff;
}
static void nds_process_gc_spi(nds_t* nds, int cpu_id){
  uint32_t aux_spi_cnt = nds_io_read32(nds,cpu_id,NDS9_AUXSPICNT);
  uint8_t spi_data = nds_io_read8(nds,cpu_id,NDS9_AUXSPIDATA);
  bool slot_mode = SB_BFE(aux_spi_cnt,13,1);
  bool slot_enable = SB_BFE(aux_spi_cnt,15,1);
  //Don't process if slot is disabled or not in backup mode
  if(slot_enable==false||slot_mode==false)return;
  nds_card_backup_t* back = &nds->backup;
  uint8_t ret_data = 0; 
  if(nds->backup.backup_type>=NDS_BACKUP_FLASH_256KB&&nds->backup.backup_type<=NDS_BACKUP_FLASH_1MB){
    ret_data = nds_process_flash_write(nds,spi_data,&nds->backup.flash,nds->mem.save_data, nds_get_save_size(nds));
    nds->backup.is_dirty=true;
  }else{
    if(back->command_offset<sizeof(back->command)){
      back->command[back->command_offset]=spi_data;
    }
    back->command_offset++;
    switch(back->command[0]){
      case 0x00: /*NOP*/  break ;
      case 0x06: /*WREN*/ back->write_enable=true;break;
      case 0x04: /*WRDI*/ back->write_enable=false;break;
      case 0x05: /*RDSR*/ 
        /*
          Status Register
            0   WIP  Write in Progress (1=Busy) (Read only) (always 0 for FRAM chips)
            1   WEL  Write Enable Latch (1=Enable) (Read only, except by WREN,WRDI)
            2-3 WP   Write Protect (0=None, 1=Upper quarter, 2=Upper Half, 3=All memory)
          For 0.5K EEPROM:
            4-7 ONEs Not used (all four bits are always set to "1" each)
          For 8K..64K EEPROM and for FRAM:
            4-6 ZERO Not used (all three bits are always set to "0" each)
            7   SRWD Status Register Write Disable (0=Normal, 1=Lock) (Only if /W=LOW)
        */
        back->status_reg&= (3<<2)|(1<<7);
        if(back->write_enable)back->status_reg|=0x2;
        if(back->backup_type==NDS_BACKUP_EEPROM_512B)back->status_reg|=0xf0;
        ret_data = back->status_reg;
        break;
      case 0x01: /*WRSR*/ back->status_reg=spi_data;break;
      case 0x9f: /*RDID*/ ret_data = 0xff; break;
      case 0x03: /*RD/RDLO*/
      case 0x0B: /*RDHI*/{
        uint32_t addr = nds_get_curr_backup_address(nds);
        if(addr!=0xffffffff)ret_data = nds->mem.save_data[addr];
        break;
      }
      case 0x02: /*WR/WRLO*/
      case 0x0A: /*WRHI*/{
        uint32_t addr = nds_get_curr_backup_address(nds);
        if(addr!=0xffffffff&&back->write_enable){
          nds->mem.save_data[addr]=spi_data;
          back->is_dirty = true;
        }
        break;
      }
      default:
        if(back->command_offset==1)printf("Unknown AUX SPI command:%02x\n",back->command[0]);
        break;
    }
  }
  nds_io_store8(nds,cpu_id,NDS9_AUXSPIDATA,ret_data);
  bool hold_chip_sel = SB_BFE(aux_spi_cnt,6,1);
  if(!hold_chip_sel){
    nds->backup.command_offset=0;
    nds->backup.flash.state =0;
  }
}
static FORCE_INLINE uint32_t nds_align_data(uint32_t addr, uint32_t data, int transaction_type){
  if(transaction_type&NDS_MEM_2B)data= (data&0xffff)<<((addr&2)*8);
  if(transaction_type&NDS_MEM_1B)data= (data&0xff)<<((addr&3)*8);
  return data; 
}
static FORCE_INLINE uint32_t nds_word_mask(uint32_t addr, int transaction_type){
  if(transaction_type&NDS_MEM_2B)return (0xffffu)<<((addr&2)*8);
  if(transaction_type&NDS_MEM_1B)return (0xffu)<<((addr&3)*8);
  return 0xffffffff;
}

#define NDS_FLASH_RECV_CMD  0 
#define NDS_FLASH_RXTX      1 
#define NDS_FLASH_SET_ADDR0 2
#define NDS_FLASH_SET_ADDR1 3
#define NDS_FLASH_SET_ADDR2 4
#define NDS_FLASH_SET_ADDR3 5
#define NDS_FLASH_DUMMY     6

static uint8_t nds_process_flash_write(nds_t *nds, uint8_t write_data, nds_flash_t* flash, uint8_t *flash_data, uint32_t flash_size){
  uint8_t return_data = 0xff;
  if(flash->state==NDS_FLASH_RECV_CMD){
    flash->cmd = write_data;
    switch(write_data){
      case 0x06: flash->write_enable = true; break;  //WriteEnable(WREM)
      case 0x04: flash->write_enable = false; break;  //WriteDisable(WRDI)

      case 0x96: //ReadJEDEC(RDID)
      case 0x05: //ReadStatus(RDSR)
        flash->state = NDS_FLASH_RXTX; flash->addr=0;
        break;
      
      case 0x03: //ReadData(READ)
      case 0x0B: //ReadDataFast(FAST)
        flash->state = NDS_FLASH_SET_ADDR0; 
        break; 

      case 0x0A: //PageWrite(PW)
      case 0x02: //PageProgram(PP)
      case 0xDB: //PageErase(PE)
      case 0xD8: //SectorErase(SE)
        if(flash->write_enable)flash->state = NDS_FLASH_SET_ADDR0;
        break;
      case 0xB9: break;  //DeepPowerDown(DP)
      case 0xAB: break;  //ReleaseDeepPowerDown(RDP)
    } 
    printf("NDS Firmware cmd:%02x\n",flash->cmd);
  }else if(flash->state == NDS_FLASH_RXTX){
    uint32_t page_mask = 0xff;
    uint32_t sector_mask = 0xffff;
    switch(flash->cmd){
      case 0x06: flash->state=0; break;  //WriteEnable(WREM)
      case 0x04: flash->state=0; break;  //WriteDisable(WRDI)

      case 0x96:{ //ReadID(RDID)
        uint8_t jedec_id[3] = { 0x20, 0x40, 0x12 };
        return_data = jedec_id[flash->addr++];
        if(flash->addr>2)flash->state = 0; 
        break;
      }
      case 0x05: //ReadStatus(RDSR)
        return_data = flash->write_enable?0x2:0;
        break;
      
      case 0x03: //ReadData(READ)
      case 0x0B:{ //ReadDataFast(FAST)
        uint32_t addr = flash->addr++;
        return_data = flash_data[addr&(flash_size-1)];
        break; 
      }
      case 0x0A: //PageWrite(PW)
      {
        uint32_t addr = flash->addr;
        flash->addr = ((flash->addr+1)&page_mask)|(flash->addr&~page_mask);
        if(flash->write_enable) return_data = flash_data[addr&(flash_size-1)]=write_data;
        break;
      }
      case 0x02: //PageProgram(PP)
      {
        uint32_t addr = flash->addr;
        flash->addr = ((flash->addr+1)&page_mask)|(flash->addr&~page_mask);
        if(flash->write_enable) return_data = flash_data[addr&(flash_size-1)]&=write_data;
        break;
      }
      case 0xDB: //PageErase(PE)
      {
        flash->addr =flash->addr&~page_mask;
        if(flash->write_enable) for(int i=0;i<=page_mask;++i)return_data = flash_data[(flash->addr|i)&(flash_size-1)]=0xff;
        break;
      }
      case 0xD8: //SectorErase(SE)
      {
        flash->addr =flash->addr&~sector_mask;
        if(flash->write_enable) for(int i=0;i<=sector_mask;++i)return_data = flash_data[(flash->addr|i)&(flash_size-1)]=0xff;
        break;
      }

      case 0xB9: flash->state = 0; break;  //DeepPowerDown(DP)
      case 0xAB: flash->state = 0; break;  //ReleaseDeepPowerDown(RDP)
    }
    //printf("NDS Firmware RXTX: cmd:%02x addr:%08x\n",flash->cmd, flash->addr);

  }else{
    switch(flash->state){
      case NDS_FLASH_SET_ADDR0:
        flash->addr = write_data<<16; 
        flash->state = NDS_FLASH_SET_ADDR1;
        break; 
      case NDS_FLASH_SET_ADDR1:
        flash->addr |= write_data<<8; 
        flash->state = NDS_FLASH_SET_ADDR2;
        break;
      case NDS_FLASH_SET_ADDR2:
        flash->addr |= write_data<<0; 
        //Dummy byte for fast read
        flash->state = flash->cmd == 0x0B?NDS_FLASH_DUMMY:NDS_FLASH_RXTX;
        flash->addr&=(flash_size-1);
        break;
      case NDS_FLASH_DUMMY:
        flash->state = NDS_FLASH_RXTX;
        break;
    }
  }
  return return_data;
}

static uint8_t nds_process_touch_ctrl_write(nds_t *nds, uint8_t data){
  nds_touch_t *touch = &nds->touch;
  uint8_t return_data = touch->tx_reg>>8;
  touch->tx_reg<<=8;
  if(data&0x80){
    //Recv'd ctrl byte
    int channel = SB_BFE(data,4,3);
    switch(channel){
      case 0: touch->tx_reg =0x7FF8; break; // Temperature 0 (requires calibration, step 2.1mV per 1'C accuracy)
      case 1: touch->tx_reg =touch->y_reg; break; // Touchscreen Y-Position  (somewhat 0B0h..F20h, or FFFh=released)
      case 2: touch->tx_reg =0xf0;    break; // Battery Voltage         (not used, connected to GND in NDS, always 000h)
      case 3: touch->tx_reg =0x7FF8; break; // Touchscreen Z1-Position (diagonal position for pressure measurement)
      case 4: touch->tx_reg =0x7FF8; break; // Touchscreen Z2-Position (diagonal position for pressure measurement)
      case 5: touch->tx_reg =touch->x_reg; break; // Touchscreen X-Position  (somewhat 100h..ED0h, or 000h=released)
      case 6: touch->tx_reg =0x7FF8; break; // AUX Input               (connected to Microphone in the NDS)
      case 7: touch->tx_reg =0x7FF8; break; // Temperature 1 (difference to Temp 0, without calibration, 2'C accuracy)
    }
    //printf("Touch: %d %04x\n",channel, nds->touch.tx_reg);
  }
  return return_data;
}
static void nds_deselect_spi(nds_t *nds){
  nds->firmware.state = NDS_FLASH_RECV_CMD; 
  nds->spi.last_device = -1;
}
static float * nds_gpu_get_active_matrix(nds_t*nds){
  switch(nds->gpu.matrix_mode){
    case NDS_MATRIX_PROJ: return nds->gpu.proj_matrix;
    case NDS_MATRIX_TBD:case NDS_MATRIX_MV: return nds->gpu.mv_matrix;
    case NDS_MATRIX_TEX: return nds->gpu.tex_matrix;
    default:
      printf("GPU: Unknown matrix type:%d\n",nds->gpu.matrix_mode);
      break;
  }
  return nds->gpu.mv_matrix;
}
static void nds_identity_matrix(float* m){
  for(int i=0;i<16;++i)m[i]=(i%5)==0?1.0:0.0;;
}
static void nds_reset_gpu(nds_t*nds){
  printf("Reset GPU\n");
  nds->gpu.mv_matrix_stack_ptr=0;
  nds->gpu.proj_matrix_stack_ptr=0;
  nds->gpu.tex_matrix_stack_ptr=0;
  nds->gpu.matrix_mode=NDS_MATRIX_PROJ;
  nds->gpu.fifo_read_ptr=nds->gpu.fifo_write_ptr=0;
  for(int i=0;i<NDS_GXFIFO_STORAGE;++i){
    nds->gpu.fifo_cmd[i]=0;
    nds->gpu.fifo_data[i]=0;
  }
  nds_identity_matrix(nds->gpu.proj_matrix);
  nds_identity_matrix(nds->gpu.tex_matrix);
  nds_identity_matrix(nds->gpu.mv_matrix);

  nds_identity_matrix(nds->gpu.proj_matrix_stack);
  nds_identity_matrix(nds->gpu.tex_matrix_stack);
  nds_identity_matrix(nds->gpu.mv_matrix_stack);
}
static void nds_gpu_swap_buffers(nds_t*nds){
  uint32_t clear_color = nds9_io_read32(nds,NDS9_CLEAR_COLOR);
  for(int i=0;i<NDS_LCD_W*NDS_LCD_H;++i){
    nds->framebuffer_3d_disp[i*4+0]=nds->framebuffer_3d[i*4+0];
    nds->framebuffer_3d_disp[i*4+1]=nds->framebuffer_3d[i*4+1];
    nds->framebuffer_3d_disp[i*4+2]=nds->framebuffer_3d[i*4+2];
    nds->framebuffer_3d_disp[i*4+3]=nds->framebuffer_3d[i*4+3];
    nds->framebuffer_3d[i*4+0]=SB_BFE(clear_color,0,5)*8;
    nds->framebuffer_3d[i*4+1]=SB_BFE(clear_color,5,5)*8;
    nds->framebuffer_3d[i*4+2]=SB_BFE(clear_color,10,5)*8;
    nds->framebuffer_3d[i*4+3]=SB_BFE(clear_color,16,5)*8;

    nds->framebuffer_3d_depth[i]=10e24;
  }
  printf("Rendered %d verts and %d polys\n",nds->gpu.curr_vert,nds->gpu.poly_ram_offset);
  nds->gpu.curr_vert = 0; 
  nds->gpu.poly_ram_offset=0;
}
//res=res*m2
void nds_mult_matrix4(float * res, float *m2){
  //printf("Mult Matrix:\n");
  //for(int y=0;y<4;++y)printf("%f %f %f %f\n",m2[0+y*4],m2[1+y*4],m2[2+y*4],m2[3+y*4]);
  float t[16];
  for(int i=0;i<16;++i)t[i]=res[i];

  for(int y=0;y<4;++y) 
    for(int x=0;x<4;++x){
      res[x+y*4] = m2[0+y*4]*t[x+0*4]
                  +m2[1+y*4]*t[x+1*4]
                  +m2[2+y*4]*t[x+2*4]
                  +m2[3+y*4]*t[x+3*4];
  }
}
void nds_translate_matrix(float * m, float x, float y, float z){
  m[12]+=m[0]*x+m[4]*y+m[8]*z;
  m[13]+=m[1]*x+m[5]*y+m[9]*z;
  m[14]+=m[2]*x+m[6]*y+m[10]*z;
  m[15]+=m[3]*x+m[7]*y+m[11]*z;
}
void nds_scale_matrix(float * m, float x, float y, float z){
  SE_RPT4 m[0*4+r] *=x;
  SE_RPT4 m[1*4+r] *=y;
  SE_RPT4 m[2*4+r] *=z;
}
void nds_mult_matrix_vector(float * result, float * m, float *v,int dims){
  for(int x=0;x<dims;++x){
    result[x]=0;
    for(int y = 0;y<dims;++y)result[x]+=m[x+y*dims]*v[y];
  }
}
static bool nds_sample_texture(nds_t* nds, float* tex_color, float*uv){
  /*
  0-15  Texture VRAM Offset div 8 (0..FFFFh -> 512K RAM in Slot 0,1,2,3)
        (VRAM must be allocated as Texture data, see Memory Control chapter)
  16    Repeat in S Direction (0=Clamp Texture, 1=Repeat Texture)
  17    Repeat in T Direction (0=Clamp Texture, 1=Repeat Texture)
  18    Flip in S Direction   (0=No, 1=Flip each 2nd Texture) (requires Repeat)
  19    Flip in T Direction   (0=No, 1=Flip each 2nd Texture) (requires Repeat)
  20-22 Texture S-Size        (for N=0..7: Size=(8 SHL N); ie. 8..1024 texels)
  23-25 Texture T-Size        (for N=0..7: Size=(8 SHL N); ie. 8..1024 texels)
  26-28 Texture Format        (0..7, see below)
  29    Color 0 of 4/16/256-Color Palettes (0=Displayed, 1=Made Transparent)
  30-31 Texture Coordinates Transformation Mode (0..3, see below)*/
  uint32_t tex_param = nds->gpu.tex_image_param;
  int vram_offset = SB_BFE(tex_param,0,16)*8;
  bool repeat[2]={SB_BFE(tex_param,16,1),SB_BFE(tex_param,17,1)};
  bool flip[2]={SB_BFE(tex_param,18,1),SB_BFE(tex_param,19,1)};
  int sz[2]={SB_BFE(tex_param,20,3),SB_BFE(tex_param,23,3)};
  int format = SB_BFE(tex_param,26,3);
  bool color0_transparent = SB_BFE(tex_param,29,1);

  tex_color[0]=0;
  tex_color[1]=0;
  tex_color[2]=0;
  tex_color[3]=1;
  
  for(int i=0;i<2;++i){
    signed sz_lin = 8<<sz[i];
    signed tex_coord = uv[i];
    if(!repeat[i]){
      if(tex_coord>=sz_lin)tex_coord=sz_lin-1;
      if(tex_coord<0)tex_coord=0;
    }else{
      signed int_part = tex_coord>>(3+sz[i]);
      tex_coord&=sz_lin-1;
      if((int_part&1)&&(flip[i]))tex_coord=sz_lin-tex_coord-1;
    }
    uv[i]=tex_coord;
    sz[i]=sz_lin;
  }
  bool palette_zero =false;
  int x = uv[0], y=uv[1];
  switch(format){
    case -1:
      tex_color[0]=fabs(uv[0]/sz[0]);
      tex_color[1]=fabs(uv[1]/sz[1]);
      tex_color[2]=0;
      tex_color[3]=1;
    break;
    case 0x0: /*No Texture*/{
      for(int i=0;i<4;++i) tex_color[i]=1;
    }break;
    case 0x1: /*Format 1: A3I5 Translucent Texture (3bit Alpha, 5bit Color Index)*/
    {
      uint32_t palette = nds_ppu_read8(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x+y*sz[0]);
      uint32_t alpha = SB_BFE(palette,5,3);
      palette = SB_BFE(palette,0,5);
      uint32_t palette_base = SB_BFE(nds->gpu.tex_plt_base,0,13)*16;
      uint16_t color= nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_base+palette*2);
      //palette_zero = palette==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
      tex_color[3] = alpha/7.;
    }break;
    case 0x2: /*4-Color Palette Texture*/
    {
      uint32_t palette = nds_ppu_read8(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x/4+y*sz[0]/4);
      palette = SB_BFE(palette,2*(x&3),2);
      uint32_t palette_base = SB_BFE(nds->gpu.tex_plt_base,0,13)*8;
      uint16_t color= nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_base+palette*2);
      palette_zero = palette==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
    }break;
    case 0x3: /*Format 3: 16-Color Palette Texture*/
    {
      uint32_t palette = nds_ppu_read8(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x/2+y*sz[0]/2);
      palette = SB_BFE(palette,(x&1)*4,4);
      uint32_t palette_base = SB_BFE(nds->gpu.tex_plt_base,0,13)*16;
      uint16_t color= nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_base+palette*2);
      palette_zero = palette==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
    }break;
    case 0x4: /*Format 4: 256-Color Palette Texture*/
    {
      uint32_t palette = nds_ppu_read8(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x+y*sz[0]);
      uint32_t palette_base = SB_BFE(nds->gpu.tex_plt_base,0,13)*16;
      uint16_t color= nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_base+palette*2);
      palette_zero = palette==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
    }break;
    case 0x5:{
      int bx = x/4, by =y/4;
      uint32_t slot0_addr= vram_offset+(bx+by*sz[0]/4)*4;
      uint32_t block = nds_ppu_read32(nds,NDS_VRAM_TEX_SLOT0+slot0_addr);

      int block_offset = (x%4)*2 + (y%4)*8;
      int texel = SB_BFE(block,block_offset,2); 

      uint32_t slot1_addr = slot0_addr>=128*1024? slot0_addr/2-64*1024 : slot0_addr/2;

      uint16_t pal_index_data = nds_ppu_read16(nds,NDS_VRAM_TEX_SLOT1+slot1_addr);
      int palette_off = SB_BFE(pal_index_data,0,14);
      int mode = SB_BFE(pal_index_data,14,2);
      int slot = slot0_addr/(128*1024);
      uint32_t palette_addr = palette_off*4+SB_BFE(nds->gpu.tex_plt_base,0,13)*16;

      switch(texel){
        case 0:{
          uint16_t color = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr);
          tex_color[0] = SB_BFE(color,0,5)/31.;
          tex_color[1] = SB_BFE(color,5,5)/31.;
          tex_color[2] = SB_BFE(color,10,5)/31.;
          tex_color[3] = 1.0;
        }break;
        case 1:{
          uint16_t color = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+2);
          tex_color[0] = SB_BFE(color,0,5)/31.;
          tex_color[1] = SB_BFE(color,5,5)/31.;
          tex_color[2] = SB_BFE(color,10,5)/31.;
          tex_color[3] = 1.0;
        }break;
        case 2:{
          if(mode==0||mode==2){
            uint16_t color = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+4);
            tex_color[0] = SB_BFE(color,0,5)/31.;
            tex_color[1] = SB_BFE(color,5,5)/31.;
            tex_color[2] = SB_BFE(color,10,5)/31.;
            tex_color[3] = 1.0;
          }else{
            uint16_t color0 = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+0);
            uint16_t color1 = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+2);
            if(mode==1){
              tex_color[0] = (SB_BFE(color0,0,5)+SB_BFE(color1,0,5))/31.*0.5;
              tex_color[1] = (SB_BFE(color0,5,5)+SB_BFE(color1,5,5))/31.*0.5;
              tex_color[2] = (SB_BFE(color0,10,5)+SB_BFE(color1,10,5))/31.*0.5;
            }else{
              tex_color[0] = (SB_BFE(color0,0,5)*5+SB_BFE(color1,0,5)*3)/8./31.;
              tex_color[1] = (SB_BFE(color0,5,5)*5+SB_BFE(color1,5,5)*3)/8./31.;
              tex_color[2] = (SB_BFE(color0,10,5)*5+SB_BFE(color1,10,5)*3)/8./31.;
            }
            tex_color[3] = 1.0;
          }
        }break;
        case 3:{
          if(mode==0||mode==1){
            tex_color[3]=0; 
            return true; 
          }else if(mode==2){
            uint16_t color = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+6);
            tex_color[0] = SB_BFE(color,0,5)/31.;
            tex_color[1] = SB_BFE(color,5,5)/31.;
            tex_color[2] = SB_BFE(color,10,5)/31.;
            tex_color[3] = 1.0;
          }else{
            uint16_t color0 = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+0);
            uint16_t color1 = nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_addr+2);
            tex_color[0] = (SB_BFE(color0,0,5)*3+SB_BFE(color1,0,5)*5)/8./31.;
            tex_color[1] = (SB_BFE(color0,5,5)*3+SB_BFE(color1,5,5)*5)/8./31.;
            tex_color[2] = (SB_BFE(color0,10,5)*3+SB_BFE(color1,10,5)*5)/8./31.;
            tex_color[3] = 1.0;
          }
        }break;
      }
    }break;
    case 0x6: /*Format 6: A5I3 Translucent Texture (5bit Alpha, 3bit Color Index)*/
    {
      uint32_t palette = nds_ppu_read8(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x+y*sz[0]);
      uint32_t alpha = SB_BFE(palette,3,5);
      palette = SB_BFE(palette,0,3);
      uint32_t palette_base = SB_BFE(nds->gpu.tex_plt_base,0,13)*16;
      uint16_t color= nds_ppu_read16(nds,NDS_VRAM_TEX_PAL_SLOT0+palette_base+palette*2);
      palette_zero = palette==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
      tex_color[3] = alpha/31.;
    }break;
    case 0x7: /* Format 7: Direct Color Texture*/
    {
      uint32_t color = nds_ppu_read16(nds,NDS_VRAM_TEX_SLOT0+vram_offset+x*2+y*sz[0]*2);
      palette_zero = SB_BFE(color,15,1)==0;
      tex_color[0] = SB_BFE(color,0,5)/31.;
      tex_color[1] = SB_BFE(color,5,5)/31.;
      tex_color[2] = SB_BFE(color,10,5)/31.;
      tex_color[3] = SB_BFE(color,15,1);
    }break;
    default:
      printf("Unknown texture format:%d\n",format);
      for(int i=0;i<2;++i)tex_color[i]= uv[i]/((float)(sz[i]));
      break;
  }
  //tex_color[0]= (format&0x1)?0xff:0;
  //tex_color[1]= (format&0x2)?0xff:0;
  //tex_color[2]= (format&0x4)?0xff:0;

  if((palette_zero&&color0_transparent))tex_color[3]=0;
  return tex_color[3]==0;
}

static bool nds_gpu_draw_tri(nds_t* nds, int vi0, int vi1, int vi2){
  uint32_t disp3dcnt = nds9_io_read32(nds,NDS_DISP3DCNT);

  bool tex_map     = SB_BFE(disp3dcnt,0,1);/*Texture Mapping      (0=Disable, 1=Enable)*/
  bool shade_mode  = SB_BFE(disp3dcnt,1,1);/*PolygonAttr Shading  (0=Toon Shading, 1=Highlight Shading)*/
  bool alpha_test  = SB_BFE(disp3dcnt,2,1);/*Alpha-Test           (0=Disable, 1=Enable) (see ALPHA_TEST_REF)*/
  bool alpha_blend = SB_BFE(disp3dcnt,3,1);/*Alpha-Blending       (0=Disable, 1=Enable) (see various Alpha values)*/
  bool anti_alias  = SB_BFE(disp3dcnt,4,1);/*Anti-Aliasing        (0=Disable, 1=Enable)*/
  bool edge_mark   = SB_BFE(disp3dcnt,5,1);/*Edge-Marking         (0=Disable, 1=Enable) (see EDGE_COLOR)*/
  bool fogalpha_mode = SB_BFE(disp3dcnt,6,1);/*Fog Color/Alpha Mode (0=Alpha and Color, 1=Only Alpha) (see FOG_COLOR)*/
  bool fog_enable  = SB_BFE(disp3dcnt,7,1);/*Fog Master Enable    (0=Disable, 1=Enable)*/
  int fog_depth_shift = SB_BFE(disp3dcnt,8,4); /*Fog Depth Shift      (FOG_STEP=400h shr FOG_SHIFT) (see FOG_OFFSET)*/
  bool rear_plane_mode = SB_BFE(disp3dcnt,14,1);/*Rear-Plane Mode                (0=Blank, 1=Bitmap)*/

  nds_vert_t *v[3] = {nds->gpu.vert_buffer+vi0,nds->gpu.vert_buffer+vi1,nds->gpu.vert_buffer+vi2};
  for(int i=0;i<3;++i){
    SE_RPT3 v[i]->clip_pos[r]=v[i]->pos[r]/fabs(v[i]->pos[3]);
  }

  float min_p[3] = {1,1,1};
  float max_p[3] = {-1,-1,-1};
  
  for(int i=0;i<3;++i){
    SE_RPT3 if(min_p[r]>v[i]->clip_pos[r])min_p[r]=v[i]->clip_pos[r];
    SE_RPT3 if(max_p[r]<v[i]->clip_pos[r])max_p[r]=v[i]->clip_pos[r];
  }

  SE_RPT3 if(min_p[r]<-1)min_p[r]=-1;
  SE_RPT3 if(max_p[r]>1)max_p[r]=1;

  float x_inc = 2./NDS_LCD_W;
  float y_inc = 2./NDS_LCD_H;

  min_p[0] = (floor(min_p[0]*NDS_LCD_W/2)-0.5)/NDS_LCD_W*2;
  min_p[1] = (floor(min_p[1]*NDS_LCD_H/2)-0.5)/NDS_LCD_H*2;

  max_p[0] = (floor(max_p[0]*NDS_LCD_W/2+0.5)+0.5)/NDS_LCD_W*2;
  max_p[1] = (floor(max_p[1]*NDS_LCD_H/2+0.5)+0.5)/NDS_LCD_H*2;

  uint32_t poly_attr = nds->gpu.poly_attr;
  int alpha = SB_BFE(poly_attr,16,5);
  int polygon_mode = SB_BFE(poly_attr,4,2);//(0=Modulation,1=Decal,2=Toon/Highlight Shading,3=Shadow)
  bool render_front =   SB_BFE(poly_attr,6,1);
  bool render_back =  SB_BFE(poly_attr,7,1);
  bool translucent_has_depth = SB_BFE(poly_attr,11,1);
  
  //Skip non-normal triangles for now TODO: Fix this
  if(polygon_mode!=0&&polygon_mode!=2)return true;
  bool front_face=true;
  {
    float e0[3],e1[3];
    SE_RPT3 e0[r]=v[1]->clip_pos[r]-v[0]->clip_pos[r];
    SE_RPT3 e1[r]=v[2]->clip_pos[r]-v[0]->clip_pos[r];

    front_face = (e0[1]*e1[0]-e0[0]*e1[1])<=0;
    
    if(!((front_face&&render_front)||(!front_face&&render_back)))return true; 
  }

  if(nds->gpu.poly_ram_offset>=2048);//return; Ignore extra polygons for now
  else nds->gpu.poly_ram_offset++;
  bool tri_not_rendered = true; 

  for(float y=min_p[1];y<max_p[1];y+=y_inc){
    for(float x=min_p[0];x<max_p[0];x+=x_inc){

      float sub_tri_area[3]={0,0,0};

      float sample_p[3] = {x,y,0};
      for(int vid = 0;vid<3;++vid){
        float edge0[3];
        float edge1[3];
        SE_RPT3 edge0[r] = v[vid]->clip_pos[r]-sample_p[r];
        SE_RPT3 edge1[r] = v[(vid+1)%3]->clip_pos[r]-sample_p[r];
        sub_tri_area[vid]=edge0[1]*edge1[0]-edge0[0]*edge1[1];
      }

      bool same_sign = (sub_tri_area[0]<=0.0&&sub_tri_area[1]<=0.0&&sub_tri_area[2]<=0.0)||(sub_tri_area[0]>=0.0&&sub_tri_area[1]>=0.0&&sub_tri_area[2]>=0.0);

      float tri_area = sub_tri_area[0]+sub_tri_area[1]+sub_tri_area[2];

      if(!same_sign)continue;
      tri_not_rendered=false;

      float bary_nopersp[3];
      float bary[3];

      SE_RPT3 bary_nopersp[r] = sub_tri_area[(r+1)%3]/tri_area;
      SE_RPT3 bary[r] = sub_tri_area[(r+1)%3]/v[r]->pos[3];

      float bary_area = bary[0]+bary[1]+bary[2];
      SE_RPT3 bary[r] /= bary_area;


      float w = bary[0]*v[0]->pos[3]+bary[1]*v[1]->pos[3]+bary[2]*v[2]->pos[3];

      float z = bary[0]*v[0]->pos[2]+bary[1]*v[1]->pos[2]+bary[2]*v[2]->pos[2];
      //if(z<=0)continue;

      int ix = (x*0.5+0.5)*NDS_LCD_W;
      int iy = (y*0.5+0.5)*NDS_LCD_H;
      int p = ix+iy*NDS_LCD_W;

      if(nds->framebuffer_3d_depth[p]<z)continue;
      float uv[4]={0,0,0,255};
      for(int i=0;i<2;++i)uv[i]=v[0]->tex[i]*bary[0]+v[1]->tex[i]*bary[1]+v[2]->tex[i]*bary[2];

      float tex_color[4]={1,1,1,1};
      bool discard = false;
      if(tex_map)discard|=nds_sample_texture(nds, tex_color, uv);
      if(discard)continue;

      float output_col[4];
      if(polygon_mode==1){ 
        //Decal Mode
        output_col[0]=1;
        output_col[1]=0;
        output_col[2]=0;
        output_col[3]=1;
      }else if(polygon_mode==0||polygon_mode==2){
        for(int c = 0;c<4;++c){
          float col; 
          if(c==3)col=alpha/31.;
          else col =(v[0]->color[c]*bary[0]+v[1]->color[c]*bary[1]+v[2]->color[c]*bary[2])/255.;
          output_col[c]=tex_color[c]*col;

          if(output_col[c]>1.0)output_col[c]=1.;
          if(output_col[c]<0.0)output_col[c]=0.;
        }
      }
      float alpha_blend_factor = 1; 
      if(alpha_blend)alpha_blend_factor = output_col[3];
      if(alpha_test){
        int alpha_test_ref = nds9_io_read8(nds,NDS9_ALPHA_TEST_REF)&0x1f;
        if(output_col[3]<=alpha_test_ref/31.)continue; 
      }
      if(translucent_has_depth||alpha_blend_factor>0.95)nds->framebuffer_3d_depth[p]=z;
      for(int c=0;c<3;++c){
        nds->framebuffer_3d[p*4+c]=output_col[c]*255*alpha_blend_factor+(nds->framebuffer_3d[p*4+c])*(1.0-alpha_blend_factor);
      }
      if(nds->framebuffer_3d[p*4+3]<alpha_blend_factor*255)nds->framebuffer_3d[p*4+3]=alpha_blend_factor*255;
    }

  }
  return tri_not_rendered;
}
static void nds_interp_wp_vert(nds_t*nds, int v_wp, int v_wn){
  nds_vert_t* vb = nds->gpu.vert_buffer;
  float wn = vb[v_wn].pos[3];
  float wp = vb[v_wp].pos[3];
  float alpha = (0.000001-wn)/(wp-wn);

  SE_RPT4 vb[v_wn].pos[r] += (vb[v_wp].pos[r]-vb[v_wn].pos[r])*alpha;
  SE_RPT3 vb[v_wn].color[r] += (vb[v_wp].color[r]-vb[v_wn].color[r])*alpha;
  SE_RPT2 vb[v_wn].tex[r] += (vb[v_wp].tex[r]-vb[v_wn].tex[r])*alpha;

}
static bool nds_gpu_clip_tri(nds_t* nds, int vi0, int vi1, int vi2){
  //nds_gpu_draw_tri(nds,vi0,vi1,vi2);
  //return;
  int inds[3] = {vi0,vi1,vi2};
  nds_vert_t* vb = nds->gpu.vert_buffer;

  int inds_wp[3] = {-1,-1};
  int inds_wn[3] = {-1,-1};
  int wp=0;
  int wn=0; 

  for(int r = 0;r<3;++r){
    int i = inds[r];
    if(vb[i].pos[3]>0.)inds_wp[wp++]=i;
    else inds_wn[wn++]=i;
  }
  if(wn==3)return true;
  if(wp==3){
    return nds_gpu_draw_tri(nds,inds_wp[0],inds_wp[1],inds_wp[2]);
  }
  if(wp==1){
    int extra_ind0 = NDS_MAX_VERTS-1;
    int extra_ind1 = NDS_MAX_VERTS-2;
    vb[extra_ind0]=vb[inds_wn[0]];
    vb[extra_ind1]=vb[inds_wn[1]];
    nds_interp_wp_vert(nds,inds_wp[0],extra_ind0);
    nds_interp_wp_vert(nds,inds_wp[0],extra_ind1);
    return nds_gpu_draw_tri(nds,inds_wp[0],extra_ind0,extra_ind1);
  }

  int extra_ind0 = NDS_MAX_VERTS-1;
  int extra_ind1 = NDS_MAX_VERTS-2;
  vb[extra_ind0]=vb[inds_wn[0]];
  vb[extra_ind1]=vb[inds_wn[0]];
  nds_interp_wp_vert(nds,inds_wp[0],extra_ind0);
  nds_interp_wp_vert(nds,inds_wp[1],extra_ind1);
  bool culled = nds_gpu_draw_tri(nds,inds_wp[0],inds_wp[1],extra_ind0);
  culled&=nds_gpu_draw_tri(nds,inds_wp[1],extra_ind0,extra_ind1);
  return culled;
}
static void nds_gpu_process_vertex(nds_t*nds, int16_t vx,int16_t vy, int16_t vz){
  if(nds->gpu.curr_vert>=6144)return;
  nds->gpu.last_vertex_pos[0]=vx;
  nds->gpu.last_vertex_pos[1]=vy;
  nds->gpu.last_vertex_pos[2]=vz;

  if(nds->vert_log)fprintf(nds->vert_log,"Vertex {%d %d %d}\n",vx,vy,vz);
  
  float v[4] = {vx/4096.0,vy/4096.0,vz/4096.0,1.0};
  float res[4];
  nds_mult_matrix_vector(res,nds->gpu.mv_matrix,v,4);
  nds_mult_matrix_vector(v,nds->gpu.proj_matrix,res,4);
  //printf("Vert <%f, %f, %f, %f> matrix_stack_ptr:%d\n",v[0],v[1],v[2],v[3],nds->gpu.mv_matrix_stack_ptr);

  float uv[4] = {nds->gpu.curr_tex_coord[0]/16.,nds->gpu.curr_tex_coord[1]/16.,0,1};
  float abs_w = v[3];

  v[1]*=-1;

  if(abs_w!=0){
    res[0]=(v[0])/abs_w;
    res[1]=(v[1])/abs_w;
    res[2]=(v[2])/abs_w;
    res[3]=v[3];
  }else{
    res[0]=v[0]<0.?-INFINITY:INFINITY;
    res[1]=v[1]<0.?-INFINITY:INFINITY;
    res[2]=v[2]<0.?-INFINITY:INFINITY;
    res[3]=v[3];
  }
  /*
  int x0 = (res[0]*0.5+0.5)*NDS_LCD_W;
  int y0 = (res[1]*0.5+0.5)*NDS_LCD_H;
  for(int px = -1;px<1;++px)for(int py=-1;py<1;++py){
    int x = px+x0;
    int y = py+y0;
    if(x>=0&&x<NDS_LCD_W&&y>=0&&y<NDS_LCD_H){
      int p = x+y*NDS_LCD_W;
      nds->framebuffer_3d[p*4+0]=0xff;
      nds->framebuffer_3d[p*4+1]=0xff;
      nds->framebuffer_3d[p*4+2]=0xff;
      nds->framebuffer_3d[p*4+3]=0xff;
      if(res[3]<0)nds->framebuffer_3d[p*4+0]=0;
    }
  }*/
  nds_vert_t*vert = nds->gpu.vert_buffer+nds->gpu.curr_vert++;
  if(nds->gpu.curr_vert+1>= NDS_MAX_VERTS){
    nds->gpu.curr_vert = NDS_MAX_VERTS-1;
    printf("Vertex overflow\n");
  }
  nds->gpu.curr_draw_vert++;
  uint32_t tex_param = nds->gpu.tex_image_param;
  int coord_xform_mode = SB_BFE(tex_param,30,2);
  switch(coord_xform_mode){
    case 0: break;
    case 1:{
      float tex_p2[4]={uv[0],uv[1],1./16.,1./16.};
      nds_mult_matrix_vector(uv,nds->gpu.tex_matrix,tex_p2,4);
    }break;
    default:
      //printf("Unknown Tex Coord XForm mode:%d\n",coord_xform_mode);
      break;
  }
  SE_RPT3 vert->color[r]=nds->gpu.curr_color[r];
  SE_RPT2 vert->tex[r]= uv[r];
  SE_RPT4 vert->pos[r] = v[r];

  switch(nds->gpu.prim_type){
    /*Triangles */ case 0: 
      if((nds->gpu.curr_draw_vert%3)==0){
        bool culled = nds_gpu_clip_tri(nds,nds->gpu.curr_vert-3,nds->gpu.curr_vert-2,nds->gpu.curr_vert-1);
        if(culled)nds->gpu.curr_vert-=3;
      }
      break;
    /*Quads     */ case 1: 
      if((nds->gpu.curr_draw_vert%4)==0){
        bool culled=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-4+0,nds->gpu.curr_vert-4+1,nds->gpu.curr_vert-4+2);
        culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-4+2,nds->gpu.curr_vert-4+3,nds->gpu.curr_vert-4+0);
        if(culled)nds->gpu.curr_vert-=4;
      }
      break;
    /*Tristrip  */ case 2: 
      if(nds->gpu.curr_draw_vert>=3){
        bool culled = true;
        if(nds->gpu.curr_draw_vert&1)culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-3,nds->gpu.curr_vert-2,nds->gpu.curr_vert-1);
        else culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-3,nds->gpu.curr_vert-1,nds->gpu.curr_vert-2);
        nds->gpu.rendered_primitive_tracker<<=1;
        if(culled){
          nds->gpu.rendered_primitive_tracker|=1;
          if((nds->gpu.rendered_primitive_tracker&0x7)==0x7){
            nds->gpu.vert_buffer[nds->gpu.curr_vert-3]=nds->gpu.vert_buffer[nds->gpu.curr_vert-2];
            nds->gpu.vert_buffer[nds->gpu.curr_vert-2]=nds->gpu.vert_buffer[nds->gpu.curr_vert-1];
            nds->gpu.curr_vert--;
          }
        }
      }
      break;
    /*Quadstrip */ case 3: 
      if(nds->gpu.curr_draw_vert>=4&&(nds->gpu.curr_draw_vert%2)==0){
        nds->gpu.rendered_primitive_tracker<<=1;
        bool culled = true;
        if(nds->gpu.curr_draw_vert%4){
          culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-6+2,nds->gpu.curr_vert-6+3,nds->gpu.curr_vert-6+5);
          culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-6+5,nds->gpu.curr_vert-6+4,nds->gpu.curr_vert-6+2);
        }else{
          culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-4+0,nds->gpu.curr_vert-4+1,nds->gpu.curr_vert-4+3);
          culled&=nds_gpu_clip_tri(nds,nds->gpu.curr_vert-4+3,nds->gpu.curr_vert-4+2,nds->gpu.curr_vert-4+0);
        }
        if(culled){
          nds->gpu.rendered_primitive_tracker|=1;
          if((nds->gpu.rendered_primitive_tracker&0x3)==0x3){
            nds->gpu.vert_buffer[nds->gpu.curr_vert-4]=nds->gpu.vert_buffer[nds->gpu.curr_vert-2];
            nds->gpu.vert_buffer[nds->gpu.curr_vert-3]=nds->gpu.vert_buffer[nds->gpu.curr_vert-1];
            nds->gpu.curr_vert-=2;
          }
        }
      }
      break;
  }
  //printf("Vertex %f %f %f->%f %f %f\n",vx/65536.0,vy/65536.0,vz/65536.0,res[0],res[1],res[2]);
}
static int nds_gpu_cmd_params(int cmd){
  switch(cmd){
    case 0x10:return  1 ; /*MTX_MODE - Set Matrix Mode (W)*/
    case 0x11:return  0 ; /*MTX_PUSH - Push Current Matrix on Stack (W)*/
    case 0x12:return  1 ; /*MTX_POP - Pop Current Matrix from Stack (W)*/
    case 0x13:return  1 ; /*MTX_STORE - Store Current Matrix on Stack (W)*/
    case 0x14:return  1 ; /*MTX_RESTORE - Restore Current Matrix from Stack (W)*/
    case 0x15:return  0 ; /*MTX_IDENTITY - Load Unit Matrix to Current Matrix (W)*/
    case 0x16:return  16; /*MTX_LOAD_4x4 - Load 4x4 Matrix to Current Matrix (W)*/
    case 0x17:return  12; /*MTX_LOAD_4x3 - Load 4x3 Matrix to Current Matrix (W)*/
    case 0x18:return  16; /*MTX_MULT_4x4 - Multiply Current Matrix by 4x4 Matrix (W)*/
    case 0x19:return  12; /*MTX_MULT_4x3 - Multiply Current Matrix by 4x3 Matrix (W)*/
    case 0x1A:return  9 ; /*MTX_MULT_3x3 - Multiply Current Matrix by 3x3 Matrix (W)*/
    case 0x1B:return  3 ; /*MTX_SCALE - Multiply Current Matrix by Scale Matrix (W)*/
    case 0x1C:return  3 ; /*MTX_TRANS - Mult. Curr. Matrix by Translation Matrix (W)*/
    case 0x20:return  1 ; /*COLOR - Directly Set Vertex Color (W)*/
    case 0x21:return  1 ; /*NORMAL - Set Normal Vector (W)*/
    case 0x22:return  1 ; /*TEXCOORD - Set Texture Coordinates (W)*/
    case 0x23:return  2 ; /*VTX_16 - Set Vertex XYZ Coordinates (W)*/
    case 0x24:return  1 ; /*VTX_10 - Set Vertex XYZ Coordinates (W)*/
    case 0x25:return  1 ; /*VTX_XY - Set Vertex XY Coordinates (W)*/
    case 0x26:return  1 ; /*VTX_XZ - Set Vertex XZ Coordinates (W)*/
    case 0x27:return  1 ; /*VTX_YZ - Set Vertex YZ Coordinates (W)*/
    case 0x28:return  1 ; /*VTX_DIFF - Set Relative Vertex Coordinates (W)*/
    case 0x29:return  1 ; /*POLYGON_ATTR - Set Polygon Attributes (W)*/
    case 0x2A:return  1 ; /*TEXIMAGE_PARAM - Set Texture Parameters (W)*/
    case 0x2B:return  1 ; /*PLTT_BASE - Set Texture Palette Base Address (W)*/
    case 0x30:return  1 ; /*DIF_AMB - MaterialColor0 - Diffuse/Ambient Reflect. (W)*/
    case 0x31:return  1 ; /*SPE_EMI - MaterialColor1 - Specular Ref. & Emission (W)*/
    case 0x32:return  1 ; /*LIGHT_VECTOR - Set Light's Directional Vector (W)*/
    case 0x33:return  1 ; /*LIGHT_COLOR - Set Light Color (W)*/
    case 0x34:return  32; /*SHININESS - Specular Reflection Shininess Table (W)*/
    case 0x40:return  1 ; /*BEGIN_VTXS - Start of Vertex List (W)*/
    case 0x41:return  0 ; /*END_VTXS - End of Vertex List (W)*/
    case 0x50:return  1 ; /*SWAP_BUFFERS - Swap Rendering Engine Buffer (W)*/
    case 0x60:return  1 ; /*VIEWPORT - Set Viewport (W)*/
    case 0x70:return  3 ; /*BOX_TEST - Test if Cuboid Sits inside View Volume (W)*/
    case 0x71:return  2 ; /*POS_TEST - Set Position Coordinates for Test (W)*/
    case 0x72:return  1 ; /*VEC_TEST - Set Directional Vector for Test (W)*/
  }
  return 0; 
}
static int nds_gpu_cmd_cycles(int cmd){
  //https://melonds.kuribo64.net/board/thread.php?id=141
  //return 1; 
  switch(cmd){
    case 0x10:return   1 ; /*MTX_MODE - Set Matrix Mode (W)*/
    case 0x11:return  17 ; /*MTX_PUSH - Push Current Matrix on Stack (W)*/
    case 0x12:return  36 ; /*MTX_POP - Pop Current Matrix from Stack (W)*/
    case 0x13:return  17 ; /*MTX_STORE - Store Current Matrix on Stack (W)*/
    case 0x14:return  36 ; /*MTX_RESTORE - Restore Current Matrix from Stack (W)*/
    case 0x15:return  19 ; /*MTX_IDENTITY - Load Unit Matrix to Current Matrix (W)*/
    case 0x16:return  34 ; /*MTX_LOAD_4x4 - Load 4x4 Matrix to Current Matrix (W)*/
    case 0x17:return  30 ; /*MTX_LOAD_4x3 - Load 4x3 Matrix to Current Matrix (W)*/
    case 0x18:return  35 ; /*MTX_MULT_4x4 - Multiply Current Matrix by 4x4 Matrix (W)*/
    case 0x19:return  31 ; /*MTX_MULT_4x3 - Multiply Current Matrix by 4x3 Matrix (W)*/
    case 0x1A:return  28 ; /*MTX_MULT_3x3 - Multiply Current Matrix by 3x3 Matrix (W)*/
    case 0x1B:return  22 ; /*MTX_SCALE - Multiply Current Matrix by Scale Matrix (W)*/
    case 0x1C:return  22 ; /*MTX_TRANS - Mult. Curr. Matrix by Translation Matrix (W)*/
    case 0x20:return  1  ; /*COLOR - Directly Set Vertex Color (W)*/
    case 0x21:return  9  ; /*NORMAL - Set Normal Vector (W)*/
    case 0x22:return  1  ; /*TEXCOORD - Set Texture Coordinates (W)*/
    case 0x23:return  9  ; /*VTX_16 - Set Vertex XYZ Coordinates (W)*/
    case 0x24:return  8  ; /*VTX_10 - Set Vertex XYZ Coordinates (W)*/
    case 0x25:return  8  ; /*VTX_XY - Set Vertex XY Coordinates (W)*/
    case 0x26:return  8  ; /*VTX_XZ - Set Vertex XZ Coordinates (W)*/
    case 0x27:return  8  ; /*VTX_YZ - Set Vertex YZ Coordinates (W)*/
    case 0x28:return  8  ; /*VTX_DIFF - Set Relative Vertex Coordinates (W)*/
    case 0x29:return  1  ; /*POLYGON_ATTR - Set Polygon Attributes (W)*/
    case 0x2A:return  1  ; /*TEXIMAGE_PARAM - Set Texture Parameters (W)*/
    case 0x2B:return  1  ; /*PLTT_BASE - Set Texture Palette Base Address (W)*/
    case 0x30:return  4  ; /*DIF_AMB - MaterialColor0 - Diffuse/Ambient Reflect. (W)*/
    case 0x31:return  4  ; /*SPE_EMI - MaterialColor1 - Specular Ref. & Emission (W)*/
    case 0x32:return  6  ; /*LIGHT_VECTOR - Set Light's Directional Vector (W)*/
    case 0x33:return  1  ; /*LIGHT_COLOR - Set Light Color (W)*/
    case 0x34:return  32 ; /*SHININESS - Specular Reflection Shininess Table (W)*/
    case 0x40:return  1  ; /*BEGIN_VTXS - Start of Vertex List (W)*/
    case 0x41:return  1  ; /*END_VTXS - End of Vertex List (W)*/
    case 0x50:return  392; /*SWAP_BUFFERS - Swap Rendering Engine Buffer (W)*/
    case 0x60:return  1  ; /*VIEWPORT - Set Viewport (W)*/
    case 0x70:return  103; /*BOX_TEST - Test if Cuboid Sits inside View Volume (W)*/
    case 0x71:return  9  ; /*POS_TEST - Set Position Coordinates for Test (W)*/
    case 0x72:return  5  ; /*VEC_TEST - Set Directional Vector for Test (W)*/
  }
  return 1; 
}
static int32_t nds_gxfifo_size(nds_t*nds){
  return (nds->gpu.fifo_write_ptr-nds->gpu.fifo_read_ptr)%(NDS_GXFIFO_MASK);
}
static void nds_gxfifo_push(nds_t* nds, uint8_t cmd, uint32_t data){
  if(nds_gxfifo_size(nds)>=NDS_GXFIFO_STORAGE){
    printf("Error GX FIFO Overflow\n"); 
    return;
  }
  nds->gpu.fifo_cmd[nds->gpu.fifo_write_ptr%NDS_GXFIFO_STORAGE]=cmd;
  nds->gpu.fifo_data[nds->gpu.fifo_write_ptr%NDS_GXFIFO_STORAGE]=data;
  nds->gpu.fifo_write_ptr++;
}
static void nds_tick_gx(nds_t* nds){
  nds_gpu_t* gpu = &nds->gpu;
  if(gpu->cmd_busy_cycles>0){gpu->cmd_busy_cycles--;return;}
  if(gpu->pending_swap){nds_gpu_swap_buffers(nds);gpu->pending_swap=false;}
  int sz = nds_gxfifo_size(nds);
  if(sz<=NDS_GX_DMA_THRESHOLD){nds->activate_dmas|=nds->dma_wait_gx;}
  uint32_t gxstat = nds9_io_read32(nds,NDS9_GXSTAT);
  int irq_mode = SB_BFE(gxstat,30,2);
  bool less_than_half_full = sz<128;
  bool empty = sz<=0;
  switch(irq_mode){
    case 0: break;
    case 1: if(less_than_half_full)nds9_send_interrupt(nds,4,1<<NDS9_INT_GX_FIFO); break;
    case 2: if(empty)nds9_send_interrupt(nds,4,1<<NDS9_INT_GX_FIFO); break;
    default: break;
  }
  gxstat&= 0xc0000000;
  gxstat|= (gpu->mv_matrix_stack_ptr&0x1f)<<8;//8-12
  gxstat|= (gpu->proj_matrix_stack_ptr&0x1)<<13;
  
  if(gpu->matrix_stack_error)gxstat|=1<<15;
  gxstat|= (sz&0x1ff)<<16;
  if(less_than_half_full)gxstat|= 1<<25; //Less than half full
  if(empty)gxstat|= 1<<26;  //Empty
  uint8_t cmd = gpu->fifo_cmd[gpu->fifo_read_ptr%NDS_GXFIFO_STORAGE];
  uint32_t cmd_params = nds_gpu_cmd_params(cmd);
  if(sz!=0&&sz>=cmd_params)gxstat|= 1<<27;//is busy

  nds9_io_store32(nds,NDS9_GXSTAT,gxstat);
  if(sz==0)return;
  if(cmd_params<1)cmd_params=1;
  if(sz<cmd_params||sz==0)return; 

  uint32_t param_buffer[NDS_GPU_MAX_PARAM];
  for(int i=0;i<cmd_params;++i)param_buffer[i]=gpu->fifo_data[(gpu->fifo_read_ptr++)%NDS_GXFIFO_STORAGE];
  int32_t *p = (int32_t*)param_buffer;
  /*
  printf("GPU CMD: %02x fifo_size: %d Data: ",cmd,sz);
  for(int i=0;i<cmd_params;++i)printf("%08x ",p[i]);
  printf("\n");
  //*/
  float fixed_to_float = 1.0/(1<<12);
  gpu->cmd_busy_cycles= nds_gpu_cmd_cycles(cmd);

  if(SB_UNLIKELY(nds->gx_log&&cmd)){
    fprintf(nds->gx_log,"GPU CMD: %02x\n",cmd);
    fprintf(nds->gx_log,"mv_stack: %d proj_stack: %d\n",gpu->mv_matrix_stack_ptr, gpu->proj_matrix_stack_ptr);
    fprintf(nds->gx_log,"proj: ");
    for(int i=0;i<16;++i)fprintf(nds->gx_log,"%f ",gpu->proj_matrix[i]);
    fprintf(nds->gx_log,"\nmv: ");
    for(int i=0;i<16;++i)fprintf(nds->gx_log,"%f ",gpu->mv_matrix[i]);
    fprintf(nds->gx_log,"\n");
  }
  

  switch(cmd){
    case 0x0: /*NOP*/ break;
    case 0x10:/*MTX_MODE*/ nds->gpu.matrix_mode = SB_BFE(p[0],0,2);break;
    case 0x11:/*MTX_PUSH*/ 
      {
        switch (gpu->matrix_mode){
          case NDS_MATRIX_MV:case NDS_MATRIX_TBD:
            if(gpu->mv_matrix_stack_ptr>=31){gpu->matrix_stack_error=true;gpu->mv_matrix_stack_ptr=30;}
            for(int i=0;i<16;++i){gpu->mv_matrix_stack[gpu->mv_matrix_stack_ptr*16+i]=gpu->mv_matrix[i];}
            gpu->mv_matrix_stack_ptr++;
            break;
          case NDS_MATRIX_TEX:
            if(gpu->tex_matrix_stack_ptr>=1){gpu->matrix_stack_error=true;gpu->tex_matrix_stack_ptr=0;}
            for(int i=0;i<16;++i){gpu->tex_matrix_stack[i]=gpu->tex_matrix[i];}
            gpu->tex_matrix_stack_ptr++;
            break;
          case NDS_MATRIX_PROJ:
            if(gpu->proj_matrix_stack_ptr>=1){gpu->matrix_stack_error=true;gpu->proj_matrix_stack_ptr=0;}
            for(int i=0;i<16;++i){gpu->proj_matrix_stack[i]=gpu->proj_matrix[i];}
            gpu->proj_matrix_stack_ptr++;
            break;
        }
      }
      break;
    case 0x12:/*MTX_POP*/ 
    {
      int32_t pop_cnt = SB_BFE(p[0],0,6);
      if (pop_cnt & 32) pop_cnt -= 64;
      switch (gpu->matrix_mode){
        case NDS_MATRIX_MV:case NDS_MATRIX_TBD:
          gpu->mv_matrix_stack_ptr-=pop_cnt;
          if(gpu->mv_matrix_stack_ptr<0){
            gpu->matrix_stack_error=true;gpu->mv_matrix_stack_ptr=0;
          }
          if(gpu->mv_matrix_stack_ptr>31){gpu->matrix_stack_error=true;gpu->mv_matrix_stack_ptr=31;}
          for(int i=0;i<16;++i){gpu->mv_matrix[i]=gpu->mv_matrix_stack[gpu->mv_matrix_stack_ptr*16+i];}
          break;
        case NDS_MATRIX_TEX:
          gpu->tex_matrix_stack_ptr--;
          if(gpu->tex_matrix_stack_ptr<0){
            gpu->matrix_stack_error=true;gpu->tex_matrix_stack_ptr=0;
          }
          for(int i=0;i<16;++i){gpu->tex_matrix[i]=gpu->tex_matrix_stack[i];}
          break;
        case NDS_MATRIX_PROJ:
          gpu->proj_matrix_stack_ptr--;
          if(gpu->proj_matrix_stack_ptr<0){
            gpu->matrix_stack_error=true;gpu->proj_matrix_stack_ptr=0;
          }
          for(int i=0;i<16;++i){gpu->proj_matrix[i]=gpu->proj_matrix_stack[i];}
          break;
      }
      break;
    }
    case 0x13: {/*MTX_STORE*/
      float * m = nds_gpu_get_active_matrix(nds);
      int new_stack = SB_BFE(p[0],0,5)*16;
      switch (gpu->matrix_mode){
        case NDS_MATRIX_MV:case NDS_MATRIX_TBD:
          for(int i=0;i<16;++i)gpu->mv_matrix_stack[new_stack+i]=m[i];
          break;
        case NDS_MATRIX_TEX:
          for(int i=0;i<16;++i)gpu->tex_matrix_stack[i]=m[i];
          break;
        case NDS_MATRIX_PROJ:
          for(int i=0;i<16;++i)gpu->proj_matrix_stack[i]=m[i];
          break;
      }
      break;
    }
    case 0x14: {/*MTX_RESTORE*/
      float * m = nds_gpu_get_active_matrix(nds);
      int new_stack = SB_BFE(p[0],0,5)*16;
      switch (gpu->matrix_mode){
        case NDS_MATRIX_MV:case NDS_MATRIX_TBD:
          for(int i=0;i<16;++i)m[i]=gpu->mv_matrix_stack[new_stack+i];
          break;
        case NDS_MATRIX_TEX:
          for(int i=0;i<16;++i)m[i]=gpu->tex_matrix_stack[i];
          break;
        case NDS_MATRIX_PROJ:
          for(int i=0;i<16;++i)m[i]=gpu->proj_matrix_stack[i];
          break;
      }
      break;
    }
    case 0x15: /*MTX_IDENTITY - Load Unit Matrix to Current Matrix (W)*/
      nds_identity_matrix(nds_gpu_get_active_matrix(nds));
      break;
    case 0x16: /*MTX_LOAD_4x4 - Load 4x4 Matrix to Current Matrix (W)*/
      for(int i=0;i<16;++i)nds_gpu_get_active_matrix(nds)[i]=p[i]*fixed_to_float;
      break;
    case 0x17:{ /*MTX_LOAD_4x3 - Load 4x3 Matrix to Current Matrix (W)*/
      float m2[16]={
        p[0]*fixed_to_float, p[1]*fixed_to_float, p[2]*fixed_to_float,0,
        p[3]*fixed_to_float, p[4]*fixed_to_float, p[5]*fixed_to_float,0,
        p[6]*fixed_to_float ,p[7]*fixed_to_float, p[8]*fixed_to_float,0,
        p[9]*fixed_to_float, p[10]*fixed_to_float,p[11]*fixed_to_float,1.,
      };
      float*m = nds_gpu_get_active_matrix(nds);
      for(int i=0;i<16;++i)m[i]=m2[i];
      break;
    }
    case 0x18:{ /*MTX_MULT_4x4 - Multiply Current Matrix by 4x4 Matrix (W)*/
      float m[16]={
        p[0]*fixed_to_float, p[1]*fixed_to_float, p[2]*fixed_to_float,p[3]*fixed_to_float, 
        p[4]*fixed_to_float, p[5]*fixed_to_float, p[6]*fixed_to_float,p[7]*fixed_to_float,
        p[8]*fixed_to_float, p[9]*fixed_to_float, p[10]*fixed_to_float,p[11]*fixed_to_float,
        p[12]*fixed_to_float, p[13]*fixed_to_float, p[14]*fixed_to_float,p[15]*fixed_to_float
      };
      if(nds->gpu.matrix_mode==NDS_MATRIX_TBD)gpu->cmd_busy_cycles+=30;
      nds_mult_matrix4(nds_gpu_get_active_matrix(nds),m);
      break;
    }
    case 0x19:{ /*MTX_MULT_4x3 - Multiply Current Matrix by 4x3 Matrix (W)*/
      float m[16]={
        p[0]*fixed_to_float, p[1]*fixed_to_float, p[2]*fixed_to_float,0,
        p[3]*fixed_to_float, p[4]*fixed_to_float, p[5]*fixed_to_float,0,
        p[6]*fixed_to_float,p[7]*fixed_to_float, p[8]*fixed_to_float,0,
        p[9]*fixed_to_float, p[10]*fixed_to_float,p[11]*fixed_to_float,1.,
      };
      if(nds->gpu.matrix_mode==NDS_MATRIX_TBD)gpu->cmd_busy_cycles+=30;
      nds_mult_matrix4(nds_gpu_get_active_matrix(nds),m);
      break;
    }
    
    case 0x1a: { /*MTX_MULT_3x3 - Multiply Current Matrix by 3x3 Matrix (W)*/
      float m[16]={
        p[0]*fixed_to_float, p[1]*fixed_to_float, p[2]*fixed_to_float,0,
        p[3]*fixed_to_float, p[4]*fixed_to_float, p[5]*fixed_to_float,0,
        p[6]*fixed_to_float, p[7]*fixed_to_float, p[8]*fixed_to_float,0,
        0,0,0,1.,
      };
      if(nds->gpu.matrix_mode==NDS_MATRIX_TBD)gpu->cmd_busy_cycles+=30;
      nds_mult_matrix4(nds_gpu_get_active_matrix(nds),m);
      break;
    }
    case 0x1c: 
      if(nds->gpu.matrix_mode==NDS_MATRIX_TBD)gpu->cmd_busy_cycles+=30;
      nds_translate_matrix(nds_gpu_get_active_matrix(nds),p[0]*fixed_to_float,
                                                                    p[1]*fixed_to_float,
                                                                    p[2]*fixed_to_float);break; /*MTX_TRAN*/
    case 0x1b: 
      if(nds->gpu.matrix_mode==NDS_MATRIX_TBD)gpu->cmd_busy_cycles+=30;
      nds_scale_matrix(nds_gpu_get_active_matrix(nds),p[0]*fixed_to_float,
                                                                p[1]*fixed_to_float,
                                                                p[2]*fixed_to_float);break; /*MTX_SCALE*/
    case 0x20: /*COLOR - Directly Set Vertex Color (W)*/
      nds->gpu.curr_color[0]=SB_BFE(p[0],0,5)<<3;
      nds->gpu.curr_color[1]=SB_BFE(p[0],5,5)<<3;
      nds->gpu.curr_color[2]=SB_BFE(p[0],10,5)<<3;          
      nds->gpu.curr_color[3]=255;
      break;
    case 0x22:/*TEXCOORD*/
      nds->gpu.curr_tex_coord[0] = SB_BFE(p[0],0,16);
      nds->gpu.curr_tex_coord[1] = SB_BFE(p[0],16,16);
      break;
    case 0x23:/*VTX_16*/ nds_gpu_process_vertex(nds,SB_BFE(p[0],0,16),
                                          SB_BFE(p[0],16,16),
                                          SB_BFE(p[1],0,16));break;

    case 0x24:/*VTX_10*/ nds_gpu_process_vertex(nds,((int16_t)SB_BFE(p[0],0,10)<<6),
                                          ((int16_t)SB_BFE(p[0],10,10)<<6),
                                          ((int16_t)SB_BFE(p[0],20,10)<<6));
                                          break;

    case 0x25: /*VTX_XY*/ nds_gpu_process_vertex(nds,SB_BFE(p[0],0,16),
                                          SB_BFE(p[0],16,16),
                                          nds->gpu.last_vertex_pos[2]);
                                          break;
    case 0x26: /*VTX_XZ*/ nds_gpu_process_vertex(nds,SB_BFE(p[0],0,16),
                                          nds->gpu.last_vertex_pos[1],
                                          SB_BFE(p[0],16,16));
                                          break;
    case 0x27: /*VTX_YZ*/ nds_gpu_process_vertex(nds,nds->gpu.last_vertex_pos[0],
                                          SB_BFE(p[0],0,16),
                                          SB_BFE(p[0],16,16));
                                          break;
    case 0x28: /*VTX_DIFF*/ 
    nds_gpu_process_vertex(nds,(((int16_t)(SB_BFE(p[0],0,10)<<6))>>6)+nds->gpu.last_vertex_pos[0],
                                          (((int16_t)(SB_BFE(p[0],10,10)<<6))>>6)+nds->gpu.last_vertex_pos[1],
                                          (((int16_t)(SB_BFE(p[0],20,10)<<6))>>6)+nds->gpu.last_vertex_pos[2]);
                                          break;
    
    case 0x29: /*POLYGON_ATTR*/ nds->gpu.poly_attr=p[0];break;
    case 0x30: /*DIF_AMB - MaterialColor0 - Diffuse/Ambient Reflect. (W)*/
      {
        nds->gpu.curr_diffuse_color[0] = SB_BFE(p[0],0,5)<<3;
        nds->gpu.curr_diffuse_color[1] = SB_BFE(p[0],5,5)<<3;
        nds->gpu.curr_diffuse_color[2] = SB_BFE(p[0],10,5)<<3;
        bool set_vertex_color = SB_BFE(p[0],15,1);
        if(set_vertex_color||true)SE_RPT3 nds->gpu.curr_color[r]=nds->gpu.curr_diffuse_color[r];
        nds->gpu.curr_ambient_color[0] = SB_BFE(p[0],16,5)<<3;
        nds->gpu.curr_ambient_color[1] = SB_BFE(p[0],21,5)<<3;
        nds->gpu.curr_ambient_color[2] = SB_BFE(p[0],26,5)<<3;

        if(true){
          SE_RPT3 nds->gpu.curr_color[r]=nds->gpu.curr_color[r]<nds->gpu.curr_ambient_color[r]?nds->gpu.curr_ambient_color[r]:nds->gpu.curr_color[r];
        }

      }break;
    case 0x2A:nds->gpu.tex_image_param = p[0];break; /*TEXIMAGE_PARAM  - Set Texture Parameters*/
    case 0x2B:nds->gpu.tex_plt_base = p[0];   break; /*PLTT_BASE - Set Texture Palette Base Address (W)*/

    case 0x40: /*BEGIN_VTXS*/ 
      nds->gpu.prim_type = SB_BFE(p[0],0,2);
      nds->gpu.curr_draw_vert =0; 
      break;
    case 0x41: /*END_VTXS  */  nds->gpu.curr_draw_vert =0; break;
    case 0x50: 
      gpu->pending_swap=true;
      nds->gpu.cmd_busy_cycles+=nds_cycles_till_vblank(nds);
      break; //Swap buffers
    case 0x60: /*SET_VIEWPORT*/
    {
      int x0 = SB_BFE(p[0],0,8);
      int y0 = SB_BFE(p[0],8,8);
      int x1 = SB_BFE(p[0],16,8);
      int y1 = SB_BFE(p[0],24,8);
      //printf("Viewport %d %d %d %d\n",x0,y0,x1,y1);
      break;
    }
    case 0x21: case 0x31: case 0x32: case 0x33: case 0x34: case 0x38: case 0x3c: break;
    default:
      
      printf("Unhandled GPU CMD: %02x Data: ",cmd);
      for(int i=0;i<cmd_params;++i)printf("%08x ",p[i]);
      printf("\n");
      
      break;
  }
}
static void nds_gpu_write_packed_cmd(nds_t *nds, uint32_t data){
  nds_gpu_t* gpu = &nds->gpu;
  if(gpu->packed_cmd){
    bool param_consumed = false;
    while(gpu->packed_cmd){
      uint8_t cmd = gpu->packed_cmd&0xff;
      int params = nds_gpu_cmd_params(cmd);
      if(params==0){
        nds_gxfifo_push(nds,cmd,data);
        gpu->packed_cmd>>=8;
        gpu->packed_cmd_param=0;
      }else{
        if(param_consumed)break;
        nds_gxfifo_push(nds,cmd,data);
        gpu->packed_cmd_param++;
        if(gpu->packed_cmd_param>=params){
          gpu->packed_cmd>>=8;gpu->packed_cmd_param=0;
        }
        param_consumed =true;
      }
    }
  }else{
    bool unpacked_cmd = SB_BFE(data,8,24)==0;
    uint8_t cmd= SB_BFE(data,0,8);
    gpu->packed_cmd = data;
    gpu->packed_cmd_param=0; 
    if(unpacked_cmd&&nds_gpu_cmd_params(cmd)==0){
      nds_gxfifo_push(nds, cmd, data);
      gpu->packed_cmd=0;
    }
  }
}
static void nds_tick_ipc_fifo(nds_t* nds){
  for(int cpu=0;cpu<2;++cpu){
    int send_size = (nds->ipc[!cpu].write_ptr-nds->ipc[!cpu].read_ptr)&0x1f;
    int recv_size = (nds->ipc[ cpu].write_ptr-nds->ipc[ cpu].read_ptr)&0x1f;

    bool send_fifo_empty = send_size ==0;
    bool send_fifo_full  = send_size ==16;
    bool recv_fifo_empty = recv_size ==0;
    bool recv_fifo_full  = recv_size ==16;
    
    if(send_size==1){
      uint16_t cnt = nds_io_read16(nds,cpu,NDS_IPCFIFOCNT);
      bool fifo_empty_irq = SB_BFE(cnt,2,1);
      if(fifo_empty_irq){
        if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
        else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
      }
    }
    if(recv_size!=0){
      uint16_t cnt = nds_io_read16(nds,cpu,NDS_IPCFIFOCNT);
      bool fifo_not_empty_irq = SB_BFE(cnt,10,1);
      if(fifo_not_empty_irq){
        if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
        else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
      }
    }
  }
}

static bool nds_preprocess_mmio(nds_t * nds, uint32_t addr,uint32_t data, int transaction_type){
  if(addr>=0x4800000&& addr<0x4900000){
    printf("Read wifi register: 0x%08x\n",addr);
    return false;
  } 
  uint32_t word_mask = nds_word_mask(addr,transaction_type);
  uint32_t baddr =addr;
  addr&=~3;
  if(addr>= GBA_TM0CNT_L&&addr<=GBA_TM3CNT_H)nds_compute_timers(nds);
  int cpu = (transaction_type&NDS_MEM_ARM9)? NDS_ARM9: NDS_ARM7;
  /*if(addr!=0x04000208&&addr!=0x04000301&&addr!=0x04000138
    &&addr!= 0x040001c0 && addr!=0x040001c2)printf("MMIO Read: %08x\n",addr);*/

  //if(addr>=0x4000620&&addr<0x04000800&&!(transaction_type&NDS_MEM_DEBUG))printf("MMIO Read: %08x\n",addr);

  //Reading ClipMTX
  if(addr>=NDS9_CLIPMTX_RESULT&&addr<=NDS9_CLIPMTX_RESULT+0x40&&cpu==NDS_ARM9){
    float clipmtx[16];
    for(int i=0;i<16;++i)clipmtx[i] = nds->gpu.mv_matrix[i];
    nds_mult_matrix4(clipmtx, nds->gpu.proj_matrix);

    for(int i=0;i<16;++i){
      float val = clipmtx[i];
      int32_t fixed_val = val*(1<<12);
      nds9_io_store32(nds,NDS9_CLIPMTX_RESULT+i*4,fixed_val);
    }
  }
  switch(addr){
    case NDS9_IF: /*case NDS7_IF: <- duplicate address*/ 
      if(transaction_type&NDS_MEM_WRITE){
        uint32_t mmio = nds_io_read32(nds,cpu,NDS9_IF);
        data = nds_align_data(baddr,data,transaction_type);
        mmio&=~data;
        nds_io_store32(nds,cpu,addr,mmio);
        nds_tick_ipc_fifo(nds);
        return false; 
      }
      break;
    case NDS7_VRAMSTAT:{
      if(cpu==NDS_ARM9)return true;
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
    case NDS7_WRAMSTAT:{
      if(cpu==NDS_ARM7)return true;
      uint8_t wramcnt = nds9_io_read8(nds,NDS9_WRAMCNT);
      nds7_io_store8(nds,NDS7_WRAMSTAT,wramcnt);
    }break;
    case NDS_IPCSYNC:{
      uint32_t sync =nds_io_read16(nds,cpu,NDS_IPCSYNC);
      sync&=0x4f00;
      sync|=nds->ipc[cpu].sync_data;
      nds_io_store16(nds,cpu,NDS_IPCSYNC,sync);
    }break;

    case NDS_IPCFIFOCNT:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS_IPCFIFOCNT);
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
      if(send_size==1){
        bool fifo_empty_irq = SB_BFE(cnt,2,1);
        if(fifo_empty_irq){
          if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
          else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
        }
      }
      if(recv_size!=0){
        bool fifo_not_empty_irq = SB_BFE(cnt,10,1);
        if(fifo_not_empty_irq){
          if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
          else             nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
        }
      }
    }break;
    case NDS9_RDLINES_COUNT:{
      if(cpu!=NDS_ARM9)return true; 
      nds9_io_store32(nds,NDS9_RDLINES_COUNT,46);
      break;
    }
    case NDS9_RAM_COUNT:
      if(cpu!=NDS_ARM9||(transaction_type&NDS_MEM_DEBUG))return true;
      nds9_io_store16(nds,NDS9_RAM_COUNT+2,nds->gpu.curr_vert);
      nds9_io_store16(nds,NDS9_RAM_COUNT,nds->gpu.poly_ram_offset);
      break;
    case NDS9_POWCNT1:
      if(cpu!=NDS_ARM9)return true;
      uint32_t d = nds9_io_read32(nds,NDS9_POWCNT1);
      d|=1;
      nds9_io_store32(nds,NDS9_POWCNT1,d);
      break;
    case NDS_IPCFIFORECV|NDS_IO_MAP_041_OFFSET:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS9_IPCFIFOCNT);
      bool enabled = SB_BFE(cnt,15,1);
      if(!enabled)return true; 

      int size = (nds->ipc[cpu].write_ptr-nds->ipc[cpu].read_ptr)&0x1f;
      // Read empty error
      if(size==0){
        nds->ipc[cpu].error=true;
        return true; 
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
    case NDS7_EXMEMSTAT:{
      uint16_t r9 = nds9_io_read16(nds,NDS9_EXMEMCNT);
      r9|=(1<<13);//Bit 13 is always set
      nds9_io_store16(nds,NDS9_EXMEMCNT,r9);

      if(cpu!=NDS_ARM7)return true; 
      uint16_t r7 = nds7_io_read16(nds,NDS7_EXMEMSTAT);
      r7&=0x7f;
      r7|= r9&0xff80;
      nds7_io_store16(nds,NDS7_EXMEMSTAT,r7);
    }break;
    case NDS_GC_BUS:nds_process_gc_bus_read(nds,cpu);break;
    case NDS9_DIVCNT:case NDS9_DIV_RESULT: case NDS9_DIVREM_RESULT:case NDS9_DIV_RESULT+4: case NDS9_DIVREM_RESULT+4:{
      if(cpu!=NDS_ARM9)return true; 
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
      if(denom==0){
        mod_result = numer;
        result = numer>-1?-1:1;
        if(mode==0)result^=0xffffffff00000000ull;
      }else{
        result = (numer)/(denom);
        mod_result = (numer)%(denom);
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
      if(cpu!=NDS_ARM9)return true; 
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
    break; 
  }
  return true; 
}

static void nds_postprocess_mmio_write(nds_t * nds, uint32_t baddr, uint32_t data,int transaction_type){
  if(baddr>=0x4800000&& baddr<0x4900000){
    printf("Write wifi register: 0x%08x\n",baddr);
    return;
  } 
  uint32_t addr=baddr&~3;
  uint32_t mmio= (transaction_type&NDS_MEM_ARM9)? nds9_io_read32(nds,addr): nds7_io_read32(nds,addr);
  int cpu = (transaction_type&NDS_MEM_ARM9)? NDS_ARM9: NDS_ARM7; 

  if(addr>=GBA_DMA0SAD&&addr<=GBA_DMA3CNT_H)nds->activate_dmas=true;
  if(addr>=0x4000440&& addr<0x40005CC &&cpu==NDS_ARM9){
    nds_gxfifo_push(nds, (addr-0x4000400)/4, nds_align_data(baddr,data,transaction_type));
  } 
  if(addr>=0x4000400&& addr<0x4000440 &&cpu==NDS_ARM9){
      nds_gpu_write_packed_cmd(nds,mmio);
  } 
  if(addr>=NDS9_VRAMCNT_A&&addr<=NDS9_VRAMCNT_I)nds_update_vram_mapping(nds);
  switch(addr){

    case NDS7_HALTCNT&~3:
      {
        if(cpu!=NDS_ARM7)return; 
        bool halt = SB_BFE(mmio,(NDS7_HALTCNT&3)*8+6,2)>=2;
        if(halt) nds->arm7.wait_for_interrupt=true;
      }
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
    case NDS7_SPI_BUS_CTL:{
      if(cpu!=NDS_ARM7)return;
      uint16_t spicnt = nds7_io_read16(nds,NDS7_SPI_BUS_CTL);
      if(nds_word_mask(baddr,transaction_type)&0xffff){
       // printf("NDS SPI BUS CTRL:%04x\n",spicnt);
        int busy = false; 
        uint8_t device = SB_BFE(spicnt,8,2);
        bool enable = SB_BFE(spicnt,15,1);
        if(!enable||nds->spi.last_device!=device){
          nds_deselect_spi(nds);
        }
        spicnt&= ~((busy<<7));
        nds7_io_store16(nds,NDS7_SPI_BUS_CTL,spicnt);
        nds->spi.last_device = device;

      }
      //printf("NDS SPI BUS CTRL\n");
      if(nds_word_mask(baddr,transaction_type)&0xff0000){
        int device = SB_BFE(spicnt,8,2);
        bool keep_selected =SB_BFE(spicnt,11,1);
        bool irq_en = SB_BFE(spicnt,14,1);
        bool enable = SB_BFE(spicnt,15,1);
        if(!enable)return; 
        uint8_t data = 0xff;
        uint8_t cmd = nds7_io_read8(nds,NDS7_SPI_BUS_DATA);
       // printf("NDS SPI BUS DATA: %d %02x %04x\n",device,cmd,spicnt);
        switch(device){
          case NDS_SPI_POWER: /*TODO*/break;
          case NDS_SPI_TOUCH: data = nds_process_touch_ctrl_write(nds,cmd); break;
          case NDS_SPI_FIRMWARE: data = nds_process_flash_write(nds,cmd,&nds->firmware,nds->mem.firmware, NDS_FIRMWARE_SIZE); break;
          default: break;
        }
        nds7_io_store8(nds,NDS7_SPI_BUS_DATA,data);
        if(!keep_selected)nds_deselect_spi(nds);
        if(irq_en)nds7_send_interrupt(nds,4,1<<NDS7_INT_SPI);
      }
    }break;
    case NDS7_RTC_BUS:
      if(cpu!=NDS_ARM7)return;
      nds_process_rtc_state_machine(nds);
    break; 
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
      int other_cnt = cpu==NDS_ARM7? nds9_io_read16(nds,NDS_IPCFIFOCNT):nds7_io_read16(nds,NDS_IPCFIFOCNT);
      bool fifo_not_empty_irq = SB_BFE(other_cnt,10,1);
      if(fifo_not_empty_irq){
        if(cpu==NDS_ARM7)nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
        else         nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
      }
    }break;
    case NDS_IPCFIFOCNT:{
      uint32_t cnt =nds_io_read16(nds,cpu,NDS_IPCFIFOCNT);
      bool clear = SB_BFE(cnt,3,1);
      if(clear){
        nds->ipc[!cpu].write_ptr=nds->ipc[!cpu].read_ptr=0;
        nds->ipc[cpu].error=false;
        cnt&=~(1<<3);
      }
      bool error = SB_BFE(cnt,14,1);
      //Storing a 1 in the error bit clears it(rockwrestler) 
      if(error)nds->ipc[cpu].error=false;
      int size = (nds->ipc[cpu].write_ptr-nds->ipc[cpu].read_ptr)&0x1f;
      int other_size = (nds->ipc[!cpu].write_ptr-nds->ipc[!cpu].read_ptr)&0x1f;

      bool recv_fifo_not_empty_irq = SB_BFE(cnt,10,1);
      if(recv_fifo_not_empty_irq&&size){
        if(cpu==NDS_ARM7)nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
        else         nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_RECV);
      }
      bool send_fifo_empty_irq = SB_BFE(cnt,2,1);
      if(send_fifo_empty_irq&&other_size==0){
        if(cpu==NDS_ARM7)nds7_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
        else             nds9_send_interrupt(nds,4,1<<NDS_INT_IPC_FIFO_SEND);
      }

      nds_io_store16(nds,cpu,NDS_IPCFIFOCNT,cnt);
    }break;
    case NDS9_VRAMCNT_E:{
      if(cpu==NDS_ARM9){
        nds7_io_store8(nds,NDS7_WRAMSTAT,nds9_io_read8(nds,NDS9_WRAMCNT));
      }
    }break;
    case NDS9_DIVCNT:case NDS9_DIV_DENOM:case NDS9_DIV_DENOM+4:case NDS9_DIV_NUMER:case NDS9_DIV_NUMER+4:
      if(cpu==NDS_ARM7)break;
      nds->math.div_last_update_clock= nds->current_clock;
      break;

    case NDS9_SQRTCNT:case NDS9_SQRT_PARAM:case NDS9_SQRT_PARAM+4:
      if(cpu==NDS_ARM7)break;
      nds->math.sqrt_last_update_clock= nds->current_clock;
      break;
    case NDS9_AUXSPICNT: 
      if(nds_word_mask(baddr,transaction_type)&0xff0000)nds_process_gc_spi(nds,cpu); break; 
    case NDS_GCBUS_CTL|NDS_IO_MAP_SPLIT_OFFSET:
    case NDS_GCBUS_CTL:
      nds->activate_dmas=true;
      nds_process_gc_bus_ctl(nds,cpu); break;
    case GBA_TM0CNT_L:
    case GBA_TM1CNT_L:
    case GBA_TM2CNT_L:
    case GBA_TM3CNT_L:
      if(nds_word_mask(baddr,transaction_type)&0xffff){
        int t = (addr-GBA_TM0CNT_L)/4;
        nds->timers[cpu][t].pending_reload_value = nds_io_read16(nds,cpu,GBA_TM0CNT_L+t*4);
      }
      break;
    case NDS9_GXSTAT:
      if(cpu==NDS_ARM7)return;
      data = nds_align_data(baddr,data,transaction_type);
      bool reset_error = SB_BFE(data,15,1);
      if(reset_error){
        nds->gpu.matrix_stack_error=false;
        nds->gpu.mv_matrix_stack_ptr=0;
        nds->gpu.tex_matrix_stack_ptr=0;
        nds->gpu.proj_matrix_stack_ptr=0;
        //Don't reinitizliae matrices as this breaks PMD explorers of Sky
      }
      break;
    case NDS_DISP3DCNT:
      if(cpu==NDS_ARM7)return;
      data = nds_align_data(baddr,data,transaction_type);
      //12    Color Buffer RDLINES Underflow (0=None, 1=Underflow/Acknowledge)
      //13    Polygon/Vertex RAM Overflow    (0=None, 1=Overflow/Acknowledge)
      uint32_t error_ack_mask = (1<<12)|(1<<13);
      uint32_t value = nds9_io_read32(nds,NDS_DISP3DCNT);
      value&= ~(data&error_ack_mask);
      nds9_io_store32(nds,NDS_DISP3DCNT,value);
      break;
  }
}
#define NDS_CLOCKS_PER_DOT 6
static FORCE_INLINE int nds_cycles_till_vblank(nds_t*nds){
  int sc = nds->ppu[0].scan_clock;
  int clocks_per_line = 355*NDS_CLOCKS_PER_DOT;
  int clocks_til_trigger = 355*(NDS_LCD_H)*NDS_CLOCKS_PER_DOT;
  if(sc<=clocks_til_trigger)return clocks_til_trigger - sc; 

  int clocks_per_frame = 355*263*NDS_CLOCKS_PER_DOT;
  return clocks_per_frame-sc +clocks_til_trigger;
}
//Returns true if the fast forward failed to be more efficient in main emu loop
static FORCE_INLINE int nds_ppu_compute_max_fast_forward(nds_t *nds){
  int scanline_clock = (nds->ppu[0].scan_clock)%(355*NDS_CLOCKS_PER_DOT);
  //If inside hblank, can fastforward to outside of hblank
  if(scanline_clock>=NDS_LCD_W*NDS_CLOCKS_PER_DOT&&scanline_clock<=355*NDS_CLOCKS_PER_DOT) return 355*NDS_CLOCKS_PER_DOT-scanline_clock-1;
  //If inside hrender, can fastforward to hblank if not the first pixel and not visible
  bool not_visible = nds->ppu[0].scan_clock>NDS_LCD_H*355*NDS_CLOCKS_PER_DOT; 
  if(not_visible&& (scanline_clock>=1 && scanline_clock<=355*NDS_CLOCKS_PER_DOT))return NDS_LCD_W*NDS_CLOCKS_PER_DOT-scanline_clock-1; 
  return (NDS_CLOCKS_PER_DOT-1)-((nds->ppu[0].scan_clock)%NDS_CLOCKS_PER_DOT);
}
static FORCE_INLINE void nds_tick_ppu(nds_t* nds,bool render){
  nds->ppu[0].scan_clock+=1;
  nds->ppu_fast_forward_ticks--;
  if(SB_LIKELY(nds->ppu[0].scan_clock%NDS_CLOCKS_PER_DOT))return;
  int clocks_per_frame = 355*263*NDS_CLOCKS_PER_DOT;
  nds->ppu[0].scan_clock%=clocks_per_frame;
  nds->ppu_fast_forward_ticks=nds_ppu_compute_max_fast_forward(nds);
  nds->ppu[1].scan_clock=nds->ppu[0].scan_clock;
  for(int ppu_id=0;ppu_id<2;++ppu_id){
    nds_ppu_t * ppu = nds->ppu+ppu_id;
    uint32_t dispcapcnt = nds9_io_read32(nds,NDS_DISPCAPCNT);

    int reg_offset = ppu_id==0? 0: 0x00001000;

    int clocks_per_line = 355*NDS_CLOCKS_PER_DOT;
    int lcd_y = (ppu->scan_clock)/clocks_per_line;
    int lcd_x = ((ppu->scan_clock)%clocks_per_line)/NDS_CLOCKS_PER_DOT;
    if(lcd_x==0||lcd_x==NDS_LCD_W){
      uint16_t disp_stat = nds9_io_read16(nds, GBA_DISPSTAT)&~0x7;
      uint16_t disp_stat7 = nds7_io_read16(nds, GBA_DISPSTAT)&~0x7;
      uint16_t vcount_cmp = SB_BFE(disp_stat,8,8);
      uint16_t vcount_cmp7 = SB_BFE(disp_stat7,8,8);
      vcount_cmp|= SB_BFE(disp_stat,7,1)<<8;
      vcount_cmp7|= SB_BFE(disp_stat7,7,1)<<8;
      bool vblank = lcd_y>=NDS_LCD_H&&lcd_y<263;
      bool hblank = lcd_x>=NDS_LCD_W;
      bool vcmp = lcd_y==vcount_cmp;
      bool vcmp7 = lcd_y==vcount_cmp7;
      disp_stat |= vblank ? 0x1: 0; 
      disp_stat |= hblank ? 0x2: 0;      
      disp_stat |= vcmp ? 0x4: 0;   
      disp_stat7 |= vblank ? 0x1: 0; 
      disp_stat7 |= hblank ? 0x2: 0;      
      disp_stat7 |= vcmp7 ? 0x4: 0;   
      if(ppu_id==0){
        nds7_io_store16(nds,GBA_VCOUNT,lcd_y);   
        nds9_io_store16(nds,GBA_VCOUNT,lcd_y);   
        nds9_io_store16(nds,GBA_DISPSTAT,disp_stat);
        nds7_io_store16(nds,GBA_DISPSTAT,disp_stat7);
      }
      uint32_t new_if = 0;
      uint32_t new_if7 = 0;
      if(hblank!=ppu->last_hblank){
        ppu->last_hblank = hblank;
        nds->activate_dmas|=nds->dma_wait_ppu;
        if(!hblank){
          ppu->dispcnt_pipeline[0]=ppu->dispcnt_pipeline[1];
          ppu->dispcnt_pipeline[1]=ppu->dispcnt_pipeline[2];
          ppu->dispcnt_pipeline[2]=nds9_io_read16(nds, GBA_DISPCNT+reg_offset);
        }else{
          bool hblank_irq_en = SB_BFE(disp_stat,4,1);
          bool hblank_irq_en7 = SB_BFE(disp_stat7,4,1);
          if(hblank_irq_en) new_if|= (1<< GBA_INT_LCD_HBLANK); 
          if(hblank_irq_en7) new_if7|= (1<< GBA_INT_LCD_HBLANK); 
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
      if(vblank!=ppu->last_vblank){
        ppu->last_vblank = vblank;
        if(vblank){
          bool vblank_irq_en = SB_BFE(disp_stat,3,1);
          bool vblank_irq_en7 = SB_BFE(disp_stat7,3,1);
          if(vblank_irq_en)  new_if |= (1<< GBA_INT_LCD_VBLANK); 
          if(vblank_irq_en7) new_if7|= (1<< GBA_INT_LCD_VBLANK);
          //Done with capture
          dispcapcnt&=~(1<<31);
          nds9_io_store32(nds,NDS_DISPCAPCNT,dispcapcnt);
          ppu->new_frame=true;
        }else{
          for(int aff=0;aff<2;++aff){
            ppu->aff[aff].internal_bgx=nds9_io_read32(nds,GBA_BG2X+(aff)*0x10+reg_offset);
            ppu->aff[aff].internal_bgy=nds9_io_read32(nds,GBA_BG2Y+(aff)*0x10+reg_offset);

            ppu->aff[aff].internal_bgx = SB_BFE(ppu->aff[aff].internal_bgx,0,28);
            ppu->aff[aff].internal_bgy = SB_BFE(ppu->aff[aff].internal_bgy,0,28);

            ppu->aff[aff].internal_bgx = (ppu->aff[aff].internal_bgx<<4)>>4;
            ppu->aff[aff].internal_bgy = (ppu->aff[aff].internal_bgy<<4)>>4;
          }
        }
        uint16_t powcnt1 = nds9_io_read16(nds,NDS9_POWCNT1);
        nds->display_flip = SB_BFE(powcnt1,15,1);
        nds->activate_dmas|=nds->dma_wait_ppu;
      }
      if(vcmp!=ppu->last_vcmp) {
        ppu->last_vcmp=vcmp;
        bool vcnt_irq_en = SB_BFE(disp_stat,5,1);
        if(vcnt_irq_en)new_if |= (1<<GBA_INT_LCD_VCOUNT);
      }
      if(vcmp7!=ppu->last_vcmp7) {
        ppu->last_vcmp7=vcmp7;
        bool vcnt_irq_en7 = SB_BFE(disp_stat7,5,1);
        if(vcnt_irq_en7)new_if7 |= (1<<GBA_INT_LCD_VCOUNT);
      }
      
      ppu->last_lcd_y  = lcd_y;
       
      if(ppu_id==0&&(new_if|new_if7)){
        nds9_send_interrupt(nds,3,new_if);
        nds7_send_interrupt(nds,3,new_if7);
      }
    }
    uint32_t dispcnt = nds9_io_read32(nds, GBA_DISPCNT+reg_offset);
    int display_mode = SB_BFE(dispcnt,16,2);
    bool enable_capture = SB_BFE(dispcapcnt,31,1)&&ppu_id==0;
    render|=enable_capture;
    if(!render)continue;
    
    bool enable_3d = ppu_id==0&&SB_BFE(dispcnt,3,1);
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
        int oam_offset = ppu_id*1024;
        int obj_vram_base = ppu_id ==0? 0x06400000: 0x06600000;
        for(int o=0;o<128;++o){
          uint16_t attr0 = *(uint16_t*)(nds->mem.oam+o*8+0+oam_offset);
          //Attr0
          uint8_t y_coord = SB_BFE(attr0,0,8);
          bool rot_scale =  SB_BFE(attr0,8,1);
          bool double_size = SB_BFE(attr0,9,1)&&rot_scale;
          bool obj_disable = SB_BFE(attr0,9,1)&&!rot_scale;
          if(obj_disable) continue; 

          int obj_mode = SB_BFE(attr0,10,2); //(0=Normal, 1=Semi-Transparent, 2=OBJ Window, 3=bitmap)
          bool mosaic  = SB_BFE(attr0,12,1);
          bool colors_or_palettes = SB_BFE(attr0,13,1);
          int obj_shape = SB_BFE(attr0,14,2);//(0=Square,1=Horizontal,2=Vertical,3=Prohibited)
          uint16_t attr1 = *(uint16_t*)(nds->mem.oam+o*8+2+oam_offset);

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
            uint16_t attr2 = *(uint16_t*)(nds->mem.oam+o*8+4 +oam_offset);
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
                uint32_t param_base = rotscale_param*0x20+oam_offset; 
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
              uint32_t col =0;
              if(obj_mode==3){

                bool linear = SB_BFE(dispcnt,6,1);
                //TODO: Bitmap sprites
                if(linear){
                  int boundry = SB_BFE(dispcnt,22,1);
                  tile_base *= boundry? 256: 128;
                  int p = sx+sy*x_size;
                  col = nds_ppu_read16(nds,obj_vram_base+tile_base+p*2);
                }else{
                  bool size = SB_BFE(dispcnt,5,1);
                  int p = 0;             
                  if(size){
                    int tile_x=SB_BFE(tile_base,0,5);
                    int tile_y=SB_BFE(tile_base,5,5);
                    p = (tile_x*8+sx)+(tile_y*8+sy)*32*8;
                  }else{
                    int tile_x=SB_BFE(tile_base,0,4);
                    int tile_y=SB_BFE(tile_base,4,6);
                    p = (tile_x*8+sx)+(tile_y*8+sy)*16*8;
                  }
                  col = nds_ppu_read16(nds,obj_vram_base+p*2);
                  if(!SB_BFE(col,15,1))continue;
                }
              }else{
                int tx = sx%8;
                int ty = sy%8;
                bool tile_obj_mapping = SB_BFE(dispcnt,4,1);
                        
                int y_tile_stride = obj_vram_map_2d? 32 : x_size/8*(colors_or_palettes? 2:1);

                int tile_boundry = 32;
                if(tile_obj_mapping ==true){
                  int tile_obj_1d_boundry = SB_BFE(dispcnt,20,2);
                  tile_boundry = 32<<tile_obj_1d_boundry;
                  y_tile_stride=x_size/8*(colors_or_palettes? 2:1);
                }
                int tile = tile_base*tile_boundry/32 + (((sx/8))*(colors_or_palettes? 2:1)+(sy/8)*y_tile_stride);
                //tile*=tile_boundry/32;
                uint16_t palette_id;
                bool use_obj_ext_palettes = SB_BFE(dispcnt,31,1);
                if(colors_or_palettes==false){
                  palette_id= nds_ppu_read8(nds,obj_vram_base+tile*32+tx/2+ty*4);
                  palette_id= (palette_id>>((tx&1)*4))&0xf;
                  if(palette_id==0)continue;
                  palette_id+=palette*16;
                  use_obj_ext_palettes=false; //Not supported in 16 color mode
                }else{
                  palette_id=nds_ppu_read8(nds,obj_vram_base+tile*32+tx+ty*8);
                  if(palette_id==0)continue;
                }
                if(use_obj_ext_palettes){
                  palette_id=(palette)*256+palette_id;
                  uint32_t read_addr = (ppu_id?NDS_VRAM_OBJB_SLOT0:NDS_VRAM_OBJA_SLOT0)+palette_id*2;
                  col = nds_ppu_read16(nds, read_addr);
                }else{
                  uint32_t pallete_offset = ppu_id?0x600:0x200; 
                  col = *(uint16_t*)(nds->mem.palette+pallete_offset+palette_id*2);
                }
              }

              //Handle window objects(not displayed but control the windowing of other things)
              if(obj_mode==2){ppu->window[x]=obj_window_control; 
              }else{
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
          if(win_xmin>win_xmax)win_xmax=NDS_LCD_W;
          if(win_ymin>win_ymax)win_ymax=NDS_LCD_H+1;
          if(win_xmax>NDS_LCD_W)win_xmax=NDS_LCD_W;
          if(lcd_y<win_ymin||lcd_y>=win_ymax)continue;
          uint16_t winin = nds9_io_read16(nds,GBA_WININ+reg_offset);
          uint8_t win_value = SB_BFE(winin,win*8,6);
          for(int x=win_xmin;x<win_xmax;++x)ppu->window[x] = win_value;
        }
        int backdrop_type = 5;
        uint32_t backdrop_col = (*(uint16_t*)(nds->mem.palette + GBA_BG_PALETTE+0*2+ppu_id*1024))|(backdrop_type<<17);
        for(int x=0;x<NDS_LCD_W;++x){
          uint8_t window_control = ppu->window[x];
          if(SB_BFE(window_control,4,1)==0)ppu->first_target_buffer[x]=backdrop_col;
        }
      }
    }
    if(visible){
      uint8_t window_control =ppu->window[lcd_x];
      bool render_backgrounds = true; //TODO hook up power management
      if(render_backgrounds){
        for(int bg = 3; bg>=0;--bg){
          #define NDS_BG_TEXT 0
          #define NDS_BG_AFFINE 1
          #define NDS_BG_BITMAP 2
          #define NDS_BG_LARGE_BITMAP 3
          #define NDS_BG_INVALID 4

          const int bg_mode_table[8*4]={
            /* mode 0: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_TEXT,
            /* mode 1: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_AFFINE,
            /* mode 2: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_AFFINE,NDS_BG_AFFINE,
            /* mode 3: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_BITMAP,
            /* mode 4: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_AFFINE,NDS_BG_BITMAP,
            /* mode 5: */NDS_BG_TEXT,NDS_BG_TEXT,NDS_BG_BITMAP,NDS_BG_BITMAP,
            /* mode 6: */NDS_BG_TEXT,NDS_BG_INVALID,NDS_BG_LARGE_BITMAP,NDS_BG_INVALID,
            /* mode 7: */NDS_BG_INVALID,NDS_BG_INVALID,NDS_BG_INVALID,NDS_BG_INVALID,
          };
          const int bg_size_table[4*4*2]={
            /* TEXT: */        
            256,256,
            512,256,
            256,512,
            512,512,
            /* AFFINE: */ 
            128,128,
            256,256,
            512,512,
            1024,1024,
            /* BITMAP: */ 
            128,128,
            256,256,
            512,256,
            512,512,
            /* LARGE BITMAP: */
            512,1024,
            1024,512,
            0,0, //INVALID
            0,0, //INVALID
          };
          int bg_type = bg_mode_table[bg_mode*4+bg];
          if(bg_type==NDS_BG_INVALID)continue;
          uint32_t col =0;         
          bool bg_en = SB_BFE(dispcnt,8+bg,1)&&SB_BFE(ppu->dispcnt_pipeline[0],8+bg,1);
          if(!bg_en || SB_BFE(window_control,bg,1)==0)continue;

          bool rot_scale = bg_type!=NDS_BG_TEXT;
          uint16_t bgcnt = nds9_io_read16(nds, GBA_BG0CNT+bg*2+reg_offset);
          int priority = SB_BFE(bgcnt,0,2);
          int character_base = SB_BFE(bgcnt,2,4);
          bool mosaic = SB_BFE(bgcnt,6,1);
          bool colors = SB_BFE(bgcnt,7,1);
          int screen_base = SB_BFE(bgcnt,8,5);
          bool display_overflow =SB_BFE(bgcnt,13,1);
          int screen_size = SB_BFE(bgcnt,14,2); 

          if(SB_UNLIKELY(enable_3d&&bg==0)){
            int p = lcd_x+lcd_y*NDS_LCD_W;
            col  = SB_BFE(nds->framebuffer_3d_disp[p*4+0],3,5);
            col |= SB_BFE(nds->framebuffer_3d_disp[p*4+1],3,5)<<5;
            col |= SB_BFE(nds->framebuffer_3d_disp[p*4+2],3,5)<<10;
            if(SB_BFE(nds->framebuffer_3d_disp[p*4+3],3,5)==0)continue;
          }else{
            int screen_size_x = bg_size_table[(bg_type*4+screen_size)*2+0];
            int screen_size_y = bg_size_table[(bg_type*4+screen_size)*2+1];
          
            int bg_x = 0;
            int bg_y = 0;
            uint32_t pallete_offset = ppu_id?0x400:0; 

            bool use_ext_palettes = SB_BFE(dispcnt,30,1);

            if(rot_scale){
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
            int character_base_addr = character_base*16*1024;
          
            int32_t bg_base = ppu_id? 0x06200000:0x06000000;
            bool bitmap_mode = SB_BFE(bgcnt,7,1)&&(bg_type==NDS_BG_BITMAP||bg_type==NDS_BG_LARGE_BITMAP);
            bool extended_bgmap=!SB_BFE(bgcnt,7,1)&&(bg_type==NDS_BG_BITMAP||bg_type==NDS_BG_LARGE_BITMAP);
            if(bitmap_mode){
              screen_base_addr=screen_base*16*1024;
              int p = bg_x+(bg_y)*screen_size_x;
              if(bitmap_mode){
                bool direct_color = SB_BFE(bgcnt,2,1);
                if(direct_color){
                  col = nds_ppu_read16(nds,bg_base+screen_base_addr+p*2);
                  if(!SB_BFE(col,15,1))continue;
                }
                else{
                  int pallete_id  = nds_ppu_read8(nds,bg_base+screen_base_addr+p);
                  if(pallete_id==0)continue;
                  col = *(uint16_t*)(nds->mem.palette+pallete_offset+pallete_id*2);
                }
              }else{
                col = nds_ppu_read16(nds,bg_base+screen_base_addr+p*2);
              }
            }else{
              bg_x = bg_x&(screen_size_x-1);
              bg_y = bg_y&(screen_size_y-1);
              int bg_tile_x = bg_x/8;
              int bg_tile_y = bg_y/8;

              int tile_off = bg_tile_y*(screen_size_x/8)+bg_tile_x;

              //engine A screen base: BGxCNT.bits*2K + DISPCNT.bits*64K
              //engine A char base: BGxCNT.bits*16K + DISPCNT.bits*64K
              if(ppu_id==0){
                character_base_addr+=SB_BFE(dispcnt,24,3)*64*1024;
                screen_base_addr+=SB_BFE(dispcnt,27,3)*64*1024;
              }
              uint16_t tile_data =0;

              int px = bg_x%8;
              int py = bg_y%8;

              if(extended_bgmap){
                tile_data=nds_ppu_read16(nds,bg_base+screen_base_addr+tile_off*2);
                int h_flip = SB_BFE(tile_data,10,1);
                int v_flip = SB_BFE(tile_data,11,1);
                if(h_flip)px=7-px;
                if(v_flip)py=7-py;
              }else if(rot_scale){
                tile_data=nds_ppu_read8(nds,bg_base+screen_base_addr+tile_off);
                use_ext_palettes=false; //Not supported for 8bit bg map
              }else{
                int tile_off = (bg_tile_y%32)*32+(bg_tile_x%32);
                if(bg_tile_x>=32)tile_off+=32*32;
                if(bg_tile_y>=32)tile_off+=32*32*(screen_size==3?2:1);
                tile_data=nds_ppu_read16(nds,bg_base+screen_base_addr+tile_off*2);
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
                tile_d=nds_ppu_read8(nds,bg_base+character_base_addr+tile_id*8*4+px/2+py*4);
                tile_d= (tile_d>>((px&1)*4))&0xf;
                if(tile_d==0)continue;
                tile_d+=palette*16;
                use_ext_palettes=false;
              }else{
                tile_d=nds_ppu_read8(nds,bg_base+character_base_addr+tile_id*8*8+px+py*8);
                if(tile_d==0)continue;
              }
              uint32_t palette_id = tile_d;
              if(use_ext_palettes){
                palette_id=(palette)*256+tile_d;
                int ext_palette_slot = bg;
                if(bg<2)ext_palette_slot+=SB_BFE(bgcnt,13,1)*2;
                uint32_t read_addr = (ppu_id?NDS_VRAM_BGB_SLOT0:NDS_VRAM_BGA_SLOT0)+palette_id*2+0x2000*(ext_palette_slot);
                col = nds_ppu_read16(nds, read_addr);
              }else col = *(uint16_t*)(nds->mem.palette+pallete_offset+palette_id*2);
            }
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
              uint16_t bldalpha= nds9_io_read16(nds,GBA_BLDALPHA+reg_offset);
              //3d engines alpha blend based on the 3d alpha
              
              int r2 = SB_BFE(col2,0,5);
              int g2 = SB_BFE(col2,5,5);
              int b2 = SB_BFE(col2,10,5);
              int eva = SB_BFE(bldalpha,0,5);
              int evb = SB_BFE(bldalpha,8,5);
              if(enable_3d&&type==0){
                eva = nds->framebuffer_3d_disp[(lcd_x+lcd_y*NDS_LCD_W)*4+3]/16;
                if(eva==15)eva=16;
                evb = 16-eva;
              }
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
      {
        uint16_t master_brightness= nds9_io_read16(nds,ppu_id==0?NDS_A_MASTER_BRIGHT:NDS9_B_MASTER_BRIGHT);
        int factor = SB_BFE(master_brightness,0,5);
        int mode = SB_BFE(master_brightness,14,2);
        if(factor>16)factor=16;
        if(mode==1){
          r += (63-r)*factor/16;
          g += (63-g)*factor/16;
          b += (63-b)*factor/16;
        }else if(mode==2){
          r -= r*factor/16;
          g -= g*factor/16;
          b -= b*factor/16;
        }
        if(r<0)r=0;
        if(g<0)g=0;
        if(b<0)b=0;

        if(r>31)r=31;
        if(g>31)g=31;
        if(b>31)b=31;
      }
      int disp_r = r; 
      int disp_g = g; 
      int disp_b = b; 

      if(display_mode==2&&ppu_id==0){
        int vram_block = SB_BFE(dispcnt,18,2);
        uint16_t value = ((uint16_t*)nds->mem.vram)[lcd_x+lcd_y*NDS_LCD_W+vram_block*64*1024];
        disp_r = SB_BFE(value,0,5);
        disp_g = SB_BFE(value,5,5);
        disp_b = SB_BFE(value,10,5);
      }else if(display_mode==0){
        disp_r=31;
        disp_g=31;
        disp_b=31;
      }

      if(enable_capture){
        uint16_t color = (((uint16_t)r&0x1f))|(((uint16_t)g&0x1f)<<5)|(((uint16_t)b&0x1f)<<10);
        //TODO: EVA/EVB, sources other than 0
        int write_block = SB_BFE(dispcapcnt, 16,2);
        int write_offset = SB_BFE(dispcapcnt, 18,2);
        int size = SB_BFE(dispcapcnt, 20,2);
        int szx = 128; int szy = 128;
        if(size!=0){szx=256; szy= size*64;}
        bool source_a = SB_BFE(dispcapcnt,24,1);
        if(source_a&&lcd_x<NDS_LCD_W&&lcd_y<NDS_LCD_H){
          int p = lcd_x+lcd_y*NDS_LCD_W;
          color  = SB_BFE(nds->framebuffer_3d_disp[p*4+0],3,5);
          color |= SB_BFE(nds->framebuffer_3d_disp[p*4+1],3,5)<<5;
          color |= SB_BFE(nds->framebuffer_3d_disp[p*4+2],3,5)<<10;
        }
        int capture_mode = SB_BFE(dispcapcnt,29,2);
        
        if(capture_mode>=2){        
          int r = SB_BFE(color,0,5);
          int g = SB_BFE(color,5,5);
          int b = SB_BFE(color,10,5);
          int read_offset = SB_BFE(dispcapcnt, 26,2);
          uint32_t read_address = 0x06800000;
          read_address+=read_offset*0x08000;
          read_address+=lcd_y*szx*2+lcd_x*2;
          uint16_t color2=nds_ppu_read16(nds,read_address);
          if(display_mode==2)color2=ppu->first_target_buffer[lcd_x];

          int r2 = SB_BFE(color2,0,5);
          int g2 = SB_BFE(color2,5,5);
          int b2 = SB_BFE(color2,10,5);
          int eva = SB_BFE(dispcapcnt,0,5);
          int evb = SB_BFE(dispcapcnt,8,5);
      
          if(eva>16)eva=16;
          if(evb>16)evb=16;
          r = (r*eva+r2*evb)/16;
          g = (g*eva+g2*evb)/16;
          b = (b*eva+b2*evb)/16;
          if(r>31)r = 31;
          if(g>31)g = 31;
          if(b>31)b = 31;
          color  = SB_BFE(r,0,5);
          color |= SB_BFE(g,0,5)<<5;
          color |= SB_BFE(b,0,5)<<10;
        }      
        if(lcd_x<szx){
          if(lcd_y<szy){
            uint32_t write_address = 0x06800000;
            write_address+=write_block*128*1024;
            write_address+=write_offset*0x08000;
            write_address+=lcd_y*szx*2+lcd_x*2;
            color|=0x8000;//TODO: Confirm that captured alpha is always 1
            nds9_write16(nds,write_address,color);
          }
        }
      }
      int p = (lcd_x+lcd_y*NDS_LCD_W)*4;
      float screen_blend_factor = 1.0-(0.3*nds->ghosting_strength);
      if(screen_blend_factor>1.0)screen_blend_factor=1;
      if(screen_blend_factor<0.0)screen_blend_factor=0;
      
      uint8_t *framebuffer = (ppu_id==0)^nds->display_flip?nds->framebuffer_bottom: nds->framebuffer_top;
      framebuffer[p+0] = disp_r*7*screen_blend_factor+framebuffer[p+0]*(1.0-screen_blend_factor);
      framebuffer[p+1] = disp_g*7*screen_blend_factor+framebuffer[p+1]*(1.0-screen_blend_factor);
      framebuffer[p+2] = disp_b*7*screen_blend_factor+framebuffer[p+2]*(1.0-screen_blend_factor); 
      int backdrop_type = 5;
      uint32_t backdrop_col = (*(uint16_t*)(nds->mem.palette + GBA_BG_PALETTE+0*2+ppu_id*1024))|(backdrop_type<<17);
      
      ppu->first_target_buffer[lcd_x] = backdrop_col;
      ppu->second_target_buffer[lcd_x] = backdrop_col;
    }
  }
}
static void nds_tick_keypad(sb_joy_t*joy, nds_t* nds){
  for(int cpu=0;cpu<2;++cpu){
    uint16_t reg_value = 0;
    //Null joy updates are used to tick the joypad when mmios are set
    if(joy){
      reg_value|= !(joy->inputs[SE_KEY_A]>0.3)     <<0;
      reg_value|= !(joy->inputs[SE_KEY_B]>0.3)     <<1;
      reg_value|= !(joy->inputs[SE_KEY_SELECT]>0.3)<<2;
      reg_value|= !(joy->inputs[SE_KEY_START]>0.3) <<3;
      reg_value|= !(joy->inputs[SE_KEY_RIGHT]>0.3) <<4;
      reg_value|= !(joy->inputs[SE_KEY_LEFT]>0.3)  <<5;
      reg_value|= !(joy->inputs[SE_KEY_UP]>0.3)    <<6;
      reg_value|= !(joy->inputs[SE_KEY_DOWN]>0.3)  <<7;
      reg_value|= !(joy->inputs[SE_KEY_R]>0.3)     <<8;
      reg_value|= !(joy->inputs[SE_KEY_L]>0.3)     <<9;
      nds_io_store16(nds, cpu,GBA_KEYINPUT, reg_value);
    }else reg_value = nds_io_read16(nds, cpu,GBA_KEYINPUT);

    uint16_t keycnt = nds_io_read16(nds,cpu,GBA_KEYCNT);
    bool irq_enable = SB_BFE(keycnt,14,1);
    bool irq_condition = SB_BFE(keycnt,15,1);//[0: any key, 1: all keys]
    int if_bit = 0;
    if(irq_enable){
      uint16_t pressed = SB_BFE(reg_value,0,10)^0x3ff;
      uint16_t mask = SB_BFE(keycnt,0,10);

      if(irq_condition&&((pressed&mask)==mask))if_bit|= 1<<GBA_INT_KEYPAD;
      if(!irq_condition&&((pressed&mask)!=0))if_bit|= 1<<GBA_INT_KEYPAD;

      if(if_bit&&!nds->prev_key_interrupt){
        if(cpu)nds9_send_interrupt(nds,4,if_bit);
        else nds7_send_interrupt(nds,4,if_bit);
        nds->prev_key_interrupt = true;
      }else nds->prev_key_interrupt = false;

    }
  }
  uint16_t ext_key = 0; 
  if(joy){
    ext_key|= !(joy->inputs[SE_KEY_X]>0.3) <<0;
    ext_key|= !(joy->inputs[SE_KEY_Y]>0.3) <<1;
    ext_key|= !(joy->inputs[SE_KEY_PEN_DOWN]>0.3)<<6;
    ext_key|= (joy->inputs[SE_KEY_FOLD_SCREEN]>0.3) <<7;
    ext_key|= (1 <<2)|(1 <<4)|(1 <<5); //always set
    nds7_io_store16(nds,NDS7_EXTKEYIN,ext_key);
  }
}
static void nds_tick_touch(sb_joy_t*joy, nds_t* nds){
  bool is_touched = joy->inputs[SE_KEY_PEN_DOWN];
  int x = joy->touch_pos[0]*NDS_LCD_W;
  int y = joy->touch_pos[1]*NDS_LCD_H; 
  uint8_t* firm_data = nds->mem.firmware;
  uint32_t user_data_off = (firm_data[0x21]<<8)|(firm_data[0x20]);
  uint32_t tsc_data_off = user_data_off*8+0x58;

  int scr_x1 = 0, scr_x2 = 0, adc_x1 = 0, adc_x2 = 0; 
  int scr_y1 = 0, scr_y2 = 0, adc_y1 = 0, adc_y2 = 0; 

  if(tsc_data_off+12>=NDS_FIRMWARE_SIZE){
    printf("TSC Data off is outside of firmware\n");
  }else{
    uint8_t* tsc_data = firm_data +tsc_data_off;
    adc_x1  = (tsc_data[0] << 0)| (tsc_data[1] << 8);
    adc_y1  = (tsc_data[2] << 0)| (tsc_data[3] << 8);
    scr_x1 = tsc_data[4];
    scr_y1 = tsc_data[5];


    adc_x2  = (tsc_data[6] << 0)| (tsc_data[7] << 8);
    adc_y2  = (tsc_data[8] << 0)| (tsc_data[9] << 8);
    scr_x2 = tsc_data[10];
    scr_y2 = tsc_data[11];
  }
  if(is_touched){
    nds->touch.x_reg = ((x - scr_x1 + 1) * (adc_x2 - adc_x1) / (scr_x2 - scr_x1) + adc_x1)<<3;
    nds->touch.y_reg = ((y - scr_y1 + 1) * (adc_y2 - adc_y1) / (scr_y2 - scr_y1) + adc_y1)<<3;
  }else{
    nds->touch.x_reg = 0;
    nds->touch.y_reg = 0xFFF<<3;
  }
  
}
static FORCE_INLINE int nds_tick_dma(nds_t*nds, int last_tick){
  if(nds->activate_dmas==false)return 0;
  int ticks =0;
  nds->activate_dmas=false;
  nds->dma_wait_gx = false;
  nds->dma_wait_ppu= false;
  for(int cpu = 0;cpu<2;++cpu){
    nds->dma_processed[cpu]=false;
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
          nds->dma[cpu][i].trigger_mode = SB_BFE(cnt_h,11,3);
        }
        int  dst_addr_ctl = SB_BFE(cnt_h,5,2); // 0: incr 1: decr 2: fixed 3: incr reload
        int  src_addr_ctl = SB_BFE(cnt_h,7,2); // 0: incr 1: decr 2: fixed 3: not allowed
        bool dma_repeat = SB_BFE(cnt_h,9,1); 
        int  mode = nds->dma[cpu][i].trigger_mode;
        if(cpu==NDS_ARM7)mode= SB_BFE(cnt_h,12,2);
        bool irq_enable = SB_BFE(cnt_h,14,1);
        bool force_first_write_sequential = false;
        int transfer_bytes = type? 4:2; 
        bool skip_dma = false;

        if(nds->dma[cpu][i].current_transaction==0){
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
          if(mode ==1 && (!nds->ppu[0].last_vblank||last_vblank)){
            nds->dma_wait_ppu=true;
            continue; 
          } 
          if(mode==2){
            nds->dma_wait_ppu=true;
            uint16_t vcount = nds_io_read16(nds,cpu,GBA_VCOUNT);
            if(vcount>NDS_LCD_H||!nds->ppu[0].last_hblank||last_hblank)continue;
          }
          //Video dma
          if(mode==3&&cpu==NDS_ARM9){
            nds->dma_wait_ppu=true;
            uint16_t vcount = nds_io_read16(nds,cpu,GBA_VCOUNT);
            if(!nds->ppu[0].last_hblank||last_hblank)continue;
            //Video dma starts at scanline 2
            if(vcount<2)continue;
            if(vcount==NDS_LCD_H+1)dma_repeat=false;
          }
          //GC Card DMA
          if((mode==5&&cpu==NDS_ARM9)||(mode==2&&cpu==NDS_ARM7)){
            uint32_t ctl= nds_io_read32(nds,cpu,NDS_GCBUS_CTL);
            uint32_t ready_mask = (1u<<31)|(1<<23); //Block Status = Word Status = 1; 
            if((ctl&ready_mask)!=ready_mask)continue;
          }
          if(dst_addr_ctl==3){
            nds->dma[cpu][i].dest_addr=nds_io_read32(nds,cpu,GBA_DMA0DAD+12*i);
            //GBA Suite says that these need to be force aligned
            if(type) nds->dma[cpu][i].dest_addr&=~3;
            else nds->dma[cpu][i].dest_addr&=~1;
          }
          if(nds->dma[cpu][i].source_addr>=0x08000000&&nds->dma[cpu][i].dest_addr>=0x08000000){
            force_first_write_sequential=true;
          }
          nds->last_transaction_dma=true;
          uint32_t cnt = nds_io_read16(nds,cpu,GBA_DMA0CNT_L+12*i);

          cnt&=0x1FFFFF;
          if(cnt==0)cnt =0x200000;
          if(cpu==NDS_ARM7){
            static const uint32_t src_mask[] = { 0x07FFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
            static const uint32_t dst_mask[] = { 0x07FFFFFF, 0x07FFFFFF, 0x07FFFFFF, 0x0FFFFFFF};
            static const uint32_t len_mask[] = { 0x3FFF, 0x3FFF,0x3FFF, 0x1FFFFF};
            nds->dma[cpu][i].source_addr&=src_mask[i];
            nds->dma[cpu][i].dest_addr  &=dst_mask[i];
            cnt&=len_mask[i];
            if(cnt==0)cnt =len_mask[i]+1;
          }else{
            static const uint32_t src_mask[] = { 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
            static const uint32_t dst_mask[] = { 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF};
            nds->dma[cpu][i].source_addr&=src_mask[i];
            nds->dma[cpu][i].dest_addr  &=dst_mask[i];
          }
          nds_io_store16(nds,cpu,GBA_DMA0CNT_L+12*i,cnt);
          if(nds->dma_log)fprintf(nds->dma_log,"DMA[%d][%d]: Src: 0x%08x DST: 0x%08x Cnt:%d mode: %d\n",cpu,i,nds->dma[cpu][i].source_addr,nds->dma[cpu][i].dest_addr,cnt,mode);
          //printf("DMA[%d][%d]: Src: 0x%08x DST: 0x%08x Cnt:%d mode: %d\n",cpu,i,nds->dma[cpu][i].source_addr,nds->dma[cpu][i].dest_addr,cnt,mode);

        }
        
        const static int dir_lookup[4]={1,-1,0,1};
        int src_dir = dir_lookup[src_addr_ctl];
        int dst_dir = dir_lookup[dst_addr_ctl];

        uint32_t src = nds->dma[cpu][i].source_addr;
        uint32_t dst = nds->dma[cpu][i].dest_addr;
        uint32_t cnt = nds_io_read16(nds,cpu,GBA_DMA0CNT_L+12*i);

        if(mode==0x7&&cpu==NDS_ARM9){
          nds->dma_wait_gx = true;
          if(nds->dma[cpu][i].gx_dma_subtransfer<=0){
            if(nds_gxfifo_size(nds)>=NDS_GX_DMA_THRESHOLD){
              //printf("Wait for threshold:%d\n",nds_gxfifo_size(nds));
              continue;
            }
            nds->dma[cpu][i].gx_dma_subtransfer=111;
          }else{
            nds->dma[cpu][i].gx_dma_subtransfer--;
            //printf("Subtransfer:%d \n",nds->dma[cpu][i].gx_dma_subtransfer);
          } 
        }

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
            nds->dma_processed[cpu]|=true;
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
          /*if(mode==0x7){
            printf("GX FIFO DMA:%d of %d data:0x%08x\n",nds->dma[cpu][i].current_transaction,cnt,nds->dma[cpu][i].latched_transfer);
          }*/
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
            uint32_t if_bit = 1<<(GBA_INT_DMA0+i);
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
      nds9_send_interrupt(nds,4,if_bit);
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

  int ticks = nds->deferred_timer_ticks; 
  nds->deferred_timer_ticks=0;
  int timer_ticks_before_event = 32768; 
  for(int cpu=0;cpu<2;++cpu){
    int last_timer_overflow = 0; 
    for(int t=0;t<4;++t){ 
      uint16_t tm_cnt_h = nds_io_read16(nds,cpu,GBA_TM0CNT_H+t*4);
      bool enable = SB_BFE(tm_cnt_h,7,1);
      nds_timer_t* timer = &(nds->timers[cpu][t]);
      if(enable){
        int compensated_ticks = ticks;
        uint16_t prescale = SB_BFE(tm_cnt_h,0,2);
        bool count_up     = SB_BFE(tm_cnt_h,2,1)&&t!=0;
        bool irq_en       = SB_BFE(tm_cnt_h,6,1);
        uint16_t value = nds_io_read16(nds,cpu,GBA_TM0CNT_L+t*4);
        if(enable!=timer->last_enable&&enable){
          timer->startup_delay=2;
          value = timer->reload_value;
          nds_io_store16(nds,cpu,GBA_TM0CNT_L+t*4,value);
        }
        if(timer->startup_delay>=0){
          timer->startup_delay-=ticks; 
          timer->last_enable = enable;
          if(timer->startup_delay>=0){
            if(timer->startup_delay<timer_ticks_before_event)timer_ticks_before_event=timer->startup_delay;
            continue;
          }
          compensated_ticks=-timer->startup_delay;
          timer->startup_delay=-1;
          timer->prescaler_timer=0;
        }

        if(count_up){
          if(last_timer_overflow){
            uint32_t v= value;
            v+=last_timer_overflow;
            last_timer_overflow=0;
            while(v>0xffff){
              v=(v+timer->reload_value)-0x10000;
              last_timer_overflow++;
            }
            value=v;
          }
        }else{
          last_timer_overflow=0;
          int prescale_time = timer->prescaler_timer;
          prescale_time+=compensated_ticks;
          const int prescaler_lookup[]={0,6,8,10};
          int prescale_duty = prescaler_lookup[prescale];

          int increment = prescale_time>>prescale_duty;
          prescale_time = prescale_time&((1<<prescale_duty)-1);
          int v = value+increment;
          while(v>0xffff){
            v=(v+timer->reload_value)-0x10000;
            last_timer_overflow++;
          }
          value = v; 
          timer->prescaler_timer=prescale_time;
          int ticks_before_overflow = (int)(0xffff-value)<<(prescale_duty);
          if(ticks_before_overflow<timer_ticks_before_event)timer_ticks_before_event=ticks_before_overflow;
        }
        timer->reload_value=timer->pending_reload_value;
        if(last_timer_overflow && irq_en){
          uint16_t if_bit = 1<<(GBA_INT_TIMER0+t);
          if(cpu==NDS_ARM9)nds9_send_interrupt(nds,4,if_bit); 
          else nds7_send_interrupt(nds,4,if_bit);       
        }
        nds_io_store16(nds,cpu,GBA_TM0CNT_L+t*4,value);
      }else last_timer_overflow=0;
      timer->last_enable = enable;
    }
  }
  nds->timer_ticks_before_event=timer_ticks_before_event;
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
      nds9_io_store32(nds,NDS9_IF,if_val);
    }
    if_bit = nds->nds7_pipelined_if[0];
    if(if_bit){
      uint32_t if_val = nds7_io_read32(nds,NDS7_IF);
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
static FORCE_INLINE void nds_tick_audio(nds_t*nds, sb_emu_state_t*emu, double delta_time, int cycles){

  nds_audio_t* audio = &nds->audio;
  if(delta_time>1.0/60.)delta_time = 1.0/60.;
  audio->current_sim_time +=delta_time;
  audio->cycles_since_tick +=cycles;
  float sample_delta_t = 1.0/SE_AUDIO_SAMPLE_RATE;

  while(audio->current_sample_generated_time < audio->current_sim_time){

    audio->current_sample_generated_time+=sample_delta_t;
    
    if((sb_ring_buffer_size(&emu->audio_ring_buff)+3>SB_AUDIO_RING_BUFFER_SIZE)) continue;
    const float lowpass_coef = 0.999;

    float l = 0, r = 0; 
    for(int c = 0; c<16;++c){
      uint32_t cnt = nds7_io_read32(nds,NDS7_SOUND0_CNT+c*16);
      bool enable = SB_BFE(cnt,31,1);
      uint32_t tmr = nds7_io_read16(nds,NDS7_SOUND0_TMR+c*16)*2;
      int format =  SB_BFE(cnt,29,2);//(0=PCM8, 1=PCM16, 2=IMA-ADPCM, 3=PSG/Noise);
      if(!enable){
        audio->channel[c].sample=0;

        audio->channel[c].timer = tmr;
        emu->audio_channel_output[c] = emu->audio_channel_output[c]*lowpass_coef;
        continue;
      }
      uint32_t sad = nds7_io_read32(nds,NDS7_SOUND0_SAD+c*16);
      uint16_t pnt = nds7_io_read16(nds,NDS7_SOUND0_PNT+c*16);
      uint16_t len = nds7_io_read32(nds,NDS7_SOUND0_LEN+c*16);
      uint32_t tot_samps = len*4;
      switch(format){
        case 0: tot_samps = len*4; pnt*=4;break;
        case 1: tot_samps = len*2;break;
        case 2: tot_samps = 8*(len-1); pnt*=8;break;
        case 3: tot_samps = 8;  break;
      }
      if(audio->channel[c].sample>=tot_samps){
        int repeat_mode = SB_BFE(cnt,27,2);
        switch(repeat_mode){
          case 0: audio->channel[c].sample=0;enable=false; break; //Manual
          case 1: audio->channel[c].sample=pnt;break; //Infinite
          case 2: audio->channel[c].sample=0;enable=false; break; //One Shot
          case 3: audio->channel[c].sample=0;enable=false; break; //Reserved
        }
        if(format==3){enable=true;audio->channel[c].sample=0;}
      }
      if(!enable){
        cnt&=~(1u<<31);
        nds7_io_store32(nds,NDS7_SOUND0_CNT+c*16,cnt);

      }else{
        float v = 0; 
        switch(format){
          case 0: v= ((int8_t)nds7_read8(nds,sad+audio->channel[c].sample))/128.;break;
          case 1: v= ((int16_t)nds7_read16(nds,sad+audio->channel[c].sample*2))/32768.;break;
          case 2: v= audio->channel[c].adpcm_sample / 32768.0;break;
          case 3: v= audio->channel[c].sample<SB_BFE(cnt,24,3);break; //Todo: add antialiasing
        }
        uint32_t vol_mul = SB_BFE(cnt,0,7);
        uint32_t vol_div = SB_BFE(cnt,8,2);
        uint16_t pan = SB_BFE(cnt,16,7);
        float div_table[4]={1.0,0.5,0.25,1.0/16.};
        v*=0.01*vol_mul*div_table[vol_div];
        emu->audio_channel_output[c] = emu->audio_channel_output[c]*lowpass_coef + fabs(v)*(1.0-lowpass_coef);
        r+=v*pan/128.;
        l+=v*(128-pan)/128.;
      }
      audio->channel[c].timer+=audio->cycles_since_tick;
      while(audio->channel[c].timer>0x1ffff){
        audio->channel[c].timer-=0x20000;
        audio->channel[c].timer+=tmr;
        if(format==2){
           static const int16_t adpcm_table[89] ={
              0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 
              0x0010, 0x0011, 0x0013, 0x0015, 0x0017, 0x0019, 0x001C, 0x001F, 
              0x0022, 0x0025, 0x0029, 0x002D, 0x0032, 0x0037, 0x003C, 0x0042,
              0x0049, 0x0050, 0x0058, 0x0061, 0x006B, 0x0076, 0x0082, 0x008F, 
              0x009D, 0x00AD, 0x00BE, 0x00D1, 0x00E6, 0x00FD, 0x0117, 0x0133,
              0x0151, 0x0173, 0x0198, 0x01C1, 0x01EE, 0x0220, 0x0256, 0x0292,
              0x02D4, 0x031C, 0x036C, 0x03C3, 0x0424, 0x048E, 0x0502, 0x0583,
              0x0610, 0x06AB, 0x0756, 0x0812, 0x08E0, 0x09C3, 0x0ABD, 0x0BD0,
              0x0CFF, 0x0E4C, 0x0FBA, 0x114C, 0x1307, 0x14EE, 0x1706, 0x1954,
              0x1BDC, 0x1EA5, 0x21B6, 0x2515, 0x28CA, 0x2CDF, 0x315B, 0x364B,
              0x3BB9, 0x41B2, 0x4844, 0x4F7E, 0x5771, 0x602F, 0x69CE, 0x7462,
              0x7FFF
            };
            static const int adpcm_indextable[8]={ -1, -1, -1, -1, 2, 4, 6, 8 };
            if(audio->channel[c].sample==0){
              uint32_t header = nds7_read32(nds,sad);
              audio->channel[c].adpcm_sample = (int16_t)(header & 0xFFFF);
              audio->channel[c].adpcm_index = (header >> 16) & 0x7F;
              if(audio->channel[c].adpcm_index>88)audio->channel[c].adpcm_index=88;
            }
            uint8_t data = nds7_read8(nds,sad+audio->channel[c].sample/2+4);
            data = (data>>((audio->channel[c].sample&1)*4))&0xf;

            int16_t entry = adpcm_table[audio->channel[c].adpcm_index];
            int16_t diff = entry >> 3;
            if (data & 1) diff += entry >> 2;
            if (data & 2) diff += entry >> 1;
            if (data & 4) diff += entry;

            if (data & 8) audio->channel[c].adpcm_sample = audio->channel[c].adpcm_sample - diff;
            else audio->channel[c].adpcm_sample = audio->channel[c].adpcm_sample + diff;
            if(audio->channel[c].adpcm_sample>+0x7FFF)audio->channel[c].adpcm_sample=0x7fff;
            if(audio->channel[c].adpcm_sample<-0x7FFF)audio->channel[c].adpcm_sample=-0x7fff;
            int new_index = audio->channel[c].adpcm_index + adpcm_indextable[data & 7];
            if(new_index>88)new_index=88;
            if(new_index<0)new_index=0;
            audio->channel[c].adpcm_index =new_index;
        }
        audio->channel[c].sample+=1;
      }
    }

    // Clipping
    if(l>1.0)l=1;
    if(r>1.0)r=1;
    if(l<-1.0)l=-1;
    if(r<-1.0)r=-1;
    l*=0.5;
    r*=0.5;
    // Quantization
    unsigned write_entry0 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
    unsigned write_entry1 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;

    emu->mix_l_volume = emu->mix_l_volume*lowpass_coef + fabs(l)*(1.0-lowpass_coef);
    emu->mix_r_volume = emu->mix_r_volume*lowpass_coef + fabs(r)*(1.0-lowpass_coef); 


    emu->audio_ring_buff.data[write_entry0] = l*32760;
    emu->audio_ring_buff.data[write_entry1] = r*32760;
    audio->cycles_since_tick=0;
  }
}


void nds_tick(sb_emu_state_t* emu, nds_t* nds, nds_scratch_t* scratch){
  //printf("#####New Frame#####\n");
  nds->ghosting_strength = emu->screen_ghosting_strength;

  nds->arm7.read8      = nds7_arm_read8;
  nds->arm7.read16     = nds7_arm_read16;
  nds->arm7.read32     = nds7_arm_read32;
  nds->arm7.read16_seq = nds7_arm_read16_seq;
  nds->arm7.read32_seq = nds7_arm_read32_seq;
  nds->arm7.write8     = nds7_arm_write8;
  nds->arm7.write16    = nds7_arm_write16;
  nds->arm7.write32    = nds7_arm_write32;
  nds->arm9.read8      = nds9_arm_read8;
  nds->arm9.read16     = nds9_arm_read16;
  nds->arm9.read32     = nds9_arm_read32;
  nds->arm9.read16_seq = nds9_arm_read16_seq;
  nds->arm9.read32_seq = nds9_arm_read32_seq;
  nds->arm9.write8     = nds9_arm_write8;
  nds->arm9.write16    = nds9_arm_write16;
  nds->arm9.write32    = nds9_arm_write32;
  nds->arm9.coprocessor_read =  nds->arm7.coprocessor_read =nds_coprocessor_read;
  nds->arm9.coprocessor_write=  nds->arm7.coprocessor_write=nds_coprocessor_write;

  nds->arm7.user_data = (void*)nds;
  nds->arm9.user_data = (void*)nds;

  nds->mem.nds7_bios=scratch->nds7_bios;
  nds->mem.nds9_bios=scratch->nds9_bios;
  nds->mem.firmware=scratch->firmware;
  nds->mem.save_data = scratch->save_data;
  nds->mem.card_data = emu->rom_data;
  nds->mem.card_size = emu->rom_size;
  nds->framebuffer_top=scratch->framebuffer_top;
  nds->framebuffer_bottom=scratch->framebuffer_bottom;
  nds->framebuffer_3d_depth=scratch->framebuffer_3d_depth;
  nds->framebuffer_3d=scratch->framebuffer_3d;
  nds->framebuffer_3d_disp=scratch->framebuffer_3d_disp;
  nds_tick_rtc(nds);
  nds_tick_keypad(&emu->joy,nds);
  nds_tick_touch(&emu->joy,nds);
  static int last_tick =0;
  bool prev_vblank=true;

  uint64_t* d = (uint64_t*)nds->mem.mmio_debug_access_buffer;
  for(int i=0;i<sizeof(nds->mem.mmio_debug_access_buffer)/8;++i){
    d[i]&=0x9191919191919191ULL;
  }
  nds->ppu[0].new_frame=false;
  while(!nds->ppu[0].new_frame){
    bool gx_fifo_full = nds_gxfifo_size(nds)>=NDS_GXFIFO_SIZE;
    if(!gx_fifo_full) nds_tick_dma(nds,last_tick);
    
    {
      if(SB_LIKELY(!nds->dma_processed[0])){
        uint32_t int7_if = nds7_io_read32(nds,NDS7_IF);
        if(int7_if){
          uint32_t ie = nds7_io_read32(nds,NDS7_IE);
          uint32_t ime = nds7_io_read32(nds,NDS7_IME);
          int7_if&=ie;
          if((ime&0x1)&&int7_if) arm7_process_interrupts(&nds->arm7, int7_if);
        }
        if(SB_UNLIKELY(nds->arm7.registers[PC]== emu->pc_breakpoint))nds->arm7.trigger_breakpoint=true;
        else arm7_exec_instruction(&nds->arm7);
      }
      if(SB_LIKELY(!nds->dma_processed[1])&&!gx_fifo_full){
        uint32_t int9_if = nds9_io_read32(nds,NDS9_IF);
        if(int9_if){
          int9_if &= nds9_io_read32(nds,NDS9_IE);
          uint32_t ime = nds9_io_read32(nds,NDS9_IME);
          if((ime&0x1)&&int9_if) arm7_process_interrupts(&nds->arm9, int9_if);
        }
        if(SB_LIKELY(!nds->arm9.wait_for_interrupt)){
          if(SB_UNLIKELY(nds->arm9.registers[PC]== emu->pc_breakpoint))nds->arm9.trigger_breakpoint=true;
          else{
            arm9_exec_instruction(&nds->arm9);
            if(SB_UNLIKELY(nds->arm9.registers[PC]== emu->pc_breakpoint))nds->arm9.trigger_breakpoint=true;
            else arm9_exec_instruction(&nds->arm9);
          }
        }
      }
      if(SB_UNLIKELY(nds->arm7.trigger_breakpoint||nds->arm9.trigger_breakpoint)){
        emu->run_mode = SB_MODE_PAUSE;
        nds->arm7.trigger_breakpoint=false;
        nds->arm9.trigger_breakpoint=false;
        break;
      }
    }      
    int ticks = 1;
    last_tick=ticks;

    if(SB_LIKELY(nds->active_if_pipe_stages==0)&&nds->arm9.wait_for_interrupt&&nds->arm7.wait_for_interrupt){
      int ppu_fast_forward = nds->ppu_fast_forward_ticks;
      if(nds->gpu.cmd_busy_cycles&&nds->gpu.cmd_busy_cycles<=ppu_fast_forward)ppu_fast_forward=nds->gpu.cmd_busy_cycles-1; 
      int timer_fast_forward = nds->timer_ticks_before_event-nds->deferred_timer_ticks;
      int fast_forward_ticks=ppu_fast_forward<timer_fast_forward?ppu_fast_forward:timer_fast_forward; 
      if(fast_forward_ticks){
        nds->deferred_timer_ticks+=fast_forward_ticks;
        nds->ppu[0].scan_clock+=fast_forward_ticks;
        nds->ppu[1].scan_clock+=fast_forward_ticks;
        nds->ppu_fast_forward_ticks-=fast_forward_ticks;
        if(nds->gpu.cmd_busy_cycles)nds->gpu.cmd_busy_cycles-=fast_forward_ticks;
        ticks =ticks<fast_forward_ticks?0:ticks-fast_forward_ticks;
      }
      double delta_t = ((double)ticks+fast_forward_ticks)/(33513982);
      nds_tick_audio(nds, emu,delta_t,ticks+fast_forward_ticks);
    }else{
      double delta_t = ((double)ticks)/(33513982);
      nds_tick_audio(nds,emu,delta_t,ticks);
    }
    //nds_tick_sio(nds);
    for(int t = 0;t<ticks;++t){
      nds_tick_interrupts(nds);
      nds_tick_timers(nds);
      nds_tick_ppu(nds,emu->render_frame);
      nds_tick_gx(nds);
      nds->current_clock++;
    }
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
#endif
