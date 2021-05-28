/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
 **/

#ifndef SB_TYPES_H 
#define SB_TYPES_H 1

#include <stdint.h>

#define MAX_CARTRIDGE_SIZE 8 * 1024 * 1024
#define SB_U16_LO(A) ((A)&0xff)
#define SB_U16_LO_SET(A,VAL) A = (((A)&0xff00)|(((int)(VAL))&0xff))
#define SB_U16_HI(A) ((A >> 8) & 0xff)
#define SB_U16_HI_SET(A,VAL) A = (((A)&0x00ff)|((((int)(VAL))&0xff)<<8))


// Extract bits from a bitfield
#define SB_BFE(VALUE, BITOFFSET, SIZE)                                         \
  (((VALUE) >> (BITOFFSET)) & ((1u << (SIZE)) - 1))
#define SB_MODE_RESET 0
#define SB_MODE_PAUSE 1
#define SB_MODE_RUN 2
#define SB_MODE_STEP 3

#define SB_LCD_W 160
#define SB_LCD_H 144

// Draw and process scroll bar style edition controls

typedef struct {
  int run_mode;          // [0: Reset, 1: Pause, 2: Run, 3: Step ]
  int step_instructions; // Number of instructions to advance while stepping
  int pc_breakpoint;     // PC to run until
} sb_emu_state_t;

typedef struct {
  // Registers
  uint16_t af, bc, de, hl, sp, pc;
  bool interrupt_enable;
  bool prefix_op;
  bool trigger_breakpoint; 
} sb_gb_cpu_t;

typedef struct {
  uint8_t data[65536];
} sb_gb_mem_t;

typedef struct {
  uint8_t data[MAX_CARTRIDGE_SIZE];
  char title[17];
  bool game_boy_color;
  uint8_t type;
  int rom_size;
  int ram_size;
} sb_gb_cartridge_t;
typedef struct{
  bool up,down,left,right;
  bool a, b, start, select;  
} sb_gb_joy_t;

typedef struct{
  unsigned int scanline_cycles;
  unsigned int curr_scanline;
  uint8_t framebuffer[SB_LCD_W*SB_LCD_H*3];
} sb_lcd_ppu_t;
 
typedef struct {
  sb_gb_cartridge_t cart;
  sb_gb_cpu_t cpu;
  sb_gb_joy_t joy; 
  sb_gb_mem_t mem;
  sb_lcd_ppu_t lcd;
} sb_gb_t;  

typedef void (*sb_opcode_impl_t)(sb_gb_t*,int op1,int op2, int op1_enum, int op2_enum, const uint8_t * flag_mask);
#endif
