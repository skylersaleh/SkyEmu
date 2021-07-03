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

#define SB_FILE_PATH_SIZE 1024
#define MAX_CARTRIDGE_SIZE 8 * 1024 * 1024
#define MAX_CARTRIDGE_RAM 128 * 1024
#define SB_U16_LO(A) ((A)&0xff)
#define SB_U16_LO_SET(A,VAL) A = (((A)&0xff00)|(((int)(VAL))&0xff))
#define SB_U16_HI(A) ((A >> 8) & 0xff)
#define SB_U16_HI_SET(A,VAL) A = (((A)&0x00ff)|((((int)(VAL))&0xff)<<8))


// Extract bits from a bitfield
#define SB_BFE(VALUE, BITOFFSET, SIZE)                                         \
  (((VALUE) >> (BITOFFSET)) & ((1u << (SIZE)) - 1))
#define SB_BIT_TEST(VALUE,BITOFFSET) ((VALUE)&(1u<<(BITOFFSET)))
#define SB_MODE_RESET 0
#define SB_MODE_PAUSE 1
#define SB_MODE_RUN 2
#define SB_MODE_STEP 3

#define SB_LCD_W 160
#define SB_LCD_H 144
#define SB_PPU_BG_COLOR_PALETTES 64
#define SB_PPU_SPRITE_COLOR_PALETTES 64
#define SB_VRAM_BANK_SIZE 8192
#define SB_VRAM_NUM_BANKS 2

#define SB_WRAM_BANK_SIZE 4096
#define SB_WRAM_NUM_BANKS 8

#define SB_GB 0 
#define SB_GBC 1 

#define SB_PANEL_CPU      0
#define SB_PANEL_TILEMAPS 1
#define SB_PANEL_TILEDATA 2
#define SB_PANEL_AUDIO    3

//Should be power of 2 for perf, 8192 samples gives ~85ms maximal latency for 48kHz
#define SB_AUDIO_RING_BUFFER_SIZE (8192*32)

// Draw and process scroll bar style edition controls

typedef struct {
  int run_mode;          // [0: Reset, 1: Pause, 2: Run, 3: Step ]
  int step_instructions; // Number of instructions to advance while stepping
  int pc_breakpoint;     // PC to run until
  int panel_mode;
  bool rom_loaded;
} sb_emu_state_t;

typedef struct {
  // Registers
  uint16_t af, bc, de, hl, sp, pc;
  bool interrupt_enable;
  bool deferred_interrupt_enable;
  bool wait_for_interrupt; 
  bool prefix_op;
  bool trigger_breakpoint; 
  int last_inter_f; 
} sb_gb_cpu_t;

typedef struct {
  uint8_t data[65536];
  uint8_t wram[SB_WRAM_NUM_BANKS*SB_WRAM_BANK_SIZE];
} sb_gb_mem_t;

typedef struct {
  uint8_t data[MAX_CARTRIDGE_SIZE];
  uint8_t ram_data[MAX_CARTRIDGE_RAM]; 
  char title[17];
  char save_file_path[SB_FILE_PATH_SIZE]; 
  bool game_boy_color;
  bool ram_write_enable;
  bool ram_is_dirty; 
  uint8_t type;
  uint8_t mbc_type; 
  uint8_t mapped_ram_bank;
  unsigned mapped_rom_bank;
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
  unsigned int curr_window_scanline;
  uint8_t framebuffer[SB_LCD_W*SB_LCD_H*3];
  uint8_t vram[SB_VRAM_BANK_SIZE*SB_VRAM_NUM_BANKS];
  uint8_t color_palettes[SB_PPU_BG_COLOR_PALETTES+SB_PPU_SPRITE_COLOR_PALETTES];
  bool in_hblank; //Used for HDMA
  bool wy_eq_ly;
  bool last_frame_ppu_disabled;
} sb_lcd_ppu_t;
typedef struct{
  bool in_hblank; 
  bool active;
  int bytes_transferred;

  bool oam_dma_active;
  int oam_bytes_transferred; 
} sb_dma_t;

typedef struct{
  int clocks_till_div_inc;
  int clocks_till_tima_inc;
} sb_timer_t;

typedef struct{
  uint16_t data[SB_AUDIO_RING_BUFFER_SIZE];
  uint32_t read_ptr;
  uint32_t write_ptr;
}sb_ring_buffer_t;
inline uint32_t sb_ring_buffer_size(sb_ring_buffer_t* buff){
  uint32_t v = (buff->write_ptr-buff->read_ptr);
  v= v%SB_AUDIO_RING_BUFFER_SIZE;
  return v;
}
typedef struct{
  float channel_output[4];
  float mix_l_volume, mix_r_volume;
  float master_volume;
  sb_ring_buffer_t ring_buff;
}sb_audio_t;
typedef struct {
  sb_gb_cartridge_t cart;
  sb_gb_cpu_t cpu;
  sb_gb_joy_t joy; 
  sb_gb_mem_t mem;
  sb_lcd_ppu_t lcd;
  sb_timer_t timers;
  sb_dma_t dma; 
  sb_audio_t audio;
  int model; 
} sb_gb_t;  

typedef void (*sb_opcode_impl_t)(sb_gb_t*,int op1,int op2, int op1_enum, int op2_enum, const uint8_t * flag_mask);
#endif
