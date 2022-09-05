

#define SB_IO_JOYPAD      0xff00
#define SB_IO_SERIAL_BYTE 0xff01
#define SB_IO_SERIAL_CTRL 0xff02
#define SB_IO_DIV         0xff04
#define SB_IO_TIMA        0xff05
#define SB_IO_TMA         0xff06
#define SB_IO_TAC         0xff07

#define SB_IO_AUD1_TONE_SWEEP   0xff10
#define SB_IO_AUD1_LENGTH_DUTY  0xff11
#define SB_IO_AUD1_VOL_ENV      0xff12
#define SB_IO_AUD1_FREQ         0xff13
#define SB_IO_AUD1_FREQ_HI      0xff14

#define SB_IO_AUD2_LENGTH_DUTY  0xff16
#define SB_IO_AUD2_VOL_ENV      0xff17
#define SB_IO_AUD2_FREQ         0xff18
#define SB_IO_AUD2_FREQ_HI      0xff19

#define SB_IO_AUD3_POWER        0xff1A
#define SB_IO_AUD3_LENGTH       0xff1B
#define SB_IO_AUD3_VOL          0xff1C
#define SB_IO_AUD3_FREQ         0xff1D
#define SB_IO_AUD3_FREQ_HI      0xff1E
#define SB_IO_AUD3_WAVE_BASE    0xff30

#define SB_IO_AUD4_LENGTH       0xff20
#define SB_IO_AUD4_VOL_ENV      0xff21
#define SB_IO_AUD4_POLY         0xff22
#define SB_IO_AUD4_COUNTER      0xff23
#define SB_IO_MASTER_VOLUME     0xff24
#define SB_IO_SOUND_OUTPUT_SEL  0xff25

#define SB_IO_SOUND_ON_OFF      0xff26
#define SB_IO_INTER_F     0xff0f
#define SB_IO_LCD_CTRL    0xff40
#define SB_IO_LCD_STAT    0xff41
#define SB_IO_LCD_SY      0xff42
#define SB_IO_LCD_SX      0xff43
#define SB_IO_LCD_LY      0xff44
#define SB_IO_LCD_LYC     0xff45

#define SB_IO_OAM_DMA     0xff46

#define SB_IO_PPU_BGP     0xff47
#define SB_IO_PPU_OBP0    0xff48
#define SB_IO_PPU_OBP1    0xff49

#define SB_IO_LCD_WY      0xff4A
#define SB_IO_LCD_WX      0xff4B
#define SB_IO_GBC_KEY0    0xFF4C

#define SB_IO_GBC_SPEED_SWITCH 0xff4d
#define SB_IO_GBC_VBK     0xff4f

#define SB_IO_BIOS_BANK   0xff50
#define SB_IO_DMA_SRC_HI  0xff51
#define SB_IO_DMA_SRC_LO  0xff52
#define SB_IO_DMA_DST_HI  0xff53
#define SB_IO_DMA_DST_LO  0xff54
#define SB_IO_DMA_MODE_LEN 0xff55

#define SB_IO_GBC_BCPS    0xff68
#define SB_IO_GBC_BCPD    0xff69

#define SB_IO_GBC_OCPS    0xff6A
#define SB_IO_GBC_OCPD    0xff6B

#define SB_IO_GBC_SVBK    0xff70

#define SB_IO_INTER_EN    0xffff

#define SB_MBC_NO_MBC 0
#define SB_MBC_MBC1 1
#define SB_MBC_MBC2 2
#define SB_MBC_MBC3 3
#define SB_MBC_MBC5 5
#define SB_MBC_MBC6 6
#define SB_MBC_MBC7 7

mmio_reg_t gb_io_reg_desc[]={
  { SB_IO_JOYPAD, "JOYPAD", { 
    { 5, 1, "Select Action buttons    (0=Select)"},
    { 4, 1, "Select Direction buttons (0=Select)"},
    { 3, 1, "Input: Down  or Start    (0=Pressed) (Read Only)"},
    { 2, 1, "Input: Up    or Select   (0=Pressed) (Read Only)"},
    { 1, 1, "Input: Left  or B        (0=Pressed) (Read Only)"},
    { 0, 1, "Input: Right or A        (0=Pressed) (Read Only)"},
  }},       
  { SB_IO_SERIAL_CTRL, "SERIAL_CTRL", { 
    { 7, 1, "Transfer Start Flag (0=No transfer is in progress or requested, 1=Transfer in progress, or requested)"},
    { 1, 1, "Clock Speed (0=Normal, 1=Fast) ** CGB Mode Only **"},
    { 0, 1, "Shift Clock (0=External Clock, 1=Internal Clock)"},
  }},  
  { SB_IO_DIV, "DIV", { 
    { 0 ,8, "Div Value"},
  }},          
  { SB_IO_TIMA, "TIMA", { 
    { 0 ,8, "Timer Value"},
  }},         
  { SB_IO_TMA, "TMA", { 
    { 0 ,8, "Timer Modulo"},
  }},          
  { SB_IO_TAC, "TAC", { 
    { 2 ,1, "Timer Enable"},
    { 0, 2, "Clock Divider (0: Clk/1024 1: Clk/16 2: Clk/64 3: Clk/256)"}
  }},          
  { SB_IO_AUD1_TONE_SWEEP, "AUD1_TONE_SWEEP", { 
    { 4,3, "Sweep Time"},
    { 3,1, "Sweep Increase(0)/Decrease(1)"},
    { 0,3, "Number of sweep shift (n: 0-7)"},
  }},    
  { SB_IO_AUD1_LENGTH_DUTY, "AUD1_LENGTH_DUTY", {
    { 6, 2, "Wave Pattern Duty (Read/Write)"},
    { 0, 6, "Sound length data (Write Only) (t1: 0-63)"},
  }},   
  { SB_IO_AUD1_VOL_ENV, "AUD1_VOL_ENV", { 
    { 4, 4, "Initial Volume of envelope (0-0Fh) (0=No Sound)" },
    { 3, 1, "Envelope Direction (0=Decrease, 1=Increase)" },
    { 0, 3, "Number of envelope sweep (n: 0-7)" },
  }},       
  { SB_IO_AUD1_FREQ, "AUD1_FREQ", { 0 }},          
  { SB_IO_AUD1_FREQ_HI, "AUD1_FREQ_HI", { 
    { 7,1, "Initial (1=Restart Sound)     (Write Only)"},
    { 6,1, "(1=Stop output when length in NR11 expires)"},
    { 0,3, "Frequency's higher 3 bits (x) (Write Only)"},
  }},       
  { SB_IO_AUD2_LENGTH_DUTY, "AUD2_LENGTH_DUTY", { 
    { 6, 2, "Wave Pattern Duty (Read/Write)"},
    { 0, 6, "Sound length data (Write Only) (t1: 0-63)"},
  }},   
  { SB_IO_AUD2_VOL_ENV, "AUD2_VOL_ENV", { 
    { 4, 4, "Initial Volume of envelope (0-0Fh) (0=No Sound)" },
    { 3, 1, "Envelope Direction (0=Decrease, 1=Increase)" },
    { 0, 3, "Number of envelope sweep (n: 0-7)" },
  }},       
  { SB_IO_AUD2_FREQ, "AUD2_FREQ", { 0 }},          
  { SB_IO_AUD2_FREQ_HI, "AUD2_FREQ_HI", { 
    { 7,1, "Initial (1=Restart Sound)     (Write Only)"},
    { 6,1, "(1=Stop output when length in NR11 expires)"},
    { 0,3, "Frequency's higher 3 bits (x) (Write Only)"},
  }},       
  { SB_IO_AUD3_POWER, "AUD3_POWER", { 
    {7,1,"Sound Channel 3 Enable"}
  }},         
  { SB_IO_AUD3_LENGTH, "AUD3_LENGTH", { 0 }},        
  { SB_IO_AUD3_VOL, "AUD3_VOL", { 
    {5,2, "Volume (0: Mute 1: 100% 2: 50% 3: 25%)"}
  }},           
  { SB_IO_AUD3_FREQ, "AUD3_FREQ", { 0 }},          
  { SB_IO_AUD3_FREQ_HI, "AUD3_FREQ_HI", { 
    { 7,1, "Initial (1=Restart Sound)     (Write Only)"},
    { 6,1, "(1=Stop output when length in NR11 expires)"},
    { 0,3, "Frequency's higher 3 bits (x) (Write Only)"},
  }},       
  { SB_IO_AUD4_LENGTH, "AUD4_LENGTH", { 0 }},        
  { SB_IO_AUD4_VOL_ENV, "AUD4_VOL_ENV", { 
    { 4, 4, "Initial Volume of envelope (0-0Fh) (0=No Sound)" },
    { 3, 1, "Envelope Direction (0=Decrease, 1=Increase)" },
    { 0, 3, "Number of envelope sweep (n: 0-7)" },
  }},       
  { SB_IO_AUD4_POLY, "AUD4_POLY", { 
    { 4,4, "Shift Clock Frequency (s)" },
    { 3,1, "Counter Step/Width (0=15 bits, 1=7 bits)" },
    { 0,3, "Dividing Ratio of Frequencies (r)" },
  }},          
  { SB_IO_AUD4_COUNTER, "AUD4_COUNTER", { 
    {7,1, "Initial (1=Restart Sound)     (Write Only)"},
    {6,1, "Counter/consecutive selection (Read/Write)"},
  }},       
  { SB_IO_SOUND_OUTPUT_SEL, "SOUND_OUTPUT_SEL", { 
    { 7,1, "Output sound 4 to SO2 terminal" },
    { 6,1, "Output sound 3 to SO2 terminal" },
    { 5,1, "Output sound 2 to SO2 terminal" },
    { 4,1, "Output sound 1 to SO2 terminal" },
    { 3,1, "Output sound 4 to SO1 terminal" },
    { 2,1, "Output sound 3 to SO1 terminal" },
    { 1,1, "Output sound 2 to SO1 terminal" },
    { 0,1, "Output sound 1 to SO1 terminal" },
  }},   
  { SB_IO_SOUND_ON_OFF, "SOUND_ON_OFF", { 
    { 7,1, "All sound on/off (Read/Write)"},
    { 3,1, "Sound 4 ON flag (Read Only)"},
    { 2,1, "Sound 3 ON flag (Read Only)"},
    { 1,1, "Sound 2 ON flag (Read Only)"},
    { 0,1, "Sound 1 ON flag (Read Only)"},
  }},       
  { SB_IO_INTER_F, "INTER_F", { 
    { 0, 1, "VBlank   Interrupt" },
    { 1, 1, "LCD STAT Interrupt" },
    { 2, 1, "Timer    Interrupt" },
    { 3, 1, "Serial   Interrupt" },
    { 4, 1, "Joypad   Interrupt" },
  }},      
  { SB_IO_LCD_CTRL, "LCD_CTRL", { 
    { 7, 1, "LCD and PPU enable  0=Off, 1=On"},
    { 6, 1, "Window tile map area  0=9800-9BFF, 1=9C00-9FFF"},
    { 5, 1, "Window enable 0=Off, 1=On"},
    { 4, 1, "BG and Window tile data area  0=8800-97FF, 1=8000-8FFF"},
    { 3, 1, "BG tile map area  0=9800-9BFF, 1=9C00-9FFF"},
    { 2, 1, "OBJ size  0=8x8, 1=8x16"},
    { 1, 1, "OBJ enable  0=Off, 1=On"},
    { 0, 1, "BG and Window enable/priority 0=Off, 1=On"},
  }},     
  { SB_IO_LCD_STAT, "LCD_STAT", { 
    { 6,1, "LYC=LY STAT Interrupt source" },
    { 5,1, "Mode 2 OAM STAT Interrupt source" },
    { 4,1, "Mode 1 VBlank STAT Interrupt source" },
    { 3,1, "Mode 0 HBlank STAT Interrupt source" },
    { 2,1, "LYC=LY Flag" },
    { 0,2, "Mode Flag (0:Hblank 1:Vblank 2:OAM 3:Transfer)" },
  }},     
  { SB_IO_LCD_SY, "LCD_SY", { 0 }},       
  { SB_IO_LCD_SX, "LCD_SX", { 0 }},       
  { SB_IO_LCD_LY, "LCD_LY", { 0 }},       
  { SB_IO_LCD_LYC, "LCD_LYC", { 0 }},      
  { SB_IO_OAM_DMA, "OAM_DMA", { 0 }},      
  { SB_IO_PPU_BGP, "PPU_BGP", {  
    { 6,2, "Color for index 3" },
    { 4,2, "Color for index 2" },
    { 2,2, "Color for index 1" },
    { 0,2, "Color for index 0" },
  }},      
  { SB_IO_PPU_OBP0, "PPU_OBP0", { 
    { 6,2, "Color for index 3" },
    { 4,2, "Color for index 2" },
    { 2,2, "Color for index 1" },
    { 0,2, "Color for index 0" },
  }},     
  { SB_IO_PPU_OBP1, "PPU_OBP1", { 
    { 6,2, "Color for index 3" },
    { 4,2, "Color for index 2" },
    { 2,2, "Color for index 1" },
    { 0,2, "Color for index 0" },
  }},     
  { SB_IO_LCD_WY, "LCD_WY", { 0 }},       
  { SB_IO_LCD_WX, "LCD_WX", { 0 }},    
  { SB_IO_GBC_KEY0, "GBC KEY0", {
    {0, 1, "DMG Mode (0=Normal, 1=DMG Compatible)"}
  }},   
  { SB_IO_GBC_SPEED_SWITCH, "GBC_SPEED_SWITCH", { 
    { 7,1, "Current Speed     (0=Normal, 1=Double) (Read Only)"},
    { 0,1, "Prepare Speed Switch (0=No, 1=Prepare) (Read/Write)"},
  }},  
  { SB_IO_GBC_VBK, "GBC_VBK", { 
    {0,1, "VRAM Bank Sel"}
  }},      
  { SB_IO_BIOS_BANK, "BIOS_BANK", { 
    {0,8, "BANK VALUE"}
  }}, 
  { SB_IO_DMA_SRC_HI, "DMA_SRC_HI", { 0 }},   
  { SB_IO_DMA_SRC_LO, "DMA_SRC_LO", { 0 }},   
  { SB_IO_DMA_DST_HI, "DMA_DST_HI", { 0 }},   
  { SB_IO_DMA_DST_LO, "DMA_DST_LO", { 0 }},   
  { SB_IO_DMA_MODE_LEN, "DMA_MODE_LEN", { 
    {7, 1, "Mode (0: General 1: HDMA)"},
    {0, 6, "Length*16B"}
  }},  
  { SB_IO_GBC_BCPS, "GBC_BCPS", { 0 }},     
  { SB_IO_GBC_BCPD, "GBC_BCPD", { 0 }},     
  { SB_IO_GBC_OCPS, "GBC_OCPS", { 0 }},     
  { SB_IO_GBC_OCPD, "GBC_OCPD", { 0 }},     
  { SB_IO_GBC_SVBK, "GBC_SVBK", {
    {0,3, "WRAM Bank Sel"}
  }},     
  { SB_IO_INTER_EN, "INTER_EN", { 
    { 0, 1, "VBlank   Interrupt Enable" },
    { 1, 1, "LCD STAT Interrupt Enable" },
    { 2, 1, "Timer    Interrupt Enable" },
    { 3, 1, "Serial   Interrupt Enable" },
    { 4, 1, "Joypad   Interrupt Enable" },
  }},     
};

typedef struct {
  // Registers
  uint16_t af, bc, de, hl, sp, pc;
  bool interrupt_enable;
  bool deferred_interrupt_enable;
  bool wait_for_interrupt; 
  bool prefix_op;
  bool trigger_breakpoint; 
  int last_inter_f; 
  bool branch_taken;
  bool halt_bug; 
} sb_gb_cpu_t;

typedef struct {
  uint8_t data[65536];
  uint8_t wram[SB_WRAM_NUM_BANKS*SB_WRAM_BANK_SIZE];
} sb_gb_mem_t;

typedef struct {
  uint8_t *data;
  uint8_t ram_data[MAX_CARTRIDGE_RAM]; 
  char title[17];
  bool game_boy_color;
  bool ram_write_enable;
  bool ram_is_dirty; 
  uint8_t type;
  uint8_t mbc_type; 
  uint8_t mapped_ram_bank;
  unsigned mapped_rom_bank;
  int rom_size;
  int ram_size;
  bool rumble;
  bool has_rumble; 
  bool bank_mode; //MBC1
} sb_gb_cartridge_t;

typedef struct{
  unsigned int scanline_cycles;
  unsigned int curr_scanline;
  unsigned int curr_window_scanline;
  uint8_t *framebuffer;
  uint8_t vram[SB_VRAM_BANK_SIZE*SB_VRAM_NUM_BANKS];
  uint8_t color_palettes[SB_PPU_BG_COLOR_PALETTES+SB_PPU_SPRITE_COLOR_PALETTES];
  bool in_hblank; //Used for HDMA
  bool wy_eq_ly;
  bool last_frame_ppu_disabled;
  bool last_stat_interrupt;
} sb_lcd_ppu_t;
typedef struct{
  bool in_hblank; 
  bool active;
  int bytes_transferred;
  bool oam_dma_active;
  int oam_bytes_transferred; 
  bool hdma; 
} sb_dma_t;

typedef struct{
  uint32_t total_clock_ticks; 
  bool tima_written;
  bool last_tick_tima;
  bool last_tick_seq;
} sb_timer_t;
typedef struct{
  uint32_t step_counter;
  int32_t length[4];
  uint32_t volume[4];
  uint32_t frequency[4];
  int32_t  env_direction[4]; //1: increase 0: nochange -1: decrease
  uint32_t env_period[4];
  uint32_t env_period_timer[4];
  bool env_overflow[4]; 
  //Only channel 1
  uint32_t sweep_period;
  uint32_t sweep_timer;
  int32_t  sweep_direction; 
  uint32_t sweep_shift;
  bool     sweep_enable;
  bool     sweep_subtracted;
  bool use_length[4];
  bool active[4];
  bool powered[4];
  float chan_t[4];
  uint16_t lfsr4;
}sb_frame_sequencer_t;
typedef struct{
  double current_sim_time;
  double current_sample_generated_time;
  float capacitor_r;
  float capacitor_l;
  bool regs_written; 
  uint8_t curr_wave_data;
  sb_frame_sequencer_t sequencer;
}sb_audio_t;
typedef struct{
  uint32_t ticks_to_complete; 
  bool last_active;
}sb_serial_t;
typedef struct{
  uint32_t bess_version; 
  uint16_t af, bc, de, hl, sp, pc;
  uint16_t interrupt_enable;
  uint16_t cart_bank_mode; 
  uint32_t data_seg; 
  uint32_t wram_seg;
  uint32_t vram_seg;
  uint32_t palette_seg; 
  uint32_t mapped_rom_bank;
  uint32_t mapped_ram_bank;
}sb_gb_bess_info_t;

typedef struct {
  sb_gb_cartridge_t cart;
  sb_gb_cpu_t cpu;
  sb_gb_mem_t mem;
  sb_lcd_ppu_t lcd;
  sb_timer_t timers;
  sb_dma_t dma; 
  sb_audio_t audio;
  sb_serial_t serial;
  sb_gb_bess_info_t bess;
  int model; 
  uint8_t dmg_palette[4*3];
  uint8_t* bios; 
} sb_gb_t;  

typedef struct{
  uint8_t framebuffer[SB_LCD_H*SB_LCD_W*4];
  uint8_t bios[2304];
 } gb_scratch_t; 

// Return offset to bess structure
static uint32_t sb_save_best_effort_state(sb_gb_t* gb){
  sb_gb_bess_info_t bess;
  gb->bess.bess_version = 1; 
  gb->bess.af = gb->cpu.af;
  gb->bess.bc = gb->cpu.bc;
  gb->bess.de = gb->cpu.de;
  gb->bess.hl = gb->cpu.hl;
  gb->bess.sp = gb->cpu.sp;
  gb->bess.pc = gb->cpu.pc;
  gb->bess.interrupt_enable = gb->cpu.interrupt_enable;

  gb->bess.data_seg = ((uint8_t*)gb->mem.data)-(uint8_t*)gb;
  gb->bess.wram_seg = ((uint8_t*)gb->mem.wram)-(uint8_t*)gb;
  gb->bess.vram_seg = ((uint8_t*)gb->lcd.vram)-(uint8_t*)gb;
  gb->bess.palette_seg = ((uint8_t*)gb->lcd.color_palettes)-(uint8_t*)gb;
  gb->bess.mapped_ram_bank = gb->cart.mapped_ram_bank;
  gb->bess.mapped_rom_bank = gb->cart.mapped_rom_bank;
  gb->bess.cart_bank_mode = gb->cart.bank_mode;

  return ((uint8_t*)&gb->bess)-(uint8_t*)gb; 
}
static bool sb_load_best_effort_state(sb_gb_t* gb, uint8_t *save_state_data, uint32_t size, uint32_t bess_offset){
  if(bess_offset+sizeof(sb_gb_bess_info_t)>size)return false;
  sb_gb_bess_info_t * bess = (sb_gb_bess_info_t*)(save_state_data+bess_offset);

  if(bess->bess_version!=1)return false; 
  if(bess->data_seg+sizeof(gb->mem.data) > size) return false;  
  if(bess->wram_seg+sizeof(gb->mem.wram) > size) return false;  
  if(bess->vram_seg+sizeof(gb->lcd.vram) > size) return false;  
  if(bess->palette_seg+sizeof(gb->lcd.color_palettes) > size) return false;  

  gb->cpu.af = bess->af;  
  gb->cpu.bc = bess->bc;  
  gb->cpu.de = bess->de;  
  gb->cpu.hl = bess->hl;  
  gb->cpu.sp = bess->sp;  
  gb->cpu.pc = bess->pc;  
  gb->cpu.interrupt_enable = bess->interrupt_enable;

  memcpy(gb->mem.data,save_state_data+bess->data_seg,sizeof(gb->mem.data));
  memcpy(gb->mem.wram,save_state_data+bess->wram_seg,sizeof(gb->mem.wram));
  memcpy(gb->lcd.vram,save_state_data+bess->vram_seg,sizeof(gb->lcd.vram));
  memcpy(gb->lcd.color_palettes,save_state_data+bess->palette_seg,sizeof(gb->lcd.color_palettes));

  gb->cart.mapped_ram_bank = bess->mapped_ram_bank;
  gb->cart.mapped_rom_bank = bess->mapped_rom_bank;
  gb->cart.bank_mode = bess->cart_bank_mode;

  return true; 
}

typedef void (*sb_opcode_impl_t)(sb_gb_t*,int op1,int op2, int op1_enum, int op2_enum, const uint8_t * flag_mask);

//Include down here because of dependence on sb_gb_t /*TODO: refactor this*/
#include "sb_instr_tables.h"

uint32_t sb_lookup_tile(sb_gb_t* gb, int px, int py, int tile_base, int data_mode);
void sb_lookup_palette_color(sb_gb_t*gb,int color_id, int*r, int *g, int *b);
static FORCE_INLINE void sb_process_audio(sb_gb_t *gb, sb_emu_state_t*emu, double delta_time);
static void sb_tick_frame_seq(sb_frame_sequencer_t* seq);
static void sb_process_audio_writes(sb_gb_t* gb); 

static FORCE_INLINE uint8_t sb_read8_direct(sb_gb_t *gb, int addr) {
  if(addr>=0x0000&&addr<=0x3fff){
    if(addr<256||(addr>=512&&addr<2304)){
      if(!sb_read8_direct(gb,SB_IO_BIOS_BANK))return gb->bios[addr]; 
    }
    int cart_addr = SB_BFE(addr,0,14);
    if(gb->cart.bank_mode&&gb->cart.mbc_type==SB_MBC_MBC1){
      cart_addr|=SB_BFE(gb->cart.mapped_ram_bank,0,2)<<19;
    }
    cart_addr%= (gb->cart.rom_size);
    return gb->cart.data[cart_addr];
  }else if(addr>=0x4000&&addr<=0x7fff){
    int cart_addr = SB_BFE(addr,0,14);
    cart_addr|=(gb->cart.mapped_rom_bank)<<14;
    if(gb->cart.mbc_type==SB_MBC_MBC1){
      cart_addr|=SB_BFE(gb->cart.mapped_ram_bank,0,2)<<19;
    }
    cart_addr%= (gb->cart.rom_size);
    return gb->cart.data[cart_addr];
  }else if(addr>=0x8000&&addr<=0x9fff){
    uint8_t vbank =sb_read8_direct(gb,SB_IO_GBC_VBK)%SB_VRAM_NUM_BANKS;
    uint8_t data =gb->lcd.vram[vbank*SB_VRAM_BANK_SIZE+addr-0x8000];
    return data;
  } else if(addr>=0xA000&&addr<=0xBfff){
    if(!gb->cart.ram_write_enable||gb->cart.ram_size==0)return 0xff;
    int ram_addr_off = 0x2000*gb->cart.mapped_ram_bank+(addr-0xA000);
    if(gb->cart.mbc_type==SB_MBC_MBC1){
      ram_addr_off = SB_BFE(addr,0,13);
      if(gb->cart.bank_mode)ram_addr_off|= SB_BFE(gb->cart.mapped_ram_bank,0,2)<<13;
    }
    ram_addr_off%=gb->cart.ram_size;
    return gb->cart.ram_data[ram_addr_off];
  }else if(addr>=0xD000&&addr<=0xDfff){
    int bank =gb->mem.data[SB_IO_GBC_SVBK]%SB_WRAM_NUM_BANKS;
    if(bank==0)bank = 1;
    int ram_addr_off = 0x1000*bank+(addr-0xd000);
    return gb->mem.wram[ram_addr_off];
  }else if(addr>=0xe000 && addr<=0xfdff){
    //Echo Ram
    addr =addr - 0xe000 + 0xc000;
  }
  return gb->mem.data[addr];
}
bool sb_gbc_enable(sb_gb_t*gb){
  return (sb_read8_direct(gb,SB_IO_GBC_KEY0)!=0x4||!sb_read8_direct(gb,SB_IO_BIOS_BANK))&&gb->model==SB_GBC;
}
uint8_t sb_io_or_mask(sb_gb_t* gb, int addr){
  bool gbc_en = sb_gbc_enable(gb);
  if(addr>=SB_IO_AUD1_TONE_SWEEP&&addr<SB_IO_AUD3_WAVE_BASE+16){
    uint8_t audio_reg_mask_table[]={
      0x80,0x3F,0x00,0xFF,0xBF, // NR10-NR15
      0xFF,0x3F,0x00,0xFF,0xBF, // NR20-NR25
      0x7F,0xFF,0x9F,0xFF,0xBF, // NR30-NR35
      0xFF,0xFF,0x00,0x00,0xBF, // NR40-NR45
      0x00,0x00,0x70,           // NR50-NR52
      0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,// Wave RAM
      0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    return audio_reg_mask_table[addr-SB_IO_AUD1_TONE_SWEEP];
  }else if(addr==SB_IO_INTER_F)return 0xE0;
  else if (addr==SB_IO_LCD_STAT)return 0x80;
  else if (addr==SB_IO_TAC)return 0xf8;
  else if (addr==SB_IO_SERIAL_CTRL)return 0x7e;
  else if (addr==SB_IO_JOYPAD)return 0xc0;
  else if(addr==0xFF03||addr==0xFF08||addr==0xFF09||addr==0xFF0A||
          addr==0xFF0B||addr==0xFF0C||addr==0xFF0D||addr==0xFF0E||
          addr==0xFF15||addr==0xFF1F||addr==0xFF27||addr==0xFF28||
          addr==0xFF29||
          (addr>=0xff4c&&addr<=0xff7f&&!gbc_en)||
          (addr>=0xff71&&addr<=0xff7f&&gbc_en)){
    return 0xff;
  }
  return 0; 
}
uint8_t sb_read8(sb_gb_t *gb, int addr) {
  //if(addr == 0xff44)return 0x90;
  //if(addr == 0xff80)gb->cpu.trigger_breakpoint=true;
  if(addr >=0xff00){
    if(addr == SB_IO_GBC_BCPD){
      uint8_t bcps = sb_read8_direct(gb, SB_IO_GBC_BCPS);
      uint8_t index = SB_BFE(bcps,0,6);
      return gb->lcd.color_palettes[index];
    }else if(addr == SB_IO_GBC_OCPD){
      uint8_t ocps = sb_read8_direct(gb, SB_IO_GBC_OCPS);
      uint8_t index = SB_BFE(ocps,0,6);
      return gb->lcd.color_palettes[index+SB_PPU_BG_COLOR_PALETTES];
    }else if (addr == SB_IO_GBC_VBK){
      uint8_t d= sb_read8_direct(gb,addr);
      return d|0xfe|sb_io_or_mask(gb,addr);
    }else if(addr>=SB_IO_AUD3_WAVE_BASE&&addr<SB_IO_AUD3_WAVE_BASE+16){
      bool wave_active = SB_BFE(sb_read8_direct(gb,SB_IO_SOUND_ON_OFF),2,1);
      if(wave_active){
        return gb->audio.curr_wave_data;
      }
    }
    return sb_read8_direct(gb,addr)|sb_io_or_mask(gb,addr);
  }
  return sb_read8_direct(gb,addr);
}
void sb_unmap_ram(sb_gb_t*gb){
  int old_bank_off = 0x2000*gb->cart.mapped_ram_bank;
  if(gb->cart.ram_is_dirty){
    for(int i= 0; i<0x2000;++i){
      gb->cart.ram_data[old_bank_off+i]=gb->mem.data[0xA000+i];
    }
  }
}
static FORCE_INLINE void sb_store8_direct(sb_gb_t *gb, int addr, int value) {
  if(addr>=0x8000&&addr<=0x9fff){
    uint8_t vbank =sb_read8_direct(gb, SB_IO_GBC_VBK)%SB_VRAM_NUM_BANKS;;
    gb->lcd.vram[vbank*SB_VRAM_BANK_SIZE+addr-0x8000]=value;
    return;
  }else if(addr>=0xA000&&addr<=0xBfff){
    if(gb->cart.ram_write_enable&&gb->cart.ram_size){
      int ram_addr_off  = SB_BFE(addr,0,13);
      if(gb->cart.mbc_type==SB_MBC_MBC1){
        if(gb->cart.bank_mode)ram_addr_off|= SB_BFE(gb->cart.mapped_ram_bank,0,2)<<13;
      }else ram_addr_off|= gb->cart.mapped_ram_bank<<13;
      ram_addr_off%=gb->cart.ram_size;
      gb->cart.ram_data[ram_addr_off]=value;
      gb->cart.ram_is_dirty = true;
      //printf("RAM WRITE: MEM[%04x, %04x] = %02x B:%d BM:%d\n",addr,ram_addr_off,value, gb->cart.mapped_ram_bank,gb->cart.bank_mode);
    }
    return;
  }else if(addr>=0xD000&&addr<=0xDfff){
    int bank =gb->mem.data[SB_IO_GBC_SVBK]%SB_WRAM_NUM_BANKS;
    if(bank==0)bank = 1;
    int ram_addr_off = 0x1000*bank+(addr-0xd000);
    gb->mem.wram[ram_addr_off]=value;
    return;
  }else if(addr>=0xe000 && addr<=0xfdff){
    //Echo Ram
    addr =addr - 0xe000 + 0xc000;
  }
  if(addr<=0x7fff){
    //printf("Attempt to write to rom address %x\n",addr);
    //gb->cpu.trigger_breakpoint=true;
    return;
  }
  gb->mem.data[addr]=value;
}
void sb_store8(sb_gb_t *gb, int addr, int value) {
  if(addr>=0xff00){
    if(!sb_gbc_enable(gb) &&addr>=0xff4C&&addr<=0xff7f&&addr!=SB_IO_BIOS_BANK)return;
    if(addr == SB_IO_DMA_SRC_LO ||addr == SB_IO_DMA_DST_LO){
      value&=~0xf;
    } else if(addr == SB_IO_DMA_MODE_LEN){
      if(gb->dma.active){
        // Writing bit 7 to 0 for a running transfer halts HDMA
        if(!(value&0x80)){
          gb->dma.active = false;
          value|=0x80;
        }
      }else{
        gb->dma.active =true;
        gb->dma.bytes_transferred=0;
        gb->dma.hdma = (value&0x80)!=0;
        gb->dma.in_hblank = false;
        value&=0x7f;
        uint16_t dma_src = sb_read8_direct(gb,SB_IO_DMA_SRC_LO)|
                    ((int)sb_read8_direct(gb,SB_IO_DMA_SRC_HI)<<8u);
        uint16_t dma_dst = sb_read8_direct(gb,SB_IO_DMA_DST_LO)|
                    ((int)sb_read8_direct(gb,SB_IO_DMA_DST_HI)<<8u);
      }
    }
    if(addr == SB_IO_OAM_DMA){
      gb->dma.oam_dma_active=true;
      gb->dma.oam_bytes_transferred=0;
    }else if(addr == SB_IO_GBC_BCPD){
      uint8_t bcps = sb_read8_direct(gb, SB_IO_GBC_BCPS);
      uint8_t index = SB_BFE(bcps,0,6);
      bool autoindex = SB_BFE(bcps,7,1);
      gb->lcd.color_palettes[index] = value;
      if(autoindex){
        index++;
        sb_store8_direct(gb,SB_IO_GBC_BCPS,(index&0x3f)|0x80);
      }
    }else if(addr == SB_IO_GBC_OCPD){
      uint8_t ocps = sb_read8_direct(gb, SB_IO_GBC_OCPS);
      uint8_t index = SB_BFE(ocps,0,6);
      bool autoindex = SB_BFE(ocps,7,1);
      gb->lcd.color_palettes[index+SB_PPU_BG_COLOR_PALETTES] = value;
      if(autoindex){
        index++;
        sb_store8_direct(gb,SB_IO_GBC_OCPS,(index&0x3f)|0x80);
      }
    }else if(addr == SB_IO_DIV){
      gb->timers.total_clock_ticks = 0;
    }else if(addr == SB_IO_SERIAL_BYTE){
      printf("%c",(char)value);
    }else if(addr>=SB_IO_AUD1_TONE_SWEEP&&addr<SB_IO_AUD3_WAVE_BASE+16){
      sb_frame_sequencer_t *seq = &gb->audio.sequencer;
      int i = (addr-SB_IO_AUD1_LENGTH_DUTY)/5;
      gb->audio.regs_written = true;
      if(addr==SB_IO_SOUND_ON_OFF){
        value&=0xf0;
        value|=sb_read8_direct(gb,SB_IO_SOUND_ON_OFF)&0xf;
      }
      if(addr>=SB_IO_AUD3_WAVE_BASE&&addr<SB_IO_AUD3_WAVE_BASE+16){
        bool wave_active = SB_BFE(sb_read8_direct(gb,SB_IO_SOUND_ON_OFF),2,1);
        if(wave_active)return;
      }
      if(addr==SB_IO_AUD1_LENGTH_DUTY||addr==SB_IO_AUD2_LENGTH_DUTY||addr==SB_IO_AUD3_LENGTH||addr==SB_IO_AUD4_LENGTH){
        uint8_t length_duty = value;
        if(i==2) gb->audio.sequencer.length[i] = 256-SB_BFE(length_duty,0,8);
        else gb->audio.sequencer.length[i] = 64-SB_BFE(length_duty,0,6);
      }else if(addr==SB_IO_AUD1_VOL_ENV||addr==SB_IO_AUD2_VOL_ENV||addr==SB_IO_AUD4_VOL_ENV){
        bool power = SB_BFE(value,3,5)!=0;
        gb->audio.sequencer.powered[i]= power;
        gb->audio.sequencer.active[i]&=power;
        gb->audio.sequencer.env_direction[i] = (SB_BFE(value,3,1)?1:-1);
        gb->audio.sequencer.env_period[i] = SB_BFE(value,0,3);
        if (gb->audio.sequencer.env_period[i]== 0 &&!gb->audio.sequencer.env_overflow[i]) {
          gb->audio.sequencer.volume[i] = (gb->audio.sequencer.volume[i] + 1) & 0xf;
        }
      }else if( addr==SB_IO_AUD1_FREQ||addr==SB_IO_AUD1_FREQ_HI||
                addr==SB_IO_AUD2_FREQ||addr==SB_IO_AUD2_FREQ_HI||
                addr==SB_IO_AUD3_FREQ||addr==SB_IO_AUD3_FREQ_HI
              ){
        uint8_t freq_lo = sb_read8_direct(gb,SB_IO_AUD1_FREQ+i*5);
        uint8_t freq_hi = sb_read8_direct(gb,SB_IO_AUD1_FREQ_HI+i*5);
        seq->frequency[i] = freq_lo | ((int)(SB_BFE(freq_hi,0,3))<<8u);
      }
      int ch = (addr-SB_IO_AUD1_TONE_SWEEP)/5;
      int reg = (addr-SB_IO_AUD1_TONE_SWEEP)%5;
    }else if(addr==SB_IO_BIOS_BANK){value|= sb_read8_direct(gb,SB_IO_BIOS_BANK);
    }else if(addr==SB_IO_GBC_KEY0){if(sb_read8_direct(gb,SB_IO_BIOS_BANK))return;}
  }else if(addr >= 0x0000 && addr <=0x1fff){
    gb->cart.ram_write_enable = (value&0xf)==0xA;
    return;
  }else if(addr >= 0x2000 && addr <=0x3fff){
    //MBC3 rombank select
    switch(gb->cart.mbc_type){
      case SB_MBC_MBC1: gb->cart.mapped_rom_bank=value%32; if(!gb->cart.mapped_rom_bank)gb->cart.mapped_rom_bank=1;break;
      case SB_MBC_MBC2: gb->cart.mapped_rom_bank=value%16; if(!gb->cart.mapped_rom_bank)gb->cart.mapped_rom_bank=1;break;
      case SB_MBC_MBC3: gb->cart.mapped_rom_bank=value%256;if(!gb->cart.mapped_rom_bank)gb->cart.mapped_rom_bank=1;break;
      case SB_MBC_MBC5: 
      case SB_MBC_MBC7: 
        if(addr>=0x3000){
          gb->cart.mapped_rom_bank&=0xff;
          gb->cart.mapped_rom_bank|= (int)(value&1)<<8;
        }else gb->cart.mapped_rom_bank=(gb->cart.mapped_rom_bank&0x100)|value;
      break;
    }    
    return;
  }else if(addr >= 0x4000 && addr <=0x5fff){
    gb->cart.rumble = false;
    if((value&(1<<3))&&gb->cart.has_rumble)gb->cart.rumble=true;
    //MBC3 rombank select
    //TODO implement other mappers
    if(gb->cart.mbc_type!=SB_MBC_MBC1&&gb->cart.ram_size)value %= (gb->cart.ram_size/0x2000);
    else value%=4;
    gb->cart.mapped_ram_bank = value;
    return;
  }else if (addr>=0xfe00 && addr<=0xfe9f ){
    //OAM cannot be written to in mode 2 and 3
    int stat = sb_read8_direct(gb, SB_IO_LCD_STAT)&0x3;
    if(stat>=2) return;            
  } else if(addr>=0x6000&&addr<=0x7fff){
    if(gb->cart.mbc_type==SB_MBC_MBC1){
      gb->cart.bank_mode = SB_BFE(value,0,1);
    }
  }else if (addr>=0x8000 && addr <=0x9fff){
    //VRAM cannot be writen to in mode 3
    int stat = sb_read8_direct(gb, SB_IO_LCD_STAT)&0x3;
    if(stat>=3) return;            
  }
  sb_store8_direct(gb,addr,value);
}
void sb_store16(sb_gb_t *gb, int addr, unsigned int value) {
  sb_store8(gb,addr,value&0xff);
  sb_store8(gb,addr+1,((value>>8u)&0xff));
}
uint16_t sb_read16(sb_gb_t *gb, int addr) {
  uint16_t g = sb_read8(gb,addr+1);
  g<<=8;
  g|= sb_read8(gb,addr+0);
  return g;
}

void sb_update_joypad_io_reg(sb_emu_state_t* state, sb_gb_t*gb){
  // FF00 - P1/JOYP - Joypad (R/W)
  //
  // Bit 7 - Not used
  // Bit 6 - Not used
  // Bit 5 - P15 Select Action buttons    (0=Select)
  // Bit 4 - P14 Select Direction buttons (0=Select)
  // Bit 3 - P13 Input: Down  or Start    (0=Pressed) (Read Only)
  // Bit 2 - P12 Input: Up    or Select   (0=Pressed) (Read Only)
  // Bit 1 - P11 Input: Left  or B        (0=Pressed) (Read Only)
  // Bit 0 - P10 Input: Right or A        (0=Pressed) (Read Only)

  uint8_t data_dir =    ((!(state->joy.inputs[SE_KEY_DOWN]>0.3))<<3)|
                        ((!(state->joy.inputs[SE_KEY_UP]>0.3))<<2)  |
                        ((!(state->joy.inputs[SE_KEY_LEFT]>0.3))<<1)|
                        ((!(state->joy.inputs[SE_KEY_RIGHT]>0.3)));
  uint8_t data_action = ((!(state->joy.inputs[SE_KEY_START]>0.3))<<3)|
                        ((!(state->joy.inputs[SE_KEY_SELECT]>0.3))<<2)|
                        ((!(state->joy.inputs[SE_KEY_B]>0.3))<<1)|
                        (!(state->joy.inputs[SE_KEY_A]>0.3));

  uint8_t data = gb->mem.data[SB_IO_JOYPAD];

  data&=0xf0;

  if(0 == (data & (1<<4))) data |= data_dir;
  if(0 == (data & (1<<5))) data |= data_action;

  switch(SB_BFE(data,4,2)){
    case 0: data|=data_dir|data_action; break;
    case 1: data|=data_action; break;
    case 2: data|=data_dir; break;
    case 3: data|=0xf; break;
  }

  gb->mem.data[SB_IO_JOYPAD] = data;

}


static FORCE_INLINE bool sb_update_lcd_status(sb_gb_t* gb, int delta_cycles){
  uint8_t stat = sb_read8_direct(gb, SB_IO_LCD_STAT);
  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  uint8_t ly  = gb->lcd.curr_scanline;
  uint8_t old_ly = ly;
  uint8_t lyc = sb_read8_direct(gb, SB_IO_LCD_LYC);
  bool enable = SB_BFE(ctrl,7,1)==1;
  int mode = 0;
  bool new_scanline = false;
  if(!enable){
    gb->lcd.scanline_cycles = 0;
    gb->lcd.curr_scanline = 0;
    gb->lcd.curr_window_scanline = 0;
    gb->lcd.wy_eq_ly = false;
    gb->lcd.last_frame_ppu_disabled = true;
    gb->lcd.in_hblank=true;
    ly = 0;
  }else{

    const int mode2_clks= 80;
    // TODO: mode 3 is 10 cycles longer for every sprite intersected
    const int mode3_clks = 168;
    const int mode0_clks = 208;
    const int scanline_dots = 456;

    gb->lcd.scanline_cycles +=delta_cycles;
    if(gb->lcd.scanline_cycles>=scanline_dots){
      gb->lcd.scanline_cycles-=scanline_dots;
      ly+=1;
      gb->lcd.curr_scanline += 1;
    }

    if(ly>153){
      ly = 0;
      gb->lcd.curr_scanline=0;
      gb->lcd.curr_window_scanline = 0;
      gb->lcd.wy_eq_ly=false;
      gb->lcd.last_frame_ppu_disabled = false;
    }

    if(gb->lcd.scanline_cycles<=mode2_clks)mode = 2;
    else if(gb->lcd.scanline_cycles<=mode3_clks+mode2_clks) mode =3;
    else mode =0;

    int old_mode = stat&0x7;
    if((old_mode&0x3)!=0&&(mode&0x3)==0)new_scanline=!gb->lcd.last_frame_ppu_disabled;


    if(new_scanline){
      int wy = sb_read8_direct(gb, SB_IO_LCD_WY);
      if(ly==wy)gb->lcd.wy_eq_ly = true;
    }
    bool lyc_eq_ly_interrupt = SB_BFE(stat, 6,1);
    bool oam_interrupt = SB_BFE(stat, 5,1);
    bool vblank_interrupt = SB_BFE(stat, 4,1);
    bool hblank_interrupt = SB_BFE(stat, 3,1);

    bool curr_stat_interrupt = false; 
    if(ly==SB_LCD_H&&old_ly!=SB_LCD_H){
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      //V-BLANK Interrupt
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<0));
    }
    if(vblank_interrupt){
      //vblank-stat Interrupt
      curr_stat_interrupt=true;
    }
    if(ly >= SB_LCD_H) {mode = 1; new_scanline = false;}
    if(ly==153&& gb->lcd.scanline_cycles>=4){ly = 0;}
    if(ly == lyc) mode|=0x4;

    if((mode&0x4)==4 && lyc_eq_ly_interrupt)curr_stat_interrupt=true;
    if(((mode&0x3) == 0x2)&& oam_interrupt){
      //oam-stat Interrupt
      curr_stat_interrupt=true;
    }

    if((mode&0x3) == 0x0 && hblank_interrupt)curr_stat_interrupt=true;
    if(curr_stat_interrupt&&!gb->lcd.last_stat_interrupt){
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }
    gb->lcd.last_stat_interrupt = curr_stat_interrupt;

  }
  gb->lcd.in_hblank = (mode&0x3)==0;
  stat = (stat&0xf8) | mode;
  sb_store8_direct(gb, SB_IO_LCD_STAT, stat);
  sb_store8_direct(gb, SB_IO_LCD_LY, ly);
  return new_scanline;
}
uint8_t sb_read_vram(sb_gb_t*gb, int cpu_address, int bank){
  return gb->lcd.vram[bank*SB_VRAM_BANK_SIZE+cpu_address-0x8000];
}
// Returns info about the pixel in the tile map packed into a 32bit integer
// ret[1:0] = color_id
// ret[7:2] = palette_id
// ret[8]   = backgroud_priority
#define SB_BACKG_PALETTE 0
#define SB_OBJ0_PALETTE 1
#define SB_OBJ1_PALETTE 2
uint32_t sb_lookup_tile(sb_gb_t* gb, int px, int py, int tile_base, int data_mode){
  const int tile_size = 8;
  const int tiles_per_row = 32;
  int tile_offset = (((px&0xff)/tile_size)+((py&0xff)/tile_size)*tiles_per_row)&0x3ff;

  int tile_id = sb_read_vram(gb, tile_base+tile_offset,0);

  int pixel_in_tile_x = 7-(px%8);
  int pixel_in_tile_y = (py%8);

  int byte_tile_data_off = 0;

  int tile_d_vram_bank = 0;
  int tile_bg_palette = 0;

  bool bg_to_oam_priority=false;
  tile_bg_palette = SB_BACKG_PALETTE;
  //Only enable GB functionality if in GBC mode
  if(sb_gbc_enable(gb)){
    uint8_t attr = sb_read_vram(gb, tile_base+tile_offset,1);

    bg_to_oam_priority = SB_BFE(attr,7,1);
    bool v_flip = SB_BFE(attr,6,1);
    bool h_flip = SB_BFE(attr,5,1);
    tile_d_vram_bank = SB_BFE(attr,3,1);
    tile_bg_palette = SB_BFE(attr,0,3);

    if(v_flip)pixel_in_tile_y = 7-pixel_in_tile_y;
    if(h_flip)pixel_in_tile_x = 7-pixel_in_tile_x;
  }

  const int bytes_per_tile = 2*8;
  if(data_mode==0){
    byte_tile_data_off = 0x8000 + 0x1000 + ((int)((int8_t)(tile_id)))*bytes_per_tile;
  }else{
    byte_tile_data_off = 0x8000 + ((int)((uint8_t)(tile_id)))*bytes_per_tile;
  }
  byte_tile_data_off+=pixel_in_tile_y*2;
  uint8_t data1 = sb_read_vram(gb, byte_tile_data_off,tile_d_vram_bank);
  uint8_t data2 = sb_read_vram(gb, byte_tile_data_off+1,tile_d_vram_bank);
  int color_id = (SB_BFE(data1,pixel_in_tile_x,1)+SB_BFE(data2,pixel_in_tile_x,1)*2);
  color_id |= (tile_bg_palette&0x3f)<<2;
  if(bg_to_oam_priority)color_id|= 1<<8;
  return color_id;
}
void sb_lookup_palette_color(sb_gb_t*gb,int color_id, int*r, int *g, int *b){
  uint8_t palette = 0;
  if(gb->model == SB_GB){
    int pal_id = SB_BFE(color_id,2,6);
    if(pal_id==SB_BACKG_PALETTE)palette = sb_read8_direct(gb, SB_IO_PPU_BGP);
    else if(pal_id==SB_OBJ1_PALETTE)palette = sb_read8_direct(gb, SB_IO_PPU_OBP1);
    else palette = color_id ==0 ? 0 : sb_read8_direct(gb, SB_IO_PPU_OBP0);
    color_id = SB_BFE(palette,2*(color_id&0x3),2);

    *r = gb->dmg_palette[color_id*3+0];
    *g = gb->dmg_palette[color_id*3+1];
    *b = gb->dmg_palette[color_id*3+2];
  }else if(gb->model == SB_GBC){

    int palette = SB_BFE(color_id,2,6);
    if(!sb_gbc_enable(gb)){
      uint8_t pal_map= 0; 
      int pal_id = SB_BFE(color_id,2,6);
      if(pal_id==SB_BACKG_PALETTE)pal_map = sb_read8_direct(gb, SB_IO_PPU_BGP);
      else if(pal_id==SB_OBJ1_PALETTE)pal_map = sb_read8_direct(gb, SB_IO_PPU_OBP1);
      else pal_map = color_id ==0 ? 0 : sb_read8_direct(gb, SB_IO_PPU_OBP0);
      color_id = SB_BFE(pal_map,2*(color_id&0x3),2);
      palette=pal_id==SB_BACKG_PALETTE?0:8;
    }

    int entry= palette*8+(color_id&0x3)*2;
    uint16_t color = gb->lcd.color_palettes[entry+0];
    color |= ((int)gb->lcd.color_palettes[entry+1])<<8;

    int tr = SB_BFE(color,0,5);
    int tg = SB_BFE(color,5,5);
    int tb = SB_BFE(color,10,5);

    *r = tr*8;
    *g = tg*8;
    *b = tb*8;
  }
}
void sb_draw_scanline(sb_gb_t*gb,sb_emu_state_t* emu){
  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  bool draw_bg_win     = SB_BFE(ctrl,0,1)==1;
  bool master_priority = true;
  bool gbc_mode = sb_gbc_enable(gb);
  if(gbc_mode){
    // This bit has a different meaning in GBC mode
    master_priority = draw_bg_win;
    draw_bg_win = true;
  }
  bool draw_sprite = SB_BFE(ctrl,1,1)==1;
  bool sprite8x16  = SB_BFE(ctrl,2,1)==1;
  int bg_tile_map_base      = SB_BFE(ctrl,3,1)==1 ? 0x9c00 : 0x9800;
  int bg_win_tile_data_mode = SB_BFE(ctrl,4,1)==1;
  bool window_enable = SB_BFE(ctrl,5,1)==1;
  int win_tile_map_base      = SB_BFE(ctrl,6,1)==1 ? 0x9c00 : 0x9800;

  int oam_table_offset = 0xfe00;
  uint8_t y = sb_read8_direct(gb, SB_IO_LCD_LY);
  int wx = sb_read8_direct(gb, SB_IO_LCD_WX)-7;
  int wy = sb_read8_direct(gb, SB_IO_LCD_WY);
  int sx = sb_read8_direct(gb, SB_IO_LCD_SX);
  int sy = sb_read8_direct(gb, SB_IO_LCD_SY);

  if(!gb->lcd.wy_eq_ly)window_enable = false;
  int sprite_h = sprite8x16 ? 16: 8;
  enum{sprites_per_scanline = 10};
  // HW only draws first 10 sprites that touch a scanline
  int render_sprites[sprites_per_scanline];
  int sprite_index=0;

  for(int i=0;i<sprites_per_scanline;++i)render_sprites[i]=-1;
  const int num_sprites= 40;
  for(int i=0;i<num_sprites;++i){
    int sprite_base = oam_table_offset+i*4;
    int yc = sb_read8_direct(gb, sprite_base+0)-16;
    int xc = sb_read8_direct(gb, sprite_base+1)-16;
    if(yc<=y && yc+sprite_h>y&& sprite_index<sprites_per_scanline){
      render_sprites[sprite_index++]=i;
    }
  }

  bool rendered_part_of_window = false;
  for(int x = 0; x < SB_LCD_W; ++x){

    const int bytes_per_tile = 2*8;
    int r=0,g=0,b=0;
    int color_id=0;

    bool background_priority= false;

    if(draw_bg_win){
      int px = x+ sx;
      int py = y+ sy;
      color_id = sb_lookup_tile(gb,px,py,bg_tile_map_base,bg_win_tile_data_mode);
    }
     if(window_enable && draw_bg_win){
      int px = x-wx;
      if(px>=0){
        int py = gb->lcd.curr_window_scanline;
        rendered_part_of_window = true;
        color_id = sb_lookup_tile(gb,px,py,win_tile_map_base,bg_win_tile_data_mode);
      }
    }
    if(draw_sprite){
      int prior_sprite = 256;
      for(int i=0;i<sprites_per_scanline;++i){
        int sprite = render_sprites[i];
        if(sprite==-1)break;
        int sprite_base = oam_table_offset+sprite*4;
        int xc = sb_read8_direct(gb, sprite_base+1)-8;

        int x_sprite = 7-(x-xc);
        int prior = !sb_gbc_enable(gb)?0 : xc;

        if(prior_sprite<=prior) continue;
        //Check if the sprite is hit
        if(x_sprite>=8 || x_sprite<0) continue;

        int yc = sb_read8_direct(gb, sprite_base+0)-16;
        int y_sprite = y-yc;

        int tile = sb_read8_direct(gb, sprite_base+2);
        int attr = sb_read8_direct(gb, sprite_base+3);
        int tile_d_vram_bank = 0;
        int tile_sprite_palette =0;

        int palette = SB_BFE(attr,4,1)!=0?SB_OBJ1_PALETTE:SB_OBJ0_PALETTE;
        if(gbc_mode){
          tile_d_vram_bank = SB_BFE(attr, 3,1);
          palette = SB_BFE(attr, 0,3)+8;
        }
        if(sprite8x16)tile &=0xfe;

        bool x_flip = SB_BFE(attr,5,1);
        bool y_flip = SB_BFE(attr,6,1);
        bool bg_win_on_top = SB_BFE(attr,7,1);


        if(x_flip)x_sprite = 7-x_sprite;
        if(y_flip)y_sprite = (sprite8x16? 15 : 7)-y_sprite;


        int byte_tile_data_off = 0x8000 + (((uint8_t)(tile))*bytes_per_tile);
        byte_tile_data_off+=y_sprite*2;

        uint8_t data1 = sb_read_vram(gb, byte_tile_data_off,tile_d_vram_bank);
        uint8_t data2 = sb_read_vram(gb, byte_tile_data_off+1,tile_d_vram_bank);

        int cid = (SB_BFE(data1,x_sprite,1)+SB_BFE(data2,x_sprite,1)*2);
        if((bg_win_on_top||(SB_BFE(color_id,8,1)))&&master_priority){
          if((color_id&0x3)==0&&cid!=0){color_id = cid | (palette<<2); prior_sprite =prior;}
        }else if(cid!=0){color_id = cid | (palette<<2); prior_sprite=prior;}

      }
    }
    sb_lookup_palette_color(gb,color_id,&r,&g,&b);

    float ghost_coef = 0.5;
    if(gb->model != SB_GB)ghost_coef= 0.2;
    ghost_coef*=emu->screen_ghosting_strength;
    int p =(x+(y)*SB_LCD_W)*4;
    gb->lcd.framebuffer[p+0] = r*(1.0-ghost_coef)+gb->lcd.framebuffer[p+0]*ghost_coef+0.5;
    gb->lcd.framebuffer[p+1] = g*(1.0-ghost_coef)+gb->lcd.framebuffer[p+1]*ghost_coef+0.5;
    gb->lcd.framebuffer[p+2] = b*(1.0-ghost_coef)+gb->lcd.framebuffer[p+2]*ghost_coef+0.5;
  }
  if(rendered_part_of_window)gb->lcd.curr_window_scanline+=1;
}
static FORCE_INLINE bool sb_update_lcd(sb_gb_t* gb, int delta_cycles, bool draw,sb_emu_state_t* emu){
  bool new_scanline = sb_update_lcd_status(gb, delta_cycles);
  if(new_scanline){
    if(draw)sb_draw_scanline(gb,emu);
    uint8_t y = sb_read8_direct(gb, SB_IO_LCD_LY);
    if(y+1==SB_LCD_H)return true;
  }
  return false;
}
void sb_update_timers(sb_gb_t* gb, int delta_clocks, bool double_speed){
  uint8_t tac = sb_read8_direct(gb, SB_IO_TAC);
  bool tima_enable = SB_BFE(tac, 2, 1);
  int clk_sel = SB_BFE(tac, 0, 2);

  int tma_bit = 0; 
  switch(clk_sel){
    case 0: tma_bit = 9;break; //4khz
    case 1: tma_bit = 3;break; //256khz
    case 2: tma_bit = 5;break; //64Khz
    case 3: tma_bit = 7;break; //16Khz
  }
  int seq_bit = double_speed?13:12;
  for(int i=0;i<delta_clocks;++i){
    uint16_t curr = gb->timers.total_clock_ticks;
    uint16_t next = curr+1;
    gb->timers.total_clock_ticks=next;
    bool tick_tima = SB_BFE(curr,tma_bit,1)&tima_enable;
    bool tick_seq = SB_BFE(curr,seq_bit,1);
    if(tick_tima==false&&gb->timers.last_tick_tima==true){
      uint8_t d = sb_read8_direct(gb, SB_IO_TIMA);
      // Trigger timer interrupt
      if(d == 255){
        uint8_t i_flag = sb_read8_direct(gb, SB_IO_INTER_F);
        i_flag |= 1<<2;
        sb_store8_direct(gb, SB_IO_INTER_F, i_flag);
        d = sb_read8_direct(gb,SB_IO_TMA);
      }else d +=1;
      sb_store8_direct(gb, SB_IO_TIMA, d);
    }
    if(tick_seq&&!gb->timers.last_tick_seq)sb_tick_frame_seq(&gb->audio.sequencer);
    gb->timers.last_tick_seq = tick_seq;
    gb->timers.last_tick_tima = tick_tima;
  }
  sb_store8_direct(gb, SB_IO_DIV, SB_BFE(gb->timers.total_clock_ticks,8,8));
}
int sb_update_dma(sb_gb_t *gb){

  int delta_cycles = 0;
  if(gb->dma.active){
    unsigned bytes_transferred = 0;
    uint16_t dma_src = sb_read8_direct(gb,SB_IO_DMA_SRC_LO)|
                    ((int)sb_read8_direct(gb,SB_IO_DMA_SRC_HI)<<8u);
    uint16_t dma_dst = sb_read8_direct(gb,SB_IO_DMA_DST_LO)|
                    ((int)sb_read8_direct(gb,SB_IO_DMA_DST_HI)<<8u);
    dma_src&=0xfff0;
    dma_dst&=0x1ff0;
    dma_dst|=0x8000;
    uint8_t dma_mode_length = sb_read8_direct(gb,SB_IO_DMA_MODE_LEN);

    int len = (SB_BFE(dma_mode_length, 0,7));
    bool hdma_mode = gb->dma.hdma;
    if(!hdma_mode||(gb->dma.in_hblank==false&&gb->lcd.in_hblank==true&&gb->lcd.curr_scanline<SB_LCD_H-1))
    {
      while(len>=0){
        for(int i=0;i<16;++i){
          int off = gb->dma.bytes_transferred++;
          if(dma_src>0xffff){len=0;break;}
          uint8_t data = sb_read8(gb,dma_src);
          sb_store8(gb,dma_dst,data);
          dma_src++;
          dma_dst++;
          bytes_transferred+=1;
        }
        sb_store8_direct(gb,SB_IO_DMA_SRC_LO,SB_BFE(dma_src,0,8));
        sb_store8_direct(gb,SB_IO_DMA_SRC_HI,SB_BFE(dma_src,8,8));
        sb_store8_direct(gb,SB_IO_DMA_DST_LO,SB_BFE(dma_dst,0,8));
        sb_store8_direct(gb,SB_IO_DMA_DST_HI,SB_BFE(dma_dst,8,8));
        len--;           
        if(hdma_mode)break;
      }

      uint8_t new_mode = (len&0x7f);
      if(len<0){
        gb->dma.active = false;
        gb->dma.hdma = false; 
        len = 0;
        hdma_mode = 0;
        new_mode = 0xff;
      }
      if(!gb->dma.active)new_mode|=0x80;
      sb_store8_direct(gb,SB_IO_DMA_MODE_LEN,new_mode);
    }
    gb->dma.in_hblank = gb->lcd.in_hblank;
    delta_cycles+= bytes_transferred/2;
  }
  return delta_cycles;
}
void sb_update_oam_dma(sb_gb_t* gb, int delta_cycles){
 if(gb->dma.oam_dma_active){
    uint16_t dma_src = ((int)sb_read8_direct(gb,SB_IO_OAM_DMA))<<8u;
    uint16_t dma_dst = 0xfe00;
    // From CasualPokePlayer:
    // in most cases echo ram is only E000-FDFF. 
    // oam dma is one of the exceptions here which have the entire E000-FFFF
    // region as echo ram for dma source
    if(dma_src==0xfe00)dma_src=0xde00;
    else if(dma_src==0xff00)dma_src=0xdf00;

    while(delta_cycles--&&gb->dma.oam_bytes_transferred<0xA0){
      uint8_t data = sb_read8(gb,dma_src+gb->dma.oam_bytes_transferred);
      sb_store8(gb,dma_dst+gb->dma.oam_bytes_transferred,data);
      gb->dma.oam_bytes_transferred++;
    }
    if(gb->dma.oam_bytes_transferred==0xA0)gb->dma.oam_dma_active=false;
  }

}
static FORCE_INLINE void sb_tick_sio(sb_gb_t* gb, int delta_cycles){
  //Just a stub for now;
  uint8_t siocnt= sb_read8_direct(gb,SB_IO_SERIAL_CTRL);
  bool active = SB_BFE(siocnt,7,1);
  if(active){
    if(gb->serial.last_active==false){
      gb->serial.last_active =true;
      gb->serial.ticks_to_complete=4*1024*1024/1024;
      bool fast_clock = SB_BFE(siocnt,1,1)&&sb_gbc_enable(gb);
      if(fast_clock)gb->serial.ticks_to_complete/=2;
    }
    bool internal_clock = SB_BFE(siocnt,0,1);
    if(internal_clock)gb->serial.ticks_to_complete-=delta_cycles;
    if(gb->serial.ticks_to_complete<=0){
      siocnt&=0x7f;
      sb_store8_direct(gb,SB_IO_SERIAL_CTRL,siocnt);
      sb_store8_direct(gb,SB_IO_SERIAL_BYTE,0xff);
      uint8_t i_flag = sb_read8_direct(gb,SB_IO_INTER_F);
      i_flag |= (1<<3);
      sb_store8_direct(gb,SB_IO_INTER_F,i_flag);
      active =false;
    }
  }
  gb->serial.last_active =active; 
}
void sb_tick(sb_emu_state_t* emu, sb_gb_t* gb,gb_scratch_t* scratch){
  gb->lcd.framebuffer = scratch->framebuffer; 
  gb->cart.data = emu->rom_data; 
  gb->bios = scratch->bios;
  int instructions_to_execute = emu->step_instructions;
  if(instructions_to_execute==0)instructions_to_execute=6000000;
  int frames_to_draw = 1;

  int total_cylces = 0; 
  int rumble_cycles= 0; 

  for(int i=0;i<instructions_to_execute;++i){
    bool double_speed = false;
    sb_update_joypad_io_reg(emu, gb);
    int dma_delta_cycles = sb_update_dma(gb);
    int cpu_delta_cycles = 0;
    if(dma_delta_cycles==0){
      cpu_delta_cycles=4;
      int pc = gb->cpu.pc;
      unsigned op = sb_read8(gb,gb->cpu.pc);
      bool request_speed_switch= false;
      if(sb_gbc_enable(gb)){
        unsigned speed = sb_read8(gb,SB_IO_GBC_SPEED_SWITCH);
        double_speed = SB_BFE(speed, 7, 1);
        request_speed_switch = SB_BFE(speed, 0, 1);
      }
      if(gb->cpu.prefix_op)op+=256;
 
      int trigger_interrupt = -1;
      // TODO: Can interrupts trigger between prefix ops and the second byte?
      if(gb->cpu.prefix_op==false){
        uint8_t ie = sb_read8_direct(gb,SB_IO_INTER_EN);
        uint8_t i_flag = gb->cpu.last_inter_f;
        uint8_t masked_interupt = ie&i_flag&0x1f;
        for(int i=0;i<5;++i){
          if(masked_interupt & (1<<i)){trigger_interrupt = i;break;}
        }
      }
      cpu_delta_cycles = 4;
      bool call_interrupt = false;
      if(trigger_interrupt!=-1&&request_speed_switch==false){
        if(gb->cpu.interrupt_enable){
          gb->cpu.interrupt_enable = false;
          gb->cpu.deferred_interrupt_enable = false;
          int interrupt_address = (trigger_interrupt*0x8)+0x40;
          sb_call_impl(gb, interrupt_address, 0, 0, 0, (const uint8_t*)"----");
          cpu_delta_cycles = 5*4;
          call_interrupt=true;
        }
        if(call_interrupt){
          uint8_t i_flag = sb_read8_direct(gb,SB_IO_INTER_F);
          i_flag &= ~(1<<trigger_interrupt);
          sb_store8_direct(gb,SB_IO_INTER_F,i_flag);
        }
        gb->cpu.wait_for_interrupt = false;
      }

      if(gb->cpu.deferred_interrupt_enable){
        gb->cpu.deferred_interrupt_enable = false;
        gb->cpu.interrupt_enable = true;
      }
 
      if(call_interrupt==false&&gb->cpu.wait_for_interrupt==false){
        sb_instr_t inst = sb_decode_table[op];
        gb->cpu.pc+=inst.length;
        if(gb->cpu.halt_bug)gb->cpu.pc--;
        gb->cpu.halt_bug = false;
        int operand1 = sb_load_operand(gb,inst.op_src1);
        int operand2 = sb_load_operand(gb,inst.op_src2);

        unsigned pc_before_inst = gb->cpu.pc;
        gb->cpu.prefix_op = false;
        inst.impl(gb, operand1, operand2,inst.op_src1,inst.op_src2, inst.flag_mask);
        if(gb->cpu.prefix_op==true)i--;

        if(gb->cpu.wait_for_interrupt){
          uint8_t ie = sb_read8_direct(gb,SB_IO_INTER_EN);
          uint8_t i_flag = gb->cpu.last_inter_f;
          uint8_t masked_interupt = ie&i_flag&0x1f;
          if(masked_interupt&&!gb->cpu.interrupt_enable){
            gb->cpu.wait_for_interrupt=false;
            gb->cpu.halt_bug =true;
          }
        }
        cpu_delta_cycles = 4*((gb->cpu.branch_taken? (inst.mcycles_branch_taken-(inst.mcycles-1)) : 1));
        gb->cpu.branch_taken=false;
      }else if(call_interrupt==false&&gb->cpu.wait_for_interrupt==true && request_speed_switch){
        gb->cpu.wait_for_interrupt = false;
        sb_store8(gb,SB_IO_GBC_SPEED_SWITCH,double_speed? 0x00: 0x80);
      }
      if(trigger_interrupt!=-1)gb->cpu.wait_for_interrupt=false;
      if(!gb->cpu.wait_for_interrupt){
        unsigned next_op = sb_read8(gb,gb->cpu.pc);
        if(gb->cpu.prefix_op)next_op+=256;
        sb_instr_t next_inst = sb_decode_table[next_op];
        cpu_delta_cycles+= (next_inst.mcycles-1)*4;
        if(gb->cpu.prefix_op){
          cpu_delta_cycles -=4;
        }
      }
      gb->cpu.last_inter_f = sb_read8_direct(gb,SB_IO_INTER_F);
    }
    sb_update_oam_dma(gb,cpu_delta_cycles);
    int delta_cycles_after_speed = double_speed ? cpu_delta_cycles/2 : cpu_delta_cycles;
    delta_cycles_after_speed+= dma_delta_cycles;
    bool vblank = sb_update_lcd(gb,delta_cycles_after_speed,emu->render_frame,emu);
    sb_update_timers(gb,dma_delta_cycles?dma_delta_cycles:cpu_delta_cycles, double_speed);
    sb_tick_sio(gb,delta_cycles_after_speed);
    rumble_cycles+=delta_cycles_after_speed*gb->cart.rumble;
    total_cylces+=delta_cycles_after_speed;
    double delta_t = ((double)delta_cycles_after_speed)/(4*1024*1024);
    //sb_push_save_state(gb);

    if (gb->cpu.pc == emu->pc_breakpoint||gb->cpu.trigger_breakpoint){
      gb->cpu.trigger_breakpoint = false;
      emu->run_mode = SB_MODE_PAUSE;
      break;
    }
    sb_process_audio(gb,emu,delta_t);
    if(vblank){break;}
  }
  emu->joy.rumble = (double)rumble_cycles/(double)total_cylces;
}
float compute_vol_env_slope(uint8_t d){
  int dir = SB_BFE(d,3,1);
  int length_of_step = SB_BFE(d,0,3);

  float step_time = length_of_step/64.0;
  float slope = 1./step_time;
  if(dir==0)slope*=-1;
  if(length_of_step==0)slope=0;
  return slope/16.;
} 
float sb_polyblep(float t,float dt){
  if(t<=dt){    
    t = t/dt;
    return t+t-t*t-1.0;;
  }else if (t >= 1-dt){
    t=(t-1.0)/dt;
    return t*t+t+t+1.0;
  }else return 0; 
}
float sb_bandlimited_square(float t, float duty_cycle,float dt){
  float t2 = t - duty_cycle;
  if(t2< 0.0)t2 +=1.0;
  float y = t < duty_cycle ? -1 : 1;
  y -= sb_polyblep(t,dt);
  y += sb_polyblep(t2,dt);
  return y;
}
static bool sb_load_rom(sb_emu_state_t* emu,sb_gb_t* gb, gb_scratch_t* scratch){
  if(!sb_path_has_file_ext(emu->rom_path,".gb") && 
     !sb_path_has_file_ext(emu->rom_path,".gbc")) return false; 
  if(emu->rom_size+1>MAX_CARTRIDGE_SIZE)return false;
  memset(gb, 0, sizeof(sb_gb_t));
  memset(scratch, 0, sizeof(gb_scratch_t));
  gb->cart.data = emu->rom_data;
  for(size_t i = 0; i< 32*1024;++i)gb->mem.data[i] = gb->cart.data[i];
  // Copy Header
  for (int i = 0; i < 11; ++i) {
    gb->cart.title[i] = gb->cart.data[i + 0x134];
  }
  gb->cart.title[12] ='\0';
  // TODO PGB Mode(Values with Bit 7 set, and either Bit 2 or 3 set)
  gb->cart.game_boy_color =
      SB_BFE(gb->cart.data[0x143], 7, 1) == 1;
  gb->cart.type = gb->cart.data[0x147];

  for(int i=0;i<sizeof(gb->lcd.color_palettes);++i)gb->lcd.color_palettes[i]=0xff;

  switch(gb->cart.type){
    case 0: gb->cart.mbc_type = SB_MBC_NO_MBC; break;

    case 1:
    case 2:
    case 3: gb->cart.mbc_type = SB_MBC_MBC1; break;

    case 5:
    case 6: gb->cart.mbc_type = SB_MBC_MBC2; break;

    case 0x0f:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13: gb->cart.mbc_type = SB_MBC_MBC3; break;

    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x1C:
    case 0x1D:
    case 0x1E:gb->cart.mbc_type = SB_MBC_MBC5; break;

    case 0x20:gb->cart.mbc_type = SB_MBC_MBC6; break;
    case 0x22:gb->cart.mbc_type = SB_MBC_MBC7; break;

  }
  gb->cart.has_rumble=false;
  switch(gb->cart.type){
    case 0x1C:
    case 0x1D:
    case 0x1E:
    case 0x22: gb->cart.has_rumble=true; break;
  }
  switch (gb->cart.data[0x148]) {
    case 0x0: gb->cart.rom_size = 32 * 1024;  break;
    case 0x1: gb->cart.rom_size = 64 * 1024;  break;
    case 0x2: gb->cart.rom_size = 128 * 1024; break;
    case 0x3: gb->cart.rom_size = 256 * 1024; break;
    case 0x4: gb->cart.rom_size = 512 * 1024; break;
    case 0x5: gb->cart.rom_size = 1024 * 1024;     break;
    case 0x6: gb->cart.rom_size = 2 * 1024 * 1024; break;
    case 0x7: gb->cart.rom_size = 4 * 1024 * 1024; break;
    case 0x8: gb->cart.rom_size = 8 * 1024 * 1024; break;
    case 0x52: gb->cart.rom_size = 1.1 * 1024 * 1024; break;
    case 0x53: gb->cart.rom_size = 1.2 * 1024 * 1024; break;
    case 0x54: gb->cart.rom_size = 1.5 * 1024 * 1024; break;
    default: gb->cart.rom_size = 32 * 1024; break;
  }
  switch (gb->cart.data[0x149]) {
    case 0x0: gb->cart.ram_size = 0; break;
    case 0x1: gb->cart.ram_size = 2*1024; break;
    case 0x2: gb->cart.ram_size = 8 * 1024; break;
    case 0x3: gb->cart.ram_size = 32 * 1024; break;
    case 0x4: gb->cart.ram_size = 128 * 1024; break;
    case 0x5: gb->cart.ram_size = 64 * 1024; break;
    default: gb->cart.ram_size = 0; break;
  }
  gb->model = SB_GB;
  if(gb->cart.game_boy_color){
    gb->model = SB_GBC;
  }
  gb->cart.mapped_rom_bank=1;
  size_t bytes =0;
  uint8_t*data = sb_load_file_data(emu->save_file_path, &bytes);
  if(data){
    if(bytes!=gb->cart.ram_size){
      printf("Warning save file size(%zu) doesn't match size expected(%d) for the cartridge type", bytes, gb->cart.ram_size);
    }
    if(bytes>gb->cart.ram_size){
      bytes = gb->cart.ram_size;
    }
    memcpy(gb->cart.ram_data, data, bytes);
    sb_free_file_data(data);
  }else{
    printf("Could not find save file: %s\n",emu->save_file_path);
    memset(gb->cart.ram_data,0,MAX_CARTRIDGE_RAM);
  }
  bool loaded_bios = false; 
  if(gb->model==SB_GB){
    loaded_bios= se_load_bios_file("GBC BIOS", emu->save_file_path, "gbc_bios.bin", scratch->bios,2304);
    if(loaded_bios){
      gb->model=SB_GBC;
    }
    if(!loaded_bios) loaded_bios= se_load_bios_file("DMG0 BIOS", emu->save_file_path, "dmg0_rom.bin", scratch->bios,256);
    if(!loaded_bios) loaded_bios= se_load_bios_file("GB BIOS", emu->save_file_path, "gb_bios.bin", scratch->bios,256);
  }else if(gb->model==SB_GBC){
    loaded_bios= se_load_bios_file("GBC BIOS", emu->save_file_path, "gbc_bios.bin", scratch->bios,2304);
  }
  if(loaded_bios){
    gb->cpu.pc = 0; 
  }else{
    sb_store8_direct(gb,SB_IO_BIOS_BANK,1);
    gb->cpu.pc = 0x100;
    gb->cpu.af=0x01B0;
    gb->cpu.bc=0x0013;
    gb->cpu.de=0x00D8;
    gb->cpu.hl=0x014D;
    gb->cpu.sp=0xFFFE;
    if(gb->model == SB_GBC){
      gb->cpu.af|=0x11<<8;
    }

    gb->mem.data[0xFF05] = 0x00; // TIMA
    gb->mem.data[0xFF06] = 0x00; // TMA
    gb->mem.data[0xFF07] = 0x00; // TAC
    /*
    gb->mem.data[0xFF10] = 0x80; // NR10
    gb->mem.data[0xFF11] = 0xBF; // NR11
    gb->mem.data[0xFF12] = 0xF3; // NR12
    gb->mem.data[0xFF14] = 0xBF; // NR14
    gb->mem.data[0xFF16] = 0x3F; // NR21
    gb->mem.data[0xFF17] = 0x00; // NR22
    gb->mem.data[0xFF19] = 0xBF; // NR24
    */
    gb->mem.data[0xFF1A] = 0x7F; // NR30
    gb->mem.data[0xFF1B] = 0xFF; // NR31
    gb->mem.data[0xFF1C] = 0x9F; // NR32
    gb->mem.data[0xFF1E] = 0xBF; // NR34
    /*
    gb->mem.data[0xFF20] = 0xFF; // NR41
    gb->mem.data[0xFF21] = 0x00; // NR42
    gb->mem.data[0xFF22] = 0x00; // NR43
    gb->mem.data[0xFF23] = 0xBF; // NR44
    gb->mem.data[0xFF24] = 0x77; // NR50
    */
    gb->mem.data[0xFF25] = 0xF3; // NR51
    gb->mem.data[0xFF26] = 0xF1; // $F0-SGB ; NR52
    gb->mem.data[0xFF40] = 0x91; // LCDC
    gb->mem.data[0xFF42] = 0x00; // SCY
    gb->mem.data[0xFF43] = 0x00; // SCX
    gb->mem.data[0xFF44] = 0x90; // SCX
    gb->mem.data[0xFF45] = 0x00; // LYC
    gb->mem.data[0xFF47] = 0xFC; // BGP
    gb->mem.data[0xFF48] = 0xFF; // OBP0
    gb->mem.data[0xFF49] = 0xFF; // OBP1
    gb->mem.data[0xFF4A] = 0x00; // WY
    gb->mem.data[0xFF4B] = 0x00; // WX
    gb->mem.data[0xFFFF] = 0x00; // IE
  }
  
  return true; 
}
static int sb_compute_next_sweep_freq(sb_frame_sequencer_t*seq){
  int shift = seq->sweep_shift?seq->sweep_shift:8;
  int32_t increment = (seq->frequency[0] >> shift)*seq->sweep_direction;
  int32_t new_frequency = seq->frequency[0]+increment;
  seq->sweep_subtracted|=seq->sweep_direction==-1;
  return new_frequency;
}
static void sb_tick_frame_sweep(sb_frame_sequencer_t*seq){
  int32_t new_frequency = sb_compute_next_sweep_freq(seq);
  if(new_frequency>2047){
    seq->active[0]=false; 
    new_frequency = 2047; 
  }else if(new_frequency<0)new_frequency=0;
  if(seq->sweep_shift){
    seq->frequency[0]= new_frequency;
    new_frequency = sb_compute_next_sweep_freq(seq);
    if(new_frequency>2047){
      seq->active[0]=false; 
      new_frequency = 2047; 
    }
  }
}
static void sb_tick_frame_seq(sb_frame_sequencer_t* seq){
  int step = (seq->step_counter++)%8;
  //Tick sweep
  if(step==2||step==6){
    if(seq->active[0]&&seq->sweep_enable){
      if(seq->sweep_timer>0)seq->sweep_timer--;
      if(seq->sweep_timer == 0){
        if(seq->sweep_period > 0){
          seq->sweep_timer = seq->sweep_period;
          sb_tick_frame_sweep(seq);
        }else seq->sweep_timer = 8;
      }
    }
  }
  //Tick envelope
  if(step==7){
    for(int i=0;i<4;++i){
      if(i==2)continue;
      if(seq->env_period[i]){
        if(seq->env_period_timer[i]>0)seq->env_period_timer[i]--;
        if(seq->env_period_timer[i]==0){
          seq->env_period_timer[i]=seq->env_period[i];
          int volume = seq->volume[i];
          volume+=seq->env_direction[i];
          if(volume<=0){volume=0;seq->env_overflow[i]=true;}
          if(volume>0xF){volume=0xF;seq->env_overflow[i]=true;};
          seq->volume[i]=volume;
        }
      }
    }
  }
  if((step%2)==0){
    //Tick length
    for(int i=0;i<4;++i){
      if(!seq->use_length[i])continue;
      if(seq->length[i]>0)seq->length[i]--;
      if(seq->length[i]==0){
        seq->active[i]=false; 
        seq->length[i] = i==2?256:64; 
        seq->use_length[i] = false;
      }
    }
  }
}
static void sb_process_audio_writes(sb_gb_t* gb){
  sb_frame_sequencer_t* seq = &gb->audio.sequencer;
  if(gb->audio.regs_written){
    gb->audio.regs_written = false; 
    int nrf_52 = sb_read8_direct(gb,SB_IO_SOUND_ON_OFF)&0xf0;
    bool master_enable = SB_BFE(nrf_52,7,1);
    if(!master_enable){
      for(int i=SB_IO_AUD1_TONE_SWEEP;i<SB_IO_SOUND_ON_OFF;++i){
        sb_store8_direct(gb,i,0);
      }
      for(int i=0;i<4;++i){
        seq->active[i]=false;
        seq->powered[i]=false;
        seq->use_length[i]=false;
        seq->length[i]=0;
      }
    }else{
      uint8_t freq_sweep1 = sb_read8_direct(gb, SB_IO_AUD1_TONE_SWEEP);
      seq->sweep_period=SB_BFE(freq_sweep1, 4, 3);
      seq->sweep_shift=SB_BFE(freq_sweep1, 0, 3);
      seq->sweep_direction= SB_BFE(freq_sweep1, 3,1)? -1. : 1; 
      for(int i=0;i<4;++i){
        bool prev_length_en = seq->use_length[i];
        uint8_t freq_hi = sb_read8_direct(gb,SB_IO_AUD1_FREQ_HI+i*5);
        seq->use_length[i]= SB_BFE(freq_hi,6,1);
        uint8_t vol_env = sb_read8_direct(gb,SB_IO_AUD1_VOL_ENV+i*5);
        if(i==2){
          bool power = SB_BFE(sb_read8_direct(gb,SB_IO_AUD3_POWER),7,1);
          seq->powered[i]=power;
        }
        if(i!=0){
          uint8_t freq_lo = sb_read8_direct(gb,SB_IO_AUD1_FREQ+i*5);
          seq->frequency[i] = freq_lo | ((int)(SB_BFE(freq_hi,0,3))<<8u);
        }
        if(i==2){
          seq->env_direction[i] = 0;
          seq->env_period[i] = 0;
        }else{
          seq->env_direction[i] = (SB_BFE(vol_env,3,1)?1:-1);
          seq->env_period[i] = SB_BFE(vol_env,0,3);
        }
        bool triggered = SB_BFE(freq_hi,7,1);
        if(triggered){
          uint8_t length_duty = sb_read8_direct(gb, SB_IO_AUD1_LENGTH_DUTY+i*5);
          uint8_t freq_lo = sb_read8_direct(gb,SB_IO_AUD1_FREQ+i*5);
          seq->frequency[i] = freq_lo | ((int)(SB_BFE(freq_hi,0,3))<<8u);
          seq->volume[i] = SB_BFE(vol_env,4,4);
         
          if(seq->length[i]==0)seq->length[i]=i==2?256:64;
          if(i==3)seq->lfsr4 = 0x7FFF;
          seq->env_period_timer[i]=0;
          seq->env_overflow[i]=false;
          seq->chan_t[i]=0;
          seq->active[i]=true;
          if(i==0){
            seq->sweep_subtracted=false;
            seq->sweep_enable = seq->sweep_period||seq->sweep_shift;
            seq->sweep_timer=seq->sweep_period;
            if(seq->sweep_timer==0)seq->sweep_timer=8; 
            if (seq->sweep_shift && sb_compute_next_sweep_freq(seq) > 2047) {
              seq->active[0] = false;
            } 
            seq->sweep_enable = seq->sweep_period>0||seq->sweep_shift>0;
          }
        }
        if(i==0&&seq->sweep_subtracted&&seq->sweep_direction!=-1){
          seq->active[0]= false; 
          seq->sweep_enable = false;
        }
        if(seq->use_length[i]&&!prev_length_en){
          bool second_half_of_length_period = (seq->step_counter&1);
          if(second_half_of_length_period){
            if(seq->length[i])seq->length[i]--;
            if(seq->length[i]==0){
              if(triggered) seq->length[i]=i==2?255:63;
              else{
                seq->active[i]=false;
                seq->use_length[i]=triggered&&seq->use_length[i];
              }
            }
          }
        }
        sb_store8_direct(gb, SB_IO_AUD1_FREQ_HI+i*5,freq_hi&0x7f);
      }
    }
  }
}
static FORCE_INLINE void sb_process_audio(sb_gb_t *gb, sb_emu_state_t*emu, double delta_time){

  sb_audio_t* audio = &gb->audio;
  audio->current_sample_generated_time -= (int)(audio->current_sim_time);
  audio->current_sim_time -= (int)(audio->current_sim_time);

  const static float duty_lookup[]={0.125,0.25,0.5,0.75};

  if(gb->audio.regs_written){sb_process_audio_writes(gb);}
  sb_frame_sequencer_t* seq = &audio->sequencer;
  int nrf_52 = sb_read8_direct(gb,SB_IO_SOUND_ON_OFF)&0xf0;
  for(int i=0;i<4;++i){
    seq->active[i]&=seq->powered[i];
    bool active = seq->active[i];
    nrf_52|=active<<i;
  }
  sb_store8_direct(gb,SB_IO_SOUND_ON_OFF,nrf_52);

  if(delta_time>1.0/60.)delta_time = 1.0/60.;
  audio->current_sim_time +=delta_time;
  if(audio->current_sample_generated_time >audio->current_sim_time)return; 
  bool master_enable = SB_BFE(nrf_52,7,1);
  if(!master_enable)return;
  float sample_delta_t = 1.0/SE_AUDIO_SAMPLE_RATE;

  uint8_t length_duty1 = sb_read8_direct(gb, SB_IO_AUD1_LENGTH_DUTY);
  float duty1 = duty_lookup[SB_BFE(length_duty1,6,2)];
  uint8_t length_duty2 = sb_read8_direct(gb, SB_IO_AUD2_LENGTH_DUTY);
  float duty2 = duty_lookup[SB_BFE(length_duty2,6,2)];

  uint8_t power3 = sb_read8_direct(gb,SB_IO_AUD3_POWER);
  uint8_t vol_env3 = sb_read8_direct(gb,SB_IO_AUD3_VOL);
  int channel3_shift = SB_BFE(vol_env3,5,2)-1;
  if(SB_BFE(power3,7,1)==0||channel3_shift==-1)channel3_shift=4;

  uint8_t poly4 = sb_read8_direct(gb,SB_IO_AUD4_POLY);
  float r4 = SB_BFE(poly4,0,3);
  uint8_t s4 = SB_BFE(poly4,4,4);
  bool sevenBit4 = SB_BFE(poly4,3,1);
  if(r4==0)r4=0.5;

  uint8_t master_vol = sb_read8_direct(gb,SB_IO_MASTER_VOLUME);
  float master_left = SB_BFE(master_vol,4,3)/7.;
  float master_right = SB_BFE(master_vol,0,3)/7.;

  uint8_t chan_sel = sb_read8_direct(gb,SB_IO_SOUND_OUTPUT_SEL);
  //These are type int to allow them to be multiplied to enable/disable
  int chan_l[4];int chan_r[4];
  for(int i=0;i<4;++i){
    chan_l[i] = SB_BFE(chan_sel,i,1);
    chan_r[i] = SB_BFE(chan_sel,i+4,1);
  }

  float freq_hz[4];
  for(int i=0;i<2;++i){freq_hz[i]= 131072./(2048-seq->frequency[i]);}
  freq_hz[2]= (65536.)/(2048-seq->frequency[2]);
  freq_hz[3] = 524288.0/r4/pow(2.0,s4+1);
  while(gb->audio.current_sample_generated_time < gb->audio.current_sim_time){

    gb->audio.current_sample_generated_time+=sample_delta_t;
    
    if((sb_ring_buffer_size(&emu->audio_ring_buff)+3>SB_AUDIO_RING_BUFFER_SIZE)) continue;

    //Advance each channel    
    for(int i=0;i<4;++i)seq->chan_t[i]  +=sample_delta_t*freq_hz[i];
    //Generate new noise value if needed
    if(seq->chan_t[3]>=1.0) {
      int bit = (seq->lfsr4 ^ (seq->lfsr4 >> 1)) & 1;
      seq->lfsr4 >>= 1;
      seq->lfsr4 |= bit << 14;
      if (sevenBit4) {
        seq->lfsr4 &= ~(1 << 7);
        seq->lfsr4 |= bit << 6;
      }
    }
    
    //Loopback
    for(int i=0;i<4;++i) seq->chan_t[i]-=(int)seq->chan_t[i];
    
    //Compute and clamp Volume Envelopes
    float v[4];
	  for(int i=0;i<4;++i)v[i] = seq->active[i]?seq->volume[i]/15.:0;
    v[2] = 1.0;

	  //Lookup wave table value
    unsigned wav_samp = ((unsigned)(seq->chan_t[2]*32))%32;
    int dat =sb_read8_direct(gb,SB_IO_AUD3_WAVE_BASE+wav_samp/2);
    gb->audio.curr_wave_data = dat;
    int offset = (wav_samp&1)? 0:4;
    dat = ((dat>>offset)&0xf)>>channel3_shift;
    int wav_offset = 8>>channel3_shift; 
    
    float channels[4];
    channels[0] = sb_bandlimited_square(seq->chan_t[0],duty1,sample_delta_t*freq_hz[0])*v[0];
    channels[1] = sb_bandlimited_square(seq->chan_t[1],duty2,sample_delta_t*freq_hz[1])*v[1];
    channels[2] = (dat-wav_offset)/8.;
    channels[3] = ((seq->lfsr4 & 1) * 2.-1.)*v[3];

    //Mix channels
    float sample_volume_l = 0;
    float sample_volume_r = 0;
    for(int i=0;i<4;++i){
      float l = channels[i]*chan_l[i];
      float r = channels[i]*chan_r[i];
      if(l>=-2.&&l<=2)sample_volume_l+=l;
      if(r>=-2.&&r<=2)sample_volume_r+=r;
    }
    
    sample_volume_l*=0.25;
    sample_volume_r*=0.25;
    sample_volume_l*=master_left;
    sample_volume_r*=master_right;

    const float lowpass_coef = 0.999;
    emu->mix_l_volume = emu->mix_l_volume*lowpass_coef + fabs(sample_volume_l)*(1.0-lowpass_coef);
    emu->mix_r_volume = emu->mix_r_volume*lowpass_coef + fabs(sample_volume_r)*(1.0-lowpass_coef); 
    
    for(int i=0;i<4;++i){
      emu->audio_channel_output[i] = emu->audio_channel_output[i]*lowpass_coef 
                                  + fabs(channels[i])*(1.0-lowpass_coef); 
    }
    // Clipping
    if(sample_volume_l>1.0)sample_volume_l=1;
    if(sample_volume_r>1.0)sample_volume_r=1;
    if(sample_volume_l<-1.0)sample_volume_l=-1;
    if(sample_volume_r<-1.0)sample_volume_r=-1;
    float out_l = sample_volume_l-audio->capacitor_l;
    float out_r = sample_volume_r-audio->capacitor_r;
    audio->capacitor_l = (sample_volume_l-out_l)*0.996;
    audio->capacitor_r = (sample_volume_r-out_r)*0.996;
    // Quantization
    unsigned write_entry0 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
    unsigned write_entry1 = (emu->audio_ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;

    emu->audio_ring_buff.data[write_entry0] = out_l*32760;
    emu->audio_ring_buff.data[write_entry1] = out_r*32760;
  }
}
