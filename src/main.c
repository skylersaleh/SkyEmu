/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#include "raylib.h"
#include "sb_instr_tables.h"
#include "sb_types.h"
#include "gba.h"
#include <stdint.h>
#include <math.h>
#define RAYGUI_IMPLEMENTATION
#define RAYGUI_SUPPORT_ICONS
#include "raygui.h"
#include "rlgl.h"
#if defined(PLATFORM_WEB)
#include <emscripten/emscripten.h>
#endif                                             

#define SB_NUM_SAVE_STATES 5
#define SB_AUDIO_BUFF_SAMPLES 2048
#define SB_AUDIO_BUFF_CHANNELS 2
#define SB_AUDIO_SAMPLE_RATE 44100

#define SB_IO_JOYPAD      0xff00
#define SB_IO_SERIAL_BYTE 0xff01
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

#define SB_IO_GBC_SPEED_SWITCH 0xff4d
#define SB_IO_GBC_VBK     0xff4f

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

const int GUI_PADDING = 10;
const int GUI_ROW_HEIGHT = 30;
const int GUI_LABEL_HEIGHT = 0;
const int GUI_LABEL_PADDING = 5;

//TODO: Clean this up to use unions...
sb_emu_state_t emu_state = {.pc_breakpoint = -1};
sb_gb_t gb_state = {};
gba_t gba; 

sb_gb_t sb_save_states[SB_NUM_SAVE_STATES];
int sb_valid_save_states = 0;
unsigned sb_save_state_index=0;

AudioStream audio_stream;

uint32_t sb_lookup_tile(sb_gb_t* gb, int px, int py, int tile_base, int data_mode);
void sb_lookup_palette_color(sb_gb_t*gb,int color_id, int*r, int *g, int *b);
void sb_process_audio(sb_gb_t *gb, double delta_time);
double sb_gb_fps_counter(int tick);

void sb_pop_save_state(sb_gb_t* gb){
  if(sb_valid_save_states>0){
    --sb_valid_save_states;
    --sb_save_state_index;
    *gb = sb_save_states[sb_save_state_index%SB_NUM_SAVE_STATES];
  }
}


void sb_push_save_state(sb_gb_t* gb){
  ++sb_valid_save_states;
  if(sb_valid_save_states>SB_NUM_SAVE_STATES)sb_valid_save_states = SB_NUM_SAVE_STATES;
  ++sb_save_state_index;
  sb_save_states[sb_save_state_index%SB_NUM_SAVE_STATES] = *gb;
}

inline static uint8_t sb_read8_direct(sb_gb_t *gb, int addr) {
  if(addr>=0x4000&&addr<=0x7fff){
    int bank = gb->cart.mapped_rom_bank;
    if(bank ==0 && gb->cart.mbc_type!= SB_MBC_MBC5)bank = 1;
    bank %= (gb->cart.rom_size)/0x4000;
    unsigned int bank_off = 0x4000*(bank);
    return gb->cart.data[addr-0x4000+bank_off];
  }else if(addr>=0x8000&&addr<=0x9fff){
    uint8_t vbank =gb->mem.data[SB_IO_GBC_VBK]%SB_VRAM_NUM_BANKS;
    return gb->lcd.vram[vbank*SB_VRAM_BANK_SIZE+addr-0x8000];
  } else if(addr>=0xA000&&addr<=0xBfff){
    int ram_addr_off = 0x2000*gb->cart.mapped_ram_bank+(addr-0xA000);
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
      return d|0xfe;
    }
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
void sb_store8_direct(sb_gb_t *gb, int addr, int value) {
  static int count = 0;
  if(addr>=0x8000&&addr<=0x9fff){
    uint8_t vbank =sb_read8_direct(gb, SB_IO_GBC_VBK)%SB_VRAM_NUM_BANKS;;
    gb->lcd.vram[vbank*SB_VRAM_BANK_SIZE+addr-0x8000]=value;
    return;
  }else if(addr>=0xA000&&addr<=0xBfff){
    if(gb->cart.ram_write_enable){
      int ram_addr_off = 0x2000*gb->cart.mapped_ram_bank+(addr-0xA000);
      gb->cart.ram_data[ram_addr_off]=value;
      gb->cart.ram_is_dirty = true;
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
    if(addr == SB_IO_DMA_SRC_LO ||addr == SB_IO_DMA_DST_LO){
      value&=~0xf;
    } else if(addr == SB_IO_DMA_MODE_LEN){
      if(gb->dma.active){
        // Writing bit 7 to 0 for a running transfer halts HDMA
        if(!(value&0x80)){
          gb->dma.active = false;
        }
      }else{
        gb->dma.active =true;
        gb->dma.bytes_transferred=0;
        gb->dma.in_hblank = gb->lcd.in_hblank;
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
      value = 0; //All writes reset the div timer
      sb_store8(gb,SB_IO_TIMA,0);//TIMA and DIV are the same counter
    }else if(addr == SB_IO_SERIAL_BYTE){
      printf("%c",(char)value);
    } else if (addr == SB_IO_SOUND_ON_OFF){
      uint8_t d= sb_read8_direct(gb,addr);
      value = (d&0x7f)|(value&0x80);
    }
  }else if(addr >= 0x0000 && addr <=0x1fff){
    gb->cart.ram_write_enable = (value&0xf)==0xA;
  }else if(addr >= 0x2000 && addr <=0x3fff){
    //MBC3 rombank select
    if(addr>=0x3000&& gb->cart.mbc_type==SB_MBC_MBC5){
      gb->cart.mapped_rom_bank&=0xff;
      gb->cart.mapped_rom_bank|= (int)(value&1)<<8;
    }else gb->cart.mapped_rom_bank=(gb->cart.mapped_rom_bank&0x100)|value;;
    return;
  }else if(addr >= 0x4000 && addr <=0x5fff){
    //MBC3 rombank select
    //TODO implement other mappers
    value %= (gb->cart.ram_size/0x2000);
    gb->cart.mapped_ram_bank = value;
    return;
  }else if (addr>=0xfe00 && addr<=0xfe9f ){
    //OAM cannot be written to in mode 2 and 3
    int stat = sb_read8_direct(gb, SB_IO_LCD_STAT)&0x3;
    if(stat>=2) return;            
  } else if (addr>=0x8000 && addr <=0x9fff){
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

Rectangle sb_inside_rect_after_padding(Rectangle outside_rect, int padding) {
  Rectangle rect_inside = outside_rect;
  rect_inside.x += padding;
  rect_inside.y += padding;
  rect_inside.width -= padding * 2;
  rect_inside.height -= padding * 2;
  return rect_inside;
}
void sb_vertical_adv(Rectangle outside_rect, int advance, int y_padd,
                     Rectangle *rect_top, Rectangle *rect_bottom) {
  *rect_top = outside_rect;
  rect_top->height = advance;
  *rect_bottom = outside_rect;
  rect_bottom->y += advance + y_padd;
  rect_bottom->height -= advance + y_padd;
}

Rectangle sb_draw_emu_state(Rectangle rect, sb_emu_state_t *emu_state, sb_gb_t*gb, bool top_panel) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING/(top_panel?2:1));
  Rectangle widget_rect;
  if(top_panel){
    widget_rect = inside_rect;
    widget_rect.width = 100;
    emu_state->run_mode =
      GuiToggleGroup(widget_rect, "#74#Reset;#132#Pause;#131#Run;#134#Step", emu_state->run_mode);
      return (Rectangle){0};// Not used for vertical alignment
  }

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  widget_rect.width =
      widget_rect.width / 4 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4;
  emu_state->run_mode =
      GuiToggleGroup(widget_rect, "#74#Reset;#132#Pause;#131#Run;#134#Step", emu_state->run_mode);

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);

  Rectangle state_rect, adv_rect;
  if(!top_panel){
    GuiLabel(widget_rect, "Panel Mode");
    widget_rect.width =
        widget_rect.width / 4 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4;
    emu_state->panel_mode =
        GuiToggleGroup(widget_rect, "CPU;Tile Maps;Tile Data;Audio", emu_state->panel_mode);

    sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                    &adv_rect);
    GuiGroupBox(state_rect, TextFormat("Emulator State [FPS: %f]", sb_gb_fps_counter(0)));
  }
  return adv_rect;
}

Rectangle sb_draw_label(Rectangle layout_rect, const char* label){ 
  Rectangle widget_rect;
  sb_vertical_adv(layout_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &layout_rect);
  GuiLabel(widget_rect, label);  
  return layout_rect;
}

Rectangle sb_draw_debug_state(Rectangle rect, sb_emu_state_t *emu_state, sb_gb_t*gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;


  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);
  widget_rect.width =
      widget_rect.width / 2 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 1 / 2;

  int save_state=GuiToggleGroup(widget_rect, "Pop Save State;Push Save State", 3);

  if(save_state ==0)sb_pop_save_state(gb);
  if(save_state ==1)sb_push_save_state(gb);

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_LABEL_PADDING,
                  &widget_rect, &inside_rect);

  GuiLabel(widget_rect, "Instructions to Step");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);

  static bool edit_step_instructions = false;
  if (GuiSpinner(widget_rect, "", &emu_state->step_instructions, 0, 0x7fffffff,
                 edit_step_instructions))
    edit_step_instructions = !edit_step_instructions;

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_LABEL_PADDING,
                  &widget_rect, &inside_rect);

  GuiLabel(widget_rect, "Breakpoint PC");
  
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);

  static bool edit_bp_pc = false;
  if (GuiSpinner(widget_rect, "", &emu_state->pc_breakpoint, -1, 0x7fffffff,
                 edit_bp_pc))
    edit_bp_pc = !edit_bp_pc;


  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Debug State");
  return adv_rect;
}
Rectangle sb_draw_reg_state(Rectangle rect, const char *group_name,
                            const char **register_names, int *values) {
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  while (*register_names) {
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5,
                    &widget_rect, &inside_rect);
    GuiLabel(widget_rect, *register_names);
    int w = (inside_rect.width - GUI_PADDING * 2) / 3;
    widget_rect.x += w;
    GuiLabel(widget_rect, TextFormat("0x%X", *values));

    widget_rect.x += w + GUI_PADDING * 2;
    GuiLabel(widget_rect, TextFormat("%i", *values));

    ++register_names;
    ++values;
  }

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  return adv_rect;
}

Rectangle sb_draw_flag_state(Rectangle rect, const char *group_name,
                             const char **register_names, bool *values) {
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  while (*register_names) {
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5,
                    &widget_rect, &inside_rect);
    widget_rect.width = GUI_PADDING;
    widget_rect.height = GUI_PADDING;

    GuiCheckBox(
        widget_rect,
        TextFormat("%s (%s)", *register_names, (*values) ? "true" : "false"),
        *values);
    ++register_names;
    ++values;
  }

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  return adv_rect;
}      
/*
Rectangle gba_draw_arm_opcode(Rectangle rect, uint32_t opcode){
  uint32_t cond_code = SB_BFE(opcode,28,4);
  const char* cond_code_table[16]=
    {"EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","","INV"};
  const char * cond = cond_code_table[cond_code];
  int internal_opcode = gba_intern_op(opcode);
  const char * name = gba_disasm_name[internal_opcode];
  const char * text = TextFormat("%s %s",name,cond);
  for(int i=0;i<16;++i){
    arm7tdmi_param_t p = arm7tdmi_params[internal_opcode];
    if(p.params[i].name==0)break;
    int v = SB_BFE(opcode,p.params[i].start,p.params[i].size);
    text = TextFormat("%s %c:%d",text,p.params[i].name,v);
  }
  GuiLabel(rect, text);
}
*/
Rectangle gba_draw_instructions(Rectangle rect, gba_t *gba) {
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  int pc = gba->cpu.registers[15];
  //TODO: Disasm Thumb
  bool thumb = arm7_get_thumb_bit(&gba->cpu);
  for (int i = -6; i < 5; ++i) {
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5,
                    &widget_rect, &inside_rect);

    int pc_render = i*(thumb?2:4) + pc;

    if (pc_render < 0) {
      widget_rect.x += 80;
      GuiLabel(widget_rect, "INVALID");
    } else {
      if (i == 0)
        GuiLabel(widget_rect, "PC->");
      widget_rect.x += 30;
      GuiLabel(widget_rect, TextFormat("%09d", pc_render));
      widget_rect.x += 80;
      uint32_t opcode = thumb? gba_read16(gba, pc_render): gba_read32(gba, pc_render);
      char disasm[64];
      arm7_get_disasm(&gba->cpu,pc_render,disasm,64);
      GuiLabel(widget_rect, disasm);
      widget_rect.x += 200;
      GuiLabel(widget_rect, TextFormat(thumb? "(%04x)":"(%08x)", opcode));
      widget_rect.x += 50;
    }
  }
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Instructions");
  return adv_rect;
}
 
Rectangle sb_draw_instructions(Rectangle rect, sb_gb_cpu_t *cpu_state,
                               sb_gb_t *gb) {
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  for (int i = -6; i < 5; ++i) {
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5,
                    &widget_rect, &inside_rect);
    int pc_render = i + cpu_state->pc;

    if (pc_render < 0) {
      widget_rect.x += 80;

      GuiLabel(widget_rect, "INVALID");
    } else {
      if (i == 0)
        GuiLabel(widget_rect, "PC->");
      widget_rect.x += 30;
      GuiLabel(widget_rect, TextFormat("%06d", pc_render));
      widget_rect.x += 50;
      int opcode = sb_read8(gb, pc_render);
      GuiLabel(widget_rect, sb_decode_table[opcode].opcode_name);
      ;
      widget_rect.x += 100;
      GuiLabel(widget_rect, TextFormat("(%02x)", sb_read8(gb, pc_render)));
      widget_rect.x += 50;
    }
  }
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Instructions");
  return adv_rect;
}

Rectangle sb_draw_joypad_state(Rectangle rect, sb_joy_t *joy) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  Rectangle wr = inside_rect;
  wr.width = GUI_PADDING;
  wr.height = GUI_PADDING;

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Up",joy->up);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Down",joy->down);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Left",joy->left);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Right",joy->right);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Shoulder-L",joy->l);
   
  inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  inside_rect.x +=rect.width/2;
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.x +=rect.width/2;
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"A",joy->a);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"B",joy->b);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Start",joy->start);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Select",joy->select);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"Shoulder-R",joy->r);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
   
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Joypad State");
  return adv_rect;
}

Rectangle sb_draw_interrupt_state(Rectangle rect, sb_gb_t *gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  Rectangle wr = inside_rect;
  wr.width = GUI_PADDING;
  wr.height = GUI_PADDING;
  uint8_t e = sb_read8(gb,SB_IO_INTER_EN);
  uint8_t f = sb_read8(gb,SB_IO_INTER_F);
  bool values[]={
    SB_BFE(e,0,1), SB_BFE(e,1,1), SB_BFE(e,2,1), SB_BFE(e,3,1), SB_BFE(e,4,1),
    SB_BFE(f,0,1), SB_BFE(f,1,1), SB_BFE(f,2,1), SB_BFE(f,3,1), SB_BFE(f,4,1),
  };
  const char * names[] ={
    "VBlank En", "Stat En", "Timer En", "Serial En", "Joypad En",
    "VBlank F", "Stat F", "Timer F", "Serial F", "Joypad F",
  };

  int num_values = sizeof(values)/sizeof(bool);
  for(int i=0;i<num_values;++i){
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
    wr.y=widget_rect.y;
    GuiCheckBox(wr,names[i],values[i]);
    if(i+1==num_values/2){
      inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
      inside_rect.x +=rect.width/2;
      wr.x +=rect.width/2;
    }
  }

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Interrupt State");
  return adv_rect;
}

Rectangle sb_draw_dma_state(Rectangle rect, sb_gb_t *gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  Rectangle wr = widget_rect;
  wr.width = GUI_PADDING;
  wr.height = GUI_PADDING;

  int dma_src = sb_read8_direct(gb,SB_IO_DMA_SRC_LO)|
                  ((int)sb_read8_direct(gb,SB_IO_DMA_SRC_HI)<<8u);
  int dma_dst = sb_read8_direct(gb,SB_IO_DMA_DST_LO)|
                  ((int)sb_read8_direct(gb,SB_IO_DMA_DST_HI)<<8u);
  uint8_t dma_mode_length = sb_read8_direct(gb,SB_IO_DMA_MODE_LEN);

  int len = (SB_BFE(dma_mode_length, 0,7)+1);
  bool hdma_mode = SB_BFE(dma_mode_length, 7,1);


  int div = sb_read8_direct(gb, SB_IO_DIV);
  int tima = sb_read8_direct(gb, SB_IO_TIMA);
  int tma = sb_read8_direct(gb, SB_IO_TMA);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("DMA SRC: %x", dma_src));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("DMA DST: %x", dma_dst));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Length (16B chunks): %d", len));


  inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  inside_rect.x +=rect.width/2;
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING*0.5, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Bytes Transferred: %d", gb->dma.bytes_transferred));

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.x =widget_rect.x;
  wr.y = widget_rect.y;

  GuiCheckBox(wr,"Active",gb->dma.active);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;
  GuiCheckBox(wr,"HDMA Mode",hdma_mode);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  wr.y=widget_rect.y;

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "DMA State");
  return adv_rect;
}
Rectangle sb_draw_timer_state(Rectangle rect, sb_gb_t *gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;
  Rectangle wr = widget_rect;
  wr.width = GUI_PADDING;
  wr.height = GUI_PADDING;


  int div = sb_read8_direct(gb, SB_IO_DIV);
  int tima = sb_read8_direct(gb, SB_IO_TIMA);
  int tma = sb_read8_direct(gb, SB_IO_TMA);
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("DIV: %d", div));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("TIMA: %d", tima));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("TMA: %d", tma));


  inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  inside_rect.x +=rect.width/2;
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("CLKs to DIV: %d", gb->timers.clocks_till_div_inc));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);
  GuiLabel(widget_rect, TextFormat("CLKs to TIMA: %d", gb->timers.clocks_till_tima_inc));
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,  &inside_rect);

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Timer State");
  return adv_rect;
}
Rectangle sb_draw_cartridge_state(Rectangle rect,
                                  sb_gb_cartridge_t *cart_state) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  const char * title = "Unknown";
  int rom_size = 0; 
  const char *system = "Unknown";
  if(emu_state.system==SYSTEM_GB){
    title = cart_state->title;
    rom_size = cart_state->rom_size;
    system = "Game Boy";
    if(cart_state->game_boy_color)system = "Game Boy Color";
  }else if (emu_state.system==SYSTEM_GBA){
    title = gba.cart.title;
    rom_size = gba.cart.rom_size;
    system = "Game Boy Advanced";
  }
  inside_rect = sb_draw_label(inside_rect, TextFormat("Title: %s", title));
  inside_rect = sb_draw_label(inside_rect, TextFormat("System: %s", system));
  inside_rect = sb_draw_label(inside_rect, TextFormat("ROM Size: %d", rom_size));
  if(emu_state.system== SYSTEM_GB){
    inside_rect=sb_draw_label(inside_rect, TextFormat("Cart Type: %x", cart_state->type));
    inside_rect=sb_draw_label(inside_rect, TextFormat("Mapped ROM Bank: %d", cart_state->mapped_rom_bank));
    inside_rect=sb_draw_label(inside_rect, TextFormat("RAM Size: %d", cart_state->ram_size));
    inside_rect=sb_draw_label(inside_rect, TextFormat("Mapped RAM Bank: %d", cart_state->mapped_ram_bank));
  }
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Cartridge State (Drag and Drop .GBC to Load ROM)");
  return adv_rect;
}
Rectangle sb_draw_cpu_state(Rectangle rect, sb_gb_cpu_t *cpu_state,
                            sb_gb_t *gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  const char *register_names_16b[] = {"AF", "BC", "DE", "HL", "SP", "PC", NULL};

  int register_values_16b[] = {cpu_state->af, cpu_state->bc, cpu_state->de,
                               cpu_state->hl, cpu_state->sp, cpu_state->pc};

  const char *register_names_8b[] = {"A", "F", "B", "C", "D",
                                     "E", "H", "L", NULL};

  int register_values_8b[] = {
      SB_U16_HI(cpu_state->af), SB_U16_LO(cpu_state->af),
      SB_U16_HI(cpu_state->bc), SB_U16_LO(cpu_state->bc),
      SB_U16_HI(cpu_state->de), SB_U16_LO(cpu_state->de),
      SB_U16_HI(cpu_state->hl), SB_U16_LO(cpu_state->hl),
  };

  const char *flag_names[] = {"Z", "N", "H", "C","Inter. En.", "Prefix", "Wait Inter",  NULL};

  bool flag_values[] = {
      SB_BFE(cpu_state->af, SB_Z_BIT, 1), // Z
      SB_BFE(cpu_state->af, SB_N_BIT, 1), // N
      SB_BFE(cpu_state->af, SB_H_BIT, 1), // H
      SB_BFE(cpu_state->af, SB_C_BIT, 1), // C
      cpu_state->interrupt_enable,
      cpu_state->prefix_op,
      cpu_state->wait_for_interrupt
  };
  // Split registers into three rects horizontally
  {
    Rectangle in_rect[3];
    const char *sections[] = {"16-bit Registers", "8-bit Registers", "Flags"};
    int orig_y = inside_rect.y;
    int x_off = 0;
    for (int i = 0; i < 3; ++i) {
      in_rect[i] = inside_rect;
      in_rect[i].width = inside_rect.width / 3 - GUI_PADDING * 2 / 3;
      in_rect[i].x += x_off;
      x_off += in_rect[i].width + GUI_PADDING;
    }
    in_rect[0] = sb_draw_reg_state(in_rect[0], "16-bit Registers",
                                   register_names_16b, register_values_16b);

    in_rect[1] = sb_draw_reg_state(in_rect[1], "8-bit Registers",
                                   register_names_8b, register_values_8b);

    in_rect[2] =
        sb_draw_flag_state(in_rect[2], "Flags", flag_names, flag_values);
    for (int i = 0; i < 3; ++i) {
      if (inside_rect.y < in_rect[i].y)
        inside_rect.y = in_rect[i].y;
    }
    for (int i = 0; i < 3; ++i) {
      in_rect[i].height = inside_rect.y - orig_y - GUI_PADDING;
      in_rect[i].y = orig_y;
      GuiGroupBox(in_rect[i], sections[i]);
    }

    inside_rect.height -= inside_rect.y - orig_y;
  }

  inside_rect = sb_draw_instructions(inside_rect, cpu_state, gb);

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "CPU State");
  return adv_rect;
}
Rectangle gba_draw_arm7_state(Rectangle rect, gba_t* gba) {
  arm7_t * arm = &gba->cpu;

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);

  // Split registers into two rects horizontally
  {
    Rectangle in_rect[2];
    const char *sections[] = {"Registers", "Banked Registers"};
    int orig_y = inside_rect.y;
    int x_off = 0;
    for (int i = 0; i < 2; ++i) {
      in_rect[i] = inside_rect;
      in_rect[i].width = inside_rect.width / 2 - GUI_PADDING * 1 / 2;
      in_rect[i].x += x_off;
      x_off += in_rect[i].width + GUI_PADDING;
    }
    const char * reg_names[] = {
      "R0","R1","R2","R3",
      "R4","R5","R6","R7",
      "R8","R9","R10","R11",
      "R12","R13","R14","R15(PC)",
      "CPSR","N","Z","C","V",
      NULL
    };
    int reg_vals[21];
    for(int i=0;i<16;++i)reg_vals[i] = arm->registers[i];

    reg_vals[16]=arm->registers[16]; 
    reg_vals[17] = SB_BFE(arm->registers[16],31,1);
    reg_vals[18] = SB_BFE(arm->registers[16],30,1);
    reg_vals[19] = SB_BFE(arm->registers[16],29,1);
    reg_vals[20] = SB_BFE(arm->registers[16],28,1);
    
    const char * banked_regs[] = {
      "SPSRfiq","SPSRirq","SPSRsvc","SPSRabt","SPSRund",
      "R8fiq","R9fiq","R10fiq","R11fiq",
      "R12fiq","R13fiq","R14fiq",
      "R13irq","R14irq","R13svc","R14svc",
      "R13abt","R14abt","R13und","R14und",
      NULL
    };  
    /*
    Banked Reg Table
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
    int banked_vals[20]; 
    for(int i=0;i<5;++i) banked_vals[i]   = arm->registers[32+i];
    for(int i=0;i<7;++i) banked_vals[5+i] = arm->registers[17+i];
    for(int i=0;i<2;++i) banked_vals[12+i]= arm->registers[24+i];
    for(int i=0;i<2;++i) banked_vals[14+i]= arm->registers[26+i];
    for(int i=0;i<2;++i) banked_vals[16+i]= arm->registers[28+i];
    for(int i=0;i<2;++i) banked_vals[18+i]= arm->registers[30+i];

    in_rect[0] = sb_draw_reg_state(in_rect[0], "Registers",
                                   reg_names, reg_vals);
    in_rect[1] = sb_draw_reg_state(in_rect[1], "Banked Registers",
                                   banked_regs, banked_vals);
     
    for (int i = 0; i < 2; ++i) {
      if (inside_rect.y < in_rect[i].y)
        inside_rect.y = in_rect[i].y;
    }
    for (int i = 0; i < 2; ++i) {
      in_rect[i].height = inside_rect.y - orig_y - GUI_PADDING;
      in_rect[i].y = orig_y;
      GuiGroupBox(in_rect[i], sections[i]);
    }
    inside_rect.height -= inside_rect.y - orig_y;
  }

  inside_rect = gba_draw_instructions(inside_rect, gba);

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "ARM7 State");
  return adv_rect;
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

  uint8_t data_dir =    ((!state->joy.down)<<3)| ((!state->joy.up)<<2)    |((!state->joy.left)<<1)|((!state->joy.right));
  uint8_t data_action = ((!state->joy.start)<<3)|((!state->joy.select)<<2)|((!state->joy.b)<<1)   |(!state->joy.a);

  uint8_t data = gb->mem.data[SB_IO_JOYPAD];

  data&=0xf0;

  if(0 == (data & (1<<4))) data |= data_dir;
  if(0 == (data & (1<<5))) data |= data_action;

  gb->mem.data[SB_IO_JOYPAD] = data;

}
void sb_poll_controller_input(sb_joy_t* joy){
  joy->left  = IsKeyDown(KEY_A);
  joy->right = IsKeyDown(KEY_D);
  joy->up    = IsKeyDown(KEY_W);
  joy->down  = IsKeyDown(KEY_S);
  joy->a = IsKeyDown(KEY_J);
  joy->b = IsKeyDown(KEY_K);
  joy->start = IsKeyDown(KEY_ENTER);
  joy->select = IsKeyDown(KEY_APOSTROPHE);
  joy->l = IsKeyDown(KEY_U);
  joy->r = IsKeyDown(KEY_I);
}

bool sb_update_lcd_status(sb_gb_t* gb, int delta_cycles){
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
    if(ly==SB_LCD_H&&old_ly!=SB_LCD_H){
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      //V-BLANK Interrupt
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<0));
    }
    if(ly==SB_LCD_H&&old_ly!=SB_LCD_H&& vblank_interrupt){
      //vblank-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }
    if(ly >= SB_LCD_H) {mode = 1; new_scanline = false;}
    if(ly==153&& gb->lcd.scanline_cycles>=4){ly = 0;}
    if(ly == lyc) mode|=0x4;

    if((old_mode & 0x4)==0 && (mode&0x4)==4 && lyc_eq_ly_interrupt){
      //LCD-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }
    if((((old_mode&0x3)!=2 && (mode&0x3) == 0x2)||((old_mode&0x3)!=1 && (mode&0x3) == 0x1)) && oam_interrupt){
      //oam-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }

    if((old_mode&0x3)!=0 && (mode&0x3) == 0x0 && hblank_interrupt){
      //hblank-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }
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

Rectangle gba_draw_tile_map_state(Rectangle rect, gba_t* gba){
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  uint16_t dispcnt = gba_read16(gba, GBA_DISPCNT);

  Rectangle r =inside_rect;
  r=sb_draw_label(r, "DISPCNT");
  r=sb_draw_label(r, TextFormat("  Mode:%d  Frame:%d HBFree:%d OBJMAP:%d FBLNK:%d",
                                       SB_BFE(dispcnt,0,3),SB_BFE(dispcnt,3,1),SB_BFE(dispcnt,4,1),SB_BFE(dispcnt,5,1),
                                       SB_BFE(dispcnt,6,1),SB_BFE(dispcnt,7,1)));

  r=sb_draw_label(r, TextFormat("  Bg0En:%d Bg1En:%d Bg2En:%d  Bg3En:%d  ObjEn:%d W0En:%d W1En:%d ObjWinEn:%d",
                                       SB_BFE(dispcnt,8,1),SB_BFE(dispcnt,9,1),SB_BFE(dispcnt,10,1),
                                       SB_BFE(dispcnt,11,1),SB_BFE(dispcnt,12,1),SB_BFE(dispcnt,13,1),SB_BFE(dispcnt,14,1),SB_BFE(dispcnt,15,1))); 
  

  for(int b=0;b<4;++b){
    r=sb_draw_label(r,TextFormat("BG%dCNT",b));
    uint16_t bgcnt = gba_read16(gba, GBA_BG0CNT+2*b);
  
    r=sb_draw_label(r, TextFormat("  Priority:%d  CharBase:%d Mosaic:%d Colors:%d ScreenBase:%d",
                                       SB_BFE(bgcnt,0,2),SB_BFE(bgcnt,2,4),SB_BFE(bgcnt,6,1),SB_BFE(bgcnt,7,1),
                                       SB_BFE(bgcnt,8,5)));
   
    r=sb_draw_label(r, TextFormat("  OverflowMode:%d  ScreenSize:%d",
                                       SB_BFE(bgcnt,13,1),SB_BFE(bgcnt,14,2)));

    uint16_t x_off = gba_read16(gba,GBA_BG0HOFS+4*b);
    uint16_t y_off = gba_read16(gba,GBA_BG0VOFS+4*b);

    r=sb_draw_label(r, TextFormat("BG%dHOFS:%d  BG%dVOFS:%d",b,SB_BFE(x_off,0,9),b,SB_BFE(y_off,0,9)));
                                        
  }

  inside_rect = r; 
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "LCD State"); 
  return adv_rect;
}
Rectangle sb_draw_tile_map_state(Rectangle rect, sb_gb_t *gb) {
  if(emu_state.system == SYSTEM_GBA) return gba_draw_tile_map_state(rect, &gba); 
  static uint8_t tmp_image[512*512*3];
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  int bg_tile_map_base      = SB_BFE(ctrl,3,1)==1 ? 0x9c00 : 0x9800;
  int bg_win_tile_data_mode = SB_BFE(ctrl,4,1)==1;
  int win_tile_map_base      = SB_BFE(ctrl,6,1)==1 ? 0x9c00 : 0x9800;

  // Draw Tilemaps
  for(int tile_map = 0;tile_map<2;++tile_map){
    Vector2 mouse_pos = GetMousePosition();
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, 0, &widget_rect,  &inside_rect);

    int image_height = 32*(8+2);
    int image_width =  32*(8+2);
    sb_vertical_adv(inside_rect, image_height+GUI_PADDING*2, GUI_PADDING, &widget_rect,  &inside_rect);
    Rectangle wr = widget_rect;
    int wx = sb_read8_direct(gb, SB_IO_LCD_WX)-7;
    int wy = sb_read8_direct(gb, SB_IO_LCD_WY);
    int sx = sb_read8_direct(gb, SB_IO_LCD_SX);
    int sy = sb_read8_direct(gb, SB_IO_LCD_SY);

    int box_x1 = tile_map ==0 ? sx : wx;
    int box_x2 = box_x1+(SB_LCD_W-1);
    int box_y1 = tile_map ==0 ? sy : wy;
    int box_y2 = box_y1+(SB_LCD_H-1);
    int tile_map_base = tile_map==0? bg_tile_map_base:win_tile_map_base;
    int scanline = tile_map==0 ? gb->lcd.curr_scanline +sy : gb->lcd.curr_window_scanline;
    for(int yt = 0; yt<32;++yt)
      for(int xt = 0; xt<32;++xt)
        for(int py = 0;py<8;++py)
          for(int px = 0;px<8;++px){
            int x = xt*8+px;
            int y = yt*8+py;
            int color_id = sb_lookup_tile(gb,x,y,tile_map_base,bg_win_tile_data_mode);
            int p = (xt*10+(px)+1)+(yt*10+py+1)*image_width;
            int r=0,g=0,b=0;
            sb_lookup_palette_color(gb,color_id,&r,&g,&b);
            if(((x==(box_x1%256)||x==(box_x2%256)) && (((y-box_y1)&0xff)>=0 && ((box_y2-y)&0xff) <=box_y2-box_y1))||
               ((y==(box_y1%256)||y==(box_y2%256)) && (((x-box_x1)&0xff)>=0 && ((box_x2-x)&0xff) <=box_x2-box_x1))){
               r=255; g=b=0;
            }
            if(y == (scanline&0xff) &&(((x-box_x1)&0xff)>=0 && (((x-box_x1)&0xff)>=0 && ((box_x2-x)&0xff) <=box_x2-box_x1))){
              b = 255;  r=g=0;
            }
            tmp_image[p*3+0]=r;
            tmp_image[p*3+1]=g;
            tmp_image[p*3+2]=b;
          }
    Image screenIm = {
          .data = tmp_image,
          .width = image_width,
          .height = image_height,
          .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
          .mipmaps = 1
    };

    Texture2D screenTex = LoadTextureFromImage(screenIm);
    SetTextureFilter(screenTex, TEXTURE_FILTER_POINT);
    Rectangle im_rect;
    im_rect.x = widget_rect.x+(widget_rect.width-image_width)/2;
    im_rect.y = widget_rect.y+GUI_PADDING;
    im_rect.width = image_width;
    im_rect.height = image_height;

    DrawTextureQuad(screenTex, (Vector2){1.f,1.f}, (Vector2){0.0f,0.0},im_rect, (Color){255,255,255,255});

    const char * name = tile_map == 0  ? "Background" : "Window";
    mouse_pos.x-=im_rect.x;
    mouse_pos.y-=im_rect.y;
    if(mouse_pos.x<im_rect.width && mouse_pos.y <im_rect.height &&
      mouse_pos.x>=0 && mouse_pos.y>=0){
      int tx = (mouse_pos.x -1)/10;
      int ty = (mouse_pos.y -1)/10;
      int t = tx+ty*32;
      int tile_data0 = sb_read_vram(gb, tile_map_base+t,0);
      int tile_data1 = sb_read_vram(gb, tile_map_base+t,1);
      GuiGroupBox(widget_rect, TextFormat("%s Tile Map (Tile (%d, %d) Index=0x%02x Attr=0x%02x)",name,tx,ty,tile_data0,tile_data1));
    }else GuiGroupBox(widget_rect, TextFormat("%s Tile Map",name));
    // Flush Raylib batch so that texture can be deleted. 
    rlDrawRenderBatchActive();
    UnloadTexture(screenTex);
  }

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "PPU State");
  return adv_rect;
}
Rectangle sb_draw_tile_data_state(Rectangle rect, sb_gb_t *gb) {
  static uint8_t tmp_image[512*512*3];
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  int bg_tile_map_base      = SB_BFE(ctrl,3,1)==1 ? 0x9c00 : 0x9800;
  int bg_win_tile_data_mode = SB_BFE(ctrl,4,1)==1;
  int win_tile_map_base      = SB_BFE(ctrl,6,1)==1 ? 0x9c00 : 0x9800;

  // Draw tile data arrays
  for(int tile_data_bank = 0;tile_data_bank<SB_VRAM_NUM_BANKS;++tile_data_bank){
    Vector2 mouse_pos = GetMousePosition();
    sb_vertical_adv(inside_rect, 0, GUI_PADDING, &widget_rect,  &inside_rect);

    int scale = 1;
    int image_height = 384/32*(8+2)*scale;
    int image_width =  32*(8+2)*scale;
    sb_vertical_adv(inside_rect, image_height+GUI_PADDING*2, GUI_PADDING, &widget_rect,  &inside_rect);
    Rectangle wr = widget_rect;

    int tile_data_base = 0x8000;
    for(int t=0;t<384;++t){
      int xt = (t%32)*10;
      int yt = (t/32)*10;

      for(int py = 0;py<8;++py)
        for(int px = 0;px<8;++px){
          int d = tile_data_base+py*2+ t*16;
          uint8_t data1 = sb_read_vram(gb,d,tile_data_bank);
          uint8_t data2 = sb_read_vram(gb,d+1,tile_data_bank);
          uint8_t value = SB_BFE(data1,px,1)+SB_BFE(data2,px,1)*2;
          uint8_t color = value*80;
          int p = (xt+(7-px)+1)+(yt+py+1)*image_width;
          tmp_image[p*3+0]=color;
          tmp_image[p*3+1]=color;
          tmp_image[p*3+2]=color;
        }
    }
    Image screenIm = {
          .data = tmp_image,
          .width = image_width,
          .height = image_height,
          .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
          .mipmaps = 1
    };

    Texture2D screenTex = LoadTextureFromImage(screenIm);
    SetTextureFilter(screenTex, TEXTURE_FILTER_POINT);
    Rectangle im_rect;
    im_rect.x = widget_rect.x+(widget_rect.width-image_width)/2;
    im_rect.y = widget_rect.y+GUI_PADDING;
    im_rect.width = image_width;
    im_rect.height = image_height;

    DrawTextureQuad(screenTex, (Vector2){1.f,1.f}, (Vector2){0.0f,0.0},im_rect, (Color){255,255,255,255});
    // Flush Raylib batch so that texture can be deleted. 
    rlDrawRenderBatchActive();
    UnloadTexture(screenTex); 
    
    mouse_pos.x-=im_rect.x;
    mouse_pos.y-=im_rect.y;
    if(mouse_pos.x<im_rect.width && mouse_pos.y <im_rect.height &&
      mouse_pos.x>=0 && mouse_pos.y>=0){
      int tx = (mouse_pos.x -1)/10;
      int ty = (mouse_pos.y -1)/10;
      int t = tx+ty*32;
      GuiGroupBox(widget_rect, TextFormat("Tile Data[%d] (TileID = 0x%02x)",tile_data_bank,t&0xff));
    }else GuiGroupBox(widget_rect, TextFormat("Tile Data[%d]",tile_data_bank));
  }
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "PPU State");
  return adv_rect;
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
  if(gb->model==SB_GBC){
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

    const uint32_t palette_dmg_green[4*3] = { 0x81,0x8F,0x38,0x64,0x7D,0x43,0x56,0x6D,0x3F,0x31,0x4A,0x2D };

    *r = palette_dmg_green[color_id*3+0];
    *g = palette_dmg_green[color_id*3+1];
    *b = palette_dmg_green[color_id*3+2];
  }else if(gb->model == SB_GBC){

    int palette = SB_BFE(color_id,2,6);
    int entry= palette*8+(color_id&0x3)*2;
    uint16_t color = gb->lcd.color_palettes[entry+0];
    color |= ((int)gb->lcd.color_palettes[entry+1])<<8;

    int tr = SB_BFE(color,0,5);
    int tg = SB_BFE(color,5,5);
    int tb = SB_BFE(color,10,5);

    // Color correction algorithm from Near's article

    // https://near.sh/articles/video/color-emulation
    int R = (tr * 26 + tg *  4 + tb *  2);
    int G = (         tg * 24 + tb *  8);
    int B = (tr *  6 + tg *  4 + tb * 22);
    if(R>960)R=960;
    if(G>960)G=960;
    if(B>960)B=960;
    *r = R >> 2;
    *g = G >> 2;
    *b = B >> 2;
  }
}
void sb_draw_scanline(sb_gb_t*gb){
  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  bool draw_bg_win     = SB_BFE(ctrl,0,1)==1;
  bool master_priority = true;
  if(gb->model == SB_GBC){
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
  const int sprites_per_scanline = 10;
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
        int prior = gb->model==SB_GBC?0 : xc;

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
        if(gb->model==SB_GBC){
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
      //r = SB_BFE(tile_id,0,3)*31;
      //g = SB_BFE(tile_id,3,3)*31;
      //b = SB_BFE(tile_id,6,2)*63;

    }
    sb_lookup_palette_color(gb,color_id,&r,&g,&b);
    gb->lcd.framebuffer[(x+(y)*SB_LCD_W)*3+0] = r;
    gb->lcd.framebuffer[(x+(y)*SB_LCD_W)*3+1] = g;
    gb->lcd.framebuffer[(x+(y)*SB_LCD_W)*3+2] = b;
  }
  if(rendered_part_of_window)gb->lcd.curr_window_scanline+=1;
}
bool sb_update_lcd(sb_gb_t* gb, int delta_cycles){
  bool new_scanline = sb_update_lcd_status(gb, delta_cycles);
  if(new_scanline){
    sb_draw_scanline(gb);
    uint8_t y = sb_read8_direct(gb, SB_IO_LCD_LY);
    if(y+1==SB_LCD_H)return true;
  }
  return false;
}
void sb_update_timers(sb_gb_t* gb, int delta_clocks){
  uint8_t tac = sb_read8_direct(gb, SB_IO_TAC);
  bool tima_enable = SB_BFE(tac, 2, 1);
  int clk_sel = SB_BFE(tac, 0, 2);
  gb->timers.clocks_till_div_inc -=delta_clocks;
  int period = 4*1024*1024/16384;
  while(gb->timers.clocks_till_div_inc<=0){
    gb->timers.clocks_till_div_inc += period;

    uint8_t d = sb_read8_direct(gb, SB_IO_DIV);
    sb_store8_direct(gb, SB_IO_DIV, d+1);
  }
  if(tima_enable)gb->timers.clocks_till_tima_inc -=delta_clocks;
  period =0;
  switch(clk_sel){
    case 0: period = 1024; break;
    case 1: period = 16; break;
    case 2: period = 64; break;
    case 3: period = 256; break;
  }
  while(gb->timers.clocks_till_tima_inc<=0){
    gb->timers.clocks_till_tima_inc += period;

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
    bool hdma_mode = SB_BFE(dma_mode_length, 7,1);
    if(!hdma_mode||(gb->dma.in_hblank==false&&gb->lcd.in_hblank==true&&gb->lcd.curr_scanline<SB_LCD_H-1))
    {
      while(len>=0){
        for(int i=0;i<16;++i){
          int off = gb->dma.bytes_transferred++;
          if(off+dma_src>0xffff){len=0;break;}
          uint8_t data = sb_read8(gb,off+dma_src);
          sb_store8(gb,off+dma_dst,data);
          bytes_transferred+=1;
          
        }
        len--;           
        if(hdma_mode)break;
      }

      uint8_t new_mode = (len&0x7f);
      if(hdma_mode)new_mode|=0x80;
      if(len<0){
        gb->dma.active = false;
        len = 0;
        hdma_mode = 0;
        new_mode = 0xff;
      }
      sb_store8_direct(gb,SB_IO_DMA_MODE_LEN,new_mode);
      gb->dma.in_hblank = gb->lcd.in_hblank;
    }else{ gb->dma.in_hblank = false;}
    delta_cycles+= bytes_transferred/2+1;
  }
  return delta_cycles;
}
void sb_update_oam_dma(sb_gb_t* gb, int delta_cycles){
 if(gb->dma.oam_dma_active){
    uint16_t dma_src = ((int)sb_read8_direct(gb,SB_IO_OAM_DMA))<<8u;
    uint16_t dma_dst = 0xfe00;

    while(delta_cycles--&&gb->dma.oam_bytes_transferred<0xA0){
      uint8_t data = sb_read8_direct(gb,dma_src+gb->dma.oam_bytes_transferred);
      sb_store8_direct(gb,dma_dst+gb->dma.oam_bytes_transferred,data);
      gb->dma.oam_bytes_transferred++;
    }
    if(gb->dma.oam_bytes_transferred==0xA0)gb->dma.oam_dma_active=false;
  }

}
double sb_gb_fps_counter(int tick){
  static int call = -1;
  static double last_t = 0;
  static double fps = 60; 
  if(call==-1){
    call = 0;
    last_t = GetTime();
  }
  call+=tick;
  
  if(call>=5){
    call=0;
    double t = GetTime();
    fps = 5./(t-last_t);
    last_t = t;
  }
  return fps; 
}
void sb_tick(){
  static FILE* file = NULL;
  static bool init_audio = false;
  
  if (emu_state.run_mode == SB_MODE_RESET) {
   if(init_audio==false&&emu_state.rom_loaded){
    printf("Initializing Audio\n");
    InitAudioDevice();
    SetAudioStreamBufferSizeDefault(SB_AUDIO_BUFF_SAMPLES);
    audio_stream = LoadAudioStream(SB_AUDIO_SAMPLE_RATE, 16, SB_AUDIO_BUFF_CHANNELS);
    PlayAudioStream(audio_stream);
    init_audio=true;
  }
    if(file)fclose(file);
    file = fopen("instr_trace.txt","wb");

    memset(&gb_state.cpu, 0, sizeof(gb_state.cpu));
    memset(&gb_state.dma, 0, sizeof(gb_state.dma));
    memset(&gb_state.timers, 0, sizeof(gb_state.timers));
    memset(&gb_state.lcd, 0, sizeof(gb_state.lcd));
    memset(&gb_state.mem.wram, 0, sizeof(gb_state.mem.wram));
    //Zero out memory
    for(int i=0x8000;i<=0xffff;++i)gb_state.mem.data[i]=0;
    gb_state.cpu.pc = 0x100;

    gb_state.cpu.af=0x01B0;
    gb_state.model = SB_GB;
    if(gb_state.cart.game_boy_color){
      gb_state.model = SB_GBC;
    }
    if(gb_state.model == SB_GBC){
      gb_state.cpu.af|=0x11<<8;
    }
    gb_state.cpu.bc=0x0013;
    gb_state.cpu.de=0x00D8;
    gb_state.cpu.hl=0x014D;
    gb_state.cpu.sp=0xFFFE;

    gb_state.mem.data[0xFF05] = 0x00; // TIMA
    gb_state.mem.data[0xFF06] = 0x00; // TMA
    gb_state.mem.data[0xFF07] = 0x00; // TAC
    /*
    gb_state.mem.data[0xFF10] = 0x80; // NR10
    gb_state.mem.data[0xFF11] = 0xBF; // NR11
    gb_state.mem.data[0xFF12] = 0xF3; // NR12
    gb_state.mem.data[0xFF14] = 0xBF; // NR14
    gb_state.mem.data[0xFF16] = 0x3F; // NR21
    gb_state.mem.data[0xFF17] = 0x00; // NR22
    gb_state.mem.data[0xFF19] = 0xBF; // NR24
    */
    gb_state.mem.data[0xFF1A] = 0x7F; // NR30
    gb_state.mem.data[0xFF1B] = 0xFF; // NR31
    gb_state.mem.data[0xFF1C] = 0x9F; // NR32
    gb_state.mem.data[0xFF1E] = 0xBF; // NR34
    /*
    gb_state.mem.data[0xFF20] = 0xFF; // NR41
    gb_state.mem.data[0xFF21] = 0x00; // NR42
    gb_state.mem.data[0xFF22] = 0x00; // NR43
    gb_state.mem.data[0xFF23] = 0xBF; // NR44
    gb_state.mem.data[0xFF24] = 0x77; // NR50
    */
    gb_state.mem.data[0xFF25] = 0xF3; // NR51
    gb_state.mem.data[0xFF26] = 0xF1; // $F0-SGB ; NR52
    gb_state.mem.data[0xFF40] = 0x91; // LCDC
    gb_state.mem.data[0xFF42] = 0x00; // SCY
    gb_state.mem.data[0xFF43] = 0x00; // SCX
    gb_state.mem.data[0xFF44] = 0x90; // SCX
    gb_state.mem.data[0xFF45] = 0x00; // LYC
    gb_state.mem.data[0xFF47] = 0xFC; // BGP
    gb_state.mem.data[0xFF48] = 0xFF; // OBP0
    gb_state.mem.data[0xFF49] = 0xFF; // OBP1
    gb_state.mem.data[0xFF4A] = 0x00; // WY
    gb_state.mem.data[0xFF4B] = 0x00; // WX
    gb_state.mem.data[0xFFFF] = 0x00; // IE

    gb_state.timers.clocks_till_div_inc=0;
    gb_state.timers.clocks_till_tima_inc=0;
    gb_state.cart.mapped_rom_bank=1;

    for(int i=0;i<SB_LCD_W*SB_LCD_H*3;++i){
      gb_state.lcd.framebuffer[i] = 127;
    }
    emu_state.run_mode = SB_MODE_RUN;
  }

  if (emu_state.rom_loaded&&(emu_state.run_mode == SB_MODE_RUN||emu_state.run_mode ==SB_MODE_STEP)) {
    
    int instructions_to_execute = emu_state.step_instructions;
    if(instructions_to_execute==0)instructions_to_execute=600000;
    int frames_to_draw = 1;
    float frame_time = 1./sb_gb_fps_counter(0);
    static float avg_frame_time = 1.0/60.*1.00;
    avg_frame_time = frame_time*0.1+avg_frame_time*0.9;
    int size = sb_ring_buffer_size(&gb_state.audio.ring_buff);
    int samples_per_buffer = SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS;
    float buffs_available = size/(float)(samples_per_buffer);
    float time_correction_scale = (1.0+10.0)/(10.+buffs_available);
    time_correction_scale = avg_frame_time/(1.0/60.)*0.995;
    if(buffs_available<0.5)time_correction_scale*=1.005;
    if(buffs_available>3)time_correction_scale*=0.98;

    //int target_buffs = 3;
    //time_correction_scale*= (target_buffs+30)/(30+buffs_available);
    for(int i=0;i<instructions_to_execute;++i){

        bool double_speed = false;
        sb_update_joypad_io_reg(&emu_state, &gb_state);
        int dma_delta_cycles = sb_update_dma(&gb_state);
        int cpu_delta_cycles = 0;
        if(dma_delta_cycles==0){
          cpu_delta_cycles=4;
          int pc = gb_state.cpu.pc;


          unsigned op = sb_read8(&gb_state,gb_state.cpu.pc);

          bool request_speed_switch= false;
          if(gb_state.model == SB_GBC){
            unsigned speed = sb_read8(&gb_state,SB_IO_GBC_SPEED_SWITCH);
            double_speed = SB_BFE(speed, 7, 1);
            request_speed_switch = SB_BFE(speed, 0, 1);
          }
          //if(gb_state.cpu.pc == 0xC65F)gb_state.cpu.trigger_breakpoint =true;
          /*
          if(gb_state.cpu.prefix_op==false)
          fprintf(file,"A: %02X F: %02X B: %02X C: %02X D: %02X E: %02X H: %02X L: %02X SP: %04X PC: 00:%04X (%02X %02X %02X %02X)\n",
            SB_U16_HI(gb_state.cpu.af),SB_U16_LO(gb_state.cpu.af),
            SB_U16_HI(gb_state.cpu.bc),SB_U16_LO(gb_state.cpu.bc),
            SB_U16_HI(gb_state.cpu.de),SB_U16_LO(gb_state.cpu.de),
            SB_U16_HI(gb_state.cpu.hl),SB_U16_LO(gb_state.cpu.hl),
            gb_state.cpu.sp,pc,
            sb_read8(&gb_state,pc),
            sb_read8(&gb_state,pc+1),
            sb_read8(&gb_state,pc+2),
            sb_read8(&gb_state,pc+3)
            );
          */
          if(gb_state.cpu.prefix_op)op+=256;
     
          int trigger_interrupt = -1;
          // TODO: Can interrupts trigger between prefix ops and the second byte?
          if(gb_state.cpu.prefix_op==false){
            uint8_t ie = sb_read8_direct(&gb_state,SB_IO_INTER_EN);
            uint8_t i_flag = gb_state.cpu.last_inter_f;
            uint8_t masked_interupt = ie&i_flag&0x1f;
            for(int i=0;i<5;++i){
              if(masked_interupt & (1<<i)){trigger_interrupt = i;break;}
            }
            //if(trigger_interrupt!=-1&&(gb_state.cpu.wait_for_interrupt==false && gb_state.cpu.interrupt_enable))i_flag &= ~(1<<trigger_interrupt);
            //if(trigger_interrupt!=-1)gb_state.cpu.trigger_breakpoint = true;
            //sb_store8_direct(&gb_state,SB_IO_INTER_F,i_flag);
          }
     
          gb_state.cpu.prefix_op = false;
          cpu_delta_cycles = 4;
          bool call_interrupt = false;
          if(trigger_interrupt!=-1&&request_speed_switch==false){
            if(gb_state.cpu.interrupt_enable){
              gb_state.cpu.interrupt_enable = false;
              gb_state.cpu.deferred_interrupt_enable = false;
              int interrupt_address = (trigger_interrupt*0x8)+0x40;
              sb_call_impl(&gb_state, interrupt_address, 0, 0, 0, (const uint8_t*)"----");
              cpu_delta_cycles = 5*4;
              call_interrupt=true;
            }
            if(call_interrupt){
              uint8_t i_flag = sb_read8_direct(&gb_state,SB_IO_INTER_F);
              i_flag &= ~(1<<trigger_interrupt);
              sb_store8_direct(&gb_state,SB_IO_INTER_F,i_flag);
            }
            gb_state.cpu.wait_for_interrupt = false;

          }

          if(gb_state.cpu.deferred_interrupt_enable){
            gb_state.cpu.deferred_interrupt_enable = false;
            gb_state.cpu.interrupt_enable = true;
          }
     
          if(call_interrupt==false&&gb_state.cpu.wait_for_interrupt==false){
            sb_instr_t inst = sb_decode_table[op];
            gb_state.cpu.pc+=inst.length;
            int operand1 = sb_load_operand(&gb_state,inst.op_src1);
            int operand2 = sb_load_operand(&gb_state,inst.op_src2);

            unsigned pc_before_inst = gb_state.cpu.pc;
            inst.impl(&gb_state, operand1, operand2,inst.op_src1,inst.op_src2, inst.flag_mask);
            if(gb_state.cpu.prefix_op==true)i--;

            unsigned next_op = sb_read8(&gb_state,gb_state.cpu.pc);
            if(gb_state.cpu.prefix_op)next_op+=256;
            sb_instr_t next_inst = sb_decode_table[next_op];
            cpu_delta_cycles = 4*(gb_state.cpu.pc==pc_before_inst? next_inst.mcycles : next_inst.mcycles+inst.mcycles_branch_taken-inst.mcycles);
          }else if(call_interrupt==false&&gb_state.cpu.wait_for_interrupt==true && request_speed_switch){
            gb_state.cpu.wait_for_interrupt = false;
            sb_store8(&gb_state,SB_IO_GBC_SPEED_SWITCH,double_speed? 0x00: 0x80);
          }
          gb_state.cpu.last_inter_f = sb_read8_direct(&gb_state,SB_IO_INTER_F);
        }
        sb_update_oam_dma(&gb_state,cpu_delta_cycles);
        int delta_cycles_after_speed = double_speed ? cpu_delta_cycles/2 : cpu_delta_cycles;
        delta_cycles_after_speed+= dma_delta_cycles;
        bool vblank = sb_update_lcd(&gb_state,delta_cycles_after_speed);
        sb_update_timers(&gb_state,cpu_delta_cycles+dma_delta_cycles*2);

        double delta_t = ((double)delta_cycles_after_speed)/(4*1024*1024);
        delta_t*=time_correction_scale;
        //sb_push_save_state(&gb_state);

        if (gb_state.cpu.pc == emu_state.pc_breakpoint||gb_state.cpu.trigger_breakpoint){
          gb_state.cpu.trigger_breakpoint = false;
          emu_state.run_mode = SB_MODE_PAUSE;
          break;
        }
        if(vblank){--frames_to_draw;sb_gb_fps_counter(1);}
        
        sb_process_audio(&gb_state,delta_t);
        int size = sb_ring_buffer_size(&gb_state.audio.ring_buff);
        
       //if(size> SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS*3)break;
       if(frames_to_draw<=0&& emu_state.step_instructions ==0 )break;
    }

  }

  if (emu_state.run_mode == SB_MODE_STEP) {
    emu_state.run_mode = SB_MODE_PAUSE;
  }
}
Rectangle sb_draw_audio_state(Rectangle rect, sb_gb_t*gb){
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;


  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);

  float fifo_size = sb_ring_buffer_size(&gb->audio.ring_buff);
  GuiLabel(widget_rect, TextFormat("FIFO Size: %4f (%4f)", fifo_size,fifo_size/SB_AUDIO_RING_BUFFER_SIZE));


  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", fifo_size/SB_AUDIO_RING_BUFFER_SIZE, 0, 1);
  for(int i=0;i<4;++i){
    sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);
    GuiLabel(widget_rect, TextFormat("Channel %d",i+1));
    sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
    GuiProgressBar(widget_rect, "", "", gb->audio.channel_output[i], 0, 1);
  } 
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);
  GuiLabel(widget_rect, "Mix Volume (R)");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", gb->audio.mix_r_volume, 0, 1);
   
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);
  GuiLabel(widget_rect, "Mix Volume (L)");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", gb->audio.mix_l_volume, 0, 1);
  
   
  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);
  GuiLabel(widget_rect, "Output Waveform");
   
  sb_vertical_adv(inside_rect, 128, GUI_PADDING, &widget_rect, &inside_rect);
  
  Color outline_color = GetColor(GuiGetStyle(DEFAULT,BORDER_COLOR_NORMAL));
  Color line_color = GetColor(GuiGetStyle(DEFAULT,BORDER_COLOR_FOCUSED));
  DrawRectangleLines(widget_rect.x,widget_rect.y,widget_rect.width,widget_rect.height,outline_color);
  int old_v = 0;
  static Vector2 points[512];
  for(int i=0;i<widget_rect.width;++i){
    int entry = (gb->audio.ring_buff.read_ptr+i)%SB_AUDIO_RING_BUFFER_SIZE;
    int value = gb->audio.ring_buff.data[entry]/256/2;
    points[i]= (Vector2){widget_rect.x+i,widget_rect.y+64+value};
    old_v=value;
  }
  DrawLineStrip(points,widget_rect.width,line_color);
     

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);


  GuiGroupBox(state_rect, "Audio State");
  return adv_rect;
}
void sb_draw_sidebar(Rectangle rect) {
  Rectangle rect_inside = sb_inside_rect_after_padding(rect, GUI_PADDING);

  rect_inside = sb_draw_emu_state(rect_inside, &emu_state,&gb_state,false);
  
  static Vector2 scroll = {0}; 
  static Rectangle last_rect={0};
  last_rect.x=last_rect.y=0;
  if(last_rect.height < rect_inside.height){
    last_rect.width = rect_inside.width-5;
  }else last_rect.width=rect_inside.width- GuiGetStyle(LISTVIEW, SCROLLBAR_WIDTH)-5;
// BeginScissor is broken on non-web platforms... TODO: File bug report            
#ifdef PLATFORM_WEB
  Rectangle view = GuiScrollPanel(rect_inside, last_rect, &scroll);
  Vector2 view_scale = GetWindowScaleDPI();
  BeginScissorMode(view.x*view_scale.x, view.y*view_scale.y,view.width*view_scale.x, view.height*view_scale.y);
  rect_inside.y+=scroll.y;
  int starty = rect_inside.y;
  rect_inside.y+=GUI_PADDING; 
  rect_inside.x+=GUI_PADDING;
  rect_inside.width = view.width-GUI_PADDING*1.5;
#endif
  if(emu_state.panel_mode==SB_PANEL_TILEMAPS){
    rect_inside = sb_draw_tile_map_state(rect_inside, &gb_state);
  }else if(emu_state.panel_mode==SB_PANEL_TILEDATA) rect_inside = sb_draw_tile_data_state(rect_inside, &gb_state);
  else if(emu_state.panel_mode==SB_PANEL_CPU){
    rect_inside = sb_draw_debug_state(rect_inside, &emu_state,&gb_state);
    rect_inside = sb_draw_cartridge_state(rect_inside, &gb_state.cart);
    if(emu_state.system==SYSTEM_GB){
      rect_inside = sb_draw_interrupt_state(rect_inside, &gb_state);
      rect_inside = sb_draw_timer_state(rect_inside, &gb_state);
      rect_inside = sb_draw_dma_state(rect_inside, &gb_state);
      rect_inside = sb_draw_cpu_state(rect_inside, &gb_state.cpu, &gb_state);
    }else if (emu_state.system == SYSTEM_GBA){
      rect_inside = gba_draw_arm7_state(rect_inside, &gba);
    }
    rect_inside = sb_draw_joypad_state(rect_inside, &emu_state.joy);
  }else if(emu_state.panel_mode==SB_PANEL_AUDIO){
    rect_inside = sb_draw_audio_state(rect_inside, &gb_state);
  }
#ifdef PLATFORM_WEB
  last_rect.width = view.width-GUI_PADDING;
  last_rect.height = rect_inside.y-starty;
  EndScissorMode();
#endif
}
void sb_draw_top_panel(Rectangle rect) {
  GuiPanel(rect);
  sb_draw_emu_state(rect, &emu_state,&gb_state, true);
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
void sb_process_audio(sb_gb_t *gb, double delta_time){
  //TODO: Move these into a struct
  static float chan1_t = 0, length_t1=0;
  static float chan2_t = 0, length_t2=0;
  static float chan3_t = 0, length_t3=0;
  static float chan4_t = 0, length_t4=0;
  static float last_noise_value = 0;

  static double current_sim_time = 0;
  static double current_sample_generated_time = 0;

  if(delta_time>1.0/60.)delta_time = 1.0/60.;
  current_sim_time +=delta_time;
  while(current_sim_time>1.0){
      current_sample_generated_time-=1.0;
      current_sim_time-=1.0;
  } 
  static float capacitor_r = 0.0;
  static float capacitor_l = 0.0;

  const static float duty_lookup[]={0.125,0.25,0.5,0.75};

  float sample_delta_t = 1.0/SB_AUDIO_SAMPLE_RATE;
  uint8_t freq_sweep1 = sb_read8_direct(gb, SB_IO_AUD1_TONE_SWEEP);
  float freq_sweep_time_mul1 = SB_BFE(freq_sweep1, 4, 3)/128.;
  float freq_sweep_sign1 = SB_BFE(freq_sweep1, 3,1)? -1. : 1;
  //float freq_sweep_n1 = 131072./(2048-SB_BFE(freq_sweep1, 0,3));
  float freq_sweep_n1 = SB_BFE(freq_sweep1, 0,3);
  if(SB_BFE(freq_sweep1,0,3)==0){freq_sweep_sign1=0;freq_sweep_time_mul1=0;}
  //if(freq_sweep_time_mul1==0)freq_sweep_time_mul1=1.0e6;
  uint8_t length_duty1 = sb_read8_direct(gb, SB_IO_AUD1_LENGTH_DUTY);
  uint8_t freq1_lo = sb_read8_direct(gb,SB_IO_AUD1_FREQ);
  uint8_t freq1_hi = sb_read8_direct(gb,SB_IO_AUD1_FREQ_HI);
  uint8_t vol_env1 = sb_read8_direct(gb,SB_IO_AUD1_VOL_ENV);
  uint16_t freq1 = freq1_lo | ((int)(SB_BFE(freq1_hi,0,3))<<8u);
  float freq1_hz = 131072.0/(2048.-freq1);
  float volume1 = SB_BFE(vol_env1,4,4)/15.f;
  float volume_env1 = compute_vol_env_slope(vol_env1);
  float duty1 = duty_lookup[SB_BFE(length_duty1,6,2)];
  float length1 = (64.-SB_BFE(length_duty1,0,6))/256.;
  if(SB_BFE(freq1_hi,7,1)){chan1_t=0.f;length_t1 = 0;}
  if(SB_BFE(freq1_hi,6,1)==0){length1 = 1.0e9;}
  freq1_hi &=0x7f;
  sb_store8_direct(gb, SB_IO_AUD1_FREQ_HI,freq1_hi);

  uint8_t length_duty2 = sb_read8_direct(gb, SB_IO_AUD2_LENGTH_DUTY);
  uint8_t freq2_lo = sb_read8_direct(gb,SB_IO_AUD2_FREQ);
  uint8_t freq2_hi = sb_read8_direct(gb,SB_IO_AUD2_FREQ_HI);
  uint8_t vol_env2 = sb_read8_direct(gb,SB_IO_AUD2_VOL_ENV);
  uint16_t freq2 = freq2_lo | ((int)(SB_BFE(freq2_hi,0,3))<<8u);
  float freq2_hz = 131072.0/(2048.-freq2);
  float volume2 = SB_BFE(vol_env2,4,4)/15.f;
  float volume_env2 = compute_vol_env_slope(vol_env2);
  float duty2 = duty_lookup[SB_BFE(length_duty2,6,2)];
  float length2 = (64.-SB_BFE(length_duty2,0,6))/256.;

  if(SB_BFE(freq2_hi,7,1)){chan2_t=0.f; length_t2=0;}
  if(SB_BFE(freq2_hi,6,1)==0){length2 = 1.0e9;}
  freq2_hi &=0x7f;
  sb_store8_direct(gb, SB_IO_AUD2_FREQ_HI,freq2_hi);

  uint8_t power3 = sb_read8_direct(gb,SB_IO_AUD3_POWER);
  uint8_t length3_dat = sb_read8_direct(gb,SB_IO_AUD3_LENGTH);
  uint8_t freq3_lo = sb_read8_direct(gb,SB_IO_AUD3_FREQ);
  uint8_t freq3_hi = sb_read8_direct(gb,SB_IO_AUD3_FREQ_HI);
  uint8_t vol_env3 = sb_read8_direct(gb,SB_IO_AUD3_VOL);
  uint16_t freq3 = freq3_lo | ((int)(SB_BFE(freq3_hi,0,3))<<8u);
  float freq3_hz = 65536.0/(2048.-freq3);
  float volume3 = 1.0f;
  float length3 = (256.-length3_dat)/256.;
  int channel3_shift = SB_BFE(vol_env3,5,2)-1;
  if(SB_BFE(power3,7,1)==0||channel3_shift==-1)channel3_shift=4;
  if(SB_BFE(freq3_hi,7,1)){chan3_t=0.f;length_t3=0.f;}
  if(SB_BFE(freq3_hi,6,1)==0){length3 = 1.0e9;}
  freq3_hi &=0x7f;
  sb_store8_direct(gb, SB_IO_AUD3_FREQ_HI,freq3_hi);

  uint8_t length_duty4 = sb_read8_direct(gb, SB_IO_AUD4_LENGTH);
  uint8_t counter4 = sb_read8_direct(gb, SB_IO_AUD4_COUNTER);
  uint8_t poly4 = sb_read8_direct(gb,SB_IO_AUD4_POLY);
  uint8_t vol_env4 = sb_read8_direct(gb,SB_IO_AUD4_VOL_ENV);
  float r4 = SB_BFE(poly4,0,3);
  uint8_t s4 = SB_BFE(poly4,4,4);
  if(r4==0)r4=0.5;
  float freq4_hz = 524288.0/r4/pow(2.0,s4+1);
  float volume4 = SB_BFE(vol_env4,4,4)/15.f;
  float volume_env4 = compute_vol_env_slope(vol_env4);
  float length4 = (64.-SB_BFE(length_duty4,0,6))/256.;
  if(SB_BFE(counter4,7,1)){chan4_t=0.f;length_t4 = 0;}
  if(SB_BFE(counter4,6,1)==0){length4 = 1.0e9;}
  counter4 &=0x7f;
  sb_store8_direct(gb, SB_IO_AUD4_COUNTER,counter4);

  uint8_t chan_sel = sb_read8_direct(gb,SB_IO_SOUND_OUTPUT_SEL);
  //These are type int to allow them to be multiplied to enable/disable
  int chan1_l = SB_BFE(chan_sel,0,1);
  int chan2_l = SB_BFE(chan_sel,1,1);
  int chan3_l = SB_BFE(chan_sel,2,1);
  int chan4_l = SB_BFE(chan_sel,3,1);
  int chan1_r = SB_BFE(chan_sel,4,1);
  int chan2_r = SB_BFE(chan_sel,5,1);
  int chan3_r = SB_BFE(chan_sel,6,1);
  int chan4_r = SB_BFE(chan_sel,7,1);


  while(current_sample_generated_time < current_sim_time){

    current_sample_generated_time+=1.0/SB_AUDIO_SAMPLE_RATE;
    
    if((sb_ring_buffer_size(&gb->audio.ring_buff)+3>SB_AUDIO_RING_BUFFER_SIZE)) continue;
    float f1 = freq1_hz*pow((1.+freq_sweep_sign1*pow(2.,-freq_sweep_n1)),length_t1/freq_sweep_time_mul1);

    //float f1 = freq1_hz+freq_sweep_sign1*freq_sweep_n1*length_t1/freq_sweep_time_mul1;
    // Advance cycle
    chan1_t+=sample_delta_t*f1;
    chan2_t+=sample_delta_t*freq2_hz;
    chan3_t+=sample_delta_t*freq3_hz;
    chan4_t+=sample_delta_t*freq4_hz;

    length_t1+=sample_delta_t;
    length_t2+=sample_delta_t;
    length_t3+=sample_delta_t;
    length_t4+=sample_delta_t;

    if(length_t1>length1){volume1=0;volume_env1=0;}
    if(length_t2>length2){volume2=0;volume_env2=0;}
    if(length_t3>length3)volume3=0;
    if(length_t4>length4){volume4=0;volume_env4=0;}

    // Loop back
    while(chan1_t>=1.0)chan1_t-=1.0;
    while(chan2_t>=1.0)chan2_t-=1.0;
    while(chan3_t>=1.0)chan3_t-=1.0;
    while(chan4_t>=1.0){
      chan4_t-=1.0;
      last_noise_value = GetRandomValue(0,1)*2.-1.;
    }
    //Volume Envelopes
    float v1=volume_env1*length_t1+volume1;
    float v2=volume_env2*length_t2+volume2;
    float v4=volume_env4*length_t4+volume4;

    if(v1<0)v1=0;
    if(v2<0)v2=0;
    if(v4<0)v4=0;

    if(v1>1)v1=1;
    if(v2>1)v2=1;
    if(v4>1)v4=1;

    float channels[4];
    // Audio Gen
    float sample_volume_l = 0;
    float sample_volume_r = 0;

    channels[0]= sb_bandlimited_square(chan1_t,duty1,sample_delta_t*f1)*v1;
    channels[1]= sb_bandlimited_square(chan2_t,duty2,sample_delta_t*freq2_hz)*v2;

    sample_volume_l+=channels[0]*chan1_l;
    sample_volume_r+=channels[0]*chan1_r;
    sample_volume_l+=channels[1]*chan2_l;
    sample_volume_r+=channels[1]*chan2_r;
     
    unsigned wav_samp = chan3_t*32;
    wav_samp%=32;
    int dat =sb_read8_direct(gb,SB_IO_AUD3_WAVE_BASE+wav_samp/2);
    int offset = (wav_samp&1)? 0:4;
    dat = ((dat>>offset)&0xf)>>channel3_shift;

    int wav_offset = 8>>channel3_shift; 
    channels[2] = (dat-wav_offset)/8.;
    sample_volume_l+=channels[2]*chan3_l;
    sample_volume_r+=channels[2]*chan3_r;

    channels[3] = last_noise_value*v4;
    sample_volume_l+=channels[3]*chan4_l;
    sample_volume_r+=channels[3]*chan4_r;
    
    sample_volume_l*=0.25;
    sample_volume_r*=0.25;
     
    const float lowpass_coef = 0.999;
    gb->audio.mix_l_volume = gb->audio.mix_l_volume*lowpass_coef + fabs(sample_volume_l)*(1.0-lowpass_coef);
    gb->audio.mix_r_volume = gb->audio.mix_r_volume*lowpass_coef + fabs(sample_volume_r)*(1.0-lowpass_coef); 
    
    for(int i=0;i<4;++i){
      gb->audio.channel_output[i] = gb->audio.channel_output[i]*lowpass_coef 
                                  + fabs(channels[i])*(1.0-lowpass_coef); 
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
    //out_l = sample_volume_l;
    //out_r = sample_volume_r;
    // Quantization
    unsigned write_entry0 = (gb->audio.ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
    unsigned write_entry1 = (gb->audio.ring_buff.write_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;

    gb->audio.ring_buff.data[write_entry0] = out_l*32760;
    gb->audio.ring_buff.data[write_entry1] = out_r*32760;
  }
}
void sb_update_audio_stream_from_fifo(sb_gb_t*gb, bool global_mute){
  static int16_t audio_buff[SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS*2];
  int size = sb_ring_buffer_size(&gb->audio.ring_buff);
  if(global_mute){
    if(IsAudioStreamProcessed(audio_stream)){
      for(int i=0;i<SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS;++i)audio_buff[i]=0;
      UpdateAudioStream(audio_stream, audio_buff, SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS);
    }
  }
  if(IsAudioStreamProcessed(audio_stream)){
    //Fill up Audio buffer from ring_buffer
    for(int i=0; i< SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS; ++i){
    
      unsigned read_entry =0;
      if(sb_ring_buffer_size(&gb->audio.ring_buff)>0)
        read_entry=(gb->audio.ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
      audio_buff[i]= gb->audio.ring_buff.data[read_entry];
    }

    UpdateAudioStream(audio_stream, audio_buff, SB_AUDIO_BUFF_SAMPLES*SB_AUDIO_BUFF_CHANNELS);
  }
}

bool sb_load_rom(const char* file_path){
  if(!IsFileExtension(file_path,".gb") && 
     !IsFileExtension(file_path,".gbc")) return false; 
  unsigned int bytes = 0;
  unsigned char *data = LoadFileData(file_path, &bytes);
  if(bytes+1>MAX_CARTRIDGE_SIZE)bytes = MAX_CARTRIDGE_SIZE;
  printf("Loaded File: %s, %d bytes\n", file_path, bytes);
  for (size_t i = 0; i < bytes; ++i) {
    gb_state.cart.data[i] = data[i];
  }
  for(size_t i = 0; i< 32*1024;++i)gb_state.mem.data[i] = gb_state.cart.data[i];
  // Copy Header
  for (int i = 0; i < 11; ++i) {
    gb_state.cart.title[i] = gb_state.cart.data[i + 0x134];
  }
  gb_state.cart.title[12] ='\0';
  // TODO PGB Mode(Values with Bit 7 set, and either Bit 2 or 3 set)
  gb_state.cart.game_boy_color =
      SB_BFE(gb_state.cart.data[0x143], 7, 1) == 1;
  gb_state.cart.type = gb_state.cart.data[0x147];

  switch(gb_state.cart.type){
    case 0: gb_state.cart.mbc_type = SB_MBC_NO_MBC; break;

    case 1:
    case 2:
    case 3: gb_state.cart.mbc_type = SB_MBC_MBC1; break;

    case 5:
    case 6: gb_state.cart.mbc_type = SB_MBC_MBC2; break;

    case 0x0f:
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13: gb_state.cart.mbc_type = SB_MBC_MBC3; break;

    case 0x19:
    case 0x1A:
    case 0x1B:
    case 0x1C:
    case 0x1D:
    case 0x1E:gb_state.cart.mbc_type = SB_MBC_MBC5; break;

    case 0x20:gb_state.cart.mbc_type = SB_MBC_MBC6; break;
    case 0x22:gb_state.cart.mbc_type = SB_MBC_MBC7; break;

  }
  switch (gb_state.cart.data[0x148]) {
    case 0x0: gb_state.cart.rom_size = 32 * 1024;  break;
    case 0x1: gb_state.cart.rom_size = 64 * 1024;  break;
    case 0x2: gb_state.cart.rom_size = 128 * 1024; break;
    case 0x3: gb_state.cart.rom_size = 256 * 1024; break;
    case 0x4: gb_state.cart.rom_size = 512 * 1024; break;
    case 0x5: gb_state.cart.rom_size = 1024 * 1024;     break;
    case 0x6: gb_state.cart.rom_size = 2 * 1024 * 1024; break;
    case 0x7: gb_state.cart.rom_size = 4 * 1024 * 1024; break;
    case 0x8: gb_state.cart.rom_size = 8 * 1024 * 1024; break;
    case 0x52: gb_state.cart.rom_size = 1.1 * 1024 * 1024; break;
    case 0x53: gb_state.cart.rom_size = 1.2 * 1024 * 1024; break;
    case 0x54: gb_state.cart.rom_size = 1.5 * 1024 * 1024; break;
    default: gb_state.cart.rom_size = 32 * 1024; break;
  }

  switch (gb_state.cart.data[0x149]) {
    case 0x0: gb_state.cart.ram_size = 0; break;
    case 0x1: gb_state.cart.ram_size = 2*1024; break;
    case 0x2: gb_state.cart.ram_size = 8 * 1024; break;
    case 0x3: gb_state.cart.ram_size = 32 * 1024; break;
    case 0x4: gb_state.cart.ram_size = 128 * 1024; break;
    case 0x5: gb_state.cart.ram_size = 64 * 1024; break;
    default: gb_state.cart.ram_size = 0; break;
  }
  emu_state.run_mode = SB_MODE_RESET;
  emu_state.rom_loaded = true;
  UnloadFileData(data);
  const char * c = GetFileNameWithoutExt(file_path);
#if defined(PLATFORM_WEB)
      const char * save_file = TextFormat("/offline/%s.sav",c);
#else
      const char * save_file = TextFormat("%s.sav",c);
#endif
  strncpy(gb_state.cart.save_file_path,save_file,SB_FILE_PATH_SIZE);
  gb_state.cart.save_file_path[SB_FILE_PATH_SIZE-1]=0;

  if(FileExists(save_file)){
    unsigned int bytes=0;
    unsigned char* data = LoadFileData(save_file,&bytes);
    printf("Loaded save file: %s, bytes: %d\n",save_file,bytes);

    if(bytes!=gb_state.cart.ram_size){
      printf("Warning save file size(%d) doesn't match size expected(%d) for the cartridge type", bytes, gb_state.cart.ram_size);
    }
    if(bytes>gb_state.cart.ram_size){
      bytes = gb_state.cart.ram_size;
    }
    memcpy(gb_state.cart.ram_data, data, bytes);
    UnloadFileData(data);

  }else{
    printf("Could not find save file: %s\n",save_file);
    memset(gb_state.cart.ram_data,0,MAX_CARTRIDGE_RAM);
  }
  return true; 
}
void se_load_rom(char *filename){
  printf("Loading ROM: %s\n", filename); 
  emu_state.rom_loaded = false; 
  if(gba_load_rom(&gba, filename)){
    emu_state.system = SYSTEM_GBA;
    emu_state.rom_loaded = true;
  }
  if(sb_load_rom(filename)){
    emu_state.system = SYSTEM_GB;
    emu_state.rom_loaded = true; 
  }
  if(emu_state.rom_loaded==false)printf("Unknown ROM type: %s\n", filename); 
  return; 
}
void sb_draw_load_rom_prompt(Rectangle rect, bool visible){

  static bool last_visible = false;
  if(visible==false){
#if defined(PLATFORM_WEB)
    if(last_visible==true){
      EM_ASM({
        var input = document.getElementById('fileInput');
        input.style.visibility= "hidden";
      });
    }
#endif
    last_visible=false;
    return;
  }

  DrawRectangleRec(rect, (Color){100,100,100,255});
  last_visible=true;
  Color color = {0,0,0,127};
  const char * label = "Drop ROM";
  int icon_scale = (rect.width<rect.height?rect.width:rect.height)/16*0.33;
  icon_scale = 6;
  int icon_off = RICON_SIZE*icon_scale/2;

  GuiDrawIcon(3,(Vector2){rect.x+rect.width/2-icon_off,rect.y+rect.height/2-icon_off},icon_scale, color);
  Vector2 label_sz= MeasureTextEx(GetFontDefault(), label, icon_scale*10/2,icon_scale/2);
  DrawText(label,rect.x+rect.width/2-label_sz.x/2,rect.y+rect.height/2+icon_off,icon_scale*10/2,color);

  Rectangle button_rect;
  button_rect.width = label_sz.x;
  button_rect.height = 30;
 #if defined(PLATFORM_WEB)
  button_rect.x= rect.width/2+rect.x-button_rect.width/2;
  button_rect.y= rect.y+rect.height/2+icon_off*2;
  bool open_dialog = GuiButton(button_rect,"Open Rom");
  char * new_path = (char*)EM_ASM_INT({
    var input = document.getElementById('fileInput');
    input.style.left = $0 +'px';
    input.style.top = $1 +'px';
    input.style.width = $2 +'px';
    input.style.height= $3 +'px';
    input.style.visibility = 'visible';
    if(input.value!= ''){
      console.log(input.value);
      var reader= new FileReader();
      file = input.files[0];
      reader.addEventListener('loadend', print_file);
      reader.readAsArrayBuffer(file);
      var filename = file.name;
      input.value = '';

      function print_file(e){
          var result=reader.result;
          const uint8_view = new Uint8Array(result);
          var out_file = '/offline/'+filename;
          FS.writeFile(out_file, uint8_view);
          FS.syncfs(function (err) {});
          var input_stage = document.getElementById('fileStaging');
          input_stage.value = out_file;
      }
    }
    var input_stage = document.getElementById('fileStaging');
    ret_path = '';
    if(input_stage.value !=''){
      ret_path = input_stage.value;
      input_stage.value = '';
    }
    var sz = lengthBytesUTF8(ret_path)+1;
    var string_on_heap = _malloc(sz);
    stringToUTF8(ret_path, string_on_heap, sz);
    return string_on_heap;
  },button_rect.x,button_rect.y,button_rect.width,button_rect.height);

  printf("%s\n",new_path);
  if(!TextIsEqual("",new_path))se_load_rom(new_path);
  free(new_path);
  //printf("Open: %s\n",file_name);
  //free(file_name);
#endif

}
float sb_distance(Vector2 a, Vector2 b){
  a.x-=b.x;
  a.y-=b.y;
  return sqrt(a.x*a.x+a.y*a.y);
}

void sb_draw_onscreen_controller(sb_emu_state_t*state, Rectangle rect){
  Color fill_color = {200,200,200,255};
  Color sel_color = {150,150,150,255};
  Color line_color = {127,127,127,255};
  float button_r = rect.width*0.09;

  float dpad_sz0 = rect.width*0.055;
  float dpad_sz1 = rect.width*0.20;


  Vector2 a_pos = {rect.width*0.85,rect.height*0.32};
  Vector2 b_pos = {rect.width*0.65,rect.height*0.48};
  Vector2 dpad_pos = {rect.width*0.25,rect.height*0.4};

  a_pos.x+=rect.x;
  b_pos.x+=rect.x;
  dpad_pos.x+=rect.x;

  a_pos.y+=rect.y;
  b_pos.y+=rect.y;
  dpad_pos.y+=rect.y;


  enum{max_points = 5};
  Vector2 points[max_points]={0};

  int p = 0;
  if(IsMouseButtonDown(0))points[p++] = GetMousePosition();
  for(int i=0; i<GetTouchPointsCount();++i){
    if(p<max_points)points[p++]=GetTouchPosition(i);
  }

  bool a=false,b=false,up=false,down=false,left=false,right=false,start=false,select=false;

  for(int i = 0;i<p;++i){
    if(sb_distance(points[i],a_pos)<button_r*1.6)a=true;
    if(sb_distance(points[i],b_pos)<button_r*1.6)b=true;

    int dx = points[i].x-dpad_pos.x;
    int dy = points[i].y-dpad_pos.y;
    if(dx>=-dpad_sz1*1.15 && dx<=dpad_sz1*1.15 && dy>=-dpad_sz1*1.15 && dy<=dpad_sz1*1.15 ){
      if(dy>dpad_sz0)down=true;
      if(dy<-dpad_sz0)up=true;

      if(dx>dpad_sz0)right=true;
      if(dx<-dpad_sz0)left=true;

    }

  }
    

  DrawCircle(a_pos.x, a_pos.y, button_r+1, line_color);
  DrawCircle(a_pos.x, a_pos.y, button_r, a?sel_color:fill_color);

  DrawCircle(b_pos.x, b_pos.y, button_r+1, line_color);
  DrawCircle(b_pos.x, b_pos.y, button_r, b?sel_color:fill_color);

  DrawRectangle(dpad_pos.x-dpad_sz1-1,dpad_pos.y-dpad_sz0-1,dpad_sz1*2+2,dpad_sz0*2+2,line_color);
  DrawRectangle(dpad_pos.x-dpad_sz0-1,dpad_pos.y-dpad_sz1-1,dpad_sz0*2+2,dpad_sz1*2+2,line_color);

  DrawRectangle(dpad_pos.x-dpad_sz1,dpad_pos.y-dpad_sz0,dpad_sz1*2,dpad_sz0*2,fill_color);
  DrawRectangle(dpad_pos.x-dpad_sz0,dpad_pos.y-dpad_sz1,dpad_sz0*2,dpad_sz1*2,fill_color);

  if(down) DrawRectangle(dpad_pos.x-dpad_sz0,dpad_pos.y+dpad_sz0,dpad_sz0*2,dpad_sz1-dpad_sz0,sel_color);
  if(up) DrawRectangle(dpad_pos.x-dpad_sz0,dpad_pos.y-dpad_sz1,dpad_sz0*2,dpad_sz1-dpad_sz0,sel_color);


  if(left) DrawRectangle(dpad_pos.x-dpad_sz1,dpad_pos.y-dpad_sz0,dpad_sz1-dpad_sz0,dpad_sz0*2,sel_color);
  if(right) DrawRectangle(dpad_pos.x+dpad_sz0,dpad_pos.y-dpad_sz0,dpad_sz1-dpad_sz0,dpad_sz0*2,sel_color);


  Rectangle widget_rect = rect;
  widget_rect.x += GUI_PADDING;
  widget_rect.y += rect.height-GUI_ROW_HEIGHT-GUI_PADDING;
  widget_rect.width -=GUI_PADDING*2;
  widget_rect.height = GUI_ROW_HEIGHT;

  char * button_name[] ={"Start", "Select"};
  int num_buttons =  sizeof(button_name)/sizeof(button_name[0]);
  int button_press=0;           
  int button_width = (widget_rect.width-(num_buttons-1)*GuiGetStyle(TOGGLE, GROUP_PADDING))/num_buttons;
  for(int b=0;b<num_buttons;++b){                                           
    int state = 0;
    Rectangle bounds = widget_rect;
    bounds.width = button_width;
    bounds.x+=(button_width+GuiGetStyle(TOGGLE, GROUP_PADDING))*(b);
   
    for(int i = 0;i<p;++i){
      int dx = points[i].x-bounds.x;
      int dy = points[i].y-bounds.y;
      if(dx>=-bounds.width*0.05 && dx<=bounds.width*1.05 && dy>=0 && dy<=bounds.height ){
        button_press|=1<<b; 
        state =1;
      }

    }
    GuiDrawRectangle(bounds, GuiGetStyle(BASE, BORDER_WIDTH), Fade(GetColor(GuiGetStyle(BUTTON, BORDER + state)), guiAlpha), Fade(GetColor(GuiGetStyle(BUTTON, BASE + state*3)), guiAlpha));
    GuiDrawText(button_name[b], GetTextBounds(BUTTON, bounds), GuiGetStyle(BUTTON, TEXT_ALIGNMENT), Fade(GetColor(GuiGetStyle(BUTTON, TEXT + state)), guiAlpha));
  }
  state->joy.left  |= left;
  state->joy.right |= right;
  state->joy.up    |= up;
  state->joy.down  |= down;
  state->joy.a |= a;
  state->joy.b |= b;
  state->joy.start |= SB_BFE(button_press,0,1);
  state->joy.select |= SB_BFE(button_press,1,1);
}

void UpdateDrawFrame() {
  if (IsFileDropped()) {
    int count = 0;
    char **files = GetDroppedFiles(&count);
    if (count > 0) {
      se_load_rom(files[0]);
    }
    ClearDroppedFiles();
  }
  static unsigned frames_since_last_save = 0; 
  frames_since_last_save++;
  if(gb_state.cart.ram_is_dirty && frames_since_last_save>10){
    frames_since_last_save = 0; 
    if(SaveFileData(gb_state.cart.save_file_path,gb_state.cart.ram_data,gb_state.cart.ram_size)){
 #if defined(PLATFORM_WEB)
      // Don't forget to sync to make sure you store it to IndexedDB
    EM_ASM(
        FS.syncfs(function (err) {});
    );
 #endif
      printf("Saved %s\n", gb_state.cart.save_file_path);
    }else printf("Failed to write out save file: %s\n",gb_state.cart.save_file_path);
    gb_state.cart.ram_is_dirty=false;
  }
  if(emu_state.system == SYSTEM_GB)sb_tick();
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &gba);
 
  bool mute = emu_state.run_mode != SB_MODE_RUN;
  // Draw
  //-----------------------------------------------------
  BeginDrawing();

  ClearBackground(RAYWHITE);
  int screen_width = GetScreenWidth();
  int screen_height = GetScreenHeight();     


  int panel_width = 430;
  Rectangle lcd_rect;
  lcd_rect.x = panel_width;
  lcd_rect.y = 0;
  lcd_rect.width = GetScreenWidth()-panel_width;
  lcd_rect.height = GetScreenHeight();
  // Controller polling must happen before handling the onscreen keyboard
  sb_poll_controller_input(&emu_state.joy);
  float lcd_aspect = 144/160.;
  int panel_height = 30+GUI_PADDING;
  if((screen_width-400)/(float)screen_height>160/144.*0.7){
    // Widescreen
    sb_draw_sidebar((Rectangle){0, 0, panel_width, GetScreenHeight()});
  }else if (screen_width*lcd_aspect/(float)(screen_height)<0.66){
    // Tall Screen
    //sb_draw_top_panel((Rectangle){0, 0, GetScreenWidth(), panel_height});
    lcd_rect = (Rectangle){0, 0, GetScreenWidth(),GetScreenWidth()*lcd_aspect};

    Rectangle cont_rect;
    cont_rect.x=0;
    cont_rect.y = lcd_rect.y+lcd_rect.height;
    cont_rect.width = GetScreenWidth();
    cont_rect.height= GetScreenHeight()-cont_rect.y;
    sb_draw_onscreen_controller(&emu_state,cont_rect);
  }else{
    // Square Screen
    lcd_rect = (Rectangle){0, panel_height, GetScreenWidth(),GetScreenHeight()-panel_height};
    sb_draw_top_panel((Rectangle){0, 0, GetScreenWidth(), panel_height});
  }
 
  Image screenIm = {
        .data = gb_state.lcd.framebuffer,
        .width = SB_LCD_W,
        .height = SB_LCD_H,
        .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
        .mipmaps = 1
  };
  if(emu_state.system==SYSTEM_GBA){
    screenIm = (Image){
        .data = gba.framebuffer,
        .width = GBA_LCD_W,
        .height = GBA_LCD_H,
        .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
        .mipmaps = 1
    }; 
  }
  Texture2D screenTex = LoadTextureFromImage(screenIm); 
  SetTextureFilter(screenTex, TEXTURE_FILTER_POINT);
  DrawTextureQuad(screenTex, (Vector2){1.f,1.f}, (Vector2){0.0f,0.0},lcd_rect, (Color){255,255,255,255});
  sb_draw_load_rom_prompt(lcd_rect,emu_state.rom_loaded==false);
  EndDrawing();
  UnloadTexture(screenTex);
  sb_update_audio_stream_from_fifo(&gb_state,mute); 

}

int main(void) {
  // Initialization
  //---------------------------------------------------------
  const int screenWidth = 1200;
  const int screenHeight = 700;

  // Set configuration flags for window creation
  SetConfigFlags(FLAG_VSYNC_HINT  |FLAG_WINDOW_HIGHDPI| FLAG_WINDOW_RESIZABLE | FLAG_MSAA_4X_HINT);
  InitWindow(screenWidth, screenHeight, "SkyBoy");
  SetTraceLogLevel(LOG_WARNING);
  ShowCursor();
  SetExitKey(0);
#if defined(PLATFORM_WEB)
// EM_ASM is a macro to call in-line JavaScript code.
    EM_ASM(
        // Make a directory other than '/'
        FS.mkdir('/offline');
        // Then mount with IDBFS type
        FS.mount(IDBFS, {}, '/offline');

        // Then sync
        FS.syncfs(true, function (err) {});
    );

  emscripten_set_main_loop(UpdateDrawFrame, 0, 1);
#else

  SetTargetFPS(60);
  // Main game loop
  while (!WindowShouldClose()) // Detect window close button or ESC key
  {
    UpdateDrawFrame();
  }
#endif

  CloseWindow(); // Close window and OpenGL context

  return 0;
}
