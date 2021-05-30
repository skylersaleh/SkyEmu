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
#include <stdint.h>                      
#include <math.h>
#define RAYGUI_IMPLEMENTATION
#define RAYGUI_SUPPORT_ICONS
#include "raygui.h"
#if defined(PLATFORM_WEB)
#include <emscripten/emscripten.h>
#endif

#define SB_NUM_SAVE_STATES 5
#define SB_AUDIO_BUFF_SAMPLES 2048
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

#define SB_IO_INTER_F     0xff0f
#define SB_IO_LCD_CTRL    0xff40
#define SB_IO_LCD_STAT    0xff41
#define SB_IO_LCD_SY      0xff42
#define SB_IO_LCD_SX      0xff43
#define SB_IO_LCD_LY      0xff44
#define SB_IO_LCD_LYC     0xff45

#define SB_IO_PPU_BGP     0xff47
#define SB_IO_PPU_OBP0    0xff48
#define SB_IO_PPU_OBP1    0xff49

#define SB_IO_LCD_WY      0xff4A
#define SB_IO_LCD_WX      0xff4B
#define SB_IO_INTER_EN    0xffff

const int GUI_PADDING = 10;
const int GUI_ROW_HEIGHT = 30;
const int GUI_LABEL_HEIGHT = 0;
const int GUI_LABEL_PADDING = 5;

sb_emu_state_t emu_state = {.pc_breakpoint = -1};
sb_gb_t gb_state = {};

sb_gb_t sb_save_states[SB_NUM_SAVE_STATES];
int sb_valid_save_states = 0; 
unsigned sb_save_state_index=0;

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
  
uint8_t sb_read8_direct(sb_gb_t *gb, int addr) { 
  return gb->mem.data[addr];
}  
uint8_t sb_read8(sb_gb_t *gb, int addr) { 
  //if(addr == 0xff44)return 0x90;
  //if(addr == 0xff80)gb->cpu.trigger_breakpoint=true;
  return sb_read8_direct(gb,addr);
}                           
void sb_store8_direct(sb_gb_t *gb, int addr, int value) {
  static int count = 0;
  if(addr<=0x7fff){
    //printf("Attempt to write to rom address %x\n",addr);
    //gb->cpu.trigger_breakpoint=true;
    return;
  }
  
  if(addr == 0xdd03||addr==0xdd01){
    //printf("store: %d %x\n",count,value);
    //gb->cpu.trigger_breakpoint=true;
  }
  if(addr == SB_IO_SERIAL_BYTE){
    printf("%c",(char)value);
  }else{
    gb->mem.data[addr]=value;
  }
}
void sb_store8(sb_gb_t *gb, int addr, int value) {
  if(addr == 0xff41){
    value&=~0x7;
    value|= sb_read8_direct(gb,addr)&0x7;
  }              
  if(addr == 0xff46){
    int src = value<<8;
    for(int i=0;i<=0x9F;++i){
      int d = sb_read8_direct(gb,src+i);
      sb_store8_direct(gb,0xfe00+i,d);
    }
  }else if(addr == SB_IO_DIV){
    value = 0; //All writes reset the div timer
  }else if(addr >= 0x0000 && addr <=0x1fff){
    printf("Enable Ram writes %d\n", value);
  }else if(addr >= 0x2000 && addr <=0x3fff){
    //MBC3 rombank select
    //TODO implement other mappers
    value&=0x7f; 
    if(value ==0)value = 1; 
    //printf("Switching to ROM bank %d\n", value);
    unsigned int bank_off = 0x4000*value;
    unsigned int size = gb->cart.rom_size;
    for(int i= 0; i<0x4000;++i){
      gb->mem.data[0x4000+i] = gb->cart.data[(bank_off+i)%size];
    }
    return;
  }else if(addr >= 0x4000 && addr <=0x5fff){
    //MBC3 rombank select
    //TODO implement other mappers
    value&=0x7f; 
    if(value ==0)value = 1; 
    //printf("Switching to RAM bank %d\n", value);
    //TODO
    //int bank_off = 0x4000*value;
    //for(int i= 0; i<0x4000;++i){
    //  gb->mem.data[0x4000+i] = gb->cart.data[bank_off+i];
    //}
    return;
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

Rectangle sb_draw_emu_state(Rectangle rect, sb_emu_state_t *emu_state, sb_gb_t*gb) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);
  widget_rect.width =
      widget_rect.width / 4 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4;
  emu_state->run_mode =
      GuiToggleGroup(widget_rect, "Reset;Pause;Run;Step", emu_state->run_mode);

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
  GuiGroupBox(state_rect, TextFormat("Emulator State [FPS: %i]", GetFPS()));
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
 
Rectangle sb_draw_joypad_state(Rectangle rect, sb_gb_joy_t *joy) {

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
                          
  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Joypad State");
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
  Rectangle widget_rect;

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Title: %s", cart_state->title));

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 10, &widget_rect,
                  &inside_rect);

  Rectangle wr = widget_rect;wr.width = wr.height = GUI_PADDING;

  GuiCheckBox(wr,
              TextFormat("Game Boy Color (%s)",
                         (cart_state->game_boy_color) ? "true" : "false"),
              cart_state->game_boy_color);

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Cart Type: %x", cart_state->type));

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("ROM Size: %d", cart_state->rom_size));

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("RAM Size: %d", cart_state->ram_size));

  Rectangle state_rect, adv_rect;
  sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                  &adv_rect);
  GuiGroupBox(state_rect, "Cartridge State (Drag and Drop .GBC to Load ROM)");
  return adv_rect;
}
Rectangle sb_draw_tile_state(Rectangle rect, sb_gb_cpu_t *cpu_state,
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

  const char *flag_names[] = {"Z", "N", "H", "C","Inter. En.", "Prefix",  NULL};

  bool flag_values[] = {
      SB_BFE(cpu_state->af, SB_Z_BIT, 1), // Z
      SB_BFE(cpu_state->af, SB_N_BIT, 1), // N
      SB_BFE(cpu_state->af, SB_H_BIT, 1), // H
      SB_BFE(cpu_state->af, SB_C_BIT, 1), // C
      cpu_state->interrupt_enable, 
      cpu_state->prefix_op
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
  GuiGroupBox(state_rect, "Tile Data");
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

  uint8_t data_dir =    ((!gb->joy.down)<<3)| ((!gb->joy.up)<<2)    |((!gb->joy.left)<<1)|((!gb->joy.right));  
  uint8_t data_action = ((!gb->joy.start)<<3)|((!gb->joy.select)<<2)|((!gb->joy.b)<<1)   |(!gb->joy.a);

  uint8_t data = gb->mem.data[SB_IO_JOYPAD];
  
  data&=0xf0;
  
  if(0 == (data & (1<<4))) data |= data_dir;
  if(0 == (data & (1<<5))) data |= data_action;

  gb->mem.data[SB_IO_JOYPAD] = data;

}        
void sb_poll_controller_input(sb_gb_t* gb){

  gb->joy.left  = IsKeyDown(KEY_A);
  gb->joy.right = IsKeyDown(KEY_D);
  gb->joy.up    = IsKeyDown(KEY_W);
  gb->joy.down  = IsKeyDown(KEY_S);
  gb->joy.a = IsKeyDown(KEY_J);
  gb->joy.b = IsKeyDown(KEY_K);
  gb->joy.start = IsKeyDown(KEY_ENTER);
  gb->joy.select = IsKeyDown(KEY_APOSTROPHE);

}

bool sb_update_lcd_status(sb_gb_t* gb, int delta_cycles){
  uint8_t stat = sb_read8_direct(gb, SB_IO_LCD_STAT); 
  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  uint8_t ly  = sb_read8_direct(gb, SB_IO_LCD_LY);
  uint8_t old_ly = ly;
  uint8_t lyc = sb_read8_direct(gb, SB_IO_LCD_LYC);
  bool enable = SB_BFE(ctrl,7,1)==1;
  int mode = 0; 
  bool new_scanline = false; 
  if(!enable){
    gb->lcd.scanline_cycles = 0;
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
    }
    
    //if(ly==153&& gb->lcd.scanline_cycles>4){ly = 0; gb->lcd.curr_window_scanline = 0;} 
    if(ly>153){ly = 0; gb->lcd.curr_window_scanline = 0;} 


    if(gb->lcd.scanline_cycles<=mode2_clks)mode = 2;
    else if(gb->lcd.scanline_cycles<=mode3_clks+mode2_clks) mode =3;
    else mode =0;

    int old_mode = stat&0x7;
    if((old_mode&0x3)!=2&&(mode&0x3)==2)new_scanline=true;
    
    bool lyc_eq_ly_interrupt = SB_BFE(stat, 6,1);
    bool oam_interrupt = SB_BFE(stat, 5,1);
    bool vblank_interrupt = SB_BFE(stat, 4,1);
    bool hblank_interrupt = SB_BFE(stat, 3,1);
    if(ly+1==SB_LCD_H&&new_scanline){
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      //V-BLANK Interrupt
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<0));
    }
    if(ly+1==SB_LCD_H&&new_scanline&& vblank_interrupt){
      //vblank-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }      
    if(ly>144) {mode = 1; new_scanline = false;} 
    if(ly +1  == lyc) mode|=0x4;

    if((old_mode & 0x4)==0 && (mode&0x4)==4 && lyc_eq_ly_interrupt){
      //LCD-stat Interrupt
      uint8_t inter_flag = sb_read8_direct(gb, SB_IO_INTER_F);
      sb_store8_direct(gb, SB_IO_INTER_F, inter_flag| (1<<1));
    }
    if((old_mode&0x3)!=2 && (mode&0x3) == 0x2 && oam_interrupt){
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
  stat = (stat&0xf8) | mode; 
  sb_store8_direct(gb, SB_IO_LCD_STAT, stat);
  sb_store8_direct(gb, SB_IO_LCD_LY, ly);
  return new_scanline; 
}
void sb_draw_scanline(sb_gb_t*gb){
  uint8_t ctrl = sb_read8_direct(gb, SB_IO_LCD_CTRL);
  bool draw_bg_win     = SB_BFE(ctrl,0,1)==1;
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

  if(wy>y)window_enable = false; 
  int sprite_h = sprite8x16 ? 16: 8;
  const int sprites_per_scanline = 10;
  // HW only draws first 10 sprites that touch a scanline
  int render_sprites[sprites_per_scanline];
  int sprite_index=0; 
  const int BACKGROUND_PALETTE = 0x40; 
  const int OBJECT_PALETTE1 = 0x10; 
  
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
    uint8_t r=0,g=0,b=0;
    uint8_t color_id=0; 
    if(draw_bg_win){
      int px = x+ sx; 
      int py = y+ sy;
      const int tile_size = 8;
      const int tiles_per_row = 32;
      int tile_offset = (((px&0xff)/tile_size)+((py&0xff)/tile_size)*tiles_per_row)&0x3ff;
      
      int tile_id = sb_read8_direct(gb, bg_tile_map_base+tile_offset);

      int pixel_in_tile_x = 7-(px%8);
      int pixel_in_tile_y = (py%8);


      int byte_tile_data_off = 0;

      if(bg_win_tile_data_mode==0){
        byte_tile_data_off = 0x8000 + 0x1000 + (((int8_t)(tile_id))*bytes_per_tile);
      }else{
        byte_tile_data_off = 0x8000 + (((uint8_t)(tile_id))*bytes_per_tile);
      }
      
      byte_tile_data_off+=pixel_in_tile_y*2;
      uint8_t data1 = sb_read8_direct(gb, byte_tile_data_off);
      uint8_t data2 = sb_read8_direct(gb, byte_tile_data_off+1);
      color_id = (SB_BFE(data1,pixel_in_tile_x,1)+SB_BFE(data2,pixel_in_tile_x,1)*2);
      color_id |= BACKGROUND_PALETTE;
    }
    if(window_enable && draw_bg_win){
      int px = x-wx; 
      int py = gb->lcd.curr_window_scanline;
      if(px>=0&&py>=0){
        rendered_part_of_window = true;
        const int tile_size = 8;
        const int tiles_per_row = 32;
        int tile_offset = (((px&0xff)/tile_size)+((py&0xff)/tile_size)*tiles_per_row)&0x3ff;
        
        int tile_id = sb_read8_direct(gb, win_tile_map_base+tile_offset);

        int pixel_in_tile_x = 7-(px%8);
        int pixel_in_tile_y = (py%8);


        int byte_tile_data_off = 0;

        if(bg_win_tile_data_mode==0){
          byte_tile_data_off = 0x8000 + 0x1000 + (((int8_t)(tile_id))*bytes_per_tile);
        }else{
          byte_tile_data_off = 0x8000 + (((uint8_t)(tile_id))*bytes_per_tile);
        }
        byte_tile_data_off+=pixel_in_tile_y*2;
        uint8_t data1 = sb_read8_direct(gb, byte_tile_data_off);
        uint8_t data2 = sb_read8_direct(gb, byte_tile_data_off+1);
        color_id = (SB_BFE(data1,pixel_in_tile_x,1)+SB_BFE(data2,pixel_in_tile_x,1)*2);
        color_id |= BACKGROUND_PALETTE;
      }
    } 
    if(draw_sprite){
      int prior_sprite_x = 256; 
      for(int i=0;i<sprites_per_scanline;++i){
        int sprite = render_sprites[i];
        if(sprite==-1)continue;
        int sprite_base = oam_table_offset+sprite*4;
        int yc = sb_read8_direct(gb, sprite_base+0)-16;
        int xc = sb_read8_direct(gb, sprite_base+1)-8;
        
        int tile = sb_read8_direct(gb, sprite_base+2);
        int attr = sb_read8_direct(gb, sprite_base+3);

        if(sprite8x16)tile &=0xfe;
        
        bool x_flip = SB_BFE(attr,5,1)==1;
        bool y_flip = SB_BFE(attr,6,1)==1;
        bool bg_win_on_top = SB_BFE(attr,7,1)==1;
                                       
        int palette = SB_BFE(attr,4,1)==1; 
        int x_sprite = 7-(x-xc); 
        int y_sprite = y-yc;       

        if(x_flip)x_sprite = 7-x_sprite;
        if(y_flip)y_sprite = (sprite8x16? 15 : 7)-y_sprite;
        //Check if the sprite is hit
        if(x_sprite>=8 || x_sprite<0)continue;
        if(y_sprite<0 || y_sprite>=16 || (y_sprite>=8 && sprite8x16==false))continue;

        if(prior_sprite_x<=xc) continue;
        
        int byte_tile_data_off = 0x8000 + (((uint8_t)(tile))*bytes_per_tile);
        byte_tile_data_off+=y_sprite*2;

        uint8_t data1 = sb_read8_direct(gb, byte_tile_data_off);
        uint8_t data2 = sb_read8_direct(gb, byte_tile_data_off+1);

        uint8_t cid = (SB_BFE(data1,x_sprite,1)+SB_BFE(data2,x_sprite,1)*2);
        if(bg_win_on_top){
          if((color_id&0x3)==0){color_id = cid | (palette<<4); prior_sprite_x =xc;}
        }else if(cid!=0){color_id = cid | (palette<<4); prior_sprite_x=xc;}
        
      }       
      //r = SB_BFE(tile_id,0,3)*31;
      //g = SB_BFE(tile_id,3,3)*31;
      //b = SB_BFE(tile_id,6,2)*63;

    }
    uint8_t palette = 0;  
    if(color_id & BACKGROUND_PALETTE)palette = sb_read8_direct(gb, SB_IO_PPU_BGP);
    else if(color_id & OBJECT_PALETTE1)palette = sb_read8_direct(gb, SB_IO_PPU_OBP1);
    else palette = color_id ==0 ? 0 : sb_read8_direct(gb, SB_IO_PPU_OBP0);
    color_id = SB_BFE(palette,2*color_id,2);
    color_id = 3-color_id; 
    r = color_id*85;
    g = color_id*85;
    b = color_id*85;

    const uint32_t palette_dmg_green[4*3] = { 0x81,0x8F,0x38,0x64,0x7D,0x43,0x56,0x6D,0x3F,0x31,0x4A,0x2D };
    color_id = 3-color_id; 
                                        
    r = palette_dmg_green[color_id*3+0];
    g = palette_dmg_green[color_id*3+1];
    b = palette_dmg_green[color_id*3+2];
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
  if(gb->timers.clocks_till_div_inc<0){
    int period = 4*1024*1024/16384; 
    gb->timers.clocks_till_div_inc+=period;
    if(gb->timers.clocks_till_div_inc<0)
      gb->timers.clocks_till_div_inc = period; 

    uint8_t d = sb_read8_direct(gb, SB_IO_DIV);
    sb_store8_direct(gb, SB_IO_DIV, d+1); 
  }
  gb->timers.clocks_till_tima_inc -=delta_clocks;
  if(gb->timers.clocks_till_tima_inc<0){
    int period =0;
    switch(clk_sel){
      case 0: period = 1024; break; 
      case 1: period = 16; break; 
      case 2: period = 64; break; 
      case 3: period = 256; break; 
    }
    gb->timers.clocks_till_tima_inc+=period;
    if(gb->timers.clocks_till_tima_inc<0)
      gb->timers.clocks_till_tima_inc = period; 

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
void sb_tick(){
  static FILE* file = NULL;
  sb_poll_controller_input(&gb_state);
  if (emu_state.run_mode == SB_MODE_RESET) {
    if(file)fclose(file);
    file = fopen("instr_trace.txt","wb");
    memset(&gb_state.cpu, 0, sizeof(gb_state.cpu));
    //memset(&gb_state.mem, 0, sizeof(gb_state.mem));
    
    gb_state.cpu.pc = 0x100;

    gb_state.cpu.af=0x01B0;
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

    for(int i=0;i<SB_LCD_W*SB_LCD_H*3;++i){
      gb_state.lcd.framebuffer[i] = 0;
    }
  }
  
  if (emu_state.run_mode == SB_MODE_RUN||emu_state.run_mode ==SB_MODE_STEP) {
    
    int instructions_to_execute = emu_state.step_instructions;
    if(instructions_to_execute==0)instructions_to_execute=0x7fffffff;
    for(int i=0;i<instructions_to_execute;++i){
    
        sb_update_joypad_io_reg(&emu_state, &gb_state);
        int pc = gb_state.cpu.pc;
        

        unsigned op = sb_read8(&gb_state,gb_state.cpu.pc);

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
        if(gb_state.cpu.interrupt_enable && gb_state.cpu.prefix_op==false){
          uint8_t ie = sb_read8_direct(&gb_state,SB_IO_INTER_EN);
          uint8_t i_flag = sb_read8_direct(&gb_state,SB_IO_INTER_F);
          uint8_t masked_interupt = ie&i_flag&0x1f;

          for(int i=0;i<5;++i){
            if(masked_interupt & (1<<i)){trigger_interrupt = i;break;}
          }
          if(trigger_interrupt!=-1)i_flag &= ~(1<<trigger_interrupt);
          //if(trigger_interrupt!=-1)gb_state.cpu.trigger_breakpoint = true; 
          sb_store8_direct(&gb_state,SB_IO_INTER_F,i_flag);
        }
        if(gb_state.cpu.deferred_interrupt_enable){
          gb_state.cpu.deferred_interrupt_enable = false;
          gb_state.cpu.interrupt_enable = true;
        }

        gb_state.cpu.prefix_op = false;
        int delta_cycles = 4;
        if(trigger_interrupt!=-1){
          gb_state.cpu.wait_for_interrupt = false;
          gb_state.cpu.interrupt_enable = false;
          gb_state.cpu.deferred_interrupt_enable = false;
          int interrupt_address = (trigger_interrupt*0x8)+0x40;
          sb_call_impl(&gb_state, interrupt_address, 0, 0, 0, (const uint8_t*)"----");
          delta_cycles = 5*4;
          
        }else if(gb_state.cpu.wait_for_interrupt==false){
          sb_instr_t inst = sb_decode_table[op];
          gb_state.cpu.pc+=inst.length;
          int operand1 = sb_load_operand(&gb_state,inst.op_src1);
          int operand2 = sb_load_operand(&gb_state,inst.op_src2);
                                  
          int pc_before_inst = gb_state.cpu.pc; 
          inst.impl(&gb_state, operand1, operand2,inst.op_src1,inst.op_src2, inst.flag_mask);
          if(gb_state.cpu.prefix_op==true)i--;

          delta_cycles = 4*(gb_state.cpu.pc==pc_before_inst? inst.mcycles : inst.mcycles_branch_taken);
        }
        bool vblank = sb_update_lcd(&gb_state,delta_cycles);
        sb_update_timers(&gb_state,delta_cycles);
                                
        //sb_push_save_state(&gb_state);

        if (gb_state.cpu.pc == emu_state.pc_breakpoint||gb_state.cpu.trigger_breakpoint){
          gb_state.cpu.trigger_breakpoint = false; 
          emu_state.run_mode = SB_MODE_PAUSE;
          break;                   
        }                            
        if(vblank&& emu_state.step_instructions ==0 )break;
    }
  }
 
  if (emu_state.run_mode == SB_MODE_STEP) {
    emu_state.run_mode = SB_MODE_PAUSE;
  }
}
void sb_draw_sidebar(Rectangle rect) {
  GuiPanel(rect);
  Rectangle rect_inside = sb_inside_rect_after_padding(rect, GUI_PADDING);

  rect_inside = sb_draw_emu_state(rect_inside, &emu_state,&gb_state);
  rect_inside = sb_draw_cartridge_state(rect_inside, &gb_state.cart);
  rect_inside = sb_draw_timer_state(rect_inside, &gb_state);
  rect_inside = sb_draw_joypad_state(rect_inside, &gb_state.joy);
  rect_inside = sb_draw_cpu_state(rect_inside, &gb_state.cpu, &gb_state);
                               
}
float compute_vol_env_slope(uint8_t d){
  int dir = SB_BFE(d,3,1);
  int length_of_step = SB_BFE(d,0,3);
  
  float step_time = 64./length_of_step;
  float slope = step_time;
  if(dir==0)slope*=-1;
  if(length_of_step==0)slope=0;
  return slope/16.; 
}
AudioStream audio_stream;
void sb_process_audio(sb_gb_t *gb){
  static int16_t audio_buff[SB_AUDIO_BUFF_SAMPLES]; 
  static float chan1_t = 0, length_t1=0; 
  static float chan2_t = 0, length_t2=0;
  static float chan3_t = 0, length_t3=0;
  static float chan4_t = 0, length_t4=0;
  static float last_noise_value = 0;

  static float capacitor = 0.0; 

  const static float duty_lookup[]={0.125,0.25,0.5,0.75};
  
  float sample_delta_t = 1.0/SB_AUDIO_SAMPLE_RATE;
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
  float volume3 = 0.0f;
  float length3 = (256.-length3_dat)/256.; 
  switch(SB_BFE(vol_env3,5,2)){
    case 1: volume3=1.;
    case 2: volume3=0.5;
    case 3: volume3=0.25;
  }
  if(SB_BFE(power3,7,1)==0)volume3=0;
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
                  
  while(IsAudioStreamProcessed(audio_stream)){
    for(int i=0;i<SB_AUDIO_BUFF_SAMPLES;++i){
      // Advance cycle
      chan1_t+=sample_delta_t*freq1_hz;
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
      if(chan1_t>=1.0)chan1_t-=1.0;
      if(chan2_t>=1.0)chan2_t-=1.0;
      if(chan3_t>=1.0)chan3_t-=1.0;
      if(chan4_t>=1.0){
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
                 
      // Audio Gen
      float sample_volume = 0;
      sample_volume+=(chan1_t>duty1?1:-1)*v1;
      sample_volume+=(chan2_t>duty2?1:-1)*v2;

      int wav_samp = chan3_t*32; 
      uint8_t dat =sb_read8_direct(gb,SB_IO_AUD3_WAVE_BASE+wav_samp/2);
      int offset = (wav_samp&1)? 0:4;
      dat = (dat>>offset)&0xf;
      sample_volume+=(dat-8)/7.*volume3;

      sample_volume+=last_noise_value*v4;

      sample_volume*=0.25;


      // Clipping
      if(sample_volume>1.0)sample_volume=1;
      if(sample_volume<-1.0)sample_volume=-1;
      float out = sample_volume-capacitor; 
      capacitor = (sample_volume-out)*0.996;
      // Quantization
      audio_buff[i] = sample_volume*32760;
      
    }
    
    UpdateAudioStream(audio_stream, audio_buff, SB_AUDIO_BUFF_SAMPLES);
  }
}


bool showContentArea = true;
void UpdateDrawFrame() {
  if (IsFileDropped()) {
    int count = 0;
    char **files = GetDroppedFiles(&count);
    if (count > 0) {
      unsigned int bytes = 0;
      unsigned char *data = LoadFileData(files[0], &bytes);
      if(bytes+1>MAX_CARTRIDGE_SIZE)bytes = MAX_CARTRIDGE_SIZE;
      printf("Dropped File: %s, %d bytes\n", files[0], bytes);
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

      switch (gb_state.cart.data[0x148]) {
      case 0x0:
        gb_state.cart.rom_size = 32 * 1024;
        break;
      case 0x1:
        gb_state.cart.rom_size = 64 * 1024;
        break;
      case 0x2:
        gb_state.cart.rom_size = 128 * 1024;
        break;
      case 0x3:
        gb_state.cart.rom_size = 256 * 1024;
        break;
      case 0x4:
        gb_state.cart.rom_size = 512 * 1024;
        break;
      case 0x5:
        gb_state.cart.rom_size = 1024 * 1024;
        break;
      case 0x6:
        gb_state.cart.rom_size = 2 * 1024 * 1024;
        break;
      case 0x7:
        gb_state.cart.rom_size = 4 * 1024 * 1024;
        break;
      case 0x8:
        gb_state.cart.rom_size = 8 * 1024 * 1024;
        break;
      case 0x52:
        gb_state.cart.rom_size = 1.1 * 1024 * 1024;
        break;
      case 0x53:
        gb_state.cart.rom_size = 1.2 * 1024 * 1024;
        break;
      case 0x54:
        gb_state.cart.rom_size = 1.5 * 1024 * 1024;
        break;
      default:
        gb_state.cart.rom_size = 32 * 1024;
        break;
      }

      switch (gb_state.cart.data[0x149]) {
      case 0x0:
        gb_state.cart.ram_size = 0;
        break;
      case 0x1:
        gb_state.cart.ram_size = 0;
        break;
      case 0x2:
        gb_state.cart.ram_size = 8 * 1024;
        break;
      case 0x3:
        gb_state.cart.ram_size = 32 * 1024;
        break;
      case 0x4:
        gb_state.cart.ram_size = 128 * 1024;
        break;
      case 0x5:
        gb_state.cart.ram_size = 64 * 1024;
        break;
      default:
        break;
      }
      emu_state.run_mode = SB_MODE_RESET;

      UnloadFileData(data);
    }
    ClearDroppedFiles();
  }
  sb_tick();                      
  sb_process_audio(&gb_state);

  // Draw
  //-----------------------------------------------------
  BeginDrawing();

  ClearBackground(RAYWHITE);
  sb_draw_sidebar((Rectangle){0, 0, 400, GetScreenHeight()});
                  
 
  Image screenIm = {
        .data = gb_state.lcd.framebuffer,
        .width = SB_LCD_W,
        .height = SB_LCD_H,
        .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
        .mipmaps = 1
  };
    
  Texture2D screenTex = LoadTextureFromImage(screenIm); 
  SetTextureFilter(screenTex, TEXTURE_FILTER_POINT);
  Rectangle rect;
  rect.x = 400;
  rect.y = 0;
  rect.width = GetScreenWidth()-400;
  rect.height = GetScreenHeight();

  DrawTextureQuad(screenTex, (Vector2){1.f,1.f}, (Vector2){0.0f,0.0},rect, (Color){255,255,255,255}); 
   
  EndDrawing();
  UnloadTexture(screenTex);
}

int main(void) {
  // Initialization
  //---------------------------------------------------------
  const int screenWidth = 1200;
  const int screenHeight = 700;

  // Set configuration flags for window creation
  SetConfigFlags(FLAG_VSYNC_HINT | FLAG_WINDOW_HIGHDPI | FLAG_WINDOW_RESIZABLE);
  InitWindow(screenWidth, screenHeight, "SkyBoy");
  InitAudioDevice();

  SetAudioStreamBufferSizeDefault(SB_AUDIO_BUFF_SAMPLES);
  audio_stream = InitAudioStream(SB_AUDIO_SAMPLE_RATE, 16, 1);
  PlayAudioStream(audio_stream);
  SetTraceLogLevel(LOG_WARNING);
#if defined(PLATFORM_WEB)
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
