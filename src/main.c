/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
**/

#define SE_AUDIO_SAMPLE_RATE 44100
#define SE_AUDIO_BUFF_SAMPLES 2048
#define SE_AUDIO_BUFF_CHANNELS 2

#include "raylib.h"
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

#include "gb.h"
#define SB_NUM_SAVE_STATES 5

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
    widget_rect.x+=(inside_rect.width-widget_rect.width*4- GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4)*0.5;
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
    if(emu_state->system == SYSTEM_GB){
      widget_rect.width = widget_rect.width / 4 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4;
      emu_state->panel_mode =
          GuiToggleGroup(widget_rect, "CPU;Tile Maps;Tile Data;Audio", emu_state->panel_mode);
    }else{
      widget_rect.width = widget_rect.width / 3 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 2 / 3;
      const int button_state[]={SB_PANEL_CPU,SB_PANEL_IO,SB_PANEL_AUDIO,-1};
      int curr_button = 0;
      for(int i=0;i<sizeof(button_state)/sizeof(button_state[0]);++i)
        if(button_state[i]==emu_state->panel_mode)curr_button = i;

      curr_button = GuiToggleGroup(widget_rect, "CPU;IO Regs;Audio", curr_button);
      emu_state->panel_mode=button_state[curr_button];

    }

    sb_vertical_adv(rect, inside_rect.y - rect.y, GUI_PADDING, &state_rect,
                    &adv_rect);
    GuiGroupBox(state_rect, TextFormat("Emulator State [FPS: %f]", 1.0/emu_state->avg_frame_time));
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

  inside_rect = sb_draw_label(inside_rect, "Instructions to Step");

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);

  static bool edit_step_instructions = false;
  if (GuiSpinner(widget_rect, "", &emu_state->step_instructions, 0, 0x7fffffff,
                 edit_step_instructions))
    edit_step_instructions = !edit_step_instructions;

  inside_rect = sb_draw_label(inside_rect, "Breakpoint PC");
  
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
  inside_rect = sb_draw_label(inside_rect,TextFormat("DMA SRC: %x", dma_src));
  inside_rect = sb_draw_label(inside_rect, TextFormat("DMA DST: %x", dma_dst));
  inside_rect = sb_draw_label(inside_rect, TextFormat("Length (16B chunks): %d", len));

  inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  inside_rect.x +=rect.width/2;
  inside_rect = sb_draw_label(inside_rect, TextFormat("Bytes Transferred: %d", gb->dma.bytes_transferred));

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
  inside_rect = sb_draw_label(inside_rect, TextFormat("DIV: %d", div));
  inside_rect = sb_draw_label(inside_rect, TextFormat("TIMA: %d", tima));
  inside_rect = sb_draw_label(inside_rect, TextFormat("TMA: %d", tma));

  inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  inside_rect.x +=rect.width/2;
  inside_rect = sb_draw_label(inside_rect,TextFormat("CLKs to DIV: %d", gb->timers.clocks_till_div_inc));
  inside_rect = sb_draw_label(inside_rect, TextFormat("CLKs to TIMA: %d", gb->timers.clocks_till_tima_inc));
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
  }else if(emu_state.system==SYSTEM_GBA){
    const char * backup_type[]={"None","EEPROM", "EEPROM (512B)", "EEPROM (8kB)", "SRAM","FLASH (64 kB)", "FLASH (128 kB)"};
    inside_rect=sb_draw_label(inside_rect, TextFormat("Backup Type: %s", backup_type[gba.cart.backup_type]));
    inside_rect=sb_draw_label(inside_rect, TextFormat("Save Path: %s", gba.cart.save_file_path));
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

Rectangle gba_draw_io_state(Rectangle rect, gba_t* gba){
  for(int i = 0; i<sizeof(gba_io_reg_desc)/sizeof(gba_io_reg_desc[0]);++i){
    Rectangle r = sb_inside_rect_after_padding(rect, GUI_PADDING);
    uint32_t addr = gba_io_reg_desc[i].addr;
    uint16_t data = gba_read16(gba, addr);
    bool has_fields = false;
    for(int f = 0; f<sizeof(gba_io_reg_desc[i].bits)/sizeof(gba_io_reg_desc[i].bits[0]);++f){
      uint32_t start = gba_io_reg_desc[i].bits[f].start; 
      uint32_t size = gba_io_reg_desc[i].bits[f].size; 
      if(size){
        uint32_t field_data = SB_BFE(data,start,size);
        has_fields=true;
        Rectangle r2 = r; 
        if(size>1)r=sb_draw_label(r, TextFormat("[%d:%d]:", start, start+size-1));
        else r=sb_draw_label(r, TextFormat("%d:", start));

        r2.x+=30; 
        sb_draw_label(r2, TextFormat("%2d",field_data));
        r2.x+=25; 
        sb_draw_label(r2, TextFormat("%s",gba_io_reg_desc[i].bits[f].name));
      }
    }
    Rectangle state_rect, adv_rect;
    sb_vertical_adv(rect, r.y - rect.y, GUI_PADDING, &state_rect, &adv_rect);
    GuiGroupBox(state_rect, TextFormat("%s(%08x): %04x", gba_io_reg_desc[i].name, addr,data)); 
    rect=adv_rect;
  }
  return rect;
}
Rectangle sb_draw_tile_map_state(Rectangle rect, sb_gb_t *gb) {
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

double se_fps_counter(int tick){
  static int call = -1;
  static double last_t = 0;
  static double fps = 60; 
  if(call==-1){
    call = 0;
    last_t = GetTime();
  }
  call+=tick;
  
  if(call>=5){
    double t = GetTime();
    fps = ((double)call)/(t-last_t);
    call=0;
    last_t = t;
  }
  return fps; 
}
Rectangle sb_draw_audio_state(Rectangle rect, sb_gb_t*gb){
  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,&inside_rect);

  float fifo_size = sb_ring_buffer_size(&emu_state.audio_ring_buff);
  GuiLabel(widget_rect, TextFormat("FIFO Size: %4f (%4f)", fifo_size,fifo_size/SB_AUDIO_RING_BUFFER_SIZE));

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", fifo_size/SB_AUDIO_RING_BUFFER_SIZE, 0, 1);
  for(int i=0;i<4;++i){
    inside_rect = sb_draw_label(inside_rect,TextFormat("Channel %d",i+1));
    sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
    GuiProgressBar(widget_rect, "", "", emu_state.audio_channel_output[i], 0, 1);
  } 
  if(emu_state.system==SYSTEM_GBA){
    inside_rect = sb_draw_label(inside_rect,TextFormat("FIFO Channel A"));
    sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
    GuiProgressBar(widget_rect, "", "", emu_state.audio_channel_output[4], 0, 1);

    inside_rect = sb_draw_label(inside_rect,TextFormat("FIFO Channel B"));
    sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
    GuiProgressBar(widget_rect, "", "", emu_state.audio_channel_output[5], 0, 1);
  }

  inside_rect = sb_draw_label(inside_rect, "Mix Volume (R)");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", emu_state.mix_r_volume, 0, 1);
   
  inside_rect = sb_draw_label(inside_rect, "Mix Volume (L)");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect, &inside_rect);
  GuiProgressBar(widget_rect, "", "", emu_state.mix_l_volume, 0, 1);
   
  inside_rect = sb_draw_label(inside_rect, "Output Waveform");
   
  sb_vertical_adv(inside_rect, 128, GUI_PADDING, &widget_rect, &inside_rect);
  
  Color outline_color = GetColor(GuiGetStyle(DEFAULT,BORDER_COLOR_NORMAL));
  Color line_color = GetColor(GuiGetStyle(DEFAULT,BORDER_COLOR_FOCUSED));
  DrawRectangleLines(widget_rect.x,widget_rect.y,widget_rect.width,widget_rect.height,outline_color);
  int old_v = 0;
  static Vector2 points[512];
  for(int i=0;i<widget_rect.width;++i){
    int entry = (emu_state.audio_ring_buff.read_ptr+i)%SB_AUDIO_RING_BUFFER_SIZE;
    int value = emu_state.audio_ring_buff.data[entry]/256/2;
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
  Rectangle view = GuiScrollPanel(rect_inside, last_rect, &scroll);
  Vector2 view_scale = GetWindowScaleDPI();
  //Begin scissor is broken on non-web platforms
#ifdef PLATFORM_WEB
  BeginScissorMode(view.x*view_scale.x, view.y*view_scale.y,view.width*view_scale.x, view.height*view_scale.y);
#endif
  rect_inside.y+=scroll.y;
  int starty = rect_inside.y;
  rect_inside.y+=GUI_PADDING; 
  rect_inside.x+=GUI_PADDING;
  rect_inside.width = view.width-GUI_PADDING*1.5;
  if(emu_state.panel_mode==SB_PANEL_TILEMAPS){
    rect_inside = sb_draw_tile_map_state(rect_inside, &gb_state);
  }else if(emu_state.panel_mode==SB_PANEL_IO){
    rect_inside = gba_draw_io_state(rect_inside, &gba);
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
  last_rect.width = view.width-GUI_PADDING;
  last_rect.height = rect_inside.y-starty;
#ifdef PLATFORM_WEB
  EndScissorMode();
#endif
}
void sb_draw_top_panel(Rectangle rect) {
  GuiPanel(rect);
  sb_draw_emu_state(rect, &emu_state,&gb_state, true);
}

void sb_update_audio_stream_from_fifo(sb_gb_t*gb, bool global_mute){
  static int16_t audio_buff[SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS*2];
  int size = sb_ring_buffer_size(&emu_state.audio_ring_buff);
  if(global_mute){
    if(IsAudioStreamProcessed(audio_stream)){
      for(int i=0;i<SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS;++i)audio_buff[i]=0;
      UpdateAudioStream(audio_stream, audio_buff, SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS);
    }
  }
  if(IsAudioStreamProcessed(audio_stream)){
    //Fill up Audio buffer from ring_buffer
    for(int i=0; i< SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS; ++i){
    
      unsigned read_entry =0;
      if(sb_ring_buffer_size(&emu_state.audio_ring_buff)>0)
        read_entry=(emu_state.audio_ring_buff.read_ptr++)%SB_AUDIO_RING_BUFFER_SIZE;
      audio_buff[i]= emu_state.audio_ring_buff.data[read_entry];
    }

    UpdateAudioStream(audio_stream, audio_buff, SE_AUDIO_BUFF_SAMPLES*SE_AUDIO_BUFF_CHANNELS);
  }
}

bool sb_load_rom(const char* file_path, const char* save_file){
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
  const char * c = GetFileNameWithoutExt(filename);
  const char * base = GetDirectoryPath(filename);
#if defined(PLATFORM_WEB)
      const char * save_file = TextFormat("/offline/%s.sav",c);
#else
      const char * save_file = TextFormat("%s/%s.sav",base, c);
#endif
  printf("Loading ROM: %s\n", filename); 
  emu_state.rom_loaded = false; 
  if(gba_load_rom(&gba, filename,save_file)){
    emu_state.system = SYSTEM_GBA;
    emu_state.rom_loaded = true;
  }
  if(sb_load_rom(filename,save_file)){
    emu_state.system = SYSTEM_GB;
    emu_state.rom_loaded = true; 
  }
  if(emu_state.rom_loaded==false)printf("Unknown ROM type: %s\n", filename);
  else{
    emu_state.run_mode= SB_MODE_RESET;
    static bool init_audio= false;
    if(init_audio==false&&emu_state.rom_loaded){
      printf("Initializing Audio\n");
      InitAudioDevice();
      SetAudioStreamBufferSizeDefault(SE_AUDIO_BUFF_SAMPLES);
      audio_stream = LoadAudioStream(SE_AUDIO_SAMPLE_RATE, 16, SE_AUDIO_BUFF_CHANNELS);
      PlayAudioStream(audio_stream);
      init_audio=true;
    }
  }
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
  //if(IsMouseButtonDown(0))points[p++] = GetMousePosition();
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
  Color color = {0,0,0,127};
  int scale = 1;
  const char* label = TextFormat("FPS:%.2f",1./emu_state.avg_frame_time);
  Vector2 label_sz= MeasureTextEx(GetFontDefault(), label, scale*10/2,scale/2);
  DrawText(label,rect.x+rect.width/2-label_sz.x/2,rect.y+5,scale*10/2,color);


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
  if(emu_state.system== SYSTEM_GB){
    if(gb_state.cart.ram_is_dirty && frames_since_last_save>10){
      frames_since_last_save = 0; 
      if(SaveFileData(gb_state.cart.save_file_path,gb_state.cart.ram_data,gb_state.cart.ram_size)){
   #if defined(PLATFORM_WEB)
        // Don't forget to sync to make sure you store it to IndexedDB
      EM_ASM( FS.syncfs(function (err) {}); );
   #endif
        printf("Saved %s\n", gb_state.cart.save_file_path);
      }else printf("Failed to write out save file: %s\n",gb_state.cart.save_file_path);
      gb_state.cart.ram_is_dirty=false;
    }
  }else if(emu_state.system ==SYSTEM_GBA){
    if(gba.cart.backup_is_dirty && frames_since_last_save>10){
      frames_since_last_save = 0; 
      int size = 0; 
      switch(gba.cart.backup_type){
        case GBA_BACKUP_NONE       : size = 0;       break;
        case GBA_BACKUP_EEPROM     : size = 8*1024;  break;
        case GBA_BACKUP_EEPROM_512B: size = 512;     break;
        case GBA_BACKUP_EEPROM_8KB : size = 8*1024;  break;
        case GBA_BACKUP_SRAM       : size = 32*1024; break;
        case GBA_BACKUP_FLASH_64K  : size = 64*1024; break;
        case GBA_BACKUP_FLASH_128K : size = 128*1024;break;
      }
      if(size){
        if(SaveFileData(gba.cart.save_file_path,gba.mem.cart_backup,size)){
          #if defined(PLATFORM_WEB)
              EM_ASM( FS.syncfs(function (err) {}););
          #endif
          printf("Saved %s\n", gba.cart.save_file_path);
        }else printf("Failed to write out save file: %s\n",gba.cart.save_file_path);
      }
      gba.cart.backup_is_dirty=false;
    }
  }
  emu_state.frame=0;
  if(emu_state.system == SYSTEM_GB)sb_tick(&emu_state,&gb_state);
  else if(emu_state.system == SYSTEM_GBA)gba_tick(&emu_state, &gba);
 
  emu_state.avg_frame_time = 1.0/se_fps_counter(emu_state.frame);
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
  float lcd_aspect = SB_LCD_H/(float)SB_LCD_W;
  if(emu_state.system==SYSTEM_GBA){
    lcd_aspect= GBA_LCD_H/(float)GBA_LCD_W;
  }
  int panel_height = 30+GUI_PADDING;
  if(screen_width-GetScreenHeight()/lcd_aspect>350){
    // Widescreen
    panel_width = screen_width-GetScreenHeight()/lcd_aspect;
    lcd_rect = (Rectangle){panel_width, 0, GetScreenHeight()/lcd_aspect,GetScreenHeight()};

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
    float height = GetScreenHeight()-panel_height;
    if(GetScreenWidth()*lcd_aspect>height){
      //Too wide
      float extra_space = GetScreenWidth()-GetScreenHeight()/lcd_aspect;
      lcd_rect = (Rectangle){extra_space*0.5, panel_height, GetScreenHeight()/lcd_aspect,height};
    }else{
      //Too tall
      float extra_space = GetScreenHeight()-GetScreenWidth()*lcd_aspect;
      lcd_rect = (Rectangle){0, panel_height+extra_space*0.5, GetScreenWidth(),GetScreenWidth()*lcd_aspect};
    }
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
  SetTextureFilter(screenTex, lcd_rect.width<screenIm.width*2?TEXTURE_FILTER_BILINEAR:TEXTURE_FILTER_POINT);
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
  SetConfigFlags(FLAG_VSYNC_HINT  | FLAG_WINDOW_RESIZABLE | FLAG_WINDOW_HIGHDPI | FLAG_MSAA_4X_HINT);
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
  while (!WindowShouldClose()) UpdateDrawFrame();
#endif

  CloseWindow(); // Close window and OpenGL context

  return 0;
}
