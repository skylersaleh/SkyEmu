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
#include "sb_gb.h"
#include <stdint.h>                      
#include <math.h>
#define RAYGUI_IMPLEMENTATION
#define RAYGUI_SUPPORT_ICONS
#include "raygui.h"
#if defined(PLATFORM_WEB)
#include <emscripten/emscripten.h>
#endif


sb_emu_state_t emu_state = {.pc_breakpoint = -1};

AudioStream audio_stream;

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
    GuiGroupBox(state_rect, TextFormat("Emulator State [FPS: %i]", GetFPS()));
  }
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

    for(int i=0;i<SB_LCD_W*SB_LCD_H*3;++i){
      gb_state.lcd.framebuffer[i] = 127;
    }
    emu_state.run_mode = SB_MODE_RUN;
  }
  
  if (emu_state.rom_loaded&&(emu_state.run_mode == SB_MODE_RUN||emu_state.run_mode ==SB_MODE_STEP)) {
    
    int instructions_to_execute = emu_state.step_instructions;
    if(instructions_to_execute==0)instructions_to_execute=60000;
    for(int i=0;i<instructions_to_execute;++i){
    
        bool double_speed = false;
        sb_update_joypad_io_reg(&emu_state, &gb_state);
        int dma_delta_cycles = sb_update_dma(&gb_state);
        int cpu_delta_cycles = 4;
        if(dma_delta_cycles==0){
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
          if(gb_state.cpu.deferred_interrupt_enable){
            gb_state.cpu.deferred_interrupt_enable = false;
            gb_state.cpu.interrupt_enable = true;
          }
             
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

  rect_inside = sb_draw_emu_state(rect_inside, &emu_state,&gb_state,false);
  if(emu_state.panel_mode==SB_PANEL_TILEMAPS) rect_inside = sb_draw_tile_map_state(rect_inside, &gb_state);
  else if(emu_state.panel_mode==SB_PANEL_TILEDATA) rect_inside = sb_draw_tile_data_state(rect_inside, &gb_state);
  else if(emu_state.panel_mode==SB_PANEL_CPU){
    rect_inside = sb_draw_debug_state(rect_inside, &emu_state,&gb_state);
    rect_inside = sb_draw_cartridge_state(rect_inside, &gb_state.cart);
    rect_inside = sb_draw_interrupt_state(rect_inside, &gb_state);
    rect_inside = sb_draw_timer_state(rect_inside, &gb_state);
    rect_inside = sb_draw_dma_state(rect_inside, &gb_state);
    rect_inside = sb_draw_joypad_state(rect_inside, &gb_state.joy);
    rect_inside = sb_draw_cpu_state(rect_inside, &gb_state.cpu, &gb_state);
  }
                               
}
void sb_draw_top_panel(Rectangle rect) {
  GuiPanel(rect);
  sb_draw_emu_state(rect, &emu_state,&gb_state, true);
}


void sb_load_rom( const char* file_path){
  
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
  if(!TextIsEqual("",new_path))sb_load_rom(new_path);
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

void sb_draw_onscreen_controller(sb_gb_t*gb, Rectangle rect){
  Color fill_color = {200,200,200,255};
  Color sel_color = {150,150,150,255};
  Color line_color = {127,127,127,255};
  float button_r = rect.width*0.09;

  float dpad_sz0 = rect.width*0.055;
  float dpad_sz1 = rect.width*0.20;


  Vector2 a_pos = {rect.width*0.85,rect.height*0.3};
  Vector2 b_pos = {rect.width*0.65,rect.height*0.5};
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
    if(sb_distance(points[i],a_pos)<button_r*1.25)a=true;
    if(sb_distance(points[i],b_pos)<button_r*1.25)b=true;

    int dx = points[i].x-dpad_pos.x;
    int dy = points[i].y-dpad_pos.y;
    if(dx>=-dpad_sz1 && dx<=dpad_sz1 && dy>=-dpad_sz1 && dy<=dpad_sz1 ){
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
  widget_rect.width = (rect.width-GUI_PADDING*2)/2;
  widget_rect.height = GUI_ROW_HEIGHT;
   
  int button = GuiToggleGroup(widget_rect, "Start;Select", -1);
  
  gb->joy.left  |= left;
  gb->joy.right |= right;
  gb->joy.up    |= up;
  gb->joy.down  |= down;
  gb->joy.a |= a;
  gb->joy.b |= b;
  gb->joy.start |= button==0;
  gb->joy.select |= button==1; 
}

void UpdateDrawFrame() {
  if (IsFileDropped()) {
    int count = 0;
    char **files = GetDroppedFiles(&count);
    if (count > 0) {
      sb_load_rom(files[0]);
    }
    ClearDroppedFiles();
  }
  if(gb_state.cart.ram_is_dirty){
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
  sb_tick();                  
  bool mute = emu_state.run_mode != SB_MODE_RUN;
  sb_process_audio(&gb_state, mute);

  // Draw
  //-----------------------------------------------------
  BeginDrawing();

  sb_poll_controller_input(&gb_state);
  Image screenIm = {
        .data = gb_state.lcd.framebuffer,
        .width = SB_LCD_W,
        .height = SB_LCD_H,
        .format = PIXELFORMAT_UNCOMPRESSED_R8G8B8,
        .mipmaps = 1
  };
    
  Texture2D screenTex = LoadTextureFromImage(screenIm); 
  SetTextureFilter(screenTex, TEXTURE_FILTER_POINT); 
  ClearBackground(RAYWHITE);
  int screen_width = GetScreenWidth();
  int screen_height = GetScreenHeight();

                   
  Rectangle lcd_rect;
  lcd_rect.x = 400;
  lcd_rect.y = 0;
  lcd_rect.width = GetScreenWidth()-400;
  lcd_rect.height = GetScreenHeight();
   
  float lcd_aspect = 144/160.;                                        
  int panel_height = 30+GUI_PADDING; 
  if((screen_width-400)/(float)screen_height>160/144.*0.7){
    // Widescreen
    sb_draw_sidebar((Rectangle){0, 0, 400, GetScreenHeight()});
  }else if (screen_width*lcd_aspect/(float)(screen_height)<0.66){
    // Tall Screen
    //sb_draw_top_panel((Rectangle){0, 0, GetScreenWidth(), panel_height});
    lcd_rect = (Rectangle){0, 0, GetScreenWidth(),GetScreenWidth()*lcd_aspect};

    Rectangle cont_rect;
    cont_rect.x=0;
    cont_rect.y = lcd_rect.y+lcd_rect.height;
    cont_rect.width = GetScreenWidth();
    cont_rect.height= GetScreenHeight()-cont_rect.y;
    sb_draw_onscreen_controller(&gb_state,cont_rect); 
  }else{
    // Square Screen
    lcd_rect = (Rectangle){0, panel_height, GetScreenWidth(),GetScreenHeight()-panel_height};
    sb_draw_top_panel((Rectangle){0, 0, GetScreenWidth(), panel_height});
  }
  
  DrawTextureQuad(screenTex, (Vector2){1.f,1.f}, (Vector2){0.0f,0.0},lcd_rect, (Color){255,255,255,255}); 
  sb_draw_load_rom_prompt(lcd_rect,emu_state.rom_loaded==false);
  EndDrawing();
  if(!IsAudioStreamPlaying(audio_stream))PlayAudioStream(audio_stream);
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
