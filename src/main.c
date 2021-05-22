/*****************************************************************************
 *
 *   SkyBoy GB Emulator
 *
 *   Copyright (c) 2021 Skyler "Sky" Saleh
 *
 **/

typedef void *sb_opcode_impl_t;
#include "raylib.h"
#include "sb_instr_tables.h"
#include <stdint.h>
#define RAYGUI_IMPLEMENTATION
#define RAYGUI_SUPPORT_ICONS
#include "raygui.h"
#if defined(PLATFORM_WEB)
#include <emscripten/emscripten.h>
#endif
Vector2 ballPosition = {200 / 2.0f, 200 / 2.0f};
Vector2 ballSpeed = {5.0f, 4.0f};
float ballRadius = 20;

int framesCounter = 0;

const int GUI_PADDING = 10;
const int GUI_ROW_HEIGHT = 30;
const int GUI_LABEL_HEIGHT = 0;
const int GUI_LABEL_PADDING = 5;
#define MAX_CARTRIDGE_SIZE 8 * 1024 * 1024
#define SB_U16_LO(A) ((A)&0xff)
#define SB_U16_HI(A) ((A >> 8) & 0xff)

// Extract bits from a bitfield
#define SB_BFE(VALUE, BITOFFSET, SIZE)                                         \
  (((VALUE) >> (BITOFFSET)) & ((2 << (SIZE)) - 1))
#define SB_MODE_RESET 0
#define SB_MODE_PAUSE 1
#define SB_MODE_RUN 2
#define SB_MODE_STEP 3

// Draw and process scroll bar style edition controls

typedef struct {
  int run_mode;          // [0: Reset, 1: Pause, 2: Run, 3: Step ]
  int step_instructions; // Number of instructions to advance while stepping
} sb_emu_state_t;

typedef struct {
  // Registers
  uint16_t af, bc, de, hl, sp, pc;
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

typedef struct {
  sb_gb_cpu_t cpu;
  sb_gb_mem_t mem;
  sb_gb_cartridge_t cart;
} sb_gb_t;

sb_emu_state_t emu_state = {0};
sb_gb_t gb_state = {0xffff};

uint16_t sb_read16(sb_gb_t *gb, int addr) {
  return *(uint16_t *)(gb->mem.data + addr);
}
uint8_t sb_read8(sb_gb_t *gb, int addr) { return gb->mem.data[addr]; }

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

Rectangle sb_draw_emu_state(Rectangle rect, sb_emu_state_t *emu_state) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);
  widget_rect.width =
      widget_rect.width / 4 - GuiGetStyle(TOGGLE, GROUP_PADDING) * 3 / 4;
  emu_state->run_mode =
      GuiToggleGroup(widget_rect, "Reset;Pause;Run;Step", emu_state->run_mode);

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_LABEL_PADDING,
                  &widget_rect, &inside_rect);

  GuiLabel(widget_rect, "Instructions to Step");
  sb_vertical_adv(inside_rect, GUI_ROW_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);

  int label_width = GetTextWidth("Instructions to Step");
  static bool edit_step_instructions = false;
  if (GuiSpinner(widget_rect, "", &emu_state->step_instructions, 1, 0x7fffffff,
                 edit_step_instructions))
    edit_step_instructions = !edit_step_instructions;

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
  for (int i = -3; i < 4; ++i) {
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
      GuiLabel(widget_rect, TextFormat("%04X", pc_render));
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
Rectangle sb_draw_cartridge_state(Rectangle rect,
                                  sb_gb_cartridge_t *cart_state) {

  Rectangle inside_rect = sb_inside_rect_after_padding(rect, GUI_PADDING);
  Rectangle widget_rect;

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Title: %s", cart_state->title));

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 10, &widget_rect,
                  &inside_rect);

  Rectangle wr = widget_rect;
  wr.width = GUI_PADDING;
  wr.height = GUI_PADDING;

  GuiCheckBox(wr,
              TextFormat("Game Boy Color (%s)",
                         (cart_state->game_boy_color) ? "true" : "false"),
              cart_state->game_boy_color);

  sb_vertical_adv(inside_rect, GUI_LABEL_HEIGHT, GUI_PADDING + 5, &widget_rect,
                  &inside_rect);
  GuiLabel(widget_rect, TextFormat("Cart Type: %d", cart_state->type));

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

  const char *flag_names[] = {"Z", "N", "H", "C", NULL};

  bool flag_values[] = {
      SB_BFE(cpu_state->af, 7, 1), // Z
      SB_BFE(cpu_state->af, 6, 1), // N
      SB_BFE(cpu_state->af, 5, 1), // H
      SB_BFE(cpu_state->af, 4, 1), // C
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
void sb_draw_sidebar(Rectangle rect) {
  GuiPanel(rect);
  Rectangle rect_inside = sb_inside_rect_after_padding(rect, GUI_PADDING);

  rect_inside = sb_draw_emu_state(rect_inside, &emu_state);
  rect_inside = sb_draw_cartridge_state(rect_inside, &gb_state.cart);
  rect_inside = sb_draw_cpu_state(rect_inside, &gb_state.cpu, &gb_state);
  if (emu_state.run_mode == SB_MODE_STEP) {
    emu_state.run_mode = SB_MODE_PAUSE;
    gb_state.cpu.pc++;
  }
  if (emu_state.run_mode == SB_MODE_RUN) {
    gb_state.cpu.pc++;
  }
  if (emu_state.run_mode == SB_MODE_RESET) {
    gb_state.cpu.pc = 0x100;
  }
}

Rectangle panelRec = {20, 40, 200, 150};
Rectangle panelContentRec = {0, 0, 340, 340};
Vector2 panelScroll = {99, -20};

bool showContentArea = true;
void UpdateDrawFrame() {
  if (IsFileDropped()) {
    int count = 0;
    char **files = GetDroppedFiles(&count);
    if (count > 0) {
      unsigned int bytes = 0;
      unsigned char *data = LoadFileData(files[0], &bytes);
      printf("Dropped File: %s, %d bytes\n", files[0], bytes);

      for (size_t i = 0; i < bytes; ++i) {
        gb_state.mem.data[i] = gb_state.cart.data[i] = data[i];
      }
      // Copy Header
      for (int i = 0; i < 11; ++i) {
        gb_state.cart.title[i] = gb_state.cart.data[i + 0x134];
      }
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

  // Bouncing ball logic
  ballPosition.x += ballSpeed.x * GetFrameTime() * 60.;
  ballPosition.y += ballSpeed.y * GetFrameTime() * 60.;
  if ((ballPosition.x >= (GetScreenWidth() - ballRadius)) ||
      (ballPosition.x <= ballRadius))
    ballSpeed.x *= -1.0f;
  if ((ballPosition.y >= (GetScreenHeight() - ballRadius)) ||
      (ballPosition.y <= ballRadius))
    ballSpeed.y *= -1.0f;
  //-----------------------------------------------------

  // Draw
  //-----------------------------------------------------
  BeginDrawing();

  if (IsWindowState(FLAG_WINDOW_TRANSPARENT))
    ClearBackground(BLANK);
  else
    ClearBackground(RAYWHITE);

  DrawCircleV(ballPosition, ballRadius, MAROON);
  DrawRectangleLinesEx(
      (Rectangle){0, 0, (float)GetScreenWidth(), (float)GetScreenHeight()}, 4,
      RAYWHITE);

  DrawCircleV(GetMousePosition(), 10, DARKBLUE);

  sb_draw_sidebar((Rectangle){0, 0, 400, GetScreenHeight()});

  EndDrawing();
}

int main(void) {
  // Initialization
  //---------------------------------------------------------
  const int screenWidth = 1200;
  const int screenHeight = 700;

  // Set configuration flags for window creation
  SetConfigFlags(FLAG_VSYNC_HINT | FLAG_WINDOW_HIGHDPI | FLAG_WINDOW_RESIZABLE);
  InitWindow(screenWidth, screenHeight, "raylib [core] example - window flags");

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
