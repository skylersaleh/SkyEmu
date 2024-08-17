#include "libretro.h"

#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <math.h>
#include <limits.h>

#include "shared.h"
#include "sb_types.h"
#include "gb.h"
#include "gba.h"
#include "nds.h"
#include "localization.h"

#define SKYEMU_LIBRETRO_VERSION "0.1.0"

static retro_video_refresh_t video_refresh_cb = NULL;
static retro_input_poll_t input_poll_cb = NULL;
static retro_input_state_t input_state_cb = NULL;
static retro_audio_sample_batch_t audio_sample_batch_cb = NULL;
static retro_environment_t env_cb = NULL;
static retro_log_printf_t log_cb = NULL;

sb_emu_state_t emu_state;

enum opts_core_override {
  OPTS_CORE_OVERRIDE_AUTOMATIC,
  OPTS_CORE_OVERRIDE_GB,
  OPTS_CORE_OVERRIDE_GBA,
  OPTS_CORE_OVERRIDE_NDS, 
};

struct {
  enum opts_core_override core_override;
  bool gb_use_bios;
  bool gba_use_bios;
  bool nds_use_bios; 
} gopts;

#define OPTS_VAL_ON "ON"
#define OPTS_VAL_OFF "OFF"

#define OPTS_KEY_SYSTEM_CORE_OVERRIDE "system_core_override"
#define OPTS_VAL_SYSTEM_CORE_OVERRIDE_AUTOMATIC "Automatic"
#define OPTS_VAL_SYSTEM_CORE_OVERRIDE_GB "Game Boy"
#define OPTS_VAL_SYSTEM_CORE_OVERRIDE_GBA "Game Boy Advance"
#define OPTS_VAL_SYSTEM_CORE_OVERRIDE_NDS "Nintendo DS"

#define OPTS_KEY_SYSTEM_GB_ENABLE_BIOS "system_gb_bios_enable"
#define OPTS_KEY_SYSTEM_GBA_ENABLE_BIOS "system_gba_bios_enable"
#define OPTS_KEY_SYSTEM_NDS_ENABLE_BIOS "system_nds_bios_enable"

void opts_initialize() {
  static struct retro_core_option_v2_category categories_default[] = {
    { .key = "system", .desc = "System Settings", .info = NULL },
    {0}
  };

  static struct retro_core_option_v2_definition shared_opts[] = {
    {
      OPTS_KEY_SYSTEM_CORE_OVERRIDE,
      "Core Override",
      NULL,
      "Determines which core is used",
      NULL,
      "system",
      {
        { OPTS_VAL_SYSTEM_CORE_OVERRIDE_AUTOMATIC, NULL },
        { OPTS_VAL_SYSTEM_CORE_OVERRIDE_GB, NULL },
        { OPTS_VAL_SYSTEM_CORE_OVERRIDE_GBA, NULL },
        { OPTS_VAL_SYSTEM_CORE_OVERRIDE_NDS, NULL },
        {0}
      },
      OPTS_VAL_SYSTEM_CORE_OVERRIDE_AUTOMATIC,
    },
    {
      OPTS_KEY_SYSTEM_GB_ENABLE_BIOS,
      "Game Boy Firmware",
      NULL,
      "Game Boy Firmware Enabled",
      NULL,
      "system",
      {
        { OPTS_VAL_ON, NULL },
        { OPTS_VAL_OFF, NULL },
        {0}
      },
      OPTS_VAL_ON,
    },
    {
      OPTS_KEY_SYSTEM_GBA_ENABLE_BIOS,
      "Game Boy Advance Firmware",
      NULL,
      "Game Boy Advance Firmware Enabled",
      NULL,
      "system",
      {
        { OPTS_VAL_ON, NULL },
        { OPTS_VAL_OFF, NULL },
        {0}
      },
      OPTS_VAL_ON,
    },
    {
      OPTS_KEY_SYSTEM_NDS_ENABLE_BIOS,
      "Nintendo DS Firmware",
      NULL,
      "Nintendo DS Firmware Enabled",
      NULL,
      "system",
      {
        { OPTS_VAL_ON, NULL },
        { OPTS_VAL_OFF, NULL },
        {0}
      },
      OPTS_VAL_ON,
    },
    {0}
  };

  static struct retro_core_option_v2_category opts_cat[SE_MAX_LANG_VALUE][sizeof categories_default / sizeof *categories_default];
  static struct retro_core_option_v2_definition opts_def[SE_MAX_LANG_VALUE][sizeof shared_opts / sizeof *shared_opts];
  static struct retro_core_options_v2 opts_langs[SE_MAX_LANG_VALUE];

  struct { unsigned sky_emu_language; unsigned retro_language; } support[] = {
    { SE_LANG_ENGLISH, RETRO_LANGUAGE_ENGLISH },
    { SE_LANG_ARABIC, RETRO_LANGUAGE_ARABIC },
    { SE_LANG_CHINESE, RETRO_LANGUAGE_CHINESE_SIMPLIFIED },
    { SE_LANG_CHINESE, RETRO_LANGUAGE_CHINESE_TRADITIONAL },
    { SE_LANG_DUTCH, RETRO_LANGUAGE_DUTCH },
    { SE_LANG_FRENCH, RETRO_LANGUAGE_FRENCH },
    { SE_LANG_GERMAN, RETRO_LANGUAGE_GERMAN },
    { SE_LANG_GREEK, RETRO_LANGUAGE_GREEK },
    { SE_LANG_ITALIAN, RETRO_LANGUAGE_ITALIAN },
    { SE_LANG_JAPANESE, RETRO_LANGUAGE_JAPANESE },
    { SE_LANG_KOREAN, RETRO_LANGUAGE_KOREAN },
    { SE_LANG_POLISH, RETRO_LANGUAGE_POLISH },
    { SE_LANG_PORTUGESE, RETRO_LANGUAGE_PORTUGUESE_PORTUGAL },
    { SE_LANG_RUSSIAN, RETRO_LANGUAGE_RUSSIAN },
    { SE_LANG_SPANISH, RETRO_LANGUAGE_SPANISH },
  };

  unsigned local;
  int skyemu_local = -1;
  env_cb(RETRO_ENVIRONMENT_GET_LANGUAGE, &local);
  for (int s = 0; s < sizeof support / sizeof *support; ++s) {
    unsigned l = support[s].sky_emu_language;
    if (support[s].retro_language == local) {
      skyemu_local = l;
    }
    se_set_language(l);

    int i = 0;
    for (; i < (sizeof opts_cat[l] / sizeof *opts_cat[l]) - 1; ++i) {
      opts_cat[l][i].key = categories_default[i].key;
      opts_cat[l][i].desc = se_localize(categories_default[i].desc);
      opts_cat[l][i].info = categories_default[i].info ? se_localize(categories_default[i].info) : NULL;
    }
    memset(&opts_cat[i], 0, sizeof *opts_cat);

    for (i = 0; i < (sizeof shared_opts / sizeof *shared_opts) - 1; ++i) {
      opts_def[l][i].key = shared_opts[i].key;
      opts_def[l][i].category_key = shared_opts[i].category_key;
      memcpy(opts_def[l][i].values, shared_opts[i].values, sizeof opts_def[l][i].values);
      opts_def[l][i].default_value = shared_opts[i].default_value;
      opts_def[l][i].desc = se_localize(shared_opts[i].desc);
      opts_def[l][i].info = se_localize(shared_opts[i].info);
      opts_def[l][i].desc_categorized = shared_opts[i].desc_categorized ? se_localize(shared_opts[i].desc_categorized) : NULL;
      opts_def[l][i].info_categorized = shared_opts[i].info_categorized ? se_localize(shared_opts[i].info_categorized) : NULL;
    }
    memset(&opts_def[l][i], 0, sizeof *opts_def[l]);

    opts_langs[l].categories = opts_cat[l];
    opts_langs[l].definitions = opts_def[l];
  }

  static struct retro_core_options_v2_intl opts;
  opts.us = &opts_langs[SE_LANG_ENGLISH];
  opts.local = skyemu_local >= 0 ? &opts_langs[skyemu_local] : NULL;

  env_cb(RETRO_ENVIRONMENT_SET_CORE_OPTIONS_V2_INTL, &opts);
}

void opts_reload_all() {
  struct retro_variable var;

  var.key = OPTS_KEY_SYSTEM_CORE_OVERRIDE;
  env_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var);
  if (strcmp(var.value, OPTS_VAL_SYSTEM_CORE_OVERRIDE_GB) == 0)
    gopts.core_override = OPTS_CORE_OVERRIDE_GB;
  else if (strcmp(var.value, OPTS_VAL_SYSTEM_CORE_OVERRIDE_GBA) == 0) 
    gopts.core_override = OPTS_CORE_OVERRIDE_GBA;
  else if (strcmp(var.value, OPTS_VAL_SYSTEM_CORE_OVERRIDE_NDS) == 0)
    gopts.core_override = OPTS_CORE_OVERRIDE_NDS;
  else
    gopts.core_override = OPTS_CORE_OVERRIDE_AUTOMATIC;

  var.key = OPTS_KEY_SYSTEM_GB_ENABLE_BIOS;
  env_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var);
  gopts.gb_use_bios = strcmp(var.value, OPTS_VAL_ON) == 0;

  var.key = OPTS_KEY_SYSTEM_GBA_ENABLE_BIOS;
  env_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var);
  gopts.gba_use_bios = strcmp(var.value, OPTS_VAL_ON) == 0;

  var.key = OPTS_KEY_SYSTEM_NDS_ENABLE_BIOS;
  env_cb(RETRO_ENVIRONMENT_GET_VARIABLE, &var);
  gopts.nds_use_bios = strcmp(var.value, OPTS_VAL_ON) == 0;  
}

bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t* data, size_t data_size) {
  (void)base_path;
  const char* syspath;
  env_cb(RETRO_ENVIRONMENT_GET_SYSTEM_DIRECTORY, &syspath);
  if (!syspath) return false;
  char bios_path[PATH_MAX];
  snprintf(bios_path, sizeof bios_path, "%s/SkyEmu/%s", syspath, file_name);

  log_cb(RETRO_LOG_INFO, "opening bios file: %s\n", bios_path);
  FILE* biosf = fopen(bios_path, "rb");
  if (!biosf) {
    return false;
  }
  fseek(biosf, 0, SEEK_END);
  long int size = ftell(biosf);
  fseek(biosf, 0, SEEK_SET);

  if (size > data_size) {
    fclose(biosf);
    return false;
  }

  bool did_read = false;
  if (
    (emu_state.system == SYSTEM_GB && gopts.gb_use_bios)
    || (emu_state.system == SYSTEM_GBA && gopts.gba_use_bios)
    || (emu_state.system == SYSTEM_NDS && gopts.nds_use_bios)
  ) {
    memset(data, 0, data_size);
    fread(data, size, 1, biosf);
    log_cb(RETRO_LOG_INFO, "successfully loaded firmware data '%s'", bios_path);
    did_read = true;
  }
  fclose(biosf);
  return did_read;
}

/* ------------------ RETROARCH GB ----------------- */

static gb_scratch_t gb_scratch;
static sb_gb_t gb;

void retro_gb_init(){
  static struct retro_memory_descriptor mdesc[9];
  // rom
  mdesc[0].ptr = gb.mem.data;
  mdesc[0].start = 0x0000;
  mdesc[0].len = 0x4000;
  mdesc[0].flags = RETRO_MEMDESC_CONST;

  mdesc[1].ptr = gb.mem.data;
  mdesc[1].offset = 0x4000;
  mdesc[1].start = 0x4000;
  mdesc[1].len = 0x4000;
  mdesc[1].flags = RETRO_MEMDESC_CONST;

  // vram
  mdesc[2].ptr = gb.mem.data;
  mdesc[2].offset = 0x8000;
  mdesc[2].start = 0x8000;
  mdesc[2].len = 0x2000;

  // wram
  mdesc[3].ptr = gb.mem.data;
  mdesc[3].offset = 0xc000;
  mdesc[3].start = 0xc000;
  mdesc[3].len = 0x1000;

  mdesc[4].ptr = gb.mem.data;
  mdesc[4].offset = 0xd000;
  mdesc[4].start = 0xd000;
  mdesc[4].len = 0x1000;

  // oam
  mdesc[5].ptr = gb.mem.data;
  mdesc[5].offset = 0xfe00;
  mdesc[5].start = 0xfe00;
  mdesc[5].len = 0xa0;
  mdesc[5].select = 0xffffff60;

  // mmio
  mdesc[6].ptr = gb.mem.data;
  mdesc[6].offset = 0xff00;
  mdesc[6].start = 0xff00;
  mdesc[6].len = 0x80;

  // hram
  mdesc[7].ptr = gb.mem.data;
  mdesc[7].offset = 0xff80;
  mdesc[7].start = 0xff80;
  mdesc[7].len = 0x7f;
  mdesc[7].select = 0xffffff80;

  // ie
  mdesc[8].ptr = gb.mem.data;
  mdesc[8].offset = 0xffff;
  mdesc[8].start = 0xffff;
  mdesc[8].len = 1;
  
  static struct retro_memory_map mmap;
  mmap.descriptors = mdesc;
  mmap.num_descriptors = sizeof mdesc / sizeof *mdesc;
  env_cb(RETRO_ENVIRONMENT_SET_MEMORY_MAPS, &mmap);

  int pixel_fmt = RETRO_PIXEL_FORMAT_XRGB8888;
  env_cb(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &pixel_fmt);

  sb_ptrs_init(&gb, &gb_scratch, emu_state.rom_data);  
}

bool retro_gb_load_rom(){
  return sb_load_rom(&emu_state, &gb, &gb_scratch);
}

void retro_gb_get_system_av_info(struct retro_system_av_info* info) {  
  info->geometry.aspect_ratio = 0.0;
  info->geometry.max_height = SB_LCD_H;
  info->geometry.max_width = SB_LCD_W;
  info->geometry.base_height = info->geometry.max_height;
  info->geometry.base_width = info->geometry.max_width;
  info->timing.fps = 59.727;
  info->timing.sample_rate = SE_AUDIO_SAMPLE_RATE;
}

void retro_gb_reset() {  
    sb_load_rom(&emu_state, &gb, &gb_scratch);
}

void* retro_gb_step_frame(uint32_t* width, uint32_t* height) {
  // must be done before each tick.
  uint8_t palette[12] = { 0xff,0xff,0xff,0xAA,0xAA,0xAA,0x55,0x55,0x55,0x00,0x00,0x00 };
  for(int i = 0; i < 12; ++i) gb.dmg_palette[i] = palette[i];

  sb_tick(&emu_state, &gb, &gb_scratch);

  static uint8_t flipped_frame[sizeof gb_scratch.framebuffer];
  *width = SB_LCD_W;
  *height = SB_LCD_H;  
  for (int i = 0; i < sizeof(flipped_frame); i += 4) {
    // NOTE: assume little endian
    flipped_frame[i + 0] = gb_scratch.framebuffer[i + 2]; // blue
    flipped_frame[i + 1] = gb_scratch.framebuffer[i + 1]; // green
    flipped_frame[i + 2] = gb_scratch.framebuffer[i + 0]; // red
    flipped_frame[i + 3] = 0; // ignored
  }
  return flipped_frame;
}

size_t retro_gb_serialize_size() {
  return sizeof gb;
}

bool retro_gb_serialize(void* data, size_t size) {
  if (size < sizeof gb) return false;
  memcpy(data, &gb, sizeof gb);
  return true;
}

bool retro_gb_unserialize(const void* data, size_t size) {
  if (size < sizeof gb) return false;
  memcpy(&gb, data, sizeof gb);
  sb_ptrs_init(&gb, &gb_scratch, emu_state.rom_data);
  return true;
}

size_t retro_gb_get_memory_size(unsigned id) {
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return sizeof gb.cart.ram_data;
    case RETRO_MEMORY_SYSTEM_RAM: return sizeof gb.mem;
    case RETRO_MEMORY_RTC: return sizeof gb.rtc;
    default: return 0;
  }
}

void* retro_gb_get_memory_data(unsigned id) {
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return gb.cart.ram_data;
    case RETRO_MEMORY_SYSTEM_RAM: return &gb.mem;
    case RETRO_MEMORY_RTC: return &gb.rtc;
    default: return NULL;
  }
}

bool retro_gb_run_cheat(const uint32_t* buffer, uint32_t size) {
  return sb_run_ar_cheat(&gb, buffer, size);
}

/* ----------------- RETROARCH GBA ----------------- */

static gba_scratch_t gba_scratch;
static gba_t gba;

void retro_gba_init() {
  // TODO: add external memory (flash/sram)
  static struct retro_memory_descriptor mdesc[11];
  // internal wram
  mdesc[0].ptr = gba.mem.wram1;
  mdesc[0].start = 0x03000000;
  mdesc[0].len = sizeof gba.mem.wram1;
  mdesc[0].select = 0xff000000;

  // wram
  mdesc[1].ptr = gba.mem.wram0;
  mdesc[1].start = 0x02000000;
  mdesc[1].len = sizeof gba.mem.wram0;
  mdesc[1].select = 0xff000000;

  // save ram
  mdesc[2].ptr = gba.mem.cart_backup;
  mdesc[2].start = 0x0e000000;
  mdesc[2].len = sizeof gba.mem.cart_backup;

  // roms
  mdesc[3].ptr = gba.mem.cart_rom;
  mdesc[3].start = 0x08000000;
  mdesc[3].len = 0x02000000;
  mdesc[3].flags = RETRO_MEMDESC_CONST;

  mdesc[4].ptr = gba.mem.cart_rom;
  mdesc[4].start = 0x0a000000;
  mdesc[4].len = 0x02000000;
  mdesc[4].flags = RETRO_MEMDESC_CONST;

  mdesc[5].ptr = gba.mem.cart_rom;
  mdesc[5].start = 0x0c000000;
  mdesc[5].len = 0x02000000;
  mdesc[5].flags = RETRO_MEMDESC_CONST;

  // bios
  mdesc[6].ptr = gba.mem.bios;
  mdesc[6].start = 0x00000000;
  mdesc[6].len = 0x00004000;
  mdesc[6].flags = RETRO_MEMDESC_CONST;

  // vram
  mdesc[7].ptr = gba.mem.vram;
  mdesc[7].start = 0x00000400;
  mdesc[7].len = sizeof gba.mem.vram;
  mdesc[7].select = 0xff000000;

  // palette
  mdesc[8].ptr = gba.mem.palette;
  mdesc[8].start = 0x05000000;
  mdesc[8].len = sizeof gba.mem.palette;
  mdesc[8].select = 0xff000000;

  // oam
  mdesc[9].ptr = gba.mem.oam;
  mdesc[9].start = 0x07000000;
  mdesc[9].len = sizeof gba.mem.oam;
  mdesc[9].select = 0xff000000;

  // mmio
  mdesc[10].ptr = gba.mem.io;
  mdesc[10].start = 0x04000000;
  mdesc[10].len = sizeof gba.mem.io;

  static struct retro_memory_map mmap;
  mmap.descriptors = mdesc;
  mmap.num_descriptors = sizeof mdesc / sizeof *mdesc;
  env_cb(RETRO_ENVIRONMENT_SET_MEMORY_MAPS, &mmap);

  int pixel_fmt = RETRO_PIXEL_FORMAT_XRGB8888;
  env_cb(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &pixel_fmt);

  gba_ptrs_init(&gba, &gba_scratch, emu_state.rom_data);
}

bool retro_gba_load_rom() {
  return gba_load_rom(&emu_state, &gba, &gba_scratch);
}

void retro_gba_get_system_av_info(struct retro_system_av_info* info) {
  info->geometry.aspect_ratio = 0.0;
  info->geometry.max_width = GBA_LCD_W;
  info->geometry.max_height = GBA_LCD_H;
  info->geometry.base_width = info->geometry.max_width;
  info->geometry.base_height = info->geometry.max_height; 
  info->timing.fps = 59.727;
  info->timing.sample_rate = SE_AUDIO_SAMPLE_RATE;
}

void retro_gba_reset() {
  gba_load_rom(&emu_state, &gba, &gba_scratch);
}

void* retro_gba_step_frame(uint32_t* width, uint32_t* height) {
  gba_tick(&emu_state, &gba, &gba_scratch);

  static uint8_t flipped_frame[sizeof gba_scratch.framebuffer];
  *width = GBA_LCD_W;
  *height = GBA_LCD_H;
  for (int i = 0; i < sizeof(flipped_frame); i += 4) {
    // NOTE: assume little endian
    flipped_frame[i + 0] = gba_scratch.framebuffer[i + 2]; // blue
    flipped_frame[i + 1] = gba_scratch.framebuffer[i + 1]; // green
    flipped_frame[i + 2] = gba_scratch.framebuffer[i + 0]; // red
    flipped_frame[i + 3] = 0; // ignored
  }
  return flipped_frame;
}

size_t retro_gba_serialize_size() {
  return sizeof gba;
}

bool retro_gba_serialize(void* data, size_t size) {
  if (size < sizeof gba) return false;
  memcpy(data, &gba, sizeof gba);
  return true;
}

bool retro_gba_unserialize(const void* data, size_t size) {
  if (size < sizeof gba) return false;
  memcpy(&gba, data, sizeof gba);
  gba_ptrs_init(&gba, &gba_scratch, emu_state.rom_data);
  return true;
}

size_t retro_gba_get_memory_size(unsigned id) {
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return sizeof gba.mem.cart_backup;
    case RETRO_MEMORY_RTC: return sizeof gba.rtc;
    default: return 0;
  }
}

void* retro_gba_get_memory_data(unsigned id) {
  // isgnoring system memory here as it is not continuous, it does not matter anyway.
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return gba.mem.cart_backup;
    case RETRO_MEMORY_RTC: return &gba.rtc;
    default: return NULL;
  }
}

bool retro_gba_run_cheat(const uint32_t* buffer, uint32_t size) {
  return gba_run_ar_cheat(&gba, buffer, size);
}

/* ----------------- RETROARCH NDS ----------------- */

static nds_scratch_t nds_scratch;
static nds_t nds;

void retro_nds_init() {
  // TODO: there are still memory regions
  // that could be added here. Particularly
  // those that exist for ARM9.
  // NOTE: we are not including data tcm, as it is movable.
  static struct retro_memory_descriptor mdesc[11];
  // instruction tcm
  mdesc[0] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.code_tcm,
    .offset = 0,

    .start = 0,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.code_tcm,
    .addrspace = NULL,
  };
  // main memory
  mdesc[1] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.ram,
    .offset = 0,

    .start = 0x02000000,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.ram,
    // .addrspace = NULL,
  };
  ;
  // shared wram
  mdesc[2] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.wram,
    .offset = 0,

    .start = 0x03000000,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.wram,
    .addrspace = NULL,
  };
  // arm9 io
  mdesc[3] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.io,
    .offset = 0,

    .start = 0x04000000,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.io,
    .addrspace = NULL,
  };
  // palette
  mdesc[4] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.palette,
    .offset = 0,

    .start = 0x05000000,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.palette,
    .addrspace = NULL,
  };
  // vram 0
  mdesc[5] = (struct retro_memory_descriptor){
    .flags = RETRO_MEMDESC_VIDEO_RAM,
    .ptr = nds.mem.vram,
    .offset = 0,

    .start = 0x06000000,
    .select = 0,
    .disconnect = 0,

    .len = 512 << 10,
    .addrspace = NULL,
  };
  // vram 1
  mdesc[6] = (struct retro_memory_descriptor){
    .flags = RETRO_MEMDESC_VIDEO_RAM,
    .ptr = nds.mem.vram,
    .offset = 512 << 10,

    .start = 0x06200000,
    .select = 0,
    .disconnect = 0,

    .len = 128 << 10,
    .addrspace = NULL,
  };
  // vram 2
  mdesc[7] = (struct retro_memory_descriptor){
    .flags = RETRO_MEMDESC_VIDEO_RAM,
    .ptr = nds.mem.vram,
    .offset = (512 << 10) + (128 << 10),

    .start = 0x06400000,
    .select = 0,
    .disconnect = 0,

    .len = 256 << 10,
    .addrspace = NULL,
  };
  // vram 3
  mdesc[8] = (struct retro_memory_descriptor){
    .flags = RETRO_MEMDESC_VIDEO_RAM,
    .ptr = nds.mem.vram,
    .offset = (512 << 10) + (128 << 10) + (256 << 10),

    .start = 0x06600000,
    .select = 0,
    .disconnect = 0,

    .len = 128 << 10,
    .addrspace = NULL,
  };
  // vram 4
  mdesc[9] = (struct retro_memory_descriptor){
    .flags = RETRO_MEMDESC_VIDEO_RAM,
    .ptr = nds.mem.vram,
    .offset = (512 << 10) + (128 << 10) * 2 + (256 << 10),

    .start = 0x06800000,
    .select = 0,
    .disconnect = 0,

    .len = 656 << 10,
    .addrspace = NULL,
  };
  // oam
  mdesc[10] = (struct retro_memory_descriptor){
    .flags = 0,
    .ptr = nds.mem.oam,
    .offset = 0,

    .start = 0x07000000,
    .select = 0,
    .disconnect = 0,

    .len = sizeof nds.mem.oam,
    .addrspace = NULL,
  };
  
  static struct retro_memory_map mmap; 
  mmap.descriptors = mdesc;
  mmap.num_descriptors = sizeof mdesc / sizeof *mdesc;
  env_cb(RETRO_ENVIRONMENT_SET_MEMORY_MAPS, &mmap);

  int pixel_fmt = RETRO_PIXEL_FORMAT_XRGB8888;
  env_cb(RETRO_ENVIRONMENT_SET_PIXEL_FORMAT, &pixel_fmt);

  nds_ptrs_init(&nds, &nds_scratch, emu_state.rom_data, emu_state.rom_size);
}

bool retro_nds_load_rom() {
  return nds_load_rom(&emu_state, &nds, &nds_scratch);
}

void retro_nds_get_system_av_info(struct retro_system_av_info* info) {
  info->geometry.aspect_ratio = 0.0;
  info->geometry.max_width = NDS_LCD_W;
  info->geometry.max_height = NDS_LCD_H * 2; // (bottom and top screen)
  info->geometry.base_width = info->geometry.max_width;
  info->geometry.base_height = info->geometry.max_height; 
  info->timing.fps = 59.8261;
  info->timing.sample_rate = SE_AUDIO_SAMPLE_RATE;
}

void retro_nds_reset() {
  nds_load_rom(&emu_state, &nds, &nds_scratch);
}

void* retro_nds_step_frame(uint32_t* width, uint32_t* height) {
  nds_tick(&emu_state, &nds, &nds_scratch);

  static uint8_t flipped_frame[sizeof nds_scratch.framebuffer_full];
  *width = NDS_LCD_W;
  *height = NDS_LCD_H * 2; // we have two screens (bottom and top)
  for (int i = 0; i < sizeof(flipped_frame); i += 4) {
    // NOTE: assume little endian
    flipped_frame[i + 0] = nds_scratch.framebuffer_full[i + 2]; // blue
    flipped_frame[i + 1] = nds_scratch.framebuffer_full[i + 1]; // green
    flipped_frame[i + 2] = nds_scratch.framebuffer_full[i + 0]; // red
    flipped_frame[i + 3] = 0; // ignored
  }
  return flipped_frame;
}

size_t retro_nds_serialize_size() {
  return sizeof nds;
}

bool retro_nds_serialize(void* data, size_t size) {
  if (size < sizeof nds) return false;
  memcpy(data, &nds, sizeof nds);
  return true;
}

bool retro_nds_unserialize(const void* data, size_t size) {
  if (size < sizeof nds) return false;
  memcpy(&nds, data, sizeof nds);
  nds_ptrs_init(&nds, &nds_scratch, emu_state.rom_data, emu_state.rom_size);
  return true;
}

size_t retro_nds_get_memory_size(unsigned id) {
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return sizeof nds_scratch.save_data;
    case RETRO_MEMORY_SYSTEM_RAM: return sizeof nds.mem.ram;
    case RETRO_MEMORY_RTC: return sizeof nds.rtc;
    default: return 0;
  }
}

void* retro_nds_get_memory_data(unsigned id) {
  switch (id) {
    case RETRO_MEMORY_SAVE_RAM: return nds_scratch.save_data;
    case RETRO_MEMORY_SYSTEM_RAM: return nds.mem.ram;
    case RETRO_MEMORY_RTC: return &nds.rtc;
    default: return NULL;
  }
}

bool retro_nds_run_cheat(const uint32_t* buffer, uint32_t size) {
  return nds_run_ar_cheat(&nds, buffer, size);
}

/* ----------------- RETROARCH IMP ----------------- */

static bool load_rom(const struct retro_game_info* game) {
  opts_reload_all();

  if (emu_state.rom_loaded) {
    free(emu_state.rom_data);
  }
  emu_state.rom_loaded = true;
  strncpy(emu_state.rom_path, game->path, SB_FILE_PATH_SIZE);
  emu_state.rom_data = malloc(game->size);
  memcpy(emu_state.rom_data, game->data, game->size);
  emu_state.rom_size = game->size;

  char* extension = strrchr(game->path, '.');  
  if (
      // there must be a dot for there to be a valid extension
      extension || gopts.core_override != OPTS_CORE_OVERRIDE_AUTOMATIC
  ) {
    if (
        ((!strcmp(".gb", extension) || !strcmp(".gbc", extension)) && gopts.core_override == OPTS_CORE_OVERRIDE_AUTOMATIC) 
        || gopts.core_override == OPTS_CORE_OVERRIDE_GB
    ) {
      emu_state.system = SYSTEM_GB;
      retro_gb_init();
      return retro_gb_load_rom();
    } else if ((!strcmp(".gba", extension) && gopts.core_override == OPTS_CORE_OVERRIDE_AUTOMATIC) || gopts.core_override == OPTS_CORE_OVERRIDE_GBA) {
      emu_state.system = SYSTEM_GBA;
      retro_gba_init();
      return retro_gba_load_rom();
    } else if ((!strcmp(".nds", extension) && gopts.core_override == OPTS_CORE_OVERRIDE_AUTOMATIC) || gopts.core_override == OPTS_CORE_OVERRIDE_NDS) {
      emu_state.system = SYSTEM_NDS;
      retro_nds_init();
      return retro_nds_load_rom();
    } 
  }  

  log_cb(RETRO_LOG_ERROR, "failed to load game '%s'\n%s\n", game->path, game->meta);
  emu_state.rom_loaded = false;
  free(emu_state.rom_data);
  return false;
}

unsigned retro_api_version(void) {
  return RETRO_API_VERSION;
}

void retro_set_environment(retro_environment_t env) {
  env_cb = env;
  env(RETRO_ENVIRONMENT_GET_LOG_INTERFACE, &log_cb);

  // set input descriptors
  static struct retro_input_descriptor input_descriptors[] = {
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_START, .description = "joypad start" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_SELECT, .description = "joypad select" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_UP, .description = "joypad up" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_DOWN, .description = "joypad down" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_LEFT, .description = "joypad left" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_RIGHT, .description = "joypad right" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_A, .description = "joypad a" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_B, .description = "joypad b" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_R, .description = "joypad r" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_L, .description = "joypad l" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_X, .description = "joypad x" },
    { .port = 0, .device = RETRO_DEVICE_JOYPAD, .index = 0, .id = RETRO_DEVICE_ID_JOYPAD_Y, .description = "joypad y" },
    { .port = 0, .device = RETRO_DEVICE_POINTER, .index = 0, .id = RETRO_DEVICE_ID_POINTER_X, .description = "touch x" },
    { .port = 0, .device = RETRO_DEVICE_POINTER, .index = 0, .id = RETRO_DEVICE_ID_POINTER_Y, .description = "touch y" },
    { .port = 0, .device = RETRO_DEVICE_POINTER, .index = 0, .id = RETRO_DEVICE_ID_POINTER_PRESSED, .description = "touch press" },
    {0}
  };
  env(RETRO_ENVIRONMENT_SET_INPUT_DESCRIPTORS, (void*)input_descriptors);

  // set core configuration options
  opts_initialize();
}

void retro_set_video_refresh(retro_video_refresh_t refresh) {
  video_refresh_cb = refresh;
}

void retro_set_audio_sample(retro_audio_sample_t sample) {
  (void)sample;
}

void retro_set_audio_sample_batch(retro_audio_sample_batch_t batch) {
  audio_sample_batch_cb = batch;
}

void retro_set_input_poll(retro_input_poll_t poll) {
  input_poll_cb = poll;
}

void retro_set_input_state(retro_input_state_t state) {
  input_state_cb = state;
}

void retro_init(void) {
  emu_state.render_frame = true;
}

void retro_deinit(void) {}

void retro_get_system_info(struct retro_system_info* info){
    info->library_name = "SkyEmu";
    info->library_version = SKYEMU_LIBRETRO_VERSION;
    info->block_extract = false;
    info->need_fullpath = false;
    info->valid_extensions = "gb|gbc|gba|nds";
}

void retro_get_system_av_info(struct retro_system_av_info* info) {
  switch (emu_state.system) {
    case SYSTEM_GB: retro_gb_get_system_av_info(info); break;
    case SYSTEM_GBA: retro_gba_get_system_av_info(info); break;
    case SYSTEM_NDS: retro_nds_get_system_av_info(info); break;
    default:;
  }
}

void retro_set_controller_port_device(unsigned port, unsigned device) {
  // TODO: confirm skyemu does not need this.
  log_cb(RETRO_LOG_WARN, "ignoring controller port device: port: %u, device: %u\n", port, device);
}

void retro_reset(void) {
  switch (emu_state.system) {
    case SYSTEM_GB: retro_gb_reset(); break;
    case SYSTEM_GBA: retro_gba_reset(); break;
    case SYSTEM_NDS: retro_nds_reset(); break;
    default:;
  }
}

void retro_run(void) {
  input_poll_cb();

  emu_state.joy.inputs[SE_KEY_A] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_A);
  emu_state.joy.inputs[SE_KEY_B] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_B);
  emu_state.joy.inputs[SE_KEY_X] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_X);
  emu_state.joy.inputs[SE_KEY_Y] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_Y);
  emu_state.joy.inputs[SE_KEY_L] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_L);
  emu_state.joy.inputs[SE_KEY_R] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_R);
  emu_state.joy.inputs[SE_KEY_UP] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_UP);
  emu_state.joy.inputs[SE_KEY_DOWN] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_DOWN);
  emu_state.joy.inputs[SE_KEY_LEFT] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_LEFT);
  emu_state.joy.inputs[SE_KEY_RIGHT] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_RIGHT);
  emu_state.joy.inputs[SE_KEY_SELECT] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_SELECT);
  emu_state.joy.inputs[SE_KEY_START] = input_state_cb(0, RETRO_DEVICE_JOYPAD, 0, RETRO_DEVICE_ID_JOYPAD_START);

  short mouse_pos[2];
  mouse_pos[0] = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_X);
  mouse_pos[1] = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_Y);
  mouse_pos[1] = mouse_pos[1] < 0 ? 0 : mouse_pos[1];

  // This is a hack specifically for the NDS core, which only allows touch for the bottom screen.
  emu_state.joy.touch_pos[0] = (float)mouse_pos[0] / USHRT_MAX + 0.5;
  emu_state.joy.touch_pos[1] = (float)mouse_pos[1] / SHRT_MAX;
  emu_state.joy.inputs[SE_KEY_PEN_DOWN] = input_state_cb(0, RETRO_DEVICE_POINTER, 0, RETRO_DEVICE_ID_POINTER_PRESSED);


  uint32_t width = 0, height = 0;
  void* data = NULL;
  switch (emu_state.system) {
    case SYSTEM_GB: { 
      data = retro_gb_step_frame(&width, &height); 
      se_run_all_ar_cheats(retro_gb_run_cheat);
    } break;
    case SYSTEM_GBA: { 
      data = retro_gba_step_frame(&width, &height);
      se_run_all_ar_cheats(retro_gba_run_cheat);
    } break;
    case SYSTEM_NDS: {
      data = retro_nds_step_frame(&width, &height);  
      se_run_all_ar_cheats(retro_nds_run_cheat);
    } break;
    default:;
  }
  int pitch = width * 4;
  video_refresh_cb(data, width, height, pitch);

  uint32_t samples = sb_ring_buffer_size(&emu_state.audio_ring_buff);
  uint32_t frames = samples >> 1;
  uint32_t beg_ptr = emu_state.audio_ring_buff.read_ptr;
  uint32_t end_ptr = (emu_state.audio_ring_buff.read_ptr + (frames << 1)) % SB_AUDIO_RING_BUFFER_SIZE;
  if (end_ptr < beg_ptr) {
    int remaining = (SB_AUDIO_RING_BUFFER_SIZE - beg_ptr) >> 1;
    audio_sample_batch_cb(&emu_state.audio_ring_buff.data[beg_ptr], remaining);
    audio_sample_batch_cb(&emu_state.audio_ring_buff.data[0], frames - remaining);
  } else {
    audio_sample_batch_cb(&emu_state.audio_ring_buff.data[beg_ptr], frames);
  }
  emu_state.audio_ring_buff.read_ptr = end_ptr;
}

size_t retro_serialize_size(void) {
  // NOTE: savestate buffer size can never be allowed
  // to increase from the initial call. But, since
  // only ever one core can be loaded, that actual
  // size will never change.
  switch (emu_state.system) {
    case SYSTEM_GB: return retro_gb_serialize_size();
    case SYSTEM_GBA: return retro_gba_serialize_size();
    case SYSTEM_NDS: return retro_nds_serialize_size(); 
    default: return 0;
  }
}

bool retro_serialize(void* data, size_t size) {
  switch (emu_state.system) {
    case SYSTEM_GB: return retro_gb_serialize(data, size);
    case SYSTEM_GBA: return retro_gba_serialize(data, size);
    case SYSTEM_NDS: return retro_nds_serialize(data, size);
    default: return false;
  }
}

bool retro_unserialize(const void* data, size_t size) {
  switch (emu_state.system) {
    case SYSTEM_GB: return retro_gb_unserialize(data, size);
    case SYSTEM_GBA: return retro_gba_unserialize(data, size);
    case SYSTEM_NDS: return retro_nds_unserialize(data, size);
    default: return false;
  }
}

void retro_cheat_reset(void) {
  se_reset_cheats();
}

void retro_cheat_set(unsigned index, bool enabled, const char* code) {
  if (index >= 32) {
    fprintf(stderr, "cheat index cannot be higher than 32\n");
    return;
  }
  log_cb(RETRO_LOG_INFO, "setting cheat %u: %b\n", index, enabled);
  se_convert_cheat_code(code, index);
  if (enabled) {
    se_enable_cheat(index);
  } else {
    se_disable_cheat(index);
  }
}

bool retro_load_game(const struct retro_game_info* game) {
  return load_rom(game); 
}

bool retro_load_game_special(unsigned game_type, const struct retro_game_info* game, size_t num_info) {
  (void)game_type;
  (void)num_info;
  return load_rom(game);
}

void retro_unload_game(void) {  
  if (emu_state.rom_loaded) {
    free(emu_state.rom_data);
  }
  emu_state.rom_loaded = false;
  emu_state.rom_path[0] = 0;
}

unsigned retro_get_region(void) {
  return RETRO_REGION_NTSC; // TODO: this is a potentially incorrect guess.
}

void* retro_get_memory_data(unsigned id) {
  switch (emu_state.system) {
    case SYSTEM_GB: return retro_gb_get_memory_data(id); 
    case SYSTEM_GBA: return retro_gba_get_memory_data(id); 
    case SYSTEM_NDS: return retro_nds_get_memory_data(id); 
    default: return NULL;
  }
}

size_t retro_get_memory_size(unsigned id) {
  switch (emu_state.system) {
    case SYSTEM_GB: return retro_gb_get_memory_size(id); 
    case SYSTEM_GBA: return retro_gba_get_memory_size(id); 
    case SYSTEM_NDS: return retro_nds_get_memory_size(id); 
    default: return 0;
  }
}
