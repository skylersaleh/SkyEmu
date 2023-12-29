#define SE_BIND_KEYBOARD 0
#define SE_BIND_KEY 1
#define SE_BIND_ANALOG 2
#define SE_KEY_A 0 
#define SE_KEY_B 1 
#define SE_KEY_X 2 
#define SE_KEY_Y 3 
#define SE_KEY_UP 4
#define SE_KEY_DOWN 5
#define SE_KEY_LEFT 6
#define SE_KEY_RIGHT 7
#define SE_KEY_L 8
#define SE_KEY_R 9
#define SE_KEY_START 10
#define SE_KEY_SELECT 11
#define SE_KEY_FOLD_SCREEN 12
#define SE_KEY_PEN_DOWN 13
#define SE_KEY_EMU_PAUSE 14
#define SE_KEY_EMU_REWIND 15
#define SE_KEY_EMU_FF_2X 16
#define SE_KEY_EMU_FF_MAX 17
#define SE_KEY_CAPTURE_STATE(A) (18+(A)*2)
#define SE_KEY_RESTORE_STATE(A) (18+(A)*2+1)
#define SE_KEY_RESET_GAME 26
#define SE_KEY_TURBO_A  27
#define SE_KEY_TURBO_B  28
#define SE_KEY_TURBO_X  29
#define SE_KEY_TURBO_Y  30
#define SE_KEY_TURBO_L  31
#define SE_KEY_TURBO_R  32
#define SE_KEY_SOLAR_P  33
#define SE_KEY_SOLAR_M  34
#define SE_KEY_TOGGLE_FULLSCREEN 35
#define SE_NUM_KEYBINDS 36

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

typedef struct{
  uint32_t addr;
  const char * name;
  struct{
    uint8_t start;
    uint8_t size;
    const char* name; 
  } bits[32]; 
}mmio_reg_t; 

static void se_join_path(char * dest_path, int dest_size, const char * base_path, const char* file_name, const char* add_extension){
  const char * seperator = base_path[0]==0? "" : "/"; 
  if(strlen(base_path)!=0){
    char last_base_char = base_path[strlen(base_path)-1];
    if(last_base_char=='/'||last_base_char=='\\')seperator="";
  }
  if(add_extension){
    const char * ext_sep = add_extension[0]=='.' ? "": ".";
    snprintf(dest_path,dest_size,"%s%s%s%s%s",base_path, seperator, file_name,ext_sep,add_extension);
  }else snprintf(dest_path,dest_size,"%s%s%s",base_path, seperator, file_name);
  dest_path[dest_size-1]=0;
}
bool se_load_bios_file(const char* name, const char* base_path, const char* file_name, uint8_t * data, size_t data_size);

