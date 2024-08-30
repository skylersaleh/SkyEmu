#include "shared.h"
#include "sb_types.h"

#include<stdio.h>
#include<string.h>

se_cheat_t cheats[SE_NUM_CHEATS];

void se_run_all_ar_cheats(se_cheat_fn fn) {
  for(int i=0;i< SE_NUM_CHEATS ;++i){
    se_cheat_t * cheat = cheats+i;
    if(cheat->state!=1)continue;
    bool success = fn(cheat->buffer,cheat->size);
    if(!success) cheat->state = 0; 
  }
}

void se_load_cheats(const char * filename){
  size_t data_size=0;
  uint8_t*data = sb_load_file_data(filename,&data_size);
  if(!data_size){
    printf("Failed to load cheats from %s\n",filename);
    return; 
  }
  int cheat_index = 0; 
  int state = 0; 
  int cheat_name_size =0; 
  int cheat_code_size =0; 
  char cheat_buffer[SE_MAX_CHEAT_CODE_SIZE*8] ={ 0 };
  for(size_t i = 0; i < data_size;++i){
    char c = data[i];
    if(c=='\n'){
      state = 0; 
      cheat_name_size = 0; 
      cheat_code_size = 0;
      cheat_index++;
      if(cheat_index>=SE_NUM_CHEATS)break;
      continue; 
    }
    se_cheat_t * ch = cheats+cheat_index;
    if(state==0 && (c=='1'||c=='0')) ch->state = c=='1';
    if(c=='"'){
      state++; 
      if(state==4){
        se_convert_cheat_code(cheat_buffer,cheat_index);
        memset(cheat_buffer, 0, sizeof(cheat_buffer));
      }
      continue;
    }
    if(state == 1){
      if(cheat_name_size<SE_MAX_CHEAT_NAME_SIZE)ch->name[cheat_name_size++]=c; 
    }
    if(state == 3){
      if(cheat_name_size<SE_MAX_CHEAT_CODE_SIZE*8)cheat_buffer[cheat_code_size++]=c; 
    }
  }
  free(data);
}

void se_save_cheats(const char * filename){
  FILE *f = fopen(filename, "wb");
  if(!f){
    printf("Failed to save cheats to %s\n",filename);
    return; 
  }
  for (int i=0;i<SE_NUM_CHEATS;++i){
    if(cheats[i].state==-1)continue;
    fprintf(f,"%s ", cheats[i].state==0? "0" : "1" );
    fprintf(f,"\"%s\" ",cheats[i].name);
    fprintf(f,"\"");
    for(int d=0;d<cheats[i].size;++d){
      if(d)fprintf(f," ");
      fprintf(f,"%08x",cheats[i].buffer[d]);
    }
    fprintf(f,"\"\n");
  }
  fclose(f);
}

void se_convert_cheat_code(const char * text_code, int cheat_index){
  if(cheat_index>=SE_NUM_CHEATS)return; 
  se_cheat_t *cheat = cheats+cheat_index; 
  int char_count = 0;
  uint8_t code_buffer_truncated[SE_MAX_CHEAT_CODE_SIZE*8];
  // Remove all the non-hex characters
  for(int i=0;i<SE_MAX_CHEAT_CODE_SIZE*8;++i){
    if(text_code[i]=='\0')break;
    else if((text_code[i]>='0' && text_code[i]<='9') || (text_code[i]>='A' && text_code[i]<='F') || (text_code[i]>='a' && text_code[i]<='f')){
      code_buffer_truncated[char_count]=text_code[i]; 
      char_count++;
    }
  }
  cheat->size = char_count/8;
  if(cheat->size>=SE_MAX_CHEAT_CODE_SIZE)cheat->size=SE_MAX_CHEAT_CODE_SIZE;
  for(int i=0;i<cheat->size;++i)cheat->buffer[i]=0; 
  for(int i=0;i<cheat->size;i++){
    char hex[9];
    memcpy(hex,code_buffer_truncated+i*8,8);
    for(int h=0;h<8;++h)if(hex[h]==0)hex[h]='0';
    hex[8]='\0';
    cheat->buffer[i]=strtoul(hex,NULL,16);
  }
}

void se_enable_cheat(int cheat_index) {
  if (cheat_index < SE_NUM_CHEATS) {
    cheats[cheat_index].state=1;
  }
}

void se_disable_cheat(int cheat_index) {
  if (cheat_index < SE_NUM_CHEATS) {
    cheats[cheat_index].state=-1;
  }
}

void se_reset_cheats(void){
  memset(cheats,0,sizeof(cheats));
  for (int i=0;i<SE_NUM_CHEATS;++i){cheats[i].state=-1;}
}
