#ifndef SE_RETRO_ACHIEVEMENTS_MEMORY_H
#define SE_RETRO_ACHIEVEMENTS_MEMORY_H

// These readers use the RetroAchievements address space, independent of CPU banking.
static uint32_t se_rc_read_gb_memory(sb_gb_t* gb, uint32_t address, uint8_t* buffer, uint32_t num_bytes){
  uint32_t count = 0;
  while(count<num_bytes){
    uint32_t current = address;
    if(current>=0x00E000U&&current<=0x00FDFFU)current-=0x2000U;
    if(current>=0x016000U&&current<=0x033FFFU){
      uint32_t offset = current-0x016000U+0x2000U;
      if(gb->cart.ram_size<=0||offset>=(uint32_t)gb->cart.ram_size||offset>=sizeof(gb->cart.ram_data))break;
      buffer[count] = gb->cart.ram_data[offset];
    }else if(current>=0x010000U&&current<=0x015FFFU){
      if(!gb->cart.game_boy_color)break;
      buffer[count] = gb->mem.wram[2*SB_WRAM_BANK_SIZE+current-0x010000U];
    }else if(current>=0x00A000U&&current<=0x00BFFFU){
      uint32_t offset = current-0x00A000U;
      if(gb->cart.ram_size<=0||offset>=(uint32_t)gb->cart.ram_size)break;
      buffer[count] = gb->cart.ram_data[offset];
    }else if(current>=0x00D000U&&current<=0x00DFFFU){
      buffer[count] = gb->mem.wram[SB_WRAM_BANK_SIZE+current-0x00D000U];
    }else if(current<0x010000U&&(current<0x00FEA0U||current>0x00FEFFU)){
      buffer[count] = sb_read8(gb,current);
    }else break;
    ++count;
    ++address;
  }
  return count;
}

static uint32_t se_rc_read_gba_memory(gba_t* gba, uint32_t address, uint8_t* buffer, uint32_t num_bytes){
  uint32_t count = 0;
  while(count<num_bytes){
    if(address<0x008000U){
      buffer[count] = gba->mem.wram1[address];
    }else if(address<0x048000U){
      buffer[count] = gba->mem.wram0[address-0x008000U];
    }else if(address<0x058000U){
      buffer[count] = gba->mem.cart_backup[address-0x048000U];
    }else break;
    ++count;
    ++address;
  }
  return count;
}

static uint32_t se_rc_read_nds_memory(nds_t* nds, uint32_t address, uint8_t* buffer, uint32_t num_bytes){
  uint32_t count = 0;
  while(count<num_bytes){
    if(address<0x0400000U){
      buffer[count] = nds->mem.ram[address];
    }else if(address>=0x1000000U&&address<0x1004000U){
      // 0x0E000000 in the RA console map is synthetic, not a CPU address.
      buffer[count] = nds->mem.data_tcm[address-0x1000000U];
    }else break;
    ++count;
    ++address;
  }
  return count;
}

#endif
