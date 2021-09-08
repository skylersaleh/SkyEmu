#ifndef ARM7_H
#define ARM7_H 1

#include <stdint.h>
#include <stdio.h>
#include <string.h>

////////////////
// Data Types //
////////////////

#define LR 14
#define PC 15
#define CPSR 16
#define SPSR 17 

#define R13_fiq 22 
#define R13_irq 24 
#define R13_svc 26 
#define R13_abt 28 
#define R13_und 30 

#define R14_fiq 23 
#define R14_irq 25 
#define R14_svc 27 
#define R14_abt 29 
#define R14_und 31 

#define SPSR_fiq 32 
#define SPSR_irq 33 
#define SPSR_svc 34 
#define SPSR_abt 35 
#define SPSR_und 36 

typedef struct {
  // Registers
  /*
  0-15: R0-R15
  16: CPSR
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
  uint32_t registers[37];
  uint64_t executed_instructions;
  bool trigger_breakpoint;
  void* user_data;
  FILE* log_cmp_file;
} arm7_t;     

typedef void (*arm7_handler_t)(arm7_t *cpu, uint32_t opcode);
typedef struct{
	arm7_handler_t handler;
	char name[12];
	char bitfield[33];
}arm7_instruction_t;

////////////////////////
// User API Functions //
////////////////////////

// This function initializes the internal state needed for the arm7 core emulation
static arm7_t arm7_init(void* user_data);
static inline void arm7_exec_instruction(arm7_t* cpu);
// Memory IO functions for the emulated CPU (these must be defined by the user)
static inline uint32_t arm7_read32(void* user_data, uint32_t address);
static inline uint32_t arm7_read16(void* user_data, uint32_t address);
static inline uint8_t arm7_read8(void* user_data, uint32_t address);
static inline void arm7_write32(void* user_data, uint32_t address, uint32_t data);
static inline void arm7_write16(void* user_data, uint32_t address, uint16_t data);
static inline void arm7_write8(void* user_data, uint32_t address, uint8_t data);
// Write the dissassembled opcode from mem_address into the out_disasm string up to out_size characters
static void arm7_get_disasm(arm7_t * cpu, uint32_t mem_address, char* out_disasm, size_t out_size);
// Used to send an interrupt to the emulated CPU. The n'th set bit triggers the n'th interrupt
static void arm7_process_interrupts(arm7_t* cpu, uint32_t interrupts);
///////////////////////////////////////////
// Functions for Internal Implementation //
///////////////////////////////////////////

// ARM Instruction Implementations
static inline void arm7_data_processing(arm7_t* cpu, uint32_t opcode);
static inline void arm7_multiply(arm7_t* cpu, uint32_t opcode);
static inline void arm7_multiply_long(arm7_t* cpu, uint32_t opcode);
static inline void arm7_single_data_swap(arm7_t* cpu, uint32_t opcode);
static inline void arm7_branch_exchange(arm7_t* cpu, uint32_t opcode);
static inline void arm7_half_word_transfer(arm7_t* cpu, uint32_t opcode);
static inline void arm7_single_word_transfer(arm7_t* cpu, uint32_t opcode);
static inline void arm7_undefined(arm7_t* cpu, uint32_t opcode);
static inline void arm7_block_transfer(arm7_t* cpu, uint32_t opcode);
static inline void arm7_branch(arm7_t* cpu, uint32_t opcode);
static inline void arm7_coproc_data_transfer(arm7_t* cpu, uint32_t opcode);
static inline void arm7_coproc_data_op(arm7_t* cpu, uint32_t opcode);
static inline void arm7_coproc_reg_transfer(arm7_t* cpu, uint32_t opcode);
static inline void arm7_software_interrupt(arm7_t* cpu, uint32_t opcode);

static inline void arm7_mrs(arm7_t* cpu, uint32_t opcode);
static inline void arm7_msr(arm7_t* cpu, uint32_t opcode);

// Thumb Instruction Implementations
static inline void arm7t_mov_shift_reg(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_add_sub(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_mov_cmp_add_sub_imm(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_alu_op(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_hi_reg_op(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_pc_rel_ldst(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_reg_off_ldst(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_ldst_bh(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_imm_off_ldst(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_imm_off_ldst_bh(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_stack_off_ldst(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_load_addr(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_add_off_sp(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_push_pop_reg(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_mult_ldst(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_cond_branch(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_soft_interrupt(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_branch(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_long_branch_link(arm7_t* cpu, uint32_t opcode);
static inline void arm7t_unknown(arm7_t* cpu, uint32_t opcode);

// Internal functions
static inline bool arm7_check_cond_code(arm7_t* cpu, uint32_t opcode);
static inline uint32_t arm7_reg_read(arm7_t*cpu, unsigned reg);
static inline uint32_t arm7_reg_read_r15_adj(arm7_t*cpu, unsigned reg, int r15_off);
static inline void arm7_reg_write(arm7_t*cpu, unsigned reg, uint32_t value);
static inline unsigned arm7_reg_index(arm7_t* cpu, unsigned reg);
static int arm7_lookup_arm_instruction_class(uint32_t opcode_key);
static int arm7_lookup_thumb_instruction_class(uint32_t opcode_key);
static inline uint32_t arm7_shift(arm7_t* arm, uint32_t opcode, uint64_t value, uint32_t shift_value, int* carry);
static inline uint32_t arm7_load_shift_reg(arm7_t* arm, uint32_t opcode, int* carry);
static inline uint32_t arm7_rotr(uint32_t value, uint32_t rotate);
static inline bool arm7_get_thumb_bit(arm7_t* cpu);
static inline void arm7_set_thumb_bit(arm7_t* cpu, bool value);

#define ARM7_BFE(VALUE, BITOFFSET, SIZE) (((VALUE) >> (BITOFFSET)) & ((1u << (SIZE)) - 1))

// ARM7 ARM Classes
const static arm7_instruction_t arm7_instruction_classes[]={
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc0010oooSnnnnddddrrrrOOOOOOOO"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00111ooSnnnnddddrrrrOOOOOOOO"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00110oo1nnnnddddrrrrOOOOOOOO"},
   //These duplications are to handle disambiguating bit 5 and 7 set to ones for DP 
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc0000oooSnnnnddddsssssss0mmmm"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc0000oooSnnnnddddssss0tt1mmmm"},
   //Handle TST, TEQ, CMP, CMN must set S case
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00011ooSnnnnddddsssssss0mmmm"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00011ooSnnnnddddssss0tt1mmmm"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00010oo1nnnnddddssss0tt1mmmm"},
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc00010oo1nnnnddddsssssss0mmmm"},

   (arm7_instruction_t){arm7_multiply,             "MUL",     "cccc000000ASddddnnnnssss1001mmmm"},
   (arm7_instruction_t){arm7_multiply_long,        "MLONG",   "cccc00001UASddddnnnnssss1001mmmm"},
   (arm7_instruction_t){arm7_single_data_swap,     "SDS",     "cccc00010B00nnnndddd00001001mmmm"},
   (arm7_instruction_t){arm7_branch_exchange,      "BX",      "cccc000100101111111111110001nnnn"},
   (arm7_instruction_t){arm7_half_word_transfer,   "HDT(h)",  "cccc000PUIWLnnnndddd00001011mmmm"},
   (arm7_instruction_t){arm7_half_word_transfer,   "HDT(sb)", "cccc000PUIWLnnnnddddOOOO1101OOOO"},
   (arm7_instruction_t){arm7_half_word_transfer,   "HDT(sh)", "cccc000PUIWLnnnnddddOOOO1111OOOO"},
   (arm7_instruction_t){arm7_single_word_transfer, "SDT",     "cccc010PUBWLnnnnddddOOOOOOOOOOOO"},
   (arm7_instruction_t){arm7_single_word_transfer, "SDT",     "cccc011PUBWLnnnnddddOOOOOOO0mmmm"},
   (arm7_instruction_t){arm7_undefined,            "UDEF",    "cccc011--------------------1----"},
   (arm7_instruction_t){arm7_block_transfer,       "BDT",     "cccc100PUSWLnnnnllllllllllllllll"},
   (arm7_instruction_t){arm7_branch,               "B",       "cccc1010OOOOOOOOOOOOOOOOOOOOOOOO"},
   (arm7_instruction_t){arm7_branch,               "BL",      "cccc1011OOOOOOOOOOOOOOOOOOOOOOOO"},
   (arm7_instruction_t){arm7_coproc_data_transfer, "CDT",     "cccc110PUNWLnnnndddd####OOOOOOOO"},
   (arm7_instruction_t){arm7_coproc_data_op,       "CDO",     "cccc1110oooonnnndddd####ppp0mmmm"},
   (arm7_instruction_t){arm7_coproc_reg_transfer,  "CRT",     "cccc1110oooLnnnndddd####ppp1mmmm"},
   (arm7_instruction_t){arm7_software_interrupt,   "SWI",     "cccc1111------------------------"},
   
   (arm7_instruction_t){arm7_mrs,                  "MRS",     "cccc00010P001111dddd000000000000"},
   (arm7_instruction_t){arm7_msr,                  "MSR",     "cccc00010P10100F111100000000mmmm"},
   (arm7_instruction_t){arm7_msr,                  "MSR",     "cccc00110P10100F1111oooooooooooo"},



   (arm7_instruction_t){arm7_undefined,            "UNKNOWN1","cccc000001--------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN2","cccc00011---------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN3","cccc00010-1-------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN4","cccc00010-01------------1001----"}, 
   // Handle invalid opcode space in DP
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN5","cccc00010-00------------1--0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN6","cccc00010-00------------01-0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN7","cccc00010-00------------0010----"},

   (arm7_instruction_t){arm7_undefined,            "UNKNOWN8","cccc00010-00------------0--1----"},

   (arm7_instruction_t){arm7_undefined,            "UNKNOWN9","cccc00010110------------1--0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNA","cccc00010110------------01-0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNB","cccc00010110------------0010----"},

   (arm7_instruction_t){arm7_undefined,            "UNKNOWNC","cccc00010110------------0--1----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWND","cccc00010010------------01-1----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNE","cccc00010010------------0011----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNF","cccc00010010------------1--0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNG","cccc00010010------------01-0----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNH","cccc00010010------------0010----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNI","cccc00110-000000000000001-------"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNJ","cccc00110-0000000000000001------"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNK","cccc00110-00000000000000001-----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNL","cccc00110-000000000000000001----"},
   (arm7_instruction_t){arm7_undefined,            "UNKNOWNM","----00110-00------------0000----"},
};  

// ARM7 Thumb Classes
const static arm7_instruction_t arm7t_instruction_classes[]={
   (arm7_instruction_t){arm7t_mov_shift_reg,      "LSL",       "00000OOOOOsssddd"},
   (arm7_instruction_t){arm7t_mov_shift_reg,      "LSR",       "00001OOOOOsssddd"},
   (arm7_instruction_t){arm7t_mov_shift_reg,      "ASR",       "00010OOOOOsssddd"},
   (arm7_instruction_t){arm7t_add_sub,            "ADD",       "00011I0nnnsssddd"},
   (arm7_instruction_t){arm7t_add_sub,            "SUB",       "00011I1nnnsssddd"},
   (arm7_instruction_t){arm7t_mov_cmp_add_sub_imm,"MCASIMM",   "001oodddOOOOOOOO"},
   (arm7_instruction_t){arm7t_alu_op,             "ALU",       "010000oooosssddd"},
   (arm7_instruction_t){arm7t_hi_reg_op,          "HROP",      "010001oohHsssddd"},
   (arm7_instruction_t){arm7t_pc_rel_ldst,        "PCRLD",     "01001dddOOOOOOOO"},
   (arm7_instruction_t){arm7t_reg_off_ldst,       "LDST[RD]",  "0101LB0ooobbbddd"},
   (arm7_instruction_t){arm7t_ldst_bh,            "SLDST[RD]", "0101HS1ooobbbddd"},
   (arm7_instruction_t){arm7t_imm_off_ldst,       "LDST[IMM]", "011BLOOOOObbbddd"},
   (arm7_instruction_t){arm7t_imm_off_ldst_bh,    "SLDSTH[IMM]","1000LOOOOObbbddd"},
   (arm7_instruction_t){arm7t_stack_off_ldst,     "LDST[SP]",  "1001LdddOOOOOOOO"},
   (arm7_instruction_t){arm7t_load_addr,          "LDADDR",    "1010SdddOOOOOOOO"},
   (arm7_instruction_t){arm7t_add_off_sp,         "SP+=OFF",   "10110000SOOOOOOO"},
   (arm7_instruction_t){arm7t_push_pop_reg,       "PUSHPOPREG","1011L10Rllllllll"},
   (arm7_instruction_t){arm7t_mult_ldst,          "MLDST",     "1100Lbbbllllllll"},
   // Conditional branches cant branch on condition 1111
   (arm7_instruction_t){arm7t_cond_branch,        "BEQ",       "11010000OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BNE",       "11010001OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BCS",       "11010010OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BCC",       "11010011OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BMI",       "11010100OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BPL",       "11010101OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BVS",       "11010110OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BVC",       "11010111OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BHI",       "11011000OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BLS",       "11011001OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BGE",       "11011010OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BLT",       "11011011OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BGT",       "11011100OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "BLE",       "11011101OOOOOOOO"},
   (arm7_instruction_t){arm7t_cond_branch,        "COND B",    "11011110OOOOOOOO"},

   (arm7_instruction_t){arm7t_soft_interrupt,     "SWI",       "11011111OOOOOOOO"},
   (arm7_instruction_t){arm7t_branch,             "B",         "11100OOOOOOOOOOO"},
   (arm7_instruction_t){arm7t_long_branch_link,   "BL",        "1111HOOOOOOOOOOO"},
   //Empty Opcode Space
   (arm7_instruction_t){arm7t_unknown,   "UNKNOWN1",           "1011--1---------"},
   (arm7_instruction_t){arm7t_unknown,   "UNKNOWN2",           "10110001--------"},
   (arm7_instruction_t){arm7t_unknown,   "UNKNOWN3",           "1011100---------"},
   (arm7_instruction_t){arm7t_unknown,   "UNKNOWN4",           "11101-----------"},


};  

static arm7_handler_t arm7_lookup_table[4096] = {};
static arm7_handler_t arm7t_lookup_table[4096] = {};

static inline unsigned arm7_reg_index(arm7_t* cpu, unsigned reg){
  if(reg<8 ||reg == 15 || reg==16)return reg;
  int mode = ARM7_BFE(cpu->registers[CPSR],0,5);
  if(mode == 0x10)mode=0;      // User
  else if(mode == 0x11)mode=1; // FIQ
  else if(mode == 0x12)mode=2; // IRQ
  else if(mode == 0x13)mode=3; // Supervisor
  else if(mode == 0x17)mode=4; // Abort
  else if(mode == 0x1b)mode=5; // Undefined
  else if(mode == 0x1f)mode=6; // System
  else {
    cpu->trigger_breakpoint=true;
    printf("Undefined ARM mode: %d\n",mode);
    return 0; 
  }
  
  // System and User mapping (SPSR returns CPSR)
  if(mode == 0 ||mode ==6) return reg==17? 16: reg; 
  // FIQ specific registers
  if(mode == 1 && reg<15) return reg+17-8; 
  // SPSR
  if(reg==SPSR)return 32+mode-1;

  if(reg==13 || reg ==14 )return 22+(mode-1)*2 + (reg-13);

  return reg; 
}
static inline void arm7_reg_write(arm7_t*cpu, unsigned reg, uint32_t value){
  cpu->registers[arm7_reg_index(cpu,reg)] = value;
} 
static inline uint32_t arm7_reg_read(arm7_t*cpu, unsigned reg){
  return cpu->registers[arm7_reg_index(cpu,reg)];
}
static inline uint32_t arm7_reg_read_r15_adj(arm7_t*cpu, unsigned reg, int r15_off){
  uint32_t v = arm7_reg_read(cpu,reg);
  if(reg==15){
    v+=r15_off;
    if(arm7_get_thumb_bit(cpu))v-=2;
  }
  return v; 
}

static int arm7_lookup_arm_instruction_class(uint32_t opcode_key){
  int key_bits[] = {4,5,6,7, 20,21,22,23,24,25,26,27};
  int matched_class = -1; 
  for(int c = 0; c<sizeof(arm7_instruction_classes)/sizeof(arm7_instruction_t);++c){
    bool matches = true; 
    for(int bit = 0; bit< sizeof(key_bits)/sizeof(key_bits[0]); ++bit){
      bool bit_value = (opcode_key>>bit)&1; 
      int b_off = key_bits[bit]; 
      matches &= arm7_instruction_classes[c].bitfield[31-b_off] != '1' || bit_value == true; 
      matches &= arm7_instruction_classes[c].bitfield[31-b_off] != '0' || bit_value == false;
      if(!matches)break; 
    }
    if(matches){
      if(matched_class!=-1){
        int32_t op_value = 0; 
        char opcode[33]="00000000000000000000000000000000";
        for(int bit = 0; bit< sizeof(key_bits)/sizeof(key_bits[0]); ++bit){
          bool bit_value = (opcode_key>>bit)&1;
          if(bit_value){
            opcode[31-key_bits[bit]]='1';
            op_value|= 1<<key_bits[bit];
          }
        }
        printf("ARM7: Class %s and %s have ambiguous encodings for: %s %08x %d\n", 
          arm7_instruction_classes[c].name,
          arm7_instruction_classes[matched_class].name,
          opcode, op_value,opcode_key);
      }
      matched_class = c; 
    }
  }
  if(matched_class==-1){
    uint32_t op_value = 0; 
    char opcode[33]="00000000000000000000000000000000";
    for(int bit = 0; bit< sizeof(key_bits)/sizeof(key_bits[0]); ++bit){
      bool bit_value = (opcode_key>>bit)&1;
      if(bit_value){
        opcode[31-key_bits[bit]]='1';
        op_value|= 1<<key_bits[bit];
      }
    }
    printf("ARM7: No matching instruction class for key: %s %08x\n", opcode,op_value); 
  } 
  return matched_class; 
}
static int arm7_lookup_thumb_instruction_class(uint32_t opcode_key){
  int key_bits[] = {8,9,10,11,12,13,14,15};
  int matched_class = -1; 
  for(int c = 0; c<sizeof(arm7t_instruction_classes)/sizeof(arm7_instruction_t);++c){
    bool matches = true; 
    for(int bit = 0; bit< sizeof(key_bits)/sizeof(key_bits[0]); ++bit){
      bool bit_value = (opcode_key>>bit)&1; 
      int b_off = key_bits[bit];
      matches &= arm7t_instruction_classes[c].bitfield[15-b_off] != '1' || bit_value == true; 
      matches &= arm7t_instruction_classes[c].bitfield[15-b_off] != '0' || bit_value == false;
      if(!matches)break; 
    }

    if(matches){
      if(matched_class!=-1){
        printf("ARM7t: Class %s and %s have ambiguous encodings\n", 
          arm7t_instruction_classes[c].name,
          arm7t_instruction_classes[matched_class].name);
      }
      matched_class = c; 
    }
  }
  if(matched_class==-1){
    uint32_t op_value = 0; 
    char opcode[17]="0000000000000000";
    for(int bit = 0; bit< sizeof(key_bits)/sizeof(key_bits[0]); ++bit){
      bool bit_value = (opcode_key>>bit)&1;
      if(bit_value){
        opcode[15-key_bits[bit]]='1';
        op_value|= 1<<key_bits[bit];
      }
    }
    printf("ARM7T: No matching instruction class for key: %s %04x\n", opcode,op_value); 
  } 
  return matched_class;
}
static arm7_t arm7_init(void* user_data){
  // Generate ARM lookup table
	for(int i=0;i<4096;++i){
		 int inst_class = arm7_lookup_arm_instruction_class(i);
     arm7_lookup_table[i]=inst_class==-1? NULL: arm7_instruction_classes[inst_class].handler;
	}
  // Generate Thumb Lookup Table
  for(int i=0;i<256;++i){
    int inst_class = arm7_lookup_thumb_instruction_class(i);
    arm7t_lookup_table[i]=inst_class==-1 ? NULL: arm7t_instruction_classes[inst_class].handler;
  }
  arm7_t arm = {.user_data = user_data};
  //arm.log_cmp_file = fopen("/Users/skylersaleh/GBA-Logs/logs/irqdemo1-log.bin","rb");

  return arm;

}
static inline bool arm7_get_thumb_bit(arm7_t* cpu){return ARM7_BFE(cpu->registers[CPSR],5,1);}
static inline void arm7_set_thumb_bit(arm7_t* cpu, bool value){
  cpu->registers[CPSR] &= ~(1<<5);
  if(value)cpu->registers[CPSR]|= 1<<5;
}
static void arm7_process_interrupts(arm7_t* cpu, uint32_t interrupts){
  uint32_t cpsr = cpu->registers[CPSR];
  bool I = ARM7_BFE(cpsr,7,1);
  if(I==0 && interrupts){
    //cpu->trigger_breakpoint=true;
    uint32_t v1 = arm7_read32(cpu->user_data, 0x03007ffc);
    uint32_t v2 = arm7_read32(cpu->user_data, 0x04000000-4);

    printf("Interrupt triggered! Mem[0x0300'7ffc]:%08x Mem[0x04000000-5]:%08x \n",v1,v2);
    //Interrupts are enabled when I ==0
    bool thumb = arm7_get_thumb_bit(cpu);
    cpu->registers[R14_irq] = cpu->registers[PC]+4;
    cpu->registers[PC] = 0x18; 
    cpu->registers[SPSR_irq] = cpsr;
    //Update mode to IRQ
    cpu->registers[CPSR] = (cpsr&0xffffffE0)| 0x12;
    //Disable interrupts(set I bit)
    cpu->registers[CPSR] |= 1<<7;
    arm7_set_thumb_bit(cpu,false); 
  }
}
static void arm7_get_disasm(arm7_t * cpu, uint32_t mem_address, char* out_disasm, size_t out_size){
  out_disasm[0]='\0';
  const char * cond_code = "";
  const char * name = "INVALID";
  if(arm7_get_thumb_bit(cpu)==false){
    uint32_t opcode = arm7_read32(cpu->user_data,mem_address);

    const char* cond_code_table[16]=
      {"EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","","INV"};
    cond_code= cond_code_table[ARM7_BFE(opcode,28,4)];

    uint32_t key = ((opcode>>4)&0xf)| ((opcode>>16)&0xff0);
    int instr_class = arm7_lookup_arm_instruction_class(key);
    name = instr_class==-1? "INVALID" : arm7_instruction_classes[instr_class].name;
    // Get more information for the DP class instruction
    if(strcmp(name,"DP")==0){
        const char* op_name[]={"AND", "EOR", "SUB", "RSB", 
                              "ADD", "ADC", "SBC", "RSC",
                              "TST", "TEQ", "CMP", "CMN",
                              "ORR", "MOV", "BIC", "MVN"};
        name = op_name[ARM7_BFE(opcode,21,4)];
    }
  }else{
    uint16_t opcode = arm7_read16(cpu->user_data,mem_address);
    uint32_t key = ((opcode>>8)&0xff);
    int instr_class = arm7_lookup_thumb_instruction_class(key);
    name = instr_class==-1? "INVALID" : arm7t_instruction_classes[instr_class].name;
  }
  int offset = sprintf(out_disasm,"%s%s",name,cond_code);

  return; 
}
static inline bool arm7_check_cond_code(arm7_t *cpu, uint32_t opcode){
  uint32_t cond_code = ARM7_BFE(opcode,28,4);
  if(cond_code==0xE)return true;
  uint32_t cpsr = cpu->registers[CPSR];
  bool N = ARM7_BFE(cpsr,31,1);
  bool Z = ARM7_BFE(cpsr,30,1);
  bool C = ARM7_BFE(cpsr,29,1);
  bool V = ARM7_BFE(cpsr,28,1);
  switch(cond_code){
    case 0x0: return Z;            //EQ: Equal
    case 0x1: return !Z;           //NE: !Equal
    case 0x2: return C;            //CS: Unsigned >=
    case 0x3: return !C;           //CC: Unsigned <
    case 0x4: return N;            //MI: Negative
    case 0x5: return !N;           //PL: Positive or Zero
    case 0x6: return V;            //VS: Overflow
    case 0x7: return !V;           //VC: No Overflow
    case 0x8: return C && !Z;      //HI: Unsigned >
    case 0x9: return !C || Z;      //LS: Unsigned <=
    case 0xA: return N==V;         //GE: Signed >=
    case 0xB: return N!=V;         //LT: Signed <  
    case 0xC: return !Z&&(N==V);   //GT: Signed >  
    case 0xD: return Z||(N!=V);    //LE: Signed <= 
  };
  return false; 
}
static inline void arm7_exec_instruction(arm7_t* cpu){
  if(cpu->log_cmp_file){
    fseek(cpu->log_cmp_file,(cpu->executed_instructions+2)*18*4,SEEK_SET);
    uint32_t cmp_regs[18];
    fread(cmp_regs,18*4,1,cpu->log_cmp_file);
    uint32_t regs[18];
    for(int i=0;i<18;++i)regs[i]=arm7_reg_read(cpu,i);
    if(arm7_get_thumb_bit(cpu)==false){
      unsigned oldpc = cpu->registers[PC]; 
      cmp_regs[15]-=8;
    }else{
      unsigned oldpc = cpu->registers[PC]; 
      cmp_regs[15]-=4;
    }

    bool matches = true;
    for(int i=0;i<18;++i)matches &= cmp_regs[i]==regs[i];
    if(!matches){
      cpu->trigger_breakpoint =true;
      printf("Log mismatch detected\n");
      printf("=====================\n");

      printf("After %llu executed_instructions\n",cpu->executed_instructions);

      char * rnames[18]={
        "R0","R1","R2","R3","R4","R5","R6","R7",
        "R8","R9","R10","R11","R12","R13","R14","R15",
        "CPSR","SPSR"
      };
      fseek(cpu->log_cmp_file,(cpu->executed_instructions+1)*18*4,SEEK_SET);
      uint32_t prev_regs[18];
      fread(prev_regs,18*4,1,cpu->log_cmp_file);
      for(int i=0;i<18;++i)
        printf("%s %d (%08x) Log Value = %d (%08x) Prev Value =%d (%08x)\n", rnames[i],regs[i],regs[i],cmp_regs[i],cmp_regs[i],prev_regs[i],prev_regs[i]);
      uint32_t log_cpsr = cmp_regs[16];
      uint32_t prev_cpsr = prev_regs[16];

      uint32_t cpsr = regs[16];
      printf("N:%d LogN:%d PrevN:%d Z:%d LogZ:%d PrevZ:%d C:%d LogC:%d PrevC:%d V:%d LogV:%d PrevV:%d\n",
        ARM7_BFE(cpsr,31,1), ARM7_BFE(log_cpsr,31,1), ARM7_BFE(prev_cpsr,31,1),
        ARM7_BFE(cpsr,30,1), ARM7_BFE(log_cpsr,30,1), ARM7_BFE(prev_cpsr,30,1),
        ARM7_BFE(cpsr,29,1), ARM7_BFE(log_cpsr,29,1), ARM7_BFE(prev_cpsr,29,1),
        ARM7_BFE(cpsr,28,1), ARM7_BFE(log_cpsr,28,1), ARM7_BFE(prev_cpsr,28,1)
      ); 
      for(int i=0;i<18;++i)arm7_reg_write(cpu,i,cmp_regs[i]);
    }

  }
  bool thumb = arm7_get_thumb_bit(cpu);
  int old_pc = cpu->registers[PC];
  if(thumb==false){
    uint32_t opcode = arm7_read32(cpu->user_data,old_pc);
    cpu->registers[PC] += 4;
    uint32_t key = ((opcode>>4)&0xf)| ((opcode>>16)&0xff0);
    int inst_class = arm7_lookup_arm_instruction_class(key);
    if(cpu->log_cmp_file) printf("ARM OP: %08x PC: %08x\n",opcode,old_pc);
    if(arm7_check_cond_code(cpu,opcode)){
    	arm7_lookup_table[key](cpu,opcode);
    }
  }else{
    uint32_t opcode = arm7_read16(cpu->user_data,cpu->registers[PC]);
    if(cpu->log_cmp_file)printf("THUMB OP: %04x PC: %08x\n",opcode,old_pc);
    cpu->registers[PC] += 2;
    uint32_t key = ((opcode>>8)&0xff);
    int inst_class = arm7_lookup_thumb_instruction_class(key);
    arm7t_lookup_table[key](cpu,opcode);
  }
  //Bit 0 of PC is always 0
  cpu->registers[PC]&= ~1; 
  cpu->executed_instructions++;

}
static inline uint32_t arm7_rotr(uint32_t value, uint32_t rotate) {
  return ((uint64_t)value >> (rotate &31)) | ((uint64_t)value << (32-(rotate&31)));
}
static inline uint32_t arm7_load_shift_reg(arm7_t* arm, uint32_t opcode, int* carry){
  uint32_t value = arm7_reg_read(arm, ARM7_BFE(opcode,0,4)); 
  uint32_t shift_value = 0; 
  if(ARM7_BFE(opcode,4,1)==true){
    int rs = ARM7_BFE(opcode,8,4);
    shift_value = arm7_reg_read(arm, rs);
  }else{
    shift_value = ARM7_BFE(opcode,7,5);
  }
  return arm7_shift(arm,opcode,value,shift_value,carry);
}
static inline uint32_t arm7_shift(arm7_t* arm, uint32_t opcode, uint64_t value, uint32_t shift_value, int* carry){
  int shift_type = ARM7_BFE(opcode,5,2);
  // Shift value of 0 has special behavior from a register: 
  // If this byte is zero, the unchanged contents of Rm will be used as the second operand,
  // and the old value of the CPSR C flag will be passed on as the shifter carry output.
  if(shift_value==0&&ARM7_BFE(opcode,4,1)){*carry=-1;return value;}
  switch(shift_type){
    case 0:
      if(shift_value>32){
        *carry = 0; 
        value = 0;
      }else{
        *carry = shift_value==0? -1: ARM7_BFE(value, 32-shift_value,1);
        value = value<<shift_value;
      }
      break;
    case 1: 
      if(shift_value>32){
        *carry = 0;
        value = 0; 
      }else{
        if(shift_value ==0){shift_value=32;}
        *carry = ARM7_BFE(value, shift_value-1,1);
        value = value>>shift_value;
      }
      break; 
    case 2:
      if(shift_value>32){
        bool b31 = ARM7_BFE(value,31,1);
        value= b31? 0xffffffff :0;
        *carry= b31;
      }else{
        if(shift_value ==0){shift_value=32;}
        *carry = ARM7_BFE(value, shift_value-1,1);
        value = (int64_t)((int32_t)value)>>shift_value;
      }
      break; 
    case 3: 
      if(shift_value==0){
        uint32_t cpsr=arm->registers[CPSR];
        int C = ARM7_BFE(cpsr,29,1); 
        //Rotate Extended (RRX)
        *carry = ARM7_BFE(value,0,1); value = (value>>1)|(C<<31);

      }else{
        //Rotate
        value = arm7_rotr(value,shift_value); *carry = ARM7_BFE(value,31,1);
      }
      break;
  }                               
  return value;
}
static inline void arm7_data_processing(arm7_t* cpu, uint32_t opcode){

  // If it's used as anything but the shift amount in an operation with a register-specified shift, r15 will be PC + 12
  // I.e. add r0, r15, r15, lsl r15 would set r0 to PC + 12 + ((PC + 12) << (PC + 8))
  uint64_t Rd = ARM7_BFE(opcode,12,4);
  int S = ARM7_BFE(opcode,20,1);
  int I = ARM7_BFE(opcode,25,1);
  int op = ARM7_BFE(opcode,21,4);

  int r15_off = 4; 

  // Load Second Operand
  uint64_t Rm = 0;
  int barrel_shifter_carry = 0; 
  if(I){
    uint32_t imm = ARM7_BFE(opcode,0,8);
    uint32_t rot = ARM7_BFE(opcode,8,4)*2;
    Rm = arm7_rotr(imm, ARM7_BFE(opcode,8,4)*2);
    //C is preserved when rot ==0 
    barrel_shifter_carry =  rot==0?-1: ARM7_BFE(Rm,31,1);
  }else{
    uint32_t shift_value = 0; 
    if(ARM7_BFE(opcode,4,1)){
      int rs = ARM7_BFE(opcode,8,4);
      // Only the first byte is used
      shift_value = arm7_reg_read_r15_adj(cpu, rs,r15_off)&0xff;
      r15_off+=4; //Using r15 for a shift adds 4 cycles
    }else shift_value = ARM7_BFE(opcode,7,5);  
    uint32_t value = arm7_reg_read_r15_adj(cpu, ARM7_BFE(opcode,0,4),r15_off); 
    Rm = arm7_shift(cpu, opcode, value, shift_value, &barrel_shifter_carry); 
  }

  uint64_t Rn = arm7_reg_read_r15_adj(cpu, ARM7_BFE(opcode,16,4), r15_off);

  uint64_t result = 0; 
  // Perform main operation
  uint32_t cpsr=cpu->registers[CPSR];
  int C = ARM7_BFE(cpsr,29,1); 
  switch(op){ 
    /*AND*/ case 0:  result = Rn&Rm;     break;
    /*EOR*/ case 1:  result = Rn^Rm;     break;
    /*SUB*/ case 2:  result = Rn-Rm;     break;
    /*RSB*/ case 3:  result = Rm-Rn;     break;
    /*ADD*/ case 4:  result = Rn+Rm;     break;
    /*ADC*/ case 5:  result = Rn+Rm+C;   break;
    /*SBC*/ case 6:  result = Rn-Rm+C-1; break;
    /*RSC*/ case 7:  result = Rm-Rn+C-1; break;
    /*TST*/ case 8:  result = Rn&Rm;     break;
    /*TEQ*/ case 9:  result = Rn^Rm;     break;
    /*CMP*/ case 10: result = Rn-Rm;     break;
    /*CMN*/ case 11: result = Rn+Rm;     break;
    /*ORR*/ case 12: result = Rn|Rm;     break;
    /*MOV*/ case 13: result = Rm;        break;
    /*BIC*/ case 14: result = Rn&~Rm;    break;
    /*MVN*/ case 15: result = ~Rm;       break;
  }

  // Writeback result
  // TST, TEQ, CMP, CMN don't write result
  if(op<8||op>11) arm7_reg_write(cpu,Rd,result);

  //Update flags
  if(S){
    //Rd is not valid for TST, TEQ, CMP, or CMN
    {
      bool N = ARM7_BFE(result,31,1);
      bool Z = (result&0xffffffff)==0;
      bool V = ARM7_BFE(cpsr,28,1);

      switch(op){ 
      // Logical Ops flags
      /*AND*/ case 0:
      /*EOR*/ case 1: 
      /*TST*/ case 8: 
      /*TEQ*/ case 9: 
      /*ORR*/ case 12:
      /*MOV*/ case 13:
      /*BIC*/ case 14:
      /*MVN*/ case 15: C = barrel_shifter_carry==-1? C: barrel_shifter_carry; break;

      /*SUB*/ case 2: 
      /*SBC*/ case 6:  
      /*CMP*/ case 10: 
        C = !ARM7_BFE(result,32,1);
        // if (Rn has a different sign as Rm and result has a differnt sign to Rn)
        V = (((Rn ^ Rm) & (Rn ^ result)) >> 31)&1;
        break;

      /*RSB*/ case 3: 
      /*RSC*/ case 7: 
        C = !ARM7_BFE(result,32,1);
        // if (Rm has a different sign as Rn and result has a differnt sign to Rm)
        V = (((Rm ^ Rn) & (Rm ^ result)) >> 31)&1;
        break;

      /*ADD*/ case 4:
      /*ADC*/ case 5:
      /*CMN*/ case 11: 
        C = ARM7_BFE(result,32,1);
        // if (Rm has the same sign as Rn and result has a different sign to Rm)
        V = (((Rm ^ ~Rn) & (Rm ^ result)) >> 31)&1;
        break;
      }
      cpsr&= 0x0fffffff;
      cpsr|= (N?1:0)<<31;   
      cpsr|= (Z?1:0)<<30;
      cpsr|= (C?1:0)<<29; 
      cpsr|= (V?1:0)<<28;
      cpu->registers[CPSR] = cpsr;
    }
    if(Rd==15){
      // When Rd is R15 and the S flag is set the result of the operation is placed in R15 
      // and the SPSR corresponding to the current mode is moved to the CPSR. This allows
      // state changes which atomically restore both PC and CPSR. This form of instruction
      // should not be used in User mode.
      cpsr = arm7_reg_read(cpu,SPSR);
      cpu->registers[CPSR] = cpsr;
    }


  }
}
static inline void arm7_multiply(arm7_t* cpu, uint32_t opcode){
  bool A = ARM7_BFE(opcode,21,1);
  bool S = ARM7_BFE(opcode,20,1);
  int64_t Rd = ARM7_BFE(opcode,16,4);
  int64_t Rn = arm7_reg_read(cpu,ARM7_BFE(opcode,12,4));
  int64_t Rs = arm7_reg_read(cpu,ARM7_BFE(opcode,8,4));
  int64_t Rm = arm7_reg_read(cpu,ARM7_BFE(opcode,0,4));

  int64_t result = Rm*Rs;
  if(A)result+=Rn;

  arm7_reg_write(cpu,Rd,result);

  if(S){
    uint32_t cpsr = cpu->registers[CPSR];
    bool N = ARM7_BFE(result,31,1);
    bool Z = (result&0xffffffff)==0;
    bool C = ARM7_BFE(cpsr,29,1);
    bool V = ARM7_BFE(cpsr,28,1);
    cpsr&= 0x0ffffff;
    cpsr|= (N?1:0)<<31;   
    cpsr|= (Z?1:0)<<30;
    cpsr|= (C?1:0)<<29; 
    cpsr|= (V?1:0)<<28;
    cpu->registers[CPSR] = cpsr;
  }
}
static inline void arm7_multiply_long(arm7_t* cpu, uint32_t opcode){
  bool U = ARM7_BFE(opcode,22,1);
  bool A = ARM7_BFE(opcode,21,1);
  bool S = ARM7_BFE(opcode,20,1);
  int64_t RdHi = ARM7_BFE(opcode,16,4);
  int64_t RdLo = ARM7_BFE(opcode,12,4);
  int64_t Rs = arm7_reg_read(cpu,ARM7_BFE(opcode,8,4));
  int64_t Rm = arm7_reg_read(cpu,ARM7_BFE(opcode,0,4));

  int64_t RdHiLo = arm7_reg_read(cpu,RdHi);
  RdHiLo = (RdHiLo<<32)| arm7_reg_read(cpu,RdLo);

  if(U){
    Rm = (int32_t)Rm;
    Rs = (int32_t)Rs;
  }
  int64_t result =  Rm*Rs;
  if(A)result+=RdHiLo;

  arm7_reg_write(cpu,RdHi,result>>32);
  arm7_reg_write(cpu,RdLo,result&0xffffffff);

  if(S){
    uint32_t cpsr = cpu->registers[CPSR];
    bool N = ARM7_BFE(result,63,1);
    bool Z = result==0;
    bool C = ARM7_BFE(cpsr,29,1);
    bool V = ARM7_BFE(cpsr,28,1);
    cpsr&= 0x0ffffff;
    cpsr|= (N?1:0)<<31;   
    cpsr|= (Z?1:0)<<30;
    cpsr|= (C?1:0)<<29; 
    cpsr|= (V?1:0)<<28;
    cpu->registers[CPSR] = cpsr;
  }

}
static inline void arm7_single_data_swap(arm7_t* cpu, uint32_t opcode){
  bool B = ARM7_BFE(opcode, 22,1);
  uint32_t addr = arm7_reg_read_r15_adj(cpu,ARM7_BFE(opcode,16,4),4);
  uint32_t Rd = ARM7_BFE(opcode,12,4);
  uint32_t Rm = ARM7_BFE(opcode,0,4);
  // Load
  uint32_t read_data = B ? arm7_read8(cpu->user_data,addr): arm7_read32(cpu->user_data,addr);

  uint32_t store_data = arm7_reg_read_r15_adj(cpu,Rm,8);
  if(B==1)arm7_write8(cpu->user_data,addr,store_data);
  else arm7_write32(cpu->user_data,addr,store_data);

  arm7_reg_write(cpu,Rd,read_data);  
  
}
static inline void arm7_branch_exchange(arm7_t* cpu, uint32_t opcode){
  int v = arm7_reg_read(cpu,ARM7_BFE(opcode,0,4));
  bool thumb = (v&1)==1;
  if(thumb)cpu->registers[PC] = (v&~1);
  else cpu->registers[PC] = (v&~3);
  arm7_set_thumb_bit(cpu,thumb);
}
static inline void arm7_half_word_transfer(arm7_t* cpu, uint32_t opcode){
  bool P = ARM7_BFE(opcode,24,1);
  bool U = ARM7_BFE(opcode,23,1);
  bool I = ARM7_BFE(opcode,22,1);
  bool W = ARM7_BFE(opcode,21,1);
  bool L = ARM7_BFE(opcode,20,1);
  int Rn = ARM7_BFE(opcode,16,4);

  bool S = ARM7_BFE(opcode,6,1);
  bool H = ARM7_BFE(opcode,5,1);

  int offset = I == 0 ? 
               arm7_reg_read(cpu,ARM7_BFE(opcode,0,4)) : 
               ((opcode>>4)&0xf0)|(opcode&0xf);
  
  uint64_t Rd = ARM7_BFE(opcode,12,4);
  uint32_t addr = arm7_reg_read(cpu, Rn);

  int increment = U? offset: -offset;
  if(P) addr += increment;
  // Store before writeback
  if(L==0){ 
    uint32_t data = arm7_reg_read(cpu,Rd);
    if(H==1)arm7_write16(cpu->user_data,addr,data);
    else arm7_write8(cpu->user_data,addr,data);
  }
  uint32_t write_back_addr = addr;
  if(!P) {write_back_addr+=increment;W=true;}
  if(W)arm7_reg_write(cpu,Rn,write_back_addr); 
  if(L==1){ // Load
    uint32_t data = H ? arm7_read16(cpu->user_data,addr): arm7_read8(cpu->user_data,addr);
    if(S){
      // Unaligned signed half words and signed byte loads sign extend the byte 
      if(H&& !(addr&1)) {
        data|= 0xffff0000*ARM7_BFE(data,15,1);
      }
      else  data|= 0xffffff00*ARM7_BFE(data,7,1);
    }
    arm7_reg_write(cpu,Rd,data);  
  }
  
}
static inline void arm7_single_word_transfer(arm7_t* cpu, uint32_t opcode){
  bool I = ARM7_BFE(opcode,25,1);
  bool P = ARM7_BFE(opcode,24,1);
  bool U = ARM7_BFE(opcode,23,1);
  bool B = ARM7_BFE(opcode,22,1);
  bool W = ARM7_BFE(opcode,21,1);
  bool L = ARM7_BFE(opcode,20,1);
  int Rn = ARM7_BFE(opcode,16,4);
  int carry; 
  int offset = I == 0 ? ARM7_BFE(opcode,0,12): 
               arm7_load_shift_reg(cpu, opcode, &carry);
  
  uint64_t Rd = ARM7_BFE(opcode,12,4);
  uint32_t addr = arm7_reg_read_r15_adj(cpu, Rn,4);
  int increment = U? offset: -offset;

  if(P) addr += increment;

  // Store before write back
  if(L==0){ 
    uint32_t data = arm7_reg_read_r15_adj(cpu,Rd,8);
    if(B==1)arm7_write8(cpu->user_data,addr,data);
    else arm7_write32(cpu->user_data,addr,data);
  }

  //Write back address before load
  uint32_t write_back_addr = addr; 
  if(!P) {write_back_addr+=increment;W=true;}
  if(W)arm7_reg_write(cpu,Rn,write_back_addr); 

  if(L==1){ // Load
    uint32_t data = B ? arm7_read8(cpu->user_data,addr): arm7_read32(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
}
static inline void arm7_undefined(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_undefined) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_block_transfer(arm7_t* cpu, uint32_t opcode){
  int P = ARM7_BFE(opcode,24,1);
  int U = ARM7_BFE(opcode,23,1);
  int S = ARM7_BFE(opcode,22,1);
  int w = ARM7_BFE(opcode,21,1);
  int L = ARM7_BFE(opcode,20,1);
  int Rn =ARM7_BFE(opcode,16,4);
  int reglist = ARM7_BFE(opcode,0,16);  

  // Examples pushing R1, R5, R7
  // P= 0(post) U = 0(dec)
  //   mem[Rn-8]   = R1
  //   mem[Rn-4] = R5
  //   mem[Rn-0] = R7
  //   Rn-=12

  // P= 0(post) U = 1(inc)
  //   mem[Rn]   = R1
  //   mem[Rn+4] = R5
  //   mem[Rn+8] = R7
  //   Rn+=12

  // P= 1(pre) U = 0(dec)
  //   mem[Rn-12]   = R1
  //   mem[Rn-8] = R5
  //   mem[Rn-4] = R7
  //   Rn-=12

  // P= 1(pre) U = 1(inc)
  //   mem[Rn+4]   = R1
  //   mem[Rn+8] = R5
  //   mem[Rn+12] = R7
  //   Rn+=12

  int addr = arm7_reg_read(cpu,Rn);
  int increment = U? 4: -4;
  int num_regs = 0; 
  for(int i=0;i<16;++i) if(ARM7_BFE(reglist,i,1)==1)num_regs+=1;
  int base_addr = addr;
  if(reglist==0){
    // Handle Empty Rlist case: R15 loaded/stored (ARMv4 only), and Rb=Rb+/-40h (ARMv4-v5).
    reglist = 1<<15;
    num_regs = 16;
  }
  if(!U)base_addr+=(num_regs)*increment;
  addr = base_addr; 
  if(U)base_addr+= (num_regs)*increment;

  
  if(!(P^U))addr+=4;

  // TODO: For some reason r15 is only offset by 4 in thumb mode. 
  // Check if other people do this to. 
  int r15_off = arm7_get_thumb_bit(cpu)? 4:8;
  // Address are word aligned
  addr&=~3;
  int cycle = 0; 
  for(int i=0;i<16;++i){
    //Writeback happens on second cycle
    //Todo, does post increment force writeback? 

    if(ARM7_BFE(reglist,i,1)==0)continue;  

    // When S is set the registers are read from the user bank
    int reg_index = S ? i : arm7_reg_index(cpu,i);
    //Store happens before writeback 
    if(!L) arm7_write32(cpu->user_data, addr,cpu->registers[reg_index] + (i==15?r15_off:0));

    //Writeback happens on second cycle
    if(++cycle==1 && w){
      arm7_reg_write(cpu,Rn,base_addr); 
    }

    // R15 is stored at PC+12
    if(L) cpu->registers[reg_index]=arm7_read32(cpu->user_data, addr);

    addr+=4;
    
    // If the instruction is a LDM then SPSR_<mode> is transferred to CPSR at
    // the same time as R15 is loaded.
    if(L&& S&& i==15){
      cpu->registers[CPSR] = arm7_reg_read(cpu,SPSR);
    }
  }
}
static inline void arm7_branch(arm7_t* cpu, uint32_t opcode){
  //Write Link Register if L=1
  if(ARM7_BFE(opcode,24,1)) arm7_reg_write(cpu, LR, cpu->registers[PC]);
  //Decode V and sign extend
  int v = ARM7_BFE(opcode,0,24);
  if(ARM7_BFE(v,23,1))v|=0xff000000;
  //Shift left and take into account prefetch
  int32_t pc_off = (v<<2)+4; 
  cpu->registers[PC]+=pc_off;
}
static inline void arm7_coproc_data_transfer(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_coproc_data_transfer) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_coproc_data_op(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_coproc_data_op) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_coproc_reg_transfer(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_coproc_reg_transfer) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_software_interrupt(arm7_t* cpu, uint32_t opcode){
  bool thumb = arm7_get_thumb_bit(cpu);
  cpu->registers[R14_svc] = cpu->registers[PC]-(thumb?0:4);
  cpu->registers[PC] = 0x8; 
  uint32_t cpsr = cpu->registers[CPSR];
  cpu->registers[SPSR_svc] = cpsr;
  //Update mode to supervisor and block irqs
  cpu->registers[CPSR] = (cpsr&0xffffffE0)| 0x13|0x80;
  arm7_set_thumb_bit(cpu,false);
}

static inline void arm7_mrs(arm7_t* cpu, uint32_t opcode){
  int P = ARM7_BFE(opcode,22,1);
  int Rd= ARM7_BFE(opcode,12,4);
  int data = arm7_reg_read(cpu,P ? SPSR: CPSR);
  arm7_reg_write(cpu,Rd,data);
}
static inline void arm7_msr(arm7_t* cpu, uint32_t opcode){
  int P = ARM7_BFE(opcode,22,1);
  int flags_only = !ARM7_BFE(opcode,16,1);
  int I = ARM7_BFE(opcode,25,1);
  int data = 0;
  int dest_reg = P ? SPSR: CPSR;

  // Mask behavior from: https://problemkaputt.de/gbatek.htm#armopcodespsrtransfermrsmsr
  uint32_t mask = 0;
  mask|= 0xff000000*ARM7_BFE(opcode,19,1);
  mask|= 0x00ff0000*ARM7_BFE(opcode,18,1);
  mask|= 0x0000ff00*ARM7_BFE(opcode,17,1);
  mask|= 0x000000ff*ARM7_BFE(opcode,16,1);

  int mode = cpu->registers[CPSR]&0x1f;
  printf("MSR: mode: %02x P: %d\n",mode,P);
  
  // There is no SPSR in user or system mode
  if(P && (mode==0x10 ||mode==0x1f)) return; 
  //User mode can only change the flags
  if(mode == 0x10)mask &=0xf0000000;
  

  if(I){
    int imm = ARM7_BFE(opcode,0,8);
    int rot = ARM7_BFE(opcode,8,4)*2;
    data = arm7_rotr(imm,rot);
  }else data = arm7_reg_read(cpu,ARM7_BFE(opcode,0,4));

  int old_data = arm7_reg_read(cpu,dest_reg);
  data&=mask;
  data|=old_data&~mask; 
  
  arm7_reg_write(cpu,dest_reg,data);
}


// Thumb Instruction Implementations
static inline void arm7t_mov_shift_reg(arm7_t* cpu, uint32_t opcode){
  uint32_t op = ARM7_BFE(opcode,11,2);
  uint32_t offset= ARM7_BFE(opcode,6,5);
  uint32_t Rs = ARM7_BFE(opcode,3,3);
  uint32_t Rd = ARM7_BFE(opcode,0,3);

  uint32_t arm_op = (0xD<<21)|(1<<20)|(Rd<<12)|(offset<<7)|(op<<5)|(Rs);
  arm7_data_processing(cpu,arm_op);
}
static inline void arm7t_add_sub(arm7_t* cpu, uint32_t opcode){
  bool I = ARM7_BFE(opcode,10,1);
  int op = ARM7_BFE(opcode,9,1) ? /*Sub*/ 2 : /*Add*/ 4;
  int Rn = ARM7_BFE(opcode,6,3);
  int Rs = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);
  uint32_t arm_op = (I<<25)|(op<<21)|(1<<20)|(Rs<<16)|(Rd<<12)|(Rn);
  arm7_data_processing(cpu,arm_op);
}
static inline void arm7t_mov_cmp_add_sub_imm(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,11,2);
  int Rd = ARM7_BFE(opcode,8,3);
  int imm = ARM7_BFE(opcode,0,8);

  switch(op){ 
    /*MOV*/ case 0: op = 0xD; break;
    /*CMP*/ case 1: op = 0xA; break;
    /*ADD*/ case 2: op = 0x4; break;
    /*SUB*/ case 3: op = 0x2; break;
  }
  uint32_t arm_op = (1<<25)|(op<<21)|(1<<20)|(Rd<<16)|(Rd<<12)|(imm);
  arm7_data_processing(cpu, arm_op);
}
static inline void arm7t_alu_op(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,6,4);
  int Rs = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);

  int op_mapping[16]={
    /*AND{S}*/ 0,
    /*EOR{S}*/ 1, 
    /*LSL{S}*/ 13, 
    /*LSR{S}*/ 13,
    /*ASR{S}*/ 13, 
    /*ADC{S}*/ 5, 
    /*SBC{S}*/ 6, 
    /*ROR{S}*/ 13, 
    /*TST   */ 8,  
    /*NEG{S}*/ 3,/*ARM Op: RSBS Rd, Rs, #0*/
    /*CMP   */ 10, 
    /*CMN   */ 11,
    /*ORR{S}*/ 12, 
    /*MUL{S}*/ 16,
    /*BIC{S}*/ 14,      
    /*MVN{S}*/ 15
  };
  int shift_mapping[16]={
    /*AND{S}*/ 0,
    /*EOR{S}*/ 0, 
    /*LSL{S}*/ 0, 
    /*LSR{S}*/ 1,
    /*ASR{S}*/ 2, 
    /*ADC{S}*/ 0, 
    /*SBC{S}*/ 0, 
    /*ROR{S}*/ 3, 
    /*TST   */ 0,  
    /*NEG{S}*/ 0,/*ARM Op: RSBS Rd, Rs, #0*/
    /*CMP   */ 0, 
    /*CMN   */ 0,
    /*ORR{S}*/ 0, 
    /*MUL{S}*/ 0,
    /*BIC{S}*/ 0,      
    /*MVN{S}*/ 0
  };

  int alu_op = op_mapping[op];
  int shift_op = shift_mapping[op];
  int Rn = (op==9)?Rs:Rd;
  if(alu_op==16){
    uint32_t arm_op = (0xE<<28)|(1<<20)|(Rd<<16)|(Rn<<8)|(9<<4)|(Rs);
    arm7_multiply(cpu, arm_op);
    return; 
  }

  uint32_t arm_op = (0xE<<28)|(alu_op<<21)|(1<<20)|(Rn<<16)|(Rd<<12)|(shift_op<<5);
  
  if(alu_op==13)arm_op |= (Rs<<8)|(1<<4)|Rd; // Special case shifts
  else if(op==9)arm_op |= 1<<25;          // Special case MVN
  else arm_op|=Rs;
  arm7_data_processing(cpu, arm_op);
}
static inline void arm7t_hi_reg_op(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,8,2);
  int H1 = ARM7_BFE(opcode,7,1);
  int H2 = ARM7_BFE(opcode,6,1);
  int Rs = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);

  Rs|= H2<<3;
  Rd|= H1<<3;

  if(op==3){
    // Only the Rs field is populated since that is all that is needed for
    // arm7_branch_exchange
    int arm_op= Rs;
    arm7_branch_exchange(cpu,arm_op);
  }else{
    int S= op==1;
    int op_mapping[3]={/*Add*/4, /*CMP*/10,/*MOV*/13 };
    op = op_mapping[op];
    //cccc 001o oooS nnnn dddd rrrr OOOO OOOO
    uint32_t arm_op = (op<<21)|(S<<20)|(op==13?0:(Rd<<16))|(Rd<<12)|(Rs<<0);
    arm7_data_processing(cpu, arm_op);
  }
}
static inline void arm7t_pc_rel_ldst(arm7_t* cpu, uint32_t opcode){
  int offset = ARM7_BFE(opcode,0,8)*4;
  int Rd = ARM7_BFE(opcode,8,3);
  uint32_t addr = (cpu->registers[PC]+offset+2)&(~3);
  uint32_t data = arm7_read32(cpu->user_data,addr);
  arm7_reg_write(cpu,Rd,data);  
}
static inline void arm7t_reg_off_ldst(arm7_t* cpu, uint32_t opcode){
  bool B = ARM7_BFE(opcode,10,1);
  bool L = ARM7_BFE(opcode,11,1);
  int Ro = ARM7_BFE(opcode,6,3);
  int Rb = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);

  int r15_off = 2; 
  Ro = arm7_reg_read_r15_adj(cpu,Ro,r15_off);
  Rb = arm7_reg_read_r15_adj(cpu,Rb,r15_off);

  uint32_t addr = Ro+Rb;
  // Store before write back
  if(L==0){ 
    uint32_t data = arm7_reg_read_r15_adj(cpu,Rd,r15_off);
    if(B==1)arm7_write8(cpu->user_data,addr,data);
    else arm7_write32(cpu->user_data,addr,data);
  }else{ // Load
    uint32_t data = B ? arm7_read8(cpu->user_data,addr): arm7_read32(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }

}
static inline void arm7t_ldst_bh(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,10,2);
  int Ro = ARM7_BFE(opcode,6,3);
  int Rb = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);

  int r15_off = 2; 
  Ro = arm7_reg_read_r15_adj(cpu,Ro,r15_off);
  Rb = arm7_reg_read_r15_adj(cpu,Rb,r15_off);
                                     
  uint32_t addr = Ro+Rb;
         
  uint32_t data; 
  switch(op){
    case 0: //Store Halfword
      data = arm7_reg_read_r15_adj(cpu,Rd,r15_off);
      break;
    case 1: //Load Sign Extended Byte
      data = arm7_read8(cpu->user_data,addr);
      if(ARM7_BFE(data,7,1))data|=0xffffff00;
      break; 
    case 2: //Load Halfword
      data = arm7_read16(cpu->user_data,addr);
      break;          
    case 3: //Load Sign Extended Half
      data = arm7_read16(cpu->user_data,addr);
      //Unaligned halfwords sign extend the byte
      if((addr&1)&&ARM7_BFE(data,7,1))data|=0xffffff00;
      else if(ARM7_BFE(data,15,1))data|=0xffff0000;
      break; 
  }
  if(op==0)arm7_write16(cpu->user_data,addr,data);
  else arm7_reg_write(cpu,Rd,data);
}
static inline void arm7t_imm_off_ldst(arm7_t* cpu, uint32_t opcode){
  bool B = ARM7_BFE(opcode,12,1);
  bool L = ARM7_BFE(opcode,11,1);
  int offset = ARM7_BFE(opcode,6,5);
  
  uint32_t Rd = ARM7_BFE(opcode,0,3);
  uint32_t Rb = ARM7_BFE(opcode,3,3);
  uint32_t addr = arm7_reg_read(cpu, Rb);
  //Offset is in 4B increments for word loads
  if(!B)offset*=4;
  addr += offset;
  if(L==0){ // Store
    uint32_t data = arm7_reg_read(cpu,Rd);
    if(B==1)arm7_write8(cpu->user_data,addr,data);
    else arm7_write32(cpu->user_data,addr,data);
  }else{ // Load
    uint32_t data = B ? arm7_read8(cpu->user_data,addr): arm7_read32(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
}
static inline void arm7t_imm_off_ldst_bh(arm7_t* cpu, uint32_t opcode){
  bool L = ARM7_BFE(opcode,11,1);
  int offset = ARM7_BFE(opcode,6,5);
  
  uint32_t Rd = ARM7_BFE(opcode,0,3);
  uint32_t addr = arm7_reg_read(cpu, ARM7_BFE(opcode,3,3));

  addr += offset*2;
  uint32_t data=0;
  if(L==0){ // Store
    data = arm7_reg_read(cpu,Rd);
    arm7_write16(cpu->user_data,addr,data);
  }else{ // Load
    data = arm7_read16(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
}
static inline void arm7t_stack_off_ldst(arm7_t* cpu, uint32_t opcode){
  bool L = ARM7_BFE(opcode,11,1);
  uint64_t Rd = ARM7_BFE(opcode,8,3);
  int offset = ARM7_BFE(opcode,0,8);
  uint32_t addr = arm7_reg_read(cpu,13);

  addr += offset*4;
  uint32_t data; 
  if(L==0){ // Store
    data = arm7_reg_read(cpu,Rd);
    arm7_write32(cpu->user_data,addr,data);
  }else{ // Load
    data = arm7_read32(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
}
static inline void arm7t_load_addr(arm7_t* cpu, uint32_t opcode){
  bool SP = ARM7_BFE(opcode,11,1);
  int Rd = ARM7_BFE(opcode,8,3);
  int imm = ARM7_BFE(opcode,0,8)*4;

  uint32_t v = arm7_reg_read_r15_adj(cpu,SP?13:15,4);
  if(!SP)v&= ~3; //Bit 1 of PC always read as 0
  v+=imm;
  arm7_reg_write(cpu,Rd, v);
}
static inline void arm7t_add_off_sp(arm7_t* cpu, uint32_t opcode){
  int32_t offset = ARM7_BFE(opcode,0,7)*4;
  int sign = ARM7_BFE(opcode,7,1);
  if(sign)offset=-offset;
  uint32_t value = arm7_reg_read(cpu,13);
  arm7_reg_write(cpu,13,value+offset);
}
static inline void arm7t_push_pop_reg(arm7_t* cpu, uint32_t opcode){
  bool push_or_pop = ARM7_BFE(opcode,11,1);
  bool include_pc_lr = ARM7_BFE(opcode,8,1);
  uint32_t r_list = ARM7_BFE(opcode,0,8);
  int P = !push_or_pop; 
  int W = 1;
  int U = push_or_pop; 

  uint32_t arm_op = (0xe<<28)|(4<<25)|(P<<24)|(U<<23)|(W<<21)|(push_or_pop<<20)|(13<<16)|r_list;
  if(include_pc_lr)arm_op|=push_or_pop? 0x8000 : 0x4000;
  arm7_block_transfer(cpu,arm_op);
}
static inline void arm7t_mult_ldst(arm7_t* cpu, uint32_t opcode){
  bool write_or_read = ARM7_BFE(opcode,11,1);
  int Rb = ARM7_BFE(opcode,8,3);
  uint32_t r_list = ARM7_BFE(opcode,0,8);
                                
  int P = 0; 
  int U = 1;                                         
  int W = 1;
  // Maps to LDMIA, STMIA opcode
  uint32_t arm_op = (0xe<<28)|(4<<25)|(P<<24)|(U<<23)|(W<<21)|(write_or_read<<20)|(Rb<<16)|r_list;
  arm7_block_transfer(cpu,arm_op);
}
static inline void arm7t_cond_branch(arm7_t* cpu, uint32_t opcode){
  int cond = ARM7_BFE(opcode,8,4);
  int s_off = ARM7_BFE(opcode,0,8);
  if(ARM7_BFE(s_off,7,1))s_off|=0xFFFFFF00;
  //ARM equv: cccc 1010 OOOO OOOO OOOO OOOO OOOO OOOO
  uint32_t arm_op = (cond<<28)|(0xA<<24); 
  if(arm7_check_cond_code(cpu,arm_op)){
    cpu->registers[PC]+=s_off*2+2;
  }
}
static inline void arm7t_soft_interrupt(arm7_t* cpu, uint32_t opcode){
  arm7_software_interrupt(cpu,opcode);
}
static inline void arm7t_branch(arm7_t* cpu, uint32_t opcode){
  int offset = ARM7_BFE(opcode,0,11)<<1;
  if(ARM7_BFE(offset,11,1))offset|=0xfffff000;
  cpu->registers[PC]+=offset+2;
}
static inline void arm7t_long_branch_link(arm7_t* cpu, uint32_t opcode){
  bool H = ARM7_BFE(opcode,11,1);
  int offset = ARM7_BFE(opcode,0,11);
  int thumb_branch = ARM7_BFE(opcode,12,1);
  uint32_t link_reg = arm7_reg_read(cpu,LR);
  // TODO: Is this +4 supposed to be +2 ARM7TDMI page 5-40
  if(H==0){
    offset <<= 12;
    if (offset& 0x400000) offset |= 0xFF800000;
    arm7_reg_write(cpu,LR,cpu->registers[PC] + offset+2);
  }else{
    link_reg += (offset<<1);
    uint32_t pc = cpu->registers[PC];
    cpu->registers[PC]= link_reg;
    arm7_reg_write(cpu,LR,(pc|thumb_branch));
    if(!thumb_branch)arm7_set_thumb_bit(cpu,false);
  }
}
static inline void arm7t_unknown(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_unknown) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}

#endif
