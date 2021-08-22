#ifndef ARM7_H
#define ARM7_H 1

#include <stdint.h>
#include <stdio.h>

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
} arm7_t;     

typedef void (*arm7_handler_t)(arm7_t *cpu, uint32_t opcode);
typedef struct{
	arm7_handler_t handler;
	char name[11];
	char bitfield[33];
}arm7_instruction_t;

////////////////////////
// User API Functions //
////////////////////////

// This function initializes the internal state needed for the arm7 core emulation
static arm7_t arm7_init(void* user_data);
static inline void arm7_exec_instruction(arm7_t* cpu);
// Memory IO functions for the emulated CPU (these must be defined by the user)
static uint32_t arm7_read32(void* user_data, uint32_t address);
static uint16_t arm7_read16(void* user_data, uint32_t address);
static uint8_t arm7_read8(void* user_data, uint32_t address);
static void arm7_write32(void* user_data, uint32_t address, uint32_t data);
static void arm7_write16(void* user_data, uint32_t address, uint16_t data);
static void arm7_write8(void* user_data, uint32_t address, uint8_t data);
// Write the dissassembled opcode from mem_address into the out_disasm string up to out_size characters
static void arm7_get_disasm(arm7_t * cpu, uint32_t mem_address, char* out_disasm, size_t out_size);

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
static inline void arm7_reg_write(arm7_t*cpu, unsigned reg, uint32_t value);
static inline unsigned arm7_reg_index(arm7_t* cpu, unsigned reg);
static int arm7_lookup_arm_instruction_class(uint32_t opcode_key);
static int arm7_lookup_thumb_instruction_class(uint32_t opcode_key);
static inline uint32_t arm7_load_shift_reg(arm7_t* arm, uint32_t opcode, int* carry);
static inline uint32_t arm7_rotr(uint32_t value, uint32_t rotate);
static inline bool arm7_get_thumb_bit(arm7_t* cpu);
static inline void arm7_set_thumb_bit(arm7_t* cpu, bool value);

#define ARM7_BFE(VALUE, BITOFFSET, SIZE) (((VALUE) >> (BITOFFSET)) & ((1u << (SIZE)) - 1))

// ARM7 ARM Classes
const static arm7_instruction_t arm7_instruction_classes[]={
   (arm7_instruction_t){arm7_data_processing,      "DP",      "cccc001ooooSnnnnddddrrrrOOOOOOOO"},
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
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN1","cccc000001--------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN2","cccc00011---------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN3","cccc00010-1-------------1001----"}, 
   (arm7_instruction_t){arm7_undefined,            "UNKNOWN4","cccc00010-01------------1001----"}, 
   // Handle invalid opcode space in DP
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWN5","cccc00010-00---------------0----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWN6","cccc00010-00------------0--1----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWN7","cccc00010110---------------0----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWN8","cccc00010110------------0--1----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWN9","cccc00010010------------01-1----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWNA","cccc00010010------------0011----"},
   (arm7_instruction_t){arm7_data_processing,      "UNKNOWNB","cccc00010010---------------0----"},

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
   (arm7_instruction_t){arm7t_imm_off_ldst_bh,    "SLDST[IMM]","1000LOOOOObbbddd"},
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

unsigned arm7_reg_index(arm7_t* cpu, unsigned reg){
  if(reg<8 ||reg == 15 || reg==16)return reg;
  int mode = SB_BFE(cpu->registers[CPSR],0,5);
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
  // System and User mapping
  if(mode == 0 ||mode ==6) return reg; 
  // FIQ specific registers
  if(mode == 1 && reg<15) return reg+17-8; 
  // SPSR
  if(reg==SPSR)return 32+mode-1;
  // 13 && 14
  if(reg==13 || reg ==14 )return 17+mode*2 + (reg-13);

  printf("Undefined register: %d for ARM mode: %d\n",reg,mode);
  return 0; 
}
void arm7_reg_write(arm7_t*cpu, unsigned reg, uint32_t value){
  cpu->registers[arm7_reg_index(cpu,reg)] = value;
} 
uint32_t arm7_reg_read(arm7_t*cpu, unsigned reg){
  return cpu->registers[arm7_reg_index(cpu,reg)];
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
  return arm;

}
static inline bool arm7_get_thumb_bit(arm7_t* cpu){return ARM7_BFE(cpu->registers[CPSR],5,1);}
static inline void arm7_set_thumb_bit(arm7_t* cpu, bool value){
  cpu->registers[CPSR] &= 1<<5;
  if(value)cpu->registers[CPSR]|= 1<<5;
}
static void arm7_get_disasm(arm7_t * cpu, uint32_t mem_address, char* out_disasm, size_t out_size){
  out_disasm[0]='\0';
  const char * cond_code = "";
  const char * name = "INVALID";
  if(arm7_get_thumb_bit(cpu)==false){
    uint32_t opcode = arm7_read32(cpu->user_data,mem_address);

    const char* cond_code_table[16]=
      {"EQ","NE","CS","CC","MI","PL","VS","VC","HI","LS","GE","LT","GT","LE","","INV"};
    cond_code= cond_code_table[SB_BFE(opcode,28,4)];

    uint32_t key = ((opcode>>4)&0xf)| ((opcode>>16)&0xff0);
    int instr_class = arm7_lookup_arm_instruction_class(key);
    name = instr_class==-1? "INVALID" : arm7_instruction_classes[instr_class].name;
    // Get more information for the DP class instruction
    if(strcmp(name,"DP")==0){
        const char* op_name[]={"AND", "EOR", "SUB", "RSB", 
                              "ADD", "ADC", "SBC", "RSC",
                              "TST", "TEQ", "CMP", "CMN",
                              "ORR", "MOV", "BIC", "MVN"};
        name = op_name[SB_BFE(opcode,21,4)];
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
  uint32_t cond_code = SB_BFE(opcode,28,4);
  if(cond_code==0xE)return true;
  uint32_t cpsr = cpu->registers[CPSR];
  bool N = SB_BFE(cpsr,31,1);
  bool Z = SB_BFE(cpsr,30,1);
  bool C = SB_BFE(cpsr,29,1);
  bool V = SB_BFE(cpsr,28,1);
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
  if(arm7_get_thumb_bit(cpu)==false){
    unsigned oldpc = cpu->registers[PC]; 
    cpu->registers[PC] += 4; 
    uint32_t opcode = arm7_read32(cpu->user_data,oldpc);
    if(arm7_check_cond_code(cpu,opcode)==false)return; 
  	uint32_t key = ((opcode>>4)&0xf)| ((opcode>>16)&0xff0);
  	arm7_lookup_table[key](cpu,opcode);
  }else{
    unsigned oldpc = cpu->registers[PC]; 
    cpu->registers[PC] += 2; 
    uint32_t opcode = arm7_read16(cpu->user_data,oldpc);
    uint32_t key = ((opcode>>8)&0xff);
    arm7t_lookup_table[key](cpu,opcode);
  }
  cpu->executed_instructions++;

}
static inline uint32_t arm7_rotr(uint32_t value, uint32_t rotate) {
    return (value >> (rotate &31)) | (value << (32-(rotate&31)));
}
static inline uint32_t arm7_load_shift_reg(arm7_t* arm, uint32_t opcode, int* carry){
  int shift_type = ARM7_BFE(opcode,5,2);
  uint32_t value = arm7_reg_read(arm, ARM7_BFE(opcode,0,4)); 
  uint32_t shift_value = 0; 
  if(ARM7_BFE(opcode,4,1)==true){
    int rs = ARM7_BFE(opcode,8,4);
    shift_value = arm7_reg_read(arm, rs);
  }else{
    shift_value = ARM7_BFE(opcode,7,5);
  }
  switch(shift_type){
    case 0: *carry = ARM7_BFE(value, 32-shift_value,1); value = value<<shift_value; break; 
    case 1: *carry = shift_value==0? -1: ARM7_BFE(value, shift_value-1,1); value = value>>shift_value; break; 
    case 2: *carry = shift_value==0? -1: ARM7_BFE(value, shift_value-1,1); value = ((int32_t)value)>>shift_value; break; 
    case 3: value = arm7_rotr(value,shift_value); *carry = ARM7_BFE(value,31,1); break; 
  }                               
  return value;
}
static inline void arm7_data_processing(arm7_t* cpu, uint32_t opcode){

  // TODO: Handle R15 operand read behavior 
  // If it's used as anything but the shift amount in an operation with a register-specified shift, r15 will be PC + 12
  // I.e. add r0, r15, r15, lsl r15 would set r0 to PC + 12 + ((PC + 12) << (PC + 8))
  uint64_t Rd = ARM7_BFE(opcode,12,4);
  uint64_t Rn = arm7_reg_read(cpu, ARM7_BFE(opcode,16,4));
  int S = ARM7_BFE(opcode,20,1);
  int I = ARM7_BFE(opcode,25,1);
  int op = ARM7_BFE(opcode,21,4);

  // Load Second Operand
  uint64_t Rm = 0;
  int barrel_shifter_carry = 0; 
  if(I){
    uint32_t imm = ARM7_BFE(opcode,0,8);
    Rm = arm7_rotr(imm, ARM7_BFE(opcode,8,4)*2);
  }else Rm = arm7_load_shift_reg(cpu, opcode, &barrel_shifter_carry); 

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
    if(Rd==15){
      // When Rd is R15 and the S flag is set the result of the operation is placed in R15 
      // and the SPSR corresponding to the current mode is moved to the CPSR. This allows
      // state changes which atomically restore both PC and CPSR. This form of instruction
      // should not be used in User mode.
      cpsr = arm7_reg_read(cpu,SPSR);
    }else{
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
        C = SB_BFE(result,32,1);
        // if (Rn has a different sign as Rm and result has a differnt sign to Rn)
        V = ((Rn ^ Rm) & (Rn ^ result)) >> 31;
        break;

      /*RSB*/ case 3: 
      /*RSC*/ case 7:  Rd = Rm-Rn+C-1;
        C = SB_BFE(result,32,1);
        // if (Rm has a different sign as Rn and result has a differnt sign to Rm)
        V = ((Rm ^ Rn) & (Rm ^ result)) >> 31;
        break;

      /*ADD*/ case 4:
      /*ADC*/ case 5:
      /*CMN*/ case 11: 
        C = SB_BFE(result,32,1);
        // if (Rn has the same sign as Rm and result has a differnt sign)
        V = ((Rn ^ ~Rm) & (Rn ^ result)) >> 31;
        break;
      }

      cpsr&= 0x0fffffff;
      cpsr|= (N?1:0)<<31;   
      cpsr|= (Z?1:0)<<30;
      cpsr|= (C?1:0)<<29; 
      cpsr|= (V?1:0)<<28;
    }

    cpu->registers[CPSR] = cpsr;

  }
}
static inline void arm7_multiply(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_multiply) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_multiply_long(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_multiply_long) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_single_data_swap(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Instruction Class (arm7_single_data_swap) Opcode: %x\n",opcode);
  cpu->trigger_breakpoint = true;
}
static inline void arm7_branch_exchange(arm7_t* cpu, uint32_t opcode){
  int v = arm7_reg_read(cpu,ARM7_BFE(opcode,0,4));
  cpu->registers[PC] = v&~1;
  arm7_set_thumb_bit(cpu,(v&1)==1);
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
  if(L==0){ // Store
    uint32_t data = arm7_reg_read(cpu,Rd);
    if(H==1)arm7_write16(cpu->user_data,addr,data);
    else arm7_write8(cpu->user_data,addr,data);
  }else{ // Load
    uint32_t data = H ? arm7_read16(cpu->user_data,addr): arm7_read8(cpu->user_data,addr);
    if(S){
      if(H) data|= 0xffff0000*ARM7_BFE(data,15,1);
      else  data|= 0xffffff00*ARM7_BFE(data,7,1);
    }
    arm7_reg_write(cpu,Rd,data);  
  }
  if(!P) {addr+=increment;W=true;}
  if(W)arm7_reg_write(cpu,Rn,addr); 
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
  uint32_t addr = arm7_reg_read(cpu, Rn);

  int increment = U? offset: -offset;
  if(P) addr += increment;
  if(L==0){ // Store
    uint32_t data = arm7_reg_read(cpu,Rd);
    if(B==1)arm7_write8(cpu->user_data,addr,data);
    else arm7_write32(cpu->user_data,addr,data);
  }else{ // Load
    uint32_t data = B ? arm7_read8(cpu->user_data,addr): arm7_read32(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
  if(!P) {addr+=increment;W=true;}
  if(W)arm7_reg_write(cpu,Rn,addr); 
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
  
  int addr = arm7_reg_read(cpu,Rn);
  int increment = U? 4: -4;
  int new_addr = addr;
  for(int i=0;i<16;++i) if(ARM7_BFE(reglist,i,1)==1)new_addr+=increment;   
  for(int i=0;i<16;++i){
    if(ARM7_BFE(reglist,i,1)==0)continue;       
    //Writeback happens on second cycle
    //Todo, does post increment force writeback? 
    if(i==1 && w){
      arm7_reg_write(cpu,Rn,new_addr); 
    }
    if(P)  addr+=increment;

    // When S is set the registers are read from the user bank
    int reg_index = S ? i : arm7_reg_index(cpu,i);

    if(L) cpu->registers[reg_index]=arm7_read32(cpu->user_data, addr);
    else arm7_write32(cpu->user_data, addr,cpu->registers[reg_index]);
    
    // If the instruction is a LDM then SPSR_<mode> is transferred to CPSR at
    // the same time as R15 is loaded.
    if(L&& S&& i==15){
      printf("Restore CPSR\n");
      cpu->registers[CPSR] = arm7_reg_read(cpu->user_data,SPSR);
    }
    if(!P) {addr+=increment;w=true;}
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
  cpu->registers[R14_svc] = cpu->registers[PC];
  cpu->registers[PC] = 0x8; 
  uint32_t cpsr = cpu->registers[CPSR];
  cpu->registers[SPSR_svc] = cpsr;
  //Update mode to supervisor
  cpu->registers[CPSR] = (cpsr&0xffffffE0)| 0x13;
}

// Thumb Instruction Implementations
static inline void arm7t_mov_shift_reg(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,11,2);
  int offset= ARM7_BFE(opcode,6,5);
  int Rs = arm7_reg_read(cpu,ARM7_BFE(opcode,3,3));
  int Rd = ARM7_BFE(opcode,3,0);
  int result = 0;
  switch(op){
    case 00: result = Rs<<offset; 
    case 01: result = ((uint32_t)Rs)>>offset; 
    case 10: result = ((int32_t)Rs)>>offset; 
  }
  arm7_reg_write(cpu,Rd,result);
}
static inline void arm7t_add_sub(arm7_t* cpu, uint32_t opcode){
  bool I = ARM7_BFE(opcode,10,1);
  int op = ARM7_BFE(opcode,9,1);
  int Rn = ARM7_BFE(opcode,6,3);
  int Rs = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,0,3);

  if(!I) Rn = arm7_reg_read(cpu,Rn);
  uint64_t result = 0; 
  // Perform main operation
  uint32_t cpsr=cpu->registers[CPSR];
  int C = ARM7_BFE(cpsr,29,1); 

  switch(op){ 
    /*ADD*/ case 0:  result = Rs+Rn;     break;
    /*SUB*/ case 1:  result = Rs-Rn;     break;
  }
  // Writeback result
  arm7_reg_write(cpu,Rd,result);

  //Update flags
  bool N = ARM7_BFE(result,31,1);
  bool Z = (result&0xffffffff)==0;
  bool V = ARM7_BFE(cpsr,28,1);

  switch(op){ 
  /*ADD*/ case 0:
    C = SB_BFE(result,32,1);
    // if (Rs has the same sign as Rn and result has a differnt sign)
    V = ((Rs ^ ~Rn) & (Rs ^ result)) >> 31;
    break;
  /*SUB*/ case 1: 
    C = SB_BFE(result,32,1);
    // if (Rs has a different sign as Rn and result has a differnt sign to Rs)
    V = ((Rs ^ Rn) & (Rs ^ result)) >> 31;
    break;
  }

  cpsr&= 0x0fffffff;
  cpsr|= (N?1:0)<<31;   
  cpsr|= (Z?1:0)<<30;
  cpsr|= (C?1:0)<<29; 
  cpsr|= (V?1:0)<<28;

  cpu->registers[CPSR] = cpsr;

}
static inline void arm7t_mov_cmp_add_sub_imm(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,11,2);
  int Rd = ARM7_BFE(opcode,8,3);
  int Rn = arm7_reg_read(cpu,Rd);
  int Rm = ARM7_BFE(opcode,0,8);
  bool S = true;
  uint64_t result = 0; 

  // Perform main operation
  uint32_t cpsr=cpu->registers[CPSR];
  int C = ARM7_BFE(cpsr,29,1); 
  // 00 mov, 01 cmp, 10, add. 11 sub

  switch(op){ 
    /*MOV*/ case 0:  result = Rm;        break;
    /*CMP*/ case 1:  result = Rn-Rm;     break;
    /*ADD*/ case 2:  result = Rn+Rm;     break;
    /*SUB*/ case 3:  result = Rn-Rm;     break;
  }
  // Writeback result
  // CMP doesn't write result
  if(op!=1) arm7_reg_write(cpu,Rd,result);

  //Update flags
  bool N = ARM7_BFE(result,31,1);
  bool Z = (result&0xffffffff)==0;
  bool V = ARM7_BFE(cpsr,28,1);

  switch(op){ 
  /*MOV*/ case 0: C = false; break;

  /*SUB*/ case 1: 
  /*CMP*/ case 2: 
    C = SB_BFE(result,32,1);
    // if (Rn has a different sign as Rm and result has a differnt sign to Rn)
    V = ((Rn ^ Rm) & (Rn ^ result)) >> 31;
    break;

  /*ADD*/ case 3:
    C = SB_BFE(result,32,1);
    // if (Rn has the same sign as Rm and result has a differnt sign)
    V = ((Rn ^ ~Rm) & (Rn ^ result)) >> 31;
    break;
  }

  cpsr&= 0x0fffffff;
  cpsr|= (N?1:0)<<31;   
  cpsr|= (Z?1:0)<<30;
  cpsr|= (C?1:0)<<29; 
  cpsr|= (V?1:0)<<28;

  cpu->registers[CPSR] = cpsr;
}
static inline void arm7t_alu_op(arm7_t* cpu, uint32_t opcode){
  int op = ARM7_BFE(opcode,6,4);
  int Rs = ARM7_BFE(opcode,3,3);
  int Rd = ARM7_BFE(opcode,3,0);
  //cccc 001o oooS nnnn ddddrrrrOOOOOOOO
  uint32_t arm_op = (0xD2<<24)|(op<<21)|(1<<20)|(Rd<<16)|(Rd<<12)|(Rs<<0);
  arm7_data_processing(cpu, arm_op);
}
static inline void arm7t_hi_reg_op(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_hi_reg_op) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_pc_rel_ldst(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_pc_rel_ldst) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_reg_off_ldst(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_reg_off_ldst) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_ldst_bh(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_ldst_bh) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_imm_off_ldst(arm7_t* cpu, uint32_t opcode){
  bool B = ARM7_BFE(opcode,12,1);
  bool L = ARM7_BFE(opcode,13,1);
  int offset = ARM7_BFE(opcode,6,5);
  
  uint64_t Rd = ARM7_BFE(opcode,0,3);
  uint32_t addr = arm7_reg_read(cpu, ARM7_BFE(opcode,3,3));

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
  bool L = ARM7_BFE(opcode,13,1);
  int offset = ARM7_BFE(opcode,6,5);
  
  uint64_t Rd = ARM7_BFE(opcode,0,3);
  uint32_t addr = arm7_reg_read(cpu, ARM7_BFE(opcode,3,3));

  addr += offset;
  if(L==0){ // Store
    uint32_t data = arm7_reg_read(cpu,Rd);
    arm7_write16(cpu->user_data,addr,data);
  }else{ // Load
    uint32_t data = arm7_read16(cpu->user_data,addr);
    arm7_reg_write(cpu,Rd,data);  
  }
}
static inline void arm7t_stack_off_ldst(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_stack_off_ldst) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_load_addr(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_load_addr) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_add_off_sp(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_add_off_sp) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_push_pop_reg(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_push_pop_reg) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_mult_ldst(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_mult_ldst) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_cond_branch(arm7_t* cpu, uint32_t opcode){
  int cond = ARM7_BFE(opcode,8,4);
  int s_off = ARM7_BFE(opcode,0,8);
  if(ARM7_BFE(s_off,8,1))s_off|=0x00FFFFFF;
  //ARM equv: cccc 1010 OOOO OOOO OOOO OOOO OOOO OOOO
  uint32_t arm_op = (cond<<28)|(0xA<<24)|s_off; 
  if(arm7_check_cond_code(cpu,arm_op)){
    arm7_branch(cpu,arm_op);
  }
}
static inline void arm7t_soft_interrupt(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_soft_interrupt) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}
static inline void arm7t_branch(arm7_t* cpu, uint32_t opcode){
  int offset = ARM7_BFE(opcode,0,11)<<1;
  if(ARM7_BFE(offset,11,1))offset|=0xfffff000;
  cpu->registers[PC]+=offset+2;
}
static inline void arm7t_long_branch_link(arm7_t* cpu, uint32_t opcode){
  bool H = ARM7_BFE(opcode,11,1);
  int offset = ARM7_BFE(opcode,0,11);
  uint32_t link_reg = arm7_reg_read(cpu,LR);
  // TODO: Is this +4 supposed to be +2 ARM7TDMI page 5-40
  if(H==0) link_reg = cpu->registers[PC] + (offset<<12)+2;
  else{
    link_reg += (offset<<1);
    uint32_t pc = cpu->registers[PC];
    cpu->registers[PC]= link_reg;
    arm7_reg_write(cpu,LR,(pc)|1);
  }
}
static inline void arm7t_unknown(arm7_t* cpu, uint32_t opcode){
  printf("Unhandled Thumb Instruction Class: (arm7t_unknown) Opcode %x\n",opcode);
  cpu->trigger_breakpoint=true;
}

#endif