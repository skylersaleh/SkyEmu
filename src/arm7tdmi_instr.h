static inline uint32_t arm7_rotr(uint32_t value, uint32_t rotate) {
    return (value >> (rotate &31)) | (value << (32-(rotate&31)));
}

static inline uint32_t arm7tdmi_load_shift_reg(arm7tdmi_t* arm, uint32_t opcode, uint32_t reg, bool* carry){
  bool shift_reg = SB_BFE(opcode,4,1)==true;
  int shift_type = SB_BFE(opcode,5,2);
  uint32_t value = arm7_reg_read(arm, reg); 
  uint32_t shift_value = 0; 
  if(shift_reg){
    int rs = SB_BFE(opcode,8,4);
    shift_value = arm7_reg_read(arm, rs);
  }else{
    shift_value = SB_BFE(opcode,7,5);
  }
  switch(shift_type){
    case 0: *carry = SB_BFE(value, 32-shift_value,1); value = value<<shift_value; break; 
    case 1: *carry = shift_value==0? false: SB_BFE(value, shift_value-1,1); value = value>>shift_value; break; 
    case 2: *carry = shift_value==0? false: SB_BFE(value, shift_value-1,1); value = ((int32_t)value)>>shift_value; break; 
    case 3: value = arm7_rotr(value,shift_value); *carry = SB_BFE(value,31,1); break; 
  }                               
  return value;
}
 
static inline void arm7_update_flags(arm7tdmi_t * arm, uint32_t value, bool C, bool V){
  uint32_t cpsr = arm->registers[CPSR];
  cpsr&= 0x0fffffff;
  cpsr|= value & (1<<31);   //N
  cpsr|= (value==0?1:0)<<30;//Z
  cpsr|= (C?1:0)<<29;       //C
  cpsr|= (V?1:0)<<28;       //V
  arm->registers[CPSR] = cpsr;
}                          
static inline void arm7_update_flags_logical(arm7tdmi_t * arm, uint32_t value, bool C){
  uint32_t cpsr = arm->registers[CPSR];
  cpsr&= 0x1fffffff;
  cpsr|= value & (1<<31);   //N
  cpsr|= (value==0?1:0)<<30;//Z
  cpsr|= (C?1:0)<<29;       //C
  arm->registers[CPSR] = cpsr;
}                          
static inline void arm7tdmi_B(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,24);
  {
    //Sign Extend v
    if(SB_BFE(v,23,1))v|=0xff000000;
    //Shift left and take into account prefetch
    int32_t pc_off = v<<2; 
    pc_off+=8;
    printf("%d\n",pc_off);
    gba->cpu.registers[PC]+=pc_off;
  }
}
static inline void arm7tdmi_BL(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,24);
  {
    printf("Hit Unimplemented BL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_BX(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  {
    printf("Hit Unimplemented BX %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_CDP(gba_t *gba, uint32_t opcode){
  int M = SB_BFE(opcode,0,4);
  int I = SB_BFE(opcode,5,3);
  int p = SB_BFE(opcode,8,4);
  int D = SB_BFE(opcode,12,4);
  int N = SB_BFE(opcode,16,4);
  int o = SB_BFE(opcode,20,4);
  {
    printf("Hit Unimplemented CDP %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDC(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int p = SB_BFE(opcode,8,4);
  int D = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int d = SB_BFE(opcode,22,1);
  int u = SB_BFE(opcode,23,1);
  int P = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDC %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MCR(gba_t *gba, uint32_t opcode){
  int M = SB_BFE(opcode,0,4);
  int I = SB_BFE(opcode,5,3);
  int p = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int N = SB_BFE(opcode,16,4);
  int o = SB_BFE(opcode,21,3);
  {
    printf("Hit Unimplemented MCR %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MRC(gba_t *gba, uint32_t opcode){
  int M = SB_BFE(opcode,0,4);
  int I = SB_BFE(opcode,5,3);
  int p = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int N = SB_BFE(opcode,16,4);
  int o = SB_BFE(opcode,21,3);
  {
    printf("Hit Unimplemented MRC %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STC(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int p = SB_BFE(opcode,8,4);
  int D = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int d = SB_BFE(opcode,22,1);
  int u = SB_BFE(opcode,23,1);
  int P = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented STC %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ADC_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ADC (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ADC_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ADC (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ADC_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1); 
  {
    printf("Hit Unimplemented ADC (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}                    
void arm7tdmi_ADD_impl(arm7tdmi_t* arm, uint32_t dest, uint32_t m, uint32_t n, bool S){
  uint64_t result = n+m;
  printf("n: %d + %d\n", n,m);
  arm7_reg_write(arm, dest, result);
  if(S){
    bool C = SB_BFE(result,32,1);
    uint32_t result2 = (n&0x7fffffff)+(m&0x7fffffff);
    bool V = SB_BFE(result2,31,1);
    arm7_update_flags(arm,result,C,V);
  }
}
static inline void arm7tdmi_ADD_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    uint32_t m= arm7_rotr(v,r*2);
    n= arm7_reg_read(&(gba->cpu),n);
    arm7tdmi_ADD_impl(&(gba->cpu),d,m,n,S);
  }
}
static inline void arm7tdmi_ADD_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    bool carry;
    m = arm7tdmi_load_shift_reg(&(gba->cpu),opcode,m,&carry); 
    arm7tdmi_ADD_impl(&(gba->cpu),d,m,n,S);
  }
}
static inline void arm7tdmi_ADD_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ADD (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_AND_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented AND (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_AND_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented AND (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_AND_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented AND (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_BIC_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented BIC (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_BIC_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented BIC (reg) %x\n",opcode);
  }                
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_BIC_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented BIC (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_CMN_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented CMN (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_CMN_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented CMN (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_CMN_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented CMN (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
void arm7tdmi_cmp_impl(arm7tdmi_t* arm, uint32_t m, uint32_t n){
  uint64_t result = ((uint64_t)n)-m;
  bool C = SB_BFE(result,32,1);
  uint32_t result2 = (n&0x7fffffff)-(m&0x7fffffff);
  bool V = SB_BFE(result2,31,1);
  arm7_update_flags(arm,result,C,V);
}
static inline void arm7tdmi_CMP_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {             
    uint32_t m= arm7_rotr(v,r*2);
    n= arm7_reg_read(&(gba->cpu),n);
    arm7tdmi_cmp_impl(&(gba->cpu),m,n); 
  }
}
static inline void arm7tdmi_CMP_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int n = SB_BFE(opcode,16,4);
  {
    bool carry;
    m = arm7tdmi_load_shift_reg(&(gba->cpu),opcode,m,&carry); 
    arm7tdmi_cmp_impl(&(gba->cpu),m,n); 
  }
}
static inline void arm7tdmi_CMP_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented CMP (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_EOR_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented EOR (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_EOR_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented EOR (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_EOR_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented EOR (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MOV_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    int m= arm7_rotr(v,r*2); 
    arm7_reg_write(&(gba->cpu),d,m);
    if(S && d !=15 ){
      arm7_update_flags_logical(&(gba->cpu), m, SB_BFE(v,31,1));   
    }
  }
}
static inline void arm7tdmi_MOV_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    bool carry = false;
    m = arm7tdmi_load_shift_reg(&(gba->cpu),opcode,m,&carry); 
    arm7_reg_write(&(gba->cpu),d,m);
    if(S && d !=15 ){
      arm7_update_flags_logical(&(gba->cpu), m, carry);   
    } 
  }
}
static inline void arm7tdmi_MOV_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MOV (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MVN_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MVN (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MVN_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MVN (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MVN_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MVN (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ORR_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ORR (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ORR_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ORR (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_ORR_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented ORR (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSB_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSB (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSB_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSB (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSB_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSB (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSC_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSC (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSC_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSC (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_RSC_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented RSC (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SBC_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SBC (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SBC_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SBC (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SBC_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SBC (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SUB_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SUB (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SUB_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SUB (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SUB_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SUB (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TEQ_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TEQ (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TEQ_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TEQ (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TEQ_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TEQ (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TST_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TST (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TST_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TST (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_TST_rsr(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int s = SB_BFE(opcode,8,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented TST (rsr) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SVC(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,24);
  {
    printf("Hit Unimplemented SVC %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_UDF(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented UDF %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_NOP(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented Reserved Hint %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SWP(gba_t *gba, uint32_t opcode){
  int u = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented SWP %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SWPB(gba_t *gba, uint32_t opcode){
  int u = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented SWPB %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRBT(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented LDRBT (A1) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRT(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented LDRT (A1) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STRBT(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented STRBT (A1) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STRT(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented STRT (A1) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDR_lit(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int u = SB_BFE(opcode,23,1);
  {
    printf("Hit Unimplemented LDR (lit) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDR_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDR (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDR_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDR (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRB_lit(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int u = SB_BFE(opcode,23,1);
  {
    printf("Hit Unimplemented LDRB (lit) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRB_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRB (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRB_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRB (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRH_lit(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRH (lit) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRH_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    int offset = v|(V<<4);
    int addr = arm7_reg_read(&(gba)->cpu,n); 
    int increment = u? offset: -offset;
    if(p)  addr+=increment;
    uint16_t data = gba_read16(gba, addr);
    if(!p) {addr+=increment;w=true;}

    if(w)arm7_reg_write(&(gba->cpu),n,addr); 
    arm7_reg_write(&(gba->cpu),t,data);
  }
}
static inline void arm7tdmi_LDRH_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRH (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSB_lit(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int u = SB_BFE(opcode,23,1);
  {
    printf("Hit Unimplemented LDRSB (lit) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSB_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRSB (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSB_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRSB (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSH_lit(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int u = SB_BFE(opcode,23,1);
  {
    printf("Hit Unimplemented LDRSH (lit) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSH_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRSH (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDRSH_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented LDRSH (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STR_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    int offset = v;
    int addr = arm7_reg_read(&(gba)->cpu,n); 
    int data = arm7_reg_read(&(gba)->cpu,t);
    int increment = u? offset: -offset;
    if(p)  addr+=increment;
    gba_store32(gba, addr, data);
    if(!p) {addr+=increment;w=true;}
    if(w)arm7_reg_write(&(gba)->cpu,n,addr); 
  }
}
static inline void arm7tdmi_STR_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented STR (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STRB_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,12);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented STRB (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STRB_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int r = SB_BFE(opcode,5,2);
  int v = SB_BFE(opcode,7,5);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented STRB (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STRH_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,4);
  int V = SB_BFE(opcode,8,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    int offset = v|(V<<4);
    int addr = arm7_reg_read(&(gba)->cpu,n); 
    int data = arm7_reg_read(&(gba)->cpu,t);
    int increment = u? offset: -offset;
    if(p)  addr+=increment;
    gba_store16(gba, addr, data);
    if(!p) {addr+=increment;w=true;}

    if(w)arm7_reg_write(&(gba)->cpu,n,addr);
  }
}
static inline void arm7tdmi_STRH_reg(gba_t *gba, uint32_t opcode){
  int m = SB_BFE(opcode,0,4);
  int t = SB_BFE(opcode,12,4);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  int u = SB_BFE(opcode,23,1);
  int p = SB_BFE(opcode,24,1);
  {
    printf("Hit Unimplemented STRH (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDM(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented LDM %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDMDA(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented LDMDA %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDMDB(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented LDMDB %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDMIB(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented LDMIB %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDM_usr(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented LDM (usr reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_LDM_eret(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented LDM (exce ret) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STM(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented STM %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STMDA(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented STMDA %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STMDB(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented STMDB %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STMIB(gba_t *gba, uint32_t opcode){
  int x = SB_BFE(opcode,0,16);
  int n = SB_BFE(opcode,16,4);
  int w = SB_BFE(opcode,21,1);
  {
    printf("Hit Unimplemented STMIB %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_STM_usr(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented STM (usr reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MLA(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int a = SB_BFE(opcode,12,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MLA %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MUL(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented MUL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SMLAL(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int a = SB_BFE(opcode,12,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SMLAL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_SMULL(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int a = SB_BFE(opcode,12,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented SMULL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_UMLAL(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int a = SB_BFE(opcode,12,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented UMLAL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_UMULL(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,8,4);
  int a = SB_BFE(opcode,12,4);
  int d = SB_BFE(opcode,16,4);
  int S = SB_BFE(opcode,20,1);
  {
    printf("Hit Unimplemented UMULL %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MRS(gba_t *gba, uint32_t opcode){
  int d = SB_BFE(opcode,12,4);
  {
    printf("Hit Unimplemented MRS %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MSR_imm(gba_t *gba, uint32_t opcode){
  int v = SB_BFE(opcode,0,8);
  int r = SB_BFE(opcode,8,4);
  int m = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented MSR (imm) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_MSR_reg(gba_t *gba, uint32_t opcode){
  int n = SB_BFE(opcode,0,4);
  int m = SB_BFE(opcode,16,4);
  {
    printf("Hit Unimplemented MSR (reg) %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
static inline void arm7tdmi_unknown(gba_t *gba, uint32_t opcode){
  {
    printf("Hit Unimplemented UNKWN %x\n",opcode);
  }
  gba->cpu.trigger_breakpoint = true;
}
