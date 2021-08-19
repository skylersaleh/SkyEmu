def bfe(value, bitoffset, size):
  return ((value >> bitoffset) & ((1<< size) - 1));
"""
optable =[]
for i in range(0, 2**10):
  bits20to27 = bfe(i,2,8);
  bits24to27 = bfe(bits20to27,3,4);
  bits25to27 = bfe(bits24to27,1,3);
  bits26to27 = bfe(bits24to27,2,2);
  bit4 = bfe(i,0,1);    
  bit8 = bfe(i,1,1);
  bit22 = bfe(bits20to27,2,1);
  bit25 = bfe(bits25to27,0,1);
  
  op ={} 
  if bits24to27 == 0b1111:
    op["name"] = "swi"
  elif bits24to27 == 0b1110:
    if bit4:
      op["name"] = "crt";
    else:
      op["name"] = "cdo";
  elif bits25to27 == 0xb110:
    op["name"] = "cdt"
  elif bits25to27 == 0x101:
    op["name"] = "b"
  elif bits25to27 == 0x100: 
    op["name"] = "bdt"
  elif bits26to27 == 0x01:
    if bit4 == True and bit25 == True:
      op["name"] = "undefined"
    else:
      op["name"] = "sdt"
  elif bits25to27 == 0x000:
    if
  else:
    op["name"] = "unknown"
  optable+=[op]

"""                                            

def gen_parameter_list(pattern):
  curr_param = pattern[31];
  curr_start = 0;
  curr_size = 0;
  params=[]
  for i in range(0,28):
    letter = pattern[31-i];
    if letter!=curr_param:
      if curr_param not in "01-":
        params += [[curr_param, curr_start, curr_size]]
      curr_size = 0;
      curr_param = letter
      curr_start = i;
    curr_size+=1;
  return params;  

    

optable ={}
needed_functions = []           
internal_op_table =[]
with open('docs/arm.inc',"r") as f:
  intern_op = 0; 
  for line in f.readlines():
    if len(line)<2: continue;
    if(line[0]=='/' and line[1] =='/'): continue;
    inst = line; 
    version = "v1"
    if "//" in line: 
      (inst, version) = line.split("//");

    version = version.strip();

    if int(version[1]) > 4: continue
    inst = inst.strip();
    inst = inst.split("INST(")[1].rsplit(")",1)[0];

    (handler, pneumonic, pattern) = inst.split(",");
    pattern = pattern.replace('"',"").strip();
    
    parameter_ranges = gen_parameter_list(pattern);

    for l in "tvmnxcwSdArsDpuOMonNa":
      pattern = pattern.replace(l,"-");

    handler = handler.replace("arm","arm7tdmi") 
    pneumonic = pneumonic.replace('"',"").strip();
    print(handler, pneumonic, pattern, version);
    needed_functions+=[handler];

    optable[pneumonic] = {
      "pattern": pattern,
      "handler": handler,
      "intern_op": intern_op,
      "params" : parameter_ranges
    };
    internal_op_table += [pneumonic]
    intern_op+=1;
                                     
def match_op(optable, arm_op):
  best_match_bits = -1; 
  best_match_name = "unknown"

  for opname in optable:
    pattern = optable[opname]["pattern"];
    bits = 0;
    match = True;
    for i in range(0,31):
      if i>27: continue
      if i<20 and i>7:continue
      if i<4: continue; 
      bit1 = bfe(arm_op,i,1);
      pat_bit = pattern[31-i];
      if pat_bit == '-': continue;
      if pat_bit == '0' and bit1 !=0: match = False; break;
      if pat_bit == '1' and bit1 !=1: match = False; break;
      bits +=1
    if match and bits > best_match_bits:
      best_match_bits = bits;
      best_match_name = opname;

  return best_match_name; 



decode_table = "  static const uint16_t conv_intern_op[]={\n";
count = 0; 
for lookup_op in range(0,4096):
  bits7_4 = bfe(lookup_op,0,4);
  bits27_20 = bfe(lookup_op,4,8);

  arm_op = (bits7_4<<4) | (bits27_20<<20)

  decoded_op = match_op(optable,arm_op);
  opvalue = optable[decoded_op]["intern_op"];
  if(lookup_op==288): print(lookup_op,optable[decoded_op]["handler"]);

  if count==0: decode_table+='   ';
  decode_table+=f' {opvalue},';
  count +=1
  if(count>=16):
    count =0;
    decode_table+='\n';
  
decode_table+="  };\n";

disasm_table = "static const char * gba_disasm_name[]={\n";
count = 0; 
for op in internal_op_table:
  if count==0: disasm_table+=' ';
  disasm_table+=f' "{op}",';
  count +=1
  if(count>=8):
    count =0;
    disasm_table+='\n';
   
disasm_table+="};\n";


dispatch_table =  """
void gba_execute_instr(gba_t* gba, uint32_t opcode){\n
  int intern_op = gba_intern_op(opcode);
  switch(intern_op){
"""

for i in range(0,len(internal_op_table)):
  func = optable[internal_op_table[i]]["handler"]
  dispatch_table += f"    case {i}: {func}(gba, opcode);break;\n"

dispatch_table+="""
  };
}
"""
param_decode_table = """
typedef struct { struct{uint8_t name, start, size;} params[10];} arm7tdmi_param_t;
const static arm7tdmi_param_t arm7tdmi_params[]={\n
""" 
 
for i in range(0,len(internal_op_table)):
  params = optable[internal_op_table[i]]["params"]
  param_decode_table +="  {{";
  for p in params:
    param_decode_table += f"{{'{p[0]}',{p[1]},{p[2]}}},"
  param_decode_table += f"{{'\\0',0,0}},"
  param_decode_table +="}},\n";

param_decode_table+="};\n";

with open("src/gba_tables.h","w") as f:

  f.write("""
// Copyright Skyler Saleh
// 
// Autogenerated decoding tables. Do not modify by hand. 

#ifndef GBA_TABLES_H
#define GBA_TABLES_H 1
#include "arm7tdmi_instr.h"

// internal opcode = {arm_op[27:20],arm_op[7:0}
static inline int gba_intern_op(uint32_t arm_op){""")
  f.write(decode_table);
  f.write("""
  return conv_intern_op[((arm_op>>4)&0xf) | (((arm_op>>20)&0xff)<<4)];
}
// Table to map interal opcodes to pneumonics
""");
  f.write(disasm_table);

  f.write(param_decode_table);  
  f.write(dispatch_table);  
  f.write("#endif\n");

generate_prototypes = False;
if generate_prototypes:
  generated ={}
  with open("src/arm7tdmi_instr_tmp.h","w") as f:
    for iop in internal_op_table:
      funct = optable[iop]["handler"]
      if funct in generated: continue
      generated[funct]=1;
      f.write(f"static inline void {funct}(gba_t *gba, uint32_t opcode){{\n");
      for p in optable[iop]["params"]:
        f.write(f"  int {p[0]} = SB_BFE(opcode,{p[1]},{p[2]});\n");
      if "reg" in iop or "rsr" in iop:
        f.write("bool carry; m = arm7tdmi_load_shift_reg(&(gba->cpu),opcode,m,&carry); \n")
      f.write("  {\n");
      f.write(f'    printf("Hit Unimplemented {iop} %x\\n",opcode);\n');
      f.write("  }\n");
      f.write('  gba->cpu.trigger_breakpoint = true;\n');
      f.write('}\n');
      
