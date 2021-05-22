#!/usr/bin/env python3
import pandas as panda
tables = panda.read_html("../docs/gbops%20-%20The%20Game%20Boy%20opcode%20table.html")
opcode_table = tables[0] #Selecting the first table (for example)
opcode_table2 = tables[1] #Selecting the first table (for example)
opcode_table=opcode_table.drop(axis=1,labels="--");
opcode_table2=opcode_table2.drop(axis=1,labels="--");

print(opcode_table);
print(opcode_table2);
opcode_list=[]

for r_index, row in opcode_table.iterrows(): #iterate over rows
    for c_index, value in row.items():
        if isinstance(value, float): value="NOP_NO_INSTR 1 1m ----";
        opcode_list+=[value.replace("\u200b","")]

for r_index, row in opcode_table2.iterrows(): #iterate over rows
    for c_index, value in row.items():
        if isinstance(value, float): value="NOP_NO_INSTR 1 1m ----";
        opcode_list+=[value.replace("\u200b","")]
 
print(opcode_list);

unique_ops ={}

with open("../src/sb_instr_tables.h","w") as f:
  f.write("""
#ifndef SB_INSTR_TABLES
#define SB_INSTR_TABLES 1

#include <stdint.h>

typedef struct{
  sb_opcode_impl_t impl;
  const char* opcode_name;
  uint8_t flag_mask[5];
  uint8_t length; // in bytes
  uint8_t mcycles;
  uint8_t mcycles_branch_taken;
}sb_instr_t;

const static sb_instr_t sb_decode_table[]={
""")
  for op in opcode_list:
    op_name = op.split(' ')[0];
    unique_ops[op_name] = True;
    splits = op.rsplit(' ', maxsplit=3);
    instr_name ='"'+splits[0]+'"';
    taken_latency = "0";
    split_mcycles = splits[2].replace('m','').split('-');
    if len(split_mcycles)>1:
       taken_latency=split_mcycles[1];
    non_taken_latency = split_mcycles[0];

    impl_name = "sgb_"+op_name.lower()+"_impl";
    impl_name ="0";
    f.write(f'  {{ {impl_name:16}, {instr_name:16}, "{splits[3]}", {splits[1]}, {non_taken_latency}, {taken_latency} }},\n') 

  f.write("""
};
#endif
""");
for op in opcode_list:
  unique_ops[op.split(' ')[0]] = True;
  splits = op.rsplit(' ', maxsplit=3);
  print(splits)

for op in unique_ops:
  print(op);
