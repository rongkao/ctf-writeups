# -*- coding: utf-8 -*-
# KCTF 靶场 01_rechall 分析脚本：解析 ELF 符号 + 反汇编关键函数
from elftools.elf.elffile import ELFFile
from capstone import *

path = r'D:\codes\ctf\KCTF2026\01_rechall\rechall'
f = open(path, 'rb')
elf = ELFFile(f)

# 收集符号
symbols = {}
symtab = elf.get_section_by_name('.symtab')
for sym in symtab.iter_symbols():
    if sym['st_value'] and sym.name:
        symbols[sym.name] = (sym['st_value'], sym['st_size'])

targets = ['main', 'checker1', 'checker2', 'checker3', 'checker4']
print("=== 符号 ===")
for t in targets:
    if t in symbols:
        print(f"{t}: addr=0x{symbols[t][0]:x} size={symbols[t][1]}")

# 拿 .text 段内容
text = elf.get_section_by_name('.text')
text_addr = text['sh_addr']
text_data = text.data()

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

def disasm(name):
    if name not in symbols: return
    addr, size = symbols[name]
    off = addr - text_addr
    code = text_data[off:off+size]
    print(f"\n=== {name} @ 0x{addr:x} ===")
    for ins in md.disasm(code, addr):
        print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")

for t in targets:
    disasm(t)
