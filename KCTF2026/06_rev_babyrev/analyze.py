# -*- coding: utf-8 -*-
# 06 BabyRev: 符号表 + 关键函数反汇编
from elftools.elf.elffile import ELFFile
from capstone import *

path = r'D:\codes\ctf\KCTF2026\06_rev_babyrev\BabyRev'
f = open(path, 'rb')
elf = ELFFile(f)

symtab = elf.get_section_by_name('.symtab')
syms = []
for sym in symtab.iter_symbols():
    if sym['st_value'] and sym.name and sym['st_info']['type'] == 'STT_FUNC':
        syms.append((sym['st_value'], sym['st_size'], sym.name))
syms.sort()
print(f'函数符号 {len(syms)} 个（用户函数优先）:')
for addr, size, name in syms:
    if not name.startswith(('_Z', '__', '_dl', '_IO', '_nl', '@')):
        print(f'  0x{addr:x} size={size:5} {name}')

text = elf.get_section_by_name('.text')
ta, tdata = text['sh_addr'], text.data()
md = Cs(CS_ARCH_X86, CS_MODE_64)
for addr, size, name in syms:
    if name == 'main':
        off = addr - ta
        print(f'\n=== main @0x{addr:x} ===')
        for ins in md.disasm(tdata[off:off+min(size, 400)], addr):
            print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
