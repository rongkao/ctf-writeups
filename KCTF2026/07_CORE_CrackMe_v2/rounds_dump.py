# -*- coding: utf-8 -*-
# 07 CORE: 精读 round 2 / round 4 完整反汇编（X 寻址 + G/H/I 形式 + 索引更新）
from capstone import *

data = open(r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin', 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

print('=== ROUND 2 完整 (0x401650-0x4017b0) ===')
for ins in md.disasm(data[0x1650:0x17b0], BASE + 0x1650):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')

print()
print('=== ROUND 4 完整 (0x401950-0x401a95) ===')
for ins in md.disasm(data[0x1950:0x1a95], BASE + 0x1950):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
