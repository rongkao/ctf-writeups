# -*- coding: utf-8 -*-
# 07 CORE: 反汇编魔改 MD5 的 init(0x4014e0) 与 transform(0x401500)，提取常量
from capstone import *

data = open(r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin', 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

print('=== 0x4014e0 (hash init) ===')
for ins in md.disasm(data[0x14e0:0x1500], BASE + 0x14e0):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')

print()
print('=== 0x401500 (transform) 前 120 条 ===')
cnt = 0
for ins in md.disasm(data[0x1500:0x1a00], BASE + 0x1500):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    cnt += 1
    if cnt >= 120:
        break
