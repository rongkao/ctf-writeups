# -*- coding: utf-8 -*-
"""IgniteMe 校验函数 0x401050 + 输入读取 0x4010f0 反汇编"""
from capstone import *

path = r'D:\codes\ctf\FlareOn\Fo4\02\IgniteMe.exe'
data = open(path, 'rb').read()
md = Cs(CS_ARCH_X86, CS_MODE_32)

# .text va=0x1000 ra=0x400 → va 0x401050 = off 0x450
print('=== validate @0x401050 ===')
off = 0x450
for ins in md.disasm(data[off:off+0xa0], 0x401050):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'ret':
        break

print()
print('=== read_input @0x4010f0 ===')
off = 0x4f0
cnt = 0
for ins in md.disasm(data[off:off+0xc0], 0x4010f0):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    cnt += 1
    if ins.mnemonic == 'ret' or cnt > 40:
        break
