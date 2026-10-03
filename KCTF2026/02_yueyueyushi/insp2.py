# -*- coding: utf-8 -*-
# 02 辅助：字符串 + 0x2813a0 分析
from capstone import *
data = open(r'D:\codes\ctf\KCTF2026\02_yueyueyushi\dumped.bin', 'rb').read()
BASE = 0x280000
for va in [0x28fd0c, 0x28fd10, 0x28fd38, 0x28fd50]:
    off = va - BASE
    s = data[off:off+24].split(b'\x00')[0]
    print(f'0x{va:x}: {s!r}')
md = Cs(CS_ARCH_X86, CS_MODE_32)
print('=== 0x2813a0 ===')
for ins in md.disasm(data[0x13a0:0x1440], BASE + 0x13a0):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
