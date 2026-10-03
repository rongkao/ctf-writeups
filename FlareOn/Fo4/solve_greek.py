# -*- coding: utf-8 -*-
"""greek_to_me 求解：提取 121 字节加密 payload，爆破单字节 key
解密: dec[i] = (enc[i] ^ key) + 0x22 (mod 256)
判定: 0x4011e6 校验函数返回 0xfb5e（先反汇编看算法）
"""
import struct
from capstone import *

path = r'D:\codes\ctf\FlareOn\Fo4\03\greek_to_me.exe'
data = open(path, 'rb').read()
# .text va=0x1000 ra=0x200 → VA 0x40107c = off 0x27c
enc = data[0x27c:0x27c + 0x79]
print('enc (121B):', enc[:32].hex(), '...')

# 反汇编校验函数 0x4011e6
md = Cs(CS_ARCH_X86, CS_MODE_32)
off = 0x200 + (0x11e6 - 0x1000)
print('\n=== checksum @0x4011e6 ===')
for ins in md.disasm(data[off:off+0x80], 0x4011e6):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'ret':
        break
