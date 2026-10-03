# -*- coding: utf-8 -*-
# 07 CORE: 提取魔改 MD5 的 T 常量 + 完整 round2-4 反汇编分析
import struct
from capstone import *

data = open(r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin', 'rb').read()
BASE = 0x400000

# 标准 MD5 T 表（前 16 个）
STD_T = [0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
         0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821]

# Round1 T @0x41c280（16 dword）
r1 = struct.unpack('<16I', data[0x41c280-BASE:0x41c280-BASE+64])
print('Round1 T @0x41c280:')
for i, w in enumerate(r1):
    std = STD_T[i]
    print(f'  T[{i:2}] = 0x{w:08x}  {"STD" if w == std else "CUSTOM (std=0x%08x)" % std}')

# Round2 T @0x41c240
r2 = struct.unpack('<16I', data[0x41c240-BASE:0x41c240-BASE+64])
print('Round2 T @0x41c240:')
for i, w in enumerate(r2[:16]):
    print(f'  T[{16+i:2}] = 0x{w:08x}')

# Round3/4 基址需要从后续反汇编确认，先看 0x41c200 / 0x41c1c0
for va in (0x41c200, 0x41c1c0):
    w = struct.unpack('<16I', data[va-BASE:va-BASE+64])
    print(f'T @0x{va:x}: ' + ' '.join(f'{x:08x}' for x in w[:4]))

print()
print('=== transform round2-4 关键指令（找 T 基址/移位/X 索引）===')
md = Cs(CS_ARCH_X86, CS_MODE_32)
code = data[0x1650:0x1ad0]
out = []
for ins in md.disasm(code, BASE + 0x1650):
    t = f'{ins.mnemonic}\t{ins.op_str}'
    # 只保留 T 常量访问、移位设置、循环计数
    if ('41c' in t and ('add' in ins.mnemonic)) or ('mov\tbyte' in t and 'ebp' in t) or ins.mnemonic == 'rol' or ('0x41c' in t):
        out.append(f'0x{ins.address:x}: {t}')
print('\n'.join(out[:80]))
