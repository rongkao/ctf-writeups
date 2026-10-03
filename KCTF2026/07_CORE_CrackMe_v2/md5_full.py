# -*- coding: utf-8 -*-
# 07 CORE: 完整提取魔改 MD5 transform 的 X 加载/GHI 函数/尾部回加
import re
from capstone import *

data = open(r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin', 'rb').read()
BASE = 0x400000
md = Cs(CS_ARCH_X86, CS_MODE_32)

insns = list(md.disasm(data[0x1500:0x1ad0], BASE + 0x1500))
print(f'total {len(insns)} insns')

# ── 1. X 加载指令: mov REG, dword ptr [ebx + REG + imm] 或 [eax + REG + imm] ──
print()
print('=== X 加载序列（按 round 分组）===')
x_loads = []
for ins in insns:
    m = re.match(r'mov\s+(\w+),\s*dword ptr \[(\w+) \+ (\w+) \+ (0x[0-9a-f]+)\]', f'{ins.mnemonic} {ins.op_str}')
    if m and ins.mnemonic == 'mov':
        x_loads.append((ins.address, int(m.group(4), 16)))
    # 也可能是 [ebx + REG + imm] 变体（第一操作数同寄存器）
for addr, off in x_loads:
    print(f'  0x{addr:x}: X offset 0x{off:x} (X[{off//4}])')

# ── 2. T 常量访问（确定 round 边界）──
print()
print('=== T 常量访问（round 边界）===')
for ins in insns:
    m = re.search(r'0x41c[0-9a-f]{3}', ins.op_str)
    if m and ins.mnemonic == 'add':
        print(f'  0x{ins.address:x}: {m.group(0)}')

# ── 3. 尾部（最后 60 条指令，看 IV 回加）──
print()
print('=== transform 尾部（最后 50 条）===')
for ins in insns[-50:]:
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
