# -*- coding: utf-8 -*-
# 02 约束自动提取：解析 0x2811a4-0x28129f 的逐字符校验指令，求出 16 字节 key
from capstone import *

data = open(r'D:\codes\ctf\KCTF2026\02_yueyueyushi\dumped.bin', 'rb').read()
BASE = 0x280000
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

start, end = 0x11a4, 0x12a1
insns = list(md.disasm(data[start:end], BASE + start))

# 栈偏移 → buf 索引: buf 基址 ebp-0x240, buf[i] = [ebp-(0x240-i)]
def idx_of(disp):                      # disp 是负数（ebp-X 的 X 取正传入）
    i = 0x240 - disp
    return i if 0 <= i < 16 else None

solved = {}          # idx -> value
last_reg_val = {}    # 最近一次 movsx 载入的 (reg -> idx)

for k, ins in enumerate(insns):
    m, ops = ins.mnemonic, ins.op_str
    # 模式1: cmp byte ptr [ebp - X], imm
    if m == 'cmp' and 'byte ptr [ebp' in ops and ops.split(',')[0].strip().startswith('byte ptr [ebp'):
        parts = ops.split(',')
        disp = int(parts[0].split('-')[1].strip().rstrip(']'), 0)
        imm = int(parts[1].strip(), 0)
        i = idx_of(disp)
        if i is not None:
            solved[i] = imm
    # 模式2: movsx reg, byte ptr [ebp - X]
    elif m == 'movsx' and 'byte ptr [ebp' in ops:
        reg = ops.split(',')[0].strip()
        disp = int(ops.split('-')[1].strip().rstrip(']'), 0)
        i = idx_of(disp)
        if i is not None:
            last_reg_val[reg] = i
    # 模式3: lea eax, [ecx ± imm]  /  lea eax, [ecx]
    elif m == 'lea':
        dst, src = [s.strip() for s in ops.split(',', 1)]
        if src.startswith('[ecx'):
            delta = 0
            if '+' in src: delta = int(src.split('+')[1].strip().rstrip(']'), 0)
            elif '-' in src: delta = -int(src.split('-')[1].strip().rstrip(']'), 0)
            pending = ('lea', dst, last_reg_val.get('ecx'), delta)
    # 模式4: add eax, imm / add eax, ecx
    elif m == 'add':
        r1, r2 = [s.strip() for s in ops.split(',')]
        if r1 == 'eax' and r2 in ('ecx',):
            pending = ('addreg', 'eax', last_reg_val.get('ecx'))
        elif r1 == 'eax':
            pending = ('add', 'eax', int(r2, 0))
    # 模式5: cmp eax, imm → 结算
    elif m == 'cmp':
        r1, r2 = [s.strip() for s in ops.split(',')]
        if r1 == 'eax':
            target = int(r2, 0)
            p = locals().get('pending')
            if not p: continue
            kind = p[0]
            if kind == 'add':                # eax = buf[i] + imm
                i = p[2]
                if i in last_reg_val.values() or i is not None:
                    pass
                src_idx = p[1] if p[1] not in ('eax',) else None
                # p = ('add','eax',imm) 时 eax 来自最近 movsx eax
                idx = last_reg_val.get('eax')
                if idx is not None:
                    solved[idx] = (target - p[2]) & 0xFF
            elif kind == 'addreg':           # eax = buf[i] + buf[j]
                i = last_reg_val.get('eax')
                j = p[2]
                if i is not None and j is not None and j in solved:
                    solved[i] = (target - solved[j]) & 0xFF
            elif kind == 'lea':              # eax = buf[j] + delta
                j = p[2]
                if j is not None:
                    solved[j] = (target - p[3]) & 0xFF

key = ''.join(chr(solved.get(i, 0x3F)) for i in range(16))
print('solved idx:', sorted(solved.keys()))
print('values    :', {i: hex(v) for i, v in sorted(solved.items())})
print('KEY =', key)
