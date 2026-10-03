# -*- coding: utf-8 -*-
"""LATTICE-4 z3 两阶段求解器
阶段1: s0..s7 ← 关卡3(mod251)/4(多项式)/5(16位滚动) —— 只涉及前8字符
阶段2: s8..s15 ← 关卡1(FNV)/2(滚动哈希) —— s0..s7 代入为常量
"""
from z3 import *

tbl = open(r'D:\codes\ctf\crackmes\lattice4\table.bin', 'rb').read()
CS = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

def in_charset(solver, c):
    solver.add(Or(
        And(c >= 0x30, c <= 0x39),
        And(c >= 0x41, c <= 0x5A),
        And(c >= 0x61, c <= 0x7A),
    ))

def T32(solver, c, name):
    """查表: 返回 32 位值（用辅助变量 + 枚举约束，比 If 链对位爆破友好）"""
    v = BitVec(name, 32)
    cons = Or([c == BitVecVal(ch, 8) for ch in CS])  # 保证有定义
    # v = T[c] 分支约束
    solver.add(Or([And(c == BitVecVal(ch, 8), v == BitVecVal(tbl[ch], 32)) for ch in CS]))
    return v

def T16(solver, c, name):
    v = BitVec(name, 16)
    solver.add(Or([And(c == BitVecVal(ch, 8), v == BitVecVal(tbl[ch], 16)) for ch in CS]))
    return v

# ══ 阶段 1: s0..s7 ══
s = [BitVec(f's{i}', 8) for i in range(8)]
sol1 = Solver()
for c in s:
    in_charset(sol1, c)

# 关卡 3
e = ZeroExt(24, s[0]) * ZeroExt(24, s[3]) + ZeroExt(24, s[1]) * ZeroExt(24, s[2]) \
  + ZeroExt(24, s[5]) * ZeroExt(24, s[6]) + ZeroExt(24, s[4]) * ZeroExt(24, s[7])
sol1.add(URem(e, BitVecVal(251, 32)) == BitVecVal(0xD1, 32))

# 关卡 4
w52 = Concat(s[3], s[2])
w56 = Concat(s[7], s[6])
p1 = (ZeroExt(24, s[0]) * 31 + ZeroExt(24, s[1]) * 17) ^ ZeroExt(16, w52)
p1 = p1 * BitVecVal(0x10001, 32)
p2 = (ZeroExt(24, s[4]) * 13 + ZeroExt(24, s[5]) * 11) ^ ZeroExt(16, w56)
sol1.add(p1 + p2 == BitVecVal(0x58DC8BD7, 32))

# 关卡 5
h5 = BitVecVal(0, 16)
for i in range(8):
    v = T16(sol1, s[i], f't5_{i}')
    h5 = (h5 * BitVecVal(0x83, 16) + v) & BitVecVal(0xFFFF, 16)
sol1.add(h5 == BitVecVal(0x7583, 16))

print('phase 1 checking...')
r1 = sol1.check()
print('phase 1:', r1)
assert r1 == sat
m1 = sol1.model()
prefix = bytes(m1[c].as_long() for c in s)
print('s0..s7 =', prefix.decode())
