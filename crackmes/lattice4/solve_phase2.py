# -*- coding: utf-8 -*-
"""LATTICE-4 阶段2: 固定 s0..s7，解 s8..s15（关卡1 FNV + 关卡2 滚动哈希）"""
from z3 import *

tbl = open(r'D:\codes\ctf\crackmes\lattice4\table.bin', 'rb').read()
CS = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
PREFIX = b'L4tT1cE4'   # 阶段 1 解

def in_cs(sol, c):
    sol.add(Or(And(c >= 0x30, c <= 0x39), And(c >= 0x41, c <= 0x5A), And(c >= 0x61, c <= 0x7A)))

# 16 字符: 前 8 常量，后 8 变量
cvals = [BitVecVal(ch, 8) for ch in PREFIX]
svar = [BitVec(f'x{i}', 8) for i in range(8)]
S = cvals + svar

sol = Solver()
for c in svar:
    in_cs(sol, c)

# 关卡 1: FNV-1a 15 步，h15 ^ s15 == 0x53FDD974
h = BitVecVal(0x811C9DC5, 32)
for i in range(15):
    h = (h ^ ZeroExt(24, S[i])) * BitVecVal(0x01000193, 32)
sol.add(h ^ ZeroExt(24, S[15]) == BitVecVal(0x53FDD974, 32))

# 关卡 2: 滚动哈希（比较最后 t）
hh = BitVecVal(0xA5A5C3C3, 32)
t_last = None
for i in range(16):
    tv = BitVec(f'T2_{i}', 32)
    sol.add(Or([And(S[i] == BitVecVal(ch, 8), tv == BitVecVal(tbl[ch], 32)) for ch in CS]))
    t = (ZeroExt(24, S[i]) * BitVecVal(0xA7, 32) + tv) ^ hh
    hh = RotateLeft(t, 7) * BitVecVal(0x85EBCA77, 32)
    t_last = t
sol.add(t_last == BitVecVal(0x73AC9527, 32))

print('phase 2 checking...')
r = sol.check()
print('phase 2:', r)
if r == sat:
    m = sol.model()
    key = PREFIX + bytes(m[c].as_long() for c in svar)
    print('KEY =', key.decode())
    open(r'D:\codes\ctf\crackmes\lattice4\answer.txt', 'w').write(key.decode())
