# -*- coding: utf-8 -*-
"""LATTICE-4 阶段2 v2: 平衡 If 树查表（6 层嵌套 vs 62 路 Or）"""
from z3 import *
import time

tbl = open(r'D:\codes\ctf\crackmes\lattice4\table.bin', 'rb').read()
CS = sorted(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
PREFIX = b'L4tT1cE4'

_pairs = [(ch, tbl[ch]) for ch in CS]

def build_tree(pairs, c, depth=0):
    """平衡二叉 If 树: 按 ch 排序递归二分"""
    if len(pairs) == 1:
        return BitVecVal(pairs[0][1], 32)
    mid = len(pairs) // 2
    pivot = pairs[mid][0]
    return If(c < BitVecVal(pivot, 8),
              build_tree(pairs[:mid], c, depth+1),
              build_tree(pairs[mid:], c, depth+1))

cvals = [BitVecVal(ch, 8) for ch in PREFIX]
svar = [BitVec(f'x{i}', 8) for i in range(8)]
S = cvals + svar

sol = Solver()
for c in svar:
    sol.add(Or(And(c >= 0x30, c <= 0x39), And(c >= 0x41, c <= 0x5A), And(c >= 0x61, c <= 0x7A)))

# 关卡 1: FNV
h = BitVecVal(0x811C9DC5, 32)
for i in range(15):
    h = (h ^ ZeroExt(24, S[i])) * BitVecVal(0x01000193, 32)
sol.add(h ^ ZeroExt(24, S[15]) == BitVecVal(0x53FDD974, 32))

# 关卡 2: 滚动哈希（平衡树查表）
hh = BitVecVal(0xA5A5C3C3, 32)
t_last = None
for i in range(16):
    tv = build_tree(_pairs, S[i])
    t = (ZeroExt(24, S[i]) * BitVecVal(0xA7, 32) + tv) ^ hh
    hh = RotateLeft(t, 7) * BitVecVal(0x85EBCA77, 32)
    t_last = t
sol.add(t_last == BitVecVal(0x73AC9527, 32))

t0 = time.time()
print('phase2-v2 checking (balanced tree)...', flush=True)
r = sol.check()
print('result:', r, f'({time.time()-t0:.1f}s)', flush=True)
if r == sat:
    m = sol.model()
    key = PREFIX + bytes(m[c].as_long() for c in svar)
    print('KEY =', key.decode(), flush=True)
    open(r'D:\codes\ctf\crackmes\lattice4\answer.txt', 'w').write(key.decode())
