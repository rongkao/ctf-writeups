# -*- coding: utf-8 -*-
"""LATTICE-4 z3 全约束求解器
五重关卡：
  1. FNV-1a: (h15 ^ s[15]) == 0x53FDD974  （h 链 15 步标准 FNV）
  2. 滚动哈希: 最后的 t = ((s[i]*0xA7 + T[s[i]]) ^ h) == 0x73AC9527
     h 链: h = rol32(t,7) * 0x85EBCA77, init 0xA5A5C3C3
  3. (s0*s3 + s1*s2 + s5*s6 + s4*s7) % 251 == 0xD1
  4. (((s0*31 + s1*17) ^ (s2 | s3<<8)) * 0x10001 + ((s4*13 + s5*11) ^ (s6 | s7<<8))) == 0x58DC8BD7 (mod 2^32)
  5. 前8字符: h = ((h*0x83 + T[s[i]]) & 0xFFFF) 8步 == 0x7583
字符集: [0-9A-Za-z]
"""
from z3 import *

tbl = open(r'D:\codes\ctf\crackmes\lattice4\table.bin', 'rb').read()
CS = b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

s = [BitVec(f's{i}', 8) for i in range(16)]
solver = Solver()

# 字符集
for c in s:
    solver.add(Or(
        And(c >= 0x30, c <= 0x39),
        And(c >= 0x41, c <= 0x5A),
        And(c >= 0x61, c <= 0x7A),
    ))

# 关卡 1: FNV-1a（h15 ^ s15 == 0x53FDD974）
h = BitVecVal(0x811C9DC5, 32)
for i in range(15):
    h = (h ^ ZeroExt(24, s[i])) * BitVecVal(0x01000193, 32)
solver.add(h ^ ZeroExt(24, s[15]) == BitVecVal(0x53FDD974, 32))

# 关卡 2: 滚动哈希（比较最后的 t）
def T_lookup(c8):
    """字节查表 → z3 If 链（只覆盖字符集 62 值，其他不关心）"""
    expr = None
    for ch in CS:
        cond = c8 == BitVecVal(ch, 8)
        val = BitVecVal(tbl[ch], 32)
        expr = If(cond, val, expr) if expr is not None else If(cond, val, BitVecVal(0, 32))
    return expr

hh = BitVecVal(0xA5A5C3C3, 32)
t_last = None
for i in range(16):
    t = (ZeroExt(24, s[i]) * BitVecVal(0xA7, 32) + T_lookup(s[i])) ^ hh
    hh = (RotateLeft(t, 7) * BitVecVal(0x85EBCA77, 32))
    t_last = t
solver.add(t_last == BitVecVal(0x73AC9527, 32))

# 关卡 3: mod 251
e = ZeroExt(24, s[0]) * ZeroExt(24, s[3]) + ZeroExt(24, s[1]) * ZeroExt(24, s[2]) \
  + ZeroExt(24, s[5]) * ZeroExt(24, s[6]) + ZeroExt(24, s[4]) * ZeroExt(24, s[7])
solver.add(URem(e, BitVecVal(251, 32)) == BitVecVal(0xD1, 32))

# 关卡 4: 多项式混合（全 32 位环绕）
w52 = Concat(s[3], s[2])                               # 16 位 word: s2 | s3<<8
w56 = Concat(s[7], s[6])
p1 = (ZeroExt(24, s[0]) * 31 + ZeroExt(24, s[1]) * 17) ^ ZeroExt(16, w52)
p1 = p1 * BitVecVal(0x10001, 32)
p2 = (ZeroExt(24, s[4]) * 13 + ZeroExt(24, s[5]) * 11) ^ ZeroExt(16, w56)
solver.add(p1 + p2 == BitVecVal(0x58DC8BD7, 32))

# 关卡 5: 16 位滚动哈希（前 8 字符）
h5 = BitVecVal(0, 16)
for i in range(8):
    v = T_lookup(s[i]) & BitVecVal(0xFFFF, 32)
    h5 = (h5 * BitVecVal(0x83, 16) + Extract(15, 0, v)) & BitVecVal(0xFFFF, 16)
solver.add(h5 == BitVecVal(0x7583, 16))

print('checking...')
r = solver.check()
print(r)
if r == sat:
    m = solver.model()
    key = bytes(m[c].as_long() for c in s)
    print('KEY:', key.decode())
    open(r'D:\codes\ctf\crackmes\lattice4\answer.txt', 'w').write(key.decode())
