# -*- coding: utf-8 -*-
# KCTF 01_rechall 求解 v2：精确对照反汇编翻译位运算
import hashlib
from z3 import *

x1, x2, x3, x4 = BitVecs('x1 x2 x3 x4', 32)
s = Solver()

# ── checker1: x1 - 0x5294b771 == 0x956438b9 ──
s.add(x1 - 0x5294b771 == 0x956438b9)

# ── checker2 ──
s.add(~((3 * (x2 & 0x52e3f96b) - (x2 | 0xad1c0694)) - x2 + 0x5a380d28) == 0xc2407eea)

# ── checker3 (K = 0xd68e3fe9, x 无符号 <= 0x10000000) ──
s.add(ULE(x3, 0x10000000))
K = 0xd68e3fe9
c1 = ((~x3) | K) - (((~x3) | K) << 2)              # -3 * (~x | K)
c2 = c1 + 3 * ~(x3 | K)                             # + 3 * (~x & ~K)
inner = 2 * (x3 & ~K) + ((~x3) & K)                 # 2*(x&~K) + (~x&K)
c3 = c2 + (inner << 2)                              # + 4*inner
res3 = c3 + 10 * (x3 & K) - (x3 ^ K)                # + 10*(x&K) - (x^K)
s.add(res3 == 0x251bc4bd)

# ── checker4 (x 无符号 <= 0x10000000) ──
s.add(ULE(x4, 0x10000000))
K1, K2, K3, K4 = 0xae7c284f, 0x5183d7b0, 0x4eda6b7c, 0xb1259483
u1 = x4 ^ K1
ecx = 11 * u1 + (4 * (x4 & K1))                     # 11*(x^K1) + 4*(x&K1)
u4 = ~(x4 | K2)
ecx = ecx - ((3 * u4 << 2) + 6 * (x4 & K2))         # - (12*~(x|K2) + 6*(x&K2))
eax = -(5 * x4) - 2 * ~(x4 | K3)                    # -5x - 2*~(x|K3)
esi = eax - (x4 | K4)
edx = esi + 3 * (x4 & K3)
esi2 = 4 * (x4 & K4) + 2 * (x4 | K4)
res4 = esi2 + edx + ecx - 0x5183d7b2
s.add(res4 == 0x88637bd8)

assert s.check() == sat, "unsat!"
m = s.model()
vals = [m[x1].as_long(), m[x2].as_long(), m[x3].as_long(), m[x4].as_long()]
print("解出的 4 个整数:", [hex(v) for v in vals])

flag = "flag{%08x-%08x-%08x-%08x}" % tuple(vals)
print("flag 字符串:", flag)
md5 = hashlib.md5(flag.encode()).hexdigest()
print("MD5:", md5)
print("期望: f2d5f978de74c1ce7a9ff53461ca3fd2")
print("匹配!" if md5 == "f2d5f978de74c1ce7a9ff53461ca3fd2" else "不匹配，需要继续求解其他解")
