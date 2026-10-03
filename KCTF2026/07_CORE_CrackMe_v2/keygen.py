# -*- coding: utf-8 -*-
"""
CORE Official CrackMe v2.0 Keygen (KCTF 靶场 07)
算法链：
  输入 = Name + Code
  code 解析: sscanf("%lx%lx%lx") → v1,v2,v3（三个 32 位十六进制，需空格分隔）
  MD5 输入串 = Name + strrev(Name) × N（N 由动态验证确定）
  m0,m1,m2 = MD5(str)[0:12] 的三个小端 dword
  变换链: f1(v1,v2)→(v1',v2a);  f2(v2a,v3)→(v2'',v3')
  要求: v1'==m0, v2''==m1, v3'==m2
  f 均为 GF(2) 64x64 线性变换（parity 内积，MSB-first 累积），可逆
"""
import struct, hashlib

DUMP = r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin'
BASE = 0x400000

def tbl(va):
    data = open(DUMP, 'rb').read()
    return struct.unpack('<64I', data[va - BASE:va - BASE + 256])

T1A, T1B = tbl(0x41c2c0), tbl(0x41c3c0)   # f1: arg2(与低32位内积), arg3(与高32位内积)
T2A, T2B = tbl(0x41c4c0), tbl(0x41c5c0)   # f2

def build_rows(PA, PB):
    """输出位 j 的矩阵行（对 64 位输入）：
    O.bit(j) = parity(a_lo & PA[i]) ^ parity(a_hi & PB[i])
    j<32: i = 31-j（loop1, MSB 先入）;  j>=32: i = 95-j（loop2）"""
    rows = [0] * 64
    for j in range(64):
        i = (31 - j) if j < 32 else (95 - j)
        rows[j] = (PA[i] & 0xFFFFFFFF) | ((PB[i] & 0xFFFFFFFF) << 32)
    return rows

def gf2_inverse(rows):
    """64x64 GF(2) 矩阵求逆（高斯消元，增广单位阵）"""
    n = 64
    aug = [rows[j] | (1 << (n + j)) for j in range(n)]
    for col in range(n):
        piv = None
        for r in range(col, n):
            if (aug[r] >> col) & 1:
                piv = r; break
        assert piv is not None, f'singular at col {col}'
        aug[col], aug[piv] = aug[piv], aug[col]
        for r in range(n):
            if r != col and (aug[r] >> col) & 1:
                aug[r] ^= aug[col]
    return [a >> n for a in aug]

def apply_rows(rows, x):
    y = 0
    for j in range(64):
        if bin(rows[j] & x).count('1') & 1:
            y |= 1 << j
    return y

# 前向变换（用于离线自检）
def forward(PA, PB, lo, hi):
    a = lo | (hi << 32)
    o = apply_rows(build_rows(PA, PB), a)
    return o & 0xFFFFFFFF, o >> 32

INV1 = gf2_inverse(build_rows(T1A, T1B))
INV2 = gf2_inverse(build_rows(T2A, T2B))

def keygen(name: str, n_append: int = 3):
    s = name + name[::-1] * n_append
    m0, m1, m2 = struct.unpack('<3I', hashlib.md5(s.encode()).digest()[:12])
    # f2(v2a, v3) = (m1, m2)
    x = apply_rows(INV2, m1 | (m2 << 32))
    v2a, v3 = x & 0xFFFFFFFF, x >> 32
    # f1(v1, v2) = (m0, v2a)
    y = apply_rows(INV1, m0 | (v2a << 32))
    v1, v2 = y & 0xFFFFFFFF, y >> 32
    # 离线自检：前向跑一遍
    a1, a2 = forward(T1A, T1B, v1, v2)
    assert (a1, a2) == (m0, v2a)
    b1, b2 = forward(T2A, T2B, a2, v3)
    assert (b1, b2) == (m1, m2)
    # sscanf("%lx%lx%lx") 贪婪匹配：三段十六进制必须以非十六进制字符分隔，用空格
    return f'{v1:x} {v2:x} {v3:x}'

if __name__ == '__main__':
    for n in (1, 2, 3):
        code = keygen('test', n)
        print(f'N={n}: test -> {code}')
