# -*- coding: utf-8 -*-
"""
CORE Official CrackMe v2.0 Keygen（最终版）
算法链：
  1. hash 输入 = name + strrev(name) × 3
  2. 自定义 MD5：标准压缩函数 + off-by-one 长度字段 ((len+1)*8)  ← 魔改点
  3. m0,m1,m2 = digest 前 12 字节（3 个小端 dword）
  4. 变换链（GF(2) 64x64 线性，可逆）：
     f2(v2a, v3) = (m1, m2)  →  v2a,v3 = f2inv(m1, m2)
     f1(v1, v2)  = (m0, v2a) →  v1,v2  = f1inv(m0, v2a)
  5. code = "%x %x %x"（空格分隔，配合 sscanf "%lx%lx%lx"）
"""
import struct, math

M32 = 0xFFFFFFFF
def rol(x, n): return ((x << n) | (x >> (32 - n))) & M32

T = [int(abs(math.sin(i + 1)) * 4294967296) & M32 for i in range(64)]
S = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4
X_ORDER = [list(range(16))] + \
          [[(1 + i*5) % 16 for i in range(16)]] + \
          [[(5 + i*3) % 16 for i in range(16)]] + \
          [[(i*7) % 16 for i in range(16)]]
def F(x,y,z): return (x & y) | (~x & z & M32)
def G(x,y,z): return (x & z) | (y & ~z & M32)
def H(x,y,z): return x ^ y ^ z
def I(x,y,z): return y ^ (x | ~z & M32)
FUNCS = [F]*16 + [G]*16 + [H]*16 + [I]*16

def custom_md5(msg: bytes):
    """标准 MD5 压缩 + off-by-one 长度字段"""
    buf = bytearray(msg + b'\x80')
    while len(buf) % 64 < 56:
        buf.append(0)
    buf += struct.pack('<I', (len(msg) + 1) * 8) + b'\x00' * 4   # ← 魔改：+1
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    for off in range(0, len(buf), 64):
        X = struct.unpack('<16I', bytes(buf[off:off+64]))
        A, B, C, D = a0, b0, c0, d0
        for r in range(4):
            for i in range(16):
                k = X_ORDER[r][i]
                f = FUNCS[r*16+i](B, C, D)
                A = (A + f + T[r*16+i] + X[k]) & M32
                A = rol(A, S[r*16+i])
                A = (A + B) & M32
                A, B, C, D = D, A, B, C
        a0 = (a0+A)&M32; b0 = (b0+B)&M32; c0 = (c0+C)&M32; d0 = (d0+D)&M32
    return a0, b0, c0, d0

# ── GF(2) 变换（从 dumped.bin 提取的表，模型已对栈上真值验证）──
DUMP = r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin'
BASE = 0x400000
_data = open(DUMP, 'rb').read()
def _tbl(va): return struct.unpack('<64I', _data[va-BASE:va-BASE+256])
T1A, T1B, T2A, T2B = _tbl(0x41c2c0), _tbl(0x41c3c0), _tbl(0x41c4c0), _tbl(0x41c5c0)

def _rows(PA, PB):
    rows = [0] * 64
    for j in range(64):
        i = (31 - j) if j < 32 else (95 - j)
        rows[j] = (PA[i] & M32) | ((PB[i] & M32) << 32)
    return rows

def _inv(rows):
    aug = [rows[j] | (1 << (64 + j)) for j in range(64)]
    for col in range(64):
        piv = next(r for r in range(col, 64) if (aug[r] >> col) & 1)
        aug[col], aug[piv] = aug[piv], aug[col]
        for r in range(64):
            if r != col and (aug[r] >> col) & 1:
                aug[r] ^= aug[col]
    return [a >> 64 for a in aug]

def _apply(rows, x):
    y = 0
    for j in range(64):
        if bin(rows[j] & x).count('1') & 1:
            y |= 1 << j
    return y

INV1 = _inv(_rows(T1A, T1B))
INV2 = _inv(_rows(T2A, T2B))

def keygen(name: str) -> str:
    m0, m1, m2, _ = custom_md5((name + name[::-1] * 3).encode())
    x = _apply(INV2, m1 | (m2 << 32))
    v2a, v3 = x & M32, x >> 32
    y = _apply(INV1, m0 | (v2a << 32))
    v1, v2 = y & M32, y >> 32
    return f'{v1:x} {v2:x} {v3:x}'

if __name__ == '__main__':
    # 自检：与 Unicorn 仿真地面真值比对
    assert custom_md5(b'testtsettsettset') == (0xc6c0a6a4, 0xfd5b4cb6, 0xed9b5781, 0x182d2423)
    print('custom_md5 self-check: PASS (ground truth match)')
    for n in ('test', 'KCTF', 'CORE'):
        print(f'{n!r} -> {keygen(n)}')
