# -*- coding: utf-8 -*-
# 07 CORE: 参数化 MD5 暴力拟合 X 序（每轮步长可配），用栈上地面真值鉴别
import struct, itertools

M32 = 0xFFFFFFFF
def rol(x, n): return ((x << n) | (x >> (32 - n))) & M32

T = [int(abs(__import__('math').sin(i + 1)) * 4294967296) & M32 for i in range(64)]
S = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4

def F(x,y,z): return (x & y) | (~x & z)
def G(x,y,z): return (x & z) | (y & ~z)
def H(x,y,z): return x ^ y ^ z
def I(x,y,z): return y ^ (x | ~z)
FUNCS = [F]*16 + [G]*16 + [H]*16 + [I]*16

def md5_custom(msg: bytes, orders=(0,5,3,7)):
    """orders = 每轮的 X 步长（round1 固定 +1 起始 0）"""
    # padding（与栈上观察一致：标准）
    ml = len(msg) * 8
    msg = msg + b'\x80' + b'\x00' * ((56 - len(msg) - 1) % 64) + struct.pack('<Q', ml)
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    # X 序列表
    x_orders = [list(range(16))]                                  # round1: 0..15
    for step in orders[1:]:
        x_orders.append([(i * step + off) % 16 for i in range(16)] for off in [0])  # 先按步长生成
    # 各轮起始偏移（标准 MD5 round2 起 1, round3 起 5, round4 起 0）——也纳入拟合
    for chunk in range(0, len(msg), 64):
        X = struct.unpack('<16I', msg[chunk:chunk+64])
        A, B, C, D = a0, b0, c0, d0
        for r in range(4):
            for i in range(16):
                k = x_orders[r][i]
                f = FUNCS[r*16+i](B, C, D)
                A = (A + f + T[r*16+i] + X[k]) & M32
                A = rol(A, S[r*16+i])
                A = (A + B) & M32
                A, B, C, D = D, A, B, C
        a0 = (a0 + A) & M32; b0 = (b0 + B) & M32
        c0 = (c0 + C) & M32; d0 = (d0 + D) & M32
    return (a0, b0, c0, d0)

TARGET = (0xc6c0a6a4, 0xfd5b4cb6, 0xed9b5781, 0x182d2423)   # 栈上地面真值（A,B,C,D）
MSG = b'testtsettsettset'

# 拟合：round2/3/4 各自 (步长, 起始) ∈ {1,3,5,7}×{0..15} 的组合，加 round1 起始固定 0
print('拟合中...')
found = []
for s2, s3, s4 in itertools.product((1,3,5,7), repeat=3):
    for o2, o3, o4 in itertools.product(range(16), repeat=3):
        # 重建 x_orders
        def build(step, start):
            return [(start + i*step) % 16 for i in range(16)]
        x_orders = [list(range(16)), build(s2,o2), build(s3,o3), build(s4,o4)]
        # inline 修改 md5_custom
        ml = len(MSG) * 8
        m = MSG + b'\x80' + b'\x00' * ((56 - len(MSG) - 1) % 64) + struct.pack('<Q', ml)
        a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        for chunk_i in range(0, len(m), 64):
            X = struct.unpack('<16I', m[chunk_i:chunk_i+64])
            A, B, C, D = a0, b0, c0, d0
            for r in range(4):
                for i in range(16):
                    k = x_orders[r][i]
                    f = FUNCS[r*16+i](B, C, D)
                    A = (A + f + T[r*16+i] + X[k]) & M32
                    A = rol(A, S[r*16+i])
                    A = (A + B) & M32
                    A, B, C, D = D, A, B, C
            a0 = (a0+A)&M32; b0 = (b0+B)&M32; c0 = (c0+C)&M32; d0 = (d0+D)&M32
        if (a0,b0,c0,d0) == TARGET:
            found.append((s2,o2,s3,o3,s4,o4))
            print(f'MATCH: round2=+{s2} start{o2}, round3=+{s3} start{o3}, round4=+{s4} start{o4}')
if not found:
    print('no match in step/start space —— G/H/I 函数或轮函数本身有修改')
