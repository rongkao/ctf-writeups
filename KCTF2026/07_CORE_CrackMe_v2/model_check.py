# -*- coding: utf-8 -*-
# 07 CORE 模型鑑別：用棧上地面真值判定 MD5 與 GF(2) 變換的正確模型
import struct, hashlib

# ── 地面真值（來自 ground_truth3 棧 dump）──
STACK_MD5 = bytes.fromhex('a4a6c0c6b64c5bfde8579bed182d2423'.replace('',''))  # 佔位，下面直接用 dword 拼回
m_words = [0xc6c0a6a4, 0xfd5b4cb6, 0xed9b5781, 0x182d2423]   # ebp-0x20 起 4 dword（A,B,C,D 小端存儲）
stack_digest_bytes = b''.join(struct.pack('<I', w) for w in m_words)
V = [0x0577b787, 0x2a3be1b8, 0xc6a74f64]   # ebp-0x10 起：v1', v2'', v3'
IN_V = [0x715d64ea, 0xb7b1776f, 0x6385e475]  # 輸入 code（keygen('test',3)）

NAME = 'test'
s = NAME + NAME[::-1] * 3
d = hashlib.md5(s.encode()).digest()
print(f'MD5 輸入串: {s!r} (len={len(s)})')
print(f'離線 MD5    : {d.hex()}')
print(f'棧上 digest : {stack_digest_bytes.hex()}')
print(f'MD5 {"匹配 ✓" if d == stack_digest_bytes else "不匹配 ✗"}')
print()

# ── GF(2) 變換模型鑑別 ──
DUMP = r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin'
BASE = 0x400000
data = open(DUMP, 'rb').read()
T1A = struct.unpack('<64I', data[0x41c2c0-BASE:0x41c2c0-BASE+256])
T1B = struct.unpack('<64I', data[0x41c3c0-BASE:0x41c3c0-BASE+256])

def parity(x): return bin(x).count('1') & 1

def forward_variant(PA, PB, lo, hi, swap_tables=False, msb_first=True, lo_first=True):
    """按不同假設跑 0x401ad0 的兩段循環
    swap_tables: PA/PB 與 lo/hi 的配對是否交換
    msb_first: edi 累積方向（edi=edi*2+bit 為 True）
    lo_first: 循環1結果寫 a[0]（否則寫 a[1]）"""
    if swap_tables:
        PA, PB = PB, PA
    out = [0, 0]
    for half in (0, 1):
        acc = 0
        for i in range(32):
            bit = parity(lo & PA[half*32+i]) ^ parity(hi & PB[half*32+i])
            acc = (acc * 2 + bit) if msb_first else (acc | (bit << i))
        out[0 if lo_first else 1] = acc
    return out[0], out[1]

lo_in, hi_in = IN_V[0], IN_V[1]
target_v1p = V[0]
print(f'f1 輸入: (lo=0x{lo_in:08x}, hi=0x{hi_in:08x})  期望輸出 lo = v1\' = 0x{target_v1p:08x}')
print()
for swap in (False, True):
    for msb in (True, False):
        for lof in (True, False):
            o_lo, o_hi = forward_variant(T1A, T1B, lo_in, hi_in, swap, msb, lof)
            hit = ' <<< MATCH' if o_lo == target_v1p else ''
            print(f'swap={swap!s:5} msb_first={msb!s:5} loop1→a[{"0" if lof else "1"}]: out=(0x{o_lo:08x}, 0x{o_hi:08x}){hit}')
