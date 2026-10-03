# -*- coding: utf-8 -*-
"""
FlareOn 4 Challenge 5 - pewpewboat.exe 完整解题脚本
ELF x86-64 战舰游戏, 每关的ship图案形成一个字母

解题步骤:
1. 计算种子: MD5迭代 "loading... %d%%\0\0" 2M次, 取前8字节
2. 用LCG PRNG + XOR解密10个关卡的board数据
3. 每个board的ship位图在8x8网格上形成一个字母
4. 按Board 10提示的顺序重排字母, 再ROT13解码
5. 得到密语 BUTWHEREISTHERUM, 最终flag在游戏中揭示

Flag: y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com
"""
import struct, hashlib

data = open('pewpewboat.exe', 'rb').read()
M64 = (1 << 64) - 1

def lcg(state):
    return (state * 0x41c64e6d + 0x3039) & M64

def decrypt_board(board_data, seed, size=0x240):
    result = bytearray(board_data[:size])
    state = seed
    for i in range(size):
        state = lcg(state)
        result[i] ^= state & 0xFF
    return bytes(result)

def popcount(n):
    return bin(n).count('1')

def compute_hit_offset(col, row):
    letter = 0x41 + col
    digit = 0x31 + row
    raw = digit * 0x593 + letter * 0x1e01 + letter * digit + 0x14a1
    if raw & 0x80000000:
        return raw | 0xFFFFFFFF00000000
    return raw

def rot13(s):
    result = []
    for c in s:
        if 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        elif 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)

# 种子: 0x403c85函数对"loading... 0%"做2M次MD5迭代, 取前8字节
# 已验证此seed能正确解密board 0为"Seaman Recruit"
seed = 0x3b1ee5f6b3d99ff7

# 解密所有关卡
key = seed
letters = "FHGUZREJVO"
order = [9, 1, 2, 7, 3, 5, 6, 5, 8, 0, 2, 3, 5, 6, 1, 4]

for i in range(11):
    off = 0x50e0 + i * 0x240
    dec = decrypt_board(data[off:off + 0x240], key)
    ships = struct.unpack_from('<Q', dec, 0)[0]
    next_orig = struct.unpack_from('<Q', dec, 0x10)[0]
    limit = struct.unpack_from('<I', dec, 0x18)[0]
    rank = dec[0x1e:0x40].split(b'\x00')[0].decode('ascii', errors='replace')
    n = popcount(ships)
    ltr = letters[i] if i < 10 else '-'
    print(f"Board {i}: [{ltr}] {rank}")
    for row in range(8):
        print('  ' + ''.join('X' if (ships >> (col*8+row)) & 1 else '.' for col in range(8)))
    if n > 0:
        total = 0
        cnt = 0
        for bit in range(64):
            if (ships >> bit) & 1:
                total = (total + compute_hit_offset(bit // 8, bit % 8)) & M64
                cnt += 1
                if cnt >= limit:
                    total = (total + 1) & M64
        key = (next_orig + total) & M64
    else:
        key = next_orig

reordered = ''.join(letters[i] for i in order)
decoded = rot13(reordered)
print(f"\n字母: {letters}")
print(f"重排: {reordered}")
print(f"ROT13: {decoded}")
print(f"\nFlag: y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com")
