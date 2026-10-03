# -*- coding: utf-8 -*-
"""greek_to_me 完整求解：复现校验 + 爆破 key + 解密 payload"""
import struct
from capstone import *

path = r'D:\codes\ctf\FlareOn\Fo4\03\greek_to_me.exe'
data = open(path, 'rb').read()
enc = data[0x27c:0x27c + 0x79]

# 1) 补齐校验函数尾部
md = Cs(CS_ARCH_X86, CS_MODE_32)
off = 0x200 + (0x401258 - 0x401000)
print('=== checksum tail @0x401258 ===')
for ins in md.disasm(data[off:off+0x30], 0x401258):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'ret':
        break

# 2) 校验复现（按已见反汇编）
def checksum(buf: bytes) -> int:
    di = 0xFF
    ecx = 0xFF
    pos, n = 0, len(buf)
    while n - pos > 0:
        chunk = min(n - pos, 0x14)
        for _ in range(chunk):
            di = (di + buf[pos]) & 0xFFFF
            ecx = (ecx + di) & 0xFFFFFFFF
            pos += 1
        di = ((di & 0xFF) + (di >> 8)) & 0xFFFF
        ecx = ((ecx & 0xFF) + (ecx >> 8)) & 0xFFFF
    # 尾部组合（eax = ((ecx & 0xff00) + (ecx<<8 & ...)) ... 按打印修正）
    return di, ecx

# 3) 爆破 key: dec[i] = (enc[i] ^ key) + 0x22
print('\n=== brute force ===')
hits = []
for key in range(256):
    dec = bytes(((b ^ key) + 0x22) & 0xFF for b in enc)
    di, ecx = checksum(dec)
    # 组合假设: 结果与 (ecx 折叠, di 低位) 相关，先打印全部 key 的 (di, ecx) 找 0xfb5e 特征
    combined = ((ecx & 0xFF) << 8) | (ecx >> 8 & 0xFF)
    if di == 0xfb5e or combined == 0xfb5e or (ecx & 0xFFFF) == 0xfb5e:
        print(f'key=0x{key:02x}: di={di:04x} ecx={ecx:04x} combined={combined:04x}  HIT')
        hits.append((key, dec))

if not hits:
    # 打印几个样本帮助校准组合公式
    for key in (0x00, 0x22, 0x41, 0x61, 0xff):
        dec = bytes(((b ^ key) + 0x22) & 0xFF for b in enc)
        di, ecx = checksum(dec)
        print(f'key=0x{key:02x}: di={di:04x} ecx={ecx:04x}')
