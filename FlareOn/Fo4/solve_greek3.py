# -*- coding: utf-8 -*-
"""greek_to_me 最终求解：精确复现校验 → 爆破 key → 解密+反汇编 payload"""
from capstone import *

path = r'D:\codes\ctf\FlareOn\Fo4\03\greek_to_me.exe'
data = open(path, 'rb').read()
enc = data[0x27c:0x27c + 0x79]

def checksum_exact(buf: bytes) -> int:
    """逐指令复现 0x4011e6 的双累加器折叠校验，返回 ax (16-bit)"""
    di = 0xFF            # [ebp-4]
    ecx = 0xFF           # 32-bit
    pos, remaining = 0, len(buf)
    while remaining:
        chunk = min(remaining, 0x14)
        remaining -= chunk
        for _ in range(chunk):
            di = (di + buf[pos]) & 0xFFFF
            ecx = (ecx + di) & 0xFFFFFFFF
            pos += 1
        di = ((di & 0xFF) + (di >> 8)) & 0xFFFF          # 折叠 di
        ecx = ((ecx & 0xFF) + ((ecx >> 8) & 0xFFFF)) & 0xFFFF  # 折叠 ecx (16位)
    # 尾部组合
    edx = di & 0xFF
    eax = ecx
    ecx_shl = (ecx << 8) & 0xFFFFFFFF
    eax &= 0xFF00
    eax = (eax + ecx_shl) & 0xFFFFFFFF
    cx = (di >> 8) & 0xFFFF
    dx = (edx + cx) & 0xFFFF
    return (eax | dx) & 0xFFFF

print('=== brute force 256 keys ===')
hits = []
for key in range(256):
    dec = bytes(((b ^ key) + 0x22) & 0xFF for b in enc)
    if checksum_exact(dec) == 0xFB5E:
        print(f'KEY FOUND: 0x{key:02x} ({key})')
        hits.append(dec)

for dec in hits:
    print('\ndecrypted payload hex:', dec.hex()[:80], '...')
    print('ascii:', ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in dec))
    # 反汇编
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print('\n=== disasm @0x40107c ===')
    for ins in md.disasm(dec, 0x40107c):
        print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
