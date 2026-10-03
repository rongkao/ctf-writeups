# -*- coding: utf-8 -*-
# 07 CORE: 验证 off-by-one padding 假设 —— 长度字段 = (len+1)*8
import struct
from unicorn import *
from unicorn.x86_const import *

DUMP = r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin'
IMG_BASE = 0x400000
STACK = 0x90000
BLOCK = 0x70000
STATE = 0x71000
RET_MAGIC = 0xDEADBEEF

img = open(DUMP, 'rb').read()

def run_transform(block_64b: bytes, state_16b: bytes) -> bytes:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(IMG_BASE, 0x40000)
    mu.mem_write(IMG_BASE, img)
    mu.mem_map(0x70000, 0x10000)
    mu.mem_map(STACK - 0x10000, 0x20000)
    mu.mem_write(BLOCK, block_64b)
    mu.mem_write(STATE, state_16b)
    sp = STACK
    sp -= 4; mu.mem_write(sp, struct.pack('<I', STATE))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BLOCK))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_MAGIC))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, STACK)
    mu.emu_start(0x401500, RET_MAGIC)
    return bytes(mu.mem_read(STATE, 16))

def custom_pad(msg: bytes) -> bytes:
    """程序语义: msg + 0x80 + 清零到 56 + 长度=(len+1)*8 (LE32) + 高32位0"""
    buf = bytearray(msg)
    buf.append(0x80)
    while len(buf) % 64 < 56:
        buf.append(0)
    ml = (len(msg) + 1) * 8          # ← off-by-one！strlen 在写入 0x80 之后
    buf += struct.pack('<I', ml) + b'\x00' * 4
    return bytes(buf)

IV = struct.pack('<4I', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

for msg in (b'testtsettsettset', b'testZZZZ99ZZZZtset9ZZZZtset9ZZZZtset'):
    data = custom_pad(msg)
    state = IV
    for off in range(0, len(data), 64):
        state = run_transform(data[off:off+64], state)
    words = struct.unpack('<4I', state)
    print(f'{msg[:20]!r}... -> ' + ' '.join(f'{w:08x}' for w in words))

print()
print('地面真值 test: c6c0a6a4 fd5b4cb6 ed9b5781 182d2423')
