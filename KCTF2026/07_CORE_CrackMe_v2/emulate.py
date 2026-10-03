# -*- coding: utf-8 -*-
# 07 CORE: Unicorn 仿真执行二进制 transform(0x401500)，验证 oracle 是否复现地面真值
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
    mu.mem_map(0x70000, 0x10000)          # 数据区
    mu.mem_map(STACK - 0x10000, 0x20000)  # 栈区
    mu.mem_write(BLOCK, block_64b)
    mu.mem_write(STATE, state_16b)
    mu.mem_write(0x71010, b'\x00' * 16)   # 干净的工作区
    # cdecl: push state; push block; call → 栈顶应是 [ret, block, state]
    sp = STACK
    sp -= 4; mu.mem_write(sp, struct.pack('<I', STATE))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BLOCK))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_MAGIC))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, STACK)
    mu.emu_start(0x401500, RET_MAGIC)
    return mu.mem_read(STATE, 16)

# ── 构造与程序一致的 padding ──
def md5_pad(msg: bytes) -> bytes:
    ml = len(msg) * 8
    pad = msg + b'\x80' + b'\x00' * ((56 - len(msg) - 1) % 64) + struct.pack('<QQ', ml & 0xFFFFFFFFFFFFFFFF, 0)[:8]
    # 程序只在 [56] 写低 32 位长度，高 32 位靠清零 —— 等价于标准小端 64 位长度
    return pad

IV = struct.pack('<4I', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)
MSG = b'testtsettsettset'

block = md5_pad(MSG)
print('block len:', len(block), 'tail:', block[56:64].hex())

out = run_transform(block, IV)
words = struct.unpack('<4I', bytes(out))
print('仿真结果  :', ' '.join(f'{w:08x}' for w in words))
print('地面真值  : c6c0a6a4 fd5b4cb6 ed9b5781 182d2423')
print('匹配' if words == (0xc6c0a6a4, 0xfd5b4cb6, 0xed9b5781, 0x182d2423) else '不匹配 —— 魔改不在 transform 内')

import hashlib
std = struct.unpack('<4I', hashlib.md5(MSG).digest())
print('标准 MD5  :', ' '.join(f'{w:08x}' for w in std))
