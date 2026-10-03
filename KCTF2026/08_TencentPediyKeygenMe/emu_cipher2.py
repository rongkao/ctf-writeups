# -*- coding: utf-8 -*-
# 用 Unicorn 仿真自定义 Feistel 块加密/解密，手动实现 CBC
import struct
from unicorn import *
from unicorn.x86_const import *

DUMP = r'D:\codes\ctf\KCTF2026\08_TencentPediyKeygenMe\dumped.bin'
BASE = 0x400000
img = open(DUMP, 'rb').read()
IMG_SIZE = len(img)

STACK = 0x800000
STACK_SIZE = 0x40000
HEAP = 0x900000

RET_ADDR = 0xDEADBEEF

def create_emu():
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    map_size = (IMG_SIZE + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, map_size)
    mu.mem_write(BASE, img[:map_size])
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(HEAP, 0x100000)
    mu.mem_map(0, 0x1000)
    mu.mem_write(0, struct.pack('<I', 0xFFFFFFFF))
    return mu

CIPHER_OBJ = HEAP
KEY_BUF = HEAP + 0x6000
BUF_A = HEAP + 0x7000
BUF_B = HEAP + 0x8000

def init_cipher(mu, direction, key):
    """初始化自定义 Feistel 加密器"""
    mu.mem_write(CIPHER_OBJ, b'\x00' * 0x2000)
    mu.mem_write(KEY_BUF, key)

    sp = STACK + STACK_SIZE - 0x1000
    args = [direction, KEY_BUF, len(key)]
    for a in reversed(args):
        sp -= 4; mu.mem_write(sp, struct.pack('<I', a & 0xFFFFFFFF))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu.emu_start(0x448b50, RET_ADDR, timeout=10000000)

def block_cipher(mu, input_8bytes):
    """调用 0x448710 对 8 字节块做 Feistel 加密/解密"""
    mu.mem_write(BUF_A, input_8bytes)
    mu.mem_write(BUF_B, b'\x00' * 8)

    sp = STACK + STACK_SIZE - 0x2000
    # 0x448710 args: [esp+8]=input_ptr(after push ecx), [esp+0xc]=output_ptr
    # 但实际上我需要看它怎么写回结果
    # 从 0x448b0d 的调用方式: push output_ptr, push input_ptr, call 0x448710
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BUF_B))  # arg2: output
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BUF_A))  # arg1: input
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu.emu_start(0x448710, RET_ADDR, timeout=5000000)

    # 读结果: 先检查 BUF_B, 再检查 BUF_A (输出可能写到输入位置)
    out_b = bytes(mu.mem_read(BUF_B, 8))
    out_a = bytes(mu.mem_read(BUF_A, 8))
    # 还需要检查栈上的局部变量
    sp_val = mu.reg_read(UC_X86_REG_ESP)
    return out_a, out_b

def xor8(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

# 测试: 初始化加密, 运行单块加密
mu = create_emu()
print('=== Init cipher (direction=0, decrypt) ===')
init_cipher(mu, 0, b'DEADBEEF')
print('Init OK')

# 测试块解密
test_block = bytes(range(8))
out_a, out_b = block_cipher(mu, test_block)
print(f'Block decrypt input:  {test_block.hex()}')
print(f'  output (at BUF_A): {out_a.hex()}')
print(f'  output (at BUF_B): {out_b.hex()}')

# 用 full CBC decrypt 验证
print()
print('=== Compare with full CBC decrypt ===')
mu2 = create_emu()
mu2.mem_write(CIPHER_OBJ, b'\x00' * 0x2000)
mu2.mem_write(KEY_BUF, b'DEADBEEF')
# init
sp = STACK + STACK_SIZE - 0x1000
for a in reversed([0, KEY_BUF, 8]):
    sp -= 4; mu2.mem_write(sp, struct.pack('<I', a))
sp -= 4; mu2.mem_write(sp, struct.pack('<I', RET_ADDR))
mu2.reg_write(UC_X86_REG_ESP, sp)
mu2.reg_write(UC_X86_REG_EBP, sp + 0x200)
mu2.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
mu2.emu_start(0x448b50, RET_ADDR, timeout=10000000)

# set IV to zero
IV_BUF = HEAP + 0x9000
mu2.mem_write(IV_BUF, b'\x00' * 8)
sp = STACK + STACK_SIZE - 0x1000
for a in reversed([IV_BUF, 4]):
    sp -= 4; mu2.mem_write(sp, struct.pack('<I', a))
sp -= 4; mu2.mem_write(sp, struct.pack('<I', RET_ADDR))
mu2.reg_write(UC_X86_REG_ESP, sp)
mu2.reg_write(UC_X86_REG_EBP, sp + 0x200)
mu2.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
mu2.emu_start(0x448a40, RET_ADDR, timeout=5000000)

# decrypt 8 bytes
IN_BUF = HEAP + 0xA000
OUT_BUF = HEAP + 0xB000
OUTSIZE = HEAP + 0xC000
mu2.mem_write(IN_BUF, test_block)
mu2.mem_write(OUTSIZE, struct.pack('<I', 32))
sp = STACK + STACK_SIZE - 0x1000
for a in reversed([IN_BUF, 8, OUT_BUF, OUTSIZE]):
    sp -= 4; mu2.mem_write(sp, struct.pack('<I', a))
sp -= 4; mu2.mem_write(sp, struct.pack('<I', RET_ADDR))
mu2.reg_write(UC_X86_REG_ESP, sp)
mu2.reg_write(UC_X86_REG_EBP, sp + 0x200)
mu2.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
mu2.emu_start(0x448a90, RET_ADDR, timeout=5000000)
cbc_out = bytes(mu2.mem_read(OUT_BUF, 8))
print(f'CBC decrypt (iv=0): {test_block.hex()} -> {cbc_out.hex()}')
print()

# CBC decrypt = D(C) ^ IV. With IV=0: CBC_dec = D(C)
# So cbc_out should equal the block decrypt output
if cbc_out == out_a:
    print('Block output matches CBC output (at BUF_A) -> output goes to input buffer')
elif cbc_out == out_b:
    print('Block output matches CBC output (at BUF_B) -> output goes to output buffer')
else:
    print('Neither matches! Need more investigation')
    # 也试试 XOR 情况
    for label, buf in [('out_a^input', xor8(out_a, test_block)), ('out_b^input', xor8(out_b, test_block))]:
        if buf == cbc_out:
            print(f'  {label} matches CBC output')
