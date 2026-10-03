# -*- coding: utf-8 -*-
"""
Challenge 08 自定义 Feistel 加密器 - 通过 Unicorn 仿真实现 CBC 加密和解密
"""
import struct
from unicorn import *
from unicorn.x86_const import *

DUMP = r'D:\codes\ctf\KCTF2026\08_TencentPediyKeygenMe\dumped.bin'
BASE = 0x400000
_img = open(DUMP, 'rb').read()
_IMG_SIZE = len(_img)

STACK = 0x800000
STACK_SIZE = 0x40000
HEAP = 0x900000
RET_ADDR = 0xDEADBEEF

CIPHER_OBJ = HEAP
BUF_A = HEAP + 0x7000
BUF_B = HEAP + 0x8000

def _create_emu():
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    map_size = (_IMG_SIZE + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, map_size)
    mu.mem_write(BASE, _img[:map_size])
    mu.mem_map(STACK, STACK_SIZE)
    mu.mem_map(HEAP, 0x100000)
    mu.mem_map(0, 0x1000)
    mu.mem_write(0, struct.pack('<I', 0xFFFFFFFF))
    return mu

def _init_cipher(mu, direction, key):
    """初始化 Feistel 加密器对象 (direction: 0=decrypt, 1=encrypt)"""
    mu.mem_write(CIPHER_OBJ, b'\x00' * 0x2000)
    KEY_BUF = HEAP + 0x6000
    mu.mem_write(KEY_BUF, key)
    sp = STACK + STACK_SIZE - 0x1000
    for a in reversed([direction, KEY_BUF, len(key)]):
        sp -= 4; mu.mem_write(sp, struct.pack('<I', a & 0xFFFFFFFF))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu.emu_start(0x448b50, RET_ADDR, timeout=10000000)

def _block_cipher(mu, input_8bytes):
    """单块 Feistel 加密/解密 (8 字节)"""
    mu.mem_write(BUF_A, input_8bytes)
    mu.mem_write(BUF_B, b'\x00' * 8)
    sp = STACK + STACK_SIZE - 0x2000
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BUF_B))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', BUF_A))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu.emu_start(0x448710, RET_ADDR, timeout=5000000)
    return bytes(mu.mem_read(BUF_B, 8))

def xor8(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

class CustomCipher:
    def __init__(self, key, direction):
        self.mu = _create_emu()
        _init_cipher(self.mu, direction, key)

    def block(self, data8):
        return _block_cipher(self.mu, data8)

def cbc_decrypt(key, iv, ciphertext):
    """CBC 解密: P[i] = D(C[i]) ^ C[i-1]"""
    assert len(ciphertext) % 8 == 0
    cipher = CustomCipher(key, 0)
    result = b''
    prev = iv
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        dec = cipher.block(block)
        result += xor8(dec, prev)
        prev = block
    return result

def cbc_encrypt(key, iv, plaintext):
    """CBC 加密: C[i] = E(P[i] ^ C[i-1])"""
    assert len(plaintext) % 8 == 0
    cipher = CustomCipher(key, 1)
    result = b''
    prev = iv
    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i+8]
        xored = xor8(block, prev)
        enc = cipher.block(xored)
        result += enc
        prev = enc
    return result

if __name__ == '__main__':
    key = b'DEADBEEF'
    iv = b'\x00' * 8

    # 测试 CBC 加密解密 roundtrip
    plain = bytes(range(16))
    print(f'原文:   {plain.hex()}')
    enc = cbc_encrypt(key, iv, plain)
    print(f'加密后: {enc.hex()}')
    dec = cbc_decrypt(key, iv, enc)
    print(f'解密后: {dec.hex()}')
    print(f'Roundtrip 匹配: {dec == plain}')

    # 使用非零 IV 测试
    print()
    iv2 = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
    enc2 = cbc_encrypt(key, iv2, plain)
    print(f'IV={iv2.hex()}, 加密后: {enc2.hex()}')
    dec2 = cbc_decrypt(key, iv2, enc2)
    print(f'解密后: {dec2.hex()}')
    print(f'Roundtrip 匹配: {dec2 == plain}')

    # 用原始 0x448a90 CBC 解密验证一致性
    print()
    print('=== 与原始 CBC 解密对比 ===')
    mu3 = _create_emu()
    mu3.mem_write(CIPHER_OBJ, b'\x00' * 0x2000)
    KEY_BUF = HEAP + 0x6000
    mu3.mem_write(KEY_BUF, key)
    sp = STACK + STACK_SIZE - 0x1000
    for a in reversed([0, KEY_BUF, 8]):
        sp -= 4; mu3.mem_write(sp, struct.pack('<I', a))
    sp -= 4; mu3.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu3.reg_write(UC_X86_REG_ESP, sp)
    mu3.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu3.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu3.emu_start(0x448b50, RET_ADDR, timeout=10000000)

    IV_BUF = HEAP + 0x9000
    mu3.mem_write(IV_BUF, iv)
    sp = STACK + STACK_SIZE - 0x1000
    for a in reversed([IV_BUF, 4]):
        sp -= 4; mu3.mem_write(sp, struct.pack('<I', a))
    sp -= 4; mu3.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu3.reg_write(UC_X86_REG_ESP, sp)
    mu3.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu3.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu3.emu_start(0x448a40, RET_ADDR, timeout=5000000)

    IN_BUF = HEAP + 0xA000
    OUT_BUF = HEAP + 0xB000
    OUTSIZE = HEAP + 0xC000
    mu3.mem_write(IN_BUF, enc)
    mu3.mem_write(OUTSIZE, struct.pack('<I', 32))
    sp = STACK + STACK_SIZE - 0x1000
    for a in reversed([IN_BUF, len(enc), OUT_BUF, OUTSIZE]):
        sp -= 4; mu3.mem_write(sp, struct.pack('<I', a))
    sp -= 4; mu3.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu3.reg_write(UC_X86_REG_ESP, sp)
    mu3.reg_write(UC_X86_REG_EBP, sp + 0x200)
    mu3.reg_write(UC_X86_REG_ECX, CIPHER_OBJ)
    mu3.emu_start(0x448a90, RET_ADDR, timeout=5000000)
    outlen = struct.unpack('<I', bytes(mu3.mem_read(OUTSIZE, 4)))[0]
    orig_dec = bytes(mu3.mem_read(OUT_BUF, 16))
    print(f'原始 CBC 解密: {enc.hex()} -> {orig_dec.hex()}')
    print(f'我的 CBC 解密: {enc.hex()} -> {dec.hex()}')
    print(f'两者一致: {orig_dec == dec}')
