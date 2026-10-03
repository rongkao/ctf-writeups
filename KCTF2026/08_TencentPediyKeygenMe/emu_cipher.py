# -*- coding: utf-8 -*-
# 用 Unicorn 仿真自定义加密/解密函数
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
HEAP_SIZE = 0x100000
RET_ADDR = 0xDEADBEEF

def create_emu():
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    # 映射二进制
    map_size = (IMG_SIZE + 0xFFF) & ~0xFFF
    mu.mem_map(BASE, map_size)
    mu.mem_write(BASE, img[:map_size])
    # 栈
    mu.mem_map(STACK, STACK_SIZE)
    # 堆
    mu.mem_map(HEAP, HEAP_SIZE)
    # 零页 (SEH)
    mu.mem_map(0, 0x1000)
    mu.mem_write(0, struct.pack('<I', 0xFFFFFFFF))
    return mu

def call_cdecl(mu, func, args, esp_base=None):
    """cdecl 调用: 参数从右到左入栈, 调用者清栈"""
    sp = esp_base or (STACK + STACK_SIZE - 0x1000)
    for a in reversed(args):
        sp -= 4
        mu.mem_write(sp, struct.pack('<I', a & 0xFFFFFFFF))
    sp -= 4
    mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x100)
    mu.emu_start(func, RET_ADDR, timeout=5000000)
    return mu.reg_read(UC_X86_REG_EAX)

def call_thiscall(mu, func, this_ptr, stack_args, esp_base=None):
    """thiscall: ecx=this, 参数从右到左入栈, 被调者清栈"""
    sp = esp_base or (STACK + STACK_SIZE - 0x1000)
    for a in reversed(stack_args):
        sp -= 4
        mu.mem_write(sp, struct.pack('<I', a & 0xFFFFFFFF))
    sp -= 4
    mu.mem_write(sp, struct.pack('<I', RET_ADDR))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, sp + 0x100)
    mu.reg_write(UC_X86_REG_ECX, this_ptr)
    mu.emu_start(func, RET_ADDR, timeout=5000000)
    return mu.reg_read(UC_X86_REG_EAX)

# 自定义加密对象地址
CIPHER_OBJ = HEAP
# 加密数据缓冲区
BUF_IN = HEAP + 0x2000
BUF_OUT = HEAP + 0x3000
BUF_IV = HEAP + 0x4000
BUF_OUTSIZE = HEAP + 0x5000

def test_cipher(direction, key, iv_data, plaintext):
    """
    direction: 0=decrypt, 1=encrypt
    key: bytes (密钥)
    iv_data: bytes (IV/AAD, max 8 bytes)
    plaintext: bytes (输入数据, 8的倍数)
    """
    mu = create_emu()

    # 清零加密对象
    mu.mem_write(CIPHER_OBJ, b'\x00' * 0x2000)

    # 写入密钥
    KEY_BUF = HEAP + 0x6000
    mu.mem_write(KEY_BUF, key)

    # 调用 0x448b50 init: thiscall(ecx=obj, direction, key, keylen)
    call_thiscall(mu, 0x448b50, CIPHER_OBJ, [direction, KEY_BUF, len(key)])
    print(f'  Init done (direction={direction})')

    # 写入 IV
    mu.mem_write(BUF_IV, iv_data + b'\x00' * (8 - len(iv_data)))

    # 调用 0x448a40 set IV: thiscall(ecx=obj, iv_ptr, iv_len)
    call_thiscall(mu, 0x448a40, CIPHER_OBJ, [BUF_IV, len(iv_data)])
    print(f'  IV set: {iv_data.hex()}')

    # 写入输入数据
    mu.mem_write(BUF_IN, plaintext)
    mu.mem_write(BUF_OUTSIZE, struct.pack('<I', len(plaintext) + 16))

    # 调用 0x448a90 process: thiscall(ecx=obj, input, inlen, output, &outlen)
    ret = call_thiscall(mu, 0x448a90, CIPHER_OBJ,
                        [BUF_IN, len(plaintext), BUF_OUT, BUF_OUTSIZE])
    outlen = struct.unpack('<I', bytes(mu.mem_read(BUF_OUTSIZE, 4)))[0]
    output = bytes(mu.mem_read(BUF_OUT, outlen if outlen > 0 else len(plaintext)))
    print(f'  Process ret={ret}, outlen={outlen}')
    print(f'  Input:  {plaintext.hex()}')
    print(f'  Output: {output.hex()}')
    return output

# 测试: 解密+加密 roundtrip
print('=== Test 1: Decrypt then Encrypt ===')
key = b'DEADBEEF'
iv = b'\x00\x00\x00\x00'
test_data = bytes(range(16))

print('Encrypting:')
try:
    enc = test_cipher(1, key, iv, test_data)
    print()
    print('Decrypting:')
    dec = test_cipher(0, key, iv, enc)
    print()
    print(f'Roundtrip match: {dec == test_data}')
except UcError as e:
    print(f'Unicorn error: {e}')
    import traceback; traceback.print_exc()
