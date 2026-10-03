# -*- coding: utf-8 -*-
# 05 zyzy: Unicorn 仿真 RC4 KSA(0xf32ca0) + PRGA(0xf32e80)，与 Python 标准实现对拍
import struct
from unicorn import *
from unicorn.x86_const import *

DUMP = r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu\dumped.bin'
BASE = 0xF30000
img = open(DUMP, 'rb').read()

STACK = 0x500000
THIS = 0x600000      # this 指针（指向可写内存即可）
STATE = 0x610000     # RC4 state
KEYBUF = 0x620000
DATABUF = 0x630000
RET = 0xDEADBEEF

def setup():
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(BASE, 0x370000)
    mu.mem_write(BASE, img[:0x370000])
    mu.mem_map(0x500000, 0x20000)   # 栈
    mu.mem_map(0x600000, 0x80000)   # 数据
    # 内存错误 hook：打印出错位置
    trace = []
    def hook_code(uc, address, size, user_data):
        trace.append(address)
        if len(trace) > 60:
            del trace[:20]
    mu.hook_add(UC_HOOK_CODE, hook_code)
    def hook_inv(uc, access, address, size, value, user_data):
        rip = uc.reg_read(UC_X86_REG_EIP)
        print(f'!! MEM invalid: access={access} addr=0x{address:x} EIP=0x{rip:x}')
        print('   last exec:', ' -> '.join(hex(a) for a in trace[-25:]))
        return False
    mu.hook_add(UC_HOOK_MEM_INVALID, hook_inv)
    return mu

def call_thiscall(mu, func, this, args):
    sp = STACK + 0x10000
    for a in reversed(args):
        sp -= 4; mu.mem_write(sp, struct.pack('<I', a))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET))
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, STACK + 0x10000)
    mu.reg_write(UC_X86_REG_ECX, this)
    # 初始化通用寄存器到可写内存，避免花指令/库函数踩垃圾值
    for reg in (UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBX,
                UC_X86_REG_EAX, UC_X86_REG_EDX):
        mu.reg_write(reg, THIS)
    mu.emu_start(func, RET)
    return mu.reg_read(UC_X86_REG_EAX)

KEY = b'qwertyuiop'
mu = setup()
mu.mem_write(KEYBUF, KEY)
# KSA(this, state=STATE, key=KEYBUF, keylen=10)
r1 = call_thiscall(mu, 0xf32ca0, THIS, [STATE, KEYBUF, len(KEY)])
print('KSA ret:', r1)

# PRGA(this, state=STATE, data=DATABUF, len=n)
test = b'f250e3d75820847d427f3af11a783379AAAAAA'
mu.mem_write(DATABUF, test)
r2 = call_thiscall(mu, 0xf32e80, THIS, [STATE, DATABUF, len(test)])
out = bytes(mu.mem_read(DATABUF, len(test)))
print('PRGA ret:', r2)
print('emulated :', out.hex())

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    o = bytearray(); x = y = 0
    for b in data:
        x = (x+1)&0xFF; y = (y+S[x])&0xFF
        S[x], S[y] = S[y], S[x]
        o.append(b ^ S[(S[x]+S[y])&0xFF])
    return bytes(o)

py = rc4(KEY, test)
print('python   :', py.hex())
print('MATCH' if out == py else 'MISMATCH —— PRGA/KSA 有魔改')

target = bytes.fromhex('5bd6d026c8dd197e6e3ecb16917dffafdd7664b0f7e58957829f0c009ed045fa')
print()
print('目标前32:', target.hex())
print('仿真前32:', out[:32].hex())
