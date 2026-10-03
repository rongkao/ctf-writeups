# -*- coding: utf-8 -*-
# 05 zyzy: 仿真整个校验函数 0xf32600(this, CString*)，观察中间缓冲与返回值
import struct
from unicorn import *
from unicorn.x86_const import *

DUMP = r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu\dumped.bin'
BASE = 0xF30000
img = open(DUMP, 'rb').read()

STACK = 0x500000
THIS = 0x700000
CSTR_HDR = 0x710000     # CString 对象（放参数区）
STRDATA = 0x720000      # 字符串数据
RET = 0xDEADBEEF

def run_check(input_bytes: bytes, wide: bool):
    import pickle, os
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(BASE, 0x370000)
    mu.mem_write(BASE, img[:0x370000])
    mu.mem_map(0x500000, 0x40000)
    mu.mem_map(0x700000, 0x100000)
    mu.mem_map(0, 0x1000)                            # fs base 默认 0 → fs:[0] 落在 0 页
    mu.mem_write(0, struct.pack('<I', 0xFFFFFFFF))   # SEH 链终止符
    # 注入系统模块区域（真进程 dump）——逐 4KB 写，失败页跳过
    pkl = r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu\sysregions.pkl'
    if os.path.exists(pkl):
        for addr, blob in pickle.load(open(pkl, 'rb')):
            base = addr & ~0xFFF
            end = (addr + len(blob) + 0xFFF) & ~0xFFF
            try:
                mu.mem_map(base, end - base)
            except UcError:
                pass
            for off in range(0, len(blob), 0x1000):
                try:
                    mu.mem_write(addr + off, blob[off:off+0x1000])
                except UcError:
                    pass
    # CString = {m_pchData}
    mu.mem_write(STRDATA, input_bytes + b'\x00\x00')
    mu.mem_write(CSTR_HDR, struct.pack('<I', STRDATA))
    # thiscall(this=ecx, arg=[CString*]) → push CSTR_HDR; push RET
    sp = STACK + 0x20000
    sp -= 4; mu.mem_write(sp, struct.pack('<I', CSTR_HDR))
    sp -= 4; mu.mem_write(sp, struct.pack('<I', RET))
    for reg in (UC_X86_REG_EDI, UC_X86_REG_ESI, UC_X86_REG_EBX):
        mu.reg_write(reg, THIS)
    mu.reg_write(UC_X86_REG_ESP, sp)
    mu.reg_write(UC_X86_REG_EBP, STACK + 0x20000)
    mu.reg_write(UC_X86_REG_ECX, THIS)
    # 花指令/内存错误诊断
    trace = []
    mu.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: (trace.append(a), len(trace) > 100 and del_trace(trace)) if False else trace.append(a))
    try:
        mu.emu_start(0xf32600, RET, 0, 0)   # 无超时
    except UcError as e:
        rip = mu.reg_read(UC_X86_REG_EIP)
        print(f'!! {e} EIP=0x{rip:x} last: {[hex(a) for a in trace[-15:]]}')
        return None
    eax = mu.reg_read(UC_X86_REG_EAX) & 0xFF
    return eax

def del_trace(t): pass

tests = [
    (b'f250e3d75820847d427f3af11a783379AAAAAA', False),
    (b'KCTF{f250e3d75820847d427f3af11a783379}', False),
]
for data, wide in tests:
    r = run_check(data, wide)
    verdict = 'PASS' if r == 1 else 'FAIL'
    print(f'{data[:20]!r}... -> ret={r} ({verdict})')
