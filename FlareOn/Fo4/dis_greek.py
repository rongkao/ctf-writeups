# -*- coding: utf-8 -*-
"""Flare-On 4 C3 greek_to_me.exe 反汇编：定位校验与数据"""
import struct, re
from capstone import *

path = r'D:\codes\ctf\FlareOn\Fo4\03\greek_to_me.exe'
data = open(path, 'rb').read()
pe_off = struct.unpack('<I', data[0x3c:0x40])[0]
opt = pe_off + 24
ep_rva = struct.unpack('<I', data[opt+16:opt+20])[0]
ib = struct.unpack('<I', data[opt+28:opt+32])[0]
nsec = struct.unpack('<H', data[pe_off+6:pe_off+8])[0]
opt_size = struct.unpack('<H', data[pe_off+20:pe_off+22])[0]
print(f'EP: {hex(ib+ep_rva)} IB: {hex(ib)}')

secs = []
so = pe_off + 24 + opt_size
for i in range(nsec):
    s = data[so+i*40:so+i*40+40]
    nm = s[:8].rstrip(b'\x00').decode(errors='replace')
    vs, va, rs, ra = struct.unpack('<IIII', s[8:24])
    secs.append((nm, va, vs, ra, rs))
    print(f'  {nm:8} va={hex(va)} vs={hex(vs)} ra={hex(ra)}')

def rva2off(rva):
    for nm, va, vs, ra, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_32)
off = rva2off(ep_rva)
print('\n=== main (EP) ===')
cnt = 0
main_calls = []
for ins in md.disasm(data[off:off+0x400], ib + ep_rva):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'call' and ins.op_str.startswith('0x'):
        main_calls.append(ins.op_str)
    cnt += 1
    if cnt > 80:
        break
print('\nmain calls:', main_calls[:12])
