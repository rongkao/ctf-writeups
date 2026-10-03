# -*- coding: utf-8 -*-
# 06 BabyRev: stripped ELF → 从 entry 找 main → 反汇编
import struct
from elftools.elf.elffile import ELFFile
from capstone import *

path = r'D:\codes\ctf\KCTF2026\06_rev_babyrev\BabyRev'
f = open(path, 'rb')
elf = ELFFile(f)
entry = elf.header.e_entry
print(f'entry: 0x{entry:x}')

# 段映射
secs = []
for s in elf.iter_sections():
    if s['sh_addr']:
        secs.append((s['sh_addr'], s['sh_size'], s.name, s.data() if s.name != '.bss' else b''))
secs.sort()
def read(addr, n):
    for base, size, name, d in secs:
        if base <= addr < base + size:
            return d[addr-base:addr-base+n]
    return b''

text = elf.get_section_by_name('.text')
ta, tdata = text['sh_addr'], text.data()
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

# _start: 标准 glibc 模式 xor ebp,ebp; ... lea rax,[main]; mov rdi,rax; call __libc_start_main@plt
code = tdata[entry-ta:entry-ta+200]
print('=== _start ===')
main_addr = None
for ins in md.disasm(code, entry):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'lea' and 'rip' in ins.op_str:
        # lea rax, [rip+off] → 计算 target
        off = int(ins.op_str.split('+')[-1].rstrip(']'), 16) if '+' in ins.op_str else -int(ins.op_str.split('-')[-1].rstrip(']'), 16)
        target = ins.address + ins.size + off
        if main_addr is None and ins.op_str.startswith('rax'):
            main_addr = target
    if ins.mnemonic == 'call':
        break

if main_addr:
    print(f'\n=== main @0x{main_addr:x} ===')
    off = main_addr - ta
    for ins in md.disasm(tdata[off:off+600], main_addr):
        print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
        if ins.mnemonic == 'ret':
            break
