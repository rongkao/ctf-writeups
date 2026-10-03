# -*- coding: utf-8 -*-
# 06 BabyRev v3: segments 解析（无 section headers）→ _start → main 反汇编
from elftools.elf.elffile import ELFFile
from capstone import *

path = r'D:\codes\ctf\KCTF2026\06_rev_babyrev\BabyRev'
elf = ELFFile(open(path, 'rb'))
entry = elf.header.e_entry
print(f'entry: 0x{entry:x}')

# 收集可读 segment（file-backed）
segs = []
for seg in elf.iter_segments():
    if seg['p_type'] == 'PT_LOAD':
        d = seg.data()
        segs.append((seg['p_vaddr'], seg['p_filesz'], d))
        print(f"PT_LOAD vaddr=0x{seg['p_vaddr']:x} filesz=0x{seg['p_filesz']:x} flags={seg['p_flags']}")

def read(addr, n):
    for base, size, d in segs:
        if base <= addr < base + size:
            return d[addr-base:addr-base+n]
    return b''

md = Cs(CS_ARCH_X86, CS_MODE_64)
print()
print('=== _start ===')
code = read(entry, 128)
main_addr = None
for ins in md.disasm(code, entry):
    print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
    if ins.mnemonic == 'lea' and 'rip' in ins.op_str and main_addr is None:
        s = ins.op_str
        try:
            off = int(s[s.index('rip+')+4:].rstrip(']'), 16) if '+' in s else -int(s[s.index('rip-')+4:].rstrip(']'), 16)
            main_addr = ins.address + ins.size + off
        except ValueError:
            pass
    if ins.mnemonic == 'hlt':
        break

if main_addr:
    print(f'\n=== main @0x{main_addr:x} ===')
    for ins in md.disasm(read(main_addr, 1200), main_addr):
        print(f'0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}')
        if ins.mnemonic == 'ret':
            break
