# -*- coding: utf-8 -*-
# 03_jinshan2007：全量反汇编 .text 段（仅 0x420 字节）
from capstone import *

path = r'D:\codes\ctf\KCTF2026\03_jinshan2007\CrackMe.exe'
data = open(path, 'rb').read()
IB = 0x400000
TEXT_OFF = 0x220
TEXT_SIZE = 0x420
code = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False
for ins in md.disasm(code, IB + TEXT_OFF):
    print(f"0x{ins.address:x}:\t{ins.mnemonic}\t{ins.op_str}")
