# -*- coding: utf-8 -*-
# 07 CORE: 搜索栈上期望值是否为 dump 内的常量
import struct, re

data = open(r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\dumped.bin', 'rb').read()
BASE = 0x400000
targets = [0xc6c0a6a4, 0xfd5b4cb6, 0xed9b5781, 0x182d2423]

for t in targets:
    pat = struct.pack('<I', t)
    hits = [hex(BASE + m.start()) for m in re.finditer(re.escape(pat), data)]
    tag = hits[:6] if hits else 'NOT IN DUMP'
    print('0x%08x: %s' % (t, tag))

seq = b''.join(struct.pack('<I', t) for t in targets)
hits = [hex(BASE + m.start()) for m in re.finditer(re.escape(seq), data)]
print('16-byte contiguous:', hits if hits else 'not found')
