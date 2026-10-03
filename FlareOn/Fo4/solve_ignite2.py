# -*- coding: utf-8 -*-
"""IgniteMe 求解器 v2：t[i] = input[i] ^ input[i+1] (i=0..37)
枚举 input[0]，正推 39 字节链，打印全可打印候选（含 @flare-on.com 的即 flag）
expected[38] 用于反推 c_init（验证用）
"""
data = open(r'D:\codes\ctf\FlareOn\Fo4\02\IgniteMe.exe', 'rb').read()
expected = data[0xa00:0xa00 + 39]

candidates = []
for first in range(1, 256):
    inp = bytearray([first])
    for i in range(38):
        inp.append(inp[i] ^ expected[i])
    if all(0x20 <= b < 0x7f for b in inp):
        c_init = inp[38] ^ expected[38]
        s = bytes(inp).decode('ascii')
        candidates.append((first, c_init, s))

print(f'可打印候选 {len(candidates)} 个:')
for first, c_init, s in candidates:
    tag = ' <-- FLAG (含 @flare-on.com)' if '@flare-on.com' in s else ''
    ci = chr(c_init) if 0x20 <= c_init < 0x7f else f'0x{c_init:02x}'
    print(f'  [0]=0x{first:02x}({chr(first)}) c_init={ci!r:>6}  {s}{tag}')
