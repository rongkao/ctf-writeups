# -*- coding: utf-8 -*-
"""Flare-On 4 Challenge 2 IgniteMe 求解器
校验: t[i] = input[i] ^ input[i+1] (i=0..37), t[38] = input[38] ^ input[0]
      t[0..38] == expected @ VA 0x403000 (文件偏移 0xa00)
恢复: 猜 input[0] → input[i+1] = input[i] ^ t[i] → 校验回绕一致性 + 可打印性
"""
data = open(r'D:\codes\ctf\FlareOn\Fo4\02\IgniteMe.exe', 'rb').read()

# .data: va=0x3000 ra=0xa00 → VA 0x403000 = off 0xa00
EXPECTED_VA = 0x403000
off = 0xa00 + (EXPECTED_VA - 0x403000)
expected = data[0xa00:0xa00 + 39]
print('expected (39B):', expected.hex())

# 爆破首字符
for first in range(0x20, 0x7f):
    inp = bytearray([first])
    for i in range(38):
        inp.append(inp[i] ^ expected[i])
    # 回绕校验: expected[38] == inp[38] ^ inp[0]
    if ((inp[38] ^ inp[0]) & 0xff) == expected[38]:
        try:
            s = bytes(inp).decode('ascii')
            print(f'input[0]=0x{first:02x} {chr(first)!r} -> FLAG: {s}')
        except UnicodeDecodeError:
            print(f'input[0]=0x{first:02x} -> non-ascii: {bytes(inp).hex()}')
