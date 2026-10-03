# -*- coding: utf-8 -*-
"""
KCTF2026 #05 zhiyanzhiyu (知言知语) - 解题脚本
算法: 输入格式 KCTF{32hex}, 提取中间32字符反转后 RC4 加密比对
RC4 key = 'qwertyuiop'
"""

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

TARGET = bytes.fromhex('5bd6d026c8dd197e6e3ecb16917dffafdd7664b0f7e58957829f0c009ed045fa')
KEY = b'qwertyuiop'

# RC4 解密得到反转后的字符串
reversed_flag = rc4(KEY, TARGET).decode('ascii')
print(f'RC4解密(反转态): {reversed_flag}')

# 再反转回来得到原始 flag 内容
flag_content = reversed_flag[::-1]
flag = f'KCTF{{{flag_content}}}'
print(f'Flag: {flag}')
# KCTF{973387a11fa3f724d74802857d3e052f}
