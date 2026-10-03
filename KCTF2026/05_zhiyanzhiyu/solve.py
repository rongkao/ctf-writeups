# -*- coding: utf-8 -*-
# 05 zhiyanzhiyu (知言知语 / Junk_Instruction) — 求解脚本
# 算法：
#   Phase 1: 检查 len==38, 提取 input[5:37] 的 32 字符并反转
#   Phase 2: RC4(key='qwertyuiop') 加密反转后的字符串, 与 32 字节目标密文比较
# 因此: inner = reverse(RC4_decrypt(target, key))

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

rc4_plaintext = rc4(KEY, TARGET).decode('ascii')
inner = rc4_plaintext[::-1]
flag = f'KCTF{{{inner}}}'
print(f'Flag: {flag}')
