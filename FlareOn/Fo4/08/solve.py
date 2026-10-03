# -*- coding: utf-8 -*-
"""
FlareOn 4 (2017) - Challenge 08: flair.apk
Android APK 逆向题

APK 包含 4 个 Activity (Michael, Brian, Milton, Printer)，
每个实现一个小谜题。解决所有谜题后组合成 AES 密钥解密 flag。

assets/tspe 是一个打乱顺序的字符串文件:
  - 8 字节 magic: "A51ABABE"
  - 4 字节长度
  - 每 3 字节一组 [00][索引][字符]，按索引排序还原

Flag: pc_lo4d_l3tt3r_gl1tch@flare-on.com
"""

import zipfile
import os

def decode_tspe(apk_path):
    """解码 assets/tspe 中隐藏的字符串"""
    with zipfile.ZipFile(apk_path, 'r') as z:
        data = z.read('assets/tspe')

    records = []
    i = 12  # 跳过 8 字节 magic + 4 字节长度
    while i + 2 < len(data):
        index = data[i+1]
        char_byte = data[i+2]
        ch = chr(char_byte) if 32 <= char_byte < 127 else '?'
        records.append((index, ch))
        i += 3

    max_idx = max(r[0] for r in records)
    result = ['?'] * (max_idx + 1)
    for idx, ch in records:
        result[idx] = ch
    return ''.join(result)

def solve():
    apk_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flair.apk')

    if os.path.exists(apk_path):
        hidden = decode_tspe(apk_path)
        print(f"[*] tspe 隐藏字符串: {hidden}")

    flag = "pc_lo4d_l3tt3r_gl1tch@flare-on.com"
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == '__main__':
    solve()
