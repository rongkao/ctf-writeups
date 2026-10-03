# -*- coding: utf-8 -*-
"""Retro OEM License Check keygen (crackmes.one)
规则: XXXXX-OEM-XXXXXXX-XXXXX
  1. 格式: len=23, [5]/[9]/[17]='-', [6:9]="OEM", 全段 isalnum(大写+数字), 中段纯数字
  2. 前段: buf[0]^..^buf[4] == 0x5A
  3. 中段: sum(digits) % 7 == 0
  4. 尾段: base36(前段[i]) + 7 mod 36 的对应字符（凯撒+7）
"""
import random

ALNUM = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def make_prefix():
    while True:
        p = [random.choice(ALNUM) for _ in range(4)]
        x = 0
        for c in p:
            x ^= ord(c)
        c5 = chr(x ^ 0x5A)
        if c5 in ALNUM:
            return ''.join(p) + c5

def make_mid():
    while True:
        d = [random.choice('0123456789') for _ in range(7)]
        if sum(map(int, d)) % 7 == 0:
            return ''.join(d)

def keygen():
    a = make_prefix()
    mid = make_mid()
    tail = ''.join(ALNUM[(int(c, 36) + 7) % 36] for c in a)
    return f'{a}-OEM-{mid}-{tail}'

def verify(key):
    if len(key) != 23 or key[5] != '-' or key[9] != '-' or key[17] != '-':
        return False
    if key[6:9] != 'OEM':
        return False
    a, mid, tail = key[:5], key[10:17], key[18:]
    if not all(c in ALNUM for c in a + tail):
        return False
    if not mid.isdigit():
        return False
    x = 0
    for c in a:
        x ^= ord(c)
    if x != 0x5A:
        return False
    if sum(map(int, mid)) % 7 != 0:
        return False
    return all(tail[i] == ALNUM[(int(a[i], 36) + 7) % 36] for i in range(5))

if __name__ == '__main__':
    for _ in range(5):
        k = keygen()
        assert verify(k), k
        print(k)
