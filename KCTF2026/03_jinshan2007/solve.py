# -*- coding: utf-8 -*-
# 03_jinshan2007 求解：还原 2007 金山 CrackMe 算法 + BFS 搜索序列号
from collections import deque

MASK32 = 0xFFFFFFFF

def rotl32(x, n):
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32

def name_hash(name: str) -> int:
    """DlgProc 用户名哈希（严格按反汇编：sar 算术右移，不是 rotl！）"""
    h = 0x13572468
    for ch in name:
        c = ord(ch)
        eax = (c + h) & MASK32
        eax = (eax * 0x3721273) & MASK32
        eax = (eax + 0x24681357) & MASK32
        # esi = eax << 25 | eax sar 7（符号扩展右移）
        lo = (eax << 25) & MASK32
        signed = eax - 0x100000000 if eax >= 0x80000000 else eax
        hi = (signed >> 7) & MASK32
        h = (lo | hi) & MASK32
    return h

def expect(hash_: int, i: int) -> int:
    """第 i 位序列号字符的期望值: (hash >> (i % 31)) % 10"""
    return ((hash_ >> (i % 31)) % 10)

# ── 比特翻转规则（校验函数核心） ──
def step(s: int, v: int):
    """状态 s（bit1..9 存在位 0..8），施加 val=v。返回新状态或 None（非法）"""
    if v == 1:
        return s ^ 1                      # 翻转 bit[1]，无条件
    if not (s >> (v - 2)) & 1:            # bit[v-1] 必须为 1
        return None
    mask = (1 << (v - 2)) - 1             # bit[1..v-2] 必须全 0
    if mask and (s & mask):
        return None
    return s ^ (1 << (v - 1))             # 翻转 bit[v]

def solve(name: str):
    h = name_hash(name)
    print(f"用户名 {name!r} 的 hash = 0x{h:08X}")
    # 初始状态: bit[1..8]=hash 位 1..8, bit[9]=1
    s0 = ((h >> 1) & 0xFF) | 0x100
    print(f"初始状态 bit 表 = 0x{s0:03X} (bit9..bit1 = {s0:09b})")

    # BFS 最短 val 序列: s0 -> 0
    q = deque([(s0, [])])
    seen = {s0}
    path = None
    while q:
        s, seq = q.popleft()
        if s == 0:
            path = seq
            break
        for v in range(1, 10):
            ns = step(s, v)
            if ns is not None and ns not in seen:
                seen.add(ns)
                q.append((ns, seq + [v]))
    if path is None:
        return None, h
    # 反推数字: digit_i = (val_i - expect_i) mod 10
    digits = [(v - expect(h, i)) % 10 for i, v in enumerate(path)]
    serial = ''.join(str(d) for d in digits)
    return serial, h

for name in ["KCTF"]:
    serial, h = solve(name)
    print(f"\n>>> {name} de xu lie hao ({len(serial)} wei): {serial}")
    with open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt', 'w') as fp:
        fp.write(f"KCTF\n{serial}\n")

# ── 离线复现校验函数，验证序列号确实通过 ──
def verify(name, serial):
    h = name_hash(name)
    s = ((h >> 1) & 0xFF) | 0x100
    for i, ch in enumerate(serial):
        if not ch.isdigit():
            return False, "非数字字符"
        val = (expect(h, i) + (ord(ch) - 0x30)) % 10
        if val == 1:
            s ^= 1
        else:
            ns = step(s, val)
            if ns is None:
                return False, f"第 {i} 位 val={val} 非法"
            s = ns
    return s == 0, f"终态 bit 表 = 0x{s:03X}"

ok, msg = verify("KCTF", serial)
print(f"verify: {'PASS (OK!!)' if ok else 'FAIL: ' + msg}")
