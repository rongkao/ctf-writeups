# -*- coding: utf-8 -*-
"""
CCG Crypto Crackme v1.0 Keygen (KCTF 靶场 04)
算法链：MD5 + RC4 + RSA(64位弱模数) + Base64
serial = Base64( RC4(key, MD5(name)[0:8]) + str( pow(int(MD5(name)[8:16]), d, n) ) )
"""
import hashlib, base64

def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    x = y = 0
    for b in data:
        x = (x + 1) & 0xFF
        y = (y + S[x]) & 0xFF
        S[x], S[y] = S[y], S[x]
        out.append(b ^ S[(S[x] + S[y]) & 0xFF])
    return bytes(out)

# 常量（从脱壳内存 dump 提取）
RC4_KEY = bytes.fromhex('2947078587332544')
N = 0xB80A90BF53C6C979
E = 65537
P, Q = 3753090347, 3533507051
D = pow(E, -1, (P - 1) * (Q - 1))

def keygen(name: str):
    md5 = hashlib.md5(name.encode()).digest()
    part1 = rc4(RC4_KEY, md5[0:8])                    # 8 字节 RC4 密文
    target = int.from_bytes(md5[8:16], 'big')          # 大端大数
    if target >= N:
        return None, target                            # m >= n 无解
    x = pow(target, D, N)
    buf = part1 + str(x).encode()
    return base64.b64encode(buf).decode(), target

def verify(name: str, serial: str):
    """离线复现校验函数 0x401610"""
    try:
        buf = base64.b64decode(serial, validate=True)
    except Exception:
        return False, 'base64 decode fail'
    if len(buf) < 9:
        return False, 'too short'
    md5 = hashlib.md5(name.encode()).digest()
    if rc4(RC4_KEY, buf[0:8]) != md5[0:8]:
        return False, 'RC4 mismatch'
    rest = buf[8:]
    if not rest.isdigit():
        return False, 'non-digit tail'
    x = int(rest)
    target = int.from_bytes(md5[8:16], 'big')
    if pow(x, E, N) != target:
        return False, 'RSA mismatch'
    return True, 'OK'

if __name__ == '__main__':
    for name in ['test', 'KCTF', 'blowfish', 'kanxue', 'CCG']:
        serial, target = keygen(name)
        if serial is None:
            print(f'{name}: target 0x{target:x} >= n，该名字无解')
            continue
        ok, msg = verify(name, serial)
        print(f'{name:10} -> {serial:40} verify={ok} ({msg})')
