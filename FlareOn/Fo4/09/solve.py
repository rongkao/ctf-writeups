# -*- coding: utf-8 -*-
"""
FlareOn 4 (2017) - Challenge 09: remorse.ino.hex
Arduino UNO (ATmega328P) 固件逆向题

解密算法: dec[i] = ((enc[i] ^ key) + i) & 0xFF
暴力枚举 key (0-255)，正确的 key 使位置 10 产生 '@'

Flag: no_r3m0rs3@flare-on.com
"""

import os

def parse_intel_hex(hex_path):
    """解析 Intel HEX 文件"""
    with open(hex_path, 'r') as f:
        lines = f.readlines()
    binary = bytearray()
    for line in lines:
        line = line.strip()
        if not line.startswith(':'):
            continue
        byte_count = int(line[1:3], 16)
        address = int(line[3:7], 16)
        record_type = int(line[7:9], 16)
        if record_type == 0:
            data = bytes.fromhex(line[9:9+byte_count*2])
            while len(binary) < address + len(data):
                binary.append(0)
            binary[address:address+len(data)] = data
        elif record_type == 1:
            break
    return bytes(binary)

def solve():
    hex_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'remorse.ino.hex')

    if os.path.exists(hex_path):
        firmware = parse_intel_hex(hex_path)
        print(f"[*] 固件大小: {len(firmware)} 字节")

    # 加密的 flag 字节
    encrypted = [0xB5, 0xB5, 0x86, 0xB4, 0xF4, 0xB3, 0xF1, 0xB0,
                 0xB0, 0xF1, 0xED, 0x80, 0xBB, 0x8F, 0xBF, 0x8D,
                 0xC6, 0x85, 0x87, 0xC0, 0x94, 0x81, 0x8C]

    # 暴力枚举 XOR 密钥
    for key in range(0x100):
        out = []
        valid = True
        for i, b in enumerate(encrypted):
            c = ((b ^ key) + i) & 0xFF
            if c < 0x20 or c > 0x7e:
                valid = False
                break
            out.append(chr(c))
        if valid and len(out) == len(encrypted) and out[10] == '@':
            flag = ''.join(out)
            print(f"[+] XOR key: 0x{key:02x} ({key})")
            print(f"[+] Flag: {flag}")
            return flag

    return None

if __name__ == '__main__':
    solve()
