#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FlareOn 4 (2017) Challenge 06 - payload.dll 解题脚本

分析:
  payload.dll 是一个 64 位 Windows DLL，导出一个名为 "EntryPoint" 的函数。
  DLL 加载时 (DllMain DLL_PROCESS_ATTACH)，会根据系统时间 (year + month) % 26
  选择一个索引，然后:
    1. 使用 MSVC 的 srand/rand 以 (0x52414E44 + index) 为种子生成随机字节流
    2. 将 .text 节区偏移 index * 0x200 处的 0x200 字节数据与随机流 XOR 解密
       解密后得到导出函数名（如 "filingmeteorsgeminately"）
    3. 修改 DLL 的导出表，将原始 "EntryPoint" 替换为新的函数名

  当用 rundll32 调用正确的导出函数名时:
    4. 使用 RC4 算法，以函数名为密钥，解密对应的代码块
    5. 解密后的代码通过 MessageBoxA 显示一个 flag 字符

  共有 26 个不同的函数名/代码块，每个对应 flag 的一个字符。

Flag: wuuut-exp0rts@flare-on.com
"""

import pefile
import struct
import re
import os

DLL_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "payload.dll")


# ============================================================
# MSVC CRT rand/srand 实现
# ============================================================
class MSVCRand:
    """模拟 MSVC 的 srand/rand"""
    def __init__(self, seed):
        self.state = seed & 0xFFFFFFFF

    def rand(self):
        self.state = (self.state * 0x343FD + 0x269EC3) & 0xFFFFFFFF
        return (self.state >> 16) & 0x7FFF


# ============================================================
# RC4 加密/解密
# ============================================================
def rc4_decrypt(key: bytes, data: bytes) -> bytes:
    """RC4 解密（与加密相同）"""
    # KSA (Key Scheduling Algorithm)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]

    # PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        output.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(output)


def solve():
    pe = pefile.PE(DLL_PATH)
    imagebase = pe.OPTIONAL_HEADER.ImageBase

    print("=" * 60)
    print("FlareOn 4 Challenge 06 - payload.dll")
    print("=" * 60)

    # --------------------------------------------------------
    # 第一步：从 .text 节区解密 26 个导出函数名
    # 加密数据位于 RVA 0x1000 (即 .text 节区起始)
    # 每个块 0x200 字节，共 26 块
    # 解密方式：srand(0x52414E44 + index), 然后 rand() & 0xFF 逐字节 XOR
    # --------------------------------------------------------
    print("\n[1] 解密导出函数名...")
    text_data = pe.get_data(0x1000, 26 * 0x200)
    func_names = []

    for idx in range(26):
        seed = 0x52414E44 + idx  # "RAND" + index
        rng = MSVCRand(seed)

        offset = idx * 0x200
        block = bytearray(text_data[offset:offset + 0x200])

        # XOR 解密
        for i in range(0x200):
            block[i] ^= rng.rand() & 0xFF

        # 提取以 null 结尾的函数名字符串
        # 解密后的块包含: [PE结构数据] [DLL名] [函数名]
        decoded = block.decode("ascii", errors="replace")
        # 寻找 ".dll" 后面的函数名
        dll_end = decoded.find(".dll")
        if dll_end >= 0:
            name_start = dll_end + 5  # 跳过 ".dll" 和空格/null
            while name_start < len(decoded) and decoded[name_start] == '\x00':
                name_start += 1
            end = decoded.find('\x00', name_start)
            if end > name_start:
                name = decoded[name_start:end]
            else:
                name = decoded[name_start:]
        else:
            # 备用方案：取最长的可打印字符串
            strings = re.findall(r'[a-z]{10,}', decoded)
            name = strings[-1] if strings else "unknown"

        func_names.append(name)
        print(f"  [{idx:2d}] {name}")

    # --------------------------------------------------------
    # 第二步：读取函数指针表
    # 表位于 .data 节区 RVA 0x198E0，包含 27 个 QWORD
    # 前 26 个是加密代码块的地址，第 27 个是分发函数 (0x5A50)
    # --------------------------------------------------------
    print("\n[2] 读取代码块地址表...")
    data_section = pe.get_data(0x19000, 0xA00)
    tab_offset = 0x8E0  # 0x198E0 - 0x19000
    func_addrs = []
    for i in range(27):
        val = struct.unpack('<Q', data_section[tab_offset + i * 8:tab_offset + (i + 1) * 8])[0]
        func_addrs.append(val)

    # --------------------------------------------------------
    # 第三步：RC4 解密每个代码块并提取 flag 字符
    # 密钥 = 函数名
    # 解密后的代码会构建字符串 "key[N] = 0xHH;"
    # 其中 HH 就是 flag 字符的十六进制值
    # --------------------------------------------------------
    print("\n[3] RC4 解密代码块并提取 flag 字符...")
    flag = ""

    for idx in range(26):
        addr = func_addrs[idx]
        next_addr = func_addrs[idx + 1]
        rva = addr - imagebase
        size = next_addr - addr

        # 读取加密的代码块
        encrypted = pe.get_data(rva, size)

        # RC4 解密，密钥为对应的导出函数名
        key = func_names[idx].encode("ascii")
        decrypted = rc4_decrypt(key, encrypted)

        # 从解密后的 x86-64 代码中提取 "mov byte ptr [rsp+offset], imm8" 指令
        # 操作码格式: C6 44 24 XX YY (mov byte ptr [rsp+XX], YY)
        bytes_at_offsets = {}
        i = 0
        while i < len(decrypted) - 4:
            if decrypted[i] == 0xC6 and decrypted[i + 1] == 0x44 and decrypted[i + 2] == 0x24:
                off = decrypted[i + 3]
                val = decrypted[i + 4]
                bytes_at_offsets[off] = val
                i += 5
            else:
                i += 1

        # 重建 "key[N] = 0xHH;" 字符串 (存储在 [rsp+0x30] 到 [rsp+0x3F])
        key_str = ""
        for off in sorted(bytes_at_offsets.keys()):
            if 0x30 <= off <= 0x3F:
                if bytes_at_offsets[off] == 0:
                    break
                key_str += chr(bytes_at_offsets[off])

        # 解析十六进制值得到 flag 字符
        m = re.search(r"0x([0-9a-fA-F]+)", key_str)
        if m:
            char_val = int(m.group(1), 16)
            char = chr(char_val)
            flag += char
            print(f"  [{idx:2d}] {key_str} -> '{char}'")
        else:
            print(f"  [{idx:2d}] 解析失败: {key_str}")

    # --------------------------------------------------------
    # 输出结果
    # --------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"FLAG: {flag}")
    print("=" * 60)

    # 验证
    expected = "wuuut-exp0rts@flare-on.com"
    if flag == expected:
        print("验证通过!")
    else:
        print(f"警告: 预期 flag 为 {expected}")

    return flag


if __name__ == "__main__":
    solve()
