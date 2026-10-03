# -*- coding: utf-8 -*-
"""
FlareOn 4 (2017) Challenge 07 - zsud.exe 解题脚本

挑战概述:
=========
zsud.exe 是一个原生 Win32 PE 可执行文件，使用 CLR Hosting 技术加载内嵌的 .NET DLL
(flareon.dll)。该 DLL 使用 AES 解密一个 PowerShell 脚本，实现了一个类似 Zork 的
文字冒险游戏（MUD - Multi-User Dungeon）。

"zsud" 的名字暗示了这是一个 "Single-User Dungeon" 类型的游戏。

技术分析:
=========
1. 主程序 (zsud.exe):
   - 原生 Win32 PE32，使用 Visual C++ 编写
   - 入口点: 0x40F240
   - 使用 CLR Hosting 手动启动 .NET 运行时
   - 内嵌一个 .NET DLL (flareon.dll) 在文件偏移 0x570B0 处

2. 内嵌 DLL (flareon.dll):
   - .NET 程序集，CLR v4.0.30319
   - 命名空间: four.flareon
   - 关键方法:
     * Decrypt2(cipherText) - AES 解密函数
     * Smth() - 解密并通过 PowerShell 执行游戏脚本

3. 加密方案:
   - 算法: RijndaelManaged (AES-256-CBC)
   - 密钥: "soooooo_sorry_zis_is_not_ze_flag" (32字节)
   - IV: 16个零字节
   - 输入: Base64 编码的密文
   - 解密后: PowerShell 游戏脚本

4. 游戏机制:
   - 游戏使用 hook 过的 rand()/srand() 函数
   - srand(42) 设置全局变量为1，后续 rand() 从硬编码数组读取方向值
   - 方向映射: {0:"n", 1:"s", 2:"e", 3:"w", 4:"u", 5:"d"}
   - 正确路径: 从内存地址 0x1389CB8 的硬编码数组中读取，共53步

5. 解题路径:
   - 首先获取钥匙 (get key)
   - 按照 RIGHT_PATH 正确导航迷宫
   - 完成路径后，钥匙文本变为包含十六进制 "findkevinmandia" 的提示
   - 最后: n, e, n, n, n, drop key, get helmet, wear helmet, say kevin hello
"""

import struct
import base64
import os
import re


def extract_embedded_dll(exe_path, output_path=None):
    """从 zsud.exe 中提取内嵌的 .NET DLL (flareon.dll)"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    # 内嵌 PE 在文件偏移 0x570B0 处
    dll_offset = 0x570B0
    dll_size = 0x1200  # 4608 字节

    dll_data = data[dll_offset:dll_offset + dll_size]

    # 验证 MZ 签名
    assert dll_data[:2] == b'MZ', "未找到 MZ 签名！"

    # 验证 PE 签名
    pe_offset = struct.unpack_from('<I', dll_data, 0x3C)[0]
    assert dll_data[pe_offset:pe_offset+4] == b'PE\x00\x00', "未找到 PE 签名！"

    if output_path:
        with open(output_path, 'wb') as f:
            f.write(dll_data)
        print(f"[+] 已提取内嵌 DLL 到: {output_path}")
        print(f"    大小: {len(dll_data)} 字节")
        print(f"    偏移: 0x{dll_offset:X}")

    return dll_data


def analyze_dll_metadata(dll_data):
    """分析 .NET DLL 的元数据"""
    # 查找 BSJB 签名（.NET 元数据标记）
    bsjb_idx = dll_data.find(b'BSJB')
    if bsjb_idx == -1:
        print("[-] 未找到 .NET 元数据")
        return

    print(f"\n[+] .NET 元数据位于偏移 0x{bsjb_idx:X}")

    # 读取运行时版本
    ver_len = struct.unpack_from('<I', dll_data, bsjb_idx + 12)[0]
    version = dll_data[bsjb_idx+16:bsjb_idx+16+ver_len].decode('utf-8', errors='replace').rstrip('\x00')
    print(f"    运行时版本: {version}")

    # 提取所有可打印字符串
    strings = re.findall(rb'[\x20-\x7e]{6,}', dll_data)
    print(f"\n[+] DLL 中的关键字符串:")
    for s in strings:
        decoded = s.decode('ascii')
        if any(kw in decoded for kw in ['Decrypt', 'Smth', 'Key', 'IV', 'Base64',
                                         'PowerShell', 'sorry', 'flag', 'flareon',
                                         'Rijndael', 'Crypto']):
            print(f"    {decoded}")

    # 查找 Unicode 字符串（.NET 用户字符串）
    unicode_strings = re.findall(rb'(?:[\x20-\x7e]\x00){4,}', dll_data)
    for s in unicode_strings:
        decoded = s.decode('utf-16-le', errors='replace')
        if len(decoded) > 5:
            print(f"    [Unicode] {decoded}")


def decode_kevin_hex():
    """
    解码 Kevin 回复的十六进制消息得到 flag

    游戏完成后，Kevin 的回复包含十六进制编码的 flag。
    """
    kevin_hex = (
        "6D 75 64 64 31 6E 67 5F"  # mudd1ng_
        "62 79 5F 79 30 75 72 35"  # by_y0ur5
        "33 6C 70 68 40 66 6C 61"  # 3lph@fla
        "72 65 2D 6F 6E 2E 63 6F"  # re-on.co
        "6D"                        # m
    )

    hex_clean = kevin_hex.replace(' ', '').replace('\n', '')
    flag = bytes.fromhex(hex_clean).decode('ascii')
    return flag


def get_right_path():
    """
    获取迷宫的正确路径

    游戏中的 rand() 函数被 hook，从硬编码数组中返回预定义的方向值。
    方向映射: {0:"n", 1:"s", 2:"e", 3:"w", 4:"u", 5:"d"}
    数组共 0x35 (53) 个条目，循环使用。
    """
    direction_map = {0: "n", 1: "s", 2: "e", 3: "w", 4: "u", 5: "d"}

    # 从二进制中提取的硬编码方向数组 (RIGHT_PATH)
    right_path_values = [
        3, 0, 0, 2, 2, 1, 1, 1,  # w n n e e s s s
        0, 2, 3, 0, 2, 2, 3, 3,  # n e w n e e w w
        3, 5, 4, 0, 5, 4, 0, 5,  # w d u n d u n d
        4, 0, 1, 4, 0, 2, 4, 0,  # u n s u n e u n
        1, 2, 3, 5, 4, 0, 1, 2,  # s e w d u n s e
        3, 1, 2, 3, 1, 2, 3, 1,  # w s e w s e w s
        2, 3, 5, 4, 0,            # e w d u n
    ]

    path = [direction_map[v] for v in right_path_values]
    return path


def get_game_solution():
    """获取完整的游戏解题步骤"""
    # 阶段1: 从桌子抽屉获取钥匙
    setup_commands = [
        "look",           # 查看当前房间
        "open drawer",    # 打开桌子抽屉
        "get key",        # 获取钥匙（触发 srand(42)）
    ]

    # 阶段2: 按照 RIGHT_PATH 导航迷宫
    maze_path = get_right_path()

    # 阶段3: 与 Kevin 交互获取 flag
    final_commands = [
        "n",               # 向北移动
        "e",               # 向东移动
        "n",               # 向北移动
        "n",               # 向北移动
        "n",               # 向北移动
        "drop key",        # 放下钥匙
        "get helmet",      # 获取头盔
        "wear helmet",     # 戴上头盔
        "say kevin hello", # 对 Kevin 说 hello -> 触发 flag 输出
    ]

    return setup_commands, maze_path, final_commands


def analyze_binary(exe_path):
    """分析 zsud.exe 的基本信息"""
    try:
        import pefile
        pe = pefile.PE(exe_path)

        print("=" * 60)
        print("FlareOn 4 Challenge 07 - zsud.exe 分析")
        print("=" * 60)

        machine = 'x86 (32位)' if pe.FILE_HEADER.Machine == 0x14C else 'x64 (64位)'
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase

        print(f"\n[+] PE 基本信息:")
        print(f"    架构: {machine}")
        print(f"    入口点: 0x{ep:X}")
        print(f"    映像基址: 0x{pe.OPTIONAL_HEADER.ImageBase:X}")
        print(f"    节数: {pe.FILE_HEADER.NumberOfSections}")

        print(f"\n[+] 节表:")
        for s in pe.sections:
            name = s.Name.decode('utf-8', errors='replace').strip('\x00')
            print(f"    {name:8s}  VA=0x{s.VirtualAddress:08X}  "
                  f"VSize=0x{s.Misc_VirtualSize:08X}  "
                  f"RawSize=0x{s.SizeOfRawData:08X}")

        print(f"\n[+] 关键导入:")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                key_funcs = []
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode()
                        if any(kw in name for kw in ['LoadLibrary', 'GetProcAddress',
                                                      'VirtualProtect', 'CreateFile',
                                                      'MessageBox', 'Internet']):
                            key_funcs.append(name)
                if key_funcs:
                    print(f"    {dll_name}: {', '.join(key_funcs)}")

        pe.close()
    except ImportError:
        print("[-] pefile 未安装，跳过 PE 分析")


def find_interesting_strings(exe_path):
    """搜索二进制中的有趣字符串"""
    with open(exe_path, 'rb') as f:
        data = f.read()

    print(f"\n[+] 关键字符串:")

    keywords = ['whiskey', 'flareon', 'Decrypt', 'bitsigd', 'FAIL',
                'msi.dll', 'InitializeEx', 'sorry', 'wininet',
                'InternetOpen', 'PowerShell', 'mscoree']

    strings = re.findall(rb'[\x20-\x7e]{6,}', data)
    seen = set()
    for s in strings:
        decoded = s.decode('ascii')
        if any(kw.lower() in decoded.lower() for kw in keywords):
            if decoded not in seen:
                seen.add(decoded)
                offset = data.find(s)
                print(f"    0x{offset:06X}: {decoded}")


def main():
    exe_path = r'D:\codes\ctf\FlareOn\Fo4\07\zsud.exe'

    if not os.path.exists(exe_path):
        print(f"[-] 文件不存在: {exe_path}")
        return

    # 1. 分析二进制基本信息
    analyze_binary(exe_path)

    # 2. 搜索有趣的字符串
    find_interesting_strings(exe_path)

    # 3. 提取内嵌 DLL
    dll_output = os.path.join(os.path.dirname(exe_path), 'flareon_extracted.dll')
    dll_data = extract_embedded_dll(exe_path, dll_output)

    # 4. 分析 DLL 元数据
    analyze_dll_metadata(dll_data)

    # 5. 显示游戏解题路径
    setup, maze, final = get_game_solution()

    print(f"\n{'=' * 60}")
    print("游戏解题步骤")
    print(f"{'=' * 60}")

    print(f"\n[阶段1] 初始设置:")
    for cmd in setup:
        print(f"    > {cmd}")

    print(f"\n[阶段2] 迷宫导航 (RIGHT_PATH, 共{len(maze)}步):")
    path_str = ', '.join(maze)
    print(f"    > {path_str}")
    print(f"    每次正确移动: 'The key emanates some warmth...'")
    print(f"    错误移动会重置进度: 'Hmm...'")

    print(f"\n[阶段3] 最终交互:")
    for cmd in final:
        print(f"    > {cmd}")

    # 6. 解码 flag
    print(f"\n{'=' * 60}")
    print("Flag 推导")
    print(f"{'=' * 60}")

    print(f"\n[+] 加密方案:")
    print(f"    算法: RijndaelManaged (AES-256-CBC)")
    print(f"    密钥: 'soooooo_sorry_zis_is_not_ze_flag'")
    print(f"    IV:   16 个零字节 (0x00 * 16)")

    print(f"\n[+] 迷宫完成后钥匙文本包含十六进制提示:")
    hint_hex = "66696e646b6576696e6d616e646961"
    hint_text = bytes.fromhex(hint_hex).decode('ascii')
    print(f"    十六进制: {hint_hex}")
    print(f"    解码:     {hint_text}")

    print(f"\n[+] Kevin 的十六进制回复:")
    kevin_hex = "6D 75 64 64 31 6E 67 5F 62 79 5F 79 30 75 72 35 33 6C 70 68 40 66 6C 61 72 65 2D 6F 6E 2E 63 6F 6D"
    print(f"    {kevin_hex}")

    flag = decode_kevin_hex()

    print(f"\n{'=' * 60}")
    print(f"FLAG: {flag}")
    print(f"{'=' * 60}")

    return flag


if __name__ == '__main__':
    flag = main()
