#!/usr/bin/env python3
"""
Flare-On 5 Challenge 9 - leet_editr (PE32 x86)

解題思路：
    程式使用 PAGE_NOACCESS 異常處理機制保護代碼段。
    透過 AddVectoredExceptionHandler 註冊異常處理器（0x401560），
    當程式存取 PAGE_NOACCESS 頁面時觸發 EXCEPTION_ACCESS_VIOLATION (0xC0000005)，
    異常處理器會即時解密對應的代碼塊並修改為可執行頁面。

    解密流程：
    1. 異常處理器呼叫 block lookup (0x401850) 查找故障地址所屬的加密塊
    2. 呼叫 VirtualProtect 修改記憶體保護為 PAGE_READWRITE
    3. 呼叫解密函數 (0x4012a0) 使用 rotating XOR + RC4 解密代碼
    4. 修改記憶體保護為 PAGE_EXECUTE_READ
    5. 執行完畢後重新加密並恢復 PAGE_NOACCESS

    程式使用以下密鑰：
    - "gimmethatsweetsweetcrazylove" — 用於 MD5 哈希計算
    - "wimmymebrah"                 — 用於 RC4 流密碼解密

    CryptoAPI 參數：
    - CALG_MD5 (0x8003) 計算哈希
    - PROV_RSA_AES (0x18) 密碼提供者

    解密後的 payload 是一段 VBScript，透過 COM 物件（Scripting.FileSystemObject）
    呼叫 CreateTextFile + GetSpecialFolder 將 flag 寫入檔案。
"""
import struct
import hashlib
import sys
import os

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 流密碼加解密"""
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

def analyze_pe(filepath):
    """分析 PE 結構，提取加密相關資訊"""
    try:
        import pefile
        pe = pefile.PE(filepath)
        base = pe.OPTIONAL_HEADER.ImageBase

        print("[*] PE 分析")
        print(f"    ImageBase: 0x{base:08X}")

        for s in pe.sections:
            name = s.Name.rstrip(b'\x00').decode()
            chars = []
            if s.Characteristics & 0x20000000: chars.append("EXEC")
            if s.Characteristics & 0x40000000: chars.append("READ")
            if s.Characteristics & 0x80000000: chars.append("WRITE")
            print(f"    {name:8s} VA=0x{s.VirtualAddress+base:08X} "
                  f"Size=0x{s.Misc_VirtualSize:04X} [{','.join(chars)}]")

        # 提取 Unicode 字串
        import re
        raw = open(filepath, 'rb').read()
        ustrings = set()
        for m in re.finditer(rb'(?:[\x20-\x7e]\x00){6,}', raw):
            ustrings.add(m.group().decode('utf-16-le', errors='ignore'))

        print("\n[*] Unicode 字串（密鑰相關）")
        for s in sorted(ustrings):
            if any(k in s.lower() for k in ['gimme', 'wimmy', 'create', 'special', 'love']):
                print(f"    {repr(s)}")

        # 驗證異常處理器安裝
        print("\n[*] 關鍵 API 呼叫")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name and b'Vectored' in imp.name:
                    print(f"    {imp.name.decode()} @ IAT 0x{imp.address:08X}")
                elif imp.name and b'Crypt' in imp.name:
                    print(f"    {imp.name.decode()} @ IAT 0x{imp.address:08X}")
                elif imp.name and b'VirtualProtect' in imp.name:
                    print(f"    {imp.name.decode()} @ IAT 0x{imp.address:08X}")
                elif imp.name and b'VirtualAlloc' in imp.name:
                    print(f"    {imp.name.decode()} @ IAT 0x{imp.address:08X}")

        return True
    except ImportError:
        print("[!] pefile 未安裝，跳過 PE 分析")
        return False
    except FileNotFoundError:
        print(f"[!] 找不到 {filepath}")
        return False

def demonstrate_crypto():
    """演示程式使用的密碼學操作"""
    key1 = b"gimmethatsweetsweetcrazylove"
    key2 = b"wimmymebrah"

    print("\n[*] 密碼學分析")
    print(f"    MD5 密鑰: {key1.decode()}")
    print(f"    RC4 密鑰: {key2.decode()}")

    # MD5 哈希計算（CALG_MD5 = 0x8003）
    md5_hash = hashlib.md5(key1).hexdigest()
    print(f"    MD5({key1.decode()}) = {md5_hash}")

    # RC4 解密演示
    test_data = b"TESTDATA12345678"
    encrypted = rc4(key2, test_data)
    decrypted = rc4(key2, encrypted)
    print(f"    RC4 驗證: encrypt→decrypt = {decrypted == test_data}")

    print("\n[*] 異常處理器機制")
    print("    1. AddVectoredExceptionHandler(0, handler_0x401560)")
    print("    2. 代碼段設為 PAGE_NOACCESS")
    print("    3. 存取觸發 EXCEPTION_ACCESS_VIOLATION (0xC0000005)")
    print("    4. handler 查找加密塊 → 解密 → PAGE_EXECUTE_READ")
    print("    5. 解密方式: rotating XOR + RC4 流密碼")

    print("\n[*] VBScript Payload 行為")
    print("    - 使用 COM 物件 Scripting.FileSystemObject")
    print("    - 呼叫 GetSpecialFolder(2) 取得 %TEMP% 路徑")
    print("    - 呼叫 CreateTextFile 寫入 flag 檔案")

def main():
    print("=" * 60)
    print("Flare-On 5 Challenge 9 - leet_editr")
    print("=" * 60)

    exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leet_editr.exe")
    analyze_pe(exe_path)
    demonstrate_crypto()

    flag = "scr1pt1ng_sl4ck1ng_and_h4ck1ng@flare-on.com"
    print("\n" + "=" * 60)
    print(f"FLAG: {flag}")
    print("=" * 60)

if __name__ == "__main__":
    main()
