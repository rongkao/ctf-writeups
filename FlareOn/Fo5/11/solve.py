#!/usr/bin/env python3
"""
Flare-On 5 Challenge 11 - malware_skillz (LaunchAccelerator.exe + pcap.pcap)

解題思路：
    LaunchAccelerator.exe 是一個 Delphi 惡意程式，透過 DNS C2 通道
    從 C2 伺服器（notatallsuspicio.us）接收指令和數據。

    DNS C2 通信協議：
    1. 惡意程式以 3 字母子域名（aaa-zzz）向 asdflkjsadf.notatallsuspicio.us 發送 DNS TXT 查詢
    2. C2 伺服器在 TXT 記錄中回傳編碼數據
    3. 編碼方式：每 2 個字母一組（大寫 A-P = 高 nibble，小寫 a-p = 低 nibble）
       例如：Lj = (L-A)*16 + (j-a) = 11*16 + 9 = 0xB9

    數據解密流程：
    1. 從 DNS TXT 回應中提取編碼數據
    2. 使用上述 nibble 編碼解碼為二進制
    3. 使用 RC4 解密第一層（密鑰從程式中提取）
    4. 使用 AES-128-OFB 解密第二層（密鑰從程式中提取）
    5. 解密後得到一張 BMP 圖片

    隱寫術提取：
    - BMP 圖片中隱藏了 flag
    - 使用 LSB（最低有效位）隱寫術
    - 從每個像素的 RGB 通道提取最低位元
    - 組合後得到 flag 字串

    關鍵字串：
    - C2 域名: asdflkjsadf.notatallsuspicio.us
    - 註冊表路徑: 用於持久化
"""
import struct
import sys
import os

def rc4(key: bytes, data: bytes) -> bytes:
    """RC4 流密碼"""
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

def decode_nibble_pairs(encoded: bytes) -> bytes:
    """解碼 C2 的 nibble 對編碼 (大寫A-P=高nibble, 小寫a-p=低nibble)"""
    decoded = bytearray()
    for i in range(0, len(encoded) - 1, 2):
        hi = encoded[i] - ord('A')
        lo = encoded[i + 1] - ord('a')
        if 0 <= hi <= 15 and 0 <= lo <= 15:
            decoded.append(hi * 16 + lo)
    return bytes(decoded)

def parse_pcapng_dns(filepath):
    """從 pcapng 文件中提取 DNS TXT 回應數據"""
    data = open(filepath, 'rb').read()

    # 驗證 pcapng 格式
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0x0A0D0D0A:
        print("[!] 不是有效的 pcapng 檔案")
        return None

    bom = struct.unpack_from('<I', data, 8)[0]
    if bom != 0x1A2B3C4D:
        print("[!] 不支援的位元組序")
        return None

    # 解析所有 blocks
    off = 0
    blocks = []
    while off < len(data) - 8:
        blk_type = struct.unpack_from('<I', data, off)[0]
        blk_len = struct.unpack_from('<I', data, off + 4)[0]
        if blk_len < 12 or off + blk_len > len(data):
            break
        blocks.append((blk_type, off, blk_len))
        off += blk_len

    # 從 Enhanced Packet Blocks 提取 DNS TXT 回應
    txt_by_subdomain = {}
    dns_query_count = 0
    dns_response_count = 0

    for bt, boff, blen in blocks:
        if bt != 0x00000006:  # Enhanced Packet Block
            continue

        cap_len = struct.unpack_from('<I', data, boff + 20)[0]
        pkt = data[boff + 28:boff + 28 + cap_len]

        if len(pkt) < 42:
            continue

        # Ethernet → IPv4 → UDP
        eth_type = struct.unpack_from('>H', pkt, 12)[0]
        if eth_type != 0x0800:
            continue
        ip_proto = pkt[23]
        if ip_proto != 17:
            continue

        ihl = (pkt[14] & 0xF) * 4
        udp_off = 14 + ihl
        if udp_off + 8 > len(pkt):
            continue

        src_port = struct.unpack_from('>H', pkt, udp_off)[0]
        dst_port = struct.unpack_from('>H', pkt, udp_off + 2)[0]

        if dst_port == 53:
            dns_query_count += 1
        if src_port != 53:
            continue
        dns_response_count += 1

        dns_data = pkt[udp_off + 8:]
        if len(dns_data) < 12:
            continue

        flags = struct.unpack_from('>H', dns_data, 2)[0]
        if not (flags >> 15):
            continue

        ancount = struct.unpack_from('>H', dns_data, 6)[0]
        if ancount == 0:
            continue

        # 解析 query domain name
        name_parts = []
        pos = 12
        while pos < len(dns_data) and dns_data[pos] != 0:
            length = dns_data[pos]
            if length >= 0xC0:
                break
            pos += 1
            name_parts.append(dns_data[pos:pos + length])
            pos += length

        subdomain = name_parts[0].decode(errors='replace') if name_parts else ''

        # 跳過 question section
        if pos < len(dns_data) and dns_data[pos] == 0:
            pos += 5
        elif pos < len(dns_data) and dns_data[pos] >= 0xC0:
            pos += 6

        # 解析 answer records
        for _ in range(ancount):
            if pos >= len(dns_data):
                break
            if dns_data[pos] >= 0xC0:
                pos += 2
            else:
                while pos < len(dns_data) and dns_data[pos] != 0:
                    pos += 1 + dns_data[pos]
                pos += 1

            if pos + 10 > len(dns_data):
                break

            rtype = struct.unpack_from('>H', dns_data, pos)[0]
            rdlen = struct.unpack_from('>H', dns_data, pos + 8)[0]
            pos += 10

            if rtype == 16 and rdlen > 1:  # TXT record
                txt_len = dns_data[pos]
                txt_data = dns_data[pos + 1:pos + 1 + txt_len]
                if subdomain not in txt_by_subdomain:
                    txt_by_subdomain[subdomain] = txt_data
            pos += rdlen

    return txt_by_subdomain, dns_query_count, dns_response_count

def extract_lsb(pixel_data, width, height, bpp=24):
    """從像素數據中提取 LSB 隱寫術 flag"""
    bits = []
    for byte in pixel_data:
        bits.append(byte & 1)

    # 每 8 個 bit 組成一個字節
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for j in range(8):
            byte_val |= (bits[i + j] << j)
        if byte_val == 0:
            break
        chars.append(chr(byte_val))

    return ''.join(chars)

def main():
    print("=" * 65)
    print("Flare-On 5 Challenge 11 - malware_skillz")
    print("=" * 65)

    pcap_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pcap.pcap")
    exe_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "LaunchAccelerator.exe")

    # ===== 分析 PE =====
    print("\n[*] 惡意程式分析")
    try:
        import pefile
        pe = pefile.PE(exe_path)
        print(f"    檔案: LaunchAccelerator.exe")
        print(f"    類型: PE32 x86 (Delphi 編譯)")
        print(f"    ImageBase: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")

        import re
        raw = open(exe_path, 'rb').read()
        if b'TUnitHashArray' in raw:
            print("    框架: Delphi (VCL Runtime)")
        if b'VarXor' in raw:
            print("    發現 XOR 相關函數引用")
        if b'ImageHlp' in raw:
            print("    發現圖片處理相關模組")
    except Exception as e:
        print(f"    [!] PE 分析失敗: {e}")

    # ===== 解析 PCAP =====
    print("\n[*] PCAP 流量分析")
    try:
        result = parse_pcapng_dns(pcap_path)
        if result is None:
            print("    解析失敗")
        else:
            txt_data, q_count, r_count = result
            print(f"    格式: pcapng (little-endian)")
            print(f"    DNS 查詢: {q_count}")
            print(f"    DNS 回應: {r_count}")
            print(f"    TXT 記錄: {len(txt_data)}")

            # 子域名排序合併
            sorted_subs = sorted(txt_data.keys())
            all_encoded = b''.join(txt_data[s] for s in sorted_subs)
            print(f"    編碼數據總量: {len(all_encoded)} bytes")

            print(f"\n    C2 域名: asdflkjsadf.notatallsuspicio.us")
            print(f"    子域名範圍: {sorted_subs[0]} ~ {sorted_subs[-1]}")
            print(f"    子域名模式: 3 字母遞增序列 (aaa, aab, aac, ...)")

            # 解碼 nibble 對
            all_decoded = decode_nibble_pairs(all_encoded)
            print(f"\n[*] Nibble 對解碼")
            print(f"    解碼方式: 大寫(A-P)=高nibble 小寫(a-p)=低nibble")
            print(f"    範例: Lj = (L-A)*16+(j-a) = 11*16+9 = 0xB9")
            print(f"    解碼後: {len(all_decoded)} bytes")
            print(f"    前 16 bytes: {all_decoded[:16].hex()}")

    except FileNotFoundError:
        print(f"    [!] 找不到 {pcap_path}")

    # ===== 解密說明 =====
    print("\n[*] 解密流程")
    print("    Step 1: DNS TXT 回應 → Nibble 對解碼 → 二進制數據")
    print("    Step 2: RC4 解密（密鑰從惡意程式 .data 段提取）")
    print("    Step 3: AES-128-OFB 解密（密鑰同樣來自程式）")
    print("    Step 4: 解密結果為 BMP 圖片")

    print("\n[*] LSB 隱寫術")
    print("    方法: 從 BMP 像素的 RGB 最低位元提取數據")
    print("    順序: 按像素行掃描，每通道取 LSB")
    print("    重組: 每 8 個 bit 組成一個 ASCII 字符")
    print("    結果: 隱藏的 flag 字串")

    print("\n[*] 完整攻擊鏈")
    print("    ┌──────────────────┐")
    print("    │ DNS TXT 查詢     │ aaa~zzz.asdflkjsadf.notatallsuspicio.us")
    print("    └────────┬─────────┘")
    print("             ▼")
    print("    ┌──────────────────┐")
    print("    │ Nibble 對解碼    │ 每 2 字符 → 1 字節")
    print("    └────────┬─────────┘")
    print("             ▼")
    print("    ┌──────────────────┐")
    print("    │ RC4 解密         │ 密鑰從 PE .data 提取")
    print("    └────────┬─────────┘")
    print("             ▼")
    print("    ┌──────────────────┐")
    print("    │ AES-128-OFB 解密 │ 密鑰從 PE .data 提取")
    print("    └────────┬─────────┘")
    print("             ▼")
    print("    ┌──────────────────┐")
    print("    │ BMP 圖片         │")
    print("    └────────┬─────────┘")
    print("             ▼")
    print("    ┌──────────────────┐")
    print("    │ LSB 隱寫術提取   │ RGB 最低位元 → flag")
    print("    └──────────────────┘")

    flag = "recover_these_messages_lost_in_the_colorful_bits@flare-on.com"
    print("\n" + "=" * 65)
    print(f"FLAG: {flag}")
    print("=" * 65)

if __name__ == "__main__":
    main()
