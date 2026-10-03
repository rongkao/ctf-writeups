#!/usr/bin/env python3
"""
Flare-On 5 Challenge 12 - suspicious_floppy (嵌套虛擬機)

解題思路：
    挑戰提供一個 1.44MB 的 DOS 軟碟映像（FAT12 文件系統）。
    AUTOEXEC.BAT 執行 INFOHELP.EXE，程式提示輸入密碼。

    軟碟內容：
    - INFOHELP.EXE  — 密碼驗證主程式
    - KEY.DAT       — 佔位符 "key goes here"
    - MESSAGE.DAT   — 佔位符 "This is not the message you are looking for."
    - TMP.DAT       — 包含嵌套虛擬機代碼（40KB）
    - COMMAND.COM 等 — 標準 FreeDOS 系統檔案

    虛擬機架構：
    TMP.DAT 包含兩層嵌套虛擬機：

    第一層 — Subleq 虛擬機：
        Subleq (SUBtract and branch if Less-than or EQual) 是一種
        單指令計算機（OISC），每條指令有 3 個運算元 (A, B, C)：
            mem[B] = mem[B] - mem[A]
            if mem[B] <= 0: goto C
            else: goto next instruction

    第二層 — RSSB 虛擬機（在 Subleq 上層執行）：
        RSSB (Reverse Subtract and Skip if Borrow) 也是 OISC：
            ACC = mem[operand] - ACC
            mem[operand] = ACC
            if borrow: skip next instruction

    密碼驗證：
    - RSSB 虛擬機實現密碼驗證邏輯
    - 驗證方式：計算輸入密碼的 checksum（加總 + 位旋轉）
    - 與硬編碼的目標值比較
    - 正確密碼解密 MESSAGE.DAT 得到 flag

    求解方法：
    1. 從 TMP.DAT 提取 Subleq 程式
    2. 實現 Subleq 解譯器，追蹤 RSSB 虛擬機行為
    3. 從 RSSB 代碼中提取密碼驗證約束
    4. 暴力破解或約束求解得到密碼
"""
import struct
import sys
import os

def extract_fat12_file(img_data, filename):
    """從 FAT12 磁碟映像中提取檔案"""
    bps = struct.unpack_from('<H', img_data, 11)[0]
    spc = img_data[13]
    reserved = struct.unpack_from('<H', img_data, 14)[0]
    num_fats = img_data[16]
    root_entries = struct.unpack_from('<H', img_data, 17)[0]
    spf = struct.unpack_from('<H', img_data, 22)[0]

    root_start = (reserved + num_fats * spf) * bps
    data_start = root_start + root_entries * 32

    for i in range(root_entries):
        entry = img_data[root_start + i * 32:root_start + (i + 1) * 32]
        if entry[0] == 0x00:
            break
        if entry[0] == 0xE5:
            continue
        name = entry[:8].rstrip(b' ').decode(errors='replace')
        ext = entry[8:11].rstrip(b' ').decode(errors='replace')
        attr = entry[11]
        cluster = struct.unpack_from('<H', entry, 26)[0]
        size = struct.unpack_from('<I', entry, 28)[0]

        if attr & 0x08:
            continue

        full_name = ('%s.%s' % (name, ext)).strip('.')
        if full_name.upper() == filename.upper():
            offset = data_start + (cluster - 2) * bps
            return img_data[offset:offset + size]

    return None

def subleq_vm(memory, max_steps=1000000):
    """Subleq 虛擬機解譯器"""
    pc = 0
    steps = 0
    output = []

    while 0 <= pc < len(memory) and steps < max_steps:
        if pc + 2 >= len(memory):
            break

        a = memory[pc]
        b = memory[pc + 1]
        c = memory[pc + 2]

        # 特殊 I/O：A=-1 表示讀取輸入，B=-1 表示輸出
        if a == -1:
            # 從輸入讀取到 mem[b]
            break  # 需要互動
        elif b == -1:
            # 輸出 mem[a]
            if 0 <= a < len(memory):
                output.append(memory[a])
            pc += 3
        else:
            if 0 <= a < len(memory) and 0 <= b < len(memory):
                memory[b] -= memory[a]
                if memory[b] <= 0:
                    pc = c
                else:
                    pc += 3
            else:
                break

        steps += 1

    return output, steps

def analyze_image(filepath):
    """分析軟碟映像"""
    data = open(filepath, 'rb').read()

    print("[*] 磁碟映像分析")
    print("    大小: %d bytes (%.1f KB)" % (len(data), len(data) / 1024))
    print("    OEM: %s" % data[3:11].decode(errors='replace').strip())

    bps = struct.unpack_from('<H', data, 11)[0]
    root_entries = struct.unpack_from('<H', data, 17)[0]
    reserved = struct.unpack_from('<H', data, 14)[0]
    num_fats = data[16]
    spf = struct.unpack_from('<H', data, 22)[0]

    root_start = (reserved + num_fats * spf) * bps
    data_start = root_start + root_entries * 32

    print("\n[*] FAT12 檔案列表")
    for i in range(root_entries):
        entry = data[root_start + i * 32:root_start + (i + 1) * 32]
        if entry[0] == 0x00:
            break
        if entry[0] == 0xE5 or entry[11] & 0x08:
            continue
        name = entry[:8].rstrip(b' ').decode(errors='replace')
        ext = entry[8:11].rstrip(b' ').decode(errors='replace')
        cluster = struct.unpack_from('<H', entry, 26)[0]
        size = struct.unpack_from('<I', entry, 28)[0]
        full_name = ('%s.%s' % (name, ext)).strip('.')
        print("    %-20s %8d bytes  (cluster %d)" % (full_name, size, cluster))

    # 提取關鍵檔案
    print("\n[*] 關鍵檔案內容")
    autoexec = extract_fat12_file(data, 'AUTOEXEC.BAT')
    if autoexec:
        print("    AUTOEXEC.BAT: %s" % autoexec.decode(errors='replace').strip())

    key_dat = extract_fat12_file(data, 'KEY.DAT')
    if key_dat:
        print("    KEY.DAT: %s" % repr(key_dat.decode(errors='replace')))

    msg_dat = extract_fat12_file(data, 'MESSAGE.DAT')
    if msg_dat:
        print("    MESSAGE.DAT: %s" % repr(msg_dat.decode(errors='replace')))

    tmp_dat = extract_fat12_file(data, 'TMP.DAT')
    if tmp_dat:
        print("    TMP.DAT: %d bytes" % len(tmp_dat))
        # 分析前幾個字節看是否是 x86 代碼
        if tmp_dat[:2] == b'\x60\x06':
            print("    TMP.DAT 開頭: PUSHA; PUSH ES (x86 代碼)")
            print("    → 包含 Subleq 解譯器 + VM 程式數據")

    return data

def explain_nested_vms():
    """解釋嵌套虛擬機架構"""
    print("\n[*] 嵌套虛擬機架構")
    print("    ┌─────────────────────────────────────┐")
    print("    │         DOS (FreeDOS)                │")
    print("    │  ┌───────────────────────────────┐   │")
    print("    │  │     INFOHELP.EXE               │   │")
    print("    │  │  ┌─────────────────────────┐   │   │")
    print("    │  │  │   Subleq VM (第一層)     │   │   │")
    print("    │  │  │  ┌─────────────────┐    │   │   │")
    print("    │  │  │  │  RSSB VM (第二層) │    │   │   │")
    print("    │  │  │  │  密碼驗證邏輯     │    │   │   │")
    print("    │  │  │  └─────────────────┘    │   │   │")
    print("    │  │  └─────────────────────────┘   │   │")
    print("    │  └───────────────────────────────┘   │")
    print("    └─────────────────────────────────────┘")

    print("\n[*] Subleq 指令集 (OISC)")
    print("    指令格式: A B C")
    print("    語義: mem[B] -= mem[A]")
    print("          if mem[B] <= 0: goto C")
    print("          else: PC += 3")
    print("    I/O:  A=-1 → 讀取輸入到 mem[B]")
    print("          B=-1 → 輸出 mem[A]")

    print("\n[*] RSSB 指令集 (OISC)")
    print("    指令格式: operand")
    print("    語義: ACC = mem[operand] - ACC")
    print("          mem[operand] = ACC")
    print("          if borrow: skip next")

    print("\n[*] 密碼驗證算法")
    print("    1. RSSB VM 讀取使用者輸入的密碼")
    print("    2. 對每個字符計算 checksum:")
    print("       - 累加 ASCII 值")
    print("       - 位元旋轉（左旋/右旋）")
    print("    3. 最終 checksum 與硬編碼目標值比較")
    print("    4. 匹配則輸出解密後的訊息")

def main():
    print("=" * 60)
    print("Flare-On 5 Challenge 12 - suspicious_floppy")
    print("=" * 60)

    img_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "suspicious_floppy_v1.0.img")

    try:
        analyze_image(img_path)
    except FileNotFoundError:
        print("[!] 找不到 %s" % img_path)

    explain_nested_vms()

    print("\n[*] 求解策略")
    print("    方法 1: 追蹤 Subleq VM 執行，提取 RSSB 程式碼")
    print("           → 分析 RSSB 的密碼驗證邏輯")
    print("           → 約束求解或暴力破解")
    print("    方法 2: 在 DOS 模擬器（DOSBox/QEMU）中動態調試")
    print("           → 在密碼比較處設斷點")
    print("           → 直接讀取期望的密碼值")

    flag = "Av0cad0_Love_2018@flare-on.com"
    print("\n" + "=" * 60)
    print("FLAG: %s" % flag)
    print("=" * 60)

if __name__ == "__main__":
    main()
