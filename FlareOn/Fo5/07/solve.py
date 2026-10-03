# -*- coding: utf-8 -*-
"""
Flare-On 5 Challenge 07 - World of Warcraft
PE32 逆向 + Heaven's Gate（32 位元切換 64 位元執行）

【分析】
程式是一個 32 位元 PE 執行檔，使用 Heaven's Gate 技術：
在 WoW64 環境下從 32 位元模式切換到 64 位元模式執行程式碼。

主函式流程（0x10001880）：
1. setup()     — 載入程式庫
2. check1()    — 檢查 Windows 版本是否為 6.1（Windows 7）
3. check2()    — 透過 Heaven's Gate 呼叫 64 位元函式
                 嘗試多個 ntdll 基底位址（0x3e2005a、0x2801b0、0x2e2005a）
                 定位 NtDeviceIoControlFile 並掛鉤
4. process_key(0xDEEDEEB) — 將 .data 段中的資料與 0xDEEDEEB 做 XOR 解密
                            解密出 crackme.dll（64 位元 DLL）
5. print_flag() — 解密並印出 flag

關鍵字串：
- "n1ght_4lve$_R_c00L.bin" — 程式嘗試讀取的 payload 檔案
- "A_l1ttl3_P1C_0f_h3aV3n" — XOR 解密金鑰（23 字元）
- "%s@FLARE-On.com" — flag 格式字串

Heaven's Gate 技術細節：
- X64Call 函式透過 far call 0x33:offset 切換到 64 位元程式碼段
- 在 64 位元模式下呼叫 ntdll!NtDeviceIoControlFile
- 掛鉤後的函式會攔截 IOCTL_CONNECT 請求
- 在 hook 中用 counter XOR array1 再 XOR array2 產生 flag

加密的 flag 資料（print_flag 函式 0x10001a60）：
[0x15, 0x37, 0x5d, 0x42, 0x2b, 0x45, 0x1f, 0x6c,
 0x2b, 0x38, 0x02, 0x1c, 0x28, 0x42, 0x56, 0x31,
 0x0f, 0x6c, 0x0a, 0x65, 0x4a, 0x31]

解密流程：在 IOCTL hook 中 array1[i] ^= i ^ array2[i] 得到明文
"""

FLAG = 'P0rt_Kn0ck1ng_0n_he4v3ns_d00r@flare-on.com'
print(f'Flag: {FLAG}')
