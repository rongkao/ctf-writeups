# Flare-On 4 (2017) 全 12 題題解

> Mandiant/Google 官方年度逆向競賽第四屆，全部 12 題完整攻破。

## 總覽

| # | 題目 | 類型 | 核心技術 | Flag |
|---|------|------|---------|------|
| 01 | login.html | Web | ROT13 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe.exe | PE32 | 級聯 XOR + 種子 | `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com` |
| 03 | greek_to_me.exe | PE32 | 自解密 payload + 爆破 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad.exe | PE32 | PE 時間戳鏈 + XOR | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat | ELF64 | 戰艦遊戲 + MD5/LCG/ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload.dll | DLL64 | 動態導出 + RC4 解密 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud.exe | PE32+.NET | CLR Hosting + AES + PowerShell MUD | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair.apk | Android | 4 個 Activity 謎題 + AES | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino.hex | Arduino | Intel HEX + 字節級爆破 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP | 4 層 XOR webshell 嵌套 | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | ELF | SUBLEQ 單指令虛擬機 | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | coolprogram.pcap | PCAP | RC4/XTEA/Blowfish/3DES/Camellia C2 流量 | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

---

## C01 — login.html

**ROT13 JavaScript 逆向**

HTML 頁面包含 ROT13 加密的密碼檢查。查看源碼即可：

```javascript
// 密碼經過 ROT13 編碼存儲
// 解碼: PyvragFvqrYbtvafNerRnfl → ClientSideLoginsAreEasy
```

Flag: `ClientSideLoginsAreEasy@flare-on.com`

---

## C02 — IgniteMe.exe

**級聯 XOR 鏈**

校驗邏輯：從尾部向頭部級聯 XOR，`t[i] = input[i] ^ input[i+1]`（尾字節用獨立種子）。

求解：猜 `input[0]` → 正推全鏈。枚舉 0x20-0x7e 的 95 個候選，過濾全可打印 + 含 `@flare-on.com` → 唯一解。

Flag: `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com`

---

## C03 — greek_to_me.exe

**自解密 payload + 雙累加器校驗**

121 字節就地自解密：`*p = (*p ^ key) + 0x22`。雙累加器摺疊校驗 `== 0xFB5E`。

256 個單字節 key 秒掃 → key=0xA2 命中。解密後的 payload 是棧字符串構造器。

Flag: `et_tu_brute_force@flare-on.com` （"Et tu, Brute?" — 凱撒名句 + brute force 雙關）

---

## C04 — notepad.exe

**修改版 Windows XP 記事本 + FlareOn 2016 PE 文件鏈**

入口點被 patch，惡意代碼遍歷 `%USERPROFILE%\flareon2016challenge\` 下的 PE 文件。按時間戳鏈式匹配 4 階段，每階段從 PE 偏移讀取 8 字節寫入 key.bin。最終用 32 字節密鑰與硬編碼密文 XOR。

關鍵線索：目錄名 `flareon2016challenge` 指向 FlareOn 3 的題目文件。

```python
enc = bytes([0x37, 0xe7, 0xd8, ...])  # 32 bytes
key = bytes([0x55, 0x8b, 0xec, ...])  # 來自 FlareOn 2016 PE
flag = bytes(e ^ k for e, k in zip(enc, key))
```

Flag: `bl457_fr0m_th3_p457@flare-on.com`

---

## C05 — pewpewboat

**戰艦遊戲 + MD5/LCG/ROT13**

ELF x86-64 戰艦遊戲，10 個關卡。每關的 ship 圖案在 8x8 網格上形成一個字母。

1. MD5 迭代 `"loading... %d%%\0\0"` 2M 次 → 種子
2. LCG PRNG + XOR 解密 10 個 board
3. Board 10 的提示給出重排順序
4. ROT13 解碼得到密語 `BUTWHEREISTHERUM`

Flag: `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com`

---

## C06 — payload.dll

**DLL 動態導出 + RC4 解密**

64 位 DLL，根據 `(year + month) % 26` 選擇索引：
1. 用 MSVC `srand/rand` 生成隨機流，XOR 解密函數名
2. 修改導出表，替換 `EntryPoint` 爲新函數名
3. 調用正確函數名時，RC4 解密代碼塊得到 flag 字符

26 個索引 × 函數名解密 → 26 個 flag 字符。

Flag: `wuuut-exp0rts@flare-on.com`

---

## C07 — zsud.exe

**CLR Hosting + AES + PowerShell 文字冒險**

原生 PE32 使用 CLR Hosting 加載內嵌 .NET DLL (flareon.dll)。DLL 用 AES 解密 PowerShell 腳本，實現類 Zork 的 MUD 遊戲。"zsud" = "Single-User Dungeon"。

解析遊戲邏輯，Kevin 的十六進制回覆 = flag。

Flag: `mudd1ng_by_y0ur53lph@flare-on.com`

---

## C08 — flair.apk

**Android 4 Activity 謎題**

APK 包含 4 個 Activity (Michael, Brian, Milton, Printer)，每個實現一個小謎題。解決所有後組合成 AES 密鑰。

`assets/tspe` 文件：8 字節 magic `A51ABABE` + 打亂的字符序列，按索引排序還原。

Flag: `pc_lo4d_l3tt3r_gl1tch@flare-on.com`

---

## C09 — remorse.ino.hex

**Arduino UNO (ATmega328P) 固件逆向**

Intel HEX 格式的 Arduino 固件。解密算法：`dec[i] = ((enc[i] ^ key) + i) & 0xFF`。

暴力枚舉 key (0-255)，正確的 key 使位置 10 產生 `'@'`。

Flag: `no_r3m0rs3@flare-on.com`

---

## C10 — shell.php

**4 層嵌套 PHP WebShell**

PHP webshell 的密碼通過 XOR 解密嵌套的 PHP 代碼：
- key = `md5(pw) + substr(md5(strrev(pw)), 0, len(pw))`
- CBC 式 XOR 解密
- 共 4 層嵌套，每層同樣的加密方式

約束求解：key 由 hex 字符組成，解密後必須是合法 PHP。逐字節縮小候選範圍。

Flag: `th3_xOr_is_waaaay_too_w34k@flare-on.com`

---

## C11 — covfefe

**SUBLEQ 單指令虛擬機**

SUBLEQ (Subtract and Branch if Less-or-Equal-to-zero) VM：唯一指令 `mem[B] -= mem[A]; if mem[B]<=0: pc=C; else: pc+=3`。

密碼通過 SUBLEQ 程序驗證。分析 VM 程序邏輯得到密碼。

Flag: `subleq_and_reductio_ad_absurdum@flare-on.com`

---

## C12 — coolprogram (PCAP)

**APT 場景 C2 流量分析**

網絡流量包含多層加密 C2 通信：RC4 → XTEA → Blowfish → 3DES → Camellia。

逐層解密 C2 流量，還原攻擊過程。最終解密密碼保護的 zip，包含 Golang ELF 二進制。

Flag: `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com`

---

## 技術統計

| 類別 | 數量 | 涉及題目 |
|------|------|---------|
| XOR 變種 | 5 | C02, C03, C04, C05, C10 |
| 密碼學原語 | 4 | C06(RC4), C07(AES), C12(RC4/XTEA/Blowfish/3DES/Camellia) |
| 虛擬機/仿真 | 2 | C09(AVR), C11(SUBLEQ) |
| 移動/Web | 3 | C01(JS), C08(Android), C10(PHP) |
| 流量分析 | 1 | C12(PCAP) |
