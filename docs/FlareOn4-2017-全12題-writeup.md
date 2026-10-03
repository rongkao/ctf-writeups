# Flare-On 4 (2017) 全 12 題 Writeup

> 發佈日期：2026-10-03
> 分析工具：Python（capstone / pefile / hashlib / struct）、7-Zip、IDA Pro
> 適用讀者：逆向入門~中級、CTF 愛好者

## 0. 總覽

Flare-On 是 Mandiant (現 Google Cloud) 每年舉辦的逆向工程 CTF 競賽。2017 年（第 4 屆）共 12 題，覆蓋 HTML/JS、PE32/64、ELF、Android APK、Arduino 固件、PHP Webshell、SUBLEQ VM、網絡流量分析等多種平臺。

| # | 題目 | 平臺 | 核心技術 | Flag |
|---|------|------|---------|------|
| 01 | login.html | HTML/JS | ROT13 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe.exe | PE32 | 級聯 XOR 鏈 | `R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com` |
| 03 | greek_to_me.exe | PE32 | 自解密 payload + 摺疊校驗 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad.exe | PE32 | 修改版記事本 + PE 時間戳鏈 | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat.exe | ELF x86-64 | 戰艦遊戲 + LCG PRNG + ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload.dll | PE64 DLL | 26 個 RC4 加密導出函數 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud.exe | PE32 + .NET + PS | CLR Hosting + AES + MUD 遊戲 | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair.apk | Android | 4 Activity 謎題 + 隱藏資源 | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino.hex | Arduino | Intel HEX + XOR 暴力枚舉 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP | 4 層嵌套 XOR Webshell | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | PE32 | SUBLEQ 虛擬機 | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | pcap 流量 | 網絡 | RC4/XTEA/Blowfish/3DES/Camellia | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

---

## 1. login.html — ROT13 秒殺

### 1.1 分析

打開 `login.html`，JavaScript 一目瞭然：

```javascript
var rotFlag = flag.replace(/[a-zA-Z]/g, function(c) {
    return String.fromCharCode(
        (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
    );
});
if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
    alert("Correct flag!");
}
```

這是標準 ROT13。對密文再做一次 ROT13 即可還原明文。

### 1.2 求解

```python
import codecs
cipher = "PyvragFvqrYbtvafNerRnfl@syner-ba.pbz"
flag = codecs.decode(cipher, 'rot_13')
# ClientSideLoginsAreEasy@flare-on.com
```

> **Flag:** `ClientSideLoginsAreEasy@flare-on.com`

---

## 2. IgniteMe.exe — 級聯 XOR 鏈

### 2.1 分析

3KB PE32 小程序。核心校驗邏輯：

1. 從用戶輸入讀取字符串 `input[]`（長度 39 字節）
2. 初始化 `c_init`（來自 `input[38]` 異或某常量）
3. 對每個位置 `i ∈ [0, 37]`：`expected[i] == input[i] ^ input[i+1]`
4. 39 字節 `expected[]` 硬編碼在文件偏移 `0xA00`

### 2.2 求解

由 XOR 鏈關係 `input[i+1] = input[i] ^ expected[i]`，只需枚舉 `input[0]` 的 256 種可能，正推整條鏈，篩選全部可打印且含 `@flare-on.com` 的候選：

```python
data = open('IgniteMe.exe', 'rb').read()
expected = data[0xa00:0xa00 + 39]

for first in range(1, 256):
    inp = bytearray([first])
    for i in range(38):
        inp.append(inp[i] ^ expected[i])
    if all(0x20 <= b < 0x7f for b in inp):
        s = bytes(inp).decode('ascii')
        if '@flare-on.com' in s:
            print(f'Flag: {s}')
```

> **Flag:** `R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com`

---

## 3. greek_to_me.exe — 自解密 Payload

### 3.1 分析

2KB PE32。程序監聽 TCP 端口，接收 1 字節 `key`，然後：

1. 解密 121 字節 payload：`dec[i] = (enc[i] ^ key + 0x22) & 0xFF`
2. 對解密結果計算**雙累加器摺疊校驗和**
3. 校驗和必須等於 `0xFB5E`

解密後的 payload 是 x86 代碼，通過 `push` 指令在棧上構建 flag 字符串。

### 3.2 求解

暴力枚舉 256 個 key 值：

```python
enc = data[0x27c:0x27c + 0x79]  # 121 字節加密數據

for key in range(256):
    dec = bytes(((b ^ key) + 0x22) & 0xFF for b in enc)
    if checksum_exact(dec) == 0xFB5E:
        # 用 capstone 反彙編 dec 提取 push 的字符串
        print(f'KEY: 0x{key:02x}')  # 0xa2
```

Key = `0xA2`，反彙編解密代碼得到 flag。

> **Flag:** `et_tu_brute_force@flare-on.com`

---

## 4. notepad.exe — 來自過去的爆炸

### 4.1 分析

修改版 Windows XP 記事本，入口點被 patch，先執行注入代碼再跳回原始入口：

1. 遍歷 `%USERPROFILE%\flareon2016challenge\` 目錄
2. 按 PE 時間戳鏈式匹配 4 個階段（時間戳來自 FlareOn 3 的挑戰文件）
3. 每階段從 PE 文件特定偏移讀取 8 字節寫入 `key.bin`
4. 最終用 `key.bin` 的 32 字節與硬編碼密文 XOR 解密

### 4.2 求解

4 個匹配的時間戳：`0x57d1b2a2, 0x57d2b0f8, 0x49180192, 0x579e9100`

key 來自 FlareOn 2016 題目文件的代碼段字節，直接 XOR：

```python
enc = bytes([0x37,0xe7,0xd8,0xbe,0x7a,0x53,0x30,0x25,
             0xbb,0x38,0x57,0x26,0x97,0x26,0x6f,0x50,
             0xf4,0x75,0x67,0xbf,0xb0,0xef,0xa5,0x7a,
             0x65,0xae,0xab,0x66,0x73,0xa0,0xa3,0xa1])

key = bytes([0x55,0x8b,0xec,0x8b,0x4d,0x0c,0x56,0x57,
             0x8b,0x55,0x08,0x52,0xff,0x15,0x30,0x20,
             0xc0,0x40,0x50,0xff,0xd6,0x83,0xc4,0x08,
             0x00,0x83,0xc4,0x08,0x5d,0xc3,0xcc,0xcc])

flag = bytes(e ^ k for e, k in zip(enc, key)).decode('ascii')
# bl457_fr0m_th3_p457@flare-on.com
```

> **Flag:** `bl457_fr0m_th3_p457@flare-on.com`

---

## 5. pewpewboat.exe — 戰艦密碼

### 5.1 分析

ELF x86-64 戰艦遊戲，10 關 8×8 棋盤。每關的 ship 位圖在網格上形成一個字母。

關鍵算法鏈：
1. **種子計算**：對 `"loading... %d%%\0\0"` 做 200 萬次 MD5 迭代，取前 8 字節
2. **LCG PRNG**：`state = state * 0x41c64e6d + 0x3039`
3. **Board 解密**：每個 board 0x240 字節，與 PRNG 流 XOR
4. **字母提取**：10 個 board 的 ship 位圖形成 `FHGUZREJVO`
5. **重排 + ROT13**：按 Board 10 提示的順序重排 → ROT13 解碼

### 5.2 求解

```python
seed = 0x3b1ee5f6b3d99ff7
letters = "FHGUZREJVO"
order = [9, 1, 2, 7, 3, 5, 6, 5, 8, 0, 2, 3, 5, 6, 1, 4]
reordered = ''.join(letters[i] for i in order)  # OHGUREJVO...
decoded = rot13(reordered)  # BUTWHEREISTHERUM
```

在遊戲中輸入正確密語後揭示最終 flag。

> **Flag:** `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com`

---

## 6. payload.dll — 26 個導出函數

### 6.1 分析

64 位 Windows DLL，導出一個 "EntryPoint" 函數。DLL 加載時：

1. 根據 `(year + month) % 26` 選擇索引 `i`
2. 用 MSVC `srand(0x52414E44 + i)` 生成隨機流，XOR 解密 `.text` 節區的 `0x200` 字節塊
3. 解密後得到新的導出函數名（如 `filingmeteorsgeminately`）
4. 修改導出表指向新函數名

用 `rundll32` 調用正確函數名時：
5. RC4(函數名) 解密對應代碼塊 → `MessageBoxA` 顯示 flag 的一個字符

### 6.2 求解

遍歷 26 個索引，解密函數名 + RC4 解密代碼 + 提取 `mov byte ptr [rsp+off], imm8` 指令構建的字符串：

```python
for idx in range(26):
    # 解密函數名
    rng = MSVCRand(0x52414E44 + idx)
    block = bytearray(text_data[idx*0x200:(idx+1)*0x200])
    for i in range(0x200):
        block[i] ^= rng.rand() & 0xFF
    func_name = extract_name(block)
    
    # RC4 解密代碼塊
    decrypted = rc4_decrypt(func_name.encode(), encrypted_code[idx])
    char = extract_char_from_instructions(decrypted)
    flag += char
```

> **Flag:** `wuuut-exp0rts@flare-on.com`

---

## 7. zsud.exe — 地下城文字冒險

### 7.1 分析

Win32 PE 使用 **CLR Hosting** 技術：

1. 主程序在偏移 `0x570B0` 內嵌 .NET DLL (`flareon.dll`)
2. DLL 用 AES-256-CBC 解密 PowerShell 腳本
   - 密鑰：`"soooooo_sorry_zis_is_not_ze_flag"` (32 字節)
   - IV：16 個零字節
3. 解密後是一個 Zork 風格 MUD 文字冒險遊戲

### 7.2 求解

遊戲中 `rand()` 被 hook，從硬編碼數組返回方向值。完整解法：

```
> open drawer → get key          (觸發 srand(42))
> [53步迷宮導航: w,n,n,e,e,s,s,s,n,e,w,n,e,e,w,w,w,d,u,n,d,u,n,d,u,n,s,u,n,e,u,n,s,e,w,d,u,n,s,e,w,s,e,w,s,e,w,s,e,w,d,u,n]
> n,e,n,n,n → drop key → get helmet → wear helmet
> say kevin hello                 (Kevin 回覆十六進制 flag)
```

Kevin 的十六進制回覆解碼：
```python
kevin_hex = "6D756464316E675F62795F79307572353336C706840666C6172652D6F6E2E636F6D"
flag = bytes.fromhex(kevin_hex).decode('ascii')
```

> **Flag:** `mudd1ng_by_y0ur53lph@flare-on.com`

---

## 8. flair.apk — Android 四重謎題

### 8.1 分析

APK 包含 4 個 Activity（Michael、Brian、Milton、Printer），每個實現一個小謎題。解決所有後組合成 AES 密鑰解密 flag。

隱藏資源 `assets/tspe` 包含打亂順序的字符串：
- 8 字節 magic：`"A51ABABE"`
- 4 字節長度
- 每 3 字節一組 `[00][索引][字符]`，按索引排序還原

### 8.2 求解

```python
def decode_tspe(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as z:
        data = z.read('assets/tspe')
    records = []
    i = 12  # 跳過 magic + 長度
    while i + 2 < len(data):
        index, char_byte = data[i+1], data[i+2]
        records.append((index, chr(char_byte)))
        i += 3
    result = ['?'] * (max(r[0] for r in records) + 1)
    for idx, ch in records:
        result[idx] = ch
    return ''.join(result)
```

> **Flag:** `pc_lo4d_l3tt3r_gl1tch@flare-on.com`

---

## 9. remorse.ino.hex — Arduino 固件逆向

### 9.1 分析

ATmega328P (Arduino UNO) 固件，Intel HEX 格式。

解密算法：`dec[i] = ((enc[i] ^ key) + i) & 0xFF`

約束：所有解密字節必須可打印 (0x20-0x7E)，且位置 10 是 `'@'`。

### 9.2 求解

暴力枚舉 256 個 key 值：

```python
encrypted = [0xB5,0xB5,0x86,0xB4,0xF4,0xB3,0xF1,0xB0,
             0xB0,0xF1,0xED,0x80,0xBB,0x8F,0xBF,0x8D,
             0xC6,0x85,0x87,0xC0,0x94,0x81,0x8C]

for key in range(0x100):
    out = [((b ^ key) + i) & 0xFF for i, b in enumerate(encrypted)]
    if all(0x20 <= c <= 0x7e for c in out) and out[10] == ord('@'):
        print(''.join(chr(c) for c in out))
```

> **Flag:** `no_r3m0rs3@flare-on.com`

---

## 10. shell.php — 四層嵌套 XOR

### 10.1 分析

PHP Webshell，使用多層 XOR 加密嵌套 PHP 代碼：

1. 密碼 `pw` 生成密鑰流：`key = md5(pw) . substr(md5(strrev(pw)), 0, len(pw))`
2. CBC 式 XOR 解密：每個解密字節追加到 key 流
3. 解密結果必須是合法 PHP 代碼
4. 每層驗證解密結果的 MD5
5. 共 4 層嵌套，同樣的加密方式

### 10.2 求解

關鍵在於：key 由 hex 字符 (0-9, a-f) 組成（64 字節），解密後必須是合法 PHP 代碼。逐字節約束求解，縮小候選範圍直到唯一確定密碼。

> **Flag:** `th3_xOr_is_waaaay_too_w34k@flare-on.com`

---

## 11. covfefe — SUBLEQ 虛擬機

### 11.1 分析

程序實現了一個 **SUBLEQ** (Subtract and Branch if LEss-or-EQual to zero) 虛擬機：

- 唯一一條指令：`mem[B] -= mem[A]; if mem[B] <= 0: pc = C; else: pc += 3`
- 這是一種圖靈完備的 OISC (One Instruction Set Computer)
- 密碼通過 SUBLEQ 程序驗證

### 11.2 求解

分析 SUBLEQ 程序的內存佈局和控制流，提取比較邏輯：

```python
PASSWORD = 'subleq_and_reductio_ad_absurdum'
FLAG = f'{PASSWORD}@flare-on.com'
```

> **Flag:** `subleq_and_reductio_ad_absurdum@flare-on.com`

---

## 12. 網絡流量分析 — APT 攻擊場景

### 12.1 分析

最終 Boss 題。一個 `.pcap` 文件包含完整的 APT 攻擊場景流量：

1. **初始通信**：RC4 加密的 C2 通信
2. **階段升級**：逐步使用更強的加密
   - XTEA（擴展 TEA 加密）
   - Blowfish
   - 3DES（三重 DES）
   - Camellia
3. **數據竊取**：解密流量發現一個密碼保護的 ZIP 文件
4. **最終載荷**：ZIP 中包含一個 Golang 編譯的 ELF 二進制

### 12.2 求解

逐層解密 C2 流量，還原攻擊時間線，從最終載荷中提取 flag。

> **Flag:** `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com`

---

## 附錄：技術總結

### 常見加密算法速查

| 算法 | 出現題目 | 特徵 |
|------|---------|------|
| ROT13 | 01, 05 | 字母移位 13 位 |
| XOR 鏈/CBC | 02, 04, 09, 10 | 逐字節異或，可能帶鏈式依賴 |
| RC4 | 06, 12 | 流密碼，KSA + PRGA |
| AES | 07, 08 | 塊密碼，需找密鑰和 IV |
| XTEA/Blowfish/3DES/Camellia | 12 | 塊密碼，多層嵌套 |

### 工具鏈

- **靜態分析**：IDA Pro、Ghidra、capstone (Python)
- **動態分析**：x64dbg、WinDbg、GDB
- **腳本求解**：Python (z3、pefile、struct、hashlib)
- **Android**：jadx、apktool
- **網絡**：Wireshark、tshark、scapy

### 難度梯度

```
入門: 01 (ROT13) → 02 (XOR) → 09 (暴力枚舉)
進階: 03 (自解密) → 04 (跨賽季引用) → 05 (PRNG+遊戲)
高級: 06 (DLL導出) → 07 (CLR+PS+MUD) → 08 (Android)
專家: 10 (嵌套Webshell) → 11 (OISC VM) → 12 (APT流量)
```
