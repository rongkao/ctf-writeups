# KCTF 靶場 Windows 逆向（二）：CORE 官方 CrackMe v2.0 完全攻破

> 發佈日期：2026-09-21
> 作者：[你的名字]
> 分析工具：Python（capstone/Unicorn/pywinauto）、ReadProcessMemory 內存轉儲、WinDbg TTD
> 前篇：KCTF 靶場 Windows 逆向四連破（rechall/躍躍欲試/金山2007/CCG）

## 0. 本篇看點

**CORE Official CrackMe v2.0**（KCTF 靶場難度 89，全站第二難）——出自 1990 年代世界頂尖破解組織 CORE 的成員 Egis 之手。本文完整記錄從零到通用 Keygen 的全過程，包括三次方向修正：

1. 老版 UPX 殼拒絕 `upx -d` → 運行時內存轉儲繞過
2. GF(2) 64×64 線性變換的建模與求逆（對棧上真值驗證）
3. **魔改 MD5 的定位之旅**：所有 MD5 要素逐一驗證均標準 → 暴力擬合 X 序失敗 → Unicorn 直接仿真二進制代碼證明壓縮函數標準 → 最終鎖定 **off-by-one 長度字段**

最終 Keygen 真機驗證通過：程序彈出 *"Man, you're good enough to join CORE!"*

```mermaid
flowchart TD
    A[CRACKME3.EXE 老版 UPX] -->|upx -d 失敗: obsolete version| B[運行時 ReadProcessMemory 轉儲]
    B --> C[定位校驗函數 0x401610]
    C --> D[sscanf %lx%lx%lx 解析三段十六進制]
    C --> E[MD5 變換鏈]
    C --> F[GF(2) 64位變換 ×2]
    D --> G{逐一比對}
    E --> G
    F --> G
    G -->|全等| H[Welcome 彈窗]
    G -->|不等| I[Failed 彈窗]
    E -.魔改點.-> J[長度字段 = len+1 × 8]
```

---

## 1. 目標概況

| 屬性 | 值 |
|------|---|
| 文件名 | CRACKME3.EXE（PE32，Egis/CORE 出品） |
| 大小 | 62,511 字節（UPX 殼，解壓後 224KB） |
| 窗口標題 | CORE Official CrackMe v2.0 - Written by Egis/CORE |
| 輸入 | Name + Registration Code（Code 爲空格分隔的三段十六進制） |
| 成功標誌 | 彈窗 "Man, you're good enough to join CORE!" |

### 1.1 脫殼

節名 `UPX0-3` 是標準 UPX 佈局，但 `upx -d` 拒絕：

```text
CantUnpackException: this program is packed with an obsolete version
```

1997 年的 UPX 0.x 格式與現代工具不兼容。沿用第一篇的方法論——**等程序進入消息循環後 ReadProcessMemory 全量轉儲**（殼已自解壓，代碼明文化，且不觸發任何反調試）：

```python
h = k32.OpenProcess(0x410, False, pid)
for off in range(0, 0x38000, 0x1000):
    k32.ReadProcessMemory(h, ctypes.c_void_p(0x400000+off), ...)
```

轉儲後明文字符串齊現：`Registered`、`... Better luck next time ...`、`... Hmmm, you don't even pass the first threshold ...`（sscanf 失敗分支）、`%lx%lx%lx`。

> 順帶一提：TTD 錄製啓動會觸發殼的單步陷阱（0x80000004）+ 棧溢出陷阱（0xC00000FD）直接崩死——本題反調試情報正來自第一篇的 TTD 偵察法。

---

## 2. 校驗邏輯還原（0x402100 對話框過程）

### 2.1 輸入處理

```c
GetDlgItemTextA(1000, name, 100);    // [ebp-0x608]
GetDlgItemTextA(1001, code, 100);    // [ebp-0x414]
```

**MD5 輸入串構造**（本題第一個小陷阱）：

```c
strcpy(buf220, name);
strrev(buf220);                       // 0x408d70 = strrev
strcat(buf608, buf220);               // append #1: name + rev
RegOpenKeyA(HKLM, buf66c, &hkey);     // 打開註冊表鍵
RegQueryValueExA(hkey, "Product..", ...);   // 值不存在 → buf220 不變！
strcat(buf608, buf220);               // append #2
RegQueryValueExA(hkey, "Registered", ...);  // 同上失敗
strcat(buf608, buf220);               // append #3
// 最終: buf608 = name + strrev(name) × 3
```

兩次 `RegQueryValueExA` 各有 **6 個參數**（含 reserved=0）——數錯成 5 個會誤判爲 RegSetValueA。註冊表值不存在時查詢失敗，緩衝區保持 strrev 內容——這段"註冊表舞蹈"是純煙霧彈。

**Code 解析**：

```c
if (sscanf(code, "%lx%lx%lx", &v1, &v2, &v3) != 3) → "Hmmm..." 彈窗
```

注意 `%lx` 無寬度限制會貪婪吞掉所有十六進制字符——**三段值必須用非十六進制字符分隔**，空格是最自然的選擇。

### 2.2 GF(2) 雙重變換鏈

兩次調用 `0x401ad0(值指針, 表A, 表B)`，64 位就地變換：

```asm
; 每個輸出位 = parity(a_lo & PA[i]) ^ parity(a_hi & PB[i])
; 兩段 32 步循環（MSB 先入），表各 64 項
movsx eax, byte ptr ... 
and   eax, [ebx]        ; a_hi & 表B[i]
call  0x401ab0          ; popcount
xor   edx, eax
and   edx, 1            ; parity
add   edi, edi          ; acc = acc*2 + bit
```

調用鏈：

```c
f1(&v1, T1A@0x41c2c0, T1B@0x41c3c0);   // (v1,v2) → (v1', v2a)
f2(&v2, T2A@0x41c4c0, T2B@0x41c5c0);   // (v2a,v3) → (v2'', v3')
if (v1'==m0 && v2''==m1 && v3'==m2)    // m* = "MD5" 前 12 字節
    → Welcome!
```

這正是 GF(2) 上的 64×64 矩陣乘法（T1b 表呈完美 LFSR 移位結構）。**線性變換必可逆**——把 64 行矩陣高斯消元求逆即可反向解出合法 code：

```python
def gf2_inverse(rows):
    aug = [rows[j] | (1 << (64 + j)) for j in range(64)]
    for col in range(64):
        piv = next(r for r in range(col, 64) if (aug[r] >> col) & 1)
        aug[col], aug[piv] = aug[piv], aug[col]
        for r in range(64):
            if r != col and (aug[r] >> col) & 1:
                aug[r] ^= aug[col]
    return [a >> 64 for a in aug]
```

---

## 3. 魔改 MD5 定位之旅（本篇精髓）

GF(2) 模型很快對棧上真值驗證通過，但比較目標 `m0/m1/m2` 與標準 MD5(name+rev×3) 對不上。排查過程：

| 步驟 | 檢查項 | 結論 |
|------|--------|------|
| 1 | init IV（0x4014e0） | 標準 67452301/... ✓ |
| 2 | T 常量表（4×16 項，散佈在 0x41c1c0-0x41c2bf） | 與 RFC 1321 逐項比對，全部標準 |
| 3 | 移位量 7,12,17,22/5,9,14,20/4,11,16,23/6,10,15,21 | 全部標準 |
| 4 | F/G/H/I 布爾函數 | 標準 |
| 5 | X 消息字序（round2 索引 1,6,11,0 即 +5；round4 循環 +0xC 恰爲 4×7 mod 16） | 全部標準 |
| 6 | 尾部 IV 回加 | 存在 ✓ |
| 7 | 暴力擬合：round2/3/4 的（步長,起始）全空間 | **全部不匹配** |
| 8 | 比較目標是否硬編碼常量 | 不在鏡像中 |
| 9 | **Unicorn 直接仿真 0x401500 二進制代碼** | 輸出 = 標準 MD5！ |

第 9 步是轉折點：壓縮函數本身標準，問題必然在**進入壓縮函數之前**。回讀 padding 構造代碼，發現致命細節：

```asm
0x4022c7: mov byte ptr [ebx + ecx], 0x80   ; buf[len] = 0x80  ← 先寫填充字節！
...
0x4022e7: (strlen(buf608) 第 2 次)          ; 此時 0x80 已計入
0x4022f9: shl eax, 3                        ; bit 長度 = (len+1) × 8  ← off-by-one！
0x402306: mov [esi + edx - 8], eax          ; 寫入長度字段
```

**程序在寫入 0x80 之後再測長度**，長度字段 = `(真實長度+1)×8`。對 16 字節消息，標準 MD5 長度字段是 128，此程序寫入 **136**。一個字節的差，整個哈希面目全非。

Unicorn 仿真 + 修正 padding 後，輸出與棧上真值**精確匹配**：

```text
仿真: c6c0a6a4 fd5b4cb6 ed9b5781 182d2423   ← 與彈窗掛起時棧上比較目標一致
```

---

## 4. Keygen

```python
def custom_md5(msg):                     # 標準 MD5 壓縮 + off-by-one 長度
    buf = msg + b'\x80'
    while len(buf) % 64 < 56: buf += b'\x00'
    buf += struct.pack('<I', (len(msg)+1)*8) + b'\x00'*4   # ← 魔改點
    ...標準 64 步壓縮...

def keygen(name):
    m0, m1, m2, _ = custom_md5((name + name[::-1]*3).encode())
    v2a, v3 = f2inv(m1, m2)              # GF(2) 逆變換 2
    v1, v2  = f1inv(m0, v2a)             # GF(2) 逆變換 1
    return f'{v1:x} {v2:x} {v3:x}'       # 空格分隔，餵給 sscanf %lx%lx%lx
```

真機驗證（pywinauto 自動填入 + 點擊）：

```text
name='test' code='c63f3c7a edd4310d 38477391'
>>> MSGBOX [Welcome]: "... Man, you're good enough to join CORE! ..."
name='KCTF' code='a86ca89f 77f81c3c fd2620f0'
>>> MSGBOX [Welcome]: "... Man, you're good enough to join CORE! ..."
```

> **Evidence → Finding → Path**
> - Evidence：轉儲鏡像反彙編（0x402100 校驗、0x401ad0 GF(2)、0x401500 壓縮、0x4022c7 off-by-one）；彈窗掛起時的棧轉儲（比較目標真值）
> - Finding：name+strrev×3 → 魔改 MD5（長度+1）→ 3×32 位比較；GF(2) 雙重可逆變換鏈
> - Path：運行時轉儲 → 棧上地面真值 → Unicorn 仿真定位魔改 → GF(2) 求逆 → 真機 Welcome

---

## 5. 方法論增量（相對第一篇）

1. **棧上地面真值法**：讓彈窗掛起（MessageBoxA 阻塞中，棧幀活着），VirtualQueryEx 全內存遍歷直接讀出 MD5 輸入串、期望值、變換結果——一次 dump 鎖定三類未知數。
2. **Unicorn 仿真 = 終極仲裁**：當靜態分析全部指向"標準"但結果對不上，把二進制代碼直接扔進 Unicorn 跑一遍。仿真結果 = 標準 MD5 這一事實，把問題空間從"壓縮函數內部"瞬間壓縮到"進入壓縮函數之前"。
3. **off-by-one padding 陷阱**：魔改哈希不一定要改常量/移位——**填充時序**（先寫 0x80 再測長）這一行代碼級的差就能讓所有"標準性檢查"全部通過而結果完全不同。定位它靠的是"仿真證明內部標準 → 外部必有問題"的排除法。
4. **數清 push 個數**：RegQueryValueExA 6 參數 vs RegSetValueA 5 參數，一個 push 的差決定了"註冊表讀"還是"註冊表寫"的語義判斷。

## 6. 其餘題目現狀（第三批預告）

| 題目 | 現狀 |
|------|------|
| 05 直言直語（3.5MB MFC） | 已識別爲 MFC 靜態鏈接大程序，含 `CCorrect` 類提示；需定位按鈕 handler，批 3 主攻 |
| 08 TencentPediyKeygenMe（難度 95） | 2010 騰訊競賽題，橢圓曲線算法（題目描述明示）；批 3 主攻 |
| 06 rev_babyrev（ELF） | 偵察完成：stripped + section headers 整體刪除（僅存 program headers），手工彙編最小運行時（非 GCC 產物），字符串混淆（`KEY_SENTVAL`/`V{`cksx}` 碎片）；批 3 主攻 |

## 7. 附：本篇產物

```text
KCTF2026/07_CORE_CrackMe_v2/
├── dumped.bin          運行時轉儲鏡像（224KB 明文）
├── keygen2.py          最終 Keygen（含 custom_md5 + GF(2) 求逆，自檢通過）
├── emulate.py/emulate2.py   Unicorn 仿真 oracle（定位 off-by-one 的關鍵證據）
├── ground_truth2/3.py  棧上地面真值採集（VirtualQueryEx 全內存遍歷）
├── md5_consts.py       T 常量/移位/X 序覈對（全部標準化的證據鏈）
└── verify_final.py     真機驗證腳本（pywinauto）
```
