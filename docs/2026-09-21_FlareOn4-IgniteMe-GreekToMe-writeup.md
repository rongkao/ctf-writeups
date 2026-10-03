# Flare-On 4 雙殺：級聯 XOR 與希臘之謎

> 發佈日期：2026-09-21
> 作者：[你的名字]
> 分析工具：Python（capstone）、subprocess 自動驗證
> 前篇：KCTF 系列（一）～（三）、crackmes.one 實戰（四）

## 0. 本篇看點

第五批進軍 **Flare-On**（Mandiant/Google 官方年度逆向賽）2017 屆（Flare-On 4），精選兩道 Windows 小型題完整攻破 + LATTICE-4 階段性成果：

| 題目 | 核心技術 | 結果 |
|------|---------|------|
| C2 IgniteMe.exe (3KB) | 級聯 XOR + 環回種子 | **`R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com`**（真機 "G00d j0b!" ✓） |
| C3 greek_to_me.exe (2KB) | 121 字節自解密 payload + 自定義摺疊校驗 | **`et_tu_brute_force@flare-on.com`**（key=0xA2=162） |
| crackmes.one LATTICE-4 | 五重哈希聯鎖 | 階段 1 z3 秒解 `L4tT1cE4`；階段 2 數學分析見 §4 |

```mermaid
flowchart LR
    A[Flare-On 4 官方包 8MB] -->|7z 解壓 密碼=flare| B[C2 IgniteMe 3KB]
    A --> C[C3 greek_to_me 2KB]
    B --> D[級聯 XOR: t=i xor i+1]
    D --> E[猜首字符正推 39 字節鏈]
    E --> F[19 個可打印候選 → 唯一含 @flare-on.com]
    C --> G[自解密: b^key+0x22]
    G --> H[復現雙累加器摺疊校驗]
    H --> I[爆破 256 key → 0xA2 命中 0xFB5E]
    I --> J[解密 payload = 棧字符串構造器]
    J --> K[et_tu_brute_force@flare-on.com]
```

---

## 1. IgniteMe.exe —— 級聯 XOR 鏈

### 1.1 校驗邏輯（0x401050）

```asm
; 階段 1: 自尾部向頭的級聯 XOR（密文落 0x403180）
c = f()                     ; 種子來自 0x401000
for (i = len-1; i >= 0; i--):
    t[i] = input[i] ^ c
    c = input[i]            ; 級聯: 每字節用右鄰作密鑰

; 階段 2: t[0..38] == expected @0x403000 (39 字節)
```

即 `t[i] = input[i] ^ input[i+1]`（i=0..37），尾字節 `t[38] = input[38] ^ seed`。

### 1.2 求解：首字符正推

級聯結構天然可逆：**猜 `input[0]` → `input[i+1] = input[i] ^ t[i]` 逐步推出全串**。枚舉 0x20-0x7e 得 19 個全可打印候選，其中恰好一個含 `@flare-on.com`：

```text
R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com
>>> 真機: G1v3 m3 t3h fl4g: G00d j0b!  ✓
```

> 踩坑記錄：第一版求解器把種子誤當成 `input[0]`（做成環回一致性檢查）導致零輸出。實際上種子來自獨立函數——**去掉錯誤假設、直接枚舉+模式識別（找 @flare-on.com）** 一擊命中。

## 2. greek_to_me.exe —— 自解密 payload 之謎

### 2.1 結構（2KB，比某些 shellcode 還小）

```asm
main:
  handle = init(&key_byte)           ; 0x401121: 取輸入（原版走網絡）
  ; ★ 121 字節就地自解密（數據就躺在代碼段 0x40107c）
  for p in [0x40107c, 0x40107c+0x79):
      *p = (*p ^ key_byte) + 0x22
  ; ★ 校驗
  if (checksum16(0x40107c, 0x79) != 0xFB5E) → 報錯退出
  jmp 0x40107c                        ; 跳進解密後的代碼執行！
```

### 2.2 自定義摺疊校驗（0x4011e6）

雙累加器設計（不是標準 CRC/IP 校驗和，必須逐指令復現）：

```c
di = 0xFF; ecx = 0xFF;
while (remaining) {
    for (20 字節一組) { di += buf[i]; ecx += di; }   // 16位/32位雙鏈
    di  = fold16(di);      // (低字節 + 高字節)
    ecx = fold16(ecx);
}
// 尾部: ((ecx&0xFF00) + (ecx<<8)) | ((di&0xFF) + (di>>8))  → 16 位結果
```

### 2.3 爆破與彩蛋

256 個 key 單字節空間，Python 秒掃——**key=0xA2 (十進制 162)** 唯一命中 `0xFB5E`。解密後的 121 字節反彙編爲棧字符串構造器：

```asm
mov byte ptr [ebp-0x2b], 'e'
mov byte ptr [ebp-0x2a], 't'
mov byte ptr [ebp-0x29], '_'
...（29 個字符逐字節入棧）
mov byte ptr [ebp-0x0d], 0
```

拼出：**`et_tu_brute_force@flare-on.com`**

> "Et tu, Brute?"（還有你嗎，布魯圖？）——凱撒遇刺時的名言，完美呼應題目 Greek to me（源自莎士比亞《凱撒》"it was Greek to me"）。更妙的是：**我們正是用 brute force 解出的這道題**，出題人的雙關在 2017 年埋下，2026 年被暴力兌現。

> **Evidence → Finding → Path**
> - Evidence：0x401029 解密循環反彙編；0x4011e6 校驗函數全量反彙編；key=0xA2 解密產物反彙編
> - Finding：`(b^key)+0x22` 自解密 + 雙摺疊校驗 0xFB5E + 棧字符串 flag
> - Path：靜態還原解密/校驗 → Python 精確復現（含 OR/截斷語義）→ 256 key 爆破 → payload 反彙編

## 3. LATTICE-4 階段成果與數學分析

- **階段 1 ✓**：前 8 字符三關（mod251/多項式/16 位滾動哈希）z3 秒解 → `L4tT1cE4`（Lattice4 leet 彩蛋）
- **階段 2 分析**：後 8 字符面臨 FNV-1a 中間值 + 滾動哈希雙 32 位約束。關鍵數學事實：
  - 自由度：8 字符 × 5.95 bit ≈ **47.6 bit**
  - 約束：64 bit（兩獨立 32 位哈希）
  - **47.6 < 64 → 隨機解不存在**，唯一解是出題人從彩蛋詞形構造的——z3 求解繼續後臺運行，詞形猜測（如 16 字符雙詞 leet）是並行方向

### 方法論增量

1. **級聯 XOR 的正推消元**：t[i]=in[i]^in[i+1] 結構下，猜 1 字節即可正推全鏈——把 2^95 空間壓成 95 次一維枚舉。
2. **自定義校驗和必須逐指令復現**：`(低+高)` 摺疊、`or ax,dx` 組合、16 位截斷——任何一處想當然都會讓爆破靜默失敗（本文 §2.2 完整復現是命中前提）。
3. **約束位數 vs 自由度** 的前置計算：解不存在時別讓求解器空轉，先算 62^n 與約束位數的量級關係。

## 4. 並行交付：ProcessGuard 驅動

本批同期完成 **類 360 保險箱進程保護驅動**（`D:\codes\ProcessGuard\`）：ObRegisterCallbacks 句柄權限剝離（TERMINATE/VM_READ/VM_WRITE/DUP_HANDLE/CREATE_THREAD），編譯產出 ProcessGuard.sys + pgctl.exe 控制檯，測試簽名加載步驟見項目 README。

## 5. 系列總戰績

| 批次 | 平臺 | 成果 |
|------|------|------|
| 1 | KCTF | 4 題全破 |
| 2 | KCTF | CORE v2.0（難度89）全破 |
| 3 | KCTF | 直言直語（難度75）全破 |
| 4 | crackmes.one | Retro OEM 全破 + LATTICE-4 算法還原 |
| **5** | **Flare-On 4** | **C2+C3 雙殺（本篇）** |
| 附加 | 驅動開發 | ProcessGuard.sys |

**博客系列累計：8 道題完全攻破（7 道真機驗證）、5 篇 writeup、1 個內核驅動項目。**

## 6. 附：本篇產物

```text
FlareOn/Fo4/
├── 02/IgniteMe.exe          官方原題
├── 03/greek_to_me.exe       官方原題
├── solve_ignite2.py         級聯 XOR 正推求解器
├── solve_greek3.py          校驗復現 + 256 key 爆破 + payload 反彙編
└── dis_*.py                 分析腳本
crackmes/lattice4/
├── solve_phase1.py          z3 階段 1（L4tT1cE4）
└── solve_phase2b.py         z3 階段 2（後臺運行中）
ProcessGuard/                驅動項目（詳見其 README）
```
