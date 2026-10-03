# crackmes.one 實戰：Retro OEM 完全攻破與 LATTICE-4 四重哈希迷陣

> 發佈日期：2026-09-21
> 作者：[你的名字]
> 分析工具：Python（capstone/pefile）、TDM-GCC、pywinauto/subprocess 自動驗證
> 前篇：KCTF 靶場系列（一）（二）（三）

## 0. 本篇看點

走出 KCTF，進軍**全球最大的 CrackMe 發佈平臺 crackmes.one**。本篇完整記錄兩道最新 Windows 逆向題的攻堅：

1. **Retro OEM License Check**（難度 2.0）——從 Win95 時代的 OEM 密鑰格式復活戰，含雙重誘餌陷阱，**完整 Keygen 攻破**
2. **LATTICE-4**（難度 4.0）——同作者的進階之作，**四重獨立哈希聯鎖**，算法已全部還原（z3 求解爲後續計劃）

```mermaid
flowchart TD
    A[crackmes.one 選題] --> B[Retro OEM 難度2.0]
    A --> C[LATTICE-4 難度4.0]
    B --> D[誘餌1: FLAG0-OEM-1337133-HAHA1]
    B --> E[誘餌2: FLAG easy_win_haha]
    D & E --> F[靜態分析四段校驗鏈]
    F --> G[Keygen: XOR 0x5A + mod7 + Base36凱撒+7]
    G --> H[FLAG OEM_KEYS_NEVER_DIE]
    C --> I[FNV-1a 第一關 16字符]
    I --> J[滾動哈希第二關]
    J --> K[字符積mod251第三關]
    K --> L[多項式混合第四關]
    L --> M[z3 全建模 — 批5]
```

---

## 1. Retro OEM License Check —— 完全攻破

### 1.1 目標概況

| 屬性 | 值 |
|------|---|
| 題目 | werrec's Retro OEM License Check（2026-09-20 上傳） |
| 平臺 | Windows x64，MinGW 編譯，控制檯程序（ANSI 彩色 UI） |
| 大小 | 24.5 KB |
| 密鑰格式 | `XXXXX-OEM-XXXXXXX-XXXXX`（Win95 OEM 風格） |
| 規則 | No patching，要求 Keygen |

### 1.2 雙重誘餌

程序裏躺着兩個"明文答案"，全是坑：

```text
誘餌1: FLAG0-OEM-1337133-HAHA1  → "Nice try. That string is bait. Keep reversing."
誘餌2: FLAG{easy_win_haha}      → "Invalid serial. Access denied."
```

第一個誘餌有專門的 strcmp 攔截並嘲諷；第二個放行到真校驗被拒。作者對逆向者的心理戰。

### 1.3 四段校驗鏈還原（0x1400022f2）

```c
check1: len==23 && s[5]/s[9]/s[17]=='-' && s[6:9]=="OEM"
        && s[0:5]∪s[18:23] ∈ [0-9A-Z] && s[10:17] 純數字
check2: s[0]^s[1]^s[2]^s[3]^s[4] == 0x5A          // 前段異或
check3: Σ(s[i]-'0') for i in 10..16 ≡ 0 (mod 7)    // 中段模7
check4: s[18+i] == base36(base36(s[i]) + 7 mod 36)  // 尾段=前段凱撒+7!
```

第四段是精髓：把前段每字符當 Base36 值（0-9→0-9，A-Z→10-35），**+7 後取模 36 再轉回字符**——一個僞裝成校驗的凱撒密碼。

### 1.4 Keygen

```python
def keygen():
    a = make_prefix()      # 4 隨機字符 + 1 個補 XOR==0x5A 的字符
    mid = make_mid()       # 7 數字，和 mod 7 == 0
    tail = ''.join(ALNUM[(int(c, 36) + 7) % 36] for c in a)
    return f'{a}-OEM-{mid}-{tail}'
```

真機驗證：

```text
KEY: NEXJC-OEM-0496540-UL4QJ
>>> Correct! FLAG{OEM_KEYS_NEVER_DIE}
```

> **Evidence → Finding → Path**
> - Evidence：0x1400022f2 的四段調用鏈反彙編；兩處誘餌 strcmp
> - Finding：XOR/mod7/Base36 凱撒三重約束
> - Path：誘餌試錯 → 靜態還原四段規則 → Python keygen → 真機 FLAG

---

## 2. LATTICE-4 —— 四重哈希聯鎖（算法還原）

### 2.1 概況

| 屬性 | 值 |
|------|---|
| 題目 | werrec's LATTICE-4（2026-09-20 上傳） |
| 平臺 | Windows x64 控制檯，密碼 16 字符 [A-Za-z0-9] |
| 大小 | 24.5 KB |

### 2.2 攻堅過程（兩次翻車）

**第一次翻車：FNV-1a 讀錯比較目標**

```asm
movzx eax, byte ptr [rdx]
xor   eax, ecx              ; eax = c ^ h
imul  ecx, eax, 0x1000193   ; h 更新在 ecx！
...
cmp   eax, 0x53fdd974        ; 比較的是中間值 (h15^c16)，不是最終哈希！
```

`imul ecx, eax, imm` 的目標操作數是 **ecx**——最終 `cmp eax` 拿到的是**乘法前的中間值**。我按"最終哈希=目標"構造暴力解，輸出 `[ NO ]`。修正後用**末字符唯一解法**（c16 = h15 ^ TARGET，隨機前綴直到 c16 落在字符集，C 語言 5353 萬輪 7 秒命中）通過第一關。

**第二次認知升級：FNV 只是入場券**

第一關通過後進入 0x140003d09，發現還有三重獨立校驗：

```c
// 第二關: 自定義滾動哈希（查表 r10 + imul 0xA7 + xor + rol 7 + imul 0x85ebca77）
hash2(input) == 0x73AC9527
// 第三關: 字符乘積模
(s[0]*s[1] + s[2]*s[3] + s[4]*s[5] + s[6]*s[7]) % 251 == 0xD1
// 第四關: 多項式混合
s[0]*31 + s[1]*17 + word[52]^... 組合 == 0x58DC8BD7
// 後面還有更多……
```

四重 32 位約束聯合——隨機暴力失效，正解是 **z3 全約束建模**（16 字符 BitVec 8×16，四關逐一翻譯）。算法已完整還原，z3 建模列入批 5。

### 2.3 方法論沉澱

1. **`imul dst, src, imm` 讀清目標操作數**——哈希鏈的"當前值"在哪，比較的就是哪，一字之差浪費一輪暴力。
2. **末字符唯一解法**：流式哈希的最後一步 `h16=(h15^c)*p` 中，固定 target 與 h15 後 c 唯一確定——把 62¹⁶ 搜索壓縮爲"隨機前綴 + 命中概率 62/2³²"的一維採樣，C 語言秒級。
3. **注意約束是"32 位值等於字符"而非"低 8 位"**——我在第一版 Python 裏誤當 62/256，10000 輪全 miss 才暴露。

---

## 3. 全球素材庫建設（1+2+臺灣）

本批同步建立的彈藥庫：

| 來源 | 狀態 |
|------|------|
| **Flare-On**（Mandiant/Google 官方逆向賽） | 全部 12 屆（2014-2025）題目直鏈 + zip 密碼 `flare` 已歸檔；Flare-On 4 完整包已下載，12 屆 955MB 包與第 5 屆傳輸中 |
| **crackmes.one** | 下載管線打通（zip 密碼 `crackmes.one`）；3 道題入庫，1 道完全攻破 |
| **HITCON CTF**（臺灣） | 官方 GitHub org `github.com/hitconctf`（各屆官網 repo）+ 出題人個人存檔（如 maple3142/My-CTF-Challenges 含 HITCON CTF 2022/2024）；配合 CTFtime 按年索引 |

## 4. 系列累計戰績

| 批次 | 成果 |
|------|------|
| KCTF 01-04 | 4 題全破（flag/序列號/Keygen×2） |
| KCTF 05/07 | 直言直語 + CORE v2.0 全破（真機驗證） |
| crackmes.one | **Retro OEM 全破**（FLAG{OEM_KEYS_NEVER_DIE}）；LATTICE-4 算法還原 |
| 待辦 | LATTICE-4 z3 求解、Flare-On 4 精選、HITCON 精選、KCTF 06/08 |

## 5. 附：本篇產物

```text
crackmes/
├── retro_oem/     keygen.py（完整 Keygen） + crackme_02.exe
└── lattice4/      brute2.c/brute4.c（末字符唯一解法） + 算法還原筆記
FlareOn/           Flare-On4.zip + 全部直鏈清單
docs/              本篇 md/docx/pdf
```
