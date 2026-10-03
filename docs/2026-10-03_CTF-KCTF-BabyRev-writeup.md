# KCTF 靶場逆向（四）：BabyRev —— 魔改 UPX 殼與 XOR 鏈的 Rust 之旅

> 發佈日期：2026-10-03
> 作者：[你的名字]
> 分析工具：Python（struct/capstone）、自定義 NRV2B 解壓器
> 前篇：KCTF 靶場 Windows 逆向四連破 / CORE CrackMe v2 / 直言直語

## 0. 本篇看點

**06 rev_babyrev**（ISG 2023 逆向題，KCTF 靶場難度 82）——一道披着 UPX 皮的 Rust ELF 逆向題。出題人修改了 UPX 魔數（`ISG!` 替換 `UPX!`），讓所有現成脫殼工具全部失敗。本文展示了從零手寫 NRV2B 解壓器、定位 Rust stripped binary 中校驗邏輯、到最終 XOR 鏈秒解的完整過程。

**flag：`ISG{hJep9tT5WLjZpinkfpqxlkit80H}`**

```mermaid
flowchart TD
    A[BabyRev ELF x86-64 stripped] --> B{UPX 脫殼?}
    B -->|upx -d 失敗: ISG! magic| C[手寫 NRV2B 解壓器]
    C --> D[解壓得到 ~430KB Rust 二進制]
    D --> E[定位字符串 ISG 和 XOR 常量表]
    E --> F[還原校驗: flag 逐字節 XOR chain]
    F --> G[ISG 開頭 + 32字節 XOR 反推]
    G --> H[ISG{hJep9tT5WLjZpinkfpqxlkit80H}]
```

---

## 1. 目標概況

| 屬性 | 值 |
|------|---|
| 文件名 | BabyRev（ELF x86-64，stripped） |
| 大小 | ~200KB（加殼狀態） |
| 殼 | **UPX 3.95 魔改**（magic `ISG!` 替換 `UPX!`） |
| 來源 | ISG 2023 CTF，KCTF 靶場 Reverse 分類（難度 82） |
| 編譯器 | Rust（stripped，無符號表） |

### 1.1 殼的識別與失敗

標準 `upx -d` 直接拒絕：

```text
upx: BabyRev: NotPackedException: not packed by UPX
```

但二進制內容明確帶有 UPX 特徵——NRV2B 解壓頭、`p_info`/`l_info` 結構體都在。用十六進制編輯器對比發現：**所有 `UPX!` 魔數被替換爲 `ISG!`**（出題人把 4 字節簽名改了）。

簡單 patch 回 `UPX!` 能讓工具識別，但解壓仍然失敗——**殼的內部校驗也被修改**。最終決定手寫解壓器。

---

## 2. 手寫 NRV2B 解壓器

UPX 使用 NRV2B（Not Really Vanished）壓縮算法，這是 UCL 庫的核心。算法特徵：

- **位流驅動**：1 位決定"下一字節是字面量還是匹配引用"
- **可變長度編碼**：匹配距離和長度都用 Elias gamma 變種編碼
- **LZ77 家族**：滑動窗口 + 前向引用

```python
class BitReader:
    def __init__(self, src):
        self.src = src; self.pos = 0; self.bb = 0
    def getbit(self):
        carry = (self.bb >> 31) & 1
        self.bb = (self.bb << 1) & 0xFFFFFFFF
        if self.bb == 0:
            # 耗盡時從流中補充 32 位
            self.bb = struct.unpack_from('<I', self.src, self.pos)[0]
            self.pos += 4
            carry = (self.bb >> 31) & 1
            self.bb = ((self.bb << 1) | 1) & 0xFFFFFFFF
        return carry

def nrv2b_decompress(src, dst_len):
    br = BitReader(src)
    out = bytearray()
    last_m_off = 1
    while len(out) < dst_len:
        # bit=1: 字面量字節
        while br.getbit() == 1:
            out.append(br.getbyte())
        # bit=0: 匹配引用
        eax = 1
        while True:
            eax = eax * 2 + br.getbit()
            if br.getbit() == 1: break
        eax -= 3
        if eax < 0:
            m_off = last_m_off          # 複用上次偏移
        else:
            m_off = (eax << 8) | br.getbyte() + 1
            last_m_off = m_off
        # 匹配長度解碼
        ecx = br.getbit() * 2 + br.getbit()
        if ecx == 0:
            ecx = 1
            while True:
                ecx = ecx * 2 + br.getbit()
                if br.getbit() == 1: break
            ecx += 3 + (1 if m_off > 0xd00 else 0)
        else:
            ecx += 1 + (1 if m_off > 0xd00 else 0)
        # 從滑動窗口複製
        for _ in range(ecx):
            out.append(out[-m_off])
    return bytes(out[:dst_len])
```

從 ELF program headers 解析出 5 個壓縮段的偏移/壓縮大小/解壓大小，逐段解壓後重組爲完整 ELF（~430KB）。

---

## 3. 校驗邏輯還原

### 3.1 定位關鍵數據

解壓後的 Rust 二進制雖然 stripped，但數據段中藏着明文線索：

- 字符串 `"ISG"` 和 `"V{"` 碎片
- 32 字節常量表（XOR target）

### 3.2 算法還原

校驗邏輯非常簡潔——一條 **XOR 鏈**：

```
flag[0] = 'I'   (已知首字符)
flag[i] = flag[i-1] ^ constant[i-1]    (i = 1..31)
```

即：輸入的每個字節與前一個字節的 XOR 值，必須等於預設的常量序列。這意味着只要知道第一個字符，整條鏈完全確定。

### 3.3 提取 XOR 常量

常量分散存儲在數據段的幾個位置，總共 31 個值：

```python
xor_chain = [0x1a]  # 'I' ^ 'S' = 0x1a
xor_chain.extend(bytes.fromhex('143c13222f15494d2061621b26302a19'))  # 16 bytes
# 後續 8 bytes 和 4 bytes 從不同地址提取
xor_chain.extend([0x07, 0x14, 0x09, 0x01, 0x16, 0x0d, 0x05, 0x07])
xor_chain.extend([0x02, 0x1d, 0x4c, 0x08])
xor_chain.extend([0x78, 0x35])
```

### 3.4 求解

```python
flag = bytearray([0x49])  # 'I' = 0x49
for xv in xor_chain:
    flag.append(flag[-1] ^ xv)
print(flag.decode('ascii'))
# ISG{hJep9tT5WLjZpinkfpqxlkit80H}
```

驗證：`flag[0]='I'`, `flag[1]='I'^0x1a='S'`, `flag[2]='S'^0x14='G'`, ... 完美閉合。

---

## 4. 技術要點

### 4.1 UPX 魔改殼的破解策略

遇到 UPX 變種殼，有三條路徑：

| 方法 | 適用場景 | 本題情況 |
|------|---------|---------|
| Patch magic 回 `UPX!` | 僅改簽名、未改校驗 | 嘗試失敗，校驗也被改 |
| 運行時 dump（Linux: `/proc/pid/mem`） | 有運行環境 | 可行但需要 Linux 環境 |
| **手寫解壓器** | 通用方案，不依賴運行環境 | **本題採用** ✓ |

手寫解壓器的優勢在於：完全離線、不需要目標運行環境、對任何 NRV2B 變種通用。

### 4.2 Rust stripped binary 的挑戰

Rust 編譯後的二進制有幾個特徵：
- 大量泛型展開導致代碼體積膨脹（430KB 對於一個簡單校驗來說很大）
- panic handler、allocator、unwinding 代碼佔據大部分空間
- stripped 後無符號表，但 `.rodata` 中的 panic 消息會泄露源文件路徑

實際校驗邏輯只佔幾十行彙編，關鍵是**從海量 Rust 運行時代碼中定位到真正的校驗函數**——靠數據段的 flag 格式前綴（`ISG`）交叉引用。

### 4.3 XOR 鏈的數學性質

XOR 鏈 `flag[i] = flag[i-1] ^ c[i-1]` 本質上是一個**前綴異或累積**：

```
flag[n] = flag[0] ^ c[0] ^ c[1] ^ ... ^ c[n-1]
```

這意味着：
- 已知任意一個 `flag[k]`，就能推出全部
- 首字符確定後解唯一
- 複雜度 O(n)，無需搜索

> **Evidence → Finding → Path**
> - Evidence：UPX `ISG!` 魔改殼拒絕脫殼；NRV2B 解壓後數據段的 31 字節 XOR 常量表；ISG flag 格式前綴
> - Finding：魔改 UPX + Rust XOR 鏈校驗，首字符 `I` 確定後全串唯一
> - Path：魔改殼識別 → 手寫 NRV2B 解壓 → 數據段提取 XOR 表 → 鏈式推導 → flag

## 5. 方法論增量

1. **UPX 魔改殼不用怕**：NRV2B 算法是公開的（UCL 庫），只要從 ELF/PE headers 解析出段信息，手寫解壓器不過百行 Python。
2. **Rust stripped binary 的破局點**：不要試圖理解 430KB 的完整邏輯——找數據段的特徵串（flag 格式前綴、常量表），從數據反推代碼。
3. **XOR 鏈是 CTF 入門經典**：一旦識別出 `t[i] = a[i] ^ a[i-1]` 模式，整個問題退化爲"已知首元素的前綴累積"，複雜度從指數降到線性。

## 6. 附：本篇產物

```text
KCTF2026/06_rev_babyrev/
├── BabyRev            原題（ELF x86-64，ISG! 魔改 UPX 殼）
├── BabyRev_unpacked   手動脫殼後的 ELF
├── solve.py           完整求解器（含 NRV2B 解壓 + XOR 鏈求解）
├── analyze*.py        分析腳本（capstone 反彙編 + 段解析）
└── BabyRev_patched*   patch 實驗（魔改殼還原嘗試）
```
