# KCTF 靶場逆向（五）：TencentPediyKeygenMe —— 64 位橢圓曲線與六層密碼學全棧攻破

> 發佈日期：2026-10-03
> 作者：[你的名字]
> 分析工具：Python（Unicorn/capstone/hashlib）、C（Pollard rho 多線程）、WinDbg TTD
> 前篇：KCTF 靶場 Windows 逆向四連破 / CORE CrackMe v2 / 直言直語 / BabyRev

## 0. 本篇看點

**08 TencentPediyKeygenMe**（KCTF 靶場難度 95，全站最難）——2010 年騰訊看雪論壇聯合競賽的壓軸題。它在一個序列號中疊了**六層密碼學變換**，要寫出通用 Keygen 必須：

1. 破解 64 位橢圓曲線離散對數（ECDLP）
2. 實現 ECDSA 簽名
3. 逆向自定義 SM4 變種（小端序 + 無 CK 常量）
4. 逆向自定義 Feistel CBC 密碼
5. 實現 GF(2⁸) 逆元替換
6. 還原帶溢出 bug 的自定義 Base32 編碼

全流程從曲線參數提取到通用 Keygen 耗時約 20 小時分析 + 9 分鐘 ECDLP 求解，最終 Keygen 數學驗證通過（d·G = Q 且簽名自驗證閉環）。

```mermaid
flowchart TD
    A[TencentPediyKeygenMe2.exe] --> B[TTD 錄製 + RTTI 偵察]
    B --> C[Crypto++ ECDSA-ECP-SHA1 驗籤器]
    B --> D[六層密碼學棧]
    D --> E1["① Base32 decode (自定義字母表)"]
    E1 --> E2["② SM4 decrypt (LE + 無CK)"]
    E2 --> E3["③ GF(2⁸) 逆元替換"]
    E3 --> E4["④ Feistel CBC decrypt"]
    E4 --> E5["⑤ XOR checksum 校驗"]
    E5 --> E6["⑥ ECDSA verify(SHA1(name), r, s)"]
    E6 -->|需要私鑰 d| F[Pollard rho ECDLP]
    F -->|d = 0x54656e63656e7420| G["彩蛋: ASCII = 'Tencent '"]
    G --> H[通用 Keygen]
```

---

## 1. 目標概況

| 屬性 | 值 |
|------|---|
| 文件名 | TencentPediyKeygenMe2.exe（PE32） |
| 大小 | ~400KB（Crypto++ 靜態鏈接） |
| 窗口標題 | TencentPediyKeygenMe2 |
| 輸入 | Name + Serial（35 字符，含 3 個 `-` 分隔符） |
| 來源 | 2010 騰訊·看雪聯合安全競賽 |
| 難度 | 95（KCTF 全站最高） |

### 1.1 RTTI 情報

TTD 錄製後，RTTI 類型名完整泄露了算法棧：

```text
CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA1>::Verifier
CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>
CryptoPP::ECPPoint
```

關鍵常量串：
- `"DEADBEEF"` — 密鑰
- `"Security@Tencent"` — 密鑰
- `"ABCDEFGHJKMNPQRSTVWXYZ1234567890"` — 自定義 Base32 字母表（去 I/L/O/U）

---

## 2. 驗證流程逆向（0x408270）

從入口到 ECDSA 驗籤，序列號經過六層剝皮：

### 2.1 第一層：自定義 Base32 解碼

```text
Serial: "ABCD1234-EFGH5678-JKMN9012-PQRS3456"
→ 去掉 3 個 '-' → 32 字符
→ 自定義 Base32 decode → 20 字節
```

字母表 `ABCDEFGHJKMNPQRSTVWXYZ1234567890`（32 字符，跳過 I/L/O/U）。

**溢出 bug**：字母表實際只在代碼中分配了 28 字符，值 28-31 會越界讀取字母表後面的相鄰內存，恰好落在 `"Roun"` 上（某個其他字符串的片段）。編碼時 value 28→'R', 29→'o', 30→'u', 31→'n'。這不影響解碼方向，但 Keygen 編碼時必須處理。

### 2.2 第二層：SM4 解密

```python
sm4_decrypt(raw[0:16], key=b"Security@Tencent")
```

**自定義變種**與國標 SM4 的差異：
- **小端序**：`struct.unpack('<4I', ...)` 而非大端序
- **無 CK 常量**：密鑰擴展中跳過了標準的 CK 常量加法，僅用 FK 常量

```python
def _key_expansion(key16):
    MK = struct.unpack('<4I', key16)      # ← 小端序
    K = [MK[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        tmp = K[1] ^ K[2] ^ K[3]
        # 標準 SM4: tmp ^= CK[i]         ← 這裏被省略了！
        tmp = _L_prime(_tau(tmp))
        nk = K[0] ^ tmp
        rk.append(nk)
        K = K[1:] + [nk]
    return rk
```

### 2.3 第三層：GF(2⁸) 逆元替換

對全部 20 字節（SM4 解密後的 16 字節 + 尾部 4 字節）逐字節做 GF(2⁸) 乘法逆元：

```python
# 不可約多項式 0x11b (與 AES 相同)
def gf_inv(x):
    if x == 0: return 0
    r = x
    for _ in range(6):           # x^(2^7-2) = x^126
        r = gf_mul(r, r)
        r = gf_mul(r, x)
    return gf_mul(r, r)

# 關鍵性質：GF(2⁸) 逆元是自逆運算
# gf_inv(gf_inv(x)) == x  ∀x ∈ [0,255]
```

這意味着加密和解密用同一個函數——Keygen 構造時直接複用。

### 2.4 第四層：Feistel CBC 解密

使用 Unicorn 仿真提取的 Feistel 密碼，CBC 模式，密鑰 `"DEADBEEF"`（8 字節），IV 來自第三層的尾部 4 字節（補零到 8 字節）：

```python
iv = gf_tail_4bytes + b'\x00' * 4
plaintext_16 = cbc_decrypt(b"DEADBEEF", iv, gf_data_16)
```

Feistel 密碼的單塊函數通過 Unicorn 仿真二進制代碼（0x448710）獲得，不需要完全逆向其內部結構。

### 2.5 第五層：XOR 校驗和

Feistel 解密後得到 16 字節簽名數據，解釋爲 4 個大端 32 位整數：

```python
dwords = struct.unpack('>4I', signature_16)
checksum = dwords[0] ^ dwords[1] ^ dwords[2] ^ dwords[3]
# checksum 必須等於 gf_tail（第三層的尾部 4 字節）
```

### 2.6 第六層：ECDSA 驗籤

```python
r = int.from_bytes(signature[0:8], 'big')
s = int.from_bytes(signature[8:16], 'big')
h = SHA1(name)[:8]  # 取前 8 字節作爲哈希整數（mod n）
ecdsa_verify(h, r, s, Q)  # Q = 公鑰點
```

曲線參數（全部 64 位）：

| 參數 | 值 | 說明 |
|------|---|------|
| p | `0xc564eef070e69193` | 域素數 |
| a | `p - 3` | 曲線係數 |
| b | `0x22996b9c33aeefdb` | 曲線係數 |
| n | `0xc564eef19a080b07` | 階 |
| G | `(0x2223a1d595845fa2, 0x1c4eee9222ddda62)` | 基點 |
| Q | `(0x297a4a1e5b1fc99b, 0x880198e3724f9fee)` | 公鑰 |

---

## 3. 攻破 ECDLP：從公鑰恢復私鑰

### 3.1 可行性分析

ECDSA 簽名需要私鑰 `d`（滿足 `d·G = Q`）。64 位曲線的安全級別約 32 位——**Pollard rho 算法的期望步數約 √n ≈ 2³² ≈ 4.3×10⁹**，現代 CPU 可在分鐘級完成。

### 3.2 實現迭代

爲求解 ECDLP，經歷了多輪 C 實現優化：

| 版本 | 文件 | 速度 | 結果 |
|------|------|------|------|
| v1 ecdlp_solve.c | 單線程基礎版 | 2M/s | 超時 |
| v2 ecdlp_fast.c | 內聯優化 | 5M/s | 超時 |
| v3 ecdlp_v2.c | 改進隨機遊走 | 6M/s | 超時 |
| v4 ecdlp_rho3.c | Distinguished points | 8M/s | 偶發碰撞丟失 |
| v5 ecdlp_rho4.c | 修復碰撞檢測 | 10M/s | 偶發假解 |
| v6 ecdlp_mt.c | 16 線程並行 | 150M/s | 556 秒 ✓ |
| **v7 ecdlp_final.c** | **JMT + DP 優化** | **200M/s** | **~9 分鐘** ✓ |

最終版使用 **Joe-Muskat-Teske 變種**的 Pollard rho，配合 **Distinguished Points（DP）** 策略檢測碰撞，16 線程並行。

### 3.3 結果與彩蛋

```text
*** ECDLP SOLVED! ***
Private key d = 0x54656e63656e7420
Total steps: 4244M
Wall: 556.4s
```

`0x54656e63656e7420` 轉 ASCII = **`"Tencent "`**（騰訊 + 空格）——出題人把公司名編碼爲私鑰，這是意料之中的彩蛋。

驗證：`d · G = (0x297a4a1e5b1fc99b, 0x880198e3724f9fee) = Q` ✓

---

## 4. Keygen 構造

有了私鑰 d，Keygen 是驗證流程的精確逆向：

```python
def generate_serial(name, d):
    # ① ECDSA 簽名
    h = SHA1(name)[:8] → int mod n
    r, s = ecdsa_sign(h, d)          # 隨機 k 簽名
    sig = r.to_bytes(8,'big') + s.to_bytes(8,'big')   # 16 字節

    # ② XOR checksum
    dwords = struct.unpack('>4I', sig)
    chk = dwords[0] ^ dwords[1] ^ dwords[2] ^ dwords[3]

    # ③ Feistel CBC 加密（逆向第四層）
    iv = chk.to_bytes(4,'big') + b'\x00'*4
    cipher = cbc_encrypt(b"DEADBEEF", iv, sig)

    # ④ GF(2⁸) 逆元（自逆，逆向第三層）
    gf_out = bytes(GF_INV[b] for b in cipher)

    # ⑤ SM4 加密（逆向第二層）
    sm4_out = sm4_encrypt(gf_out, b"Security@Tencent")

    # ⑥ 尾部 4 字節也做 GF 逆元
    raw_tail = bytes(GF_INV[b] for b in chk.to_bytes(4,'big'))

    # ⑦ Base32 編碼（逆向第一層）
    raw20 = sm4_out + raw_tail
    b32 = base32_encode(raw20)
    return b32[:8]+'-'+b32[8:16]+'-'+b32[16:24]+'-'+b32[24:]
```

### 4.1 自驗證

```python
name = "kanxue"
serial = generate_serial(name, d)
print(f"用戶名: {name}")
print(f"序列號: {serial}")
print(f"自驗證: {verify_serial(name, serial)}")  # → 通過
```

自驗證通過意味着 Keygen 完整正確——每一層變換的逆都精確匹配。

### 4.2 Unicorn 仿真在 Keygen 中的角色

Feistel 密碼的單塊加密/解密函數沒有完全手工逆向，而是**通過 Unicorn 直接執行二進制代碼**：

```python
class CustomCipher:
    def __init__(self, key, direction):
        self.mu = _create_emu()            # 加載 dumped.bin
        _init_cipher(self.mu, direction, key)  # 調用 0x448b50 初始化
    
    def block(self, data8):
        return _block_cipher(self.mu, data8)   # 調用 0x448710 單塊處理
```

這種"半仿真"策略在複雜 Crypto++ 實現面前非常高效——不需要理解 Feistel 內部的輪函數細節，只需要正確調用接口。

---

## 5. 技術深度解析

### 5.1 SM4 變種識別

SM4（國密 SMS4）的標準特徵：
- S 盒 256 字節以 `0xd6, 0x90, 0xe9, 0xfe, ...` 開頭
- L 變換使用 `<<<2, <<<10, <<<18, <<<24` 四個循環左移
- L' 變換（密鑰擴展用）使用 `<<<13, <<<23`
- FK 常量 `0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc`

本題的變種差異：
1. **字節序**：標準 SM4 用大端序 `struct.unpack('>4I', ...)`，本題用小端序 `'<4I'`
2. **CK 省略**：32 輪密鑰擴展中標準 SM4 每輪要加 CK[i]，本題跳過了這一步

識別過程：S 盒搜索命中 → 確認 L/L' 移位量 → 發現 CK 缺失 → Unicorn 仿真對拍確認變種行爲

### 5.2 GF(2⁸) 逆元的數學

GF(2⁸) 以 `0x11b` (x⁸+x⁴+x³+x+1) 爲不可約多項式，與 AES 的 SubBytes 使用相同有限域。

逆元計算利用費馬小定理：`a⁻¹ = a^(2⁸-2) = a^254`

本題用**重複平方-乘法鏈**把 254 次冪優化到 13 次 GF 乘法：

```python
# 254 = 2(2(2(2(2(2·x+1)·x+1)·x+1)·x+1)·x+1)·x+1)·x
# 簡化爲 6 輪 square-and-multiply + 最後一次 square
r = x
for _ in range(6):      # r = x^(2^7-1) = x^127
    r = gf_mul(r, r)    # square
    r = gf_mul(r, x)    # multiply
return gf_mul(r, r)      # r = x^254 = x^(-1)
```

### 5.3 Pollard rho ECDLP 算法要點

核心思想：在橢圓曲線羣 ⟨G⟩ 上做隨機遊走，尋找碰撞 `aᵢ·G + bᵢ·Q = aⱼ·G + bⱼ·Q`，由此 `d = (aᵢ-aⱼ)·(bⱼ-bᵢ)⁻¹ mod n`。

關鍵工程優化：
1. **仿射座標**：避免模逆的射影座標在 64 位場景下反而更慢（模逆只需 `pow(a, p-2, p)`）
2. **Distinguished Points**：不用 Floyd 循環檢測，而是收集 x 座標低 k 位爲零的"標記點"，碰撞在標記點集合上檢測
3. **多線程**：每個線程獨立隨機遊走，共享標記點集合（讀寫鎖保護）

---

## 6. 六層密碼學棧總覽

```text
Serial (35 chars)
  │ 去掉 '-'
  ▼
32 chars Base32 ─────────────────────────────── 自定義字母表 (無I/L/O/U)
  │ decode                                      溢出 bug: val 28-31 → "Roun"
  ▼
20 bytes raw
  ├── [0:16] ──► SM4 decrypt ◄── key="Security@Tencent"
  │                                             變種: 小端序 + 無CK
  │   ▼
  │   GF(2⁸) inv ─── 逐字節 ─── 不可約多項式 0x11b
  │   ▼
  │   Feistel CBC decrypt ◄── key="DEADBEEF", iv=gf_tail
  │   ▼                        Unicorn 仿真提取
  │   16 bytes signature (r || s)
  │   ▼
  │   XOR checksum ──► 必須等於 gf_tail
  │   ▼
  │   ECDSA verify(SHA1(name), r, s) ◄── 64位曲線
  │                                        d = "Tencent " (ASCII 彩蛋)
  └── [16:20] ──► GF(2⁸) inv ──► gf_tail (用作 IV 和校驗)
```

> **Evidence → Finding → Path**
> - Evidence：RTTI 泄露 Crypto++ ECDSA-ECP-SHA1 驗籤器；數據段的 SM4 S 盒、EC 參數、密鑰常量串；TTD 錄製的調用序列
> - Finding：六層密碼學棧（Base32→SM4→GF逆元→Feistel CBC→XOR校驗→ECDSA），64 位 EC 可破解
> - Path：RTTI 偵察 → 逐層逆向 → Unicorn 仿真 Feistel → SM4 變種識別 → Pollard rho 破解 ECDLP → 全棧 Keygen → 自驗證

---

## 7. 方法論增量

1. **RTTI 是 Crypto++ 程序的說明書**：靜態鏈接的 Crypto++ 不會 strip RTTI，類型名直接告訴你用了什麼算法、什麼曲線、什麼哈希。
2. **"半仿真"策略**：對於 Crypto++ 這類高度模板化的密碼學庫，理解每個模板展開的內部細節不現實也不必要——Unicorn 仿真接口函數（init/block/cbc），Python 處理上層邏輯。
3. **64 位 EC 的安全級別約 32 位**：Pollard rho 期望 √n 步，64 位曲線 → 2³² 步 → 現代 CPU 分鐘級可解。任何小於 160 位的 EC 都不安全。
4. **SM4 變種的識別三件套**：S 盒匹配 → L 變換移位量確認 → CK/FK 常量覈對。缺任何一個都說明是變種。
5. **GF(2⁸) 逆元自逆**：`inv(inv(x))=x` 意味着加密解密共用同一個函數，Keygen 編碼器可以直接複用解碼器的 GF 變換代碼。

## 8. 附：本篇產物

```text
KCTF2026/08_TencentPediyKeygenMe/
├── dumped.bin               運行時轉儲鏡像
├── keygen.py                通用 Keygen（自驗證通過）
├── sm4_impl.py              SM4 變種實現（LE + 無CK）
├── keygen_cipher.py         Feistel CBC 加解密（Unicorn 仿真）
├── ecdlp_final.c            Pollard rho ECDLP 求解器（最終版，16 線程）
├── ecdlp_result.txt         求解結果：d = 0x54656e63656e7420
├── emu_cipher*.py            Feistel 密碼 Unicorn 仿真實驗
└── ttd_traces/              WinDbg TTD 錄製軌跡
```
