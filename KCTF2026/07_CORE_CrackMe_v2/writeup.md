# 07 CORE Official CrackMe v2.0

**難度**: 89 | **平臺**: Windows PE32 | **結果**: 通用 Keygen

## 算法

1. `hash_input = name + strrev(name) × 3`（註冊表查詢是煙霧彈）
2. **魔改 MD5**：標準壓縮函數 + off-by-one 長度字段 `(len+1)*8`
3. 取 digest 前 12 字節 → 3 個 32 位比較目標 m0, m1, m2
4. **GF(2) 64×64 線性變換**（雙重）：可逆，高斯消元求逆矩陣
5. `code = "%x %x %x"`（空格分隔，sscanf `%lx%lx%lx` 解析）

## 關鍵技術

- **魔改 MD5 定位之旅**：所有 MD5 要素逐一標準 → Unicorn 仿真證明壓縮函數標準 → 定位 off-by-one（先寫 0x80 再測長度）
- **GF(2) 矩陣求逆**：從 dumped.bin 提取 4 張 64 項表（T1A/T1B/T2A/T2B），構建 64×64 矩陣後高斯消元
- **棧上地面真值法**：彈窗掛起時 ReadProcessMemory 全內存遍歷，直接讀出 MD5 期望值

## Keygen

```python
def keygen(name):
    m0, m1, m2, _ = custom_md5((name + name[::-1]*3).encode())
    v2a, v3 = gf2_inv2(m1, m2)
    v1, v2 = gf2_inv1(m0, v2a)
    return f'{v1:x} {v2:x} {v3:x}'
```

## 驗證

真機彈窗: **"Man, you're good enough to join CORE!"** ✓

詳細分析見 [docs/writeup](../../docs/2026-09-21_CTF-KCTF-CORE-CrackMe-v2-writeup.md)
