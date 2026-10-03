# 06 BabyRev (ISG 2023)

**難度**: 82 | **平臺**: Linux ELF x86-64 (Rust) | **Flag**: `ISG{hJep9tT5WLjZpinkfpqxlkit80H}`

## 算法

32 字節 XOR 鏈：`flag[i] = flag[i-1] ^ constant[i-1]`，首字符 `'I'` 已知。

## 關鍵技術

- **UPX 3.95 魔改殼**：magic `ISG!` 替換 `UPX!`，標準脫殼工具全部失敗
- **手寫 NRV2B 解壓器**：從 ELF program headers 解析 5 個壓縮段，逐段解壓重組
- **Rust stripped binary**：430KB 運行時代碼中定位幾十行校驗邏輯，靠 `ISG` 前綴交叉引用

## 求解

```python
xor_chain = [0x1a, 0x14, 0x3c, ...]  # 31 個常量值
flag = bytearray([0x49])  # 'I'
for xv in xor_chain:
    flag.append(flag[-1] ^ xv)
# ISG{hJep9tT5WLjZpinkfpqxlkit80H}
```

詳細分析見 [docs/writeup](../../docs/2026-10-03_CTF-KCTF-BabyRev-writeup.md)
