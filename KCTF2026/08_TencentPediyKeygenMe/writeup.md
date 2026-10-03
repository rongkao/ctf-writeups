# 08 TencentPediyKeygenMe (2010 騰訊看雪競賽)

**難度**: 95 (全站最高) | **平臺**: Windows PE32 | **結果**: 通用 Keygen

## 算法 — 六層密碼學棧

```
Serial → Base32 decode → SM4 decrypt → GF(2⁸) inv → Feistel CBC decrypt → XOR checksum → ECDSA verify
```

1. **Base32** 自定義字母表 `ABCDEFGHJKMNPQRSTVWXYZ1234567890`（溢出 bug: val 28-31 → "Roun"）
2. **SM4 變種** 密鑰 `Security@Tencent`（小端序 + 無 CK 常量）
3. **GF(2⁸) 逆元** 不可約多項式 0x11b（自逆：加密解密共用）
4. **Feistel CBC** 密鑰 `DEADBEEF`，IV 來自 GF 尾部
5. **XOR 校驗和** 4 個大端 dword XOR = 尾部 4 字節
6. **ECDSA 驗籤** 64 位橢圓曲線，SHA1(name)

## 破解 ECDLP

| 參數 | 值 |
|------|---|
| 曲線階 n | `0xc564eef19a080b07` (64 bit) |
| 私鑰 d | `0x54656e63656e7420` = ASCII **"Tencent "** |
| 求解方法 | Pollard rho (16 線程, ~9 分鐘) |
| 總步數 | 4244M |

## Keygen

```python
def generate_serial(name, d):
    h = SHA1(name)[:8]
    r, s = ecdsa_sign(h, d)
    sig = r || s  # 16 bytes
    → XOR checksum → Feistel CBC encrypt → GF inv → SM4 encrypt → Base32 encode
    → 插入 '-' 分隔符 → 35 字符序列號
```

## 驗證

數學驗證: d·G = Q ✓ | 簽名自驗證 ✓

詳細分析見 [docs/writeup](../../docs/2026-10-03_CTF-KCTF-TencentPediyKeygenMe-writeup.md)
