# 08 TencentPediyKeygenMe (2010 腾讯看雪竞赛)

**难度**: 95 (全站最高) | **平台**: Windows PE32 | **结果**: 通用 Keygen

## 算法 — 六层密码学栈

```
Serial → Base32 decode → SM4 decrypt → GF(2⁸) inv → Feistel CBC decrypt → XOR checksum → ECDSA verify
```

1. **Base32** 自定义字母表 `ABCDEFGHJKMNPQRSTVWXYZ1234567890`（溢出 bug: val 28-31 → "Roun"）
2. **SM4 变种** 密钥 `Security@Tencent`（小端序 + 无 CK 常量）
3. **GF(2⁸) 逆元** 不可约多项式 0x11b（自逆：加密解密共用）
4. **Feistel CBC** 密钥 `DEADBEEF`，IV 来自 GF 尾部
5. **XOR 校验和** 4 个大端 dword XOR = 尾部 4 字节
6. **ECDSA 验签** 64 位椭圆曲线，SHA1(name)

## 破解 ECDLP

| 参数 | 值 |
|------|---|
| 曲线阶 n | `0xc564eef19a080b07` (64 bit) |
| 私钥 d | `0x54656e63656e7420` = ASCII **"Tencent "** |
| 求解方法 | Pollard rho (16 线程, ~9 分钟) |
| 总步数 | 4244M |

## Keygen

```python
def generate_serial(name, d):
    h = SHA1(name)[:8]
    r, s = ecdsa_sign(h, d)
    sig = r || s  # 16 bytes
    → XOR checksum → Feistel CBC encrypt → GF inv → SM4 encrypt → Base32 encode
    → 插入 '-' 分隔符 → 35 字符序列号
```

## 验证

数学验证: d·G = Q ✓ | 签名自验证 ✓

详细分析见 [docs/writeup](../../docs/2026-10-03_CTF-KCTF-TencentPediyKeygenMe-writeup.md)
