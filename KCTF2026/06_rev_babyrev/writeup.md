# 06 BabyRev (ISG 2023)

**难度**: 82 | **平台**: Linux ELF x86-64 (Rust) | **Flag**: `ISG{hJep9tT5WLjZpinkfpqxlkit80H}`

## 算法

32 字节 XOR 链：`flag[i] = flag[i-1] ^ constant[i-1]`，首字符 `'I'` 已知。

## 关键技术

- **UPX 3.95 魔改壳**：magic `ISG!` 替换 `UPX!`，标准脱壳工具全部失败
- **手写 NRV2B 解压器**：从 ELF program headers 解析 5 个压缩段，逐段解压重组
- **Rust stripped binary**：430KB 运行时代码中定位几十行校验逻辑，靠 `ISG` 前缀交叉引用

## 求解

```python
xor_chain = [0x1a, 0x14, 0x3c, ...]  # 31 个常量值
flag = bytearray([0x49])  # 'I'
for xv in xor_chain:
    flag.append(flag[-1] ^ xv)
# ISG{hJep9tT5WLjZpinkfpqxlkit80H}
```

详细分析见 [docs/writeup](../../docs/2026-10-03_CTF-KCTF-BabyRev-writeup.md)
