# 07 CORE Official CrackMe v2.0

**难度**: 89 | **平台**: Windows PE32 | **结果**: 通用 Keygen

## 算法

1. `hash_input = name + strrev(name) × 3`（注册表查询是烟雾弹）
2. **魔改 MD5**：标准压缩函数 + off-by-one 长度字段 `(len+1)*8`
3. 取 digest 前 12 字节 → 3 个 32 位比较目标 m0, m1, m2
4. **GF(2) 64×64 线性变换**（双重）：可逆，高斯消元求逆矩阵
5. `code = "%x %x %x"`（空格分隔，sscanf `%lx%lx%lx` 解析）

## 关键技术

- **魔改 MD5 定位之旅**：所有 MD5 要素逐一标准 → Unicorn 仿真证明压缩函数标准 → 定位 off-by-one（先写 0x80 再测长度）
- **GF(2) 矩阵求逆**：从 dumped.bin 提取 4 张 64 项表（T1A/T1B/T2A/T2B），构建 64×64 矩阵后高斯消元
- **栈上地面真值法**：弹窗挂起时 ReadProcessMemory 全内存遍历，直接读出 MD5 期望值

## Keygen

```python
def keygen(name):
    m0, m1, m2, _ = custom_md5((name + name[::-1]*3).encode())
    v2a, v3 = gf2_inv2(m1, m2)
    v1, v2 = gf2_inv1(m0, v2a)
    return f'{v1:x} {v2:x} {v3:x}'
```

## 验证

真机弹窗: **"Man, you're good enough to join CORE!"** ✓

详细分析见 [docs/writeup](../../docs/2026-09-21_CTF-KCTF-CORE-CrackMe-v2-writeup.md)
