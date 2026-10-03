# KCTF 01 - rechall (z3 约束求解)

## 概况

| 属性 | 值 |
|------|---|
| 文件 | rechall.exe (Windows PE x86) |
| 平台 | Windows |
| 难度 | ★★☆☆☆ |
| 核心技术 | z3 约束求解、位运算逆向 |

## 分析过程

程序输入格式为 `flag{xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx}`，其中每段是 8 位十六进制数（对应一个 32 位整数）。

通过 IDA/x64dbg 反编译，发现程序内部有 4 个独立的 checker 函数，分别对 4 个整数 x1~x4 施加复杂的位运算约束。

### Checker 1 — 简单减法
```
x1 - 0x5294b771 == 0x956438b9
```
直接求解：`x1 = 0x5294b771 + 0x956438b9 = 0xe7f8f02a`

### Checker 2 — 位运算组合
```python
~((3 * (x2 & 0x52e3f96b) - (x2 | 0xad1c0694)) - x2 + 0x5a380d28) == 0xc2407eea
```

### Checker 3/4 — 多重位运算混合
涉及 AND、OR、XOR、NOT、移位等操作组合，手动求解极其困难。

## 算法还原

程序验证逻辑可以概括为：4 个 32 位整数分别满足 4 个位运算等式。由于位运算的非线性特征，手工求解不现实。

## 求解

使用 z3 SMT 求解器建模所有约束，一次性求解：

```python
from z3 import *

x1, x2, x3, x4 = BitVecs('x1 x2 x3 x4', 32)
s = Solver()
s.add(x1 - 0x5294b771 == 0x956438b9)
s.add(~((3 * (x2 & 0x52e3f96b) - (x2 | 0xad1c0694)) - x2 + 0x5a380d28) == 0xc2407eea)
# ... checker3, checker4 ...
s.check()  # sat
```

最终通过 MD5 校验确认解的正确性。

## Flag

```
flag{e7f8f02a-90a38781-054d1c1b-0ddf83d6}
MD5: f2d5f978de74c1ce7a9ff53461ca3fd2
```

## 收获与技巧

1. **z3 是逆向的利器**：面对复杂位运算约束，z3 比手动推导快几个数量级
2. **BitVec 精度**：使用 `BitVec('x', 32)` 而非普通整数，才能正确处理溢出和移位
3. **ULE 约束**：z3 的 `ULE()` 处理无符号比较，对应汇编中的 `jbe` 指令
