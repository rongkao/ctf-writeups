# KCTF 01 - rechall (z3 約束求解)

## 概況

| 屬性 | 值 |
|------|---|
| 文件 | rechall.exe (Windows PE x86) |
| 平臺 | Windows |
| 難度 | ★★☆☆☆ |
| 核心技術 | z3 約束求解、位運算逆向 |

## 分析過程

程序輸入格式爲 `flag{xxxxxxxx-xxxxxxxx-xxxxxxxx-xxxxxxxx}`，其中每段是 8 位十六進制數（對應一個 32 位整數）。

通過 IDA/x64dbg 反編譯，發現程序內部有 4 個獨立的 checker 函數，分別對 4 個整數 x1~x4 施加複雜的位運算約束。

### Checker 1 — 簡單減法
```
x1 - 0x5294b771 == 0x956438b9
```
直接求解：`x1 = 0x5294b771 + 0x956438b9 = 0xe7f8f02a`

### Checker 2 — 位運算組合
```python
~((3 * (x2 & 0x52e3f96b) - (x2 | 0xad1c0694)) - x2 + 0x5a380d28) == 0xc2407eea
```

### Checker 3/4 — 多重位運算混合
涉及 AND、OR、XOR、NOT、移位等操作組合，手動求解極其困難。

## 算法還原

程序驗證邏輯可以概括爲：4 個 32 位整數分別滿足 4 個位運算等式。由於位運算的非線性特徵，手工求解不現實。

## 求解

使用 z3 SMT 求解器建模所有約束，一次性求解：

```python
from z3 import *

x1, x2, x3, x4 = BitVecs('x1 x2 x3 x4', 32)
s = Solver()
s.add(x1 - 0x5294b771 == 0x956438b9)
s.add(~((3 * (x2 & 0x52e3f96b) - (x2 | 0xad1c0694)) - x2 + 0x5a380d28) == 0xc2407eea)
# ... checker3, checker4 ...
s.check()  # sat
```

最終通過 MD5 校驗確認解的正確性。

## Flag

```
flag{e7f8f02a-90a38781-054d1c1b-0ddf83d6}
MD5: f2d5f978de74c1ce7a9ff53461ca3fd2
```

## 收穫與技巧

1. **z3 是逆向的利器**：面對複雜位運算約束，z3 比手動推導快幾個數量級
2. **BitVec 精度**：使用 `BitVec('x', 32)` 而非普通整數，才能正確處理溢出和移位
3. **ULE 約束**：z3 的 `ULE()` 處理無符號比較，對應彙編中的 `jbe` 指令
