# KCTF 03 - 金山2007 CrackMe (比特翻转 + BFS)

## 概况

| 属性 | 值 |
|------|---|
| 文件 | 金山2007.exe (Windows PE x86) |
| 平台 | Windows |
| 难度 | ★★★☆☆ |
| 核心技术 | 哈希函数逆向、比特翻转状态机、BFS 搜索 |

## 分析过程

### 第一步：用户名哈希

程序首先对用户名计算一个 32 位哈希值：

```python
def name_hash(name):
    h = 0x13572468
    for ch in name:
        eax = (ord(ch) + h) * 0x3721273 + 0x24681357
        # sar 7 (算术右移) + shl 25 组合旋转
        h = ((eax << 25) | (signed_eax >> 7)) & 0xFFFFFFFF
    return h
```

注意：这里使用的是 `sar`（算术右移），不是 `shr`（逻辑右移），负数情况下行为不同。

### 第二步：序列号验证

序列号每一位数字经过变换后得到一个 value（1-9），用来操作一个 9 位比特状态机：

- `value == 1`：无条件翻转 bit[1]
- `value == v (v>1)`：要求 bit[v-1]=1 且 bit[1..v-2]=0，翻转 bit[v]

初始状态由用户名哈希决定（bit[1..8] + bit[9]=1），目标是让所有比特归零。

### 第三步：期望值映射

```python
digit_i = (serial_char_i - expect_i) % 10
expect_i = (hash >> (i % 31)) % 10
```

## 算法还原

这本质上是一个**状态搜索问题**：从初始状态 s0 出发，通过一系列合法操作到达全零状态。

## 求解

使用 BFS（广度优先搜索）寻找最短操作序列：

```python
from collections import deque

q = deque([(s0, [])])
seen = {s0}
while q:
    s, seq = q.popleft()
    if s == 0:  # 找到！
        break
    for v in range(1, 10):
        ns = step(s, v)
        if ns is not None and ns not in seen:
            seen.add(ns)
            q.append((ns, seq + [v]))
```

序列号长度约 496 位。

## Flag

```
用户名: KCTF
序列号: (496位数字序列，见 serial.txt)
```

## 收获与技巧

1. **sar vs shr**：算术右移和逻辑右移的区别是逆向中的经典坑
2. **状态机建模**：把验证逻辑抽象为状态转移，用 BFS 搜索最优解
3. **离线验证**：自己实现一遍验证函数，确保 keygen 生成的序列号确实正确
