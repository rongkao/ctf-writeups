# KCTF 03 - 金山2007 CrackMe (比特翻轉 + BFS)

## 概況

| 屬性 | 值 |
|------|---|
| 文件 | 金山2007.exe (Windows PE x86) |
| 平臺 | Windows |
| 難度 | ★★★☆☆ |
| 核心技術 | 哈希函數逆向、比特翻轉狀態機、BFS 搜索 |

## 分析過程

### 第一步：用戶名哈希

程序首先對用戶名計算一個 32 位哈希值：

```python
def name_hash(name):
    h = 0x13572468
    for ch in name:
        eax = (ord(ch) + h) * 0x3721273 + 0x24681357
        # sar 7 (算術右移) + shl 25 組合旋轉
        h = ((eax << 25) | (signed_eax >> 7)) & 0xFFFFFFFF
    return h
```

注意：這裏使用的是 `sar`（算術右移），不是 `shr`（邏輯右移），負數情況下行爲不同。

### 第二步：序列號驗證

序列號每一位數字經過變換後得到一個 value（1-9），用來操作一個 9 位比特狀態機：

- `value == 1`：無條件翻轉 bit[1]
- `value == v (v>1)`：要求 bit[v-1]=1 且 bit[1..v-2]=0，翻轉 bit[v]

初始狀態由用戶名哈希決定（bit[1..8] + bit[9]=1），目標是讓所有比特歸零。

### 第三步：期望值映射

```python
digit_i = (serial_char_i - expect_i) % 10
expect_i = (hash >> (i % 31)) % 10
```

## 算法還原

這本質上是一個**狀態搜索問題**：從初始狀態 s0 出發，通過一系列合法操作到達全零狀態。

## 求解

使用 BFS（廣度優先搜索）尋找最短操作序列：

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

序列號長度約 496 位。

## Flag

```
用戶名: KCTF
序列號: (496位數字序列，見 serial.txt)
```

## 收穫與技巧

1. **sar vs shr**：算術右移和邏輯右移的區別是逆向中的經典坑
2. **狀態機建模**：把驗證邏輯抽象爲狀態轉移，用 BFS 搜索最優解
3. **離線驗證**：自己實現一遍驗證函數，確保 keygen 生成的序列號確實正確
