# KCTF 02 - 跃跃欲试 (ASPack 脱壳 + 约束提取)

## 概况

| 属性 | 值 |
|------|---|
| 文件 | 跃跃欲试.exe (Windows PE x86, ASPack 加壳) |
| 平台 | Windows |
| 难度 | ★★★☆☆ |
| 核心技术 | ASPack 运行时脱壳、capstone 反汇编、约束自动提取 |

## 分析过程

### 第一步：脱壳

程序使用 ASPack 加壳保护。运行程序后，使用调试器在 OEP 处 dump 内存获得脱壳后的 `dumped.bin`。

### 第二步：定位校验逻辑

在脱壳后的二进制中搜索字符串和调用链，定位到校验函数在偏移 `0x2811a4-0x28129f` 范围内。

### 第三步：自动提取约束

校验函数对 16 字节 key 逐字节检查，使用了三种模式：

1. **直接比较**: `cmp byte ptr [ebp - X], imm` — 直接得到字节值
2. **加法比较**: `movsx eax, buf[i]` → `add eax, imm` → `cmp eax, target` — 反推 `buf[i] = target - imm`
3. **双字节加法**: `buf[i] + buf[j] == target` — 已知一个字节后推导另一个

## 算法还原

```python
# 栈偏移 → buf 索引: buf 基址 ebp-0x240
def idx_of(disp):
    return 0x240 - disp  # buf[i] = [ebp-(0x240-i)]
```

使用 capstone 反汇编引擎自动解析指令流，逐步提取所有约束条件。

## 求解

```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
# 解析指令流，自动提取 16 字节 key
key = ''.join(chr(solved.get(i, 0x3F)) for i in range(16))
```

## Flag

```
KEY = BZ9dmq4c8g9G7bAY
```

## 收获与技巧

1. **ASPack 脱壳**：ESP 定律或硬件断点跟踪，在 OEP 处 dump
2. **capstone 自动化**：用 Python + capstone 编写指令模式匹配器，避免手动分析上百条指令
3. **约束传播**：已求解的字节可以用来推导有依赖关系的未知字节
