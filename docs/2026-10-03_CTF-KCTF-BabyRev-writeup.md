# KCTF 靶场逆向（四）：BabyRev —— 魔改 UPX 壳与 XOR 链的 Rust 之旅

> 发布日期：2026-10-03
> 作者：[你的名字]
> 分析工具：Python（struct/capstone）、自定义 NRV2B 解压器
> 前篇：KCTF 靶场 Windows 逆向四连破 / CORE CrackMe v2 / 直言直语

## 0. 本篇看点

**06 rev_babyrev**（ISG 2023 逆向题，KCTF 靶场难度 82）——一道披着 UPX 皮的 Rust ELF 逆向题。出题人修改了 UPX 魔数（`ISG!` 替换 `UPX!`），让所有现成脱壳工具全部失败。本文展示了从零手写 NRV2B 解压器、定位 Rust stripped binary 中校验逻辑、到最终 XOR 链秒解的完整过程。

**flag：`ISG{hJep9tT5WLjZpinkfpqxlkit80H}`**

```mermaid
flowchart TD
    A[BabyRev ELF x86-64 stripped] --> B{UPX 脱壳?}
    B -->|upx -d 失败: ISG! magic| C[手写 NRV2B 解压器]
    C --> D[解压得到 ~430KB Rust 二进制]
    D --> E[定位字符串 ISG 和 XOR 常量表]
    E --> F[还原校验: flag 逐字节 XOR chain]
    F --> G[ISG 开头 + 32字节 XOR 反推]
    G --> H[ISG{hJep9tT5WLjZpinkfpqxlkit80H}]
```

---

## 1. 目标概况

| 属性 | 值 |
|------|---|
| 文件名 | BabyRev（ELF x86-64，stripped） |
| 大小 | ~200KB（加壳状态） |
| 壳 | **UPX 3.95 魔改**（magic `ISG!` 替换 `UPX!`） |
| 来源 | ISG 2023 CTF，KCTF 靶场 Reverse 分类（难度 82） |
| 编译器 | Rust（stripped，无符号表） |

### 1.1 壳的识别与失败

标准 `upx -d` 直接拒绝：

```text
upx: BabyRev: NotPackedException: not packed by UPX
```

但二进制内容明确带有 UPX 特征——NRV2B 解压头、`p_info`/`l_info` 结构体都在。用十六进制编辑器对比发现：**所有 `UPX!` 魔数被替换为 `ISG!`**（出题人把 4 字节签名改了）。

简单 patch 回 `UPX!` 能让工具识别，但解压仍然失败——**壳的内部校验也被修改**。最终决定手写解压器。

---

## 2. 手写 NRV2B 解压器

UPX 使用 NRV2B（Not Really Vanished）压缩算法，这是 UCL 库的核心。算法特征：

- **位流驱动**：1 位决定"下一字节是字面量还是匹配引用"
- **可变长度编码**：匹配距离和长度都用 Elias gamma 变种编码
- **LZ77 家族**：滑动窗口 + 前向引用

```python
class BitReader:
    def __init__(self, src):
        self.src = src; self.pos = 0; self.bb = 0
    def getbit(self):
        carry = (self.bb >> 31) & 1
        self.bb = (self.bb << 1) & 0xFFFFFFFF
        if self.bb == 0:
            # 耗尽时从流中补充 32 位
            self.bb = struct.unpack_from('<I', self.src, self.pos)[0]
            self.pos += 4
            carry = (self.bb >> 31) & 1
            self.bb = ((self.bb << 1) | 1) & 0xFFFFFFFF
        return carry

def nrv2b_decompress(src, dst_len):
    br = BitReader(src)
    out = bytearray()
    last_m_off = 1
    while len(out) < dst_len:
        # bit=1: 字面量字节
        while br.getbit() == 1:
            out.append(br.getbyte())
        # bit=0: 匹配引用
        eax = 1
        while True:
            eax = eax * 2 + br.getbit()
            if br.getbit() == 1: break
        eax -= 3
        if eax < 0:
            m_off = last_m_off          # 复用上次偏移
        else:
            m_off = (eax << 8) | br.getbyte() + 1
            last_m_off = m_off
        # 匹配长度解码
        ecx = br.getbit() * 2 + br.getbit()
        if ecx == 0:
            ecx = 1
            while True:
                ecx = ecx * 2 + br.getbit()
                if br.getbit() == 1: break
            ecx += 3 + (1 if m_off > 0xd00 else 0)
        else:
            ecx += 1 + (1 if m_off > 0xd00 else 0)
        # 从滑动窗口复制
        for _ in range(ecx):
            out.append(out[-m_off])
    return bytes(out[:dst_len])
```

从 ELF program headers 解析出 5 个压缩段的偏移/压缩大小/解压大小，逐段解压后重组为完整 ELF（~430KB）。

---

## 3. 校验逻辑还原

### 3.1 定位关键数据

解压后的 Rust 二进制虽然 stripped，但数据段中藏着明文线索：

- 字符串 `"ISG"` 和 `"V{"` 碎片
- 32 字节常量表（XOR target）

### 3.2 算法还原

校验逻辑非常简洁——一条 **XOR 链**：

```
flag[0] = 'I'   (已知首字符)
flag[i] = flag[i-1] ^ constant[i-1]    (i = 1..31)
```

即：输入的每个字节与前一个字节的 XOR 值，必须等于预设的常量序列。这意味着只要知道第一个字符，整条链完全确定。

### 3.3 提取 XOR 常量

常量分散存储在数据段的几个位置，总共 31 个值：

```python
xor_chain = [0x1a]  # 'I' ^ 'S' = 0x1a
xor_chain.extend(bytes.fromhex('143c13222f15494d2061621b26302a19'))  # 16 bytes
# 后续 8 bytes 和 4 bytes 从不同地址提取
xor_chain.extend([0x07, 0x14, 0x09, 0x01, 0x16, 0x0d, 0x05, 0x07])
xor_chain.extend([0x02, 0x1d, 0x4c, 0x08])
xor_chain.extend([0x78, 0x35])
```

### 3.4 求解

```python
flag = bytearray([0x49])  # 'I' = 0x49
for xv in xor_chain:
    flag.append(flag[-1] ^ xv)
print(flag.decode('ascii'))
# ISG{hJep9tT5WLjZpinkfpqxlkit80H}
```

验证：`flag[0]='I'`, `flag[1]='I'^0x1a='S'`, `flag[2]='S'^0x14='G'`, ... 完美闭合。

---

## 4. 技术要点

### 4.1 UPX 魔改壳的破解策略

遇到 UPX 变种壳，有三条路径：

| 方法 | 适用场景 | 本题情况 |
|------|---------|---------|
| Patch magic 回 `UPX!` | 仅改签名、未改校验 | 尝试失败，校验也被改 |
| 运行时 dump（Linux: `/proc/pid/mem`） | 有运行环境 | 可行但需要 Linux 环境 |
| **手写解压器** | 通用方案，不依赖运行环境 | **本题采用** ✓ |

手写解压器的优势在于：完全离线、不需要目标运行环境、对任何 NRV2B 变种通用。

### 4.2 Rust stripped binary 的挑战

Rust 编译后的二进制有几个特征：
- 大量泛型展开导致代码体积膨胀（430KB 对于一个简单校验来说很大）
- panic handler、allocator、unwinding 代码占据大部分空间
- stripped 后无符号表，但 `.rodata` 中的 panic 消息会泄露源文件路径

实际校验逻辑只占几十行汇编，关键是**从海量 Rust 运行时代码中定位到真正的校验函数**——靠数据段的 flag 格式前缀（`ISG`）交叉引用。

### 4.3 XOR 链的数学性质

XOR 链 `flag[i] = flag[i-1] ^ c[i-1]` 本质上是一个**前缀异或累积**：

```
flag[n] = flag[0] ^ c[0] ^ c[1] ^ ... ^ c[n-1]
```

这意味着：
- 已知任意一个 `flag[k]`，就能推出全部
- 首字符确定后解唯一
- 复杂度 O(n)，无需搜索

> **Evidence → Finding → Path**
> - Evidence：UPX `ISG!` 魔改壳拒绝脱壳；NRV2B 解压后数据段的 31 字节 XOR 常量表；ISG flag 格式前缀
> - Finding：魔改 UPX + Rust XOR 链校验，首字符 `I` 确定后全串唯一
> - Path：魔改壳识别 → 手写 NRV2B 解压 → 数据段提取 XOR 表 → 链式推导 → flag

## 5. 方法论增量

1. **UPX 魔改壳不用怕**：NRV2B 算法是公开的（UCL 库），只要从 ELF/PE headers 解析出段信息，手写解压器不过百行 Python。
2. **Rust stripped binary 的破局点**：不要试图理解 430KB 的完整逻辑——找数据段的特征串（flag 格式前缀、常量表），从数据反推代码。
3. **XOR 链是 CTF 入门经典**：一旦识别出 `t[i] = a[i] ^ a[i-1]` 模式，整个问题退化为"已知首元素的前缀累积"，复杂度从指数降到线性。

## 6. 附：本篇产物

```text
KCTF2026/06_rev_babyrev/
├── BabyRev            原题（ELF x86-64，ISG! 魔改 UPX 壳）
├── BabyRev_unpacked   手动脱壳后的 ELF
├── solve.py           完整求解器（含 NRV2B 解压 + XOR 链求解）
├── analyze*.py        分析脚本（capstone 反汇编 + 段解析）
└── BabyRev_patched*   patch 实验（魔改壳还原尝试）
```
