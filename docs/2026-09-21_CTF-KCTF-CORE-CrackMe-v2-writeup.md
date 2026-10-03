# KCTF 靶场 Windows 逆向（二）：CORE 官方 CrackMe v2.0 完全攻破

> 发布日期：2026-09-21
> 作者：[你的名字]
> 分析工具：Python（capstone/Unicorn/pywinauto）、ReadProcessMemory 内存转储、WinDbg TTD
> 前篇：KCTF 靶场 Windows 逆向四连破（rechall/跃跃欲试/金山2007/CCG）

## 0. 本篇看点

**CORE Official CrackMe v2.0**（KCTF 靶场难度 89，全站第二难）——出自 1990 年代世界顶尖破解组织 CORE 的成员 Egis 之手。本文完整记录从零到通用 Keygen 的全过程，包括三次方向修正：

1. 老版 UPX 壳拒绝 `upx -d` → 运行时内存转储绕过
2. GF(2) 64×64 线性变换的建模与求逆（对栈上真值验证）
3. **魔改 MD5 的定位之旅**：所有 MD5 要素逐一验证均标准 → 暴力拟合 X 序失败 → Unicorn 直接仿真二进制代码证明压缩函数标准 → 最终锁定 **off-by-one 长度字段**

最终 Keygen 真机验证通过：程序弹出 *"Man, you're good enough to join CORE!"*

```mermaid
flowchart TD
    A[CRACKME3.EXE 老版 UPX] -->|upx -d 失败: obsolete version| B[运行时 ReadProcessMemory 转储]
    B --> C[定位校验函数 0x401610]
    C --> D[sscanf %lx%lx%lx 解析三段十六进制]
    C --> E[MD5 变换链]
    C --> F[GF(2) 64位变换 ×2]
    D --> G{逐一比对}
    E --> G
    F --> G
    G -->|全等| H[Welcome 弹窗]
    G -->|不等| I[Failed 弹窗]
    E -.魔改点.-> J[长度字段 = len+1 × 8]
```

---

## 1. 目标概况

| 属性 | 值 |
|------|---|
| 文件名 | CRACKME3.EXE（PE32，Egis/CORE 出品） |
| 大小 | 62,511 字节（UPX 壳，解压后 224KB） |
| 窗口标题 | CORE Official CrackMe v2.0 - Written by Egis/CORE |
| 输入 | Name + Registration Code（Code 为空格分隔的三段十六进制） |
| 成功标志 | 弹窗 "Man, you're good enough to join CORE!" |

### 1.1 脱壳

节名 `UPX0-3` 是标准 UPX 布局，但 `upx -d` 拒绝：

```text
CantUnpackException: this program is packed with an obsolete version
```

1997 年的 UPX 0.x 格式与现代工具不兼容。沿用第一篇的方法论——**等程序进入消息循环后 ReadProcessMemory 全量转储**（壳已自解压，代码明文化，且不触发任何反调试）：

```python
h = k32.OpenProcess(0x410, False, pid)
for off in range(0, 0x38000, 0x1000):
    k32.ReadProcessMemory(h, ctypes.c_void_p(0x400000+off), ...)
```

转储后明文字符串齐现：`Registered`、`... Better luck next time ...`、`... Hmmm, you don't even pass the first threshold ...`（sscanf 失败分支）、`%lx%lx%lx`。

> 顺带一提：TTD 录制启动会触发壳的单步陷阱（0x80000004）+ 栈溢出陷阱（0xC00000FD）直接崩死——本题反调试情报正来自第一篇的 TTD 侦察法。

---

## 2. 校验逻辑还原（0x402100 对话框过程）

### 2.1 输入处理

```c
GetDlgItemTextA(1000, name, 100);    // [ebp-0x608]
GetDlgItemTextA(1001, code, 100);    // [ebp-0x414]
```

**MD5 输入串构造**（本题第一个小陷阱）：

```c
strcpy(buf220, name);
strrev(buf220);                       // 0x408d70 = strrev
strcat(buf608, buf220);               // append #1: name + rev
RegOpenKeyA(HKLM, buf66c, &hkey);     // 打开注册表键
RegQueryValueExA(hkey, "Product..", ...);   // 值不存在 → buf220 不变！
strcat(buf608, buf220);               // append #2
RegQueryValueExA(hkey, "Registered", ...);  // 同上失败
strcat(buf608, buf220);               // append #3
// 最终: buf608 = name + strrev(name) × 3
```

两次 `RegQueryValueExA` 各有 **6 个参数**（含 reserved=0）——数错成 5 个会误判为 RegSetValueA。注册表值不存在时查询失败，缓冲区保持 strrev 内容——这段"注册表舞蹈"是纯烟雾弹。

**Code 解析**：

```c
if (sscanf(code, "%lx%lx%lx", &v1, &v2, &v3) != 3) → "Hmmm..." 弹窗
```

注意 `%lx` 无宽度限制会贪婪吞掉所有十六进制字符——**三段值必须用非十六进制字符分隔**，空格是最自然的选择。

### 2.2 GF(2) 双重变换链

两次调用 `0x401ad0(值指针, 表A, 表B)`，64 位就地变换：

```asm
; 每个输出位 = parity(a_lo & PA[i]) ^ parity(a_hi & PB[i])
; 两段 32 步循环（MSB 先入），表各 64 项
movsx eax, byte ptr ... 
and   eax, [ebx]        ; a_hi & 表B[i]
call  0x401ab0          ; popcount
xor   edx, eax
and   edx, 1            ; parity
add   edi, edi          ; acc = acc*2 + bit
```

调用链：

```c
f1(&v1, T1A@0x41c2c0, T1B@0x41c3c0);   // (v1,v2) → (v1', v2a)
f2(&v2, T2A@0x41c4c0, T2B@0x41c5c0);   // (v2a,v3) → (v2'', v3')
if (v1'==m0 && v2''==m1 && v3'==m2)    // m* = "MD5" 前 12 字节
    → Welcome!
```

这正是 GF(2) 上的 64×64 矩阵乘法（T1b 表呈完美 LFSR 移位结构）。**线性变换必可逆**——把 64 行矩阵高斯消元求逆即可反向解出合法 code：

```python
def gf2_inverse(rows):
    aug = [rows[j] | (1 << (64 + j)) for j in range(64)]
    for col in range(64):
        piv = next(r for r in range(col, 64) if (aug[r] >> col) & 1)
        aug[col], aug[piv] = aug[piv], aug[col]
        for r in range(64):
            if r != col and (aug[r] >> col) & 1:
                aug[r] ^= aug[col]
    return [a >> 64 for a in aug]
```

---

## 3. 魔改 MD5 定位之旅（本篇精髓）

GF(2) 模型很快对栈上真值验证通过，但比较目标 `m0/m1/m2` 与标准 MD5(name+rev×3) 对不上。排查过程：

| 步骤 | 检查项 | 结论 |
|------|--------|------|
| 1 | init IV（0x4014e0） | 标准 67452301/... ✓ |
| 2 | T 常量表（4×16 项，散布在 0x41c1c0-0x41c2bf） | 与 RFC 1321 逐项比对，全部标准 |
| 3 | 移位量 7,12,17,22/5,9,14,20/4,11,16,23/6,10,15,21 | 全部标准 |
| 4 | F/G/H/I 布尔函数 | 标准 |
| 5 | X 消息字序（round2 索引 1,6,11,0 即 +5；round4 循环 +0xC 恰为 4×7 mod 16） | 全部标准 |
| 6 | 尾部 IV 回加 | 存在 ✓ |
| 7 | 暴力拟合：round2/3/4 的（步长,起始）全空间 | **全部不匹配** |
| 8 | 比较目标是否硬编码常量 | 不在镜像中 |
| 9 | **Unicorn 直接仿真 0x401500 二进制代码** | 输出 = 标准 MD5！ |

第 9 步是转折点：压缩函数本身标准，问题必然在**进入压缩函数之前**。回读 padding 构造代码，发现致命细节：

```asm
0x4022c7: mov byte ptr [ebx + ecx], 0x80   ; buf[len] = 0x80  ← 先写填充字节！
...
0x4022e7: (strlen(buf608) 第 2 次)          ; 此时 0x80 已计入
0x4022f9: shl eax, 3                        ; bit 长度 = (len+1) × 8  ← off-by-one！
0x402306: mov [esi + edx - 8], eax          ; 写入长度字段
```

**程序在写入 0x80 之后再测长度**，长度字段 = `(真实长度+1)×8`。对 16 字节消息，标准 MD5 长度字段是 128，此程序写入 **136**。一个字节的差，整个哈希面目全非。

Unicorn 仿真 + 修正 padding 后，输出与栈上真值**精确匹配**：

```text
仿真: c6c0a6a4 fd5b4cb6 ed9b5781 182d2423   ← 与弹窗挂起时栈上比较目标一致
```

---

## 4. Keygen

```python
def custom_md5(msg):                     # 标准 MD5 压缩 + off-by-one 长度
    buf = msg + b'\x80'
    while len(buf) % 64 < 56: buf += b'\x00'
    buf += struct.pack('<I', (len(msg)+1)*8) + b'\x00'*4   # ← 魔改点
    ...标准 64 步压缩...

def keygen(name):
    m0, m1, m2, _ = custom_md5((name + name[::-1]*3).encode())
    v2a, v3 = f2inv(m1, m2)              # GF(2) 逆变换 2
    v1, v2  = f1inv(m0, v2a)             # GF(2) 逆变换 1
    return f'{v1:x} {v2:x} {v3:x}'       # 空格分隔，喂给 sscanf %lx%lx%lx
```

真机验证（pywinauto 自动填入 + 点击）：

```text
name='test' code='c63f3c7a edd4310d 38477391'
>>> MSGBOX [Welcome]: "... Man, you're good enough to join CORE! ..."
name='KCTF' code='a86ca89f 77f81c3c fd2620f0'
>>> MSGBOX [Welcome]: "... Man, you're good enough to join CORE! ..."
```

> **Evidence → Finding → Path**
> - Evidence：转储镜像反汇编（0x402100 校验、0x401ad0 GF(2)、0x401500 压缩、0x4022c7 off-by-one）；弹窗挂起时的栈转储（比较目标真值）
> - Finding：name+strrev×3 → 魔改 MD5（长度+1）→ 3×32 位比较；GF(2) 双重可逆变换链
> - Path：运行时转储 → 栈上地面真值 → Unicorn 仿真定位魔改 → GF(2) 求逆 → 真机 Welcome

---

## 5. 方法论增量（相对第一篇）

1. **栈上地面真值法**：让弹窗挂起（MessageBoxA 阻塞中，栈帧活着），VirtualQueryEx 全内存遍历直接读出 MD5 输入串、期望值、变换结果——一次 dump 锁定三类未知数。
2. **Unicorn 仿真 = 终极仲裁**：当静态分析全部指向"标准"但结果对不上，把二进制代码直接扔进 Unicorn 跑一遍。仿真结果 = 标准 MD5 这一事实，把问题空间从"压缩函数内部"瞬间压缩到"进入压缩函数之前"。
3. **off-by-one padding 陷阱**：魔改哈希不一定要改常量/移位——**填充时序**（先写 0x80 再测长）这一行代码级的差就能让所有"标准性检查"全部通过而结果完全不同。定位它靠的是"仿真证明内部标准 → 外部必有问题"的排除法。
4. **数清 push 个数**：RegQueryValueExA 6 参数 vs RegSetValueA 5 参数，一个 push 的差决定了"注册表读"还是"注册表写"的语义判断。

## 6. 其余题目现状（第三批预告）

| 题目 | 现状 |
|------|------|
| 05 直言直语（3.5MB MFC） | 已识别为 MFC 静态链接大程序，含 `CCorrect` 类提示；需定位按钮 handler，批 3 主攻 |
| 08 TencentPediyKeygenMe（难度 95） | 2010 腾讯竞赛题，椭圆曲线算法（题目描述明示）；批 3 主攻 |
| 06 rev_babyrev（ELF） | 侦察完成：stripped + section headers 整体删除（仅存 program headers），手工汇编最小运行时（非 GCC 产物），字符串混淆（`KEY_SENTVAL`/`V{`cksx}` 碎片）；批 3 主攻 |

## 7. 附：本篇产物

```text
KCTF2026/07_CORE_CrackMe_v2/
├── dumped.bin          运行时转储镜像（224KB 明文）
├── keygen2.py          最终 Keygen（含 custom_md5 + GF(2) 求逆，自检通过）
├── emulate.py/emulate2.py   Unicorn 仿真 oracle（定位 off-by-one 的关键证据）
├── ground_truth2/3.py  栈上地面真值采集（VirtualQueryEx 全内存遍历）
├── md5_consts.py       T 常量/移位/X 序核对（全部标准化的证据链）
└── verify_final.py     真机验证脚本（pywinauto）
```
