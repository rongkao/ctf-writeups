# Flare-On 4 双杀：级联 XOR 与希腊之谜

> 发布日期：2026-09-21
> 作者：[你的名字]
> 分析工具：Python（capstone）、subprocess 自动验证
> 前篇：KCTF 系列（一）～（三）、crackmes.one 实战（四）

## 0. 本篇看点

第五批进军 **Flare-On**（Mandiant/Google 官方年度逆向赛）2017 届（Flare-On 4），精选两道 Windows 小型题完整攻破 + LATTICE-4 阶段性成果：

| 题目 | 核心技术 | 结果 |
|------|---------|------|
| C2 IgniteMe.exe (3KB) | 级联 XOR + 环回种子 | **`R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com`**（真机 "G00d j0b!" ✓） |
| C3 greek_to_me.exe (2KB) | 121 字节自解密 payload + 自定义折叠校验 | **`et_tu_brute_force@flare-on.com`**（key=0xA2=162） |
| crackmes.one LATTICE-4 | 五重哈希联锁 | 阶段 1 z3 秒解 `L4tT1cE4`；阶段 2 数学分析见 §4 |

```mermaid
flowchart LR
    A[Flare-On 4 官方包 8MB] -->|7z 解压 密码=flare| B[C2 IgniteMe 3KB]
    A --> C[C3 greek_to_me 2KB]
    B --> D[级联 XOR: t=i xor i+1]
    D --> E[猜首字符正推 39 字节链]
    E --> F[19 个可打印候选 → 唯一含 @flare-on.com]
    C --> G[自解密: b^key+0x22]
    G --> H[复现双累加器折叠校验]
    H --> I[爆破 256 key → 0xA2 命中 0xFB5E]
    I --> J[解密 payload = 栈字符串构造器]
    J --> K[et_tu_brute_force@flare-on.com]
```

---

## 1. IgniteMe.exe —— 级联 XOR 链

### 1.1 校验逻辑（0x401050）

```asm
; 阶段 1: 自尾部向头的级联 XOR（密文落 0x403180）
c = f()                     ; 种子来自 0x401000
for (i = len-1; i >= 0; i--):
    t[i] = input[i] ^ c
    c = input[i]            ; 级联: 每字节用右邻作密钥

; 阶段 2: t[0..38] == expected @0x403000 (39 字节)
```

即 `t[i] = input[i] ^ input[i+1]`（i=0..37），尾字节 `t[38] = input[38] ^ seed`。

### 1.2 求解：首字符正推

级联结构天然可逆：**猜 `input[0]` → `input[i+1] = input[i] ^ t[i]` 逐步推出全串**。枚举 0x20-0x7e 得 19 个全可打印候选，其中恰好一个含 `@flare-on.com`：

```text
R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com
>>> 真机: G1v3 m3 t3h fl4g: G00d j0b!  ✓
```

> 踩坑记录：第一版求解器把种子误当成 `input[0]`（做成环回一致性检查）导致零输出。实际上种子来自独立函数——**去掉错误假设、直接枚举+模式识别（找 @flare-on.com）** 一击命中。

## 2. greek_to_me.exe —— 自解密 payload 之谜

### 2.1 结构（2KB，比某些 shellcode 还小）

```asm
main:
  handle = init(&key_byte)           ; 0x401121: 取输入（原版走网络）
  ; ★ 121 字节就地自解密（数据就躺在代码段 0x40107c）
  for p in [0x40107c, 0x40107c+0x79):
      *p = (*p ^ key_byte) + 0x22
  ; ★ 校验
  if (checksum16(0x40107c, 0x79) != 0xFB5E) → 报错退出
  jmp 0x40107c                        ; 跳进解密后的代码执行！
```

### 2.2 自定义折叠校验（0x4011e6）

双累加器设计（不是标准 CRC/IP 校验和，必须逐指令复现）：

```c
di = 0xFF; ecx = 0xFF;
while (remaining) {
    for (20 字节一组) { di += buf[i]; ecx += di; }   // 16位/32位双链
    di  = fold16(di);      // (低字节 + 高字节)
    ecx = fold16(ecx);
}
// 尾部: ((ecx&0xFF00) + (ecx<<8)) | ((di&0xFF) + (di>>8))  → 16 位结果
```

### 2.3 爆破与彩蛋

256 个 key 单字节空间，Python 秒扫——**key=0xA2 (十进制 162)** 唯一命中 `0xFB5E`。解密后的 121 字节反汇编为栈字符串构造器：

```asm
mov byte ptr [ebp-0x2b], 'e'
mov byte ptr [ebp-0x2a], 't'
mov byte ptr [ebp-0x29], '_'
...（29 个字符逐字节入栈）
mov byte ptr [ebp-0x0d], 0
```

拼出：**`et_tu_brute_force@flare-on.com`**

> "Et tu, Brute?"（还有你吗，布鲁图？）——凯撒遇刺时的名言，完美呼应题目 Greek to me（源自莎士比亚《凯撒》"it was Greek to me"）。更妙的是：**我们正是用 brute force 解出的这道题**，出题人的双关在 2017 年埋下，2026 年被暴力兑现。

> **Evidence → Finding → Path**
> - Evidence：0x401029 解密循环反汇编；0x4011e6 校验函数全量反汇编；key=0xA2 解密产物反汇编
> - Finding：`(b^key)+0x22` 自解密 + 双折叠校验 0xFB5E + 栈字符串 flag
> - Path：静态还原解密/校验 → Python 精确复现（含 OR/截断语义）→ 256 key 爆破 → payload 反汇编

## 3. LATTICE-4 阶段成果与数学分析

- **阶段 1 ✓**：前 8 字符三关（mod251/多项式/16 位滚动哈希）z3 秒解 → `L4tT1cE4`（Lattice4 leet 彩蛋）
- **阶段 2 分析**：后 8 字符面临 FNV-1a 中间值 + 滚动哈希双 32 位约束。关键数学事实：
  - 自由度：8 字符 × 5.95 bit ≈ **47.6 bit**
  - 约束：64 bit（两独立 32 位哈希）
  - **47.6 < 64 → 随机解不存在**，唯一解是出题人从彩蛋词形构造的——z3 求解继续后台运行，词形猜测（如 16 字符双词 leet）是并行方向

### 方法论增量

1. **级联 XOR 的正推消元**：t[i]=in[i]^in[i+1] 结构下，猜 1 字节即可正推全链——把 2^95 空间压成 95 次一维枚举。
2. **自定义校验和必须逐指令复现**：`(低+高)` 折叠、`or ax,dx` 组合、16 位截断——任何一处想当然都会让爆破静默失败（本文 §2.2 完整复现是命中前提）。
3. **约束位数 vs 自由度** 的前置计算：解不存在时别让求解器空转，先算 62^n 与约束位数的量级关系。

## 4. 并行交付：ProcessGuard 驱动

本批同期完成 **类 360 保险箱进程保护驱动**（`D:\codes\ProcessGuard\`）：ObRegisterCallbacks 句柄权限剥离（TERMINATE/VM_READ/VM_WRITE/DUP_HANDLE/CREATE_THREAD），编译产出 ProcessGuard.sys + pgctl.exe 控制台，测试签名加载步骤见项目 README。

## 5. 系列总战绩

| 批次 | 平台 | 成果 |
|------|------|------|
| 1 | KCTF | 4 题全破 |
| 2 | KCTF | CORE v2.0（难度89）全破 |
| 3 | KCTF | 直言直语（难度75）全破 |
| 4 | crackmes.one | Retro OEM 全破 + LATTICE-4 算法还原 |
| **5** | **Flare-On 4** | **C2+C3 双杀（本篇）** |
| 附加 | 驱动开发 | ProcessGuard.sys |

**博客系列累计：8 道题完全攻破（7 道真机验证）、5 篇 writeup、1 个内核驱动项目。**

## 6. 附：本篇产物

```text
FlareOn/Fo4/
├── 02/IgniteMe.exe          官方原题
├── 03/greek_to_me.exe       官方原题
├── solve_ignite2.py         级联 XOR 正推求解器
├── solve_greek3.py          校验复现 + 256 key 爆破 + payload 反汇编
└── dis_*.py                 分析脚本
crackmes/lattice4/
├── solve_phase1.py          z3 阶段 1（L4tT1cE4）
└── solve_phase2b.py         z3 阶段 2（后台运行中）
ProcessGuard/                驱动项目（详见其 README）
```
