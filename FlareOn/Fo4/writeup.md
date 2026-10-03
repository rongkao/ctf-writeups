# Flare-On 4 (2017) 全 12 题题解

> Mandiant/Google 官方年度逆向竞赛第四届，全部 12 题完整攻破。

## 总览

| # | 题目 | 类型 | 核心技术 | Flag |
|---|------|------|---------|------|
| 01 | login.html | Web | ROT13 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe.exe | PE32 | 级联 XOR + 种子 | `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com` |
| 03 | greek_to_me.exe | PE32 | 自解密 payload + 爆破 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad.exe | PE32 | PE 时间戳链 + XOR | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat | ELF64 | 战舰游戏 + MD5/LCG/ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload.dll | DLL64 | 动态导出 + RC4 解密 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud.exe | PE32+.NET | CLR Hosting + AES + PowerShell MUD | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair.apk | Android | 4 个 Activity 谜题 + AES | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino.hex | Arduino | Intel HEX + 字节级爆破 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP | 4 层 XOR webshell 嵌套 | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | ELF | SUBLEQ 单指令虚拟机 | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | coolprogram.pcap | PCAP | RC4/XTEA/Blowfish/3DES/Camellia C2 流量 | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

---

## C01 — login.html

**ROT13 JavaScript 逆向**

HTML 页面包含 ROT13 加密的密码检查。查看源码即可：

```javascript
// 密码经过 ROT13 编码存储
// 解码: PyvragFvqrYbtvafNerRnfl → ClientSideLoginsAreEasy
```

Flag: `ClientSideLoginsAreEasy@flare-on.com`

---

## C02 — IgniteMe.exe

**级联 XOR 链**

校验逻辑：从尾部向头部级联 XOR，`t[i] = input[i] ^ input[i+1]`（尾字节用独立种子）。

求解：猜 `input[0]` → 正推全链。枚举 0x20-0x7e 的 95 个候选，过滤全可打印 + 含 `@flare-on.com` → 唯一解。

Flag: `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com`

---

## C03 — greek_to_me.exe

**自解密 payload + 双累加器校验**

121 字节就地自解密：`*p = (*p ^ key) + 0x22`。双累加器折叠校验 `== 0xFB5E`。

256 个单字节 key 秒扫 → key=0xA2 命中。解密后的 payload 是栈字符串构造器。

Flag: `et_tu_brute_force@flare-on.com` （"Et tu, Brute?" — 凯撒名句 + brute force 双关）

---

## C04 — notepad.exe

**修改版 Windows XP 记事本 + FlareOn 2016 PE 文件链**

入口点被 patch，恶意代码遍历 `%USERPROFILE%\flareon2016challenge\` 下的 PE 文件。按时间戳链式匹配 4 阶段，每阶段从 PE 偏移读取 8 字节写入 key.bin。最终用 32 字节密钥与硬编码密文 XOR。

关键线索：目录名 `flareon2016challenge` 指向 FlareOn 3 的题目文件。

```python
enc = bytes([0x37, 0xe7, 0xd8, ...])  # 32 bytes
key = bytes([0x55, 0x8b, 0xec, ...])  # 来自 FlareOn 2016 PE
flag = bytes(e ^ k for e, k in zip(enc, key))
```

Flag: `bl457_fr0m_th3_p457@flare-on.com`

---

## C05 — pewpewboat

**战舰游戏 + MD5/LCG/ROT13**

ELF x86-64 战舰游戏，10 个关卡。每关的 ship 图案在 8x8 网格上形成一个字母。

1. MD5 迭代 `"loading... %d%%\0\0"` 2M 次 → 种子
2. LCG PRNG + XOR 解密 10 个 board
3. Board 10 的提示给出重排顺序
4. ROT13 解码得到密语 `BUTWHEREISTHERUM`

Flag: `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com`

---

## C06 — payload.dll

**DLL 动态导出 + RC4 解密**

64 位 DLL，根据 `(year + month) % 26` 选择索引：
1. 用 MSVC `srand/rand` 生成随机流，XOR 解密函数名
2. 修改导出表，替换 `EntryPoint` 为新函数名
3. 调用正确函数名时，RC4 解密代码块得到 flag 字符

26 个索引 × 函数名解密 → 26 个 flag 字符。

Flag: `wuuut-exp0rts@flare-on.com`

---

## C07 — zsud.exe

**CLR Hosting + AES + PowerShell 文字冒险**

原生 PE32 使用 CLR Hosting 加载内嵌 .NET DLL (flareon.dll)。DLL 用 AES 解密 PowerShell 脚本，实现类 Zork 的 MUD 游戏。"zsud" = "Single-User Dungeon"。

解析游戏逻辑，Kevin 的十六进制回复 = flag。

Flag: `mudd1ng_by_y0ur53lph@flare-on.com`

---

## C08 — flair.apk

**Android 4 Activity 谜题**

APK 包含 4 个 Activity (Michael, Brian, Milton, Printer)，每个实现一个小谜题。解决所有后组合成 AES 密钥。

`assets/tspe` 文件：8 字节 magic `A51ABABE` + 打乱的字符序列，按索引排序还原。

Flag: `pc_lo4d_l3tt3r_gl1tch@flare-on.com`

---

## C09 — remorse.ino.hex

**Arduino UNO (ATmega328P) 固件逆向**

Intel HEX 格式的 Arduino 固件。解密算法：`dec[i] = ((enc[i] ^ key) + i) & 0xFF`。

暴力枚举 key (0-255)，正确的 key 使位置 10 产生 `'@'`。

Flag: `no_r3m0rs3@flare-on.com`

---

## C10 — shell.php

**4 层嵌套 PHP WebShell**

PHP webshell 的密码通过 XOR 解密嵌套的 PHP 代码：
- key = `md5(pw) + substr(md5(strrev(pw)), 0, len(pw))`
- CBC 式 XOR 解密
- 共 4 层嵌套，每层同样的加密方式

约束求解：key 由 hex 字符组成，解密后必须是合法 PHP。逐字节缩小候选范围。

Flag: `th3_xOr_is_waaaay_too_w34k@flare-on.com`

---

## C11 — covfefe

**SUBLEQ 单指令虚拟机**

SUBLEQ (Subtract and Branch if Less-or-Equal-to-zero) VM：唯一指令 `mem[B] -= mem[A]; if mem[B]<=0: pc=C; else: pc+=3`。

密码通过 SUBLEQ 程序验证。分析 VM 程序逻辑得到密码。

Flag: `subleq_and_reductio_ad_absurdum@flare-on.com`

---

## C12 — coolprogram (PCAP)

**APT 场景 C2 流量分析**

网络流量包含多层加密 C2 通信：RC4 → XTEA → Blowfish → 3DES → Camellia。

逐层解密 C2 流量，还原攻击过程。最终解密密码保护的 zip，包含 Golang ELF 二进制。

Flag: `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com`

---

## 技术统计

| 类别 | 数量 | 涉及题目 |
|------|------|---------|
| XOR 变种 | 5 | C02, C03, C04, C05, C10 |
| 密码学原语 | 4 | C06(RC4), C07(AES), C12(RC4/XTEA/Blowfish/3DES/Camellia) |
| 虚拟机/仿真 | 2 | C09(AVR), C11(SUBLEQ) |
| 移动/Web | 3 | C01(JS), C08(Android), C10(PHP) |
| 流量分析 | 1 | C12(PCAP) |
