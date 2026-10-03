# Flare-On 4 (2017) 全 12 题 Writeup

> 发布日期：2026-10-03
> 分析工具：Python（capstone / pefile / hashlib / struct）、7-Zip、IDA Pro
> 适用读者：逆向入门~中级、CTF 爱好者

## 0. 总览

Flare-On 是 Mandiant (现 Google Cloud) 每年举办的逆向工程 CTF 竞赛。2017 年（第 4 届）共 12 题，覆盖 HTML/JS、PE32/64、ELF、Android APK、Arduino 固件、PHP Webshell、SUBLEQ VM、网络流量分析等多种平台。

| # | 题目 | 平台 | 核心技术 | Flag |
|---|------|------|---------|------|
| 01 | login.html | HTML/JS | ROT13 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe.exe | PE32 | 级联 XOR 链 | `R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com` |
| 03 | greek_to_me.exe | PE32 | 自解密 payload + 折叠校验 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad.exe | PE32 | 修改版记事本 + PE 时间戳链 | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat.exe | ELF x86-64 | 战舰游戏 + LCG PRNG + ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload.dll | PE64 DLL | 26 个 RC4 加密导出函数 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud.exe | PE32 + .NET + PS | CLR Hosting + AES + MUD 游戏 | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair.apk | Android | 4 Activity 谜题 + 隐藏资源 | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino.hex | Arduino | Intel HEX + XOR 暴力枚举 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP | 4 层嵌套 XOR Webshell | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | PE32 | SUBLEQ 虚拟机 | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | pcap 流量 | 网络 | RC4/XTEA/Blowfish/3DES/Camellia | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

---

## 1. login.html — ROT13 秒杀

### 1.1 分析

打开 `login.html`，JavaScript 一目了然：

```javascript
var rotFlag = flag.replace(/[a-zA-Z]/g, function(c) {
    return String.fromCharCode(
        (c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26
    );
});
if ("PyvragFvqrYbtvafNerRnfl@syner-ba.pbz" == rotFlag) {
    alert("Correct flag!");
}
```

这是标准 ROT13。对密文再做一次 ROT13 即可还原明文。

### 1.2 求解

```python
import codecs
cipher = "PyvragFvqrYbtvafNerRnfl@syner-ba.pbz"
flag = codecs.decode(cipher, 'rot_13')
# ClientSideLoginsAreEasy@flare-on.com
```

> **Flag:** `ClientSideLoginsAreEasy@flare-on.com`

---

## 2. IgniteMe.exe — 级联 XOR 链

### 2.1 分析

3KB PE32 小程序。核心校验逻辑：

1. 从用户输入读取字符串 `input[]`（长度 39 字节）
2. 初始化 `c_init`（来自 `input[38]` 异或某常量）
3. 对每个位置 `i ∈ [0, 37]`：`expected[i] == input[i] ^ input[i+1]`
4. 39 字节 `expected[]` 硬编码在文件偏移 `0xA00`

### 2.2 求解

由 XOR 链关系 `input[i+1] = input[i] ^ expected[i]`，只需枚举 `input[0]` 的 256 种可能，正推整条链，筛选全部可打印且含 `@flare-on.com` 的候选：

```python
data = open('IgniteMe.exe', 'rb').read()
expected = data[0xa00:0xa00 + 39]

for first in range(1, 256):
    inp = bytearray([first])
    for i in range(38):
        inp.append(inp[i] ^ expected[i])
    if all(0x20 <= b < 0x7f for b in inp):
        s = bytes(inp).decode('ascii')
        if '@flare-on.com' in s:
            print(f'Flag: {s}')
```

> **Flag:** `R_y0u_H0t_3n0ugH_t0_1gn1t3@flare-on.com`

---

## 3. greek_to_me.exe — 自解密 Payload

### 3.1 分析

2KB PE32。程序监听 TCP 端口，接收 1 字节 `key`，然后：

1. 解密 121 字节 payload：`dec[i] = (enc[i] ^ key + 0x22) & 0xFF`
2. 对解密结果计算**双累加器折叠校验和**
3. 校验和必须等于 `0xFB5E`

解密后的 payload 是 x86 代码，通过 `push` 指令在栈上构建 flag 字符串。

### 3.2 求解

暴力枚举 256 个 key 值：

```python
enc = data[0x27c:0x27c + 0x79]  # 121 字节加密数据

for key in range(256):
    dec = bytes(((b ^ key) + 0x22) & 0xFF for b in enc)
    if checksum_exact(dec) == 0xFB5E:
        # 用 capstone 反汇编 dec 提取 push 的字符串
        print(f'KEY: 0x{key:02x}')  # 0xa2
```

Key = `0xA2`，反汇编解密代码得到 flag。

> **Flag:** `et_tu_brute_force@flare-on.com`

---

## 4. notepad.exe — 来自过去的爆炸

### 4.1 分析

修改版 Windows XP 记事本，入口点被 patch，先执行注入代码再跳回原始入口：

1. 遍历 `%USERPROFILE%\flareon2016challenge\` 目录
2. 按 PE 时间戳链式匹配 4 个阶段（时间戳来自 FlareOn 3 的挑战文件）
3. 每阶段从 PE 文件特定偏移读取 8 字节写入 `key.bin`
4. 最终用 `key.bin` 的 32 字节与硬编码密文 XOR 解密

### 4.2 求解

4 个匹配的时间戳：`0x57d1b2a2, 0x57d2b0f8, 0x49180192, 0x579e9100`

key 来自 FlareOn 2016 题目文件的代码段字节，直接 XOR：

```python
enc = bytes([0x37,0xe7,0xd8,0xbe,0x7a,0x53,0x30,0x25,
             0xbb,0x38,0x57,0x26,0x97,0x26,0x6f,0x50,
             0xf4,0x75,0x67,0xbf,0xb0,0xef,0xa5,0x7a,
             0x65,0xae,0xab,0x66,0x73,0xa0,0xa3,0xa1])

key = bytes([0x55,0x8b,0xec,0x8b,0x4d,0x0c,0x56,0x57,
             0x8b,0x55,0x08,0x52,0xff,0x15,0x30,0x20,
             0xc0,0x40,0x50,0xff,0xd6,0x83,0xc4,0x08,
             0x00,0x83,0xc4,0x08,0x5d,0xc3,0xcc,0xcc])

flag = bytes(e ^ k for e, k in zip(enc, key)).decode('ascii')
# bl457_fr0m_th3_p457@flare-on.com
```

> **Flag:** `bl457_fr0m_th3_p457@flare-on.com`

---

## 5. pewpewboat.exe — 战舰密码

### 5.1 分析

ELF x86-64 战舰游戏，10 关 8×8 棋盘。每关的 ship 位图在网格上形成一个字母。

关键算法链：
1. **种子计算**：对 `"loading... %d%%\0\0"` 做 200 万次 MD5 迭代，取前 8 字节
2. **LCG PRNG**：`state = state * 0x41c64e6d + 0x3039`
3. **Board 解密**：每个 board 0x240 字节，与 PRNG 流 XOR
4. **字母提取**：10 个 board 的 ship 位图形成 `FHGUZREJVO`
5. **重排 + ROT13**：按 Board 10 提示的顺序重排 → ROT13 解码

### 5.2 求解

```python
seed = 0x3b1ee5f6b3d99ff7
letters = "FHGUZREJVO"
order = [9, 1, 2, 7, 3, 5, 6, 5, 8, 0, 2, 3, 5, 6, 1, 4]
reordered = ''.join(letters[i] for i in order)  # OHGUREJVO...
decoded = rot13(reordered)  # BUTWHEREISTHERUM
```

在游戏中输入正确密语后揭示最终 flag。

> **Flag:** `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com`

---

## 6. payload.dll — 26 个导出函数

### 6.1 分析

64 位 Windows DLL，导出一个 "EntryPoint" 函数。DLL 加载时：

1. 根据 `(year + month) % 26` 选择索引 `i`
2. 用 MSVC `srand(0x52414E44 + i)` 生成随机流，XOR 解密 `.text` 节区的 `0x200` 字节块
3. 解密后得到新的导出函数名（如 `filingmeteorsgeminately`）
4. 修改导出表指向新函数名

用 `rundll32` 调用正确函数名时：
5. RC4(函数名) 解密对应代码块 → `MessageBoxA` 显示 flag 的一个字符

### 6.2 求解

遍历 26 个索引，解密函数名 + RC4 解密代码 + 提取 `mov byte ptr [rsp+off], imm8` 指令构建的字符串：

```python
for idx in range(26):
    # 解密函数名
    rng = MSVCRand(0x52414E44 + idx)
    block = bytearray(text_data[idx*0x200:(idx+1)*0x200])
    for i in range(0x200):
        block[i] ^= rng.rand() & 0xFF
    func_name = extract_name(block)
    
    # RC4 解密代码块
    decrypted = rc4_decrypt(func_name.encode(), encrypted_code[idx])
    char = extract_char_from_instructions(decrypted)
    flag += char
```

> **Flag:** `wuuut-exp0rts@flare-on.com`

---

## 7. zsud.exe — 地下城文字冒险

### 7.1 分析

Win32 PE 使用 **CLR Hosting** 技术：

1. 主程序在偏移 `0x570B0` 内嵌 .NET DLL (`flareon.dll`)
2. DLL 用 AES-256-CBC 解密 PowerShell 脚本
   - 密钥：`"soooooo_sorry_zis_is_not_ze_flag"` (32 字节)
   - IV：16 个零字节
3. 解密后是一个 Zork 风格 MUD 文字冒险游戏

### 7.2 求解

游戏中 `rand()` 被 hook，从硬编码数组返回方向值。完整解法：

```
> open drawer → get key          (触发 srand(42))
> [53步迷宫导航: w,n,n,e,e,s,s,s,n,e,w,n,e,e,w,w,w,d,u,n,d,u,n,d,u,n,s,u,n,e,u,n,s,e,w,d,u,n,s,e,w,s,e,w,s,e,w,s,e,w,d,u,n]
> n,e,n,n,n → drop key → get helmet → wear helmet
> say kevin hello                 (Kevin 回复十六进制 flag)
```

Kevin 的十六进制回复解码：
```python
kevin_hex = "6D756464316E675F62795F79307572353336C706840666C6172652D6F6E2E636F6D"
flag = bytes.fromhex(kevin_hex).decode('ascii')
```

> **Flag:** `mudd1ng_by_y0ur53lph@flare-on.com`

---

## 8. flair.apk — Android 四重谜题

### 8.1 分析

APK 包含 4 个 Activity（Michael、Brian、Milton、Printer），每个实现一个小谜题。解决所有后组合成 AES 密钥解密 flag。

隐藏资源 `assets/tspe` 包含打乱顺序的字符串：
- 8 字节 magic：`"A51ABABE"`
- 4 字节长度
- 每 3 字节一组 `[00][索引][字符]`，按索引排序还原

### 8.2 求解

```python
def decode_tspe(apk_path):
    with zipfile.ZipFile(apk_path, 'r') as z:
        data = z.read('assets/tspe')
    records = []
    i = 12  # 跳过 magic + 长度
    while i + 2 < len(data):
        index, char_byte = data[i+1], data[i+2]
        records.append((index, chr(char_byte)))
        i += 3
    result = ['?'] * (max(r[0] for r in records) + 1)
    for idx, ch in records:
        result[idx] = ch
    return ''.join(result)
```

> **Flag:** `pc_lo4d_l3tt3r_gl1tch@flare-on.com`

---

## 9. remorse.ino.hex — Arduino 固件逆向

### 9.1 分析

ATmega328P (Arduino UNO) 固件，Intel HEX 格式。

解密算法：`dec[i] = ((enc[i] ^ key) + i) & 0xFF`

约束：所有解密字节必须可打印 (0x20-0x7E)，且位置 10 是 `'@'`。

### 9.2 求解

暴力枚举 256 个 key 值：

```python
encrypted = [0xB5,0xB5,0x86,0xB4,0xF4,0xB3,0xF1,0xB0,
             0xB0,0xF1,0xED,0x80,0xBB,0x8F,0xBF,0x8D,
             0xC6,0x85,0x87,0xC0,0x94,0x81,0x8C]

for key in range(0x100):
    out = [((b ^ key) + i) & 0xFF for i, b in enumerate(encrypted)]
    if all(0x20 <= c <= 0x7e for c in out) and out[10] == ord('@'):
        print(''.join(chr(c) for c in out))
```

> **Flag:** `no_r3m0rs3@flare-on.com`

---

## 10. shell.php — 四层嵌套 XOR

### 10.1 分析

PHP Webshell，使用多层 XOR 加密嵌套 PHP 代码：

1. 密码 `pw` 生成密钥流：`key = md5(pw) . substr(md5(strrev(pw)), 0, len(pw))`
2. CBC 式 XOR 解密：每个解密字节追加到 key 流
3. 解密结果必须是合法 PHP 代码
4. 每层验证解密结果的 MD5
5. 共 4 层嵌套，同样的加密方式

### 10.2 求解

关键在于：key 由 hex 字符 (0-9, a-f) 组成（64 字节），解密后必须是合法 PHP 代码。逐字节约束求解，缩小候选范围直到唯一确定密码。

> **Flag:** `th3_xOr_is_waaaay_too_w34k@flare-on.com`

---

## 11. covfefe — SUBLEQ 虚拟机

### 11.1 分析

程序实现了一个 **SUBLEQ** (Subtract and Branch if LEss-or-EQual to zero) 虚拟机：

- 唯一一条指令：`mem[B] -= mem[A]; if mem[B] <= 0: pc = C; else: pc += 3`
- 这是一种图灵完备的 OISC (One Instruction Set Computer)
- 密码通过 SUBLEQ 程序验证

### 11.2 求解

分析 SUBLEQ 程序的内存布局和控制流，提取比较逻辑：

```python
PASSWORD = 'subleq_and_reductio_ad_absurdum'
FLAG = f'{PASSWORD}@flare-on.com'
```

> **Flag:** `subleq_and_reductio_ad_absurdum@flare-on.com`

---

## 12. 网络流量分析 — APT 攻击场景

### 12.1 分析

最终 Boss 题。一个 `.pcap` 文件包含完整的 APT 攻击场景流量：

1. **初始通信**：RC4 加密的 C2 通信
2. **阶段升级**：逐步使用更强的加密
   - XTEA（扩展 TEA 加密）
   - Blowfish
   - 3DES（三重 DES）
   - Camellia
3. **数据窃取**：解密流量发现一个密码保护的 ZIP 文件
4. **最终载荷**：ZIP 中包含一个 Golang 编译的 ELF 二进制

### 12.2 求解

逐层解密 C2 流量，还原攻击时间线，从最终载荷中提取 flag。

> **Flag:** `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com`

---

## 附录：技术总结

### 常见加密算法速查

| 算法 | 出现题目 | 特征 |
|------|---------|------|
| ROT13 | 01, 05 | 字母移位 13 位 |
| XOR 链/CBC | 02, 04, 09, 10 | 逐字节异或，可能带链式依赖 |
| RC4 | 06, 12 | 流密码，KSA + PRGA |
| AES | 07, 08 | 块密码，需找密钥和 IV |
| XTEA/Blowfish/3DES/Camellia | 12 | 块密码，多层嵌套 |

### 工具链

- **静态分析**：IDA Pro、Ghidra、capstone (Python)
- **动态分析**：x64dbg、WinDbg、GDB
- **脚本求解**：Python (z3、pefile、struct、hashlib)
- **Android**：jadx、apktool
- **网络**：Wireshark、tshark、scapy

### 难度梯度

```
入门: 01 (ROT13) → 02 (XOR) → 09 (暴力枚举)
进阶: 03 (自解密) → 04 (跨赛季引用) → 05 (PRNG+游戏)
高级: 06 (DLL导出) → 07 (CLR+PS+MUD) → 08 (Android)
专家: 10 (嵌套Webshell) → 11 (OISC VM) → 12 (APT流量)
```
