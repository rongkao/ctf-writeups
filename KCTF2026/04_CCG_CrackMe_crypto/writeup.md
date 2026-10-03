# KCTF 04 - CCG Crypto CrackMe (UPX + MD5/RC4/RSA-64)

## 概况

| 属性 | 值 |
|------|---|
| 文件 | CCG_CrackMe.exe (Windows PE x86, UPX 加壳) |
| 平台 | Windows |
| 难度 | ★★★☆☆ |
| 核心技术 | UPX 脱壳、MD5 哈希、RC4 流密码、RSA 64 位弱密钥分解 |

## 分析过程

### 第一步：UPX 脱壳

标准 UPX 壳，`upx -d` 或手动 dump 即可。

### 第二步：逆向验证算法

验证函数位于 `0x401610`，流程为：

```
serial → Base64 解码 → 分成两部分
  前 8 字节: RC4(key, part1) 必须等于 MD5(name)[0:8]
  后面的数字: pow(x, e, n) 必须等于 int(MD5(name)[8:16])
```

### 第三步：提取常量

从脱壳后的内存中提取：
- RC4 密钥: `0x2947078587332544`
- RSA 模数 N: `0xB80A90BF53C6C979` (64 位，极易分解)
- RSA 公钥指数 e: `65537`

### 第四步：分解 RSA

64 位 RSA 模数可以瞬间分解：

```python
N = 0xB80A90BF53C6C979
P, Q = 3753090347, 3533507051  # factordb.com 秒出
D = pow(E, -1, (P-1) * (Q-1))
```

## 算法还原

Keygen 流程（验证的逆过程）：

```python
def keygen(name):
    md5 = hashlib.md5(name.encode()).digest()
    part1 = rc4(RC4_KEY, md5[0:8])         # RC4 加密前 8 字节
    target = int.from_bytes(md5[8:16], 'big')
    x = pow(target, D, N)                   # RSA 签名
    return base64.b64encode(part1 + str(x).encode())
```

## Flag

```
通用 Keygen，示例:
test       -> kFqQOPnHLz84NDc4MTUwNjM3OQ==    verify=OK
KCTF       -> YwABMxCFUzI0NjAxNjEwNzc=        verify=OK
```

## 收获与技巧

1. **弱 RSA 密钥**：64 位模数在现代计算机上毫无安全性，factordb 可以直接查询
2. **MD5 分段使用**：前 8 字节用于 RC4 对称校验，后 8 字节用于 RSA 非对称校验——混合密码方案
3. **Base64 编解码**：注意 `validate=True` 参数在验证时很重要
4. **内存 dump 技巧**：加壳程序的常量需要运行时从内存中提取，静态分析看不到
