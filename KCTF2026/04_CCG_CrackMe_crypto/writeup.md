# KCTF 04 - CCG Crypto CrackMe (UPX + MD5/RC4/RSA-64)

## 概況

| 屬性 | 值 |
|------|---|
| 文件 | CCG_CrackMe.exe (Windows PE x86, UPX 加殼) |
| 平臺 | Windows |
| 難度 | ★★★☆☆ |
| 核心技術 | UPX 脫殼、MD5 哈希、RC4 流密碼、RSA 64 位弱密鑰分解 |

## 分析過程

### 第一步：UPX 脫殼

標準 UPX 殼，`upx -d` 或手動 dump 即可。

### 第二步：逆向驗證算法

驗證函數位於 `0x401610`，流程爲：

```
serial → Base64 解碼 → 分成兩部分
  前 8 字節: RC4(key, part1) 必須等於 MD5(name)[0:8]
  後面的數字: pow(x, e, n) 必須等於 int(MD5(name)[8:16])
```

### 第三步：提取常量

從脫殼後的內存中提取：
- RC4 密鑰: `0x2947078587332544`
- RSA 模數 N: `0xB80A90BF53C6C979` (64 位，極易分解)
- RSA 公鑰指數 e: `65537`

### 第四步：分解 RSA

64 位 RSA 模數可以瞬間分解：

```python
N = 0xB80A90BF53C6C979
P, Q = 3753090347, 3533507051  # factordb.com 秒出
D = pow(E, -1, (P-1) * (Q-1))
```

## 算法還原

Keygen 流程（驗證的逆過程）：

```python
def keygen(name):
    md5 = hashlib.md5(name.encode()).digest()
    part1 = rc4(RC4_KEY, md5[0:8])         # RC4 加密前 8 字節
    target = int.from_bytes(md5[8:16], 'big')
    x = pow(target, D, N)                   # RSA 簽名
    return base64.b64encode(part1 + str(x).encode())
```

## Flag

```
通用 Keygen，示例:
test       -> kFqQOPnHLz84NDc4MTUwNjM3OQ==    verify=OK
KCTF       -> YwABMxCFUzI0NjAxNjEwNzc=        verify=OK
```

## 收穫與技巧

1. **弱 RSA 密鑰**：64 位模數在現代計算機上毫無安全性，factordb 可以直接查詢
2. **MD5 分段使用**：前 8 字節用於 RC4 對稱校驗，後 8 字節用於 RSA 非對稱校驗——混合密碼方案
3. **Base64 編解碼**：注意 `validate=True` 參數在驗證時很重要
4. **內存 dump 技巧**：加殼程序的常量需要運行時從內存中提取，靜態分析看不到
