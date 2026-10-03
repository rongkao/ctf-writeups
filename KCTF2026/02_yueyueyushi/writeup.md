# KCTF 02 - 躍躍欲試 (ASPack 脫殼 + 約束提取)

## 概況

| 屬性 | 值 |
|------|---|
| 文件 | 躍躍欲試.exe (Windows PE x86, ASPack 加殼) |
| 平臺 | Windows |
| 難度 | ★★★☆☆ |
| 核心技術 | ASPack 運行時脫殼、capstone 反彙編、約束自動提取 |

## 分析過程

### 第一步：脫殼

程序使用 ASPack 加殼保護。運行程序後，使用調試器在 OEP 處 dump 內存獲得脫殼後的 `dumped.bin`。

### 第二步：定位校驗邏輯

在脫殼後的二進制中搜索字符串和調用鏈，定位到校驗函數在偏移 `0x2811a4-0x28129f` 範圍內。

### 第三步：自動提取約束

校驗函數對 16 字節 key 逐字節檢查，使用了三種模式：

1. **直接比較**: `cmp byte ptr [ebp - X], imm` — 直接得到字節值
2. **加法比較**: `movsx eax, buf[i]` → `add eax, imm` → `cmp eax, target` — 反推 `buf[i] = target - imm`
3. **雙字節加法**: `buf[i] + buf[j] == target` — 已知一個字節後推導另一個

## 算法還原

```python
# 棧偏移 → buf 索引: buf 基址 ebp-0x240
def idx_of(disp):
    return 0x240 - disp  # buf[i] = [ebp-(0x240-i)]
```

使用 capstone 反彙編引擎自動解析指令流，逐步提取所有約束條件。

## 求解

```python
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
# 解析指令流，自動提取 16 字節 key
key = ''.join(chr(solved.get(i, 0x3F)) for i in range(16))
```

## Flag

```
KEY = BZ9dmq4c8g9G7bAY
```

## 收穫與技巧

1. **ASPack 脫殼**：ESP 定律或硬件斷點跟蹤，在 OEP 處 dump
2. **capstone 自動化**：用 Python + capstone 編寫指令模式匹配器，避免手動分析上百條指令
3. **約束傳播**：已求解的字節可以用來推導有依賴關係的未知字節
