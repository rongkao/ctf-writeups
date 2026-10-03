# 05 直言直語 (Junk_Instruction)

**難度**: 75 | **平臺**: Windows PE32 (MFC) | **Flag**: `KCTF{973387a11fa3f724d74802857d3e052f}`

## 算法

1. 輸入格式 `KCTF{32字符hex}`，總長 38
2. 提取內部 32 字符並**反轉**（"拐彎抹角"）
3. RC4 加密（密鑰 `qwertyuiop`）
4. 與 32 字節硬編碼密文比較

## 關鍵技術

- **MFC 消息映射表**定位 Check 按鈕處理器（搜索 `WM_COMMAND + BN_CLICKED + ID=1001`）
- **花指令**（`call+pop+ljmp` 和 `mov ebx,0x33333333`）純防人眼，不影響仿真
- **Unicorn 仿真**證明 KSA/PRGA 爲標準 RC4（無魔改）
- 數學正確但真機 Error → 謎面提示"拐彎抹角" = 反轉

## 求解

```python
TARGET = bytes.fromhex('5bd6d026c8dd197e6e3ecb16917dffafdd7664b0f7e58957829f0c009ed045fa')
rc4_plaintext = rc4(b'qwertyuiop', TARGET).decode('ascii')  # f250e3d75820847d...
flag = f'KCTF{{{rc4_plaintext[::-1]}}}'  # 反轉！
```

## 驗證

真機彈窗: **Correct!** ✓

詳細分析見 [docs/writeup](../../docs/2026-09-21_CTF-KCTF-ZhiYanZhiYu-writeup.md)
