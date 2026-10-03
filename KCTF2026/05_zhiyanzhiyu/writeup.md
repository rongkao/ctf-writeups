# 05 直言直语 (Junk_Instruction)

**难度**: 75 | **平台**: Windows PE32 (MFC) | **Flag**: `KCTF{973387a11fa3f724d74802857d3e052f}`

## 算法

1. 输入格式 `KCTF{32字符hex}`，总长 38
2. 提取内部 32 字符并**反转**（"拐弯抹角"）
3. RC4 加密（密钥 `qwertyuiop`）
4. 与 32 字节硬编码密文比较

## 关键技术

- **MFC 消息映射表**定位 Check 按钮处理器（搜索 `WM_COMMAND + BN_CLICKED + ID=1001`）
- **花指令**（`call+pop+ljmp` 和 `mov ebx,0x33333333`）纯防人眼，不影响仿真
- **Unicorn 仿真**证明 KSA/PRGA 为标准 RC4（无魔改）
- 数学正确但真机 Error → 谜面提示"拐弯抹角" = 反转

## 求解

```python
TARGET = bytes.fromhex('5bd6d026c8dd197e6e3ecb16917dffafdd7664b0f7e58957829f0c009ed045fa')
rc4_plaintext = rc4(b'qwertyuiop', TARGET).decode('ascii')  # f250e3d75820847d...
flag = f'KCTF{{{rc4_plaintext[::-1]}}}'  # 反转！
```

## 验证

真机弹窗: **Correct!** ✓

详细分析见 [docs/writeup](../../docs/2026-09-21_CTF-KCTF-ZhiYanZhiYu-writeup.md)
