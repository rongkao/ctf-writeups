# -*- coding: utf-8 -*-
"""
Flare-On 5 Challenge 04 - binstall (Browser Assistant Installer)

解題思路：
binstall.exe 是一個 ConfuserEx 混淆的 .NET 安裝程序，行為如下：
1. 釋放 browserassist.dll 到系統目錄
2. 通過 AppInit_DLLs 註冊表項注入 DLL 到所有進程
3. DLL Hook 進 Firefox（≤54 版本），攔截對 flare-on.com 的請求
4. 從 Pastebin 下載加密的 JavaScript 注入規則
   - 使用 "FL@R3ON.EXE" 的哈希作為解密密鑰
5. 注入的 JS 在 flare-on.com 網站上創建假的 Linux 終端
   - 添加 "su" 命令（需要密碼：k9btBW7k2y）
   - 添加隱藏的 "Key" 文件夾
6. 輸入正確密碼並訪問 Key 文件夾即可獲得 flag

關鍵技術：
- .NET 反射繞過 ConfuserEx 混淆
- AppInit_DLLs DLL 注入
- Firefox 擴展/Hook 機制
- JavaScript 注入與命令注入概念
"""

flag = "c0Mm4nD_inJ3c7ioN@flare-on.com"
print(f"Flag: {flag}")
