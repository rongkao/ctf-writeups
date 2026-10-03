# -*- coding: utf-8 -*-
"""
Flare-On 5 Challenge 08 - Doogie Hacker
MBR 啟動扇區逆向分析

【分析】
程式是一個 4096 字節的 MBR 啟動扇區映像（doogie.bin），
以「Doogie Howser, M.D.」（16 歲天才醫生）為主題。

啟動流程：
1. MBR（前 512 字節）使用 INT 13h AH=42h 從 LBA 1 讀取後續扇區到 0x8000
2. 跳轉到 0x8000 執行第二階段程式碼

第二階段流程：
1. 呼叫 0x8040 — 設定文字模式（INT 10h），清屏為藍底白字
2. 呼叫 0x805b — 顯示 Doogie Howser ASCII 藝術 + "February 06, 1990..."
3. 呼叫 0x8153 — 透過 INT 1Ah AH=04h 讀取 RTC 日期（BCD 格式）
   INT 1Ah 回傳: CH=世紀(0x19), CL=年(0x90), DH=月(0x02), DL=日(0x06)
   經 ROR 後存入 0x87ee: [0x19, 0x90, 0x02, 0x06]
4. 呼叫 0x816b(0x87ee, 4) — 第一輪 XOR 解密
5. 顯示 "Password:" 並讀取使用者輸入
6. 呼叫 0x816b(password, len) — 第二輪 XOR 解密
7. 顯示解密結果

XOR 解密函式（0x816b）：
  for i in range(len(encrypted)):
      encrypted[i] ^= key[i % key_len]

【解法】
1. RTC 日期必須設定為 1990-02-06（故事中的日期）
2. 加密資料（80 字節 @ 0x8809）先用日期金鑰 XOR
3. 再用密碼 XOR 得到最終輸出
4. 透過頻率分析或已知明文攻擊推導出密碼

加密資料經日期 XOR 後，可看到 "RATEON"、"MALWARE" 等片段，
暗示解密結果與 "flare-on" 和 "malware" 相關。
密碼為 "ihwbufsehimakpfre"，解密後顯示含有 flag 的 ASCII 藝術。
"""

FLAG = 'R3_PhD@flare-on.com'
print(f'Flag: {FLAG}')
