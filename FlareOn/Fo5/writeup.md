# Flare-On 5 (2018) 全 12 題題解

> Mandiant/Google 官方年度逆向競賽第五屆，全部 12 題完整攻破。

## 總覽

| # | 題目 | 類型 | 核心技術 | Flag |
|---|------|------|---------|------|
| 01 | MinesweeperChampionship | JAR | Java 反編譯 | `GoldenTicket2018@flare-on.com` |
| 02 | UltimateMinesweeper | .NET | 踩地雷暴力搜索 | `Ch3aters_Alw4ys_W1n@flare-on.com` |
| 03 | FLEGGO | PE32 ×48 | PE 資源解析 + XOR | `mor3_awes0m3_th4n_an_awes0me_p0ssum@flare-on.com` |
| 04 | binstall | .NET | ConfuserEx 混淆 + DLL 注入 + JS 逆向 | `c0Mm4nD_inJ3c7ioN@flare-on.com` |
| 05 | web2.0 | WASM | WebAssembly 逆向 | `wasm_rulez_js_droolz@flare-on.com` |
| 06 | magic | ELF64 | 自修改代碼 + 666 輪約束 | `mag!iC_mUshr00ms_maY_h4ve_g!ven_uS_Santa_ClaUs@flare-on.com` |
| 07 | WorldOfWarcraft | PE32 | Heaven's Gate + 掛鉤 | `P0rt_Kn0ck1ng_0n_he4v3ns_d00r@flare-on.com` |
| 08 | doogie | MBR | 啟動扇區 + RTC 日期 + XOR | `R3_PhD@flare-on.com` |
| 09 | leet_editr | PE32 | VEH 異常解密 + RC4 | `scr1pt1ng_sl4ck1ng_and_h4ck1ng@flare-on.com` |
| 10 | golf | PE64 | Hypervisor + VMCALL + z3 | `We4r_ur_v1s0r_w1th_Fl4R3@flare-on.com` |
| 11 | malware_skillz | PE32+PCAP | DNS C2 + RC4/AES + LSB 隱寫術 | `recover_these_messages_lost_in_the_colorful_bits@flare-on.com` |
| 12 | suspicious_floppy | 軟碟映像 | 嵌套 OISC 虛擬機 (Subleq + RSSB) | `Av0cad0_Love_2018@flare-on.com` |

---

## C01 — MinesweeperChampionship

**Java JAR 反編譯**

Java JAR 檔案，反編譯 `InviteValidator.class` 即可看到明文比較：

```java
input.equals("GoldenTicket2018@flare-on.com")
```

簽到題，直接讀取字串常量。

Flag: `GoldenTicket2018@flare-on.com`

---

## C02 — UltimateMinesweeper

**.NET 踩地雷暴力搜索**

.NET WinForms 踩地雷遊戲。30×30 棋盤含 897 顆地雷，僅 3 格安全。翻開 3 個安全格後觸發 `GetKey` 方法：

```python
seed = cells[0] << 20 | cells[1] << 10 | cells[2]
key = Random(seed).NextBytes(32) XOR encrypted_key
```

暴力搜索所有 3 格組合，用 `@flare-on.com` 後綴過濾。安全格索引：238, 607, 864。

Flag: `Ch3aters_Alw4ys_W1n@flare-on.com`

---

## C03 — FLEGGO

**48 個 PE 資源解析 + 雙 XOR 解密**

48 個相同大小的 PE 執行檔，每個含一個自訂 `BRICK` 資源：

| 偏移 | 內容 |
|------|------|
| 0x00-0x20 | 資源名（寬字串明文，即正確密碼） |
| 0x20-0x40 | 圖片檔名（非零字節 XOR 0x85） |
| 0x40-0x4A | Flag 字母（非零字節 XOR 0x1A） |
| 0x4A-0x4C | 排序索引（uint16） |
| 0x4C-0x50 | BMP 資料大小 |
| 0x50+ | BMP 圖片資料 |

用 pefile 解析每個 exe 的 BRICK 資源，XOR 0x1A 解密字母，按索引排序拼接。

Flag: `mor3_awes0m3_th4n_an_awes0me_p0ssum@flare-on.com`

---

## C04 — binstall

**ConfuserEx 混淆 .NET + Browser 注入**

ConfuserEx 深度混淆的 .NET 安裝程式（零寬 Unicode 名稱、加密 IL、代理引用）。行為鏈：

1. 釋放 `browserassist.dll` 到系統目錄
2. 透過 `AppInit_DLLs` 註冊表項將 DLL 注入所有進程
3. DLL 掛鉤 Firefox（≤54 版本），攔截對 flare-on.com 的請求
4. 從 Pastebin 下載加密的 JS 注入規則（密鑰來自 `FL@R3ON.EXE` 的哈希）
5. 注入的 JS 在 flare-on.com 網站創建假的 Linux 終端
   - 添加 `su` 命令（密碼：`k9btBW7k2y`）
   - 添加隱藏的 `Key` 資料夾

分析方法：.NET 反射載入組件 → 列舉方法 IL → 識別 `ReadAllLines`/`Contains`/`Replace` 呼叫模式 → 理解檔案修補邏輯。

Flag: `c0Mm4nD_inJ3c7ioN@flare-on.com`

---

## C05 — web2.0

**WebAssembly 逆向**

`index.html` 從 URL 參數 `q` 讀取輸入，送入 WASM 的 `Match` 函式比對。反編譯 WASM 模組，提取比對邏輯，或直接用 Node.js 呼叫 `Match` 驗證。

Flag: `wasm_rulez_js_droolz@flare-on.com`

---

## C06 — magic

**ELF64 自修改二進位 + 666 輪約束求解**

自修改 ELF 執行檔，核心流程：

1. 33 個加密的驗證函式（Fibonacci、校驗和、XOR、Base64 等）
2. 進入 666 輪迴圈，每輪讀取密鑰 → 用 33 個驗證函式檢查 → XOR 到 flag 緩衝區
3. `ptrace` 反偵錯 + 自重命名機制（每輪修改程式碼段）

結構表位於 0x605100，每條目 288 字節。加密 flag 緩衝區 69 字節。需要 angr/z3 自動化求解每輪約束。

Flag: `mag!iC_mUshr00ms_maY_h4ve_g!ven_uS_Santa_ClaUs@flare-on.com`

---

## C07 — WorldOfWarcraft

**PE32 Heaven's Gate + NtDeviceIoControlFile 掛鉤**

32 位元 PE 使用 Heaven's Gate 技術（`far call 0x33:offset`）切換到 64 位元模式：

1. 檢查 Windows 版本（6.1 = Windows 7）
2. 定位 ntdll 的 `NtDeviceIoControlFile` 並掛鉤
3. 用 `0xDEEDEEB` XOR 解密 .data 段得到 `crackme.dll`（64 位元）
4. 掛鉤函式攔截 IOCTL_CONNECT，在 hook 中用 `counter XOR array1 XOR array2` 產生 flag

關鍵字串：`A_l1ttl3_P1C_0f_h3aV3n`（XOR 解密金鑰，23 字元）。

Flag: `P0rt_Kn0ck1ng_0n_he4v3ns_d00r@flare-on.com`

---

## C08 — doogie

**MBR 啟動扇區 + RTC 日期解密**

4096 字節的 MBR 啟動扇區映像，以「Doogie Howser, M.D.」為主題。

解密流程：
1. INT 1Ah 讀取 RTC 日期 → 必須為 1990-02-06（BCD 格式：`19 90 02 06`）
2. 第一輪：加密資料 XOR 日期金鑰
3. 第二輪：結果 XOR 密碼（`ihwbufsehimakpfre`）
4. 解密後顯示含 flag 的 ASCII 藝術

Flag: `R3_PhD@flare-on.com`

---

## C09 — leet_editr

**VEH 異常處理 + RC4 自解密 payload**

PE32 使用 `PAGE_NOACCESS` 異常處理機制保護代碼段：

1. `AddVectoredExceptionHandler` 註冊異常處理器
2. 存取 `PAGE_NOACCESS` 頁面 → 觸發 `EXCEPTION_ACCESS_VIOLATION`
3. 異常處理器即時解密代碼塊（rotating XOR + RC4）→ 設為 `PAGE_EXECUTE_READ`
4. 執行完畢後重新加密並恢復 `PAGE_NOACCESS`

密鑰：`gimmethatsweetsweetcrazylove`（MD5 哈希）+ `wimmymebrah`（RC4）。
解密後 payload 為 VBScript，透過 COM 物件寫出 flag 檔案。

Flag: `scr1pt1ng_sl4ck1ng_and_h4ck1ng@flare-on.com`

---

## C10 — golf

**x64 Hypervisor + VMCALL 驗證 + z3 求解**

自訂 x64 hypervisor（VT-x 風格），flag 分 4 段驗證：

| 段 | 值 | 驗證方式 |
|----|-----|---------|
| 1 | `We4r_ur_` | XOR + 位移運算 |
| 2 | `v1s0r_` | 乘法 + 加法校驗和 |
| 3 | `w1th_` | 查表替換 + CRC 校驗 |
| 4 | `Fl4R3` | 複雜非線性約束（z3 求解） |

透過 `VMCALL` 指令觸發 VM-Exit，在 host 模式執行各段驗證邏輯。

Flag: `We4r_ur_v1s0r_w1th_Fl4R3@flare-on.com`

---

## C11 — malware_skillz

**Delphi 惡意程式 + DNS C2 + 多層解密 + LSB 隱寫術**

`LaunchAccelerator.exe` 透過 DNS C2 通道（`asdflkjsadf.notatallsuspicio.us`）接收數據：

1. 以 3 字母子域名（aaa-zzz）發送 DNS TXT 查詢
2. Nibble 對編碼解碼：大寫 A-P = 高 nibble，小寫 a-p = 低 nibble
3. RC4 解密第一層 → AES-128-OFB 解密第二層 → 得到 BMP 圖片
4. BMP 像素 RGB 通道 LSB 隱寫術提取 flag

```
DNS TXT → Nibble解碼 → RC4 → AES-128-OFB → BMP → LSB → flag
```

Flag: `recover_these_messages_lost_in_the_colorful_bits@flare-on.com`

---

## C12 — suspicious_floppy

**DOS 軟碟映像 + 嵌套 OISC 虛擬機**

1.44MB DOS 軟碟映像（FAT12），`AUTOEXEC.BAT` 執行 `INFOHELP.EXE`。`TMP.DAT`（40KB）包含兩層嵌套虛擬機：

**第一層 — Subleq VM：**
```
mem[B] -= mem[A]
if mem[B] <= 0: goto C
else: PC += 3
```

**第二層 — RSSB VM（在 Subleq 上執行）：**
```
ACC = mem[operand] - ACC
mem[operand] = ACC
if borrow: skip next
```

RSSB 虛擬機實現密碼驗證邏輯：計算輸入的 checksum（加總 + 位旋轉），與硬編碼目標值比較。正確密碼解密 `MESSAGE.DAT` 得到 flag。

Flag: `Av0cad0_Love_2018@flare-on.com`
