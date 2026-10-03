# CTF 逆向工程題解教程

> 逆向工程 CTF 題解合集 — 包含 KCTF2026 看雪靶場全 8 題 + Flare-On 4/5 全 24 題，附完整解題腳本與詳細分析

## 目錄

### KCTF2026 看雪逆向靶場 (8/8 ✅)

| # | 題目 | 難度 | 核心技術 | Writeup |
|---|------|------|----------|---------|
| 01 | [rechall](KCTF2026/01_rechall/) | ★★☆☆☆ | z3 約束求解、位元運算 | [題解](KCTF2026/01_rechall/writeup.md) |
| 02 | [躍躍欲試](KCTF2026/02_yueyueyushi/) | ★★★☆☆ | ASPack 脫殼、capstone 自動化 | [題解](KCTF2026/02_yueyueyushi/writeup.md) |
| 03 | [金山2007](KCTF2026/03_jinshan2007/) | ★★★☆☆ | 雜湊逆向、BFS 狀態搜尋 | [題解](KCTF2026/03_jinshan2007/writeup.md) |
| 04 | [CCG CrackMe](KCTF2026/04_CCG_CrackMe_crypto/) | ★★★☆☆ | UPX 脫殼、MD5/RC4/RSA-64 | [題解](KCTF2026/04_CCG_CrackMe_crypto/writeup.md) |
| 05 | [知言知語](KCTF2026/05_zhiyanzhiyu/) | ★★★☆☆ | 花指令、RC4 串流加密 | [題解](KCTF2026/05_zhiyanzhiyu/writeup.md) |
| 06 | [BabyRev](KCTF2026/06_rev_babyrev/) | ★★★☆☆ | UPX 魔改殼 + Rust XOR 鏈 | [題解](KCTF2026/06_rev_babyrev/writeup.md) |
| 07 | [CORE CrackMe v2](KCTF2026/07_CORE_CrackMe_v2/) | ★★★★☆ | 魔改 MD5 + GF(2) 矩陣逆 | [題解](KCTF2026/07_CORE_CrackMe_v2/writeup.md) |
| 08 | [TencentPediy KeygenMe](KCTF2026/08_TencentPediyKeygenMe/) | ★★★★★ | ECDSA + SM4 + Feistel + GF(2^8) | [題解](KCTF2026/08_TencentPediyKeygenMe/writeup.md) |

### Flare-On 4 / 2017 (12/12 ✅)

| # | 題目 | 核心技術 | Flag |
|---|------|----------|------|
| 01 | login.html | JavaScript 逆向 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe | XOR 鏈解密 | `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com` |
| 03 | greek_to_me | 單位元組爆破 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad | PE 時間戳鏈 + XOR | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat | 戰艦遊戲 + ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload | DLL 匯出 + 解密 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud | 文字冒險 + 密碼學 | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair | ELF 共享函式庫 | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino | Arduino HEX 分析 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP WebShell 解密 | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | SUBLEQ 虛擬機 | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | coolprogram | .NET + 多層加密 | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

**[完整 Flare-On 4 題解](FlareOn/Fo4/writeup.md)**

### Flare-On 5 / 2018 (12/12 ✅)

| # | 題目 | 核心技術 | Flag |
|---|------|----------|------|
| 01 | MinesweeperChampionship | Java 反編譯 | `GoldenTicket2018@flare-on.com` |
| 02 | UltimateMinesweeper | .NET 踩地雷暴力搜索 | `Ch3aters_Alw4ys_W1n@flare-on.com` |
| 03 | FLEGGO | PE 資源解析 + XOR | `mor3_awes0m3_th4n_an_awes0me_p0ssum@flare-on.com` |
| 04 | binstall | ConfuserEx 混淆 + DLL 注入 | `c0Mm4nD_inJ3c7ioN@flare-on.com` |
| 05 | web2.0 | WebAssembly 逆向 | `wasm_rulez_js_droolz@flare-on.com` |
| 06 | magic | 自修改 ELF + 666 輪約束 | `mag!iC_mUshr00ms_maY_h4ve_g!ven_uS_Santa_ClaUs@flare-on.com` |
| 07 | WorldOfWarcraft | Heaven's Gate + 掛鉤 | `P0rt_Kn0ck1ng_0n_he4v3ns_d00r@flare-on.com` |
| 08 | doogie | MBR 啟動扇區 + RTC | `R3_PhD@flare-on.com` |
| 09 | leet_editr | VEH 異常解密 + RC4 | `scr1pt1ng_sl4ck1ng_and_h4ck1ng@flare-on.com` |
| 10 | golf | Hypervisor + VMCALL + z3 | `We4r_ur_v1s0r_w1th_Fl4R3@flare-on.com` |
| 11 | malware_skillz | DNS C2 + LSB 隱寫術 | `recover_these_messages_lost_in_the_colorful_bits@flare-on.com` |
| 12 | suspicious_floppy | 嵌套 OISC 虛擬機 | `Av0cad0_Love_2018@flare-on.com` |

**[完整 Flare-On 5 題解](FlareOn/Fo5/writeup.md)**

---

## 技術棧

### 逆向工具
- **IDA Pro** — 靜態分析
- **x64dbg / x32dbg** — 動態偵錯
- **Ghidra** — 反編譯
- **capstone** — Python 反組譯引擎

### 求解工具
- **z3 (SMT Solver)** — 約束求解
- **Python** — 腳本自動化
- **Unicorn Engine** — CPU 模擬
- **pywinauto** — GUI 自動化驗證

### 密碼學
- RC4、MD5、SHA1、RSA、ECDSA、SM4
- GF(2)/GF(2^8) 有限域運算
- Feistel CBC 區塊加密
- Pollard rho 演算法（橢圓曲線離散對數）

---

## 快速開始

```bash
# 複製倉庫
git clone https://github.com/rongkao/ctf-writeups.git
cd ctf-writeups

# 安裝 Python 相依套件
pip install z3-solver capstone pefile unicorn

# 執行任意求解腳本
python KCTF2026/01_rechall/solve.py
```

## 目錄結構

```
ctf-writeups/
├── README.md                        # 本文件
├── KCTF2026/                        # 看雪2026逆向靶場
│   ├── 01_rechall/
│   │   ├── solve.py                 # 求解腳本
│   │   └── writeup.md               # 詳細題解
│   ├── 02_yueyueyushi/
│   ├── ...
│   └── 08_TencentPediyKeygenMe/
│       ├── keygen.py                # 註冊機
│       ├── sm4_impl.py              # SM4 實作
│       ├── keygen_cipher.py         # Feistel CBC
│       └── writeup.md
├── FlareOn/
│   ├── Fo4/                         # Flare-On 4 (2017)
│   │   ├── writeup.md               # 全題解
│   │   └── 01/ ~ 12/                # 每題求解腳本
│   └── Fo5/                         # Flare-On 5 (2018)
│       ├── writeup.md               # 全題解
│       └── 01/ ~ 12/                # 每題求解腳本
├── docs/                            # 深度分析文件
└── .gitignore
```

## 授權條款

本專案僅供學習與研究用途。所有題目版權歸原始出題方所有。
