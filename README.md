# CTF Reverse Engineering Writeups

> 逆向工程 CTF 题解合集 — 包含 KCTF2026 看雪靶场全 8 题 + Flare-On 4 全 12 题

## 目录

### KCTF2026 看雪逆向靶场 (8/8 ✅)

| # | 题目 | 难度 | 核心技术 | Writeup |
|---|------|------|----------|---------|
| 01 | [rechall](KCTF2026/01_rechall/) | ★★☆☆☆ | z3 约束求解、位运算 | [writeup](docs/2026-09-21_CTF-KCTF-Windows-Reverse-4题-writeup.md) |
| 02 | [跃跃欲试](KCTF2026/02_yueyueyushi/) | ★★★☆☆ | ASPack 脱壳、capstone 自动化 | [writeup](docs/2026-09-21_CTF-KCTF-Windows-Reverse-4题-writeup.md) |
| 03 | [金山2007](KCTF2026/03_kanxue_jinshan2007/) | ★★★☆☆ | 哈希逆向、BFS 状态搜索 | [writeup](docs/2026-09-21_CTF-KCTF-Windows-Reverse-4题-writeup.md) |
| 04 | [CCG CrackMe](KCTF2026/04_CCG_CrackMe/) | ★★★☆☆ | UPX 脱壳、MD5/RC4/RSA-64 | [writeup](docs/2026-09-21_CTF-KCTF-Windows-Reverse-4题-writeup.md) |
| 05 | [知言知语](KCTF2026/05_zhiyanzhiyu/) | ★★★☆☆ | 花指令、RC4 流密码 | [writeup](docs/2026-09-21_CTF-KCTF-ZhiYanZhiYu-writeup.md) |
| 06 | [BabyRev](KCTF2026/06_rev_babyrev/) | ★★★☆☆ | UPX 魔改壳 + Rust XOR 链 | [writeup](docs/2026-10-03_CTF-KCTF-BabyRev-writeup.md) |
| 07 | [CORE CrackMe v2](KCTF2026/07_CORE_CrackMe_v2/) | ★★★★☆ | 魔改 MD5 + GF(2) 矩阵逆 | [writeup](docs/2026-09-21_CTF-KCTF-CORE-CrackMe-v2-writeup.md) |
| 08 | [TencentPediy KeygenMe](KCTF2026/08_TencentPediyKeygenMe/) | ★★★★★ | ECDSA + SM4 + Feistel + GF(2^8) | [writeup](docs/KCTF2026-08-TencentPediyKeygenMe-writeup.md) |

### Flare-On 4 / 2017 (12/12 ✅)

| # | 题目 | 核心技术 | Flag |
|---|------|----------|------|
| 01 | login.html | JavaScript 逆向 | `ClientSideLoginsAreEasy@flare-on.com` |
| 02 | IgniteMe | XOR 链解密 | `R_y0u_H0t_3n0ugH_t0_1gN1t3@flare-on.com` |
| 03 | greek_to_me | 单字节爆破 | `et_tu_brute_force@flare-on.com` |
| 04 | notepad | PE 时间戳链 + XOR | `bl457_fr0m_th3_p457@flare-on.com` |
| 05 | pewpewboat | 战舰游戏 + ROT13 | `y0u__sUnK_mY__P3Wp3w_b04t@flare-on.com` |
| 06 | payload | DLL 导出 + 解密 | `wuuut-exp0rts@flare-on.com` |
| 07 | zsud | 文字冒险 + 密码学 | `mudd1ng_by_y0ur53lph@flare-on.com` |
| 08 | flair | ELF 共享库 | `pc_lo4d_l3tt3r_gl1tch@flare-on.com` |
| 09 | remorse.ino | Arduino HEX 分析 | `no_r3m0rs3@flare-on.com` |
| 10 | shell.php | PHP WebShell 解密 | `th3_xOr_is_waaaay_too_w34k@flare-on.com` |
| 11 | covfefe | SUBLEQ VM | `subleq_and_reductio_ad_absurdum@flare-on.com` |
| 12 | [coolprogram] | .NET + 多层加密 | `n3v3r_gunna_l3t_you_down_1987_4_ever@flare-on.com` |

**[完整 Flare-On 4 题解](docs/FlareOn4-2017-全12题-writeup.md)**

---

## 技术栈

### 逆向工具
- **IDA Pro** — 静态分析
- **x64dbg / x32dbg** — 动态调试
- **Ghidra** — 反编译
- **capstone** — Python 反汇编引擎

### 求解工具
- **z3 (SMT Solver)** — 约束求解
- **Python** — 脚本自动化
- **Unicorn Engine** — CPU 仿真
- **pywinauto** — GUI 自动化验证

### 密码学
- RC4, MD5, SHA1, RSA, ECDSA, SM4
- GF(2)/GF(2^8) 有限域运算
- Feistel CBC 分组密码
- Pollard rho 算法 (椭圆曲线离散对数)

---

## 快速开始

```bash
# 克隆仓库
git clone <repo-url>
cd ctf

# 安装 Python 依赖
pip install z3-solver capstone pefile unicorn

# 运行任意 solve 脚本
python KCTF2026/01_rechall/solve.py
```

## 目录结构

```
ctf/
├── README.md                    # 本文件
├── KCTF2026/                    # 看雪2026逆向靶场
│   ├── 01_rechall/
│   │   ├── solve.py             # 求解脚本
│   │   └── writeup.md           # 详细题解
│   ├── 02_yueyueyushi/
│   ├── ...
│   └── 08_TencentPediyKeygenMe/
│       ├── keygen.py            # 注册机
│       ├── sm4_impl.py          # SM4 实现
│       ├── keygen_cipher.py     # Feistel CBC
│       └── writeup.md
├── FlareOn/
│   └── Fo4/                     # Flare-On 4 (2017)
│       ├── writeup.md           # 全题解
│       ├── 01/ ~ 12/            # 每题 solve 脚本
│       └── ...
└── .gitignore
```

## License

本项目仅用于学习和研究目的。所有题目版权归原始出题方所有。
