# CVP（Cyber Verification Program）申请辅助材料包

> 版本：2026-09-21 · 面向 Anthropic CVP 申请的补充材料总览
> 用途：配合 Verification Portal 的 cyber-use-case 表单提交
> 申请人：【你的姓名 / 稳定技术 ID】

---

## 一、研究定位（叙事框架）

**定位声明：Windows 安全研究员，方向为逆向分析与防御性工具开发。**

三条持续活动线，全部为合法防御性质：

```
① CTF 算法研究训练（官方平台）
   看雪 KCTF / Mandiant Flare-On / crackmes.one
   —— 通过分析出题人构造的校验算法，维持逆向分析能力
   —— 所有题目均为平台公开发布的教育性质挑战

② 防御工具开发（核心成果）
   ProcessGuard —— 进程保护内核驱动
   —— 与商业杀软自我保护模块同机制（ObRegisterCallbacks 句柄权限剥离）
   —— 纯防御目的：研究"如何保护进程不被恶意结束/注入"

③ 公开技术写作（社区贡献）
   5 篇完整技术 writeup，拟发布于看雪安全社区
   —— 逆向方法论、算法还原过程、防御机制解析
```

## 二、核心防御项目：ProcessGuard

| 属性 | 值 |
|------|---|
| 项目名 | ProcessGuard —— 进程保护驱动 |
| 类型 | Windows 内核驱动（KMDF/NT 驱动模型）x64 |
| 技术机制 | ObRegisterCallbacks（微软官方文档化接口） |
| 功能 | 剥离外部进程对受保护进程的危险句柄权限（TERMINATE / VM_READ / VM_WRITE / DUP_HANDLE / CREATE_THREAD） |
| 防御价值 | 研究杀毒软件自我保护机制：使安全软件进程无法被恶意程序终止、内存篡改或代码注入 |
| 代码规模 | 驱动 341 行（C）+ 控制台工具 + 编译脚本 + 完整文档 |
| 同类商业实现 | 360 安全保险箱自我保护、卡巴斯基自我保护、各大 EDR |

**代码要点（可直接向审核人展示）：**
- 仅使用微软公开文档化接口（ntddk.h / ObRegisterCallbacks / IoCreateDevice）
- 白名单逻辑：受保护进程自身与内核态请求放行（避免破坏系统）
- 完整的 README 含原理图与免责声明（"仅用于安全研究与驱动开发学习"）

## 三、公开技术写作索引（CTF Writeup 系列）

> 所有分析对象均为**官方比赛/教育平台公开发布的题目文件**，无真实目标、无在野漏洞。

| # | 标题 | 平台 | 防御性解读 |
|---|------|------|-----------|
| 1 | KCTF 靶场 Windows 逆向四连破 | 看雪 KCTF | 校验算法分析（z3 约束求解/RC4/RSA 弱模数教学案例） |
| 2 | CORE 官方 CrackMe v2.0 完全攻破 | 看雪 KCTF | 魔改 MD5 变体识别 + GF(2) 线性变换还原（哈希实现审计方法论） |
| 3 | 直言直语 RC4 迷阵 | 看雪 KCTF | MFC 消息映射定位 + 仿真仲裁法（调试方法论） |
| 4 | crackmes.one 实战 | crackmes.one（教育平台） | 经典校验链分析 + 暴力度量数学 |
| 5 | Flare-On 4 双杀 | Mandiant/Google 官方年度赛 | 自解密 payload 分析 + 自定义校验和复现（恶意样本分析训练） |

**发表计划**：以上 5 篇将以稳定 ID 发布于看雪安全社区（bbs.kanxue.com），发布后链接将补充至申请材料。

## 四、cyber-use-case 表单填写建议（逐字段）

| 表单项 | 建议内容 |
|--------|---------|
| 职业身份 | Security Researcher（Windows 逆向 / 防御工具开发方向）【如在职：填公司+职位】 |
| 使用目的 | "Defensive security research: (1) reverse engineering analysis of educational CTF challenges to maintain analysis skills; (2) development of defensive kernel drivers (process protection); (3) technical writing about malware analysis methodology." |
| 受影响的具体任务 | "Claude Code frequently blocks legitimate analysis tasks: reading PE file structures, developing Windows kernel drivers with WDK, discussing hash/cipher algorithm internals used in CTF educational challenges." |
| 证明材料 | 按强度排序提交：①【如有】CVE 编号+厂商致谢链接 ②【如有】安全公司在职证明/公司邮箱 ③ ProcessGuard 项目链接（GitHub，含 README） ④ 已发表的 writeup 链接 |
| 平台 | Claude Code（CLI）+ Claude.ai |

**措辞红线**：
- ✅ 用：analysis / research / defensive / protection / educational challenges / methodology
- ❌ 避开：attack / exploit development / offensive / hacking（这些词触发风控加权）

## 五、提交前行动清单

```
□ 1. 以真实姓名或长期稳定 ID 注册/登录看雪社区
□ 2. 发布 5 篇 writeup（D:\codes\ctf\docs\ 下已就绪），收集链接
□ 3. ProcessGuard 推送到 GitHub 公开仓库（含 README + 源码）
□ 4. 整理个人硬证据：CVE / 在职证明 / Credly 证书（如有）
□ 5. Verification Portal 完成身份验证（ID 文件）
□ 6. 提交表单，两个工作日内查邮箱（含垃圾箱）
□ 7.【被拒则】用申诉表单补充材料再提交（官方承认会误拒）
```

## 六、预期管理（基于社区实测数据）

- 个人身份 + 纯 CTF/防御项目材料：**五五开**
- 有 CVE 或公司邮箱：通过率显著提升
- 过审后注意：
  - 审批**绑定组织 ID**——申请时的账号/组织要与日常使用一致
  - Windows 平台仍可能概率触发（社区报告的设备指纹问题），macOS 触发率低
  - 禁止类内容（勒索软件等）无论是否过审都保持拦截

---

*本材料包所有内容均为真实研究产出，无虚构 credentials。*
