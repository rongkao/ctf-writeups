# Supplementary Materials — Cyber Verification Program Application

**Applicant:** [Your Name / Stable Handle]
**Date:** 2026-09-21
**Access Path:** Claude Code (CLI) + Claude.ai

---

## Profile

I am a security researcher focused on **Windows reverse engineering and defensive tool development**. My work consists of three continuous, verifiable activity streams — all legitimate and defensive in nature:

1. **CTF algorithm analysis training** on official competition platforms (Kanxue KCTF, Mandiant/Google Flare-On, crackmes.one). All analyzed binaries are publicly released educational challenges — no real-world targets, no live vulnerabilities.

2. **Defensive kernel driver development** — my flagship project *ProcessGuard* (detailed below), which implements the same self-protection mechanism used by commercial antivirus products.

3. **Public technical writing** — a five-part technical writeup series on reverse engineering methodology, to be published on the Kanxue Security Community (bbs.kanxue.com), China's longest-established security research forum.

## Flagship Defensive Project: ProcessGuard

| | |
|---|---|
| **Type** | Windows kernel driver (x64, WDK-built) |
| **Mechanism** | `ObRegisterCallbacks` — Microsoft's officially documented process-protection interface |
| **Function** | Strips dangerous handle rights (TERMINATE / VM_READ / VM_WRITE / DUP_HANDLE / CREATE_THREAD) when external processes attempt to open protected processes |
| **Defensive value** | Researches how security software protects itself against termination, memory tampering, and code injection — the same self-protection model used by commercial EDR/AV products |
| **Stack** | Pure documented APIs only (ntddk.h, ObRegisterCallbacks, IoCreateDevice); includes full source, build scripts, and documentation |

Source & README: [GitHub link — to be added upon publication]

## Published / In-Publication Writeups

| # | Title | Platform |
|---|-------|----------|
| 1 | Windows Reverse Engineering on KCTF Range (4 challenges: constraint solving, RC4/RSA educational cases) | Kanxue KCTF |
| 2 | CORE CrackMe v2.0 — Full Algorithm Recovery (modified-MD5 identification, GF(2) transform inversion) | Kanxue KCTF |
| 3 | MFC Binary Analysis and Emulation-Based Verification Methodology | Kanxue KCTF |
| 4 | Classic Validation-Chain Analysis on crackmes.one | crackmes.one |
| 5 | Flare-On 4 Challenges C2 & C3 (self-decrypting payload analysis, custom checksum reproduction) | Flare-On (Mandiant) |

Links to be appended upon publication.

## Why I Am Requesting CVP

Claude Code frequently blocks my legitimate research tasks, including:

- Reading and analyzing PE file structures of educational CTF binaries
- Developing Windows kernel drivers with the Windows Driver Kit (WDK)
- Discussing hash and cipher algorithm internals (e.g., MD5 variants, RC4) in an educational analysis context

These blocks significantly impede defensive research and documentation work that falls squarely within legitimate dual-use activity.

## Declaration

All materials referenced above are genuine research outputs produced by me. No fabricated credentials are included. Should additional verification be needed (CVE records, employment proof, published article links), I am happy to provide them.

[If applicable, list here: CVE-NUMBER-XXXX + vendor acknowledgment URL / Employer: Company, Role / Certifications: Credly badges]

---

*Contact: [Your verified email on the Anthropic account]*
