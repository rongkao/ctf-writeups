# -*- coding: utf-8 -*-
"""
wp_audit.py —— WordPress 插件半自动审计器（配合《WP插件审计速成工作单》）
用法: python wp_audit.py <插件目录> [--all-sinks]
输出: 按漏洞类型分组的可疑代码位置（file:line + 摘要）
注意: 命中 ≠ 漏洞，需人工追数据流确认（工作单 §三）
"""
import os
import re
import sys
import argparse

# ── 检测规则 ──────────────────────────────────────────────
SUPERGLOBALS = r'\$_(GET|POST|REQUEST|COOKIE|SERVER)\b'

RULES = [
    # (类型, 严重度, 正则, 说明)
    ('SQLi',   'HIGH', rf'\$wpdb->(query|get_var|get_row|get_results|get_col)\s*\([^)]*{SUPERGLOBALS}', 'wpdb sink 直接吃超全局变量'),
    ('SQLi',   'HIGH', r'\$wpdb->prepare\s*\(\s*"[^"]*\$|prepare\s*\(\s*\'[^\']*\$', 'prepare() 占位符缺失（字符串内嵌变量）'),
    ('XSS',    'MED',  rf'(echo|print(?:_r)?)\s*.{{0,20}}{SUPERGLOBALS}', '超全局变量直接回显'),
    ('XSS',    'MED',  rf'wp_send_json_(success|error)\s*\([^)]*{SUPERGLOBALS}', 'JSON 响应回传未转义输入'),
    ('AUTH',   'HIGH', r"add_action\s*\(\s*['\"]wp_ajax_nopriv_", 'nopriv AJAX（未登录可调用，检查是否本应限权）'),
    ('POP',    'CRIT', rf'unserialize\s*\(\s*.{{0,30}}{SUPERGLOBALS}', '反序列化用户输入（找 POP 链 = RCE）'),
    ('POP',    'CRIT', rf'maybe_unserialize\s*\(.{{0,30}}{SUPERGLOBALS}', 'maybe_unserialize 吃用户输入'),
    ('POP',    'HIGH', r'(file_exists|file_get_contents|file_put_contents|fopen|is_dir)\s*\(.{0,30}phar://', 'phar:// 流操作（上传名触发反序列化）'),
    ('SSRF',   'HIGH', rf'(wp_remote_get|wp_remote_post|wp_remote_request|curl_init)\s*\(\s*.{{0,40}}{SUPERGLOBALS}', '服务端代抓用户指定 URL'),
    ('SSRF',   'HIGH', rf'file_get_contents\s*\(.{{0,30}}{SUPERGLOBALS}', 'file_get_contents 读用户 URL'),
    ('LFI',    'HIGH', rf'(include|include_once|require|require_once)\s*.{{0,30}}{SUPERGLOBALS}', '动态包含'),
    ('FILE',   'CRIT', r'move_uploaded_file\s*\(', '文件上传（检查后缀白名单）'),
    ('FILE',   'HIGH', rf'file_put_contents\s*\(.{{0,60}}{SUPERGLOBALS}', '任意路径写'),
    ('RCE',    'CRIT', r'\b(eval|assert)\s*\(', 'eval/assert'),
    ('RCE',    'CRIT', r'\b(system|exec|shell_exec|passthru|popen)\s*\(', '命令执行函数'),
    ('RCE',    'CRIT', rf'call_user_func(_array)?\s*\(.{{0,40}}{SUPERGLOBALS}', '动态函数调用'),
    ('SECRET', 'LOW',  r'(api[_-]?key|secret|token)\s*=>?\s*[\'"][A-Za-z0-9]{16,}[\'"]', '疑似硬编码密钥'),
    ('DEBUG',  'LOW',  r'define\s*\(\s*[\'\"]WP_DEBUG[\'\"]\s*,\s*true', '调试模式常开'),
]

# nonce/权限检查的辅助启发：ajax handler 注册行 vs 同文件是否有防护
AJAX_REGISTER = re.compile(r"add_action\s*\(\s*['\"]wp_ajax_(nopriv_)?([^'\"]+)['\"]")
GUARD = re.compile(r'check_ajax_referer|current_user_can|wp_verify_nonce|is_admin\s*\(')


def audit_file(path, all_sinks=False):
    hits = []
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
    except OSError:
        return hits
    has_guard = any(GUARD.search(l) for l in lines)
    for no, line in enumerate(lines, 1):
        for vtype, sev, pat, desc in RULES:
            if re.search(pat, line):
                snippet = line.strip()[:160]
                hits.append((vtype, sev, path, no, desc, snippet))
        # AJAX handler 无防护启发式
        m = AJAX_REGISTER.search(line)
        if m and not has_guard:
            hits.append(('AUTH', 'MED', path, no, f'AJAX handler "{m.group(2)}" 所在文件未见 nonce/权限检查',
                         line.strip()[:160]))
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('target', help='插件目录或单个 PHP 文件')
    args = ap.parse_args()

    files = []
    if os.path.isfile(args.target):
        files = [args.target]
    else:
        for root, _, names in os.walk(args.target):
            files += [os.path.join(root, n) for n in names if n.endswith('.php')]

    all_hits = []
    for f in files:
        all_hits += audit_file(f)

    # 分组输出
    order = {'CRIT': 0, 'HIGH': 1, 'MED': 2, 'LOW': 3}
    all_hits.sort(key=lambda h: (order[h[1]], h[0]))
    cur = None
    for vtype, sev, path, no, desc, snippet in all_hits:
        key = (vtype, sev)
        if key != cur:
            cur = key
            print(f'\n=== [{sev}] {vtype} ===')
        print(f'  {path}:{no}  {desc}')
        print(f'      {snippet}')

    print(f'\n总计: {len(files)} 个 PHP 文件, {len(all_hits)} 处可疑点')
    print('提示: 命中≠漏洞 —— 按工作单 §三 人工追数据流（source→sink 之间的有效过滤才算安全）')


if __name__ == '__main__':
    main()
