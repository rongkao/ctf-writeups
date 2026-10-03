# -*- coding: utf-8 -*-
"""Flare-On 4 题目侦察：greek_to_me.exe / IgniteMe.exe"""
import re, struct, glob

for name in ['greek_to_me', 'IgniteMe']:
    hits = glob.glob(rf'D:\codes\ctf\FlareOn\Fo4\**\{name}.exe', recursive=True)
    if not hits:
        print(f'=== {name}: NOT FOUND ===')
        continue
    path = hits[0]
    data = open(path, 'rb').read()
    pe_off = struct.unpack('<I', data[0x3c:0x40])[0]
    machine = struct.unpack('<H', data[pe_off+4:pe_off+6])[0]
    print(f'=== {name} ({len(data)}B, {hex(machine)}) ===')
    strs = [s.decode(errors='replace') for s in re.findall(rb'[\x20-\x7e]{4,}', data)]
    kw = [t for t in strs if re.search(r'flag|key|congrat|correct|wrong|input|flare|enter|success|fail|@', t, re.I)]
    seen = set()
    for t in kw[:20]:
        if t not in seen and len(t) < 90:
            seen.add(t)
            print(f'  {t!r}')
    # 希腊字母段（UTF-8 0xCE 开头双字节）
    greek = re.findall(rb'(?:\xce[\x80-\xff]){4,}', data)
    for g in greek[:3]:
        try:
            txt = g.decode('utf-8')[:40]
        except Exception:
            txt = repr(g[:20])
        print(f'  GREEK: {txt!r} ({len(g)} chars)')
    print()
