# -*- coding: utf-8 -*-
# 07 CORE 地面真值：點擊後彈窗掛起時 dump 棧，抓真實 MD5 輸入串 + 期望值
import sys, time, subprocess, ctypes, re
import win32gui, win32process, win32con
from pywinauto import Application

TITLE = 'CORE Official CrackMe v2.0 - Written by Egis/CORE'
NAME = 'testZZZZ9'   # 唯一標記，避免與其他內存撞
CODE = 'aaa bbb ccc' # 三個合法十六進制，能過 sscanf

subprocess.run(['taskkill', '/F', '/IM', 'CRACKME3.EXE'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\CRACKME3.EXE'],
                     cwd=r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
time.sleep(3)
main = win32gui.FindWindow(None, TITLE)
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus(); time.sleep(0.3)
edits = [c for c in dlg.children() if c.class_name() == 'Edit']
edits[0].set_edit_text(NAME)
edits[1].set_edit_text(CODE)
time.sleep(0.4)
ok = [c for c in dlg.children() if c.class_name() == 'Button' and c.control_id() == 1002][0]
ok.click_input()
time.sleep(1.5)   # 彈窗掛起，棧幀活著

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
h = k32.OpenProcess(0x410, False, pid)
read = ctypes.c_size_t()

# 掃線程棧區域（32 位進程棧通常在 0x100000-0x400000）
blobs = []
for base in range(0x100000, 0x400000, 0x10000):
    buf = ctypes.create_string_buffer(0x10000)
    if k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(base), buf, 0x10000, ctypes.byref(read)):
        blobs.append((base, buf.raw[:read.value]))

marker = NAME.encode()
print('=== 棧中標記出現位置及上下文 ===')
for base, blob in blobs:
    for m in re.finditer(re.escape(marker), blob):
        s = max(0, m.start()-16)
        ctx = blob[s:m.start()+260]
        print(f'@0x{base+m.start():x}: {ctx!r}')

# 找 MD5 期望值：計算幾個候選串的 MD5 前綴並在棧中搜索
import hashlib, struct
print()
print('=== 候選 MD5 在棧中的命中 ===')
rev = NAME[::-1]
cands = {
    'name+rev': NAME + rev,
    'name+rev*2': NAME + rev*2,
    'name+rev*3': NAME + rev*3,
    'name': NAME,
}
for tag, s in cands.items():
    d = hashlib.md5(s.encode()).digest()
    for base, blob in blobs:
        if d[:12] in blob:
            off = blob.find(d[:12])
            print(f'{tag}: HIT @0x{base+off:x} 串={s!r}')
            # 打印附近（轉換後的 v 值就在附近）
            around = blob[max(0,off-64):off+64]
            print('   ctx:', around.hex())
        # 也搜 3 dword 反序（大端可能性）
        words = struct.pack('>3I', *struct.unpack('<3I', d[:12]))
        if words in blob:
            print(f'{tag}: BE-HIT 串={s!r}')
# 關閉彈窗
for w in app.windows():
    try:
        if w.window_text() == 'Failed':
            w.close()
    except Exception:
        pass
