# -*- coding: utf-8 -*-
# 07 CORE 地面真值 v2：VirtualQueryEx 全內存遍歷，彈窗掛起時抓真實 MD5 輸入串
import sys, time, subprocess, ctypes, re, hashlib, struct
import win32gui, win32process
from pywinauto import Application

ctypes.windll.kernel32.OpenProcess.restype = ctypes.c_void_p
k32 = ctypes.windll.kernel32

TITLE = 'CORE Official CrackMe v2.0 - Written by Egis/CORE'
NAME = 'testZZZZ9'
CODE = 'aaa bbb ccc'

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_ulong), ('RegionSize', ctypes.c_size_t),
                ('State', ctypes.c_ulong), ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong)]

def read_all(h):
    """遍歷全部 MEM_COMMIT 可讀內存，返回 [(base, bytes)]"""
    out = []
    addr = 0
    mbi = MBI()
    PAGE_READABLE = 0x02 | 0x04 | 0x20 | 0x40  # R, RW, RX, RWX
    while addr < 0x7FFF0000:
        if not k32.VirtualQueryEx(ctypes.c_void_p(h), ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        rs = mbi.RegionSize or 0x1000
        if mbi.State == 0x1000 and (mbi.Protect & PAGE_READABLE) and not (mbi.Protect & 0x100):  # commit, readable, not PAGE_GUARD
            size = min(rs, 0x2000000)
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t()
            if k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(mbi.BaseAddress), buf, size, ctypes.byref(read)):
                out.append((mbi.BaseAddress, buf.raw[:read.value]))
        addr = (mbi.BaseAddress or 0) + rs
    return out

# ── 啟動 + 交互 ──
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
print('readback name:', repr(edits[0].window_text()), '| edits:', len(edits))
edits[0].set_edit_text(NAME)
edits[1].set_edit_text(CODE)
time.sleep(0.4)
print('readback name:', repr(edits[0].window_text()), 'code:', repr(edits[1].window_text()))
ok = [c for c in dlg.children() if c.class_name() == 'Button' and c.control_id() == 1002][0]
ok.click_input()
time.sleep(1.5)

h = k32.OpenProcess(0x410, False, pid)
print('handle:', h, 'pid:', pid)
blobs = read_all(h)
print('regions read:', len(blobs), 'total MB:', sum(len(b) for _, b in blobs)//1048576)

marker = NAME.encode()
print()
print('=== 標記出現位置（前 8 個）===')
hits = 0
for base, blob in blobs:
    for m in re.finditer(re.escape(marker), blob):
        s = max(0, m.start()-8)
        ctx = blob[s:m.start()+200]
        print(f'@0x{base+m.start():x}: {ctx!r}')
        hits += 1
        if hits >= 8: break
    if hits >= 8: break
if not hits:
    print('!! 標記未找到 —— 彈窗可能未掛起或讀取失敗')

# 候選 MD5 搜索
print()
print('=== 候選 MD5 命中 ===')
rev = NAME[::-1]
cands = {'name': NAME, 'name+rev': NAME+rev, 'name+rev2': NAME+rev*2, 'name+rev3': NAME+rev*3}
for tag, s in cands.items():
    d = hashlib.md5(s.encode()).digest()
    found = [(base+blob.find(d[:12])) for base, blob in blobs if d[:12] in blob]
    if found:
        print(f'{tag} ({s!r}): {[hex(x) for x in found]}')

# 關彈窗
for w in app.windows():
    try:
        if w.window_text() in ('Failed', 'M'):
            w.close()
    except Exception:
        pass
