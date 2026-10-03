# -*- coding: utf-8 -*-
# 05 zyzy: Error 弹窗挂起时全内存搜索 —— 定位真机执行流与仿真的分歧点
import time, subprocess, ctypes, re, sys
import win32gui, win32process, win32con
from pywinauto import Application

ctypes.windll.kernel32.OpenProcess.restype = ctypes.c_void_p
k32 = ctypes.windll.kernel32

INPUT = b'f250e3d75820847d427f3af11a783379AAAAAA'

class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_ulong), ('RegionSize', ctypes.c_size_t),
                ('State', ctypes.c_ulong), ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong)]

def read_all(h):
    out = []
    addr = 0
    mbi = MBI()
    while addr < 0x7FFF0000:
        if not k32.VirtualQueryEx(ctypes.c_void_p(h), ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
            break
        rs = mbi.RegionSize or 0x1000
        if mbi.State == 0x1000 and (mbi.Protect & 0x66) and not (mbi.Protect & 0x100):
            size = min(rs, 0x2000000)
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t()
            if k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(mbi.BaseAddress), buf, size, ctypes.byref(read)):
                out.append((mbi.BaseAddress, buf.raw[:read.value]))
        addr = (mbi.BaseAddress or 0) + rs
    return out

# 交互
subprocess.run(['taskkill', '/F', '/IM', 'zyzy.exe'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu\zyzy.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu')
time.sleep(3.5)
main = win32gui.FindWindow(None, 'Junk_Instruction')
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus(); time.sleep(0.3)
edits = [c for c in dlg.children() if c.class_name() == 'Edit']
edits[0].set_edit_text(INPUT.decode())
time.sleep(0.4)
btns = [c for c in dlg.children() if c.class_name() == 'Button']
btns[0].click_input()
time.sleep(1.5)

h = k32.OpenProcess(0x410, False, pid)
blobs = read_all(h)
print('regions:', len(blobs))

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    o = bytearray(); x = y = 0
    for b in data:
        x = (x+1)&0xFF; y = (y+S[x])&0xFF
        S[x], S[y] = S[y], S[x]
        o.append(b ^ S[(S[x]+S[y])&0xFF])
    return bytes(o)

HARD = bytes.fromhex('5bd6d026c8dd197e6e3ecb16917dffafdd7664b0f7e58957829f0c009ed045fa')
CIPHER = rc4(b'qwertyuiop', INPUT)
targets = {
    '原始输入(ascii)': INPUT,
    '原始输入(wide)': INPUT.decode().encode('utf-16le'),
    '硬编码目标32B': HARD,
    'RC4密文38B': CIPHER,
    'RC4密文前32B': CIPHER[:32],
}
for tag, pat in targets.items():
    hits = []
    for base, blob in blobs:
        for m in re.finditer(re.escape(pat), blob):
            hits.append(base + m.start())
    print(f'{tag}: {[hex(x) for x in hits[:6]]}')

# 关弹窗
for w in app.windows():
    try:
        if w.window_text() == 'Dialog':
            w.close()
    except Exception:
        pass
