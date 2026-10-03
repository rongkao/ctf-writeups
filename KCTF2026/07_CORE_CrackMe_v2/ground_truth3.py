# -*- coding: utf-8 -*-
# 07 CORE 地面真值 v3：读栈上 ebp 附近的 m0/m1/m2 与 v1'/v2''/v3'，与离线计算对照
import sys, time, subprocess, ctypes, struct, hashlib
import win32gui, win32process
from pywinauto import Application

ctypes.windll.kernel32.OpenProcess.restype = ctypes.c_void_p
k32 = ctypes.windll.kernel32
read = ctypes.c_size_t()

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
from keygen import forward, T1A, T1B, T2A, T2B, keygen

TITLE = 'CORE Official CrackMe v2.0 - Written by Egis/CORE'
NAME = 'test'                      # 与之前失败测试相同的 name
CODE = keygen(NAME, 3)             # 我 N=3 的 keygen: '715d64ea b7b1776f 6385e475'
print('code under test:', CODE)

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
time.sleep(1.5)

h = k32.OpenProcess(0x410, False, pid)

# 全内存找 buf608 = NAME + rev*3
import re
rev = NAME[::-1]
target = (NAME + rev * 3).encode()
found_base = None
addr = 0
class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_ulong), ('RegionSize', ctypes.c_size_t),
                ('State', ctypes.c_ulong), ('Protect', ctypes.c_ulong), ('Type', ctypes.c_ulong)]
while addr < 0x7FFF0000 and not found_base:
    mbi = MBI()
    if not k32.VirtualQueryEx(ctypes.c_void_p(h), ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        break
    rs = mbi.RegionSize or 0x1000
    if mbi.State == 0x1000 and mbi.BaseAddress and mbi.BaseAddress < 0x800000:
        size = min(rs, 0x100000)
        buf = ctypes.create_string_buffer(size)
        if k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(mbi.BaseAddress), buf, size, ctypes.byref(read)):
            off = buf.raw.find(target)
            if off >= 0:
                found_base = mbi.BaseAddress + off
    addr = (mbi.BaseAddress or 0) + rs

if not found_base:
    print('buf608 not found!'); sys.exit(1)

buf608 = found_base
ebp = buf608 + 0x608
print(f'buf608 @0x{buf608:x} → ebp=0x{ebp:x}')

# 读 ebp-0x40 .. ebp（覆盖 m0/m1/m2 与 v1'/v2''/v3'）
snap = ctypes.create_string_buffer(0x48)
k32.ReadProcessMemory(ctypes.c_void_p(h), ctypes.c_void_p(ebp - 0x40), snap, 0x48, ctypes.byref(read))
d = snap.raw[:read.value]
def dw(i): return struct.unpack('<I', d[i*4:i*4+4])[0]
print()
print('=== 栈上实际值 (相对 ebp 偏移) ===')
labels = {0x40-0x40:'ebp-0x40', 0x3c-0x40:'ebp-0x3c', 0x38-0x40:'ebp-0x38', 0x34-0x40:'ebp-0x34',
          0x30-0x40:'ebp-0x30', 0x2c-0x40:'ebp-0x2c', 0x28-0x40:'[ebp-0x28]', 0x24-0x40:'[ebp-0x24]',
          0x20-0x40:'m0', 0x1c-0x40:'m1', 0x18-0x40:'m2', 0x14-0x40:'ebp-0x14',
          0x10-0x40:'v1\'', 0x0c-0x40:'v2\'\'', 0x08-0x40:'v3\'', 0x04-0x40:'ebp-4', 0x00:'ebp'}
for i in range(len(d)//4):
    off = i*4
    tag = labels.get(off, hex(off))
    print(f'  {tag:12} = 0x{dw(i):08x}')

# ── 离线计算对照 ──
print()
print('=== 离线计算 ===')
md = hashlib.md5(NAME + rev*3).digest()
lm0, lm1, lm2 = struct.unpack('<3I', md[:12])
print(f'MD5(name+rev*3) = {md.hex()}')
print(f'离线 m0/m1/m2 = {lm0:08x} {lm1:08x} {lm2:08x}')
v1, v2, v3 = [int(x, 16) for x in CODE.split()]
a1, a2 = forward(T1A, T1B, v1, v2)
b1, b2 = forward(T2A, T2B, a2, v3)
print(f'离线变换: v1\'={a1:08x} v2\'\'={b1:08x} v3\'={b2:08x}')
print()
print(f'm0 匹配: 栈={dw(0x20//4):08x} 离线={lm0:08x} {"OK" if dw(0x20//4)==lm0 else "MISMATCH"}')
print(f'v1\' 匹配: 栈={dw(0x10//4):08x} 离线={a1:08x} {"OK" if dw(0x10//4)==a1 else "MISMATCH"}')

# 关弹窗
for w in app.windows():
    try:
        if w.window_text() == 'Failed':
            w.close()
    except Exception:
        pass
