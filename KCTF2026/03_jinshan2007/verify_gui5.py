# -*- coding: utf-8 -*-
# 03 真机验证 v5：UIA 读 MessageBox 文本（不依赖 Static 类名）
import time
import win32gui, win32con, win32process
from pywinauto import Application

# 启动新进程
import subprocess
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\03_jinshan2007\CrackMe.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\03_jinshan2007')
time.sleep(2.5)

main = win32gui.FindWindow(None, 'CrackMe2')
tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid)

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
btn = [h for h, c, i in children if c == 'Button' and i == 1000][0]

serial = open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt').read().split()
name, sn = serial[0], serial[1]

ok1 = win32gui.SetWindowText(edit_by_id[1001], name)
ok2 = win32gui.SetWindowText(edit_by_id[1002], sn)
time.sleep(0.5)
print('set result:', ok1, ok2,
      '| readback1001:', repr(win32gui.GetWindowText(edit_by_id[1001])),
      '| len1002:', len(win32gui.GetWindowText(edit_by_id[1002])))

win32gui.PostMessage(btn, win32con.BM_CLICK, 0, 0)
time.sleep(2.5)

# UIA 全量枚举顶层窗口，找同 pid 的非主窗口
from pywinauto import Desktop
try:
    for w in Desktop(backend='uia').windows():
        try:
            info = w.element_info
            if info.process_id == pid:
                print('UIA top:', repr(w.window_text()), '|', w.class_name())
                for c in w.descendants():
                    try:
                        ct = c.element_info.control_type
                        t = c.window_text()
                        if t:
                            print('   child:', ct, repr(t))
                    except Exception:
                        pass
        except Exception:
            pass
except Exception as e:
    print('uia enum err:', e)

# win32 backend 备用：列出所有子控件类名（不过滤）
try:
    app = Application(backend='win32').connect(process=pid)
    for w in app.windows():
        if w.window_text() != 'CrackMe2':
            print('WIN32 BOX:', repr(w.window_text()), w.class_name())
            for c in w.children():
                print('   ', c.class_name(), repr(c.window_text()))
except Exception as e:
    print('win32 enum err:', e)
