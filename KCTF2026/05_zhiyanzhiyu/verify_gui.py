# -*- coding: utf-8 -*-
# 05 zhiyanzhiyu 真机验证
import sys, time, subprocess
import win32gui, win32process
from pywinauto import Application

FLAG = 'f250e3d75820847d427f3af11a783379'
TITLE = 'Junk_Instruction'

subprocess.run(['taskkill', '/F', '/IM', 'zyzy.exe'], capture_output=True)
time.sleep(0.8)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu\zyzy.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\05_zhiyanzhiyu')
time.sleep(3.5)
main = win32gui.FindWindow(None, TITLE)
if not main:
    print('ERROR: window not found')
    sys.exit(1)

tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus(); time.sleep(0.3)
edits = [c for c in dlg.children() if c.class_name() == 'Edit']
edits[0].set_edit_text(FLAG)
time.sleep(0.4)
btns = [c for c in dlg.children() if c.class_name() == 'Button']
btns[0].click_input()
time.sleep(1.8)

hit = False
for w in app.windows():
    try:
        t = w.window_text()
        if t and t != TITLE and t not in ('M', 'Default IME', 'MSCTFIME UI'):
            kids = [(c.class_name(), c.window_text()) for c in w.children()]
            print(f'MSGBOX [{t!r}]: {kids}')
            w.close()
            hit = True
    except Exception:
        pass
if not hit:
    print('(no popup)')

subprocess.run(['taskkill', '/F', '/IM', 'zyzy.exe'], capture_output=True)
