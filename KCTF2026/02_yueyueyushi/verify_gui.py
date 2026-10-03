# -*- coding: utf-8 -*-
# 02 真机验证
import time, subprocess
import win32gui, win32process
from pywinauto import Application

subprocess.run(['taskkill', '/F', '/IM', 'yyys.exe'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\02_yueyueyushi\yyys.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\02_yueyueyushi')
time.sleep(3)

main = win32gui.FindWindow(None, 'Registration')
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus()
time.sleep(0.3)

children = [(c.class_name(), c.control_id(), c.window_text()) for c in dlg.children()]
for c in children:
    print(c)

edits = [(c.control_id(), c) for c in dlg.children() if c.class_name() == 'Edit']
# 1001=Email, 1002=code
for cid, ctrl in edits:
    ctrl.set_edit_text('user@kanxue.com' if cid == 0x3E9 else 'BZ9dm4qc8g9G7bAY')
time.sleep(0.5)

btns = [c for c in dlg.children() if c.class_name() == 'Button']
btns[0].click_input()
time.sleep(2)

for w in app.windows():
    try:
        if w.window_text() == 'Registeration':
            kids = [(c.class_name(), c.window_text()) for c in w.children()]
            print('>>> MSGBOX:', kids)
            w.close()
    except Exception:
        pass
