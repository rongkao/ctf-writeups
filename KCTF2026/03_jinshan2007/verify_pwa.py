# -*- coding: utf-8 -*-
# 03 真机验证（pywinauto 正确姿势版）
import time, subprocess
import win32gui, win32process
from pywinauto import Application

parts = open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt').read().split()
name, sn = parts[0], parts[1]
print(f'name={name} serial({len(sn)} digits)')

subprocess.run(['taskkill', '/F', '/IM', 'CrackMe.exe'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\03_jinshan2007\CrackMe.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\03_jinshan2007')
time.sleep(2.5)

main = win32gui.FindWindow(None, 'CrackMe2')
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus()
time.sleep(0.3)

name_box = dlg.child_window(control_id=1001, class_name='Edit')
sn_box = dlg.child_window(control_id=1002, class_name='Edit')
name_box.set_edit_text(name)
sn_box.set_edit_text(sn)
time.sleep(0.5)
print('filled name:', name_box.texts(), '| sn len:', len(sn_box.texts()[0]))

btn = [c for c in dlg.children() if c.class_name() == 'Button' and c.control_id() == 1000][0]
btn.click_input()
time.sleep(2)

# 03 的 MessageBox 标题为空，枚举同进程新窗口读所有子控件
for w in app.windows():
    try:
        if w.window_text() != 'CrackMe2':
            kids = [(c.class_name(), c.window_text()) for c in w.children()]
            print('>>> MSGBOX:', repr(w.window_text()), kids)
            w.close()
    except Exception:
        pass
