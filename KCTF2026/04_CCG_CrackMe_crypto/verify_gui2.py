# -*- coding: utf-8 -*-
# 04 真机验证 v2：pywinauto click_input（DPI aware）
import time, subprocess, sys
import win32gui, win32process
from pywinauto import Application

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto')
from keygen import keygen

NAME = 'KCTF'
serial, _ = keygen(NAME)
print('name:', NAME, 'serial:', serial)

subprocess.run(['taskkill', '/F', '/IM', 'crackme_crypto.exe'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto\crackme_crypto.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto')
time.sleep(3)

main = win32gui.FindWindow(None, 'CCG Crypto Crackme v1.0  ---  by blowfish')
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus()
time.sleep(0.5)

# 用 pywinauto type_keys 填入（真实键盘消息）
name_box = dlg.child_window(control_id=1008, class_name='Edit')
ser_box = dlg.child_window(control_id=1007, class_name='Edit')
name_box.set_edit_text(NAME)
ser_box.set_edit_text(serial)
time.sleep(0.5)
print('filled:', name_box.texts(), len(ser_box.texts()[0]) if ser_box.texts() else 0)

reg_btn = dlg.child_window(control_id=1003, class_name='Button')
reg_btn.click_input()
time.sleep(2.5)

for w in app.windows():
    try:
        t = w.window_text()
        if t in ('Great', 'Failed'):
            kids = [(c.class_name(), c.window_text()) for c in w.children()]
            print(f'>>> MSGBOX [{t}]:', kids)
            w.close()
    except Exception as e:
        pass
