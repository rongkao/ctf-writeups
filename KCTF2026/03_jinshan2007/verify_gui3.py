# -*- coding: utf-8 -*-
# 03 真机验证 v3：pywinauto 真实点击
import time
from pywinauto import Application

app = Application(backend='win32').connect(title='CrackMe2')
dlg = app.window(title='CrackMe2')
dlg.set_focus()
time.sleep(0.3)

children = dlg.children()
for ch in children:
    print(ch.class_name(), ch.control_id(), repr(ch.window_text()))

btn = [c for c in children if c.class_name() == 'Button'][0]
btn.click_input()
time.sleep(2)

# 找弹窗（同进程新窗口）
for w in Application(backend='win32').windows():
    try:
        if w.class_name() == '#32770' and w.window_text() != 'CrackMe2':
            texts = [c.window_text() for c in w.children()]
            print('BOX:', repr(w.window_text()), '| children texts:', texts)
    except Exception as e:
        print('err', e)
