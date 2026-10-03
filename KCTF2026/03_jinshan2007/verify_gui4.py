# -*- coding: utf-8 -*-
# 03 真机验证 v4：pywinauto 按 PID 连接 + 真实点击
import time, win32gui, win32process
from pywinauto import Application

main = win32gui.FindWindow(None, 'CrackMe2')
tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid)

app = Application(backend='win32').connect(process=pid)
dlg = app.window(title='CrackMe2')
dlg.set_focus()
time.sleep(0.3)

children = dlg.children()
for ch in children:
    print(ch.class_name(), ch.control_id(), repr(ch.window_text()))

btn = [c for c in children if ch.class_name() == 'Button']
btn = [c for c in children if c.class_name() == 'Button'][0]
btn.click_input()
time.sleep(2)

# 找同进程弹窗
tops = app.windows()
for w in tops:
    try:
        if w.class_name() == '#32770' and w.window_text() != 'CrackMe2':
            texts = [c.window_text() for c in w.children()]
            print('BOX:', repr(w.window_text()), '| children:', texts)
    except Exception as e:
        print('err', e)
