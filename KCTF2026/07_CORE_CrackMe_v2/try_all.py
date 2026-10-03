# -*- coding: utf-8 -*-
# 07 CORE 真机验证：依次试 N=1,2,3 的 keygen，捕获弹窗判定
import sys, time
import win32gui, win32process
from pywinauto import Application

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
from keygen import keygen

TITLE = 'CORE Official CrackMe v2.0 - Written by Egis/CORE'
main = win32gui.FindWindow(None, TITLE)
assert main, 'window not found'
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
dlg = app.top_window()
dlg.set_focus()
time.sleep(0.3)

name = 'test'
for n in (1, 2, 3):
    code = keygen(name, n)
    print(f'--- N={n}: code={code!r}')
    edits = [c for c in dlg.children() if c.class_name() == 'Edit']
    edits[0].set_edit_text(name)
    edits[1].set_edit_text(code)
    time.sleep(0.4)
    ok_btn = [c for c in dlg.children() if c.class_name() == 'Button' and c.control_id() == 1002][0]
    ok_btn.click_input()
    time.sleep(1.5)
    hit = False
    for w in app.windows():
        try:
            t = w.window_text()
            if t and t != TITLE:
                kids = [(c.class_name(), c.window_text()) for c in w.children()]
                print(f'    MSGBOX [{t!r}]:', kids)
                w.close()
                hit = True
                if any('CORE' in str(k) for k in kids):
                    print(f'    *** N={n} SUCCESS ***')
        except Exception:
            pass
    if not hit:
        print('    (no popup)')
print('done')
