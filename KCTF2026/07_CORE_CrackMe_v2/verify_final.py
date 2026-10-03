# -*- coding: utf-8 -*-
# 07 CORE 真机验证（最终版 keygen）
import sys, time, subprocess
import win32gui, win32process
from pywinauto import Application

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
from keygen2 import keygen

TITLE = 'CORE Official CrackMe v2.0 - Written by Egis/CORE'

for name in ('test', 'KCTF'):
    code = keygen(name)
    print(f'--- name={name!r} code={code!r}')
    subprocess.run(['taskkill', '/F', '/IM', 'CRACKME3.EXE'], capture_output=True)
    time.sleep(0.8)
    p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\CRACKME3.EXE'],
                         cwd=r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
    time.sleep(2.5)
    main = win32gui.FindWindow(None, TITLE)
    assert main, 'window not found'
    tid, pid = win32process.GetWindowThreadProcessId(main)
    app = Application(backend='win32').connect(process=pid)
    dlg = app.top_window()
    dlg.set_focus(); time.sleep(0.3)
    edits = [c for c in dlg.children() if c.class_name() == 'Edit']
    edits[0].set_edit_text(name)
    edits[1].set_edit_text(code)
    time.sleep(0.4)
    ok = [c for c in dlg.children() if c.class_name() == 'Button' and c.control_id() == 1002][0]
    ok.click_input()
    time.sleep(1.8)
    hit = False
    for w in app.windows():
        try:
            t = w.window_text()
            if t and t != TITLE and t not in ('M', 'Default IME', 'MSCTFIME UI'):
                kids = [(c.class_name(), c.window_text()) for c in w.children()]
                print(f'    MSGBOX [{t!r}]:', kids)
                w.close()
                hit = True
                if any("CORE" in str(k) for k in kids):
                    print(f'    *** {name} SUCCESS ***')
        except Exception:
            pass
    if not hit:
        print('    (no popup)')
    subprocess.run(['taskkill', '/F', '/IM', 'CRACKME3.EXE'], capture_output=True)
print('done')
