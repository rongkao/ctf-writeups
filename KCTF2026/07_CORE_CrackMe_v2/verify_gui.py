# -*- coding: utf-8 -*-
# 07 CORE 真机验证：枚举控件 → 填入 → 点击 → 捕获弹窗（自动试 N=1,2,3）
import sys, time, subprocess
import win32gui, win32process
from pywinauto import Application

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
from keygen import keygen

def try_code(n_app, name='test'):
    code = keygen(name, n_app)
    print(f'--- N={n_app}: name={name!r} code={code!r}')
    main = win32gui.FindWindow(None, 'CORE Official CrackMe v2.0 - Written by Egis/CORE')
    assert main, 'window not found'
    tid, pid = win32process.GetWindowThreadProcessId(main)
    app = Application(backend='win32').connect(process=pid)
    dlg = app.top_window()
    dlg.set_focus()
    time.sleep(0.3)
    edits = [c for c in dlg.children() if c.class_name() == 'Edit']
    if len(edits) != 2:
        print('!! edits count =', len(edits)); return False
    edits[0].set_edit_text(name)
    edits[1].set_edit_text(code)
    time.sleep(0.4)
    btns = [c for c in dlg.children() if c.class_name() == 'Button']
    btns[-1].click_input()
    time.sleep(1.5)
    for w in app.windows():
        try:
            t = w.window_text()
            if t and t != 'CORE Official CrackMe v2.0 - Written by Egis/CORE':
                kids = [(c.class_name(), c.window_text()) for c in w.children()]
                print(f'>>> MSGBOX [{t!r}]:', kids)
                w.close()
                if 'CORE' in str(kids):
                    return True
        except Exception:
            pass
    return False

# 先枚举一次控件布局
main = win32gui.FindWindow(None, 'CORE Official CrackMe v2.0 - Written by Egis/CORE')
if not main:
    subprocess.Popen([r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2\CRACKME3.EXE'],
                     cwd=r'D:\codes\ctf\KCTF2026\07_CORE_CrackMe_v2')
    time.sleep(3)
    main = win32gui.FindWindow(None, 'CORE Official CrackMe v2.0 - Written by Egis/CORE')
tid, pid = win32process.GetWindowThreadProcessId(main)
app = Application(backend='win32').connect(process=pid)
print('pid:', pid)
for c in app.top_window().children():
    print(c.class_name(), c.control_id(), repr(c.window_text()))
