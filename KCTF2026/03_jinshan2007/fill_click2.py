# -*- coding: utf-8 -*-
# TTD 录制期间的自动交互 v2：轮询等窗口出现（最多 40s）→ 填入 → 点击 → 抓弹窗
import time, sys
import win32gui, win32con, win32process

main = 0
for _ in range(80):
    main = win32gui.FindWindow(None, 'CrackMe2')
    if main:
        break
    time.sleep(0.5)
if not main:
    print('no window after 40s', flush=True); sys.exit(1)
time.sleep(1.5)  # 等对话框完全初始化

tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid, flush=True)

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
btn = [h for h, c, i in children if c == 'Button' and i == 1000][0]

win32gui.SetWindowText(edit_by_id[1001], 'KCTF')
win32gui.SetWindowText(edit_by_id[1002], '123')
time.sleep(0.5)
print('edit1001:', repr(win32gui.GetWindowText(edit_by_id[1001])), flush=True)
print('edit1002:', repr(win32gui.GetWindowText(edit_by_id[1002])), flush=True)

win32gui.PostMessage(btn, win32con.BM_CLICK, 0, 0)
time.sleep(2.5)

def cb2(hwnd, _):
    if win32gui.GetClassName(hwnd) == '#32770':
        _, p = win32process.GetWindowThreadProcessId(hwnd)
        if p == pid and hwnd != main:
            kids = []
            def cb3(ch, _2):
                kids.append((win32gui.GetClassName(ch), win32gui.GetWindowText(ch)))
                return True
            win32gui.EnumChildWindows(hwnd, cb3, None)
            print('BOX:', repr(win32gui.GetWindowText(hwnd)), kids, flush=True)
            win32gui.SendMessage(hwnd, win32con.WM_CLOSE, 0, 0)
    return True
win32gui.EnumWindows(cb2, None)
print('done', flush=True)
