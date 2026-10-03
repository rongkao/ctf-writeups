# -*- coding: utf-8 -*-
# 04 交互脚本：轮询 CCG 窗口 60s → 填测试数据 → 点 Register → 保持运行
import time, sys
import win32gui, win32con, win32process

main = 0
for _ in range(120):
    main = win32gui.FindWindow(None, 'CCG Crypto Crackme v1.0  ---  by blowfish')
    if main:
        break
    time.sleep(0.5)
if not main:
    print('no window after 60s', flush=True); sys.exit(1)
time.sleep(2)  # 等 TTD 注入稳定

tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid, flush=True)

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
reg = [h for h, c, i in children if c == 'Button' and i == 1003][0]

win32gui.SetWindowText(edit_by_id[1008], 'test')       # Name
win32gui.SetWindowText(edit_by_id[1007], 'A' * 32)     # Serial
time.sleep(0.5)
print('readback name:', repr(win32gui.GetWindowText(edit_by_id[1008])),
      'serial len:', len(win32gui.GetWindowText(edit_by_id[1007])), flush=True)

win32gui.PostMessage(reg, win32con.BM_CLICK, 0, 0)
print('clicked register', flush=True)
time.sleep(3)
# 打印同 pid 新窗口（弹窗）
def cb2(h, _):
    if win32gui.GetClassName(h) == '#32770':
        _, p = win32process.GetWindowThreadProcessId(h)
        if p == pid and h != main:
            kids = []
            def cb3(ch, _2):
                kids.append((win32gui.GetClassName(ch), win32gui.GetWindowText(ch)))
                return True
            win32gui.EnumChildWindows(h, cb3, None)
            print('BOX:', repr(win32gui.GetWindowText(h)), kids, flush=True)
    return True
win32gui.EnumWindows(cb2, None)
print('done', flush=True)
