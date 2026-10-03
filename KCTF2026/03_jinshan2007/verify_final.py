# -*- coding: utf-8 -*-
# 03 真机验证 v6（终版）：普通权限 + 全量打印
import time, subprocess
import win32gui, win32con, win32process

# 杀掉所有旧实例
subprocess.run(['taskkill', '/F', '/IM', 'CrackMe.exe'], capture_output=True)
time.sleep(1)

p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\03_jinshan2007\CrackMe.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\03_jinshan2007')
time.sleep(2.5)

main = win32gui.FindWindow(None, 'CrackMe2')
assert main, 'no main window'
tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid)

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
btn = [h for h, c, i in children if c == 'Button' and i == 1000][0]

parts = open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt').read().split()
name, sn = parts[0], parts[1]

win32gui.SetWindowText(edit_by_id[1001], name)
win32gui.SetWindowText(edit_by_id[1002], sn)
time.sleep(0.5)
print('readback1001:', repr(win32gui.GetWindowText(edit_by_id[1001])),
      '| readback1002 len:', len(win32gui.GetWindowText(edit_by_id[1002])))

win32gui.PostMessage(btn, win32con.BM_CLICK, 0, 0)
print('clicked')

# 轮询 5 秒找同 pid 新窗口
found = False
for _ in range(25):
    time.sleep(0.2)
    boxes = []
    def cb2(h, _):
        _, pp = win32process.GetWindowThreadProcessId(h)
        if pp == pid and h != main:
            boxes.append(h)
        return True
    win32gui.EnumWindows(cb2, None)
    if boxes:
        for h in boxes:
            print('NEW TOP:', hex(h), win32gui.GetClassName(h), repr(win32gui.GetWindowText(h)))
            kids = []
            def cb3(ch, _2):
                kids.append((win32gui.GetClassName(ch), win32gui.GetWindowText(ch)))
                return True
            win32gui.EnumChildWindows(h, cb3, None)
            for k in kids:
                print('    child:', k)
        found = True
        break
if not found:
    print('no new window; dump main state:')
    def cb4(ch, _):
        print('    main child:', win32gui.GetClassName(ch), win32gui.GetDlgCtrlID(ch), repr(win32gui.GetWindowText(ch)))
        return True
    win32gui.EnumChildWindows(main, cb4, None)
