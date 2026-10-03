# -*- coding: utf-8 -*-
# 03 真机验证 v2：按控件 ID 精确定位 + WM_COMMAND 触发
import time, win32gui, win32con

main = win32gui.FindWindow(None, "CrackMe2")
assert main, "main window not found"

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
for h, c, cid in children:
    print(f"child {hex(h)} class={c!r} id={cid}")

edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
serial_parts = open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt').read().split()
name, sn = serial_parts[0], serial_parts[1]
print(f"name={name!r} serial_len={len(sn)}")

win32gui.SetWindowText(edit_by_id[1001], name)
win32gui.SetWindowText(edit_by_id[1002], sn)
time.sleep(0.3)
# 直接给对话框发 WM_COMMAND (ID=1001, BN_CLICKED=0)
win32gui.SendMessage(main, win32con.WM_COMMAND, 1001, 0)
time.sleep(0.8)

boxes = []
def cb2(hwnd, _):
    if win32gui.GetClassName(hwnd) == '#32770' and win32gui.GetParent(hwnd) == 0 and hwnd != main:
        txt = win32gui.GetWindowText(hwnd)
        if 'CrackMe' in txt or txt == '' :
            boxes.append((hwnd, txt))
win32gui.EnumWindows(cb2, None)
print("boxes:", [(hex(h), t) for h, t in boxes])
for hwnd, title in boxes:
    def cb3(ch, _):
        if win32gui.GetClassName(ch) == 'Static':
            print("  >>> 消息:", repr(win32gui.GetWindowText(ch)))
    win32gui.EnumChildWindows(hwnd, cb3, None)
    win32gui.SendMessage(hwnd, win32con.WM_CLOSE, 0, 0)
    break
