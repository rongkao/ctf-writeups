# -*- coding: utf-8 -*-
# 03 真机验证：向 CrackMe 对话框发送用户名/序列号并点击按钮
import time, win32gui, win32con, win32api

def find_windows(parent, cls=None):
    result = []
    def cb(hwnd, _):
        result.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetWindowText(hwnd)))
    win32gui.EnumChildWindows(parent, cb, None)
    return result

# 主窗口
main = win32gui.FindWindow(None, "CrackMe2")
assert main, "main window not found"
print("main:", hex(main))
children = find_windows(main)
for h, c, t in children:
    print(f"  child {hex(h)} class={c!r} text={t!r}")

# 找 Edit 控件（按控件 ID）和 Button
edits = [h for h, c, t in children if c == 'Edit']
buttons = [h for h, c, t in children if c == 'Button']
print("edits:", [hex(e) for e in edits], "buttons:", [hex(b) for b in buttons])

serial = open(r'D:\codes\ctf\KCTF2026\03_jinshan2007\serial.txt').read().split()
name, sn = serial[0], serial[1]

win32gui.SetWindowText(edits[0], name)     # 1001 用户名
win32gui.SetWindowText(edits[1], sn)       # 1002 序列号
time.sleep(0.3)
win32gui.SendMessage(buttons[0], win32con.BM_CLICK, 0, 0)
time.sleep(0.5)

# 检查弹出的 MessageBox
def find_msgbox():
    boxes = []
    def cb2(hwnd, _):
        if win32gui.GetClassName(hwnd) == '#32770' and hwnd != main:
            boxes.append((hwnd, win32gui.GetWindowText(hwnd)))
    win32gui.EnumWindows(cb2, None)
    return boxes

boxes = find_msgbox()
print("msgbox:", boxes)
for hwnd, title in boxes:
    kids = find_windows(hwnd)
    for h, c, t in kids:
        if c == 'Static':
            print("  >>> 消息内容:", repr(t))
            win32gui.SendMessage(hwnd, win32con.WM_CLOSE, 0, 0)
