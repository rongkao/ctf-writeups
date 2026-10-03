# -*- coding: utf-8 -*-
# 04 真机验证：填入 Name/Serial 点 Register，弹窗标题是 'Great'/'Failed'
import time, subprocess, sys
import win32gui, win32con, win32process

sys.path.insert(0, r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto')
from keygen import keygen

NAME = 'KCTF'
serial, _ = keygen(NAME)
print('name:', NAME, 'serial:', serial)

subprocess.run(['taskkill', '/F', '/IM', 'crackme_crypto.exe'], capture_output=True)
time.sleep(1)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto\crackme_crypto.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto')
time.sleep(3)

main = win32gui.FindWindow(None, 'CCG Crypto Crackme v1.0  ---  by blowfish')
assert main, 'no window'
tid, pid = win32process.GetWindowThreadProcessId(main)
print('pid:', pid)

children = []
def cb(hwnd, _):
    children.append((hwnd, win32gui.GetClassName(hwnd), win32gui.GetDlgCtrlID(hwnd)))
win32gui.EnumChildWindows(main, cb, None)
edit_by_id = {cid: h for h, c, cid in children if c == 'Edit'}
reg = [h for h, c, i in children if c == 'Button' and i == 1003][0]

win32gui.SetWindowText(edit_by_id[1008], NAME)      # Name
win32gui.SetWindowText(edit_by_id[1007], serial)    # Serial
time.sleep(0.5)
print('readback name:', repr(win32gui.GetWindowText(edit_by_id[1008])),
      '| serial ok:', win32gui.GetWindowText(edit_by_id[1007]) == serial)

win32gui.PostMessage(reg, win32con.BM_CLICK, 0, 0)
time.sleep(2)

# 弹窗标题 'Great' / 'Failed'
for title in ['Great', 'Failed']:
    h = win32gui.FindWindow('#32770', title)
    if h:
        texts = []
        def cb3(ch, _2):
            texts.append((win32gui.GetClassName(ch), win32gui.GetWindowText(ch)))
            return True
        win32gui.EnumChildWindows(h, cb3, None)
        print(f'>>> 弹窗 [{title}]:', texts)
        win32gui.SendMessage(h, win32con.WM_CLOSE, 0, 0)
        break
else:
    print('no msgbox')
