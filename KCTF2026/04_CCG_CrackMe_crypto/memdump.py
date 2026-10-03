# -*- coding: utf-8 -*-
# 04 内存 dump：运行时 ReadProcessMemory 抓取解密后的代码段（绕过一切反调试）
import ctypes, ctypes.wintypes as wt, struct, time, subprocess, sys

k32 = ctypes.windll.kernel32
PROCESS_VM_READ = 0x10
PROCESS_QUERY_INFORMATION = 0x400

def dump(pid, out_path):
    h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        print('OpenProcess fail', ctypes.GetLastError()); return False
    # PE 头先读出来拿 image size
    buf = ctypes.create_string_buffer(0x1000)
    read = ctypes.c_size_t()
    if not k32.ReadProcessMemory(h, ctypes.c_void_p(0x400000), buf, 0x1000, ctypes.byref(read)):
        print('read header fail'); return False
    hdr = buf.raw[:read.value]
    pe_off = struct.unpack('<I', hdr[0x3c:0x40])[0]
    size_of_image = struct.unpack('<I', hdr[pe_off+24+56:pe_off+24+60])[0]
    print('SizeOfImage:', hex(size_of_image))
    big = ctypes.create_string_buffer(size_of_image)
    # 分节读（有的页可能 NOACCESS，逐 64KB 试）
    total = 0
    for base in range(0, size_of_image, 0x10000):
        chunk = min(0x10000, size_of_image - base)
        if k32.ReadProcessMemory(h, ctypes.c_void_p(0x400000 + base), 
                                 ctypes.byref(big, base), chunk, ctypes.byref(read)):
            total += read.value
    print(f'dumped {total} / {size_of_image} bytes')
    with open(out_path, 'wb') as f:
        f.write(big.raw[:size_of_image])
    k32.CloseHandle(h)
    return total > 0

# 启动程序
subprocess.run(['taskkill', '/F', '/IM', 'crackme_crypto.exe'], capture_output=True)
time.sleep(0.5)
p = subprocess.Popen([r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto\crackme_crypto.exe'],
                     cwd=r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto')
time.sleep(4)  # 等壳解压 + 窗口消息循环

import win32gui
main = win32gui.FindWindow(None, 'CCG Crypto Crackme v1.0  ---  by blowfish')
print('window:', main, 'pid:', p.pid)
ok = dump(p.pid, r'D:\codes\ctf\KCTF2026\04_CCG_CrackMe_crypto\dumped.bin')
print('dump ok:', ok)
