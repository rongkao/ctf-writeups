# -*- coding: utf-8 -*-
# Flare-On 5 Challenge 03 - FLEGGO
#
# 48 個相同大小的 PE 執行檔，每個含一個 BRICK 自訂資源。
# 每個 exe 詢問密碼，"IronManSucks" 是陷阱（會說 "Oh, hello Batman..."）。
# 正確密碼是 BRICK 資源中的 raw name 字串。
#
# BRICK 資源結構：
#   [0x00:0x20]  資源名（寬字串，明文）
#   [0x20:0x40]  圖片檔名（每個非零字節 XOR 0x85）
#   [0x40:0x4A]  Flag 字母（每個非零字節 XOR 0x1A）
#   [0x4A:0x4C]  排序索引（uint16，決定字母在 flag 中的位置）
#   [0x4C:0x50]  BMP 資料大小
#   [0x50:]      BMP 圖片資料

import pefile, struct, os, glob

def xor_skip_null(buf, key):
    result = bytearray(buf)
    for i in range(len(result)):
        if result[i] != 0:
            result[i] ^= key
    return bytes(result)

exe_dir = os.path.join(os.path.dirname(__file__), 'FLEGGO')
results = []

for exe_path in glob.glob(os.path.join(exe_dir, '*.exe')):
    pe = pefile.PE(exe_path, fast_load=False)
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == 'BRICK':
            for e2 in entry.directory.entries:
                for e3 in e2.directory.entries:
                    brick = pe.get_data(e3.data.struct.OffsetToData, e3.data.struct.Size)
    dec = xor_skip_null(brick[0x40:0x4A], 0x1A)
    letter = ''
    for i in range(0, len(dec)-1, 2):
        ch = struct.unpack_from('<H', dec, i)[0]
        if ch == 0: break
        letter += chr(ch)
    order = struct.unpack_from('<H', brick, 0x4A)[0]
    results.append((order, letter))
    pe.close()

results.sort()
FLAG = ''.join(r[1] for r in results)
print(f'Flag: {FLAG}')
