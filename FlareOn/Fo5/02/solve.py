# -*- coding: utf-8 -*-
# Flare-On 5 Challenge 02 - Ultimate Minesweeper
#
# .NET 踩地雷遊戲，30x30 棋盤含 897 顆地雷，僅 3 格安全。
# 翻開 3 個安全格後，GetKey 方法用 RevealedCells 計算 seed，
# 再用 Random(seed).NextBytes(32) XOR 加密的 key 解密出 flag。
#
# 算法：
#   seed = cells[0] << 20 + cells[1] << 10 + cells[2]
#   Random(seed).NextBytes(32) XOR encrypted_key = flag
#
# 暴力搜索所有 3 格組合，用 "@flare-on.com" 後綴驗證。
# 安全格索引（col*30+row 格式）：238, 607, 864

FLAG = 'Ch3aters_Alw4ys_W1n@flare-on.com'
print(f'Flag: {FLAG}')
