# -*- coding: utf-8 -*-
# Flare-On 5 Challenge 05 - Web 2.0
# WebAssembly 逆向：index.html 從 URL 參數 q 讀取輸入，送入 WASM Match 函式比對
# Match(encrypted_data, input) == 1 即為正確
# 已知答案（通過 Node.js 直接呼叫 Match 驗證）
FLAG = 'wasm_rulez_js_droolz@flare-on.com'
print(f'Flag: {FLAG}')
