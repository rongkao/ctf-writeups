# -*- coding: utf-8 -*-
# FlareOn 4 Challenge 11 - covfefe SUBLEQ VM
# 密码: subleq_and_reductio_ad_absurdum
# Flag: subleq_and_reductio_ad_absurdum@flare-on.com
#
# 算法: SUBLEQ 虚拟机 (subtract and branch if less-or-equal-to-zero)
# 只有一条指令: mem[B] -= mem[A]; if mem[B]<=0: pc=C; else: pc+=3
# 密码通过 SUBLEQ 程序验证, 成功后输出 flag

PASSWORD = 'subleq_and_reductio_ad_absurdum'
FLAG = f'{PASSWORD}@flare-on.com'
print(f'Password: {PASSWORD}')
print(f'Flag: {FLAG}')
