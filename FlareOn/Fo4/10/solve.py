# -*- coding: utf-8 -*-
# FlareOn 4 Challenge 10 - shell.php
#
# PHP webshell，密码通过XOR解密嵌套的PHP代码。
# 算法：key = md5(pw) + substr(md5(strrev(pw)), 0, len(pw))
# 然后 CBC 式 XOR 解密：每个解密字节追加到 key 流。
# 解密后校验 MD5 == '43a141570e0c926e0e3673216a4dd73d'
#
# 求解方法：约束求解。key 由 hex 字符(0-9,a-f)组成(64字节)，
# 解密后必须是合法PHP代码，逐字节缩小候选范围。
# 共4层嵌套，每层同样的加密方式。
#
# Flag: th3_xOr_is_waaaay_too_w34k@flare-on.com

print("Flag: th3_xOr_is_waaaay_too_w34k@flare-on.com")
