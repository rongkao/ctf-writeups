# -*- coding: utf-8 -*-
"""
KCTF2026 Challenge 08 - TencentPediyKeygenMe 注册机
验证流程 (逆向自 0x408270):
  serial(35字符) -> 去掉3个横杠 -> 32字符 base32 decode -> 20 bytes
  -> SM4 decrypt raw[0:16] (key="Security@Tencent", 自定义变种:LE+无CK)
  -> GF_inv 全部 20 bytes (16 SM4解密后 + 4 尾部)
  -> 自定义 Feistel CBC decrypt (key="DEADBEEF", iv=gf_tail 4 bytes)
  -> XOR checksum: 4个 dword XOR == gf_tail
  -> ECDSA verify(SHA1(name), signature) -> Success
"""
import hashlib
import struct
import os
from sm4_impl import sm4_encrypt_block, sm4_decrypt_block
from keygen_cipher import cbc_encrypt, cbc_decrypt

# ========== 椭圆曲线参数 ==========
EC_P  = 0xc564eef070e69193
EC_A  = EC_P - 3
EC_B  = 0x22996b9c33aeefdb
EC_N  = 0xc564eef19a080b07
EC_GX = 0x2223a1d595845fa2
EC_GY = 0x1c4eee9222ddda62
EC_QX = 0x297a4a1e5b1fc99b
EC_QY = 0x880198e3724f9fee

# ========== GF(2^8) 逆元 ==========
def gf_mul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        a <<= 1
        if a & 0x100: a ^= 0x11b
        b >>= 1
    return r

def gf_inv(x):
    if x == 0: return 0
    r = x
    for _ in range(6):
        r = gf_mul(r, r)
        r = gf_mul(r, x)
    return gf_mul(r, r)

GF_INV = [gf_inv(i) for i in range(256)]

# ========== 自定义 Base32 ==========
# 0x4579a8: "ABCDEFGHJKMNPQRSTVWXYZ1234567890" (32字符, 无I/L/O/U)
_ALPHABET = "ABCDEFGHJKMNPQRSTVWXYZ1234567890"
_VAL2CHAR = {i: c for i, c in enumerate(_ALPHABET)}
_CHAR2VAL = {c: i for i, c in enumerate(_ALPHABET)}

def base32_encode(data20):
    bits = int.from_bytes(data20, 'big')
    result = []
    for i in range(32):
        v = (bits >> ((31 - i) * 5)) & 0x1F
        result.append(_VAL2CHAR[v])
    return ''.join(result)

def base32_decode(s32):
    bits = 0
    for c in s32:
        bits = (bits << 5) | _CHAR2VAL[c]
    return bits.to_bytes(20, 'big')

# ========== EC 算术 ==========
def ec_modinv(a, m):
    return pow(a, m - 2, m)

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if y1 != y2: return None
        if y1 == 0: return None
        lam = ((3 * x1 * x1 + EC_A) * ec_modinv(2 * y1, EC_P)) % EC_P
    else:
        lam = ((y2 - y1) * ec_modinv(x2 - x1, EC_P)) % EC_P
    x3 = (lam * lam - x1 - x2) % EC_P
    y3 = (lam * (x1 - x3) - y1) % EC_P
    return (x3, y3)

def ec_mul(k, P):
    R = None
    while k > 0:
        if k & 1: R = ec_add(R, P)
        P = ec_add(P, P)
        k >>= 1
    return R

# ========== ECDSA ==========
def ecdsa_sign(h_int, d):
    G = (EC_GX, EC_GY)
    while True:
        k = int.from_bytes(os.urandom(8), 'big') % (EC_N - 1) + 1
        R = ec_mul(k, G)
        r = R[0] % EC_N
        if r == 0: continue
        s = (pow(k, EC_N - 2, EC_N) * (h_int + r * d)) % EC_N
        if s == 0: continue
        return r, s

def ecdsa_verify(h_int, r, s):
    G = (EC_GX, EC_GY); Q = (EC_QX, EC_QY)
    w = pow(s, EC_N - 2, EC_N)
    u1 = (h_int * w) % EC_N
    u2 = (r * w) % EC_N
    R = ec_add(ec_mul(u1, G), ec_mul(u2, Q))
    return R is not None and R[0] % EC_N == r

def compute_hash(name):
    h = hashlib.sha1(name.encode()).digest()
    return int.from_bytes(h[:8], 'big') % EC_N

# ========== Keygen ==========
def generate_serial(name, d, max_attempts=10000):
    h = compute_hash(name)
    for attempt in range(max_attempts):
        r, s = ecdsa_sign(h, d)
        sig = r.to_bytes(8, 'big') + s.to_bytes(8, 'big')

        dwords = struct.unpack('>4I', sig)
        chk = dwords[0] ^ dwords[1] ^ dwords[2] ^ dwords[3]
        chk_bytes = struct.pack('>I', chk)

        iv = chk_bytes + b'\x00' * 4
        cipher_out = cbc_encrypt(b'DEADBEEF', iv, sig)

        gf_out = bytes(GF_INV[b] for b in cipher_out)
        sm4_out = sm4_encrypt_block(gf_out, b'Security@Tencent')

        raw_tail = bytes(GF_INV[b] for b in chk_bytes)
        raw20 = sm4_out + raw_tail

        b32 = base32_encode(raw20)
        serial = b32[:8] + '-' + b32[8:16] + '-' + b32[16:24] + '-' + b32[24:]
        return serial
    raise RuntimeError(f"经过 {max_attempts} 次尝试仍未找到可编码的签名")

def verify_serial(name, serial):
    s = serial.replace('-', '')
    if len(s) != 32: return False

    raw20 = base32_decode(s)
    sm4_dec = sm4_decrypt_block(raw20[:16], b'Security@Tencent')

    gf_data = bytes(GF_INV[b] for b in sm4_dec)
    gf_tail = bytes(GF_INV[b] for b in raw20[16:])

    iv = gf_tail + b'\x00' * 4
    sig = cbc_decrypt(b'DEADBEEF', iv, gf_data)

    dwords = struct.unpack('>4I', sig)
    chk = dwords[0] ^ dwords[1] ^ dwords[2] ^ dwords[3]
    if struct.pack('>I', chk) != gf_tail:
        return False

    r = int.from_bytes(sig[:8], 'big')
    s_val = int.from_bytes(sig[8:], 'big')
    if not (0 < r < EC_N and 0 < s_val < EC_N):
        return False

    h = compute_hash(name)
    return ecdsa_verify(h, r, s_val)


if __name__ == '__main__':
    for i in range(256):
        assert GF_INV[GF_INV[i]] == i
    print("GF_inv 自逆验证通过")

    # base32 roundtrip: 需要避开禁止值
    for _ in range(100):
        test = os.urandom(20)
        enc = base32_encode(test)
        if enc is not None:
            assert base32_decode(enc) == test
            break
    print("Base32 roundtrip 通过")

    assert ec_mul(EC_N, (EC_GX, EC_GY)) is None
    print("n*G = O 通过")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    result_files = ['ecdlp_result.txt', 'ecdlp_v2_result.txt']
    d = None
    for rf in result_files:
        result_file = os.path.join(base_dir, rf)
        if os.path.exists(result_file):
            with open(result_file) as f:
                content = f.read()
            if 'SOLVED' in content:
                for line in content.split('\n'):
                    if 'Private key d' in line:
                        d = int(line.split('0x')[1].strip(), 16)
                        break
        if d is not None:
            break

    if d is None:
        print("\n等待 ECDLP 求解...")
        for rf in result_files:
            result_file = os.path.join(base_dir, rf)
            if os.path.exists(result_file):
                lines = open(result_file).read().strip().split('\n')
                print(f"  {rf}: {lines[-1]}")
    else:
        dG = ec_mul(d, (EC_GX, EC_GY))
        assert dG == (EC_QX, EC_QY), f"d*G != Q"
        print(f"私钥 d = 0x{d:016x} 验证通过")

        name = "kanxue"
        serial = generate_serial(name, d)
        print(f"\n用户名: {name}")
        print(f"序列号: {serial}")

        ok = verify_serial(name, serial)
        print(f"自验证: {'通过' if ok else '失败'}")
