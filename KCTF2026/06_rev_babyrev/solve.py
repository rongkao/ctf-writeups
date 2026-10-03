# -*- coding: utf-8 -*-
"""
KCTF2026 #06 BabyRev - 解题脚本
UPX 3.95 加壳 (ISG! magic 篡改) + Rust ELF x86-64
算法: 32 字节 XOR 链, flag[0]='I', flag[i] ^ flag[i-1] = constant[i-1]
"""
import struct

def unpack_babyrev(path):
    """自定义 NRV2B 解压 + ELF 重建"""
    data = open(path, 'rb').read()

    class BR:
        def __init__(self, src):
            self.src = src; self.pos = 0; self.bb = 0
        def getbit(self):
            carry = (self.bb >> 31) & 1
            self.bb = (self.bb << 1) & 0xFFFFFFFF
            if self.bb == 0:
                self.bb = struct.unpack_from('<I', self.src, self.pos)[0]
                self.pos += 4
                carry = (self.bb >> 31) & 1
                self.bb = ((self.bb << 1) | 1) & 0xFFFFFFFF
            return carry
        def getbyte(self):
            b = self.src[self.pos]; self.pos += 1; return b

    def nrv2b(src, dst_len):
        br = BR(src)
        out = bytearray()
        last_m_off = 1
        while len(out) < dst_len:
            while br.getbit() == 1:
                out.append(br.getbyte())
                if len(out) >= dst_len: return bytes(out[:dst_len])
            eax = 1
            while True:
                eax = eax * 2 + br.getbit()
                if br.getbit() == 1: break
            eax -= 3
            if eax < 0: m_off = last_m_off
            else:
                raw = (eax << 8) | br.getbyte()
                if raw == 0xFFFFFFFF: break
                m_off = raw + 1; last_m_off = m_off
            ecx = br.getbit()
            ecx = ecx * 2 + br.getbit()
            if ecx == 0:
                ecx = 1
                while True:
                    ecx = ecx * 2 + br.getbit()
                    if br.getbit() == 1: break
                ecx += 3 + (1 if m_off > 0xd00 else 0)
            else:
                ecx += 1 + (1 if m_off > 0xd00 else 0)
            for i in range(ecx):
                if len(out) >= dst_len: break
                out.append(out[-m_off])
        return bytes(out[:dst_len])

    blocks = [(0x10c,736,230), (0x1fe,26032,6280), (0x1a92,306673,141614),
              (0x243cc,72928,31590), (0x2bf3e,15088,4172)]
    offsets = [0x0, 0x2e0, 0x7000, 0x52000, 0x64540]
    elf = bytearray(0x68938)
    for (off,unc,cpr), foff in zip(blocks, offsets):
        dec = nrv2b(data[off:off+cpr], unc)
        elf[foff:foff+len(dec)] = dec
    return bytes(elf)

def solve():
    xor_target1 = bytes.fromhex('143c13222f15494d2061621b26302a19')

    xor_chain = [0x1a]
    xor_chain.extend(xor_target1)
    v = 0x0714090116_0d_05_07
    for i in range(8):
        xor_chain.append((v >> (i*8)) & 0xFF)
    v2 = 0x084c1d02
    for i in range(4):
        xor_chain.append((v2 >> (i*8)) & 0xFF)
    xor_chain.extend([0x78, 0x35])

    flag = bytearray([0x49])  # 'I'
    for xv in xor_chain:
        flag.append(flag[-1] ^ xv)

    return flag.decode('ascii')

if __name__ == '__main__':
    flag = solve()
    print(f'Flag: {flag}')
    # ISG{hJep9tT5WLjZpinkfpqxlkit80H}
