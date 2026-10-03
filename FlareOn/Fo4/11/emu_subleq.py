# -*- coding: utf-8 -*-
# FlareOn 4 Challenge 11 - covfefe SUBLEQ VM emulator
# Memory layout (dword indices):
#   arr[0]: temp/zero
#   arr[1]: input char buffer
#   arr[2]: output char buffer
#   arr[3]: input request flag (1 = please read)
#   arr[4]: output request flag (1 = please print)
# SUBLEQ: A,B,C = mem[pc],mem[pc+1],mem[pc+2]
#   mem[B] -= mem[A]; branch to C if mem[B]<=0 (C=0 means no branch, C=-1 means halt)
import pefile, struct

pe = pefile.PE('covfefe.exe')
data = pe.get_data(0x3000, 0x4600)
arr_raw = data[8:]
total = (0x4408 - 8) // 4
vals = list(struct.unpack(f'<{total}i', arr_raw[:total*4]))

def run_vm(input_bytes, rand_val=0, verbose=False):
    mem = vals[:]
    mem[0x444] = rand_val % 32
    pc = 0x463
    limit = 0x1100
    output = []
    in_idx = 0

    for step in range(5000000):
        if pc < 0 or pc + 2 >= total:
            return None, output, step

        A, B, C = mem[pc], mem[pc+1], mem[pc+2]

        if 0 <= A < total and 0 <= B < total:
            mem[B] -= mem[A]

        # I/O after each instruction
        if mem[4] == 1:
            ch = mem[2] & 0xFF
            output.append(chr(ch) if (32 <= ch < 127 or ch == 10) else '?')
            mem[4] = 0
            mem[2] = 0

        if mem[3] == 1:
            if in_idx < len(input_bytes):
                mem[1] = input_bytes[in_idx]
                in_idx += 1
            else:
                mem[1] = 10
            mem[3] = 0

        # Branch
        if C == 0:
            pc += 3
        elif 0 <= B < total and mem[B] <= 0:
            if C == -1:
                return True, output, step
            pc = C
        else:
            pc += 3

        if pc + 3 > limit:
            return False, output, step

    return None, output, 5000000

# Test with different random values
for rv in [0, 1, 15, 31]:
    result, output, steps = run_vm(b'AAAA\n', rv)
    msg = ''.join(output)
    print(f'rand={rv:2d} result={result} steps={steps} output={msg!r}')
