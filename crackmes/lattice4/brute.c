// LATTICE4 solver: 16 chars [A-Za-z0-9], FNV-1a == 0x53FDD974
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

static const char CS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#define NCS 62
#define TARGET 0x53FDD974u

int main(void) {
    uint32_t seed = (uint32_t)getpid() ^ 0x9e3779b9u;
    char buf[17] = {0};
    unsigned char c16[NCS];
    for (int i = 0; i < NCS; i++) c16[i] = (unsigned char)CS[i];
    for (uint64_t iter = 0; ; iter++) {
        // xorshift 随机生成前 16 字符
        uint32_t h = 0x811c9dc5u;
        for (int i = 0; i < 16; i++) {
            seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
            unsigned char c = c16[seed % NCS];
            buf[i] = (char)c;
            h = (h ^ c) * 0x01000193u;
        }
        if (h == TARGET) {
            printf("FOUND: %s (iter %llu)\n", buf, (unsigned long long)iter);
            return 0;
        }
        if ((iter & 0xFFFFFFF) == 0) {
            fprintf(stderr, "progress %lluM\n", (unsigned long long)(iter >> 20));
        }
    }
}
