// LATTICE4 solver v2: 随机前缀15字符 + 末字符唯一解（62/2^32 每轮，~7e7 轮期望命中）
#include <stdio.h>
#include <stdint.h>

static const char CS[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
#define NCS 62
#define INV_P 0x359c449bu   /* 0x01000193 的模�?*/
#define NEED  0x53FDD974u   /* TARGET * INV_P */

static int is_alnum_c(uint32_t x) {
    if (x >= '0' && x <= '9') return 1;
    if (x >= 'A' && x <= 'Z') return 1;
    if (x >= 'a' && x <= 'z') return 1;
    return 0;
}

int main(void) {
    uint32_t seed = 0x12345678u ^ (uint32_t)(uintptr_t)&seed;
    char buf[17] = {0};
    for (uint64_t iter = 0; ; iter++) {
        uint32_t h = 0x811c9dc5u;
        for (int i = 0; i < 15; i++) {
            seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
            uint32_t c = (uint32_t)CS[seed % NCS];
            buf[i] = (char)c;
            h = (h ^ c) * 0x01000193u;
        }
        uint32_t last = h ^ NEED;
        if (is_alnum_c(last)) {
            buf[15] = (char)last;
            /* 全量复验 */
            uint32_t v = 0x811c9dc5u;
            for (int i = 0; i < 16; i++) v = (v ^ (uint8_t)buf[i]) * 0x01000193u;
            if (v == 0x53FDD974u) {
                printf("FOUND: %s (iter %llu)\n", buf, (unsigned long long)iter);
                return 0;
            }
        }
    }
}
