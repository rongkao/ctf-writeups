// Pollard rho (Brent) for 128-bit semiprime, Montgomery arithmetic with R = 2^128.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

static u128 N;     // modulus (odd)
static u128 Ninv;  // -N^{-1} mod 2^128
static u128 R2;    // 2^256 mod N

static void mul256(u128 a, u128 b, u128 *lo, u128 *hi) {
    u64 a0 = (u64)a, a1 = (u64)(a >> 64), b0 = (u64)b, b1 = (u64)(b >> 64);
    u128 p00 = (u128)a0 * b0, p01 = (u128)a0 * b1;
    u128 p10 = (u128)a1 * b0, p11 = (u128)a1 * b1;
    u128 mid = (p00 >> 64) + (u64)p01 + (u64)p10;
    *lo = ((u128)(u64)mid << 64) | (u64)p00;
    *hi = p11 + (p01 >> 64) + (p10 >> 64) + (mid >> 64);
}

static inline u128 redc(u128 lo, u128 hi) {
    u128 m = lo * Ninv;
    u128 ml, mh;
    mul256(m, N, &ml, &mh);
    u128 s = lo + ml;
    u128 carry = (s < lo) ? 1 : 0;
    u128 t = hi + mh + carry;
    if (t >= N) t -= N;
    return t;
}

static inline u128 mmul(u128 a, u128 b) {
    u128 lo, hi;
    mul256(a, b, &lo, &hi);
    return redc(lo, hi);
}

static u128 to_mont(u128 a) { return mmul(a, R2); }
static u128 from_mont(u128 a) { return redc(a, 0); }

static u128 gcd128(u128 a, u128 b) {
    while (b) { u128 t = a % b; a = b; b = t; }
    return a;
}

static void print128(u128 v) {
    if (v == 0) { printf("0"); return; }
    char buf[45]; int i = 44; buf[i--] = 0;
    while (v) { buf[i--] = '0' + (int)(v % 10); v /= 10; }
    printf("%s", buf + i + 1);
}

int main(int argc, char **argv) {
    // n as decimal string, seed c
    N = 0;
    for (const char *p = argv[1]; *p; ++p) N = N * 10 + (*p - '0');
    u64 cseed = strtoull(argv[2], NULL, 10);

    // Ninv = -N^{-1} mod 2^128 via Newton
    u128 inv = 1;
    for (int i = 0; i < 8; i++) inv *= 2 - N * inv;
    Ninv = (u128)0 - inv;

    // R2 = 2^256 mod N  (repeated doubling; N > 2^127 so 2^128 mod N = 2^128 - N)
    u128 D = (u128)0 - N;
    u128 t = 1 % N;
    for (int i = 0; i < 256; i++) {
        int of = (int)(t >> 127);
        t <<= 1;
        if (of) t += D;
        else if (t >= N) t -= N;
    }
    R2 = t;

    const u64 M = 1ULL << 20;
    for (u64 round = 0; round < 4096; ++round) {
        u128 c = to_mont((u128)(cseed + round * 7919ULL) % N);
        u128 x = to_mont((u128)(cseed * 2654435761ULL + round) % N);
        u128 y = x, q = to_mont(1), ys = x, g = 1;
        u64 r = 1;
        while (g == 1) {
            x = y;
            for (u64 i = 0; i < r; i++) { y = mmul(y, y); y += c; if (y >= N) y -= N; }
            u64 k = 0;
            while (k < r && g == 1) {
                ys = y;
                u64 lim = (M < r - k) ? M : (r - k);
                for (u64 i = 0; i < lim; i++) {
                    y = mmul(y, y); y += c; if (y >= N) y -= N;
                    u128 d = (x > y) ? (x - y) : (y - x);
                    if (d == 0) d = 1;
                    q = mmul(q, d);
                }
                g = gcd128(from_mont(q), N);
                k += lim;
            }
            r <<= 1;
            if (r > (1ULL << 34)) break;
        }
        if (g != 1 && g != N) {
            printf("FACTOR "); print128(g); printf(" "); print128(N / g); printf("\n");
            fflush(stdout);
            return 0;
        }
        if (g == N) {
            g = 1;
            u128 yy = ys;
            while (g == 1) {
                yy = mmul(yy, yy); yy += c; if (yy >= N) yy -= N;
                u128 d = (x > yy) ? (x - yy) : (yy - x);
                if (d == 0) break;
                g = gcd128(from_mont(d), N);
            }
            if (g != 1 && g != N) {
                printf("FACTOR "); print128(g); printf(" "); print128(N / g); printf("\n");
                fflush(stdout);
                return 0;
            }
        }
    }
    printf("NOFACTOR\n");
    return 0;
}
