/* 64-bit ECDLP solver using Pollard rho */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

/* Curve: y^2 = x^3 + ax + b (mod p) */
static const u64 P  = 0xc564eef070e69193ULL;
static const u64 A  = 0xc564eef070e69190ULL; /* p - 3 */
static const u64 B  = 0x22996b9c33aeefdbULL;
static const u64 N  = 0xc564eef19a080b07ULL;
static const u64 GX = 0x2223a1d595845fa2ULL;
static const u64 GY = 0x1c4eee9222ddda62ULL;
static const u64 QX = 0x297a4a1e5b1fc99bULL;
static const u64 QY = 0x880198e3724f9feeULL;

static inline u64 mulmod(u64 a, u64 b, u64 m) {
    return (u64)(((u128)a * b) % m);
}

static inline u64 addmod(u64 a, u64 b, u64 m) {
    u64 s = a + b;
    return s >= m || s < a ? s - m : s;
}

static inline u64 submod(u64 a, u64 b, u64 m) {
    return a >= b ? a - b : a + m - b;
}

static u64 powmod(u64 base, u64 exp, u64 m) {
    u64 result = 1;
    base %= m;
    while (exp > 0) {
        if (exp & 1) result = mulmod(result, base, m);
        base = mulmod(base, base, m);
        exp >>= 1;
    }
    return result;
}

static u64 invmod(u64 a, u64 m) {
    return powmod(a, m - 2, m);
}

/* EC point: (0,0) = infinity */
typedef struct { u64 x, y; } ECPoint;

static const ECPoint INF = {0, 0};

static int is_inf(ECPoint p) { return p.x == 0 && p.y == 0; }

static ECPoint ec_add(ECPoint p1, ECPoint p2) {
    if (is_inf(p1)) return p2;
    if (is_inf(p2)) return p1;

    u64 lam;
    if (p1.x == p2.x) {
        if (addmod(p1.y, p2.y, P) == 0) return INF;
        /* lam = (3*x^2 + a) / (2*y) */
        u64 num = addmod(mulmod(3, mulmod(p1.x, p1.x, P), P), A, P);
        u64 den = addmod(p1.y, p1.y, P);
        lam = mulmod(num, invmod(den, P), P);
    } else {
        u64 num = submod(p2.y, p1.y, P);
        u64 den = submod(p2.x, p1.x, P);
        lam = mulmod(num, invmod(den, P), P);
    }

    u64 x3 = submod(submod(mulmod(lam, lam, P), p1.x, P), p2.x, P);
    u64 y3 = submod(mulmod(lam, submod(p1.x, x3, P), P), p1.y, P);
    return (ECPoint){x3, y3};
}

static ECPoint ec_mul(u64 k, ECPoint p) {
    ECPoint r = INF;
    while (k > 0) {
        if (k & 1) r = ec_add(r, p);
        p = ec_add(p, p);
        k >>= 1;
    }
    return r;
}

/* Pollard rho for ECDLP: find d s.t. Q = d*G */
static void step(ECPoint *R, u64 *a, u64 *b, ECPoint G, ECPoint Q) {
    /* partition by x mod 3 */
    int part = is_inf(*R) ? 0 : (int)(R->x % 3);
    switch (part) {
    case 0:
        *R = ec_add(*R, Q);
        *b = addmod(*b, 1, N);
        break;
    case 1:
        *R = ec_add(*R, *R);
        *a = addmod(*a, *a, N);
        *b = addmod(*b, *b, N);
        break;
    case 2:
        *R = ec_add(*R, G);
        *a = addmod(*a, 1, N);
        break;
    }
}

/* extended gcd */
static int64_t ext_gcd(int64_t a, int64_t b, int64_t *x, int64_t *y) {
    if (a == 0) { *x = 0; *y = 1; return b; }
    int64_t x1, y1;
    int64_t g = ext_gcd(b % a, a, &x1, &y1);
    *x = y1 - (b / a) * x1;
    *y = x1;
    return g;
}

int main(void) {
    ECPoint G = {GX, GY};
    ECPoint Q = {QX, QY};

    /* verify points on curve */
    u64 lhs = mulmod(GY, GY, P);
    u64 rhs = addmod(addmod(mulmod(GX, mulmod(GX, GX, P), P), mulmod(A, GX, P), P), B, P);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }

    lhs = mulmod(QY, QY, P);
    rhs = addmod(addmod(mulmod(QX, mulmod(QX, QX, P), P), mulmod(A, QX, P), P), B, P);
    if (lhs != rhs) { printf("Q not on curve!\n"); return 1; }

    printf("Curve verified. Starting Pollard rho...\n");
    printf("p = 0x%016llx\n", (unsigned long long)P);
    printf("n = 0x%016llx\n", (unsigned long long)N);
    fflush(stdout);

    srand((unsigned)time(NULL));

    for (int attempt = 0; attempt < 100; attempt++) {
        u64 a1 = (u64)rand() << 32 | rand();
        u64 b1 = (u64)rand() << 32 | rand();
        a1 %= N; b1 %= N;
        if (a1 == 0) a1 = 1;

        ECPoint R1 = ec_add(ec_mul(a1, G), ec_mul(b1, Q));
        u64 a2 = a1, b2 = b1;
        ECPoint R2 = R1;

        for (u64 i = 1; i < 10000000000ULL; i++) {
            step(&R1, &a1, &b1, G, Q);
            step(&R2, &a2, &b2, G, Q);
            step(&R2, &a2, &b2, G, Q);

            if (R1.x == R2.x && R1.y == R2.y) {
                /* a1 + d*b1 = a2 + d*b2 (mod n) */
                u64 da = submod(a2, a1, N);
                u64 db = submod(b1, b2, N);

                if (db == 0) {
                    printf("  attempt %d: db=0, retrying\n", attempt);
                    break;
                }

                u64 d = mulmod(da, invmod(db, N), N);
                ECPoint check = ec_mul(d, G);
                if (check.x == QX && check.y == QY) {
                    printf("\n*** ECDLP SOLVED! ***\n");
                    printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                    printf("d = %llu\n", (unsigned long long)d);
                    printf("Verified: d*G = Q ✓\n");
                    return 0;
                } else {
                    printf("  attempt %d: false collision at i=%llu\n",
                           attempt, (unsigned long long)i);
                    break;
                }
            }

            if (i % 100000000 == 0) {
                printf("  attempt %d: %lluM iterations...\n",
                       attempt, (unsigned long long)(i / 1000000));
                fflush(stdout);
            }
        }
    }

    printf("Failed after all attempts\n");
    return 1;
}
