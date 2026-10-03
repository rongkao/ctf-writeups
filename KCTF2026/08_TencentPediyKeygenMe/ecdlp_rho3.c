/* ECDLP Pollard rho: pure r-adding walk, no doubling step */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

#define P  0xc564eef070e69193ULL
#define N  0xc564eef19a080b07ULL
#define GX 0x2223a1d595845fa2ULL
#define GY 0x1c4eee9222ddda62ULL
#define QX 0x297a4a1e5b1fc99bULL
#define QY 0x880198e3724f9feeULL
#define A_COEFF (P - 3)
#define B_COEFF 0x22996b9c33aeefdbULL

static inline u64 mulmod(u64 a, u64 b, u64 m) { return (u64)(((u128)a * b) % m); }
static inline u64 addmod(u64 a, u64 b, u64 m) { u64 s = a + b; return (s >= m || s < a) ? s - m : s; }
static inline u64 submod(u64 a, u64 b, u64 m) { return a >= b ? a - b : a + m - b; }

static u64 invmod(u64 a, u64 m) {
    u64 r = 1; a %= m; u64 e = m - 2;
    while (e > 0) { if (e & 1) r = mulmod(r, a, m); a = mulmod(a, a, m); e >>= 1; }
    return r;
}

typedef struct { u64 x, y; } Pt;
static const Pt PTINF = {0, 0};
#define IS_INF(p) ((p).x == 0 && (p).y == 0)

static Pt ec_add(Pt p1, Pt p2) {
    if (IS_INF(p1)) return p2;
    if (IS_INF(p2)) return p1;
    u64 lam;
    if (p1.x == p2.x) {
        if (p1.y != p2.y || p1.y == 0) return PTINF;
        u64 num = addmod(mulmod(3, mulmod(p1.x, p1.x, P), P), A_COEFF, P);
        lam = mulmod(num, invmod(addmod(p1.y, p1.y, P), P), P);
    } else {
        lam = mulmod(submod(p2.y, p1.y, P), invmod(submod(p2.x, p1.x, P), P), P);
    }
    u64 x3 = submod(submod(mulmod(lam, lam, P), p1.x, P), p2.x, P);
    u64 y3 = submod(mulmod(lam, submod(p1.x, x3, P), P), p1.y, P);
    return (Pt){x3, y3};
}

static Pt ec_mul(u64 k, Pt p) {
    Pt R = PTINF;
    while (k > 0) { if (k & 1) R = ec_add(R, p); p = ec_add(p, p); k >>= 1; }
    return R;
}

#define NR 32
static Pt RA[NR];
static u64 RA_a[NR], RA_b[NR];

static u64 rng_state;
static u64 rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static void init_walk(Pt G, Pt Q) {
    rng_state = (u64)time(NULL) ^ ((u64)clock() << 32);
    for (int i = 0; i < NR; i++) {
        RA_a[i] = rng_next() % N; if (RA_a[i] == 0) RA_a[i] = 1;
        RA_b[i] = rng_next() % N; if (RA_b[i] == 0) RA_b[i] = 1;
        RA[i] = ec_add(ec_mul(RA_a[i], G), ec_mul(RA_b[i], Q));
    }
}

static inline void rstep(Pt *R, u64 *a, u64 *b) {
    int idx = (int)(R->x & (NR - 1));
    *R = ec_add(*R, RA[idx]);
    *a = addmod(*a, RA_a[idx], N);
    *b = addmod(*b, RA_b[idx], N);
}

int main(void) {
    Pt G = {GX, GY}, Q = {QX, QY};

    u64 lhs = mulmod(GY, GY, P);
    u64 rhs = addmod(addmod(mulmod(GX, mulmod(GX, GX, P), P), mulmod(A_COEFF, GX, P), P), B_COEFF, P);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }
    lhs = mulmod(QY, QY, P);
    rhs = addmod(addmod(mulmod(QX, mulmod(QX, QX, P), P), mulmod(A_COEFF, QX, P), P), B_COEFF, P);
    if (lhs != rhs) { printf("Q not on curve!\n"); return 1; }

    Pt nG = ec_mul(N, G);
    if (!IS_INF(nG)) { printf("n*G != O!\n"); return 1; }

    printf("Curve OK. r-adding Pollard rho (NR=%d, affine)...\n", NR);
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)P, (unsigned long long)N);
    fflush(stdout);

    init_walk(G, Q);
    printf("Walk table initialized.\n");
    fflush(stdout);

    clock_t start = clock();

    for (int attempt = 0; attempt < 200; attempt++) {
        u64 a1 = rng_next() % N; if (a1 == 0) a1 = 1;
        u64 b1 = rng_next() % N; if (b1 == 0) b1 = 1;
        Pt R1 = ec_add(ec_mul(a1, G), ec_mul(b1, Q));
        u64 a2 = a1, b2 = b1;
        Pt R2 = R1;

        for (u64 i = 1; i < 20000000000ULL; i++) {
            rstep(&R1, &a1, &b1);
            rstep(&R2, &a2, &b2);
            rstep(&R2, &a2, &b2);

            if (R1.x == R2.x) {
                u64 da = submod(a2, a1, N);
                u64 db = submod(b1, b2, N);
                if (db == 0) {
                    printf("  attempt %d: db=0 at i=%llu, retry\n", attempt, (unsigned long long)i);
                    break;
                }
                u64 d = mulmod(da, invmod(db, N), N);
                Pt chk = ec_mul(d, G);
                if (chk.x == QX && chk.y == QY) {
                    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                    printf("\n*** ECDLP SOLVED! ***\n");
                    printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                    printf("d = %llu\n", (unsigned long long)d);
                    printf("Iterations: %llu (attempt %d)\n", (unsigned long long)i, attempt);
                    printf("Time: %.1f seconds\n", elapsed);
                    printf("Verified: d*G = Q\n");
                    fflush(stdout);
                    FILE *f = fopen("ecdlp_result.txt", "a");
                    if (f) {
                        fprintf(f, "\n*** ECDLP SOLVED! ***\n");
                        fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)d);
                        fprintf(f, "d = %llu\n", (unsigned long long)d);
                        fprintf(f, "Time: %.1f seconds\n", elapsed);
                        fprintf(f, "Verified: d*G = Q\n");
                        fclose(f);
                    }
                    return 0;
                }
                /* y mismatch: d is for -Q, try n - d */
                d = N - d;
                chk = ec_mul(d, G);
                if (chk.x == QX && chk.y == QY) {
                    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                    printf("\n*** ECDLP SOLVED (negation)! ***\n");
                    printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                    printf("d = %llu\n", (unsigned long long)d);
                    printf("Iterations: %llu (attempt %d)\n", (unsigned long long)i, attempt);
                    printf("Time: %.1f seconds\n", elapsed);
                    printf("Verified: d*G = Q\n");
                    fflush(stdout);
                    FILE *f = fopen("ecdlp_result.txt", "a");
                    if (f) {
                        fprintf(f, "\n*** ECDLP SOLVED! ***\n");
                        fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)d);
                        fprintf(f, "d = %llu\n", (unsigned long long)d);
                        fprintf(f, "Time: %.1f seconds\n", elapsed);
                        fprintf(f, "Verified: d*G = Q\n");
                        fclose(f);
                    }
                    return 0;
                }
                printf("  attempt %d: false positive at i=%llu\n", attempt, (unsigned long long)i);
                break;
            }
            if (i % 50000000 == 0) {
                double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                printf("  attempt %d: %lluM iter (%.0fs, %.1fM/s)\n",
                       attempt, (unsigned long long)(i/1000000), elapsed, (double)i/elapsed/1e6);
                fflush(stdout);
            }
        }
    }
    printf("Failed after all attempts\n");
    return 1;
}
