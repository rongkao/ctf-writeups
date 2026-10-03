/* ECDLP solver: Pollard rho with AFFINE coordinates (correct walk function) */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

static const u64 P  = 0xc564eef070e69193ULL;
static const u64 N  = 0xc564eef19a080b07ULL;
static const u64 GX = 0x2223a1d595845fa2ULL;
static const u64 GY = 0x1c4eee9222ddda62ULL;
static const u64 QX = 0x297a4a1e5b1fc99bULL;
static const u64 QY = 0x880198e3724f9feeULL;

static inline u64 mulmod(u64 a, u64 b, u64 m) { return (u64)(((u128)a * b) % m); }
static inline u64 addmod(u64 a, u64 b, u64 m) { u64 s=a+b; return s>=m||s<a ? s-m : s; }
static inline u64 submod(u64 a, u64 b, u64 m) { return a>=b ? a-b : a+m-b; }
static inline u64 sqmod(u64 a, u64 m) { return (u64)(((u128)a * a) % m); }
static u64 powmod(u64 base, u64 exp, u64 m) {
    u64 r=1; base%=m;
    while(exp>0) { if(exp&1) r=mulmod(r,base,m); base=sqmod(base,m); exp>>=1; }
    return r;
}
static inline u64 invmod_p(u64 a) { return powmod(a, P-2, P); }
static inline u64 invmod_n(u64 a) { return powmod(a, N-2, N); }

typedef struct { u64 x, y; int inf; } APoint;
static const APoint INF = {0, 0, 1};

static APoint ec_add(APoint p, APoint q) {
    if (p.inf) return q;
    if (q.inf) return p;
    u64 lam;
    if (p.x == q.x) {
        if (p.y != q.y || p.y == 0) return INF;
        /* doubling */
        u64 num = addmod(mulmod(3, sqmod(p.x, P), P), P - 3, P); /* 3x^2 + a, a=p-3 */
        u64 den = addmod(p.y, p.y, P);
        lam = mulmod(num, invmod_p(den), P);
    } else {
        u64 num = submod(q.y, p.y, P);
        u64 den = submod(q.x, p.x, P);
        lam = mulmod(num, invmod_p(den), P);
    }
    u64 x3 = submod(submod(sqmod(lam, P), p.x, P), q.x, P);
    u64 y3 = submod(mulmod(lam, submod(p.x, x3, P), P), p.y, P);
    return (APoint){x3, y3, 0};
}

static APoint ec_mul(u64 k, APoint base) {
    APoint R = INF;
    while (k > 0) {
        if (k & 1) R = ec_add(R, base);
        base = ec_add(base, base);
        k >>= 1;
    }
    return R;
}

static u64 myrand64(void) {
    return ((u64)rand()<<48) ^ ((u64)rand()<<32) ^ ((u64)rand()<<16) ^ rand();
}

/* r-adding walk with 32 precomputed points */
#define NPTS 32
static APoint RA[NPTS];
static u64 RA_a[NPTS], RA_b[NPTS];

static void init_radding(APoint G, APoint Q) {
    printf("  Precomputing %d walk points...\n", NPTS);
    for (int i = 0; i < NPTS; i++) {
        RA_a[i] = myrand64() % N; if (RA_a[i] == 0) RA_a[i] = 1;
        RA_b[i] = myrand64() % N;
        APoint ga = ec_mul(RA_a[i], G);
        APoint bq = ec_mul(RA_b[i], Q);
        RA[i] = ec_add(ga, bq);
    }
    printf("  Walk points ready.\n");
    fflush(stdout);
}

static inline void step(APoint *R, u64 *a, u64 *b) {
    int idx = (int)(R->x & (NPTS - 1));
    *R = ec_add(*R, RA[idx]);
    *a = addmod(*a, RA_a[idx], N);
    *b = addmod(*b, RA_b[idx], N);
}

int main(void) {
    APoint G = {GX, GY, 0};
    APoint Q = {QX, QY, 0};

    /* Verify points on curve: y^2 = x^3 + ax + b, a = p-3 */
    u64 lhs = sqmod(GY, P);
    u64 rhs = addmod(addmod(mulmod(GX, sqmod(GX, P), P), mulmod(P-3, GX, P), P), 0x22996b9c33aeefdbULL, P);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }
    lhs = sqmod(QY, P);
    rhs = addmod(addmod(mulmod(QX, sqmod(QX, P), P), mulmod(P-3, QX, P), P), 0x22996b9c33aeefdbULL, P);
    if (lhs != rhs) { printf("Q not on curve!\n"); return 1; }

    srand((unsigned)time(NULL) ^ 99999);

    printf("ECDLP solver (AFFINE coordinates, r-adding walk)\n");
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)P, (unsigned long long)N);
    printf("Expected collision: ~%llu steps\n", (unsigned long long)4726000000ULL);
    fflush(stdout);

    clock_t start = clock();

    for (int attempt = 0; attempt < 200; attempt++) {
        init_radding(G, Q);

        u64 a1 = myrand64() % N; if (a1 == 0) a1 = 1;
        u64 b1 = myrand64() % N;
        APoint R1 = ec_add(ec_mul(a1, G), ec_mul(b1, Q));

        u64 a2 = a1, b2 = b1;
        APoint R2 = R1;

        for (u64 i = 1; i < 20000000000ULL; i++) {
            /* Tortoise: 1 step */
            step(&R1, &a1, &b1);
            /* Hare: 2 steps */
            step(&R2, &a2, &b2);
            step(&R2, &a2, &b2);

            if (R1.inf && R2.inf) {
                printf("  Both at infinity, retrying\n");
                break;
            }
            if (!R1.inf && !R2.inf && R1.x == R2.x) {
                /* x-coordinates match: either R1=R2 or R1=-R2 */
                if (R1.y == R2.y) {
                    /* R1 = R2: a1*G + b1*Q = a2*G + b2*Q */
                    u64 da = submod(a1, a2, N);
                    u64 db = submod(b2, b1, N);
                    if (db != 0) {
                        u64 d = mulmod(da, invmod_n(db), N);
                        APoint check = ec_mul(d, G);
                        if (!check.inf && check.x == QX && check.y == QY) {
                            double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                            printf("\n*** ECDLP SOLVED! ***\n");
                            printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                            printf("d = %llu\n", (unsigned long long)d);
                            printf("Iterations: %llu (attempt %d)\n", (unsigned long long)i, attempt);
                            printf("Time: %.1f seconds\n", elapsed);
                            printf("Verified: d*G = Q\n");
                            fflush(stdout);

                            FILE *f = fopen("ecdlp_result.txt", "w");
                            if (f) {
                                fprintf(f, "*** ECDLP SOLVED! ***\n");
                                fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)d);
                                fprintf(f, "d = %llu\n", (unsigned long long)d);
                                fprintf(f, "Iterations: %llu\n", (unsigned long long)i);
                                fprintf(f, "Time: %.1f seconds\n", elapsed);
                                fclose(f);
                            }
                            return 0;
                        }
                    }
                } else {
                    /* R1 = -R2: a1*G + b1*Q = -(a2*G + b2*Q) */
                    u64 da = addmod(a1, a2, N);
                    u64 db = addmod(b1, b2, N);
                    if (db != 0) {
                        u64 d = mulmod(submod(0, da, N), invmod_n(db), N);
                        APoint check = ec_mul(d, G);
                        if (!check.inf && check.x == QX && check.y == QY) {
                            double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                            printf("\n*** ECDLP SOLVED (negation)! ***\n");
                            printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                            printf("d = %llu\n", (unsigned long long)d);
                            printf("Iterations: %llu (attempt %d)\n", (unsigned long long)i, attempt);
                            printf("Time: %.1f seconds\n", elapsed);
                            printf("Verified: d*G = Q\n");
                            fflush(stdout);

                            FILE *f = fopen("ecdlp_result.txt", "w");
                            if (f) {
                                fprintf(f, "*** ECDLP SOLVED! ***\n");
                                fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)d);
                                fprintf(f, "d = %llu\n", (unsigned long long)d);
                                fprintf(f, "Iterations: %llu\n", (unsigned long long)i);
                                fprintf(f, "Time: %.1f seconds\n", elapsed);
                                fclose(f);
                            }
                            return 0;
                        }
                    }
                }
                printf("  attempt %d: collision at i=%llu but d invalid, retrying\n",
                       attempt, (unsigned long long)i);
                fflush(stdout);
                break;
            }

            if (i % 5000000 == 0) {
                double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                printf("  attempt %d: %lluM iter (%.0fs, %.0fK/s)\n",
                       attempt, (unsigned long long)(i / 1000000), elapsed,
                       (double)i / elapsed / 1e3);
                fflush(stdout);
            }
        }
    }
    printf("Failed\n");
    return 1;
}
