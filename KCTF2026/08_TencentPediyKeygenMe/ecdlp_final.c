/* ECDLP solver: multi-threaded, Montgomery multiplication, affine coords */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

/* Curve parameters */
static const u64 EC_P = 0xc564eef070e69193ULL;
static const u64 EC_N = 0xc564eef19a080b07ULL;
static const u64 GX   = 0x2223a1d595845fa2ULL;
static const u64 GY   = 0x1c4eee9222ddda62ULL;
static const u64 QX   = 0x297a4a1e5b1fc99bULL;
static const u64 QY   = 0x880198e3724f9feeULL;

/* ===== Montgomery multiplication over EC_P ===== */
static u64 MONT_P_PRIME; /* -P^{-1} mod 2^64 */
static u64 MONT_R_MOD_P; /* R mod P = 2^64 mod P */
static u64 MONT_R2;      /* R^2 mod P */
static u64 MONT_A;       /* a = P-3 in Montgomery form */
static u64 MONT_ONE;     /* 1 in Montgomery form = R mod P */

static inline u64 mulmod_n(u64 a, u64 b) { return (u64)(((u128)a * b) % EC_N); }
static inline u64 addmod_n(u64 a, u64 b) { u64 s=a+b; return s>=EC_N||s<a ? s-EC_N : s; }
static inline u64 submod_n(u64 a, u64 b) { return a>=b ? a-b : a+EC_N-b; }

static inline u64 REDC(u128 T) {
    u64 t_lo = (u64)T;
    u64 t_hi = (u64)(T >> 64);
    u64 m = t_lo * MONT_P_PRIME;
    u128 mP = (u128)m * EC_P;
    u64 mP_hi = (u64)(mP >> 64);
    u64 carry = (t_lo != 0) ? 1 : 0;
    u64 r = t_hi + mP_hi;
    int of1 = (r < t_hi);
    r += carry;
    int of2 = (r < carry);
    if (of1 | of2) {
        r += MONT_R_MOD_P; /* r_actual = r + 2^64 >= P, so result = r + (2^64 - P) */
    } else if (r >= EC_P) {
        r -= EC_P;
    }
    return r;
}

static inline u64 mont_mul(u64 a, u64 b) { return REDC((u128)a * b); }
static inline u64 mont_sqr(u64 a) { return REDC((u128)a * a); }
static inline u64 mont_add(u64 a, u64 b) { u64 s=a+b; return s>=EC_P||s<a ? s-EC_P : s; }
static inline u64 mont_sub(u64 a, u64 b) { return a>=b ? a-b : a+EC_P-b; }

static inline u64 to_mont(u64 a) { return mont_mul(a, MONT_R2); }
static inline u64 from_mont(u64 a) { return REDC((u128)a); }

static u64 mont_pow(u64 base, u64 exp) {
    u64 r = MONT_ONE;
    while (exp > 0) {
        if (exp & 1) r = mont_mul(r, base);
        base = mont_sqr(base);
        exp >>= 1;
    }
    return r;
}

static inline u64 mont_inv(u64 a) { return mont_pow(a, EC_P - 2); }

static void mont_init(void) {
    /* Compute P' = -P^{-1} mod 2^64 using Newton's method */
    u64 x = 1;
    for (int i = 0; i < 6; i++)
        x = x * (2 - EC_P * x); /* All mod 2^64 via natural overflow */
    /* x = P^{-1} mod 2^64, we want -x */
    MONT_P_PRIME = (u64)0 - x;

    /* R mod P = 2^64 mod P. Since P > 2^63: 2^64 mod P = 2^64 - P */
    MONT_R_MOD_P = (u64)0 - EC_P;
    MONT_ONE = MONT_R_MOD_P;

    /* R^2 mod P */
    MONT_R2 = (u64)(((u128)MONT_R_MOD_P * MONT_R_MOD_P) % EC_P);

    /* a = P - 3 in Montgomery form */
    MONT_A = to_mont(EC_P - 3);

    /* Verify: from_mont(to_mont(7)) should be 7 */
    u64 test = from_mont(to_mont(7));
    if (test != 7) {
        printf("Montgomery init FAILED! to_mont/from_mont(7) = %llu\n", (unsigned long long)test);
        exit(1);
    }
    /* Verify: mont_mul(to_mont(3), to_mont(5)) should give to_mont(15) */
    u64 a = to_mont(3), b = to_mont(5);
    u64 c = mont_mul(a, b);
    if (from_mont(c) != 15) {
        printf("Montgomery mul FAILED! 3*5 = %llu\n", (unsigned long long)from_mont(c));
        exit(1);
    }
    /* Verify inverse */
    u64 inv7 = mont_inv(to_mont(7));
    u64 check = mont_mul(to_mont(7), inv7);
    if (from_mont(check) != 1) {
        printf("Montgomery inv FAILED! 7*inv(7) = %llu\n", (unsigned long long)from_mont(check));
        exit(1);
    }
}

/* ===== Elliptic curve (Montgomery form) ===== */
typedef struct { u64 x, y; int inf; } MPoint; /* coords in Montgomery form */
static const MPoint MINF = {0, 0, 1};

static MPoint ec_add_mont(MPoint p, MPoint q) {
    if (p.inf) return q;
    if (q.inf) return p;
    u64 lam;
    if (p.x == q.x) {
        if (p.y != q.y || p.y == 0) return MINF;
        /* doubling: lam = (3x^2 + a) / (2y) */
        u64 x2 = mont_sqr(p.x);
        u64 three_x2 = mont_add(mont_add(x2, x2), x2);
        u64 num = mont_add(three_x2, MONT_A);
        u64 den = mont_add(p.y, p.y);
        lam = mont_mul(num, mont_inv(den));
    } else {
        u64 num = mont_sub(q.y, p.y);
        u64 den = mont_sub(q.x, p.x);
        lam = mont_mul(num, mont_inv(den));
    }
    u64 x3 = mont_sub(mont_sub(mont_sqr(lam), p.x), q.x);
    u64 y3 = mont_sub(mont_mul(lam, mont_sub(p.x, x3)), p.y);
    return (MPoint){x3, y3, 0};
}

static MPoint ec_mul_mont(u64 k, MPoint base) {
    MPoint R = MINF;
    while (k > 0) {
        if (k & 1) R = ec_add_mont(R, base);
        base = ec_add_mont(base, base);
        k >>= 1;
    }
    return R;
}

/* Standard (non-Montgomery) EC for final verification */
static inline u64 mulmod_p(u64 a, u64 b) { return (u64)(((u128)a * b) % EC_P); }
static u64 powmod_n(u64 b, u64 e) { u64 r=1; b%=EC_N; while(e>0){if(e&1)r=mulmod_n(r,b);b=mulmod_n(b,b);e>>=1;} return r; }

/* ===== Multi-threaded Pollard rho ===== */
static volatile int solved = 0;

#define NPTS 32

static u64 lcg_next(u64 *s) {
    *s = *s * 6364136223846793005ULL + 1442695040888963407ULL;
    return *s;
}

typedef struct {
    int tid;
    MPoint mG, mQ;
    u64 result_d;
    int found;
    u64 iterations;
} ThreadArg;

static void *worker(void *arg) {
    ThreadArg *ta = (ThreadArg *)arg;
    MPoint mG = ta->mG, mQ = ta->mQ;
    int tid = ta->tid;

    u64 rng = (u64)time(NULL) * 2654435761ULL + (u64)tid * 0x9E3779B97F4A7C15ULL;

    MPoint RA[NPTS];
    u64 RA_a[NPTS], RA_b[NPTS];

    for (int attempt = 0; attempt < 100 && !solved; attempt++) {
        /* Precompute walk points */
        for (int i = 0; i < NPTS; i++) {
            RA_a[i] = lcg_next(&rng) % EC_N; if (RA_a[i] == 0) RA_a[i] = 1;
            RA_b[i] = lcg_next(&rng) % EC_N;
            RA[i] = ec_add_mont(ec_mul_mont(RA_a[i], mG), ec_mul_mont(RA_b[i], mQ));
        }

        u64 a1 = lcg_next(&rng) % EC_N; if (a1 == 0) a1 = 1;
        u64 b1 = lcg_next(&rng) % EC_N;
        MPoint R1 = ec_add_mont(ec_mul_mont(a1, mG), ec_mul_mont(b1, mQ));
        u64 a2 = a1, b2 = b1;
        MPoint R2 = R1;

        for (u64 i = 1; i < 20000000000ULL && !solved; i++) {
            /* Tortoise: 1 step */
            int idx = (int)(R1.x & (NPTS - 1));
            R1 = ec_add_mont(R1, RA[idx]);
            a1 = addmod_n(a1, RA_a[idx]);
            b1 = addmod_n(b1, RA_b[idx]);

            /* Hare: 2 steps */
            idx = (int)(R2.x & (NPTS - 1));
            R2 = ec_add_mont(R2, RA[idx]);
            a2 = addmod_n(a2, RA_a[idx]);
            b2 = addmod_n(b2, RA_b[idx]);

            idx = (int)(R2.x & (NPTS - 1));
            R2 = ec_add_mont(R2, RA[idx]);
            a2 = addmod_n(a2, RA_a[idx]);
            b2 = addmod_n(b2, RA_b[idx]);

            /* Compare Montgomery x-coords (unique per abstract point) */
            if (!R1.inf && !R2.inf && R1.x == R2.x) {
                u64 d_candidate = 0;
                int valid = 0;

                /* Convert to affine for verification */
                u64 r1x = from_mont(R1.x), r1y = from_mont(R1.y);
                u64 r2x = from_mont(R2.x), r2y = from_mont(R2.y);

                if (r1y == r2y) {
                    /* R1 = R2 */
                    u64 da = submod_n(a1, a2);
                    u64 db = submod_n(b2, b1);
                    if (db != 0) {
                        d_candidate = mulmod_n(da, powmod_n(db, EC_N - 2));
                        /* Verify d*G = Q using Montgomery */
                        MPoint check = ec_mul_mont(d_candidate, ta->mG);
                        if (!check.inf && from_mont(check.x) == QX && from_mont(check.y) == QY)
                            valid = 1;
                    }
                } else {
                    /* R1 = -R2 */
                    u64 da = addmod_n(a1, a2);
                    u64 db = addmod_n(b1, b2);
                    if (db != 0) {
                        d_candidate = mulmod_n(submod_n(0, da), powmod_n(db, EC_N - 2));
                        MPoint check = ec_mul_mont(d_candidate, ta->mG);
                        if (!check.inf && from_mont(check.x) == QX && from_mont(check.y) == QY)
                            valid = 1;
                    }
                }

                if (valid) {
                    ta->result_d = d_candidate;
                    ta->found = 1;
                    ta->iterations = i;
                    solved = 1;
                    return NULL;
                }
                /* Collision but invalid d - break and retry */
                break;
            }

            if (tid == 0 && i % 2000000 == 0) {
                printf("\r  [T0] att %d: %lluM iter, %.0fK/s  ",
                       attempt, (unsigned long long)(i/1000000),
                       (double)i / ((double)(clock()) / CLOCKS_PER_SEC) / 1e3);
                fflush(stdout);
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int nthreads = 16;
    if (argc > 1) nthreads = atoi(argv[1]);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 32) nthreads = 32;

    printf("Initializing Montgomery arithmetic...\n");
    mont_init();
    printf("Montgomery OK.\n");

    /* Convert base points to Montgomery form */
    MPoint mG = {to_mont(GX), to_mont(GY), 0};
    MPoint mQ = {to_mont(QX), to_mont(QY), 0};

    /* Verify G on curve: y^2 = x^3 + ax + b */
    u64 mb = to_mont(0x22996b9c33aeefdbULL);
    u64 lhs = mont_sqr(mG.y);
    u64 x3 = mont_mul(mG.x, mont_sqr(mG.x));
    u64 ax = mont_mul(MONT_A, mG.x);
    u64 rhs = mont_add(mont_add(x3, ax), mb);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }
    printf("G verified on curve.\n");

    /* Verify n*G = O */
    MPoint nG = ec_mul_mont(EC_N, mG);
    if (!nG.inf) { printf("n*G != O!\n"); return 1; }
    printf("n*G = O verified.\n");

    printf("\nECDLP solver: %d threads, Montgomery mul, r-adding walk\n", nthreads);
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)EC_P, (unsigned long long)EC_N);
    fflush(stdout);

    clock_t start = clock();
    pthread_t threads[32];
    ThreadArg args[32];

    for (int i = 0; i < nthreads; i++) {
        args[i].tid = i;
        args[i].mG = mG;
        args[i].mQ = mQ;
        args[i].found = 0;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    double wall = (double)(clock() - start) / CLOCKS_PER_SEC;

    for (int i = 0; i < nthreads; i++) {
        if (args[i].found) {
            printf("\n\n*** ECDLP SOLVED by thread %d! ***\n", i);
            printf("Private key d = 0x%016llx\n", (unsigned long long)args[i].result_d);
            printf("d (decimal) = %llu\n", (unsigned long long)args[i].result_d);
            printf("Iterations: %llu\n", (unsigned long long)args[i].iterations);
            printf("Wall time: %.1f seconds\n", wall);
            fflush(stdout);

            FILE *f = fopen("ecdlp_result.txt", "w");
            if (f) {
                fprintf(f, "*** ECDLP SOLVED! ***\n");
                fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)args[i].result_d);
                fprintf(f, "d = %llu\n", (unsigned long long)args[i].result_d);
                fprintf(f, "Iterations: %llu (thread %d)\n", (unsigned long long)args[i].iterations, i);
                fprintf(f, "Wall time: %.1f seconds\n", wall);
                fclose(f);
            }
            return 0;
        }
    }
    printf("\nNo solution found after %.1f seconds.\n", wall);
    return 1;
}
