/* Multi-threaded ECDLP solver: Pollard rho, affine coords, Montgomery mul */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;
typedef int64_t i64;

static const u64 EC_P = 0xc564eef070e69193ULL;
static const u64 EC_N = 0xc564eef19a080b07ULL;
static const u64 GX   = 0x2223a1d595845fa2ULL;
static const u64 GY   = 0x1c4eee9222ddda62ULL;
static const u64 QX   = 0x297a4a1e5b1fc99bULL;
static const u64 QY   = 0x880198e3724f9feeULL;

static volatile int solved = 0;
static u64 solution_d = 0;

/* Standard modular arithmetic (used for N arithmetic and setup) */
static inline u64 mulmod(u64 a, u64 b, u64 m) { return (u64)(((u128)a * b) % m); }
static inline u64 addmod(u64 a, u64 b, u64 m) { u64 s=a+b; return s>=m||s<a ? s-m : s; }
static inline u64 submod(u64 a, u64 b, u64 m) { return a>=b ? a-b : a+m-b; }
static u64 powmod(u64 base, u64 exp, u64 m) {
    u64 r=1; base%=m;
    while(exp>0) { if(exp&1) r=mulmod(r,base,m); base=mulmod(base,base,m); exp>>=1; }
    return r;
}

/* Extended GCD for fast modular inverse (faster than Fermat for 64-bit) */
static u64 invmod_gcd(u64 a, u64 m) {
    i64 old_r = (i64)a, r = (i64)m;
    i64 old_s = 1, s = 0;
    while (r != 0) {
        i64 q = old_r / r;
        i64 tmp;
        tmp = old_r - q * r; old_r = r; r = tmp;
        tmp = old_s - q * s; old_s = s; s = tmp;
    }
    return old_s < 0 ? (u64)(old_s + (i64)m) : (u64)old_s;
}

typedef struct { u64 x, y; int inf; } APoint;
static const APoint AINF = {0, 0, 1};

static APoint ec_add(APoint p, APoint q) {
    if (p.inf) return q;
    if (q.inf) return p;
    u64 lam;
    if (p.x == q.x) {
        if (p.y != q.y || p.y == 0) return AINF;
        u64 num = addmod(mulmod(3, mulmod(p.x, p.x, EC_P), EC_P), EC_P - 3, EC_P);
        u64 den = addmod(p.y, p.y, EC_P);
        lam = mulmod(num, invmod_gcd(den, EC_P), EC_P);
    } else {
        u64 num = submod(q.y, p.y, EC_P);
        u64 den = submod(q.x, p.x, EC_P);
        lam = mulmod(num, invmod_gcd(den, EC_P), EC_P);
    }
    u64 x3 = submod(submod(mulmod(lam, lam, EC_P), p.x, EC_P), q.x, EC_P);
    u64 y3 = submod(mulmod(lam, submod(p.x, x3, EC_P), EC_P), p.y, EC_P);
    return (APoint){x3, y3, 0};
}

static APoint ec_mul(u64 k, APoint base) {
    APoint R = AINF;
    while (k > 0) {
        if (k & 1) R = ec_add(R, base);
        base = ec_add(base, base);
        k >>= 1;
    }
    return R;
}

#define NPTS 32

typedef struct {
    int thread_id;
    APoint G, Q;
    u64 result_d;
    int found;
    u64 iterations;
    double elapsed;
} ThreadArg;

/* unused - use lcg_next instead */

/* Windows doesn't have rand_r, use a simple LCG */
static u64 lcg_next(u64 *state) {
    *state = *state * 6364136223846793005ULL + 1442695040888963407ULL;
    return *state;
}

static void *worker(void *arg) {
    ThreadArg *ta = (ThreadArg *)arg;
    APoint G = ta->G, Q = ta->Q;
    int tid = ta->thread_id;

    u64 rng = (u64)time(NULL) ^ ((u64)tid * 0x9E3779B97F4A7C15ULL) ^ 0xDEADBEEF12345678ULL;

    APoint RA[NPTS];
    u64 RA_a[NPTS], RA_b[NPTS];

    clock_t start = clock();

    for (int attempt = 0; attempt < 100 && !solved; attempt++) {
        for (int i = 0; i < NPTS; i++) {
            RA_a[i] = lcg_next(&rng) % EC_N; if (RA_a[i] == 0) RA_a[i] = 1;
            RA_b[i] = lcg_next(&rng) % EC_N;
            RA[i] = ec_add(ec_mul(RA_a[i], G), ec_mul(RA_b[i], Q));
        }

        u64 a1 = lcg_next(&rng) % EC_N; if (a1 == 0) a1 = 1;
        u64 b1 = lcg_next(&rng) % EC_N;
        APoint R1 = ec_add(ec_mul(a1, G), ec_mul(b1, Q));

        u64 a2 = a1, b2 = b1;
        APoint R2 = R1;

        for (u64 i = 1; i < 20000000000ULL && !solved; i++) {
            /* Tortoise: 1 step */
            int idx = (int)(R1.x & (NPTS - 1));
            R1 = ec_add(R1, RA[idx]);
            a1 = addmod(a1, RA_a[idx], EC_N);
            b1 = addmod(b1, RA_b[idx], EC_N);

            /* Hare: 2 steps */
            idx = (int)(R2.x & (NPTS - 1));
            R2 = ec_add(R2, RA[idx]);
            a2 = addmod(a2, RA_a[idx], EC_N);
            b2 = addmod(b2, RA_b[idx], EC_N);

            idx = (int)(R2.x & (NPTS - 1));
            R2 = ec_add(R2, RA[idx]);
            a2 = addmod(a2, RA_a[idx], EC_N);
            b2 = addmod(b2, RA_b[idx], EC_N);

            if (!R1.inf && !R2.inf && R1.x == R2.x) {
                u64 d_candidate;
                int valid = 0;

                if (R1.y == R2.y) {
                    u64 da = submod(a1, a2, EC_N);
                    u64 db = submod(b2, b1, EC_N);
                    if (db != 0) {
                        d_candidate = mulmod(da, powmod(db, EC_N - 2, EC_N), EC_N);
                        APoint check = ec_mul(d_candidate, G);
                        if (!check.inf && check.x == QX && check.y == QY)
                            valid = 1;
                    }
                } else {
                    u64 da = addmod(a1, a2, EC_N);
                    u64 db = addmod(b1, b2, EC_N);
                    if (db != 0) {
                        d_candidate = mulmod(submod(0, da, EC_N), powmod(db, EC_N - 2, EC_N), EC_N);
                        APoint check = ec_mul(d_candidate, G);
                        if (!check.inf && check.x == QX && check.y == QY)
                            valid = 1;
                    }
                }

                if (valid) {
                    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                    ta->result_d = d_candidate;
                    ta->found = 1;
                    ta->iterations = i;
                    ta->elapsed = elapsed;
                    solved = 1;
                    return NULL;
                }
                break;
            }

            if (i % 2000000 == 0 && tid == 0) {
                double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                printf("\r  [T0] attempt %d: %lluM iter (%.0fs, %.0fK/s)   ",
                       attempt, (unsigned long long)(i / 1000000), elapsed,
                       elapsed > 0 ? (double)i / elapsed / 1e3 : 0);
                fflush(stdout);
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    int nthreads = 8;
    if (argc > 1) nthreads = atoi(argv[1]);
    if (nthreads < 1) nthreads = 1;
    if (nthreads > 32) nthreads = 32;

    APoint G = {GX, GY, 0}, Q = {QX, QY, 0};

    u64 lhs = mulmod(GY, GY, EC_P);
    u64 rhs = addmod(addmod(mulmod(GX, mulmod(GX, GX, EC_P), EC_P),
                    mulmod(EC_P - 3, GX, EC_P), EC_P), 0x22996b9c33aeefdbULL, EC_P);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }

    printf("ECDLP solver: %d threads, affine coords, r-adding walk\n", nthreads);
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)EC_P, (unsigned long long)EC_N);
    printf("Expected: ~4726M steps per thread, effective ~%lluM with %d threads\n",
           (unsigned long long)(4726 / nthreads), nthreads);
    fflush(stdout);

    pthread_t threads[32];
    ThreadArg args[32];

    clock_t wall_start = clock();

    for (int i = 0; i < nthreads; i++) {
        args[i].thread_id = i;
        args[i].G = G;
        args[i].Q = Q;
        args[i].found = 0;
        pthread_create(&threads[i], NULL, worker, &args[i]);
    }

    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);

    double wall_elapsed = (double)(clock() - wall_start) / CLOCKS_PER_SEC;

    for (int i = 0; i < nthreads; i++) {
        if (args[i].found) {
            printf("\n\n*** ECDLP SOLVED by thread %d! ***\n", i);
            printf("Private key d = 0x%016llx\n", (unsigned long long)args[i].result_d);
            printf("d = %llu\n", (unsigned long long)args[i].result_d);
            printf("Iterations: %llu\n", (unsigned long long)args[i].iterations);
            printf("Thread time: %.1f seconds\n", args[i].elapsed);
            printf("Wall time: %.1f seconds\n", wall_elapsed);
            printf("Verified: d*G = Q\n");
            fflush(stdout);

            FILE *f = fopen("ecdlp_result.txt", "w");
            if (f) {
                fprintf(f, "*** ECDLP SOLVED! ***\n");
                fprintf(f, "Private key d = 0x%016llx\n", (unsigned long long)args[i].result_d);
                fprintf(f, "d = %llu\n", (unsigned long long)args[i].result_d);
                fprintf(f, "Iterations: %llu (thread %d)\n", (unsigned long long)args[i].iterations, i);
                fprintf(f, "Wall time: %.1f seconds\n", wall_elapsed);
                fclose(f);
            }
            return 0;
        }
    }
    printf("\nNo solution found.\n");
    return 1;
}
