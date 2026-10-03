/* Fast 64-bit ECDLP solver: Pollard rho with Jacobian coordinates */
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

static inline u64 mulmod(u64 a, u64 b, u64 m) {
    return (u64)(((u128)a * b) % m);
}
static inline u64 addmod(u64 a, u64 b, u64 m) {
    u64 s = a + b; return s >= m || s < a ? s - m : s;
}
static inline u64 submod(u64 a, u64 b, u64 m) {
    return a >= b ? a - b : a + m - b;
}
static inline u64 sqmod(u64 a, u64 m) {
    return (u64)(((u128)a * a) % m);
}
static u64 powmod(u64 base, u64 exp, u64 m) {
    u64 r = 1; base %= m;
    while (exp > 0) {
        if (exp & 1) r = mulmod(r, base, m);
        base = sqmod(base, m); exp >>= 1;
    }
    return r;
}
static inline u64 invmod(u64 a, u64 m) { return powmod(a, m - 2, m); }

/* Jacobian point: (X:Y:Z), affine = (X/Z^2, Y/Z^3), INF = Z==0 */
typedef struct { u64 X, Y, Z; } JPoint;
/* Affine point */
typedef struct { u64 x, y; } APoint;

static const JPoint JINF = {1, 1, 0};

static inline int jis_inf(JPoint p) { return p.Z == 0; }

/* Jacobian doubling with a = p-3 optimization
   Cost: 4M + 4S
   2*(X1:Y1:Z1) when a = -3:
     A = 3*(X1 - Z1^2)*(X1 + Z1^2)
     B = 2*Y1
     C = B^2
     D = 2*X1*C
     X3 = A^2 - 2*D
     Y3 = A*(D - X3) - C^2/2  ... actually let me use standard formulas
*/
static JPoint jdbl(JPoint p) {
    if (jis_inf(p) || p.Y == 0) return JINF;
    u64 Z2 = sqmod(p.Z, P);
    /* a = p-3, so a*Z^4 = -3*Z^4 = P - 3*Z^4 */
    u64 Z4 = sqmod(Z2, P);
    u64 threeZ4 = addmod(addmod(Z4, Z4, P), Z4, P);
    u64 X2 = sqmod(p.X, P);
    u64 threeX2 = addmod(addmod(X2, X2, P), X2, P);
    /* alpha = 3*X^2 + a*Z^4 = 3*X^2 - 3*Z^4 = 3*(X^2 - Z^4) = 3*(X-Z^2)*(X+Z^2) */
    u64 alpha = submod(threeX2, threeZ4, P);
    u64 Y2 = sqmod(p.Y, P);
    u64 beta = mulmod(4, mulmod(p.X, Y2, P), P);
    u64 X3 = submod(sqmod(alpha, P), addmod(beta, beta, P), P);
    u64 eightY4 = mulmod(8, sqmod(Y2, P), P);
    u64 Y3 = submod(mulmod(alpha, submod(beta, X3, P), P), eightY4, P);
    u64 Z3 = mulmod(2, mulmod(p.Y, p.Z, P), P);
    return (JPoint){X3, Y3, Z3};
}

/* Mixed addition: Jacobian + Affine → Jacobian
   Cost: 8M + 3S (when Z1 != 1) */
static JPoint jmadd(JPoint p, APoint q) {
    if (jis_inf(p)) return (JPoint){q.x, q.y, 1};

    u64 Z2 = sqmod(p.Z, P);
    u64 ZZ3 = mulmod(p.Z, Z2, P);
    u64 U2 = mulmod(q.x, Z2, P);
    u64 S2 = mulmod(q.y, ZZ3, P);

    u64 H = submod(U2, p.X, P);
    u64 R = submod(S2, p.Y, P);

    if (H == 0) {
        if (R == 0) return jdbl(p);
        return JINF;
    }

    u64 H2 = sqmod(H, P);
    u64 H3 = mulmod(H, H2, P);
    u64 UH2 = mulmod(p.X, H2, P);

    u64 X3 = submod(submod(sqmod(R, P), H3, P), addmod(UH2, UH2, P), P);
    u64 Y3 = submod(mulmod(R, submod(UH2, X3, P), P), mulmod(p.Y, H3, P), P);
    u64 Z3 = mulmod(p.Z, H, P);
    return (JPoint){X3, Y3, Z3};
}

/* Convert Jacobian to affine */
static APoint j_to_affine(JPoint p) {
    if (jis_inf(p)) return (APoint){0, 0};
    u64 zi = invmod(p.Z, P);
    u64 zi2 = sqmod(zi, P);
    u64 zi3 = mulmod(zi, zi2, P);
    return (APoint){mulmod(p.X, zi2, P), mulmod(p.Y, zi3, P)};
}

/* Scalar multiplication (Jacobian) */
static JPoint jmul(u64 k, APoint p) {
    JPoint R = JINF;
    while (k > 0) {
        if (k & 1) R = jmadd(R, p);
        /* Double: need to convert p to Jacobian for doubling in loop...
           Actually for scalar mul, use double-and-add with Jacobian accumulator */
        k >>= 1;
        if (k > 0) {
            /* We need to double the base point too, but it's affine...
               Convert to Jacobian, double, convert back? Too expensive.
               Instead, use windowed method or just keep in Jacobian. */
        }
    }
    return R;
}

/* Better scalar mul: full Jacobian */
static JPoint jmul2(u64 k, APoint base) {
    JPoint R = JINF;
    JPoint B = {base.x, base.y, 1};
    while (k > 0) {
        if (k & 1) {
            if (jis_inf(R)) R = B;
            else {
                APoint ba = j_to_affine(B);
                R = jmadd(R, ba);
            }
        }
        B = jdbl(B);
        k >>= 1;
    }
    return R;
}

/* Compare two Jacobian points by x-coordinate only (sufficient for collision detection) */
static int jxeq(JPoint a, JPoint b) {
    if (jis_inf(a) && jis_inf(b)) return 1;
    if (jis_inf(a) || jis_inf(b)) return 0;
    /* X1*Z2^2 == X2*Z1^2 */
    u64 lhs = mulmod(a.X, sqmod(b.Z, P), P);
    u64 rhs = mulmod(b.X, sqmod(a.Z, P), P);
    return lhs == rhs;
}

/* Pollard rho step using Jacobian coordinates
   Partition by hash(X) to avoid degeneracy */
static inline void step(JPoint *R, u64 *a, u64 *b, APoint G, APoint Q) {
    /* Use a hash of the X coordinate for partitioning (avoid mod 3 on Jacobian X) */
    u64 h = R->X;
    h ^= (h >> 17);
    int part = jis_inf(*R) ? 0 : (int)(h % 3);
    switch (part) {
    case 0:
        *R = jmadd(*R, Q);
        *b = addmod(*b, 1, N);
        break;
    case 1:
        *R = jdbl(*R);
        *a = addmod(*a, *a, N);
        *b = addmod(*b, *b, N);
        break;
    case 2:
        *R = jmadd(*R, G);
        *a = addmod(*a, 1, N);
        break;
    }
}

/* r-adding walk: use 16 precomputed points for better mixing
   This avoids the doubling step which can cause short cycles */
static APoint RA[16];
static u64 RA_a[16], RA_b[16];

static void init_radding(APoint G, APoint Q) {
    srand((unsigned)time(NULL));
    for (int i = 0; i < 16; i++) {
        RA_a[i] = ((u64)rand() << 32 | rand()) % N;
        RA_b[i] = ((u64)rand() << 32 | rand()) % N;
        if (RA_a[i] == 0) RA_a[i] = 1;
        JPoint tmp = jmadd(jmul2(RA_a[i], G), Q);
        /* Hack: jmul2(RA_b[i], Q) is expensive, use simpler init */
        tmp = jmul2(RA_b[i], Q);
        JPoint ga = jmul2(RA_a[i], G);
        JPoint combined;
        if (jis_inf(ga)) combined = tmp;
        else {
            APoint ta = j_to_affine(tmp);
            combined = jmadd(ga, ta);
        }
        RA[i] = j_to_affine(combined);
    }
}

static inline void rstep(JPoint *R, u64 *a, u64 *b) {
    u64 h = R->X;
    int idx = (int)(h & 0xF);
    *R = jmadd(*R, RA[idx]);
    *a = addmod(*a, RA_a[idx], N);
    *b = addmod(*b, RA_b[idx], N);
}

int main(void) {
    APoint G = {GX, GY};
    APoint Q = {QX, QY};

    /* Verify */
    u64 lhs = sqmod(GY, P);
    u64 rhs = addmod(addmod(mulmod(GX, sqmod(GX, P), P),
                            mulmod(P - 3, GX, P), P), 0x22996b9c33aeefdbULL, P);
    if (lhs != rhs) { printf("G not on curve!\n"); return 1; }
    lhs = sqmod(QY, P);
    rhs = addmod(addmod(mulmod(QX, sqmod(QX, P), P),
                        mulmod(P - 3, QX, P), P), 0x22996b9c33aeefdbULL, P);
    if (lhs != rhs) { printf("Q not on curve!\n"); return 1; }

    /* Verify n*G = O */
    JPoint nG = jmul2(N, G);
    if (!jis_inf(nG)) { printf("n*G != O!\n"); return 1; }

    printf("Curve verified. Jacobian Pollard rho starting...\n");
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)P, (unsigned long long)N);
    fflush(stdout);

    clock_t start = clock();

    for (int attempt = 0; attempt < 200; attempt++) {
        u64 a1 = ((u64)rand() << 32 | rand()) % N;
        u64 b1 = ((u64)rand() << 32 | rand()) % N;
        if (a1 == 0) a1 = 1;

        /* R1 = a1*G + b1*Q */
        JPoint aG = jmul2(a1, G);
        JPoint bQ = jmul2(b1, Q);
        JPoint R1;
        if (jis_inf(aG)) R1 = bQ;
        else if (jis_inf(bQ)) R1 = aG;
        else { APoint ba = j_to_affine(bQ); R1 = jmadd(aG, ba); }

        u64 a2 = a1, b2 = b1;
        JPoint R2 = R1;

        for (u64 i = 1; i < 10000000000ULL; i++) {
            step(&R1, &a1, &b1, G, Q);
            step(&R2, &a2, &b2, G, Q);
            step(&R2, &a2, &b2, G, Q);

            /* Check collision by comparing x-coordinates */
            if (jxeq(R1, R2)) {
                u64 da = submod(a2, a1, N);
                u64 db = submod(b1, b2, N);
                if (db == 0) {
                    printf("  attempt %d: db=0, retrying (i=%llu)\n",
                           attempt, (unsigned long long)i);
                    break;
                }
                u64 d = mulmod(da, invmod(db, N), N);
                /* Verify */
                JPoint check = jmul2(d, G);
                APoint ca = j_to_affine(check);
                if (ca.x == QX && ca.y == QY) {
                    double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                    printf("\n*** ECDLP SOLVED! ***\n");
                    printf("Private key d = 0x%016llx\n", (unsigned long long)d);
                    printf("d = %llu\n", (unsigned long long)d);
                    printf("Iterations: %llu (attempt %d)\n",
                           (unsigned long long)i, attempt);
                    printf("Time: %.1f seconds\n", elapsed);
                    printf("Verified: d*G = Q\n");
                    return 0;
                }
                printf("  attempt %d: false positive at i=%llu\n",
                       attempt, (unsigned long long)i);
                break;
            }

            if (i % 50000000 == 0) {
                double elapsed = (double)(clock() - start) / CLOCKS_PER_SEC;
                printf("  attempt %d: %lluM iter (%.0fs, %.1fM/s)\n",
                       attempt, (unsigned long long)(i / 1000000),
                       elapsed, (double)i / elapsed / 1e6);
                fflush(stdout);
            }
        }
    }
    printf("Failed\n");
    return 1;
}
