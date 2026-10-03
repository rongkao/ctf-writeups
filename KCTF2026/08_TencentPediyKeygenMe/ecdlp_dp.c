/* ECDLP: distinguished-point Pollard rho, 线性加速 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

static const u64 P  = 0xc564eef070e69193ULL;
static const u64 N  = 0xc564eef19a080b07ULL;
static const u64 GX = 0x2223a1d595845fa2ULL;
static const u64 GY = 0x1c4eee9222ddda62ULL;
static const u64 QX = 0x297a4a1e5b1fc99bULL;
static const u64 QY = 0x880198e3724f9feeULL;

static volatile int solved = 0;

static inline u64 mulmod(u64 a, u64 b, u64 m) { return (u64)(((u128)a * b) % m); }
static inline u64 addmod(u64 a, u64 b, u64 m) { u64 s=a+b; return s>=m||s<a ? s-m : s; }
static inline u64 submod(u64 a, u64 b, u64 m) { return a>=b ? a-b : a+m-b; }

static u64 invmod(u64 a, u64 m) {
    u64 r0 = m, r1 = a, s0 = 0, s1 = 1;
    while (r1 != 0) {
        u64 q = r0 / r1;
        u64 r2 = r0 - q * r1;
        u64 qs = (u64)(((u128)q * s1) % m);
        u64 s2 = s0 >= qs ? s0 - qs : s0 + m - qs;
        r0 = r1; r1 = r2;
        s0 = s1; s1 = s2;
    }
    return s0;
}

static u64 powmod(u64 b, u64 e, u64 m) {
    u64 r=1; b%=m;
    while(e>0){if(e&1)r=mulmod(r,b,m);b=mulmod(b,b,m);e>>=1;}
    return r;
}

typedef struct { u64 x,y; int inf; } Pt;
static const Pt INF_PT = {0,0,1};

static Pt ec_add(Pt p, Pt q) {
    if(p.inf) return q;
    if(q.inf) return p;
    u64 lam;
    if(p.x == q.x) {
        if(p.y != q.y || p.y == 0) return INF_PT;
        u64 num = addmod(mulmod(3, mulmod(p.x, p.x, P), P), P-3, P);
        lam = mulmod(num, invmod(addmod(p.y, p.y, P), P), P);
    } else {
        lam = mulmod(submod(q.y, p.y, P), invmod(submod(q.x, p.x, P), P), P);
    }
    u64 x3 = submod(submod(mulmod(lam, lam, P), p.x, P), q.x, P);
    u64 y3 = submod(mulmod(lam, submod(p.x, x3, P), P), p.y, P);
    return (Pt){x3, y3, 0};
}

static Pt ec_mul(u64 k, Pt b) {
    Pt R = INF_PT;
    while(k>0){if(k&1) R=ec_add(R,b); b=ec_add(b,b); k>>=1;}
    return R;
}

/* Distinguished point: 高20位全零 */
#define DP_BITS 20
#define DP_MASK ((1ULL << DP_BITS) - 1)
#define IS_DP(x) (((x) >> (64 - DP_BITS)) == 0)

/* 哈希表存储 distinguished points */
#define HT_SIZE (1 << 22)  /* 4M 桶 */
#define HT_MASK (HT_SIZE - 1)

typedef struct {
    u64 x;    /* 点的 x 坐标 */
    u64 a, b; /* 系数: R = a*G + b*Q */
    int used;
} DPEntry;

static DPEntry ht[HT_SIZE];
static pthread_mutex_t ht_lock = PTHREAD_MUTEX_INITIALIZER;

static u64 result_d = 0;

#define NPTS 32

static u64 lcg(u64 *s) {
    *s = *s * 6364136223846793005ULL + 1442695040888963407ULL;
    return *s;
}

/* 预计算的步进点 */
static Pt RA[NPTS];
static u64 Ra[NPTS], Rb[NPTS];

typedef struct { int tid; u64 iters; } TArg;

static int try_insert_dp(u64 x, u64 a, u64 b) {
    u64 h = (x * 0x9E3779B97F4A7C15ULL) >> (64 - 22);
    for (int probe = 0; probe < 64; probe++) {
        int idx = (int)((h + probe) & HT_MASK);
        pthread_mutex_lock(&ht_lock);
        if (!ht[idx].used) {
            ht[idx].x = x; ht[idx].a = a; ht[idx].b = b; ht[idx].used = 1;
            pthread_mutex_unlock(&ht_lock);
            return 0; /* 新插入 */
        }
        if (ht[idx].x == x) {
            u64 old_a = ht[idx].a, old_b = ht[idx].b;
            pthread_mutex_unlock(&ht_lock);

            /* 碰撞! 尝试求解 d */
            /* a1*G + b1*Q = a2*G + b2*Q => d*(b1-b2) = a2-a1 mod N */
            u64 da = submod(old_a, a, N);
            u64 db = submod(b, old_b, N);
            if (db == 0) return -1; /* 无用碰撞 */

            u64 dc = mulmod(da, powmod(db, N-2, N), N);
            Pt check = ec_mul(dc, (Pt){GX,GY,0});
            if (!check.inf && check.x == QX && check.y == QY) {
                result_d = dc;
                return 1; /* 找到! */
            }
            /* R1 = -R2 情况 */
            da = addmod(old_a, a, N);
            db = addmod(old_b, b, N);
            if (db == 0) return -1;
            dc = mulmod(submod(0, da, N), powmod(db, N-2, N), N);
            check = ec_mul(dc, (Pt){GX,GY,0});
            if (!check.inf && check.x == QX && check.y == QY) {
                result_d = dc;
                return 1;
            }
            return -1;
        }
        pthread_mutex_unlock(&ht_lock);
    }
    return 0; /* 表满，忽略 */
}

static void *worker(void *arg) {
    TArg *t = (TArg*)arg;
    int tid = t->tid;
    u64 rng = (u64)time(NULL) * 2654435761ULL + (u64)tid * 0x9E3779B97F4A7C15ULL + 12345;
    Pt G = {GX,GY,0}, Q = {QX,QY,0};

    u64 total_steps = 0;

    for (int att = 0; att < 1000 && !solved; att++) {
        /* 随机起点 */
        u64 a1 = lcg(&rng) % N; if (!a1) a1 = 1;
        u64 b1 = lcg(&rng) % N;
        Pt R = ec_add(ec_mul(a1, G), ec_mul(b1, Q));

        for (u64 i = 0; i < 2000000000ULL && !solved; i++) {
            int idx = (int)(R.x & (NPTS-1));
            R = ec_add(R, RA[idx]);
            a1 = addmod(a1, Ra[idx], N);
            b1 = addmod(b1, Rb[idx], N);
            total_steps++;

            if (R.inf) break; /* 撞到无穷远点，重新开始 */

            if (IS_DP(R.x)) {
                int res = try_insert_dp(R.x, a1, b1);
                if (res == 1) {
                    solved = 1;
                    t->iters = total_steps;
                    return NULL;
                }
                if (res == -1) break; /* 无用碰撞，重新开始 */
            }

            if (tid == 0 && total_steps % 2000000 == 0) {
                double el = (double)(clock()) / CLOCKS_PER_SEC;
                printf("\r  [T0] %lluM steps (%.0fs, %.0fK/s)    ",
                       (unsigned long long)(total_steps/1000000), el,
                       el>0 ? (double)total_steps/el/1e3 : 0);
                fflush(stdout);
            }
        }
    }
    t->iters = total_steps;
    return NULL;
}

int main(int argc, char **argv) {
    int nt = 16; if(argc>1) nt=atoi(argv[1]); if(nt<1) nt=1; if(nt>32) nt=32;

    Pt G = {GX,GY,0}, Q = {QX,QY,0};
    u64 l = mulmod(GY,GY,P), r = addmod(addmod(mulmod(GX,mulmod(GX,GX,P),P),mulmod(P-3,GX,P),P),0x22996b9c33aeefdbULL,P);
    if(l!=r){printf("G bad\n");return 1;}
    Pt nG = ec_mul(N,G); if(!nG.inf){printf("nG!=O\n");return 1;}
    u64 inv7 = invmod(7,P); if(mulmod(7,inv7,P)!=1){printf("invmod broken!\n");return 1;}

    /* 预计算步进点 */
    u64 rng_init = 0xDEADBEEF42ULL;
    for (int i = 0; i < NPTS; i++) {
        Ra[i] = lcg(&rng_init) % N; if (!Ra[i]) Ra[i] = 1;
        Rb[i] = lcg(&rng_init) % N;
        RA[i] = ec_add(ec_mul(Ra[i], G), ec_mul(Rb[i], Q));
    }

    memset(ht, 0, sizeof(ht));

    printf("ECDLP: %d threads, distinguished-point (d=%d), %d walk pts\n", nt, DP_BITS, NPTS);
    printf("Expected: ~%.0fM total steps, ~%.0fM per thread\n",
           4726.0, 4726.0 / nt);
    fflush(stdout);

    clock_t start = clock();
    pthread_t thr[32]; TArg args[32];
    for (int i = 0; i < nt; i++) { args[i].tid = i; args[i].iters = 0; pthread_create(&thr[i], NULL, worker, &args[i]); }
    for (int i = 0; i < nt; i++) pthread_join(thr[i], NULL);
    double wall = (double)(clock()-start)/CLOCKS_PER_SEC;

    u64 total = 0;
    for (int i = 0; i < nt; i++) total += args[i].iters;

    if (solved && result_d) {
        printf("\n\n*** ECDLP SOLVED! ***\n");
        printf("Private key d = 0x%016llx\n", (unsigned long long)result_d);
        printf("d = %llu\n", (unsigned long long)result_d);
        printf("Total steps: %lluM, Wall: %.1fs\n", (unsigned long long)(total/1000000), wall);
        fflush(stdout);
        FILE *f = fopen("ecdlp_result.txt","w");
        if(f){fprintf(f,"*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nd = %llu\nTotal steps: %lluM\nWall: %.1fs\n",
               (unsigned long long)result_d,(unsigned long long)result_d,(unsigned long long)(total/1000000),wall);fclose(f);}
        return 0;
    }
    printf("\nFailed after %lluM steps, %.1fs\n", (unsigned long long)(total/1000000), wall);
    return 1;
}
