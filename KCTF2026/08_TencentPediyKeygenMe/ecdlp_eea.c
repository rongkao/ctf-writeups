/* ECDLP: multi-threaded, correct EEA inverse, standard mulmod */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
static const Pt INF = {0,0,1};

static Pt ec_add(Pt p, Pt q) {
    if(p.inf) return q;
    if(q.inf) return p;
    u64 lam;
    if(p.x == q.x) {
        if(p.y != q.y || p.y == 0) return INF;
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
    Pt R = INF;
    while(k>0){if(k&1) R=ec_add(R,b); b=ec_add(b,b); k>>=1;}
    return R;
}

#define NPTS 32

static u64 lcg(u64 *s) {
    *s = *s * 6364136223846793005ULL + 1442695040888963407ULL;
    return *s;
}

typedef struct {
    int tid; Pt G, Q; u64 d; int found; u64 iters;
} TArg;

static void *worker(void *arg) {
    TArg *t = (TArg*)arg;
    Pt G = t->G, Q = t->Q;
    u64 rng = (u64)time(NULL) * 2654435761ULL + (u64)t->tid * 0x9E3779B97F4A7C15ULL;

    Pt RA[NPTS]; u64 Ra[NPTS], Rb[NPTS];

    for(int att=0; att<100 && !solved; att++) {
        for(int i=0; i<NPTS; i++) {
            Ra[i]=lcg(&rng)%N; if(!Ra[i])Ra[i]=1;
            Rb[i]=lcg(&rng)%N;
            RA[i]=ec_add(ec_mul(Ra[i],G), ec_mul(Rb[i],Q));
        }
        u64 a1=lcg(&rng)%N; if(!a1)a1=1;
        u64 b1=lcg(&rng)%N;
        Pt R1=ec_add(ec_mul(a1,G),ec_mul(b1,Q));
        u64 a2=a1, b2=b1; Pt R2=R1;

        for(u64 i=1; i<20000000000ULL && !solved; i++) {
            int idx=(int)(R1.x&(NPTS-1));
            R1=ec_add(R1,RA[idx]); a1=addmod(a1,Ra[idx],N); b1=addmod(b1,Rb[idx],N);
            idx=(int)(R2.x&(NPTS-1));
            R2=ec_add(R2,RA[idx]); a2=addmod(a2,Ra[idx],N); b2=addmod(b2,Rb[idx],N);
            idx=(int)(R2.x&(NPTS-1));
            R2=ec_add(R2,RA[idx]); a2=addmod(a2,Ra[idx],N); b2=addmod(b2,Rb[idx],N);

            if(!R1.inf && !R2.inf && R1.x==R2.x) {
                u64 dc=0; int ok=0;
                if(R1.y==R2.y) {
                    u64 da=submod(a1,a2,N), db=submod(b2,b1,N);
                    if(db){dc=mulmod(da,powmod(db,N-2,N),N); Pt c=ec_mul(dc,G); if(!c.inf&&c.x==QX&&c.y==QY)ok=1;}
                } else {
                    u64 da=addmod(a1,a2,N), db=addmod(b1,b2,N);
                    if(db){dc=mulmod(submod(0,da,N),powmod(db,N-2,N),N); Pt c=ec_mul(dc,G); if(!c.inf&&c.x==QX&&c.y==QY)ok=1;}
                }
                if(ok){t->d=dc;t->found=1;t->iters=i;solved=1;return NULL;}
                break;
            }
            if(t->tid==0 && i%2000000==0) {
                double el=(double)(clock())/CLOCKS_PER_SEC;
                printf("\r  [T0] att %d: %lluM (%.0fs, %.0fK/s)    ",att,(unsigned long long)(i/1000000),el,el>0?(double)i/el/1e3:0);
                fflush(stdout);
            }
        }
    }
    return NULL;
}

int main(int argc,char**argv) {
    int nt=16; if(argc>1)nt=atoi(argv[1]); if(nt<1)nt=1; if(nt>32)nt=32;
    Pt G={GX,GY,0}, Q={QX,QY,0};
    u64 l=mulmod(GY,GY,P), r=addmod(addmod(mulmod(GX,mulmod(GX,GX,P),P),mulmod(P-3,GX,P),P),0x22996b9c33aeefdbULL,P);
    if(l!=r){printf("G bad\n");return 1;}
    Pt nG=ec_mul(N,G); if(!nG.inf){printf("nG!=O\n");return 1;}

    /* Quick inverse test */
    u64 inv7=invmod(7,P); if(mulmod(7,inv7,P)!=1){printf("invmod broken! 7*inv7=%llu\n",(unsigned long long)mulmod(7,inv7,P));return 1;}
    printf("ECDLP: %d threads, EEA inverse, r-adding walk\n",nt);
    fflush(stdout);

    clock_t start=clock();
    pthread_t thr[32]; TArg args[32];
    for(int i=0;i<nt;i++){args[i].tid=i;args[i].G=G;args[i].Q=Q;args[i].found=0;pthread_create(&thr[i],NULL,worker,&args[i]);}
    for(int i=0;i<nt;i++)pthread_join(thr[i],NULL);
    double wall=(double)(clock()-start)/CLOCKS_PER_SEC;

    for(int i=0;i<nt;i++) if(args[i].found) {
        printf("\n\n*** ECDLP SOLVED (thread %d)! ***\n",i);
        printf("Private key d = 0x%016llx\n",(unsigned long long)args[i].d);
        printf("d = %llu\n",(unsigned long long)args[i].d);
        printf("Iters: %llu, Wall: %.1fs\n",(unsigned long long)args[i].iters,wall);
        fflush(stdout);
        FILE*f=fopen("ecdlp_result.txt","w");
        if(f){fprintf(f,"*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nd = %llu\nIters: %llu\nWall: %.1fs\n",
               (unsigned long long)args[i].d,(unsigned long long)args[i].d,(unsigned long long)args[i].iters,wall);fclose(f);}
        return 0;
    }
    printf("\nFailed after %.1fs\n",wall);return 1;
}
