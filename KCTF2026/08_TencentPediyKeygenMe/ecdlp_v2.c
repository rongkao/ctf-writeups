/* Improved ECDLP solver: r-adding walk + handle both R1=R2 and R1=-R2 */
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
static inline u64 invmod(u64 a, u64 m) { return powmod(a, m-2, m); }

typedef struct { u64 X,Y,Z; } JPoint;
typedef struct { u64 x,y; } APoint;
static const JPoint JINF = {1,1,0};
static inline int jis_inf(JPoint p) { return p.Z==0; }

static JPoint jdbl(JPoint p) {
    if(jis_inf(p)||p.Y==0) return JINF;
    u64 Z2=sqmod(p.Z,P), Z4=sqmod(Z2,P);
    u64 threeZ4=addmod(addmod(Z4,Z4,P),Z4,P);
    u64 X2=sqmod(p.X,P);
    u64 threeX2=addmod(addmod(X2,X2,P),X2,P);
    u64 alpha=submod(threeX2,threeZ4,P);
    u64 Y2=sqmod(p.Y,P);
    u64 beta=mulmod(4,mulmod(p.X,Y2,P),P);
    u64 X3=submod(sqmod(alpha,P),addmod(beta,beta,P),P);
    u64 eightY4=mulmod(8,sqmod(Y2,P),P);
    u64 Y3=submod(mulmod(alpha,submod(beta,X3,P),P),eightY4,P);
    u64 Z3=mulmod(2,mulmod(p.Y,p.Z,P),P);
    return (JPoint){X3,Y3,Z3};
}

static JPoint jmadd(JPoint p, APoint q) {
    if(jis_inf(p)) return (JPoint){q.x,q.y,1};
    u64 Z2=sqmod(p.Z,P), ZZ3=mulmod(p.Z,Z2,P);
    u64 U2=mulmod(q.x,Z2,P), S2=mulmod(q.y,ZZ3,P);
    u64 H=submod(U2,p.X,P), R=submod(S2,p.Y,P);
    if(H==0) { return R==0 ? jdbl(p) : JINF; }
    u64 H2=sqmod(H,P), H3=mulmod(H,H2,P), UH2=mulmod(p.X,H2,P);
    u64 X3=submod(submod(sqmod(R,P),H3,P),addmod(UH2,UH2,P),P);
    u64 Y3=submod(mulmod(R,submod(UH2,X3,P),P),mulmod(p.Y,H3,P),P);
    u64 Z3=mulmod(p.Z,H,P);
    return (JPoint){X3,Y3,Z3};
}

static APoint j_to_affine(JPoint p) {
    if(jis_inf(p)) return (APoint){0,0};
    u64 zi=invmod(p.Z,P), zi2=sqmod(zi,P), zi3=mulmod(zi,zi2,P);
    return (APoint){mulmod(p.X,zi2,P), mulmod(p.Y,zi3,P)};
}

static JPoint jmul2(u64 k, APoint base) {
    JPoint R=JINF, B={base.x,base.y,1};
    while(k>0) {
        if(k&1) { if(jis_inf(R)) R=B; else { APoint ba=j_to_affine(B); R=jmadd(R,ba); } }
        B=jdbl(B); k>>=1;
    }
    return R;
}

/* Compare affine x-coordinates in Jacobian form */
static int jxeq(JPoint a, JPoint b) {
    if(jis_inf(a)&&jis_inf(b)) return 1;
    if(jis_inf(a)||jis_inf(b)) return 0;
    return mulmod(a.X,sqmod(b.Z,P),P) == mulmod(b.X,sqmod(a.Z,P),P);
}

/* r-adding walk: 32 precomputed random points for better mixing */
#define NPTS 32
static APoint RA[NPTS];
static u64 RA_a[NPTS], RA_b[NPTS];

static u64 myrand64(void) {
    return ((u64)rand()<<48) ^ ((u64)rand()<<32) ^ ((u64)rand()<<16) ^ rand();
}

static void init_radding(APoint G, APoint Q) {
    for(int i=0; i<NPTS; i++) {
        RA_a[i] = myrand64() % N; if(RA_a[i]==0) RA_a[i]=1;
        RA_b[i] = myrand64() % N;
        JPoint ga = jmul2(RA_a[i], G);
        JPoint bq = jmul2(RA_b[i], Q);
        JPoint combined;
        if(jis_inf(ga)) combined = bq;
        else if(jis_inf(bq)) combined = ga;
        else { APoint ba = j_to_affine(bq); combined = jmadd(ga, ba); }
        RA[i] = j_to_affine(combined);
    }
}

static inline void rstep(JPoint *R, u64 *a, u64 *b) {
    int idx = (int)(R->X & (NPTS-1));
    *R = jmadd(*R, RA[idx]);
    *a = addmod(*a, RA_a[idx], N);
    *b = addmod(*b, RA_b[idx], N);
}

int main(void) {
    APoint G={GX,GY}, Q={QX,QY};

    /* Verify curve */
    u64 lhs=sqmod(GY,P);
    u64 rhs=addmod(addmod(mulmod(GX,sqmod(GX,P),P),mulmod(P-3,GX,P),P),0x22996b9c33aeefdbULL,P);
    if(lhs!=rhs){printf("G not on curve!\n");return 1;}
    lhs=sqmod(QY,P);
    rhs=addmod(addmod(mulmod(QX,sqmod(QX,P),P),mulmod(P-3,QX,P),P),0x22996b9c33aeefdbULL,P);
    if(lhs!=rhs){printf("Q not on curve!\n");return 1;}

    srand((unsigned)time(NULL) ^ 12345);

    printf("Improved ECDLP solver (r-adding walk, handles +/- collisions)\n");
    printf("p = 0x%016llx, n = 0x%016llx\n", (unsigned long long)P, (unsigned long long)N);
    fflush(stdout);

    clock_t start = clock();

    for(int attempt=0; attempt<200; attempt++) {
        init_radding(G, Q);

        u64 a1 = myrand64()%N; if(a1==0) a1=1;
        u64 b1 = myrand64()%N;
        JPoint aG=jmul2(a1,G), bQ=jmul2(b1,Q);
        JPoint R1;
        if(jis_inf(aG)) R1=bQ;
        else if(jis_inf(bQ)) R1=aG;
        else { APoint ba=j_to_affine(bQ); R1=jmadd(aG,ba); }

        u64 a2=a1, b2=b1;
        JPoint R2=R1;

        for(u64 i=1; i<20000000000ULL; i++) {
            rstep(&R1,&a1,&b1);
            rstep(&R2,&a2,&b2);
            rstep(&R2,&a2,&b2);

            if(jxeq(R1,R2)) {
                /* Try R1 = R2 case: d = (a1-a2)/(b2-b1) */
                u64 da = submod(a1,a2,N);
                u64 db = submod(b2,b1,N);
                if(db != 0) {
                    u64 d = mulmod(da, invmod(db,N), N);
                    JPoint check = jmul2(d,G);
                    APoint ca = j_to_affine(check);
                    if(ca.x==QX && ca.y==QY) {
                        double elapsed=(double)(clock()-start)/CLOCKS_PER_SEC;
                        printf("\n*** ECDLP SOLVED! ***\n");
                        printf("Private key d = 0x%016llx\n",(unsigned long long)d);
                        printf("d = %llu\n",(unsigned long long)d);
                        printf("Iterations: %llu (attempt %d)\n",(unsigned long long)i,attempt);
                        printf("Time: %.1f seconds\n",elapsed);
                        printf("Verified: d*G = Q\n");
                        fflush(stdout);
                        return 0;
                    }
                }

                /* Try R1 = -R2 case: d = -(a1+a2)/(b1+b2) */
                da = addmod(a1,a2,N);
                db = addmod(b1,b2,N);
                if(db != 0) {
                    u64 d = mulmod(submod(0,da,N), invmod(db,N), N);
                    JPoint check = jmul2(d,G);
                    APoint ca = j_to_affine(check);
                    if(ca.x==QX && ca.y==QY) {
                        double elapsed=(double)(clock()-start)/CLOCKS_PER_SEC;
                        printf("\n*** ECDLP SOLVED (negation case)! ***\n");
                        printf("Private key d = 0x%016llx\n",(unsigned long long)d);
                        printf("d = %llu\n",(unsigned long long)d);
                        printf("Iterations: %llu (attempt %d)\n",(unsigned long long)i,attempt);
                        printf("Time: %.1f seconds\n",elapsed);
                        printf("Verified: d*G = Q\n");
                        fflush(stdout);
                        return 0;
                    }
                }

                printf("  attempt %d: collision at i=%llu but d not found, retrying\n",
                       attempt, (unsigned long long)i);
                fflush(stdout);
                break;
            }

            if(i % 50000000 == 0) {
                double elapsed=(double)(clock()-start)/CLOCKS_PER_SEC;
                printf("  attempt %d: %lluM iter (%.0fs, %.1fM/s)\n",
                       attempt,(unsigned long long)(i/1000000),elapsed,(double)i/elapsed/1e6);
                fflush(stdout);
            }
        }
    }
    printf("Failed\n");
    return 1;
}
