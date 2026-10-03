/* ECDLP: Jacobian r-adding Pollard rho (no doubling, fast) */
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

static inline u64 mulmod(u64 a, u64 b, u64 m) { return (u64)(((u128)a*b)%m); }
static inline u64 sqmod(u64 a, u64 m) { return (u64)(((u128)a*a)%m); }
static inline u64 addmod(u64 a, u64 b, u64 m) { u64 s=a+b; return (s>=m||s<a)?s-m:s; }
static inline u64 submod(u64 a, u64 b, u64 m) { return a>=b ? a-b : a+m-b; }
static u64 invmod(u64 a, u64 m) {
    u64 r=1; a%=m; u64 e=m-2;
    while(e>0){if(e&1)r=mulmod(r,a,m);a=mulmod(a,a,m);e>>=1;}
    return r;
}

typedef struct { u64 x, y; } APt;
typedef struct { u64 X, Y, Z; } JPt;
#define JINF ((JPt){0,1,0})
#define IS_JINF(p) ((p).Z==0)

static JPt jdbl(JPt p) {
    if(IS_JINF(p)||p.Y==0) return JINF;
    u64 Z2=sqmod(p.Z,P), Z4=sqmod(Z2,P);
    u64 X2=sqmod(p.X,P);
    u64 alpha=submod(addmod(addmod(X2,X2,P),X2,P), addmod(addmod(Z4,Z4,P),Z4,P), P);
    u64 Y2=sqmod(p.Y,P);
    u64 beta=mulmod(4,mulmod(p.X,Y2,P),P);
    u64 X3=submod(sqmod(alpha,P),addmod(beta,beta,P),P);
    u64 Y3=submod(mulmod(alpha,submod(beta,X3,P),P),mulmod(8,sqmod(Y2,P),P),P);
    u64 Z3=mulmod(2,mulmod(p.Y,p.Z,P),P);
    return(JPt){X3,Y3,Z3};
}

static JPt jmadd(JPt p, APt q) {
    if(IS_JINF(p)) return(JPt){q.x,q.y,1};
    u64 Z2=sqmod(p.Z,P), Z3=mulmod(p.Z,Z2,P);
    u64 U2=mulmod(q.x,Z2,P), S2=mulmod(q.y,Z3,P);
    u64 H=submod(U2,p.X,P), R=submod(S2,p.Y,P);
    if(H==0){ return R==0 ? jdbl(p) : JINF; }
    u64 H2=sqmod(H,P), H3=mulmod(H,H2,P), UH2=mulmod(p.X,H2,P);
    u64 X3=submod(submod(sqmod(R,P),H3,P),addmod(UH2,UH2,P),P);
    u64 Y3=submod(mulmod(R,submod(UH2,X3,P),P),mulmod(p.Y,H3,P),P);
    return(JPt){X3,Y3,mulmod(p.Z,H,P)};
}

static int jxeq(JPt a, JPt b) {
    if(IS_JINF(a)&&IS_JINF(b)) return 1;
    if(IS_JINF(a)||IS_JINF(b)) return 0;
    return mulmod(a.X,sqmod(b.Z,P),P)==mulmod(b.X,sqmod(a.Z,P),P);
}

static JPt jmul(u64 k, APt base) {
    JPt R=JINF, B={base.x,base.y,1};
    while(k>0){
        if(k&1){ if(IS_JINF(R))R=B; else{u64 zi=invmod(B.Z,P);u64 z2=sqmod(zi,P);APt a={mulmod(B.X,z2,P),mulmod(B.Y,mulmod(zi,z2,P),P)};R=jmadd(R,a);}}
        B=jdbl(B); k>>=1;
    }
    return R;
}

static APt j2a(JPt p) {
    if(IS_JINF(p)) return(APt){0,0};
    u64 zi=invmod(p.Z,P),z2=sqmod(zi,P);
    return(APt){mulmod(p.X,z2,P),mulmod(p.Y,mulmod(zi,z2,P),P)};
}

#define NR 32
static APt RA[NR];
static u64 RA_a[NR], RA_b[NR];

static u64 rng_s;
static u64 rng(void){rng_s^=rng_s<<13;rng_s^=rng_s>>7;rng_s^=rng_s<<17;return rng_s;}

static void init_walk(APt G, APt Q) {
    rng_s=(u64)time(NULL)^((u64)clock()<<32)^0xCAFEBABE12345678ULL;
    for(int i=0;i<NR;i++){
        RA_a[i]=rng()%N; if(!RA_a[i])RA_a[i]=1;
        RA_b[i]=rng()%N; if(!RA_b[i])RA_b[i]=1;
        JPt aG=jmul(RA_a[i],G), bQ=jmul(RA_b[i],Q);
        JPt c; if(IS_JINF(aG))c=bQ; else if(IS_JINF(bQ))c=aG;
        else{APt ba=j2a(bQ);c=jmadd(aG,ba);}
        RA[i]=j2a(c);
    }
}

static inline void rstep(JPt *R, u64 *a, u64 *b) {
    u64 h=R->X; h^=(h>>17); h^=(h<<11);
    int idx=(int)(h&(NR-1));
    *R=jmadd(*R,RA[idx]);
    *a=addmod(*a,RA_a[idx],N);
    *b=addmod(*b,RA_b[idx],N);
}

int main(void) {
    APt G={GX,GY}, Q={QX,QY};

    u64 l=sqmod(GY,P), r=addmod(addmod(mulmod(GX,sqmod(GX,P),P),mulmod(P-3,GX,P),P),0x22996b9c33aeefdbULL,P);
    if(l!=r){printf("G bad\n");return 1;}
    l=sqmod(QY,P); r=addmod(addmod(mulmod(QX,sqmod(QX,P),P),mulmod(P-3,QX,P),P),0x22996b9c33aeefdbULL,P);
    if(l!=r){printf("Q bad\n");return 1;}

    JPt nG=jmul(N,G);
    if(!IS_JINF(nG)){printf("n*G!=O\n");return 1;}

    printf("OK. Jacobian r-adding Pollard rho (NR=%d)\n",NR);
    printf("p=0x%016llx n=0x%016llx\n",(unsigned long long)P,(unsigned long long)N);
    fflush(stdout);

    init_walk(G,Q);
    printf("Walk table ready.\n"); fflush(stdout);
    clock_t start=clock();

    for(int att=0;att<200;att++){
        u64 a1=rng()%N,b1=rng()%N;
        if(!a1)a1=1; if(!b1)b1=1;
        JPt aG=jmul(a1,G),bQ=jmul(b1,Q);
        JPt R1; if(IS_JINF(aG))R1=bQ; else if(IS_JINF(bQ))R1=aG;
        else{APt ba=j2a(bQ);R1=jmadd(aG,ba);}
        u64 a2=a1,b2=b1; JPt R2=R1;

        for(u64 i=1;i<20000000000ULL;i++){
            rstep(&R1,&a1,&b1);
            rstep(&R2,&a2,&b2);
            rstep(&R2,&a2,&b2);

            if(jxeq(R1,R2)){
                u64 da=submod(a2,a1,N), db=submod(b1,b2,N);
                if(db==0){printf("  att %d: db=0 i=%llu\n",att,(unsigned long long)i);break;}
                u64 d=mulmod(da,invmod(db,N),N);
                APt chk=j2a(jmul(d,G));
                if(chk.x==QX&&chk.y==QY){
                    double el=(double)(clock()-start)/CLOCKS_PER_SEC;
                    printf("\n*** ECDLP SOLVED! ***\n");
                    printf("Private key d = 0x%016llx\n",(unsigned long long)d);
                    printf("Iterations: %llu Time: %.1fs\n",(unsigned long long)i,el);
                    printf("Verified: d*G = Q\n"); fflush(stdout);
                    FILE *f=fopen("ecdlp_result.txt","a");
                    if(f){fprintf(f,"\n*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nTime: %.1fs\nVerified: d*G = Q\n",(unsigned long long)d,el);fclose(f);}
                    return 0;
                }
                d=N-d; chk=j2a(jmul(d,G));
                if(chk.x==QX&&chk.y==QY){
                    double el=(double)(clock()-start)/CLOCKS_PER_SEC;
                    printf("\n*** ECDLP SOLVED (neg)! ***\n");
                    printf("Private key d = 0x%016llx\n",(unsigned long long)d);
                    printf("Iterations: %llu Time: %.1fs\n",(unsigned long long)i,el);
                    printf("Verified: d*G = Q\n"); fflush(stdout);
                    FILE *f=fopen("ecdlp_result.txt","a");
                    if(f){fprintf(f,"\n*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nTime: %.1fs\nVerified: d*G = Q\n",(unsigned long long)d,el);fclose(f);}
                    return 0;
                }
                printf("  att %d: false pos i=%llu\n",att,(unsigned long long)i);
                break;
            }
            if(i%50000000==0){
                double el=(double)(clock()-start)/CLOCKS_PER_SEC;
                printf("  att %d: %lluM (%.0fs, %.1fM/s)\n",att,(unsigned long long)(i/1000000),el,(double)i/el/1e6);
                fflush(stdout);
            }
        }
    }
    return 1;
}
