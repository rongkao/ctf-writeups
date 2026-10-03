/* Multi-threaded Jacobian r-adding Pollard rho ECDLP solver */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

#define P  0xc564eef070e69193ULL
#define N  0xc564eef19a080b07ULL
#define GX 0x2223a1d595845fa2ULL
#define GY 0x1c4eee9222ddda62ULL
#define QX 0x297a4a1e5b1fc99bULL
#define QY 0x880198e3724f9feeULL

static inline u64 mulmod(u64 a,u64 b,u64 m){return(u64)(((u128)a*b)%m);}
static inline u64 sqmod(u64 a,u64 m){return(u64)(((u128)a*a)%m);}
static inline u64 addmod(u64 a,u64 b,u64 m){u64 s=a+b;return(s>=m||s<a)?s-m:s;}
static inline u64 submod(u64 a,u64 b,u64 m){return a>=b?a-b:a+m-b;}
static u64 invmod(u64 a,u64 m){u64 r=1;a%=m;u64 e=m-2;while(e>0){if(e&1)r=mulmod(r,a,m);a=mulmod(a,a,m);e>>=1;}return r;}

typedef struct{u64 x,y;}APt;
typedef struct{u64 X,Y,Z;}JPt;
#define JINF ((JPt){0,1,0})
#define IS_JINF(p) ((p).Z==0)

static JPt jdbl(JPt p){
    if(IS_JINF(p)||p.Y==0)return JINF;
    u64 Z2=sqmod(p.Z,P),Z4=sqmod(Z2,P);
    u64 X2=sqmod(p.X,P);
    u64 alpha=submod(addmod(addmod(X2,X2,P),X2,P),addmod(addmod(Z4,Z4,P),Z4,P),P);
    u64 Y2=sqmod(p.Y,P);
    u64 beta=mulmod(4,mulmod(p.X,Y2,P),P);
    u64 X3=submod(sqmod(alpha,P),addmod(beta,beta,P),P);
    u64 Y3=submod(mulmod(alpha,submod(beta,X3,P),P),mulmod(8,sqmod(Y2,P),P),P);
    u64 Z3=mulmod(2,mulmod(p.Y,p.Z,P),P);
    return(JPt){X3,Y3,Z3};
}

static JPt jmadd(JPt p,APt q){
    if(IS_JINF(p))return(JPt){q.x,q.y,1};
    u64 Z2=sqmod(p.Z,P),Z3c=mulmod(p.Z,Z2,P);
    u64 U2=mulmod(q.x,Z2,P),S2=mulmod(q.y,Z3c,P);
    u64 H=submod(U2,p.X,P),R=submod(S2,p.Y,P);
    if(H==0)return R==0?jdbl(p):JINF;
    u64 H2=sqmod(H,P),H3=mulmod(H,H2,P),UH2=mulmod(p.X,H2,P);
    u64 X3=submod(submod(sqmod(R,P),H3,P),addmod(UH2,UH2,P),P);
    u64 Y3=submod(mulmod(R,submod(UH2,X3,P),P),mulmod(p.Y,H3,P),P);
    return(JPt){X3,Y3,mulmod(p.Z,H,P)};
}

static APt j2a(JPt p){
    if(IS_JINF(p))return(APt){0,0};
    u64 zi=invmod(p.Z,P),z2=sqmod(zi,P);
    return(APt){mulmod(p.X,z2,P),mulmod(p.Y,mulmod(zi,z2,P),P)};
}

static JPt jmul(u64 k,APt base){
    JPt R=JINF,B={base.x,base.y,1};
    while(k>0){
        if(k&1){if(IS_JINF(R))R=B;else{APt ba=j2a(B);R=jmadd(R,ba);}}
        B=jdbl(B);k>>=1;
    }
    return R;
}

static int jxeq(JPt a,JPt b){
    if(IS_JINF(a)&&IS_JINF(b))return 1;
    if(IS_JINF(a)||IS_JINF(b))return 0;
    return mulmod(a.X,sqmod(b.Z,P),P)==mulmod(b.X,sqmod(a.Z,P),P);
}

static volatile int solved=0;
#define NR 32

typedef struct{
    int tid;
    u64 result_d;
    int found;
    u64 iterations;
}TArg;

static u64 lcg(u64*s){*s=*s*6364136223846793005ULL+1442695040888963407ULL;return*s;}

static void*worker(void*arg){
    TArg*ta=(TArg*)arg;
    int tid=ta->tid;
    APt G={GX,GY},Q={QX,QY};

    u64 rng=(u64)time(NULL)*2654435761ULL+(u64)tid*0x9E3779B97F4A7C15ULL+(u64)clock();

    APt RA[NR];u64 RA_a[NR],RA_b[NR];

    for(int att=0;att<100&&!solved;att++){
        for(int i=0;i<NR;i++){
            RA_a[i]=lcg(&rng)%N;if(!RA_a[i])RA_a[i]=1;
            RA_b[i]=lcg(&rng)%N;if(!RA_b[i])RA_b[i]=1;
            JPt ag=jmul(RA_a[i],G),bq=jmul(RA_b[i],Q);
            JPt c;if(IS_JINF(ag))c=bq;else if(IS_JINF(bq))c=ag;
            else{APt ba=j2a(bq);c=jmadd(ag,ba);}
            RA[i]=j2a(c);
        }

        u64 a1=lcg(&rng)%N,b1=lcg(&rng)%N;
        if(!a1)a1=1;if(!b1)b1=1;
        JPt ag=jmul(a1,G),bq=jmul(b1,Q);
        JPt R1;if(IS_JINF(ag))R1=bq;else if(IS_JINF(bq))R1=ag;
        else{APt ba=j2a(bq);R1=jmadd(ag,ba);}
        u64 a2=a1,b2=b1;JPt R2=R1;

        for(u64 i=1;i<20000000000ULL&&!solved;i++){
            u64 h1=R1.X;h1^=(h1>>17);h1^=(h1<<11);
            int idx1=(int)(h1&(NR-1));
            R1=jmadd(R1,RA[idx1]);
            a1=addmod(a1,RA_a[idx1],N);
            b1=addmod(b1,RA_b[idx1],N);

            u64 h2=R2.X;h2^=(h2>>17);h2^=(h2<<11);
            int idx2=(int)(h2&(NR-1));
            R2=jmadd(R2,RA[idx2]);
            a2=addmod(a2,RA_a[idx2],N);
            b2=addmod(b2,RA_b[idx2],N);

            h2=R2.X;h2^=(h2>>17);h2^=(h2<<11);
            idx2=(int)(h2&(NR-1));
            R2=jmadd(R2,RA[idx2]);
            a2=addmod(a2,RA_a[idx2],N);
            b2=addmod(b2,RA_b[idx2],N);

            if(jxeq(R1,R2)){
                u64 da=submod(a2,a1,N),db=submod(b1,b2,N);
                if(db==0){break;}
                u64 d=mulmod(da,invmod(db,N),N);
                APt chk=j2a(jmul(d,G));
                if(chk.x==QX&&chk.y==QY){
                    ta->result_d=d;ta->found=1;ta->iterations=i;solved=1;return NULL;
                }
                d=N-d;chk=j2a(jmul(d,G));
                if(chk.x==QX&&chk.y==QY){
                    ta->result_d=d;ta->found=1;ta->iterations=i;solved=1;return NULL;
                }
                break;
            }
            if(tid==0&&i%50000000==0){
                printf("\r  [T0] att %d: %lluM (%.1fM/s)  ",att,(unsigned long long)(i/1000000),(double)i/((double)clock()/CLOCKS_PER_SEC)/1e6);
                fflush(stdout);
            }
        }
    }
    return NULL;
}

int main(int argc,char**argv){
    int nth=12;
    if(argc>1)nth=atoi(argv[1]);
    if(nth<1)nth=1;if(nth>32)nth=32;

    APt G={GX,GY};
    u64 l=sqmod(GY,P),r=addmod(addmod(mulmod(GX,sqmod(GX,P),P),mulmod(P-3,GX,P),P),0x22996b9c33aeefdbULL,P);
    if(l!=r){printf("G bad\n");return 1;}
    JPt nG=jmul(N,G);if(!IS_JINF(nG)){printf("n*G!=O\n");return 1;}

    printf("ECDLP: %d threads, Jacobian r-adding Pollard rho (NR=%d)\n",nth,NR);
    printf("p=0x%016llx n=0x%016llx\n",(unsigned long long)P,(unsigned long long)N);
    fflush(stdout);

    clock_t start=clock();
    pthread_t thr[32];TArg args[32];
    for(int i=0;i<nth;i++){args[i].tid=i;args[i].found=0;pthread_create(&thr[i],NULL,worker,&args[i]);}
    for(int i=0;i<nth;i++)pthread_join(thr[i],NULL);
    double wall=(double)(clock()-start)/CLOCKS_PER_SEC;

    for(int i=0;i<nth;i++){
        if(args[i].found){
            printf("\n*** ECDLP SOLVED by thread %d! ***\n",i);
            printf("Private key d = 0x%016llx\n",(unsigned long long)args[i].result_d);
            printf("d = %llu\n",(unsigned long long)args[i].result_d);
            printf("Iterations: %llu\nWall: %.1fs\nVerified: d*G = Q\n",(unsigned long long)args[i].iterations,wall);
            fflush(stdout);
            FILE*f=fopen("ecdlp_result.txt","a");
            if(f){fprintf(f,"\n*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nd = %llu\nWall: %.1fs\nVerified: d*G = Q\n",(unsigned long long)args[i].result_d,(unsigned long long)args[i].result_d,wall);fclose(f);}
            f=fopen("ecdlp_jmt_result.txt","w");
            if(f){fprintf(f,"*** ECDLP SOLVED! ***\nPrivate key d = 0x%016llx\nd = %llu\nIterations: %llu\nWall: %.1fs\nVerified: d*G = Q\n",(unsigned long long)args[i].result_d,(unsigned long long)args[i].result_d,(unsigned long long)args[i].iterations,wall);fclose(f);}
            return 0;
        }
    }
    printf("\nFailed after %.1fs\n",wall);return 1;
}
