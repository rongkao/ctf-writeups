#include <stdio.h>
#include <stdint.h>
typedef unsigned __int128 u128;
typedef uint64_t u64;
#define P 0xc564eef070e69193ULL
#define N 0xc564eef19a080b07ULL
static inline u64 mulmod(u64 a,u64 b,u64 m){return(u64)(((u128)a*b)%m);}
static inline u64 sqmod(u64 a,u64 m){return(u64)(((u128)a*a)%m);}
static inline u64 addmod(u64 a,u64 b,u64 m){u64 s=a+b;return(s>=m||s<a)?s-m:s;}
static inline u64 submod(u64 a,u64 b,u64 m){return a>=b?a-b:a+m-b;}
static u64 invmod(u64 a,u64 m){u64 r=1;a%=m;u64 e=m-2;while(e>0){if(e&1)r=mulmod(r,a,m);a=mulmod(a,a,m);e>>=1;}return r;}
typedef struct{u64 x,y;}Pt;
#define INF ((Pt){0,0})
#define IS_INF(p)((p).x==0&&(p).y==0)
static Pt ec_add(Pt p1,Pt p2){
    if(IS_INF(p1))return p2;if(IS_INF(p2))return p1;
    u64 lam;
    if(p1.x==p2.x){if(p1.y!=p2.y||p1.y==0)return INF;
        u64 num=addmod(mulmod(3,mulmod(p1.x,p1.x,P),P),P-3,P);
        lam=mulmod(num,invmod(addmod(p1.y,p1.y,P),P),P);
    }else{lam=mulmod(submod(p2.y,p1.y,P),invmod(submod(p2.x,p1.x,P),P),P);}
    u64 x3=submod(submod(mulmod(lam,lam,P),p1.x,P),p2.x,P);
    u64 y3=submod(mulmod(lam,submod(p1.x,x3,P),P),p1.y,P);
    return(Pt){x3,y3};
}
static Pt ec_mul(u64 k,Pt p){Pt R=INF;while(k>0){if(k&1)R=ec_add(R,p);p=ec_add(p,p);k>>=1;}return R;}
int main(void){
    Pt G={0x2223a1d595845fa2ULL,0x1c4eee9222ddda62ULL};
    Pt Q={0x297a4a1e5b1fc99bULL,0x880198e3724f9feeULL};
    Pt g2=ec_mul(2,G),g3=ec_mul(3,G),g12345=ec_mul(12345,G);
    printf("2*G=(%016llx,%016llx)\n",(unsigned long long)g2.x,(unsigned long long)g2.y);
    printf("3*G=(%016llx,%016llx)\n",(unsigned long long)g3.x,(unsigned long long)g3.y);
    printf("12345*G=(%016llx,%016llx)\n",(unsigned long long)g12345.x,(unsigned long long)g12345.y);
    printf("Expected: 2G=(199e011ccdcd7e3e,6c0b4f13efc53d61)\n");
    printf("Expected: 3G=(34e7e79a7b96d004,5007bdb71ad897c3)\n");
    printf("Expected: 12345G=(684f0bd5678d30f6,59449c853ad1f6cb)\n");
    printf("Match 2G: %s\n",g2.x==0x199e011ccdcd7e3eULL&&g2.y==0x6c0b4f13efc53d61ULL?"YES":"NO");
    printf("Match 3G: %s\n",g3.x==0x34e7e79a7b96d004ULL&&g3.y==0x5007bdb71ad897c3ULL?"YES":"NO");
    printf("Match 12345G: %s\n",g12345.x==0x684f0bd5678d30f6ULL&&g12345.y==0x59449c853ad1f6cbULL?"YES":"NO");
    /* Test addmod overflow case */
    u64 a=P-1,b=P-2;
    u64 sum=addmod(a,b,P);
    u64 expected=(a+b>=P)?(a+b-P):(a+b); /* could overflow u64 */
    printf("\naddmod(%016llx,%016llx,P)=%016llx\n",(unsigned long long)a,(unsigned long long)b,(unsigned long long)sum);
    /* Manual: a+b = 2P-3, which > 2^64? P=0xc564eef070e69193, 2P-3=0x18ac9dde0e1cd2323 > 2^64 -> YES overflow */
    /* Correct: 2P-3-P = P-3 = 0xc564eef070e69190 */
    printf("Expected: P-3=%016llx\n",(unsigned long long)(P-3));
    printf("addmod correct: %s\n",sum==P-3?"YES":"NO");
    return 0;
}
