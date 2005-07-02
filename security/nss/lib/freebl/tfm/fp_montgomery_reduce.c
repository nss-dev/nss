/* TomsFastMath, a fast ISO C bignum library.
 * 
 * This project is meant to fill in where LibTomMath
 * falls short.  That is speed ;-)
 *
 * This project is public domain and free for all purposes.
 * 
 * Tom St Denis, tomstdenis@iahu.ca
 */
#include <tfm.h>

/******************************************************************/
#if defined(TFM_X86) 
/* x86-32 code */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL \
asm(                  \
"movl %7,%%eax \n\t"  \
"mull %6       \n\t"  \
"addl %5,%%eax \n\t"  \
"adcl $0,%%edx \n\t"  \
"addl %%eax,%0 \n\t"  \
"adcl $0,%%edx \n\t"  \
"movl %%edx,%2 \n\t"  \
:"=g"(_c[LO]), "=g"(_c[HI]), "=g"(cy) \
:"0"(_c[LO]), "1"(_c[HI]), "2"(cy), "g"(mu), "g"(*tmpm++) \
: "%eax", "%edx", "%cc")

#define PROPCARRY \
asm( \
"addl   %5,%0    \n\t"  \
"setb   %%al     \n\t"  \
"movzbl  %%al,%2 \n\t"  \
:"=g"(_c[LO]), "=g"(_c[HI]), "=g"(cy) \
:"0"(_c[LO]), "1"(_c[HI]), "2"(cy),   \
 "m"(_c[LO]), "m"(_c[HI+1]), "m"(_c[CY+1])  \
: "%eax", "%cc")

/******************************************************************/
#elif defined(TFM_X86_64)
/* x86-64 code */

#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL \
asm(                  \
"movq %7,%%rax \n\t"  \
"mulq %6       \n\t"  \
"addq %5,%%rax \n\t"  \
"adcq $0,%%rdx \n\t"  \
"addq %%rax,%0 \n\t"  \
"adcq $0,%%rdx \n\t"  \
"movq %%rdx,%2 \n\t"  \
:"=g"(_c[LO]), "=g"(_c[HI]), "=g"(cy) \
:"0"(_c[LO]), "1"(_c[HI]), "2"(cy), "g"(mu), "g"(*tmpm++) \
: "%rax", "%rdx", "%cc")

#define INNERMUL8 \
asm(                  \
"movq 0(%5),%%rax    \n\t"  \
"movq 0(%2),%%r10    \n\t"  \
"movq 0x8(%5),%%r11  \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x8(%2),%%r10  \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0(%0)    \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x10(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x10(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x8(%0)  \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x18(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x18(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x10(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x20(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x20(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x18(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x28(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x28(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x20(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x30(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x30(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x28(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"movq 0x38(%5),%%r11 \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq 0x38(%2),%%r10 \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x30(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
"movq %%r11,%%rax    \n\t"  \
"mulq %4             \n\t"  \
"addq %%r10,%%rax    \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"addq %3,%%rax       \n\t"  \
"adcq $0,%%rdx       \n\t"  \
"movq %%rax,0x38(%0) \n\t"  \
"movq %%rdx,%1       \n\t"  \
\
:"=r"(_c), "=r"(cy) \
: "0"(_c),  "1"(cy), "g"(mu), "r"(tmpm)\
: "%rax", "%rdx", "%r10", "%r11", "%cc")

#define PROPCARRY \
asm( \
"addq   %5,%0    \n\t"  \
"setb   %%al     \n\t"  \
"movzbq  %%al,%2 \n\t"  \
:"=g"(_c[LO]), "=g"(_c[HI]), "=g"(cy) \
:"0"(_c[LO]), "1"(_c[HI]), "2"(cy),   \
 "m"(_c[LO]), "m"(_c[HI+1]), "m"(_c[CY+1])  \
: "%rax", "%cc")

/******************************************************************/
#elif defined(TFM_SSE2)  
/* SSE2 code (assumes 32-bit fp_digits) */
/* XMM register assignments:
 * xmm0  *tmpm++, then Mu * (*tmpm++)
 * xmm1  c[x], then Mu
 * xmm2  mp
 * xmm3  cy
 * xmm4  _c[LO]
 */

#define MONT_START \
asm("movd %0,%%mm2"::"g"(mp))

#define MONT_FINI \
asm("emms")

#define LOOP_START \
asm(\
"movd %1,%%mm1        \n\t" \
"movd %0,%%mm3        \n\t" \
"pmuludq %%mm2,%%mm1  \n" \
:: "r"(cy), "g"(c[x]))

/* pmuludq on mmx registers does a 32x32->64 multiply. */
#define INNERMUL \
asm(             \
"movd %2,%%mm0        \n\t" \
"pmuludq %%mm1,%%mm0  \n\t" \
"movd %1,%%mm4        \n\t" \
"paddq %%mm3,%%mm0    \n\t" \
"paddq %%mm4,%%mm0    \n\t" \
"movd %%mm0,%0        \n\t" \
"psrlq $32, %%mm0     \n\t" \
"movq %%mm0,%%mm3     \n"   \
:"=g"(_c[LO]) : "0"(_c[LO]), "g"(*tmpm++) );

#define LOOP_END \
asm( "movd %%mm3,%0  \n" :"=r"(cy))

#define PROPCARRY \
asm( \
"addl   %5,%0    \n\t"  \
"setb   %%al     \n\t"  \
"movzbl  %%al,%2 \n"  \
:"=g"(_c[LO]), "=g"(_c[HI]), "=r"(cy) \
:"0"(_c[LO]), "1"(_c[HI]), "2"(cy),   \
 "m"(_c[LO]), "m"(_c[HI+1]), "m"(_c[CY+1])  \
: "%eax", "%cc")

/******************************************************************/
/* #elif defined(TFM_ARM)   ARM code */
/******************************************************************/
#else

/* ISO C code */
#define MONT_START 
#define MONT_FINI
#define LOOP_END
#define LOOP_START \
   mu = c[x] * mp

#define INNERMUL \
   do { fp_word t; \
   _c[0] = t  = ((fp_word)_c[0] + (fp_word)cy) + \
                (((fp_word)mu) * ((fp_word)*tmpm++)); \
   cy = (t >> DIGIT_BIT); \
   } while (0)

#define PROPCARRY \
   do { fp_digit t = _c[0] += cy; cy = (t < cy); } while (0)

#endif
/******************************************************************/


#define LO  0
#define HI  1
#define CY  2

/* computes x/R == x (mod N) via Montgomery Reduction */
void fp_montgomery_reduce(fp_int *a, fp_int *m, fp_digit mp)
{
#define CSIZE (3*FP_SIZE)
   fp_digit c[CSIZE], *_c, *tmpm, mu;
   int      aused, x, mused;

#if defined(USE_MEMSET)
   /* now zero the buff */
   memset(c, 0, sizeof c);
#else
   int limit;
#endif
   mused = m->used;

   /* copy the input */
   aused = a->used;
   for (x = 0; x < aused; x++) {
       c[x] = a->dp[x];
   }
#if !defined(USE_MEMSET)
   limit = aused + 2*mused + 3;
   for (; x < limit; x++) {
       c[x] = 0;
   }
#endif
   MONT_START;

   for (x = 0; x < mused; x++) {
       int y;
       fp_digit cy = 0;
       /* get Mu for this round */
       LOOP_START;
       _c   = c + x;
       tmpm = m->dp;
       y    = 0;
#if defined(TFM_X86_64)
       for (; y < mused; y += 8) {
          INNERMUL8;
          _c   += 8;
	  tmpm += 8;
       }
#endif
       for (; y < mused; y++) {
          INNERMUL;
          ++_c;
       }
       LOOP_END;
       while (cy) {
           PROPCARRY; //  cy = cy > (*_c += cy);
           ++_c;
       }
  }

  /* now copy out */
  _c   = c + mused;
  tmpm = a->dp;
  for (x = 0; x < mused+1; x++) {
     *tmpm++ = *_c++;
  }

  for (; x < aused; x++)   {
     *tmpm++ = 0;
  }

  MONT_FINI;

  a->used = mused+1;
  fp_clamp(a);
  
  /* if A >= m then A = A - m */
  if (fp_cmp_mag (a, m) != FP_LT) {
    s_fp_sub (a, m, a);
  }
}
