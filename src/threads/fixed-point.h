#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

#define F (1<<14)
typedef int fp;

#define int_to_fp(INTEGER) (INTEGER * F)
#define fp_to_int(FP) (FP / F)
#define fp_mul(FP1, FP2) (((int64_t) (FP1)) * (FP2) / F)
#define fp_div(DIVIDEND, DIVISOR) (((int64_t) (DIVIDEND)) * F / (DIVISOR))
#define fp_to_int_round(FP) (FP >= 0 ? \
                            ((FP) + F / 2) / F : ((FP) - F / 2) / F)
typedef int myfp;


#endif /**< threads/fixed-point.h */