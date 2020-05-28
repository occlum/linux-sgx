#ifndef _OUTSIDE_EXITINFO_H_
#define _OUTSIDE_EXITINFO_H_

#include "sgx_trts_exception.h"

// To simulate #PF and #GP exception on SGX 1, we need extra info about the
// exception from outside the enclave. This extra info is represented in
// struct outside_exitinfo.

typedef struct {
    int         vector; // Must be SGX_EXCEPTION_VECTOR_GP or SGX_EXCEPTION_VECTOR_PF
    int         err_flag;
    uint64_t    addr;
} outside_exitinfo_t;

// Error flags for #PF exception
// Whether the page that caused the fault is presented or not
#define PF_ERR_FLAG_PRESENT         (1 << 0)
// Whether the fault is caused by a write
#define PF_ERR_FLAG_WRITE           (1 << 1)
// Whether the fault is caused in the user space (for our purpose, always 1)
#define PF_ERR_FLAG_USER            (1 << 2)
// Whether the fault is caused by instruction fetch
#define PF_ERR_FLAG_INSTRUCTION     (1 << 4)
// Whether the fault is caused by Intel MPK
#define PF_ERR_FLAG_PROTECT_KEY     (1 << 5)
// Whether the fault is caused by Intel SGX
#define PF_ERR_FLAG_SGX             (1 << 15)

#define PF_ERR_FLAG_MASK            ( PF_ERR_FLAG_PRESENT \
                                    | PF_ERR_FLAG_WRITE \
                                    | PF_ERR_FLAG_USER \
                                    | PF_ERR_FLAG_INSTRUCTION \
                                    | PF_ERR_FLAG_PROTECT_KEY \
                                    | PF_ERR_FLAG_SGX )

#endif /* _OUTSIDE_EXITINFO_H_ */
