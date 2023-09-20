#ifndef _SGX_INTERRUPT_H_
#define _SGX_INTERRUPT_H_

// An interrupt mechanism for dynamically-loaded workloads in enclaves.
//
// Workloads in an enclave can be classified into two categories: statically-loaded and
// dynamically-loaded workloads. Statically-loaded workloads are application code that
// are built into the enclave; that is, they are part of the enclave since enclave initialization.
// Dynamically-loaded workloads, as the name suggests, are application code loaded after
// the enclave gets running.
//
// One typical example of dynamically-loaded workloads is user programs loaded by a SGX
// LibOS. The user programs could be arbitrary code. As a result, once the user program
// gets executed, the LibOS may never have the opportunity to take control of the CPU.
// Without the ability to regain the control, it is impossible for the LibOS to implement
// features like interruptible signal handler or preemptive in-enclave thread scheduling.
//
// To address the issue above, we implement the signal-based interrupt mechanism for
// dynamically-loaded workloads. With the provided APIs, the users can now interrupt the
// dynamically-loaded workloads executed in a SGX thread by simply sending a real-time
// POSIX signal (whosenumber is 64, the max value of signal numbers on Linux) to the SGX
// thread. The signal will be captured and (if the timing is good) a pre-registered
// interrupt handler will get executed inside the enclave.
//
// Note that the interrupt mechanism only performs the signal-to-interrupt conversion
// described above is in a best-effort manner. That is, sending a signal may not
// result in the interrupt handler getting called. For example, if the target SGX thread is
// executing some code outside the enclave, then the signal received will be simply
// ignored, thus not triggering the interrupt handler to be executed. So the users of
// the interrupt mechanism should find other means to determine if an interrupt has been
// delivered, and if not, whether and when to resend the interrupt (via POSIX signal).

#include "sgx_error.h"
#include "sgx_trts_exception.h"

// A data structure that represents an interrupt
 __attribute__((aligned(64)))
typedef struct _sgx_interrupt_info_t {
    sgx_cpu_context_t   cpu_context;
    uint32_t            interrupt_valid;
    uint32_t            reserved;
    uint64_t            xsave_size;
#if defined (_M_X64) || defined (__x86_64__)
    uint64_t            reserved1[4];
#else
    uint64_t            reserved1[1];
#endif
    uint8_t             xsave_area[0];    // 64-byte aligned
} sgx_interrupt_info_t;

// A handler function that processes an interrupt
typedef void (*sgx_interrupt_handler_t)(sgx_interrupt_info_t*);

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the interrupt mechanism for SGX threads.
sgx_status_t SGXAPI sgx_interrupt_init(sgx_interrupt_handler_t handler);

// Make the current thread interruptible when executing in the given code region.
//
// By default, a SGX thread is not interruptible. It is the responsibility of the
// caller of this API to ensure that the given code region is ok to be interrupted,
// e.g., not causing deadlocks.
sgx_status_t SGXAPI sgx_interrupt_enable(size_t code_addr, size_t code_size);

// Make the current thread uninterruptible.
sgx_status_t SGXAPI sgx_interrupt_disable(void);

#ifdef __cplusplus
}
#endif

#endif /* _SGX_INTERRUPT_H_ */
