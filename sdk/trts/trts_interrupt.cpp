#include "sgx_interrupt.h"
#include "thread_data.h"
#include "trts_internal.h"

static sgx_interrupt_handler_t registered_handler = NULL;

static __thread size_t enabled_code_addr = 0;
static __thread size_t enabled_code_size = 0;
static __thread bool is_enabled = false;

static void set_enabled(bool new_val) {
    // Make sure all writes before this store are visible
    __atomic_store_n(&is_enabled, new_val, __ATOMIC_RELEASE);
}


sgx_status_t sgx_interrupt_init(sgx_interrupt_handler_t handler) {
    if (handler == NULL) {
        return SGX_ERROR_INVALID_PARAMETER;
    }
    if (registered_handler != NULL) {
        return SGX_ERROR_INVALID_STATE;
    }

    registered_handler = handler;
    return SGX_SUCCESS;
}

sgx_status_t sgx_interrupt_enable(size_t code_addr, size_t code_size) {
    if (registered_handler == NULL) {
        return SGX_ERROR_INVALID_STATE;
    }
    if (is_enabled) {
        return SGX_ERROR_INVALID_STATE;
    }

    enabled_code_addr = code_addr;
    enabled_code_size = code_size;
    set_enabled(true);
    return SGX_SUCCESS;
}

sgx_status_t sgx_interrupt_disable(void) {
    if (!is_enabled) {
        return SGX_ERROR_INVALID_STATE;
    }
    set_enabled(false);
    return SGX_SUCCESS;
}

int check_ip_interruptible(size_t ip) {
    return is_enabled &&
        ip >= enabled_code_addr &&
        (ip - enabled_code_addr) < enabled_code_size;
}

__attribute__((regparm(1))) void internal_handle_interrupt(sgx_interrupt_info_t *info) {
    registered_handler(info);
    // Note that the registered handler must be in charge of continueing the execution of
    // the interrupted workloads.
    // TODO: restore the CPU context info
    abort();
}
