#include "sgx_interrupt.h"
#include "arch.h"
#include "thread_data.h"
#include "trts_internal.h"
#include "util.h"
#include "trts_util.h"

#include "se_memcpy.h"
extern "C" __attribute__((regparm(1))) void continue_execution(sgx_interrupt_info_t *info);

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

extern "C" __attribute__((regparm(1))) void internal_handle_interrupt(sgx_interrupt_info_t *info) {
    thread_data_t *thread_data = get_thread_data();
    uint8_t *xsave_in_ssa = NULL;

    if (info->interrupt_valid)
    {
        xsave_in_ssa = (uint8_t*)ROUND_TO_PAGE(thread_data->first_ssa_gpr) - ROUND_TO_PAGE(get_xsave_size() + sizeof(ssa_gpr_t));
        memcpy_s(info->xsave_area, info->xsave_size, xsave_in_ssa, info->xsave_size);

        registered_handler(info);
        // Note that the registered handler must be in charge of continueing the execution of
        // the interrupted workloads.
        // TODO: restore the CPU context info
        abort();
    }
    else
    {
        continue_execution(info);
    }
    return;
}
