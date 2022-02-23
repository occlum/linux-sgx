/*
 * Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include "se_event.h"

#include <linux/futex.h>
#include <sys/time.h>

int se_event_timeout_wait(se_handle_t se_event, int clockbit, const struct timespec *ts, int absolute_time, int *err)
{
    int ret = 0;

    if (se_event == NULL || err == NULL)
        return SE_MUTEX_INVALID;

    if (__sync_fetch_and_add((int*)se_event, -1) == 0) {
        // From futex man page:
        // For FUTEX_WAIT, timeout is interpreted as a relative value. This differs from other futex operations, where
        // timeout is interpreted as an absolute value. To obtain the equivalent of FUTEX_WAIT with an absolute timeout,
        // employ FUTEX_WAIT_BITSET with val3 specified as FUTEX_BITSET_MATCH_ANY.
        if (absolute_time == 1) {
            ret = (int)syscall(__NR_futex, se_event, FUTEX_WAIT_BITSET | clockbit, -1, ts, NULL, FUTEX_BITSET_MATCH_ANY);
        } else {
            // FUTEX_WAIT can't work with FUTEX_CLOCK_REALTIME in Linux. Thus, ignore the clockbit.
            // Reference: https://github.com/torvalds/linux/commit/4fbf5d6837bf81fd7a27d771358f4ee6c4f243f8
            ret = (int)syscall(__NR_futex, se_event, FUTEX_WAIT, -1, ts, NULL, 0);
        }
        __sync_val_compare_and_swap((int*)se_event, -1, 0);
    }
    *err = ret < 0 ? errno : 0;

    return SE_MUTEX_SUCCESS;
}
