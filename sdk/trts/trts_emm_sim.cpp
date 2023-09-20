/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
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

#include "util.h"
#include "sgx_mm.h"
#include "emm_private.h"
#include <errno.h>

int mm_commit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return 0;
}

int mm_uncommit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return 0;
}

int mm_modify_permissions(void* addr, size_t size, int prot)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(prot);
    return 0;
}

int sgx_mm_alloc(void* addr, size_t size, int flags,
                 sgx_enclave_fault_handler_t handler, void* priv,
                 void** out_addr)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(flags);
    UNUSED(handler);
    UNUSED(priv);
    UNUSED(out_addr);
    return EOPNOTSUPP;
}

int sgx_mm_commit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return EOPNOTSUPP;
}

int sgx_mm_uncommit(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return EOPNOTSUPP;
}

int sgx_mm_dealloc(void* addr, size_t size)
{
    UNUSED(addr);
    UNUSED(size);
    return EOPNOTSUPP;
}

int sgx_mm_commit_data(void* addr, size_t size, uint8_t* data, int prot)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(data);
    UNUSED(prot);
    return EOPNOTSUPP;
}

int sgx_mm_modify_type(void* addr, size_t size, int type)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(type);
    return EOPNOTSUPP;
}

int sgx_mm_modify_permissions(void* addr, size_t size, int prot)
{
    UNUSED(addr);
    UNUSED(size);
    UNUSED(prot);
    return EOPNOTSUPP;
}
