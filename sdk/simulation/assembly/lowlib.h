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


/**
 * File: lowlib.h
 * Description:
 *   This file declared some functions written in assembly.
 */
#ifndef _LOW_LIB_H_
#define _LOW_LIB_H_

#include <stdint.h>

#if defined(__GNUC__) && !defined(__clang__)
#define LOAD_REGS_ATTRIBUTES \
  __attribute__((optimize("-O0,-fno-omit-frame-pointer")))
#elif defined(__clang__)
#define LOAD_REGS_ATTRIBUTES [[clang::optnone]]
#else
#pragma warning "Unsupported compiler for per-function deoptimization"
#endif

#ifdef __cplusplus
extern "C" {
#endif

uintptr_t get_bp(void);

typedef struct _enclu_regs_t
{
    uintptr_t xax;
    uintptr_t xbx;
    uintptr_t xcx;
    uintptr_t xdx;
    uintptr_t xsi;
    uintptr_t xdi;
    uintptr_t xbp;
    uintptr_t xsp;
    uintptr_t xip;
} enclu_regs_t;

void load_regs(enclu_regs_t *regs);

#ifdef __cplusplus
}
#endif

#endif
