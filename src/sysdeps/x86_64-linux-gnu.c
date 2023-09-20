// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <signal.h>

void* hwexception_get_sp(void const* in) {
    ucontext_t const* ctx = (ucontext_t const*)in;
    return (void*)ctx->uc_mcontext.gregs[REG_RSP];
}

void* hwexception_get_ip(void const* in) {
    ucontext_t const* ctx = (ucontext_t const*)in;
    return (void*)ctx->uc_mcontext.gregs[REG_RIP];
}
