// Copyright (c) 2023 Daniel Fox Franke
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifdef HAVE_UNWINDER
extern void* _Unwind_FindEnclosingFunction (void *ip);
#endif

// Defined in sysdeps
void* hwexception_get_sp(void const* in);
void* hwexception_get_ip(void const* in);

enum sigill_code {
    RUST_ILL_ILLOPC,
    RUST_ILL_ILLOPN,
    RUST_ILL_ILLADR,
    RUST_ILL_ILLTRP,
    RUST_ILL_PRVOPC,
    RUST_ILL_PRVREG,
    RUST_ILL_COPROC,
    RUST_ILL_BADSTK
};

enum sigfpe_code {
    RUST_FPE_INTDIV,
    RUST_FPE_INTOVF,
    RUST_FPE_FLTDIV,
    RUST_FPE_FLTOVF,
    RUST_FPE_FLTUND,
    RUST_FPE_FLTRES,
    RUST_FPE_FLTINV,
    RUST_FPE_FLTSUB
};

enum sigsegv_code {
    RUST_SEGV_MAPERR,
    RUST_SEGV_ACCERR,
    RUST_SEGV_BNDERR,
    RUST_SEGV_PKUERR
};

enum sigbus_code {
    RUST_BUS_ADRALN,
    RUST_BUS_ADRERR,
    RUST_BUS_OBJERR,
    RUST_BUS_MCEERR_AR,
    RUST_BUS_MCEERR_AO
};

enum sigtrap_code {
    RUST_TRAP_BRKPT,
    RUST_TRAP_TRACE,
    RUST_TRAP_BRANCH,
    RUST_TRAP_HWBKPT,
};

int hwexception_catch(void (*cb)(void *), void *ctx, void *exception, jmp_buf **jmp_buf_ptr, void **err_buf_ptr)
{
    jmp_buf env;
    jmp_buf *old_jmp_buf_ptr;
    void *old_err_buf_ptr;
    int ret;

    
    old_jmp_buf_ptr = *jmp_buf_ptr;
    old_err_buf_ptr = *err_buf_ptr;
    *jmp_buf_ptr = &env;
    *err_buf_ptr = exception;

    if ((ret = setjmp(env)) == 0) {
        cb(ctx);
    }

    *jmp_buf_ptr = old_jmp_buf_ptr;
    *err_buf_ptr = old_err_buf_ptr;
    return ret;
}

void hwexception_throw(void const* exception, size_t exception_len, jmp_buf **jmp_buf_ptr, void **err_buf_ptr) {
    if(*jmp_buf_ptr != NULL && *err_buf_ptr != NULL) {
        memcpy(*err_buf_ptr, exception, exception_len);
        longjmp(**jmp_buf_ptr, 1);
    }
}

int hwexception_translate_sigill_code(enum sigill_code *out, int in) {
    enum sigill_code dummy;
    if(out == NULL) out = &dummy;

    switch (in) {
        case ILL_ILLOPC:
            *out = RUST_ILL_ILLOPC;
            return 1;
        case ILL_ILLOPN:
            *out = RUST_ILL_ILLOPN;
            return 1;
        case ILL_ILLADR:
            *out = RUST_ILL_ILLADR;
            return 1;
        case ILL_ILLTRP:
            *out = RUST_ILL_ILLTRP;
            return 1;
        case ILL_PRVOPC:
            *out = RUST_ILL_PRVOPC;
            return 1;
        case ILL_PRVREG:
            *out = RUST_ILL_PRVREG;
            return 1;
        case ILL_COPROC:
            *out = RUST_ILL_COPROC;
            return 1;
        case ILL_BADSTK:
            *out = RUST_ILL_BADSTK;
            return 1;
        default:
            return 0;
    }
}

int hwexception_translate_sigfpe_code(enum sigfpe_code *out, int in) {
    enum sigfpe_code dummy;
    if(out == NULL) out = &dummy;

    switch (in) {
        case FPE_INTDIV:
            *out = RUST_FPE_INTDIV;
            return 1;
        case FPE_INTOVF:
            *out = RUST_FPE_INTOVF;
            return 1;
        case FPE_FLTDIV:
            *out = RUST_FPE_FLTDIV;
            return 1;
        case FPE_FLTOVF:
            *out = RUST_FPE_FLTOVF;
            return 1;
        case FPE_FLTUND:
            *out = RUST_FPE_FLTUND;
            return 1;
        case FPE_FLTRES:
            *out = RUST_FPE_FLTRES;
            return 1;
        case FPE_FLTINV:
            *out = RUST_FPE_FLTINV;
            return 1;
        case FPE_FLTSUB:
            *out = RUST_FPE_FLTSUB;
            return 1;
        default:
            return 0;
    }
}

int hwexception_translate_sigsegv_code(enum sigsegv_code *out, int in) {
   enum sigsegv_code dummy;
    if(out == NULL) out = &dummy;

    switch (in) {
        case SEGV_MAPERR:
            *out = RUST_SEGV_MAPERR;
            return 1;
        case SEGV_ACCERR:
            *out = RUST_SEGV_ACCERR;
            return 1;
#ifdef SEGV_BNDERR
        case SEGV_BNDERR:
            *out = RUST_SEGV_BNDERR;
            return 1;
#endif
#ifdef SEGV_PKUERR
        case SEGV_PKUERR:
            *out = RUST_SEGV_PKUERR;
            return 1;
#endif
        default:
            return 0;
    }
}

int hwexception_translate_sigbus_code(enum sigbus_code *out, int in) {
    enum sigbus_code dummy;
    if(out == NULL) out = &dummy;

    switch (in) {
        case BUS_ADRALN:
            *out = RUST_BUS_ADRALN;
            return 1;
        case BUS_ADRERR:
            *out = RUST_BUS_ADRERR;
            return 1;
        case BUS_OBJERR:
            *out = RUST_BUS_OBJERR;
            return 1;
#ifdef BUS_MCEERR_AR
        case BUS_MCEERR_AR:
            *out = RUST_BUS_MCEERR_AR;
            return 1;
#endif
#ifdef BUS_MCEERR_AO
        case BUS_MCEERR_AO:
            *out = RUST_BUS_MCEERR_AO;
            return 1;
#endif
        default:
            return 0;
    }
}

int hwexception_translate_sigtrap_code(enum sigtrap_code *out, int in) {
    enum sigtrap_code dummy;
    if(out == NULL) out = &dummy;

    switch (in) {
#ifdef TRAP_BRKPT
        case TRAP_BRKPT:
            *out = RUST_TRAP_BRKPT;
            return 1;
#endif
#ifdef TRAP_TRACE
        case TRAP_TRACE:
            *out = RUST_TRAP_TRACE;
            return 1;
#endif
#ifdef TRAP_BRANCH
        case TRAP_BRANCH:
            *out = RUST_TRAP_BRANCH;
            return 1;
#endif
#ifdef TRAP_HWBKPT
        case TRAP_HWBKPT:
            *out = RUST_TRAP_HWBKPT;
            return 1;
#endif
        default:
            return 0;
    }
}

void* hwexception_get_symbol_address(void const* in) {
#ifdef HAVE_UNWINDER
    void *ip = hwexception_get_ip(in);
    if (ip) {
        return _Unwind_FindEnclosingFunction(ip);
    } else {
        return NULL;
    }
#else
    return hwexception_get_ip(in);
#endif
}

short hwexception_get_addr_lsb(siginfo_t const* in) {
#ifdef BUS_MCEERR_AO
    return in->si_addr_lsb;
#else
    (void)in;
    abort()
#endif
}

void* hwexception_get_lower(siginfo_t const* in) {
#ifdef SEGV_BNDERR
    return in->si_lower;
#else
    (void)in;
    abort()
#endif
}

void* hwexception_get_upper(siginfo_t const* in) {
#ifdef SEGV_BNDERR
    return in->si_upper;
#else
    (void)in;
    abort()
#endif
}

int hwexception_get_pkey(siginfo_t const* in) {
#ifdef SEGV_PKUERR
    return in->si_pkey;
#else
    (void)in;
    abort()
#endif
}
